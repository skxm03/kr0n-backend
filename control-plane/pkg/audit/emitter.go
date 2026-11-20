package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

var (
	// ErrEmitterClosed is returned when emitting to an emitter that has been shut down.
	ErrEmitterClosed = errors.New("audit: emitter is closed")

	// ErrBufferFull is returned when the non-blocking async buffer is full (fail-open).
	ErrBufferFull = errors.New("audit: async emitter buffer is full")
)

// Emitter publishes audit events to the downstream audit messaging infrastructure.
type Emitter interface {
	// Emit enqueues an audit event asynchronously without blocking the caller's request path.
	Emit(ctx context.Context, ev Event) error
	// EmitSync publishes an audit event synchronously and waits for broker transmission.
	EmitSync(ctx context.Context, ev Event) error
	// Close drains any buffered asynchronous events and releases underlying connections.
	Close() error
}

// Transport abstracts low-level message publication to support testing and custom brokers.
type Transport interface {
	Publish(ctx context.Context, exchange, routingKey string, msg amqp.Publishing) error
	Close() error
}

// EmitterConfig configures a RabbitMQ-backed audit Emitter.
type EmitterConfig struct {
	AMQPURL          string
	ServiceName      string
	ExchangeName     string
	QueueName        string
	RoutingKeyPrefix string
	BufferSize       int
	Workers          int
	PublishTimeout   time.Duration
	Transport        Transport // optional override for unit testing
}

func (c *EmitterConfig) setDefaults() {
	c.ServiceName = strings.TrimSpace(c.ServiceName)
	if c.ServiceName == "" {
		c.ServiceName = "unknown"
	}
	c.ExchangeName = strings.TrimSpace(c.ExchangeName)
	if c.ExchangeName == "" {
		c.ExchangeName = DefaultExchangeName
	}
	c.QueueName = strings.TrimSpace(c.QueueName)
	if c.QueueName == "" {
		c.QueueName = DefaultQueueName
	}
	c.RoutingKeyPrefix = strings.TrimSpace(c.RoutingKeyPrefix)
	if c.RoutingKeyPrefix == "" {
		c.RoutingKeyPrefix = DefaultRoutingKeyPrefix
	}
	if c.BufferSize <= 0 {
		c.BufferSize = 1024
	}
	if c.Workers <= 0 {
		c.Workers = 2
	}
	if c.PublishTimeout <= 0 {
		c.PublishTimeout = 5 * time.Second
	}
}

// RabbitMQEmitter is a thread-safe, resilient audit event producer with an asynchronous worker pool
// and automatic reconnection on connection/channel drops.
type RabbitMQEmitter struct {
	cfg       EmitterConfig
	transport Transport
	queue     chan Event
	wg        sync.WaitGroup
	closed    atomic.Bool
	closeOnce sync.Once
	dropped   atomic.Uint64
}

// NewRabbitMQEmitter initializes a new audit event emitter connected to the audit RabbitMQ broker.
func NewRabbitMQEmitter(cfg EmitterConfig) (*RabbitMQEmitter, error) {
	cfg.setDefaults()

	transport := cfg.Transport
	if transport == nil {
		if strings.TrimSpace(cfg.AMQPURL) == "" {
			return nil, errors.New("audit: rabbitmq url is required")
		}
		rmqTransport, err := newAMQPTransport(cfg.AMQPURL, cfg.ExchangeName, cfg.QueueName)
		if err != nil {
			return nil, err
		}
		transport = rmqTransport
	}

	e := &RabbitMQEmitter{
		cfg:       cfg,
		transport: transport,
		queue:     make(chan Event, cfg.BufferSize),
	}

	for i := 0; i < cfg.Workers; i++ {
		e.wg.Add(1)
		go e.worker()
	}

	return e, nil
}

func (e *RabbitMQEmitter) worker() {
	defer e.wg.Done()
	for ev := range e.queue {
		ctx, cancel := context.WithTimeout(context.Background(), e.cfg.PublishTimeout)
		if err := e.publish(ctx, ev); err != nil {
			log.Printf("[audit-emitter] async publish error (service=%s action=%s id=%s): %v",
				ev.Service, ev.Action, ev.ID, err)
		}
		cancel()
	}
}

// Emit normalizes, validates, and enqueues the event into the non-blocking async buffer.
// If the buffer is full, it logs a warning and returns ErrBufferFull without blocking the caller.
func (e *RabbitMQEmitter) Emit(_ context.Context, ev Event) error {
	if e.closed.Load() {
		return ErrEmitterClosed
	}
	ev.Normalize(e.cfg.ServiceName)
	if err := ev.Validate(); err != nil {
		return err
	}

	select {
	case e.queue <- ev:
		return nil
	default:
		count := e.dropped.Add(1)
		log.Printf("[audit-emitter] warning: async buffer full, dropping audit event (service=%s action=%s total_dropped=%d)",
			ev.Service, ev.Action, count)
		return ErrBufferFull
	}
}

// EmitSync normalizes, validates, and publishes the event synchronously to the broker.
func (e *RabbitMQEmitter) EmitSync(ctx context.Context, ev Event) error {
	if e.closed.Load() {
		return ErrEmitterClosed
	}
	ev.Normalize(e.cfg.ServiceName)
	if err := ev.Validate(); err != nil {
		return err
	}
	return e.publish(ctx, ev)
}

// DroppedCount returns the total number of async audit events dropped due to buffer saturation.
func (e *RabbitMQEmitter) DroppedCount() uint64 {
	return e.dropped.Load()
}

func (e *RabbitMQEmitter) publish(ctx context.Context, ev Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}

	pub := amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent,
		MessageId:    ev.ID.String(),
		Timestamp:    ev.Timestamp,
		Type:         ev.Action,
		AppId:        ev.Service,
		Body:         body,
	}

	routingKey := ev.RoutingKey(e.cfg.RoutingKeyPrefix)
	return e.transport.Publish(ctx, e.cfg.ExchangeName, routingKey, pub)
}

// Close stops accepting new events, drains all in-flight buffered events, and closes the transport.
func (e *RabbitMQEmitter) Close() error {
	var closeErr error
	e.closeOnce.Do(func() {
		e.closed.Store(true)
		close(e.queue)
		e.wg.Wait()
		if e.transport != nil {
			closeErr = e.transport.Close()
		}
	})
	return closeErr
}

// amqpTransport manages an AMQP connection and channel with automatic reconnect on publish failure.
type amqpTransport struct {
	mu           sync.Mutex
	amqpURL      string
	exchangeName string
	queueName    string
	conn         *amqp.Connection
	ch           *amqp.Channel
	closed       bool
}

func newAMQPTransport(amqpURL, exchangeName, queueName string) (*amqpTransport, error) {
	t := &amqpTransport{
		amqpURL:      amqpURL,
		exchangeName: exchangeName,
		queueName:    queueName,
	}
	if err := t.connectLocked(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *amqpTransport) connectLocked() error {
	if t.ch != nil {
		_ = t.ch.Close()
		t.ch = nil
	}
	if t.conn != nil {
		_ = t.conn.Close()
		t.conn = nil
	}

	conn, err := amqp.Dial(t.amqpURL)
	if err != nil {
		return fmt.Errorf("dial audit rabbitmq: %w", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("open audit rabbitmq channel: %w", err)
	}
	if err := DeclareTopology(ch, t.exchangeName, t.queueName); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return err
	}

	t.conn = conn
	t.ch = ch
	return nil
}

func (t *amqpTransport) Publish(ctx context.Context, exchange, routingKey string, msg amqp.Publishing) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrEmitterClosed
	}

	if t.conn == nil || t.conn.IsClosed() || t.ch == nil || t.ch.IsClosed() {
		if err := t.connectLocked(); err != nil {
			return fmt.Errorf("reconnect audit rabbitmq: %w", err)
		}
	}

	err := t.ch.PublishWithContext(ctx, exchange, routingKey, false, false, msg)
	if err != nil {
		// Attempt one immediate reconnect in case the channel was closed mid-flight.
		if reconnErr := t.connectLocked(); reconnErr == nil {
			err = t.ch.PublishWithContext(ctx, exchange, routingKey, false, false, msg)
		}
	}
	if err != nil {
		return fmt.Errorf("publish audit event to %s (%s): %w", exchange, routingKey, err)
	}
	return nil
}

func (t *amqpTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	var firstErr error
	if t.ch != nil {
		if err := t.ch.Close(); err != nil {
			firstErr = err
		}
		t.ch = nil
	}
	if t.conn != nil {
		if err := t.conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		t.conn = nil
	}
	return firstErr
}

// MemoryEmitter records emitted events in memory for unit tests.
type MemoryEmitter struct {
	mu          sync.Mutex
	serviceName string
	events      []Event
	closed      bool
}

// NewMemoryEmitter creates an in-memory Emitter for testing.
func NewMemoryEmitter(serviceName string) *MemoryEmitter {
	if strings.TrimSpace(serviceName) == "" {
		serviceName = "test"
	}
	return &MemoryEmitter{serviceName: serviceName}
}

func (m *MemoryEmitter) Emit(_ context.Context, ev Event) error {
	return m.record(ev)
}

func (m *MemoryEmitter) EmitSync(_ context.Context, ev Event) error {
	return m.record(ev)
}

func (m *MemoryEmitter) record(ev Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrEmitterClosed
	}
	ev.Normalize(m.serviceName)
	if err := ev.Validate(); err != nil {
		return err
	}
	m.events = append(m.events, ev)
	return nil
}

func (m *MemoryEmitter) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Event, len(m.events))
	copy(out, m.events)
	return out
}

func (m *MemoryEmitter) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}
