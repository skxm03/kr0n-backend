package audit

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/skxm03/kr0n-backend/control-plane/internal/audit/config"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// SinkBuilder constructs a Sink pipeline from configuration and database connectivity.
type SinkBuilder func(ctx context.Context, cfg *config.Config) (Sink, error)

// DialFunc is the signature for dialing an AMQP connection, allowing dependency injection in tests.
type DialFunc func(url string) (*amqp.Connection, error)

// App encapsulates the stateless RabbitMQ audit consumer, sink pipeline, and batch processor.
type App struct {
	cfg          *config.Config
	rmqURL       string
	exchangeName string
	queueName    string
	sink         Sink
	processor    *BatchProcessor
	dialer       DialFunc
	minBackoff   time.Duration
	maxBackoff   time.Duration
}

// Option configures App.
type Option func(*App)

// WithDialer overrides the AMQP dialer for unit testing.
func WithDialer(dialer DialFunc) Option {
	return func(a *App) {
		if dialer != nil {
			a.dialer = dialer
		}
	}
}

// WithBackoffOverrides configures the reconnect backoff window.
func WithBackoffOverrides(min, max time.Duration) Option {
	return func(a *App) {
		if min > 0 {
			a.minBackoff = min
		}
		if max > 0 {
			a.maxBackoff = max
		}
	}
}

// NewApp wires the configuration, sink pipeline, and batch processor.
func NewApp(ctx context.Context, cfg *config.Config, buildSink SinkBuilder, opts ...Option) (*App, error) {
	if buildSink == nil {
		return nil, errors.New("audit: sink builder is required")
	}

	rmqURL := cfg.EffectiveRabbitMQURL()
	if rmqURL == "" {
		return nil, errors.New("audit: AUDIT_RABBITMQ_URL (or RABBITMQ_URL) is required")
	}

	sink, err := buildSink(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("init audit sinks: %w", err)
	}

	exchangeName := strings.TrimSpace(cfg.ExchangeName)
	if exchangeName == "" {
		exchangeName = pkgAudit.DefaultExchangeName
	}

	queueName := strings.TrimSpace(cfg.QueueName)
	if queueName == "" {
		queueName = pkgAudit.DefaultQueueName
	}

	batchSize := cfg.BatchSize
	if batchSize < 1 {
		batchSize = 100
	}

	processor := NewBatchProcessor(
		sink,
		BatchConfig{
			BatchSize:    batchSize,
			BatchTimeout: cfg.BatchTimeout,
			MaxRetries:   cfg.MaxRetries,
			RetryBackoff: cfg.RetryBackoff,
		},
		RedactSensitiveMetadataTransformer(),
	)

	app := &App{
		cfg:          cfg,
		rmqURL:       rmqURL,
		exchangeName: exchangeName,
		queueName:    queueName,
		sink:         sink,
		processor:    processor,
		dialer:       amqp.Dial,
		minBackoff:   500 * time.Millisecond,
		maxBackoff:   15 * time.Second,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(app)
		}
	}

	return app, nil
}

// Run starts consuming audit events from RabbitMQ with automatic reconnect on broker/channel drops,
// and batch-writes to sinks until ctx is canceled.
func (a *App) Run(ctx context.Context) error {
	defer func() {
		if a.sink != nil {
			_ = a.sink.Close()
		}
	}()

	backoff := a.minBackoff
	for {
		if ctx.Err() != nil {
			return nil
		}

		conn, ch, deliveries, err := a.connectAndConsume(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("[audit-worker] connection error: %v (retrying in %s)", err, backoff)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
				backoff = min(backoff*2, a.maxBackoff)
				continue
			}
		}

		// Connected successfully: reset backoff
		backoff = a.minBackoff
		log.Printf("audit worker service consuming from exchange=%q queue=%q sink=%q (batch_size=%d, batch_timeout=%s)",
			a.exchangeName, a.queueName, a.sink.Name(), a.processor.cfg.BatchSize, a.processor.cfg.BatchTimeout)

		runErr := a.processor.Run(ctx, deliveries)
		_ = ch.Close()
		_ = conn.Close()

		if runErr == nil || errors.Is(runErr, context.Canceled) {
			return nil
		}

		if errors.Is(runErr, ErrBrokerDisconnected) {
			log.Printf("[audit-worker] warning: broker connection dropped, attempting reconnect in %s...", backoff)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
				backoff = min(backoff*2, a.maxBackoff)
				continue
			}
		}

		return runErr
	}
}

func (a *App) connectAndConsume(ctx context.Context) (*amqp.Connection, *amqp.Channel, <-chan amqp.Delivery, error) {
	conn, err := a.dialer(a.rmqURL)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("dial audit rabbitmq: %w", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, fmt.Errorf("open audit rabbitmq channel: %w", err)
	}

	if err := pkgAudit.DeclareTopology(ch, a.exchangeName, a.queueName); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return nil, nil, nil, err
	}

	batchSize := a.processor.cfg.BatchSize
	if batchSize < 1 {
		batchSize = 100
	}
	if err := ch.Qos(batchSize*2, 0, false); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return nil, nil, nil, fmt.Errorf("set audit rabbitmq qos: %w", err)
	}

	hostname, _ := os.Hostname()
	consumerTag := fmt.Sprintf("kr0n-audit-worker-%s-%d", hostname, os.Getpid())

	deliveries, err := ch.Consume(
		a.queueName,
		consumerTag,
		false, // autoAck: false
		false, // exclusive: false
		false, // noLocal
		false, // noWait
		nil,
	)
	if err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return nil, nil, nil, fmt.Errorf("consume queue %q: %w", a.queueName, err)
	}

	return conn, ch, deliveries, nil
}
