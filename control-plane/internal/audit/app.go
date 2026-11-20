package audit

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/skxm03/kr0n-backend/control-plane/internal/audit/config"
	pkgAudit "github.com/skxm03/kr0n-backend/control-plane/pkg/audit"
)

// SinkBuilder constructs a Sink pipeline from configuration and database connectivity.
type SinkBuilder func(ctx context.Context, cfg *config.Config) (Sink, error)

// App encapsulates the stateless RabbitMQ audit consumer, sink pipeline, and batch processor.
type App struct {
	cfg          *config.Config
	conn         *amqp.Connection
	ch           *amqp.Channel
	exchangeName string
	queueName    string
	sink         Sink
	processor    *BatchProcessor
}

// NewApp wires the RabbitMQ topology, sink pipeline, and stateless batch processor.
func NewApp(ctx context.Context, cfg *config.Config, buildSink SinkBuilder) (*App, error) {
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

	conn, err := amqp.Dial(rmqURL)
	if err != nil {
		_ = sink.Close()
		return nil, fmt.Errorf("dial audit rabbitmq: %w", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		_ = sink.Close()
		return nil, fmt.Errorf("open audit rabbitmq channel: %w", err)
	}

	exchangeName := strings.TrimSpace(cfg.ExchangeName)
	if exchangeName == "" {
		exchangeName = pkgAudit.DefaultExchangeName
	}

	queueName := strings.TrimSpace(cfg.QueueName)
	if queueName == "" {
		queueName = pkgAudit.DefaultQueueName
	}

	if err := pkgAudit.DeclareTopology(ch, exchangeName, queueName); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		_ = sink.Close()
		return nil, err
	}

	batchSize := cfg.BatchSize
	if batchSize < 1 {
		batchSize = 100
	}
	if err := ch.Qos(batchSize*2, 0, false); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		_ = sink.Close()
		return nil, fmt.Errorf("set audit rabbitmq qos: %w", err)
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

	return &App{
		cfg:          cfg,
		conn:         conn,
		ch:           ch,
		exchangeName: exchangeName,
		queueName:    queueName,
		sink:         sink,
		processor:    processor,
	}, nil
}

// Run starts consuming audit events from RabbitMQ and batch-writing to sinks until ctx is canceled.
func (a *App) Run(ctx context.Context) error {
	defer func() {
		_ = a.ch.Close()
		_ = a.conn.Close()
		if a.sink != nil {
			_ = a.sink.Close()
		}
	}()

	hostname, _ := os.Hostname()
	consumerTag := fmt.Sprintf("kr0n-audit-worker-%s-%d", hostname, os.Getpid())

	deliveries, err := a.ch.Consume(
		a.queueName,
		consumerTag,
		false, // autoAck: false (manual Ack/Nack after sink persistence)
		false, // exclusive: false (competing stateless consumers supported)
		false, // noLocal
		false, // noWait
		nil,
	)
	if err != nil {
		return fmt.Errorf("consume queue %q: %w", a.queueName, err)
	}

	log.Printf("audit worker service consuming from exchange=%q queue=%q sink=%q (batch_size=%d, batch_timeout=%s)",
		a.exchangeName, a.queueName, a.sink.Name(), a.processor.cfg.BatchSize, a.processor.cfg.BatchTimeout)

	return a.processor.Run(ctx, deliveries)
}
