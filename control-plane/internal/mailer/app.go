package mailer

import (
	"context"
	"fmt"
	"log"
	"strings"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/skxm03/kr0n-backend/control-plane/internal/email"
	"github.com/skxm03/kr0n-backend/control-plane/internal/mailer/config"
)

// App encapsulates the RabbitMQ consumer, template engine, SMTP dispatcher, and batch worker pool.
type App struct {
	cfg       *config.Config
	conn      *amqp.Connection
	ch        *amqp.Channel
	queueName string
	processor *BatchProcessor
}

// NewApp wires the template engine, SMTP sender, RabbitMQ connection/channel, and batch processor.
func NewApp(cfg *config.Config) (*App, error) {
	engine, err := NewEngine()
	if err != nil {
		return nil, fmt.Errorf("init template engine: %w", err)
	}

	conn, err := amqp.Dial(cfg.RabbitMQURL)
	if err != nil {
		return nil, fmt.Errorf("dial rabbitmq: %w", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("open rabbitmq channel: %w", err)
	}

	queueName := strings.TrimSpace(cfg.QueueName)
	if queueName == "" {
		queueName = email.DefaultQueueName
	}

	if err := email.DeclareQueues(ch, queueName); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return nil, err
	}

	batchSize := cfg.BatchSize
	if batchSize < 1 {
		batchSize = 20
	}
	if err := ch.Qos(batchSize*2, 0, false); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("set rabbitmq qos: %w", err)
	}

	smtpSender := email.NewSMTPSender(email.SMTPConfig{
		Addr:     cfg.SMTPAddr,
		From:     cfg.SMTPFrom,
		Username: cfg.SMTPUsername,
		Password: cfg.SMTPPassword,
		Timeout:  cfg.SMTPTimeout,
	})

	processor := NewBatchProcessor(engine, smtpSender, BatchConfig{
		BatchSize:    batchSize,
		BatchTimeout: cfg.BatchTimeout,
		Workers:      cfg.BatchWorkers,
	})

	return &App{
		cfg:       cfg,
		conn:      conn,
		ch:        ch,
		queueName: queueName,
		processor: processor,
	}, nil
}

// Run starts consuming from RabbitMQ and batch-processing email jobs until ctx is canceled.
func (a *App) Run(ctx context.Context) error {
	defer func() {
		_ = a.ch.Close()
		_ = a.conn.Close()
	}()

	deliveries, err := a.ch.Consume(
		a.queueName,
		"kr0n-mailer",
		false, // autoAck = false (manual Ack/Nack after batch goroutine processing)
		false, // exclusive
		false, // noLocal
		false, // noWait
		nil,
	)
	if err != nil {
		return fmt.Errorf("consume queue %q: %w", a.queueName, err)
	}

	log.Printf("mailer service consuming queue %q (batch_size=%d, workers=%d)", a.queueName, a.processor.cfg.BatchSize, a.processor.cfg.Workers)
	return a.processor.Run(ctx, deliveries)
}
