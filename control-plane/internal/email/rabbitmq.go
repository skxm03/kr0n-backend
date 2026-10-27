package email

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

// DeclareQueues declares the dead-letter queue (<queue>.dlq) and the main durable email job queue
// configured to route rejected/expired messages into the DLQ.
func DeclareQueues(ch *amqp.Channel, queueName string) error {
	if strings.TrimSpace(queueName) == "" {
		queueName = DefaultQueueName
	}
	dlqName := queueName + ".dlq"
	if _, err := ch.QueueDeclare(
		dlqName,
		true,  // durable
		false, // autoDelete
		false, // exclusive
		false, // noWait
		nil,
	); err != nil {
		return fmt.Errorf("declare dlq %q: %w", dlqName, err)
	}

	args := amqp.Table{
		"x-dead-letter-exchange":    "",
		"x-dead-letter-routing-key": dlqName,
	}
	if _, err := ch.QueueDeclare(
		queueName,
		true,  // durable
		false, // autoDelete
		false, // exclusive
		false, // noWait
		args,
	); err != nil {
		return fmt.Errorf("declare queue %q: %w", queueName, err)
	}
	return nil
}

// RabbitMQSender publishes transactional email jobs to a RabbitMQ queue.
type RabbitMQSender struct {
	mu        sync.Mutex
	conn      *amqp.Connection
	ch        *amqp.Channel
	queueName string
}

// NewRabbitMQSender dials RabbitMQ, declares the durable email queue + DLQ, and returns a publisher.
func NewRabbitMQSender(amqpURL, queueName string) (*RabbitMQSender, error) {
	if strings.TrimSpace(amqpURL) == "" {
		return nil, errors.New("email: rabbitmq url is required")
	}
	if strings.TrimSpace(queueName) == "" {
		queueName = DefaultQueueName
	}

	conn, err := amqp.Dial(amqpURL)
	if err != nil {
		return nil, fmt.Errorf("dial rabbitmq: %w", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("open rabbitmq channel: %w", err)
	}
	if err := DeclareQueues(ch, queueName); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return nil, err
	}

	return &RabbitMQSender{
		conn:      conn,
		ch:        ch,
		queueName: queueName,
	}, nil
}

// Close closes the underlying AMQP channel and connection.
func (s *RabbitMQSender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var firstErr error
	if s.ch != nil {
		if err := s.ch.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.conn != nil {
		if err := s.conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Enqueue publishes an arbitrary JobMessage to the configured RabbitMQ queue.
func (s *RabbitMQSender) Enqueue(ctx context.Context, job JobMessage) error {
	if job.ID == "" {
		job.ID = uuid.NewString()
	}
	if job.CreatedAt.IsZero() {
		job.CreatedAt = time.Now().UTC()
	}
	body, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshal email job: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ch.PublishWithContext(
		ctx,
		"",          // default exchange
		s.queueName, // routing key
		false,       // mandatory
		false,       // immediate
		amqp.Publishing{
			ContentType:  "application/json",
			DeliveryMode: amqp.Persistent,
			MessageId:    job.ID,
			Timestamp:    job.CreatedAt,
			Body:         body,
		},
	)
}

// SendVerificationEmail enqueues a verify_email job.
func (s *RabbitMQSender) SendVerificationEmail(ctx context.Context, recipient, rawToken string) error {
	return s.Enqueue(ctx, JobMessage{
		Type:      TemplateVerifyEmail,
		Recipient: recipient,
		Data: map[string]string{
			"token": rawToken,
		},
	})
}

// SendPasswordResetEmail enqueues a password_reset job.
func (s *RabbitMQSender) SendPasswordResetEmail(ctx context.Context, recipient, rawToken string) error {
	return s.Enqueue(ctx, JobMessage{
		Type:      TemplatePasswordReset,
		Recipient: recipient,
		Data: map[string]string{
			"token": rawToken,
		},
	})
}

// SendOrgInviteEmail enqueues an org_invite job.
func (s *RabbitMQSender) SendOrgInviteEmail(ctx context.Context, recipient, orgName, roleID, rawToken string) error {
	return s.Enqueue(ctx, JobMessage{
		Type:      TemplateOrgInvite,
		Recipient: recipient,
		Data: map[string]string{
			"org_name": orgName,
			"role_id":  roleID,
			"token":    rawToken,
		},
	})
}
