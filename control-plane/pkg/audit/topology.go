package audit

import (
	"fmt"
	"strings"

	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	// DefaultExchangeName is the durable topic exchange used for all audit events.
	DefaultExchangeName = "audit.events"

	// DefaultQueueName is the main durable queue consumed by the stateless audit worker pool.
	DefaultQueueName = "audit.events.worker"

	// DefaultRoutingKeyPrefix is prepended to all emitted routing keys (`audit.<service>.<action>`).
	DefaultRoutingKeyPrefix = "audit"

	// DefaultBindingKey binds the worker queue to all events under the `audit.` hierarchy.
	DefaultBindingKey = "audit.#"
)

// DeclareExchange idempotently declares the durable topic exchange for audit events.
func DeclareExchange(ch *amqp.Channel, exchangeName string) error {
	exchangeName = strings.TrimSpace(exchangeName)
	if exchangeName == "" {
		exchangeName = DefaultExchangeName
	}
	if err := ch.ExchangeDeclare(
		exchangeName,
		"topic",
		true,  // durable
		false, // auto-deleted
		false, // internal
		false, // no-wait
		nil,
	); err != nil {
		return fmt.Errorf("declare audit exchange %q: %w", exchangeName, err)
	}
	return nil
}

// DeclareTopology idempotently declares the topic exchange, the dead-letter queue (<queue>.dlq),
// and the main durable worker queue bound to the exchange with `audit.#`.
func DeclareTopology(ch *amqp.Channel, exchangeName, queueName string) error {
	exchangeName = strings.TrimSpace(exchangeName)
	if exchangeName == "" {
		exchangeName = DefaultExchangeName
	}
	queueName = strings.TrimSpace(queueName)
	if queueName == "" {
		queueName = DefaultQueueName
	}

	if err := DeclareExchange(ch, exchangeName); err != nil {
		return err
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
		return fmt.Errorf("declare audit dlq %q: %w", dlqName, err)
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
		return fmt.Errorf("declare audit queue %q: %w", queueName, err)
	}

	if err := ch.QueueBind(
		queueName,
		DefaultBindingKey,
		exchangeName,
		false, // noWait
		nil,
	); err != nil {
		return fmt.Errorf("bind audit queue %q to exchange %q: %w", queueName, exchangeName, err)
	}

	return nil
}
