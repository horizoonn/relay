package smtp

import (
	"context"
	"errors"
	"net"
	"net/textproto"
)

var ErrUnavailable = errors.New("SMTP delivery unavailable")

type DeliveryError struct {
	Operation string
	Kind      string
	permanent bool
}

func (e *DeliveryError) Error() string {
	return "SMTP " + e.Operation + ": " + e.Kind
}

func (e *DeliveryError) Permanent() bool {
	return e.Operation == "validate" || e.permanent
}

func (e *DeliveryError) Unwrap() error { return ErrUnavailable }

func deliveryError(operation string, err error) *DeliveryError {
	result := &DeliveryError{
		Operation: operation,
		Kind:      "protocol",
	}
	var network net.Error
	var reply *textproto.Error
	switch {
	case errors.Is(err, context.Canceled):
		result.Kind = "cancelled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &network) && network.Timeout():
		result.Kind = "timeout"
	case errors.As(err, &reply):
		result.Kind = "smtp_rejected"
		result.permanent = operation == "recipient" && reply.Code >= 500 && reply.Code < 600
	case operation == "tls":
		result.Kind = "tls_failed"
	case operation == "authentication":
		result.Kind = "authentication_failed"
	case operation == "connect":
		result.Kind = "connection_failed"
	}
	return result
}
