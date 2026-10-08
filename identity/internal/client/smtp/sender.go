package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	netsmtp "net/smtp"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/horizoonn/relay/identity/internal/usecase/email"
)

type Sender struct {
	config Config
	host   string
	log    *zap.Logger
}

func New(cfg Config, log *zap.Logger) (*Sender, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate SMTP config: %w", err)
	}
	if log == nil {
		return nil, errors.New("SMTP logger is required")
	}
	host, _, err := net.SplitHostPort(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("parse SMTP address: %w", err)
	}
	return &Sender{
		config: cfg,
		host:   host,
		log:    log,
	}, nil
}

func (s *Sender) Send(ctx context.Context, message email.Mail) error {
	recipient, err := mail.ParseAddress(message.To)
	if err != nil || recipient.Address != message.To ||
		strings.ContainsAny(message.To+message.Subject, "\r\n") ||
		len(message.Subject) > 128 || len(message.Body) > 4096 {
		return &DeliveryError{
			Operation: "validate",
			Kind:      "invalid_message",
		}
	}
	operation, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
	conn, err := (&net.Dialer{
		Timeout: s.config.Timeout,
	}).DialContext(operation, "tcp", s.config.Address)
	if err != nil {
		return deliveryError("connect", err)
	}
	closeConnection := sync.OnceFunc(func() {
		if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			s.logCleanupError("close", closeErr)
		}
	})
	defer closeConnection()
	deadline, _ := operation.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return deliveryError("deadline", err)
	}
	stop := context.AfterFunc(operation, closeConnection)
	defer stop()
	client, err := netsmtp.NewClient(conn, s.host)
	if err != nil {
		return deliveryError("greeting", err)
	}
	if err = s.secure(client); err != nil {
		return err
	}
	if err = client.Mail(s.config.From); err != nil {
		return deliveryError("mail", err)
	}
	if err = client.Rcpt(recipient.Address); err != nil {
		return deliveryError("recipient", err)
	}
	body, err := client.Data()
	if err != nil {
		return deliveryError("data", err)
	}
	if err = s.writeMessage(body, message); err != nil {
		return err
	}
	if quitErr := client.Quit(); quitErr != nil {
		s.logCleanupError("quit", quitErr)
	}
	return nil
}

func (s *Sender) logCleanupError(operation string, err error) {
	failure := deliveryError(operation, err)
	s.log.Warn("SMTP connection cleanup failed",
		zap.String("operation", failure.Operation),
		zap.String("error_kind", failure.Kind),
	)
}

func (s *Sender) secure(client *netsmtp.Client) error {
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{
			ServerName: s.host,
			MinVersion: tls.VersionTLS12,
		}); err != nil {
			return deliveryError("tls", err)
		}
	} else if !s.config.AllowInsecure {
		return &DeliveryError{
			Operation: "tls",
			Kind:      "tls_required",
		}
	}
	if s.config.Username != "" {
		if err := client.Auth(netsmtp.PlainAuth("", s.config.Username, s.config.Password, s.host)); err != nil {
			return deliveryError("authentication", err)
		}
	}
	return nil
}
