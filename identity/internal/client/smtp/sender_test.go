package smtp

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/horizoonn/relay/identity/internal/usecase/email"
)

func TestSenderRejectsInvalidConfiguration(t *testing.T) {
	valid := Config{
		Address: "localhost:1025",
		From:    "no-reply@example.com",
		Timeout: time.Second,
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{
			name: "missing port",
			change: func(c *Config) {
				c.Address = "localhost"
			},
		},
		{
			name: "zero port",
			change: func(c *Config) {
				c.Address = "localhost:0"
			},
		},
		{
			name: "named port",
			change: func(c *Config) {
				c.Address = "localhost:smtp"
			},
		},
		{
			name: "port out of range",
			change: func(c *Config) {
				c.Address = "localhost:65536"
			},
		},
		{
			name: "invalid sender",
			change: func(c *Config) {
				c.From = "bad\r\nTo: victim@example.com"
			},
		},
		{
			name: "missing timeout",
			change: func(c *Config) {
				c.Timeout = 0
			},
		},
		{
			name: "missing password",
			change: func(c *Config) {
				c.Username = "user"
			},
		},
		{
			name: "credentials over plaintext",
			change: func(c *Config) {
				c.Username = "user"
				c.Password = "secret"
				c.AllowInsecure = true
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.change(&cfg)
			if _, err := New(cfg, zap.NewNop()); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestDeliveryErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		name      string
		operation string
		err       error
		kind      string
		permanent bool
	}{
		{
			name:      "temporary rejection",
			operation: "recipient",
			err: &textproto.Error{
				Code: 451,
				Msg:  "private-marker",
			},
			kind: "smtp_rejected",
		},
		{
			name:      "permanent rejection",
			operation: "recipient",
			err: &textproto.Error{
				Code: 550,
				Msg:  "private-marker",
			},
			kind:      "smtp_rejected",
			permanent: true,
		},
		{
			name:      "authentication",
			operation: "authentication",
			err:       errors.New("private-marker"),
			kind:      "authentication_failed",
		},
		{
			name:      "TLS",
			operation: "tls",
			err:       errors.New("private-marker"),
			kind:      "tls_failed",
		},
		{
			name:      "timeout",
			operation: "greeting",
			err:       context.DeadlineExceeded,
			kind:      "timeout",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := deliveryError(tc.operation, tc.err)
			if !errors.Is(err, ErrUnavailable) ||
				err.Operation != tc.operation ||
				err.Kind != tc.kind ||
				err.Permanent() != tc.permanent {
				t.Fatalf("classification=%+v", err)
			}
			if strings.Contains(err.Error(), "private-marker") {
				t.Fatal("SMTP reply leaked")
			}
		})
	}
}

func TestPermanentDeliveryErrors(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failure   *DeliveryError
		permanent bool
	}{
		{
			name: "invalid message",
			failure: &DeliveryError{
				Operation: "validate",
			},
			permanent: true,
		},
		{
			name: "recipient rejected",
			failure: deliveryError("recipient", &textproto.Error{
				Code: 550,
			}),
			permanent: true,
		},
		{
			name: "recipient temporarily unavailable",
			failure: deliveryError("recipient", &textproto.Error{
				Code: 451,
			}),
		},
		{
			name:    "TLS configuration",
			failure: deliveryError("tls", errors.New("certificate invalid")),
		},
		{
			name:    "SMTP credentials",
			failure: deliveryError("authentication", errors.New("authentication failed")),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.failure.Permanent() != tc.permanent {
				t.Fatalf("permanent=%t", tc.failure.Permanent())
			}
		})
	}
}

func TestSenderTLSAndTimeout(t *testing.T) {
	for _, tc := range []struct {
		name  string
		greet bool
	}{{
		name:  "plaintext SMTP rejected",
		greet: true,
	}, {
		name:  "silent SMTP times out",
		greet: false,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			t.Cleanup(func() { _ = listener.Close(); <-done })
			go func() {
				defer close(done)
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				if tc.greet {
					_, _ = conn.Write([]byte("220 test SMTP\r\n"))
					reader := bufio.NewReader(conn)
					line, readErr := reader.ReadString('\n')
					if readErr == nil && strings.HasPrefix(line, "EHLO") {
						_, _ = conn.Write([]byte("250 test\r\n"))
					}
					_, _ = reader.ReadString('\n')
				} else {
					_, _ = bufio.NewReader(conn).ReadString('\n')
				}
			}()
			sender, err := New(Config{
				Address: listener.Addr().String(),
				From:    "no-reply@example.com",
				Timeout: 100 * time.Millisecond,
			}, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			err = sender.Send(t.Context(), email.Mail{
				To:      "user@example.com",
				Subject: "Test",
				Body:    "test\r\n",
			})
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("error=%v", err)
			}
			if time.Since(started) > time.Second {
				t.Fatal("SMTP exceeded operation deadline")
			}
		})
	}
	sender, err := New(Config{
		Address: "127.0.0.1:1",
		From:    "no-reply@example.com",
		Timeout: time.Second,
	}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := sender.Send(ctx, email.Mail{
		To:      "user@example.com",
		Subject: "Test",
		Body:    "text",
	}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cancelled SMTP succeeded")
	}
}
