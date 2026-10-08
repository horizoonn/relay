package smtp

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"
	"time"
	"uuid"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/horizoonn/relay/identity/internal/usecase/email"
)

func TestSenderDelivery(t *testing.T) {
	for _, tc := range []struct {
		name            string
		acknowledgement string
		quit            string
		failed          bool
	}{
		{
			name:            "accepted",
			acknowledgement: "250 accepted",
			quit:            "221 bye",
		},
		{
			name:            "accepted despite QUIT failure",
			acknowledgement: "250 accepted",
			quit:            "500 private-marker",
		},
		{
			name:            "DATA rejected",
			acknowledgement: "550 rejected",
			failed:          true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			messages := make(chan string, 1)
			done := make(chan error, 1)
			t.Cleanup(func() { _ = listener.Close() })
			go func() {
				done <- serveMessage(listener, messages, tc.acknowledgement, tc.quit)
			}()
			core, logs := observer.New(zap.WarnLevel)
			sender, err := New(Config{
				Address:       listener.Addr().String(),
				From:          "no-reply@example.com",
				AllowInsecure: true,
				Timeout:       time.Second,
			}, zap.New(core))
			if err != nil {
				t.Fatal(err)
			}
			message := email.Mail{
				ID:        uuid.NewV7(),
				CreatedAt: time.Now().UTC().Truncate(time.Second),
				To:        "user@example.com",
				Subject:   "Confirm your email",
				Body:      "First line\r\n.Second line\r\n",
			}
			err = sender.Send(t.Context(), message)
			if errors.Is(err, ErrUnavailable) != tc.failed {
				t.Fatalf("send error=%v", err)
			}
			warnings := logs.All()
			if strings.HasPrefix(tc.quit, "500") {
				if len(warnings) != 1 || warnings[0].ContextMap()["operation"] != "quit" ||
					warnings[0].ContextMap()["error_kind"] != "smtp_rejected" {
					t.Fatalf("QUIT failure was not reported safely: %+v", warnings)
				}
				for _, field := range warnings[0].Context {
					if strings.Contains(field.String, "private-marker") {
						t.Fatal("SMTP reply leaked into diagnostics")
					}
				}
			} else if len(warnings) != 0 {
				t.Fatalf("unexpected cleanup warnings: %+v", warnings)
			}
			if peerErr := <-done; peerErr != nil {
				t.Fatal(peerErr)
			}
			parsed, err := mail.ReadMessage(strings.NewReader(<-messages))
			if err != nil {
				t.Fatal(err)
			}
			date, err := parsed.Header.Date()
			if err != nil || !date.Equal(message.CreatedAt) {
				t.Fatalf("Date=%q error=%v", parsed.Header.Get("Date"), err)
			}
			if parsed.Header.Get("Message-ID") != "<"+message.ID.String()+"@example.com>" ||
				parsed.Header.Get("To") != message.To || parsed.Header.Get("Subject") != message.Subject {
				t.Fatal("message identity or headers changed")
			}
			body, err := io.ReadAll(parsed.Body)
			if err != nil || string(body) != "First line\n.Second line\n" {
				t.Fatalf("body=%q error=%v", body, err)
			}
		})
	}
}

func TestWriteMessageErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		writeErr error
		closeErr error
		want     []string
	}{
		{
			name: "accepted",
		},
		{
			name:     "write failed",
			writeErr: errors.New("private-write-marker"),
			want:     []string{"body"},
		},
		{
			name:     "acknowledgement failed",
			closeErr: errors.New("private-ack-marker"),
			want:     []string{"acknowledgement"},
		},
		{
			name:     "write and acknowledgement failed",
			writeErr: errors.New("private-write-marker"),
			closeErr: errors.New("private-ack-marker"),
			want:     []string{"body", "acknowledgement"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &messageBody{
				writeErr: tc.writeErr,
				closeErr: tc.closeErr,
			}
			sender := &Sender{
				config: Config{
					From: "no-reply@example.com",
				},
			}
			err := sender.writeMessage(body, email.Mail{
				To:      "user@example.com",
				Subject: "Test",
				Body:    "test",
			})
			if !body.closed || errors.Is(err, ErrUnavailable) != (len(tc.want) != 0) {
				t.Fatalf("closed=%t error=%v", body.closed, err)
			}
			if err == nil {
				return
			}
			for _, operation := range tc.want {
				if !strings.Contains(err.Error(), "SMTP "+operation+":") {
					t.Fatalf("lost %s error: %v", operation, err)
				}
			}
			if strings.Contains(err.Error(), "private-") {
				t.Fatal("message failure leaked private diagnostics")
			}
		})
	}
}

type messageBody struct {
	writeErr error
	closeErr error
	closed   bool
}

func (b *messageBody) Write(data []byte) (int, error) {
	if b.writeErr != nil {
		return 0, b.writeErr
	}
	return len(data), nil
}

func (b *messageBody) Close() error {
	b.closed = true
	return b.closeErr
}

func serveMessage(
	listener net.Listener,
	messages chan<- string,
	acknowledgement, quit string,
) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if deadlineErr := conn.SetDeadline(time.Now().Add(2 * time.Second)); deadlineErr != nil {
		return deadlineErr
	}
	reader := textproto.NewReader(bufio.NewReader(conn))
	for _, step := range []struct {
		reply   string
		command string
	}{
		{
			reply:   "220 test SMTP",
			command: "EHLO",
		},
		{
			reply:   "250 test SMTP",
			command: "MAIL FROM:",
		},
		{
			reply:   "250 sender accepted",
			command: "RCPT TO:",
		},
		{
			reply:   "250 recipient accepted",
			command: "DATA",
		},
	} {
		if _, writeErr := io.WriteString(conn, step.reply+"\r\n"); writeErr != nil {
			return writeErr
		}
		line, readErr := reader.ReadLine()
		if readErr != nil {
			return readErr
		}
		if !strings.HasPrefix(line, step.command) {
			return errors.New("unexpected SMTP command")
		}
	}
	if _, writeErr := io.WriteString(conn, "354 send message\r\n"); writeErr != nil {
		return writeErr
	}
	data, err := reader.ReadDotBytes()
	if err != nil {
		return err
	}
	messages <- string(data)
	if _, err := io.WriteString(conn, acknowledgement+"\r\n"); err != nil {
		return err
	}
	if quit != "" {
		if _, err := reader.ReadLine(); err != nil {
			return err
		}
		_, err := io.WriteString(conn, quit+"\r\n")
		return err
	}
	return nil
}
