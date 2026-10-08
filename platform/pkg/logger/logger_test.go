package logger

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestLoggerPreservesRepeatedEvents(t *testing.T) {
	log, err := New(Config{
		ServiceName: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Sync(log) })
	entry := zapcore.Entry{
		Time:    time.Now(),
		Level:   zap.InfoLevel,
		Message: "HTTP request",
	}
	for range 250 {
		if log.Core().Check(entry, nil) == nil {
			t.Fatal("request log was sampled")
		}
	}
}

func TestLoggerRejectsInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config Config
	}{
		{
			name: "missing service",
			config: Config{
				Level: "info",
			},
		},
		{
			name: "invalid level",
			config: Config{
				ServiceName: "test",
				Level:       "unknown",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.config); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestErrorFieldsExcludePrivateDetails(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		kind  string
		state string
	}{
		{
			name: "wrapped deadline",
			err:  fmt.Errorf("private detail: %w", context.DeadlineExceeded),
			kind: "timeout",
		},
		{
			name: "cancelled",
			err:  context.Canceled,
			kind: "cancelled",
		},
		{
			name: "postgresql",
			err: &pgconn.PgError{
				Code:    "23505",
				Message: "private detail",
				Detail:  "private detail",
			},
			kind:  "postgresql",
			state: "23505",
		},
		{
			name: "wrapped PostgreSQL failure",
			err: fmt.Errorf("register account transaction: %w",
				fmt.Errorf("create user: %w", &pgconn.PgError{
					Code:    "23505",
					Message: "private detail",
				})),
			kind:  "postgresql",
			state: "23505",
		},
		{
			name: "wrapped cancellation",
			err:  fmt.Errorf("load user: %w", context.Canceled),
			kind: "cancelled",
		},
		{
			name: "unknown",
			err:  errors.New("private detail"),
			kind: "internal",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zap.ErrorLevel)
			zap.New(core).Error("request failed", ErrorFields(tc.err)...)
			fields := logs.All()[0].ContextMap()
			if fields["error_kind"] != tc.kind {
				t.Fatalf("fields=%v", fields)
			}
			if tc.state != "" && fields["sqlstate"] != tc.state {
				t.Fatalf("fields=%v", fields)
			}
			for _, value := range fields {
				if value == "private detail" {
					t.Fatal("private error detail logged")
				}
			}
		})
	}
}
