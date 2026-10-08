package httpmiddleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestRequestIDsValidateAndPropagate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		values    []string
		preserved bool
	}{
		{
			name:      "valid",
			values:    []string{"client-id"},
			preserved: true,
		},
		{
			name: "missing",
		},
		{
			name:   "duplicate",
			values: []string{"first", "second"},
		},
		{
			name:   "oversized",
			values: []string{strings.Repeat("x", 129)},
		},
		{
			name:   "NUL",
			values: []string{"a\x00b"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			for _, value := range tc.values {
				request.Header.Add("X-Request-ID", value)
			}
			RequestIDs(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				id := RequestID(r.Context())
				if id == "" || id != w.Header().Get("X-Request-ID") {
					t.Fatal("request ID not propagated")
				}
				if tc.preserved && id != tc.values[0] {
					t.Fatal("valid ID replaced")
				}
				if !tc.preserved && len(tc.values) > 0 && id == tc.values[0] {
					t.Fatal("invalid ID retained")
				}
			})).ServeHTTP(response, request)
		})
	}
}

func TestDeadlineCancelsWork(t *testing.T) {
	Deadline(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			if r.Context().Err() != context.DeadlineExceeded {
				t.Fatal("unexpected cancellation")
			}
		case <-time.After(time.Second):
			t.Fatal("handler work did not time out")
		}
	}), 10*time.Millisecond).ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil),
	)
}

func TestAccessLogFields(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		writeBody bool
	}{
		{
			name:   "implicit status",
			status: 200,
		},
		{
			name:      "body",
			status:    200,
			writeBody: true,
		},
		{
			name:   "error",
			status: 503,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zap.InfoLevel)
			handler := AccessLog(
				zap.New(core).With(zap.String("service", "test")),
				RequestIDs(PrivateResponses(http.HandlerFunc(func(
					w http.ResponseWriter,
					r *http.Request,
				) {
					SetOperation(r.Context(), "GetItem")
					if tc.status != 200 {
						w.WriteHeader(tc.status)
					}
					if tc.writeBody {
						_, _ = w.Write([]byte("ok"))
					}
				}))),
			)
			response := httptest.NewRecorder()
			handler.ServeHTTP(
				response,
				httptest.NewRequestWithContext(
					t.Context(),
					http.MethodGet,
					"/private?token=private-marker",
					nil,
				),
			)
			fields := logs.All()[0].ContextMap()
			if fields["operation"] != "GetItem" ||
				fields["status"] != int64(tc.status) ||
				fields["service"] != "test" ||
				fields["request_id"] == "" {
				t.Fatalf("fields=%v", fields)
			}
			if response.Header().Get("Cache-Control") != "no-store" ||
				response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing private response headers")
			}
			if _, ok := fields["url"]; ok {
				t.Fatal("private URL logged")
			}
		})
	}
}
