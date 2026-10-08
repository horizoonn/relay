package identityv1

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReadinessResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{
			name:   "available",
			status: http.StatusOK,
		},
		{
			name:   "unavailable",
			err:    errors.New("private database detail"),
			status: http.StatusServiceUnavailable,
		},
		{
			name:   "deadline exceeded",
			err:    context.DeadlineExceeded,
			status: http.StatusServiceUnavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			handler := Readyz(func(ctx context.Context) error {
				called = true
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > time.Second {
					t.Fatal("readiness check has no bounded deadline")
				}
				return tc.err
			})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil))
			if !called || response.Code != tc.status {
				t.Fatalf("called=%v status=%d", called, response.Code)
			}
			if strings.Contains(response.Body.String(), "private database detail") {
				t.Fatal("dependency details leaked into response")
			}
		})
	}
}

func TestHealthz(t *testing.T) {
	response := httptest.NewRecorder()
	Healthz(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d", response.Code)
	}
}
