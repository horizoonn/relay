package httpmiddleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestPanicRecovery(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		status  int
		abort   bool
		logged  bool
	}{
		{
			name: "successful request",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
			status: http.StatusNoContent,
		},
		{
			name: "panic before response",
			handler: func(http.ResponseWriter, *http.Request) {
				panic("private-marker")
			},
			status: http.StatusInternalServerError,
			logged: true,
		},
		{
			name: "panic after response",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				panic("private-marker")
			},
			status: http.StatusOK,
			abort:  true,
			logged: true,
		},
		{
			name: "intentional server abort",
			handler: func(http.ResponseWriter, *http.Request) {
				panic(http.ErrAbortHandler)
			},
			status: http.StatusOK,
			abort:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zap.ErrorLevel)
			handler := Recovery(zap.New(core), tc.handler, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})
			response := httptest.NewRecorder()
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				handler.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
			}()
			abortErr, _ := recovered.(error)
			if errors.Is(abortErr, http.ErrAbortHandler) != tc.abort || response.Code != tc.status {
				t.Fatalf("panic=%v status=%d", recovered, response.Code)
			}
			if (logs.Len() == 1) != tc.logged {
				t.Fatalf("log count=%d", logs.Len())
			}
			for _, entry := range logs.All() {
				if entry.ContextMap()["error_kind"] != "panic" || len(entry.Context) != 2 {
					t.Fatal("panic diagnostics contain unexpected data")
				}
			}
		})
	}
}
