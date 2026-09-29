package contentv1

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"uuid"

	"github.com/horizoonn/relay/content/internal/usecase/capture"
	"github.com/horizoonn/relay/content/internal/usecase/collection"
	"github.com/horizoonn/relay/content/internal/usecase/item"
	"github.com/horizoonn/relay/content/internal/usecase/search"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testHandler(t *testing.T) *Handler {
	t.Helper()
	codec, err := NewCursorCodec([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	captureStore := newCaptureRouteStore()
	h, err := NewHandler(
		capture.NewService(captureStore, captureStore, routeTx{}),
		item.NewService(&routeStore{}, routeTx{}),
		collection.NewService(&routeReader{}),
		search.NewService(&routeSearch{}),
		codec,
		testLogger(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestServerErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		method     string
		path       string
		cookie     string
		origin     string
		csrf       string
		auth       fakeAuthenticator
		wantStatus int
		wantCode   string
	}{
		{
			name:   "disallowed origin",
			method: http.MethodPost,
			path:   "/api/v1/items",
			cookie: "access",
			origin: "https://evil.example",
			csrf:   "csrf",
			auth: fakeAuthenticator{
				owner: uuid.New(),
				token: "access",
				csrf:  "csrf",
			},
			wantStatus: http.StatusForbidden,
			wantCode:   "FORBIDDEN",
		},
		{
			name:   "missing cookie before origin",
			method: http.MethodPost,
			path:   "/api/v1/items",
			origin: "https://evil.example",
			csrf:   "csrf",
			auth: fakeAuthenticator{
				owner: uuid.New(),
				token: "access",
				csrf:  "csrf",
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   "UNAUTHENTICATED",
		},
		{
			name:   "invalid cookie",
			method: http.MethodGet,
			path:   "/api/v1/items/recent",
			cookie: "invalid",
			auth: fakeAuthenticator{
				owner: uuid.New(),
				token: "access",
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   "UNAUTHENTICATED",
		},
		{
			name:   "Identity timeout",
			method: http.MethodGet,
			path:   "/api/v1/items/recent",
			cookie: "access",
			auth: fakeAuthenticator{
				err: context.DeadlineExceeded,
			},
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "SERVICE_UNAVAILABLE",
		},
		{
			name:   "missing CSRF",
			method: http.MethodPost,
			path:   "/api/v1/items",
			cookie: "access",
			origin: testOrigin,
			auth: fakeAuthenticator{
				owner: uuid.New(),
				token: "access",
			},
			wantStatus: http.StatusForbidden,
			wantCode:   "FORBIDDEN",
		},
		{
			name:       "unknown route",
			method:     http.MethodPost,
			path:       "/api/v1/unknown",
			origin:     "https://evil.example",
			wantStatus: http.StatusNotFound,
			wantCode:   "ROUTE_NOT_FOUND",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server, err := NewServer(testHandler(t), tt.auth, testOrigin)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequestWithContext(context.Background(), tt.method, tt.path, strings.NewReader(`{}`))
			if tt.cookie != "" {
				request.AddCookie(&http.Cookie{
					Name:  "relay_access_token",
					Value: tt.cookie,
				})
			}
			if tt.origin != "" {
				request.Header.Set("Origin", tt.origin)
			}
			if tt.csrf != "" {
				request.Header.Set("X-CSRF-Token", tt.csrf)
			}
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			assertProblem(t, response, tt.wantStatus, tt.wantCode)
		})
	}
}

func TestServerErrorFallback(t *testing.T) {
	t.Parallel()
	response := httptest.NewRecorder()
	ctx := withRequestID(context.Background(), "request-1")
	testHandler(t).decodeError(ctx, response, nil, errors.New("encode response failed"))
	assertProblem(t, response, http.StatusInternalServerError, "INTERNAL_ERROR")
}

func TestNewServerOrigin(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		origin string
	}{
		{
			name:   "empty",
			origin: "",
		},
		{
			name:   "path",
			origin: "https://relay.example/path",
		},
		{
			name:   "wildcard",
			origin: "*",
		},
		{
			name:   "userinfo",
			origin: "https://user@relay.example",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewServer(testHandler(t), fakeAuthenticator{}, tt.origin); err == nil {
				t.Fatalf("NewServer accepted origin %q", tt.origin)
			}
		})
	}
}

func TestNewHandlerDependencies(t *testing.T) {
	t.Parallel()
	_, err := NewHandler(nil, nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("NewHandler accepted missing use cases and cursor codec")
	}
}

func TestNewServerHandler(t *testing.T) {
	t.Parallel()
	_, err := NewServer(&Handler{}, fakeAuthenticator{}, "https://relay.example")
	if err == nil {
		t.Fatal("NewServer accepted a handler without use cases")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	t.Parallel()
	srv, err := NewServer(testHandler(t), fakeAuthenticator{}, "https://relay.example")
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/v1/items", nil))
	assertProblem(t, response, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
	if response.Header().Get("Allow") != "POST" {
		t.Fatalf("Allow = %q; want POST", response.Header().Get("Allow"))
	}
}

func assertProblem(
	t *testing.T,
	response *httptest.ResponseRecorder,
	status int,
	code string,
) {
	t.Helper()
	if response.Code != status || response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("status/type = %d/%q; want %d/problem+json", response.Code, response.Header().Get("Content-Type"), status)
	}
	var body struct {
		Type      string `json:"type"`
		Status    int    `json:"status"`
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode Problem: %v; body=%s", err, response.Body.String())
	}
	if body.Status != response.Code {
		t.Fatalf("Problem status = %d; want HTTP status %d", body.Status, response.Code)
	}
	if body.Code != code || body.Type == "" || body.RequestID == "" ||
		body.RequestID != response.Header().Get("X-Request-ID") {
		t.Fatalf("Problem = %+v; want code %s and matching request ID", body, code)
	}
}
