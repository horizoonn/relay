package contentv1

import (
	"context"
	"net/http"
	"strings"
	"uuid"
)

const maxJSONBodyBytes = 512 << 10

type requestIDKey struct{}

func requestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if len(id) == 0 || len(id) > 128 || strings.ContainsAny(id, "\r\n\x00") {
			id = uuid.New().String()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := withRequestID(r.Context(), id)
		ctx = withRequestOrigin(ctx, r.Header.Get("Origin"))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func bodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}
