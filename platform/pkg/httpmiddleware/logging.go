package httpmiddleware

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"
)

type operationKey struct{}

type requestOperation struct {
	name string
}

func SetOperation(ctx context.Context, name string) {
	if operation, ok := ctx.Value(operationKey{}).(*requestOperation); ok {
		operation.name = name
	}
}

func AccessLog(log *zap.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		operation := &requestOperation{}
		ctx := context.WithValue(r.Context(), operationKey{}, operation)
		response := &statusWriter{
			ResponseWriter: w,
		}
		completed := false
		defer func() {
			status := response.status
			if !completed && status == 0 {
				status = http.StatusInternalServerError
			} else if status == 0 {
				status = http.StatusOK
			}
			log.Info("HTTP request",
				zap.String("method", r.Method),
				zap.String("operation", operation.name),
				zap.Int("status", status),
				zap.String("request_id", response.Header().Get("X-Request-ID")),
				zap.Duration("duration", time.Since(started)),
			)
		}()
		next.ServeHTTP(response, r.WithContext(ctx))
		completed = true
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	if status < http.StatusOK {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
