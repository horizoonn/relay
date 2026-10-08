package httpmiddleware

import (
	"errors"
	"net/http"

	"go.uber.org/zap"
)

func Recovery(log *zap.Logger, next http.Handler, failed http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := &statusWriter{
			ResponseWriter: w,
		}
		defer func(r *http.Request) {
			value := recover()
			if value == nil {
				return
			}
			if err, ok := value.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(http.ErrAbortHandler)
			}
			log.Error("HTTP handler panicked",
				zap.String("request_id", RequestID(r.Context())),
				zap.String("error_kind", "panic"),
			)
			if response.status != 0 {
				panic(http.ErrAbortHandler)
			}
			failed(response, r)
		}(r)
		next.ServeHTTP(response, r)
	})
}
