package logger

import (
	"context"
	"errors"
	"net"

	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"
)

func ErrorFields(err error) []zap.Field {
	var database *pgconn.PgError
	var network net.Error
	var connection *net.OpError
	switch {
	case errors.Is(err, context.Canceled):
		return []zap.Field{zap.String("error_kind", "cancelled")}
	case errors.Is(err, context.DeadlineExceeded):
		return []zap.Field{zap.String("error_kind", "timeout")}
	case errors.As(err, &database):
		return []zap.Field{zap.String("error_kind", "postgresql"), zap.String("sqlstate", database.Code)}
	case errors.As(err, &network) && network.Timeout():
		return []zap.Field{zap.String("error_kind", "timeout")}
	case errors.As(err, &connection):
		return []zap.Field{zap.String("error_kind", "connection_failed")}
	default:
		return []zap.Field{zap.String("error_kind", "internal")}
	}
}
