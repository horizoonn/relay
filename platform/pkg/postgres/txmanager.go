package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type TxManager struct {
	pool *pgxpool.Pool
}

func NewTxManager(pool *pgxpool.Pool) *TxManager {
	return &TxManager{
		pool: pool,
	}
}

// WithinTransaction joins an existing transaction from this manager or starts one.
func (m *TxManager) WithinTransaction(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	if m.txFromContext(ctx) != nil {
		return fn(ctx)
	}
	return pgx.BeginFunc(ctx, m.pool, func(tx pgx.Tx) error {
		return fn(m.contextWithTx(ctx, tx))
	})
}

func (m *TxManager) Executor(ctx context.Context) Executor {
	if tx := m.txFromContext(ctx); tx != nil {
		return tx
	}
	return m.pool
}
