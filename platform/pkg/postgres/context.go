package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
)

type txKey struct {
	manager *TxManager
}

func (m *TxManager) txFromContext(ctx context.Context) pgx.Tx {
	tx, _ := ctx.Value(txKey{
		manager: m,
	}).(pgx.Tx)
	return tx
}

func (m *TxManager) contextWithTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, txKey{
		manager: m,
	}, tx)
}
