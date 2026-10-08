//go:build integration && searchperf

package integration

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	contentrepo "github.com/horizoonn/relay/content/internal/repository/postgres"
	"github.com/horizoonn/relay/content/internal/usecase/search"
)

const searchPerformanceRows = 100_000

type searchQueryTrace struct {
	mu    sync.Mutex
	sql   string
	args  []any
	armed bool
}

func (trace *searchQueryTrace) TraceQueryStart(
	ctx context.Context,
	_ *pgx.Conn,
	data pgx.TraceQueryStartData,
) context.Context {
	trace.mu.Lock()
	if trace.armed {
		trace.sql = data.SQL
		trace.args = slices.Clone(data.Args)
		trace.armed = false
	}
	trace.mu.Unlock()
	return ctx
}

func (*searchQueryTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestSearchPerformance(t *testing.T) {
	dsn := os.Getenv("RELAY_CONTENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("RELAY_CONTENT_TEST_DATABASE_URL must point to an isolated migrated PostgreSQL 18 Content database")
	}
	maintenanceDSN := os.Getenv("RELAY_CONTENT_TEST_MIGRATOR_DATABASE_URL")
	if maintenanceDSN == "" {
		t.Fatal("RELAY_CONTENT_TEST_MIGRATOR_DATABASE_URL must use the migrator role for the same isolated database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	trace := &searchQueryTrace{}
	poolConfig.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	owner := uuid.New()
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		if _, cleanupErr := pool.Exec(cleanupCtx, `DELETE FROM content.items WHERE owner_id=$1`, owner); cleanupErr != nil {
			t.Errorf("remove search performance fixture: %v", cleanupErr)
		}
	})
	seedSearchPerformance(t, ctx, pool, owner)
	maintenance, err := pgx.Connect(ctx, maintenanceDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = maintenance.Close(context.Background()) }()
	if _, err := maintenance.Exec(ctx, `ANALYZE content.items`); err != nil {
		t.Fatalf("analyze performance fixture as migrator: %v", err)
	}

	repo := contentrepo.NewRepository(func(context.Context) postgres.Executor {
		return pool
	}, 30*time.Second)
	service := search.NewService(repo)
	for _, tc := range []struct {
		name  string
		query string
	}{
		{
			name:  "short title prefix",
			query: "Go",
		},
		{
			name:  "text substring",
			query: "backend",
		},
		{
			name:  "URL substring",
			query: "example.com/articles/99",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := search.Params{
				OwnerID: owner,
				Query:   tc.query,
				Limit:   20,
			}
			trace.mu.Lock()
			trace.sql, trace.args, trace.armed = "", nil, true
			trace.mu.Unlock()
			page, queryErr := service.Search(ctx, params)
			if queryErr != nil || len(page.Items) == 0 {
				t.Fatalf("search fixture query %q: items=%d err=%v", tc.query, len(page.Items), queryErr)
			}
			logSearchPlan(t, ctx, pool, trace)
			for range 5 {
				if _, warmupErr := service.Search(ctx, params); warmupErr != nil {
					t.Fatal(warmupErr)
				}
			}
			samples := make([]time.Duration, 100)
			for i := range samples {
				started := time.Now()
				if _, searchErr := service.Search(ctx, params); searchErr != nil {
					t.Fatal(searchErr)
				}
				samples[i] = time.Since(started)
			}
			slices.Sort(samples)
			p95, p99 := samples[94], samples[98]
			t.Logf("rows=%d query=%q p95=%s p99=%s", searchPerformanceRows, tc.query, p95, p99)
			if p95 > 500*time.Millisecond || p99 > 1500*time.Millisecond {
				t.Errorf("Search exceeds the documented p95/p99 target on this database")
			}
		})
	}
}

func seedSearchPerformance(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	owner uuid.UUID,
) {
	t.Helper()
	const query = `
		INSERT INTO content.items (
			id, owner_id, source_type, original_url, normalized_url, normalized_url_hash,
			source_text, display_title, review_status, created_at, updated_at, last_captured_at
		)
		SELECT gen_random_uuid(), $1,
			CASE WHEN n % 5 = 0 THEN 'url' ELSE 'text' END,
			CASE WHEN n % 5 = 0 THEN url END,
			CASE WHEN n % 5 = 0 THEN url END,
			CASE WHEN n % 5 = 0 THEN sha256(convert_to(url, 'UTF8')) END,
			CASE WHEN n % 5 <> 0 THEN 'Notes about backend APIs, search and PostgreSQL item ' || n END,
			CASE WHEN n % 3 = 0 THEN 'Go backend guide ' || n ELSE 'Saved page ' || n END,
			'none', now() - n * interval '1 second', now() - n * interval '1 second',
			now() - n * interval '1 second'
		FROM generate_series(1, $2::integer) AS n
		CROSS JOIN LATERAL (SELECT 'https://example.com/articles/' || n AS url) AS source
	`
	if _, err := pool.Exec(ctx, query, owner, searchPerformanceRows); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM content.items WHERE owner_id=$1`, owner).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != searchPerformanceRows {
		t.Fatalf("seeded rows = %d, want %d", count, searchPerformanceRows)
	}
	t.Logf("seeded %d items: 80%% text, 20%% URL", count)
}

func logSearchPlan(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	trace *searchQueryTrace,
) {
	t.Helper()
	trace.mu.Lock()
	sql := trace.sql
	args := slices.Clone(trace.args)
	trace.armed = false
	trace.mu.Unlock()
	if sql == "" {
		t.Fatal("search SQL was not captured for EXPLAIN")
	}
	rows, err := pool.Query(ctx, "EXPLAIN (ANALYZE, BUFFERS) "+sql, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(&plan, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	t.Logf("EXPLAIN (ANALYZE, BUFFERS):\n%s", plan.String())
}
