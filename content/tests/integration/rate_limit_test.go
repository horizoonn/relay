//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/ratelimit"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	contentlimit "github.com/horizoonn/relay/content/internal/ratelimit"
)

func rateLimitRedis(t *testing.T) *redis.Client {
	t.Helper()
	value := os.Getenv("RELAY_CONTENT_TEST_REDIS_URL")
	if value == "" {
		t.Fatal("RELAY_CONTENT_TEST_REDIS_URL must point to isolated Redis")
	}
	opts, err := redis.ParseURL(value)
	if err != nil {
		t.Fatal(err)
	}
	opts.MaxRetries = -1
	opts.DialerRetries = 1
	opts.ContextTimeoutEnabled = true
	client := redis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(t.Context()).Err(); err != nil {
		t.Fatal(err)
	}
	return client
}

func rateLimitRules() map[contentlimit.Scope]ratelimit.Rule {
	rules := map[contentlimit.Scope]ratelimit.Rule{}
	for _, scope := range []contentlimit.Scope{
		contentlimit.Capture,
		contentlimit.Write,
		contentlimit.Read,
		contentlimit.Search,
	} {
		rules[scope] = ratelimit.Rule{
			Rate:   1,
			Period: time.Hour,
			Burst:  7,
		}
	}
	return rules
}

func TestContentRateLimitAcrossClients(t *testing.T) {
	key, subject := uuid.NewV7().String(), uuid.NewV7().String()
	clients := make([]*contentlimit.Limiter, 2)
	for i := range clients {
		limiter, err := contentlimit.NewLimiter(rateLimitRedis(t), []byte(key), time.Second, rateLimitRules(), zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		clients[i] = limiter
	}
	var allowed atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 40 {
		wg.Go(func() {
			<-start
			err := clients[i%2].Allow(t.Context(), contentlimit.Search, subject)
			if err == nil {
				allowed.Add(1)
				return
			}
			var exceeded *ratelimit.ExceededError
			if !errors.As(err, &exceeded) {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()
	if allowed.Load() != 7 {
		t.Fatalf("allowed=%d want=7", allowed.Load())
	}
	for _, tc := range []struct {
		name    string
		scope   contentlimit.Scope
		subject string
	}{
		{
			name:    "capture independent",
			scope:   contentlimit.Capture,
			subject: subject,
		}, {
			name:    "owner independent",
			scope:   contentlimit.Search,
			subject: uuid.NewV7().String(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := clients[0].Allow(t.Context(), tc.scope, tc.subject); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestContentRateLimitFallbackIsBounded(t *testing.T) {
	for _, scope := range []contentlimit.Scope{
		contentlimit.Capture,
		contentlimit.Write,
		contentlimit.Read,
		contentlimit.Search,
	} {
		t.Run(string(scope), func(t *testing.T) {
			client := rateLimitRedis(t)
			limiter, err := contentlimit.NewLimiter(
				client,
				[]byte(uuid.NewV7().String()),
				time.Second,
				rateLimitRules(),
				zap.NewNop(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if err := limiter.Allow(t.Context(), scope, "owner"); err != nil {
				t.Fatal(err)
			}
			denied := false
			for range 200 {
				var exceeded *ratelimit.ExceededError
				err := limiter.Allow(t.Context(), scope, uuid.NewV7().String())
				if errors.As(err, &exceeded) {
					denied = true
				} else if err != nil {
					t.Fatal(err)
				}
			}
			if !denied {
				t.Fatal("fallback did not bound traffic across owners")
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := limiter.Allow(ctx, scope, "owner"); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled request: %v", err)
			}
		})
	}
}
