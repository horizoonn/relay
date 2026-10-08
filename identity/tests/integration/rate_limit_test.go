//go:build integration

package integration

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/ratelimit"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
)

func redisConnection(t *testing.T) *redis.Client {
	t.Helper()
	value := os.Getenv("RELAY_IDENTITY_TEST_REDIS_URL")
	if value == "" {
		t.Fatal("RELAY_IDENTITY_TEST_REDIS_URL must point to isolated Redis")
	}
	options, err := redis.ParseURL(value)
	if err != nil {
		t.Fatal(err)
	}
	options.MaxRetries = -1
	options.DialerRetries = 1
	options.DialTimeout = time.Second
	options.ReadTimeout = time.Second
	options.WriteTimeout = time.Second
	options.ContextTimeoutEnabled = true
	client := redis.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(t.Context()).Err(); err != nil {
		t.Fatal(err)
	}
	return client
}

func redisRules() map[identitylimit.Scope]ratelimit.Rule {
	rules := make(map[identitylimit.Scope]ratelimit.Rule)
	for _, scope := range []identitylimit.Scope{
		identitylimit.LoginIP,
		identitylimit.LoginAccount,
		identitylimit.RegisterIP,
		identitylimit.RefreshIP,
		identitylimit.ReadUser,
		identitylimit.LogoutIP,
		identitylimit.RevokeUser,
		identitylimit.EmailIP,
		identitylimit.EmailAccount,
		identitylimit.ActionIP,
	} {
		rules[scope] = ratelimit.Rule{
			Rate:   1,
			Period: time.Hour,
			Burst:  7,
		}
	}
	return rules
}

func newRedisLimiter(
	t *testing.T,
	client *redis.Client,
	key string,
	rules map[identitylimit.Scope]ratelimit.Rule,
) *identitylimit.Limiter {
	t.Helper()
	limiter, err := identitylimit.NewLimiter(client, []byte(key), time.Second, rules, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	return limiter
}

func TestConcurrentRateLimitAcrossClients(t *testing.T) {
	key, subject := uuid.NewV7().String(), uuid.NewV7().String()+"@example.com"
	first := newRedisLimiter(t, redisConnection(t), key, redisRules())
	second := newRedisLimiter(t, redisConnection(t), key, redisRules())
	var allowed atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Go(func() {
			<-start
			limiter := first
			if i%2 != 0 {
				limiter = second
			}
			err := limiter.Allow(t.Context(), identitylimit.LoginAccount, subject)
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

	if err := first.Allow(t.Context(), identitylimit.RegisterIP, subject); err != nil {
		t.Fatal(err)
	}
	if err := first.Allow(t.Context(), identitylimit.LoginAccount, "other-"+subject); err != nil {
		t.Fatal(err)
	}
}

func rateKeys(t *testing.T, client *redis.Client) map[string]bool {
	t.Helper()
	keys := make(map[string]bool)
	var cursor uint64
	for {
		batch, next, err := client.Scan(t.Context(), cursor, "rate:identity:v1:*", 100).Result()
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range batch {
			keys[key] = true
		}
		cursor = next
		if cursor == 0 {
			return keys
		}
	}
}

func TestRateLimitExpirationAndScriptReload(t *testing.T) {
	client := redisConnection(t)
	rules := redisRules()
	rules[identitylimit.LoginAccount] = ratelimit.Rule{
		Rate:   1,
		Period: time.Second,
		Burst:  1,
	}
	limiter := newRedisLimiter(t, client, uuid.NewV7().String(), rules)
	subject := uuid.NewV7().String() + "@example.com"
	before := rateKeys(t, client)
	if err := limiter.Allow(t.Context(), identitylimit.LoginAccount, subject); err != nil {
		t.Fatal(err)
	}
	var key string
	for candidate := range rateKeys(t, client) {
		if !before[candidate] {
			if key != "" {
				t.Fatal("more than one state key created")
			}
			key = candidate
		}
	}
	if key == "" || strings.Contains(key, subject) || strings.Contains(key, "example.com") {
		t.Fatal("state key missing or exposes email")
	}
	initialTTL, err := client.PTTL(t.Context(), key).Result()
	if err != nil || initialTTL <= 0 {
		t.Fatalf("TTL=%v err=%v", initialTTL, err)
	}
	for range 10 {
		allowErr := limiter.Allow(t.Context(), identitylimit.LoginAccount, subject)
		var exceeded *ratelimit.ExceededError
		if !errors.As(allowErr, &exceeded) || exceeded.RetryAfter <= 0 {
			t.Fatalf("expected rejection, got %v", allowErr)
		}
	}
	ttl, err := client.PTTL(t.Context(), key).Result()
	if err != nil || ttl > initialTTL {
		t.Fatalf("denial extended TTL: before=%v after=%v err=%v", initialTTL, ttl, err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := limiter.Allow(ctx, identitylimit.LoginAccount, subject)
		if err == nil {
			break
		}
		var exceeded *ratelimit.ExceededError
		if !errors.As(err, &exceeded) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("budget did not refill")
		case <-ticker.C:
		}
	}

	if err := client.ScriptFlush(t.Context()).Err(); err != nil {
		t.Fatal(err)
	}
	if err := limiter.Allow(t.Context(), identitylimit.RegisterIP, subject); err != nil {
		t.Fatalf("NOSCRIPT fallback failed: %v", err)
	}
}

func TestRedisFailurePolicies(t *testing.T) {
	client := redisConnection(t)
	limiter := newRedisLimiter(t, client, uuid.NewV7().String(), redisRules())
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		scope       identitylimit.Scope
		unavailable bool
	}{
		{
			name:        "login IP",
			scope:       identitylimit.LoginIP,
			unavailable: true,
		},
		{
			name:        "login account",
			scope:       identitylimit.LoginAccount,
			unavailable: true,
		},
		{
			name:        "registration",
			scope:       identitylimit.RegisterIP,
			unavailable: true,
		},
		{
			name:        "refresh",
			scope:       identitylimit.RefreshIP,
			unavailable: true,
		},
		{
			name:        "email IP",
			scope:       identitylimit.EmailIP,
			unavailable: true,
		},
		{
			name:        "email account",
			scope:       identitylimit.EmailAccount,
			unavailable: true,
		},
		{
			name:        "account action",
			scope:       identitylimit.ActionIP,
			unavailable: true,
		},
		{
			name:        "read sessions",
			scope:       identitylimit.ReadUser,
			unavailable: false,
		},
		{
			name:        "logout",
			scope:       identitylimit.LogoutIP,
			unavailable: false,
		},
		{
			name:        "revoke",
			scope:       identitylimit.RevokeUser,
			unavailable: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := limiter.Allow(t.Context(), tc.scope, "subject")
			if tc.unavailable {
				if !errors.Is(err, ratelimit.ErrUnavailable) {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
	denied := false
	for range 200 {
		err := limiter.Allow(t.Context(), identitylimit.LogoutIP, "another IP")
		var exceeded *ratelimit.ExceededError
		if errors.As(err, &exceeded) {
			denied = true
		}
	}
	if !denied {
		t.Fatal("local fallback did not bound traffic")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := limiter.Allow(ctx, identitylimit.LogoutIP, "subject"); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled request used fallback")
	}
}

func TestRateLimitRedisTimeout(t *testing.T) {
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections []net.Conn
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}

			connections = append(connections, conn)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-accepted
		for _, conn := range connections {
			_ = conn.Close()
		}
	})
	client := redis.NewClient(&redis.Options{
		Addr:                  listener.Addr().String(),
		MaxRetries:            -1,
		DialerRetries:         1,
		DialTimeout:           time.Second,
		ReadTimeout:           5 * time.Second,
		WriteTimeout:          5 * time.Second,
		ContextTimeoutEnabled: true,
	})
	t.Cleanup(func() { _ = client.Close() })
	limiter, err := identitylimit.NewLimiter(
		client,
		[]byte(uuid.NewV7().String()),
		100*time.Millisecond,
		redisRules(),
		zap.NewNop(),
	)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err = limiter.Allow(t.Context(), identitylimit.LoginIP, "192.0.2.1")
	if !errors.Is(err, ratelimit.ErrUnavailable) {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("deadline did not bound network wait: %s", elapsed)
	}
}
