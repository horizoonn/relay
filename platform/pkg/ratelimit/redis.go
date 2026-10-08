package ratelimit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis_rate/v10"
	"github.com/redis/go-redis/v9"
)

type RedisLimiter struct {
	remote    *redis_rate.Limiter
	namespace string
	key       []byte
	timeout   time.Duration
}

func NewRedisLimiter(
	client *redis.Client,
	namespace string,
	key []byte,
	timeout time.Duration,
) (*RedisLimiter, error) {
	if client == nil || namespace == "" || len(namespace) > 64 ||
		strings.ContainsAny(namespace, "\x00 \r\n") || len(key) < 32 ||
		timeout <= 0 || timeout > time.Second {
		return nil, errors.New("invalid Redis rate limiter configuration")
	}
	return &RedisLimiter{
		remote:    redis_rate.NewLimiter(client),
		namespace: namespace,
		key:       append([]byte(nil), key...),
		timeout:   timeout,
	}, nil
}

func (l *RedisLimiter) Allow(
	ctx context.Context,
	scope string,
	subject string,
	rule Rule,
) error {
	if scope == "" || strings.ContainsRune(scope, '\x00') || subject == "" {
		return errors.New("invalid rate limit request")
	}
	if err := rule.Validate(); err != nil {
		return fmt.Errorf("validate rate limit rule: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	operation, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()
	mac := hmac.New(sha256.New, l.key)
	_, _ = mac.Write([]byte(scope + "\x00" + subject))
	key := l.namespace + ":" + scope + ":" + hex.EncodeToString(mac.Sum(nil))
	result, err := l.remote.Allow(operation, key, redis_rate.Limit{
		Rate:   rule.Rate,
		Period: rule.Period,
		Burst:  rule.Burst,
	})
	if err != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		return ErrUnavailable
	}
	if result.Allowed == 0 {
		return &ExceededError{
			RetryAfter: result.RetryAfter,
		}
	}
	return nil
}
