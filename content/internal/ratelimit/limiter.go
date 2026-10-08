package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"time"

	platformlimit "github.com/horizoonn/relay/platform/pkg/ratelimit"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

type Limiter struct {
	remote    *platformlimit.RedisLimiter
	rules     map[Scope]platformlimit.Rule
	fallback  map[Scope]*rate.Limiter
	log       *zap.Logger
	outageLog *rate.Limiter
}

func NewLimiter(
	client *redis.Client,
	key []byte,
	timeout time.Duration,
	rules map[Scope]platformlimit.Rule,
	log *zap.Logger,
) (*Limiter, error) {
	if log == nil {
		return nil, errors.New("rate limiter logger is required")
	}
	remote, err := platformlimit.NewRedisLimiter(client, "content:v1", key, timeout)
	if err != nil {
		return nil, fmt.Errorf("initialize Redis rate limiter: %w", err)
	}
	limits := make(map[Scope]platformlimit.Rule, 4)
	for _, scope := range []Scope{Capture, Write, Read, Search} {
		rule, ok := rules[scope]
		if !ok {
			return nil, fmt.Errorf("missing rate limit rule for %s", scope)
		}
		if err := rule.Validate(); err != nil {
			return nil, fmt.Errorf("validate rate limit rule for %s: %w", scope, err)
		}
		limits[scope] = rule
	}
	return &Limiter{
		remote: remote,
		rules:  limits,
		log:    log,
		fallback: map[Scope]*rate.Limiter{
			Capture: rate.NewLimiter(5, 10),
			Write:   rate.NewLimiter(10, 20),
			Read:    rate.NewLimiter(50, 100),
			Search:  rate.NewLimiter(5, 10),
		},
		outageLog: rate.NewLimiter(rate.Every(time.Minute), 1),
	}, nil
}

func (l *Limiter) Allow(ctx context.Context, scope Scope, subject string) error {
	rule, ok := l.rules[scope]
	if !ok {
		return errors.New("invalid rate limit scope")
	}
	err := l.remote.Allow(ctx, string(scope), subject, rule)
	if !errors.Is(err, platformlimit.ErrUnavailable) {
		return err
	}
	if !l.fallback[scope].Allow() {
		return &platformlimit.ExceededError{
			RetryAfter: time.Second,
		}
	}
	if l.outageLog.Allow() {
		l.log.Warn("Redis rate limit unavailable; using local protection", zap.String("scope", string(scope)))
	}
	return nil
}
