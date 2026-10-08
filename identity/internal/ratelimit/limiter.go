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
	remote       *platformlimit.RedisLimiter
	rules        map[Scope]platformlimit.Rule
	log          *zap.Logger
	readFallback *rate.Limiter
	endFallback  *rate.Limiter
	outageLog    *rate.Limiter
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
	remote, err := platformlimit.NewRedisLimiter(client, "identity:v1", key, timeout)
	if err != nil {
		return nil, fmt.Errorf("initialize Redis rate limiter: %w", err)
	}
	limits := make(map[Scope]platformlimit.Rule, len(rules))
	for _, scope := range []Scope{
		LoginIP,
		LoginAccount,
		RegisterIP,
		RefreshIP,
		ReadUser,
		LogoutIP,
		RevokeUser,
		EmailIP,
		EmailAccount,
		ActionIP,
	} {
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
		remote:       remote,
		rules:        limits,
		log:          log,
		readFallback: rate.NewLimiter(50, 100),
		endFallback:  rate.NewLimiter(10, 20),
		outageLog:    rate.NewLimiter(rate.Every(time.Minute), 1),
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
	var fallback *rate.Limiter
	switch scope {
	case ReadUser:
		fallback = l.readFallback
	case LogoutIP, RevokeUser:
		fallback = l.endFallback
	case LoginIP, LoginAccount, RegisterIP, RefreshIP, EmailIP, EmailAccount, ActionIP:
		return err
	default:
		return err
	}
	if !fallback.Allow() {
		return &platformlimit.ExceededError{
			RetryAfter: time.Second,
		}
	}
	if l.outageLog.Allow() {
		l.log.Warn("Redis rate limit unavailable; using local protection", zap.String("scope", string(scope)))
	}
	return nil
}
