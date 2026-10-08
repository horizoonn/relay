package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/horizoonn/relay/platform/pkg/logger"
	platformredis "github.com/horizoonn/relay/platform/pkg/redis"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/horizoonn/relay/identity/internal/config"
	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
)

func newRedisLimiter(
	ctx context.Context,
	cfg config.RedisConfig,
	policies config.RateLimitConfig,
	log *zap.Logger,
) (*redis.Client, *identitylimit.Limiter, error) {
	client, err := platformredis.NewClient(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("create Redis client: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	pingErr := client.Ping(pingCtx).Err()
	cancel()
	if pingErr != nil {
		log.Warn("Redis startup ping failed; sensitive operations require Redis", logger.ErrorFields(pingErr)...)
	}
	rules, err := policies.Rules()
	if err != nil {
		err = fmt.Errorf("configure rate limit rules: %w", err)
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close Redis after initialization failure: %w", closeErr))
		}
		return nil, nil, err
	}
	limiter, err := identitylimit.NewLimiter(client, []byte(policies.Key), cfg.Timeout, rules, log)
	if err != nil {
		err = fmt.Errorf("create Identity rate limiter: %w", err)
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close Redis after initialization failure: %w", closeErr))
		}
		return nil, nil, err
	}
	return client, limiter, nil
}
