package config

import (
	"errors"
	"fmt"

	"github.com/horizoonn/relay/platform/pkg/ratelimit"
	platformredis "github.com/horizoonn/relay/platform/pkg/redis"

	contentlimit "github.com/horizoonn/relay/content/internal/ratelimit"
)

type RedisConfig = platformredis.Config

type RateLimitConfig struct {
	Key     string `env:"RATE_LIMIT_KEY,required,notEmpty"`
	Capture string `env:"RATE_CAPTURE_USER" envDefault:"30/1m/10"`
	Write   string `env:"RATE_WRITE_USER" envDefault:"60/1m/20"`
	Read    string `env:"RATE_READ_USER" envDefault:"300/1m/60"`
	Search  string `env:"RATE_SEARCH_USER" envDefault:"60/1m/10"`
}

func (c RateLimitConfig) Rules() (map[contentlimit.Scope]ratelimit.Rule, error) {
	if len(c.Key) < 32 {
		return nil, errors.New("CONTENT_RATE_LIMIT_KEY must contain at least 32 bytes")
	}
	values := map[contentlimit.Scope]string{
		contentlimit.Capture: c.Capture,
		contentlimit.Write:   c.Write,
		contentlimit.Read:    c.Read,
		contentlimit.Search:  c.Search,
	}
	rules := make(map[contentlimit.Scope]ratelimit.Rule, len(values))
	for scope, value := range values {
		rule, err := ratelimit.ParseRule(value)
		if err != nil {
			return nil, fmt.Errorf("rate limit %s: %w", scope, err)
		}
		rules[scope] = rule
	}
	return rules, nil
}
