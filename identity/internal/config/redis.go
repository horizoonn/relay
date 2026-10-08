package config

import (
	"errors"
	"fmt"

	"github.com/horizoonn/relay/platform/pkg/ratelimit"
	platformredis "github.com/horizoonn/relay/platform/pkg/redis"

	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
)

type RedisConfig = platformredis.Config

type RateLimitConfig struct {
	EmailIP      string `env:"RATE_EMAIL_IP" envDefault:"30/1h/5"`
	EmailAccount string `env:"RATE_EMAIL_ACCOUNT" envDefault:"5/1h/2"`
	ActionIP     string `env:"RATE_ACTION_IP" envDefault:"30/1m/10"`
	Key          string `env:"RATE_LIMIT_KEY,required,notEmpty"`
	LoginIP      string `env:"RATE_LOGIN_IP" envDefault:"30/1m/10"`
	LoginAccount string `env:"RATE_LOGIN_ACCOUNT" envDefault:"5/1m/5"`
	RegisterIP   string `env:"RATE_REGISTER_IP" envDefault:"6/1h/3"`
	RefreshIP    string `env:"RATE_REFRESH_IP" envDefault:"120/1m/30"`
	ReadUser     string `env:"RATE_READ_USER" envDefault:"120/1m/30"`
	LogoutIP     string `env:"RATE_LOGOUT_IP" envDefault:"30/1m/10"`
	RevokeUser   string `env:"RATE_REVOKE_USER" envDefault:"30/1m/10"`
}

func (c RateLimitConfig) Rules() (map[identitylimit.Scope]ratelimit.Rule, error) {
	if len(c.Key) < 32 {
		return nil, errors.New("IDENTITY_RATE_LIMIT_KEY must contain at least 32 bytes")
	}
	values := map[identitylimit.Scope]string{
		identitylimit.EmailIP:      c.EmailIP,
		identitylimit.EmailAccount: c.EmailAccount,
		identitylimit.ActionIP:     c.ActionIP,
		identitylimit.LoginIP:      c.LoginIP,
		identitylimit.LoginAccount: c.LoginAccount,
		identitylimit.RegisterIP:   c.RegisterIP,
		identitylimit.RefreshIP:    c.RefreshIP,
		identitylimit.ReadUser:     c.ReadUser,
		identitylimit.LogoutIP:     c.LogoutIP,
		identitylimit.RevokeUser:   c.RevokeUser,
	}
	rules := make(map[identitylimit.Scope]ratelimit.Rule, len(values))
	for scope, value := range values {
		rule, err := ratelimit.ParseRule(value)
		if err != nil {
			return nil, fmt.Errorf("rate limit %s: %w", scope, err)
		}
		rules[scope] = rule
	}
	return rules, nil
}
