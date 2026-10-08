package redis

import (
	"testing"
	"time"
)

func TestNewClientRejectsInvalidOptions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{
			name: "missing host",
			change: func(c *Config) {
				c.Address = ":6379"
			},
		},
		{
			name: "zero port",
			change: func(c *Config) {
				c.Address = "localhost:0"
			},
		},
		{
			name: "non-numeric port",
			change: func(c *Config) {
				c.Address = "localhost:redis"
			},
		},
		{
			name: "zero timeout",
			change: func(c *Config) {
				c.Timeout = 0
			},
		},
		{
			name: "excessive timeout",
			change: func(c *Config) {
				c.Timeout = 2 * time.Second
			},
		},
		{
			name: "unbounded pool",
			change: func(c *Config) {
				c.MaxConnections = 0
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Address:        "localhost:6379",
				Timeout:        100 * time.Millisecond,
				MaxConnections: 2,
			}
			tc.change(&cfg)
			if _, err := NewClient(cfg); err == nil {
				t.Fatal("invalid options accepted")
			}
		})
	}
}

func TestNewClientAllowsUnavailableRedisAtStartup(t *testing.T) {
	client, err := NewClient(Config{
		Address:        "127.0.0.1:1",
		Timeout:        100 * time.Millisecond,
		MaxConnections: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if client.Options().MaxActiveConns != 1 {
		t.Fatal("connection cap missing")
	}
}
