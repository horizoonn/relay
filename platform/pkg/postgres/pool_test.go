package postgres

import (
	"strings"
	"testing"
	"time"
)

func TestNewPoolInvalidURL(t *testing.T) {
	cfg := Config{
		Host:           "bad\nhost",
		Port:           5432,
		Database:       "test",
		User:           "test",
		Password:       "private-marker",
		SSLMode:        "disable",
		MaxConns:       1,
		ConnectTimeout: time.Second,
	}
	pool, err := NewPool(t.Context(), cfg)
	if pool != nil {
		pool.Close()
	}
	if err == nil {
		t.Fatal("malformed URL accepted")
	}
	if strings.Contains(err.Error(), cfg.Password) {
		t.Fatal("credentials leaked")
	}
}
