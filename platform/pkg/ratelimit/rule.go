package ratelimit

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

var ErrUnavailable = errors.New("rate limiter unavailable")

type ExceededError struct {
	RetryAfter time.Duration
}

func (e *ExceededError) Error() string { return "rate limit exceeded" }

type Rule struct {
	Rate   int
	Period time.Duration
	Burst  int
}

func ParseRule(value string) (Rule, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 3 {
		return Rule{}, errors.New("rate limit must have rate/period/burst format")
	}
	rate, rateErr := strconv.Atoi(parts[0])
	period, periodErr := time.ParseDuration(parts[1])
	burst, burstErr := strconv.Atoi(parts[2])
	if rateErr != nil || periodErr != nil || burstErr != nil {
		return Rule{}, errors.New("rate limit contains an invalid number or duration")
	}
	rule := Rule{
		Rate:   rate,
		Period: period,
		Burst:  burst,
	}
	return rule, rule.Validate()
}

func (r Rule) Validate() error {
	if r.Rate < 1 ||
		r.Rate > 100000 ||
		r.Burst < 1 ||
		r.Burst > 100000 ||
		r.Period < time.Second ||
		r.Period > 24*time.Hour {
		return errors.New("rate limit requires rate and burst between 1 and 100000 and period between 1s and 24h")
	}

	if time.Duration(r.Burst)*r.Period/time.Duration(r.Rate) > 24*time.Hour {
		return errors.New("rate limit burst must refill within 24h")
	}
	return nil
}
