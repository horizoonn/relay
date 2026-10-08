package ratelimit

import (
	"testing"
	"time"
)

func TestParseRule(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  Rule
		valid bool
	}{
		{
			name:  "login budget",
			value: "5/1m/3",
			want: Rule{
				5,
				time.Minute,
				3,
			},
			valid: true,
		},
		{
			name:  "hourly budget",
			value: "6/1h/3",
			want: Rule{
				6,
				time.Hour,
				3,
			},
			valid: true,
		},
		{
			name:  "missing burst",
			value: "5/1m",
			want:  Rule{},
			valid: false,
		},
		{
			name:  "invalid period",
			value: "5/minute/3",
			want:  Rule{},
			valid: false,
		},
		{
			name:  "zero rate",
			value: "0/1m/3",
			want:  Rule{},
			valid: false,
		},
		{
			name:  "negative burst",
			value: "5/1m/-1",
			want:  Rule{},
			valid: false,
		},
		{
			name:  "excessive rate",
			value: "100001/1m/3",
			want:  Rule{},
			valid: false,
		},
		{
			name:  "subsecond period",
			value: "5/1ms/3",
			want:  Rule{},
			valid: false,
		},
		{
			name:  "excessive retention",
			value: "1/24h/2",
			want:  Rule{},
			valid: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRule(tc.value)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if tc.valid && got != tc.want {
				t.Fatalf("got=%v want=%v", got, tc.want)
			}
		})
	}
}
