package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeEmail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{
			name:  "unchanged",
			input: "user@example.com",
			want:  "user@example.com",
		},
		{
			name:  "domain case",
			input: "User@EXAMPLE.COM",
			want:  "User@example.com",
		},
		{
			name:  "surrounding whitespace",
			input: " \tUser@EXAMPLE.COM \t",
			want:  "User@example.com",
		},
		{
			name:  "local part case preserved",
			input: "USER@example.com",
			want:  "USER@example.com",
		},
		{
			name:  "plus address preserved",
			input: "user+notes@example.com",
			want:  "user+notes@example.com",
		},
		{
			name:    "empty",
			wantErr: ErrInvalidEmail,
		},
		{
			name:    "missing local part",
			input:   "@example.com",
			wantErr: ErrInvalidEmail,
		},
		{
			name:    "missing domain",
			input:   "user@",
			wantErr: ErrInvalidEmail,
		},
		{
			name:    "display name",
			input:   "User <user@example.com>",
			wantErr: ErrInvalidEmail,
		},
		{
			name:    "multiple addresses",
			input:   "one@example.com,two@example.com",
			wantErr: ErrInvalidEmail,
		},
		{
			name:    "embedded newline",
			input:   "user@exam\nple.com",
			wantErr: ErrInvalidEmail,
		},
		{
			name:    "oversized",
			input:   strings.Repeat("a", 255) + "@example.com",
			wantErr: ErrInvalidEmail,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeEmail(tt.input)
			if !errors.Is(err, tt.wantErr) || got != tt.want {
				t.Errorf("NormalizeEmail() = %q, %v; want %q, %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}
