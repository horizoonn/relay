package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/horizoonn/relay/content/internal/domain"
)

func TestNewTextSource(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		text    string
		wantErr bool
	}{
		{
			name: "preserve surrounding spaces",
			text: "  hello  ",
		},
		{
			name: "Unicode text",
			text: "Привет, мир",
		},
		{
			name:    "empty",
			text:    "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			text:    " \t\n ",
			wantErr: true,
		},
		{
			name:    "over byte limit",
			text:    strings.Repeat("x", 65537),
			wantErr: true,
		},
		{
			name:    "invalid UTF-8",
			text:    string([]byte{0xff}),
			wantErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			source, err := domain.NewTextSource(tt.text)
			if tt.wantErr {
				if !errors.Is(err, domain.ErrInvalidSource) {
					t.Fatalf("NewTextSource() error = %v; want ErrInvalidSource", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if source.Type != domain.SourceText || source.Text != tt.text {
				t.Fatalf("NewTextSource() = %+v; want exact text", source)
			}
		})
	}
}
