package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{
			name:  "lowercase scheme and host, add root path",
			input: "HTTPS://EXAMPLE.COM",
			want:  "https://example.com/",
		},
		{
			name:  "remove default HTTP port",
			input: "http://example.com:80/a",
			want:  "http://example.com/a",
		},
		{
			name:  "remove default HTTPS port with leading zero",
			input: "https://example.com:0443/a",
			want:  "https://example.com/a",
		},
		{
			name:  "keep non-default port",
			input: "https://example.com:8443/a",
			want:  "https://example.com:8443/a",
		},
		{
			name:  "remove dot segment",
			input: "https://example.com/a/./b",
			want:  "https://example.com/a/b",
		},
		{
			name:  "remove parent segment",
			input: "https://example.com/a/x/../b",
			want:  "https://example.com/a/b",
		},
		{
			name:  "decode encoded dot segment",
			input: "https://example.com/a/%2e/b",
			want:  "https://example.com/a/b",
		},
		{
			name:  "decode encoded parent segment",
			input: "https://example.com/a/%2E%2E/b",
			want:  "https://example.com/b",
		},
		{
			name:  "decode unreserved character",
			input: "https://example.com/%7Euser",
			want:  "https://example.com/~user",
		},
		{
			name:  "preserve encoded slash",
			input: "https://example.com/%2f",
			want:  "https://example.com/%2F",
		},
		{
			name:  "encoded slash prevents dot segment",
			input: "https://example.com/a/%2e%2Fb",
			want:  "https://example.com/a/.%2Fb",
		},
		{
			name:  "preserve repeated slashes",
			input: "https://example.com/a//b/../c",
			want:  "https://example.com/a//c",
		},
		{
			name:  "convert IDN to punycode",
			input: "https://пример.рф/",
			want:  "https://xn--e1afmkfd.xn--p1ai/",
		},
		{
			name:  "encode Unicode path",
			input: "https://example.com/привет",
			want:  "https://example.com/%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82",
		},
		{
			name:  "encode Unicode query",
			input: "https://example.com/?q=привет",
			want:  "https://example.com/?q=%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82",
		},
		{
			name:  "keep empty query marker",
			input: "https://example.com/?",
			want:  "https://example.com/?",
		},
		{
			name:  "keep empty fragment marker",
			input: "https://example.com/#",
			want:  "https://example.com/#",
		},
		{
			name:  "convert one IDN label",
			input: "https://example.com.л/",
			want:  "https://example.com.xn--k1a/",
		},
		{
			name:  "keep trailing host dot",
			input: "https://example.com./",
			want:  "https://example.com./",
		},
		{
			name:  "keep IPv4 host",
			input: "http://192.168.1.10/",
			want:  "http://192.168.1.10/",
		},
		{
			name:  "canonicalize IPv6 host",
			input: "http://[2001:0db8:0:0::1]:80/",
			want:  "http://[2001:db8::1]/",
		},
		{
			name:    "reject unsupported scheme",
			input:   "ftp://example.com/",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject missing host",
			input:   "https:///path",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject userinfo",
			input:   "https://user@example.com/",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject incomplete percent escape",
			input:   "https://example.com/%",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject short percent escape",
			input:   "https://example.com/%2",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject malformed percent escape",
			input:   "https://example.com/%GG",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject malformed query escape",
			input:   "https://example.com/?q=%GG",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject malformed fragment escape",
			input:   "https://example.com/#%GG",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject raw space",
			input:   "https://example.com/a b",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject raw backslash",
			input:   "https://example.com/\\a",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject control character",
			input:   "https://example.com/\n",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject empty port",
			input:   "https://example.com:",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject nonnumeric port",
			input:   "https://example.com:bad/",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject out-of-range port",
			input:   "https://example.com:65536/",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject short IPv4",
			input:   "http://127.1/",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject IPv4 with leading zero",
			input:   "http://0127.0.0.1/",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject hexadecimal IPv4",
			input:   "http://0x7f000001/",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject hexadecimal IPv4 component",
			input:   "http://127.0.0x0.1/",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject numeric DNS suffix",
			input:   "http://example.42/",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject Unicode mapped IPv4",
			input:   "http://①.②.③.④/",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject IPv6 zone",
			input:   "http://[fe80::1%25eth0]/",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject nonbreaking space",
			input:   "https://example.com/a\u00a0b",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject Unicode control",
			input:   "https://example.com/a\u0085b",
			wantErr: ErrInvalidSource,
		},
		{
			name:    "reject URL over byte limit",
			input:   strings.Repeat("x", 8193),
			wantErr: ErrInvalidSource,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := NormalizeURL(tt.input)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("NormalizeURL(%q) error = %v, want %v", tt.input, err, tt.wantErr)
				}
				if got != "" {
					t.Errorf("NormalizeURL(%q) = %q on error, want empty", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeURL(%q): %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("NormalizeURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeURLIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a, b     string
		wantSame bool
	}{
		{
			name:     "IDN and punycode",
			a:        "https://пример.рф/",
			b:        "https://xn--e1afmkfd.xn--p1ai/",
			wantSame: true,
		},
		{
			name:     "Unicode and escaped path",
			a:        "https://example.com/привет",
			b:        "https://example.com/%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82",
			wantSame: true,
		},
		{
			name:     "Unicode and escaped query",
			a:        "https://example.com/?q=привет",
			b:        "https://example.com/?q=%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82",
			wantSame: true,
		},
		{
			name:     "encoded unreserved character",
			a:        "https://example.com/a/%7E",
			b:        "https://example.com/a/~",
			wantSame: true,
		},
		{
			name:     "encoded parent segment",
			a:        "https://example.com/a/%2E%2E/b",
			b:        "https://example.com/b",
			wantSame: true,
		},
		{
			name: "HTTP and HTTPS",
			a:    "http://example.com/a",
			b:    "https://example.com/a",
		},
		{
			name: "www host",
			a:    "https://example.com/a",
			b:    "https://www.example.com/a",
		},
		{
			name: "trailing path slash",
			a:    "https://example.com/a",
			b:    "https://example.com/a/",
		},
		{
			name: "query order",
			a:    "https://example.com/?a=1&b=2",
			b:    "https://example.com/?b=2&a=1",
		},
		{
			name: "empty query marker",
			a:    "https://example.com/",
			b:    "https://example.com/?",
		},
		{
			name: "empty fragment marker",
			a:    "https://example.com/",
			b:    "https://example.com/#",
		},
		{
			name: "fragment value",
			a:    "https://example.com/a#one",
			b:    "https://example.com/a#two",
		},
		{
			name: "encoded and literal slash",
			a:    "https://example.com/a%2Fb",
			b:    "https://example.com/a/b",
		},
		{
			name: "encoded slash prevents dot segment",
			a:    "https://example.com/a/%2e%2Fb",
			b:    "https://example.com/a/b",
		},
		{
			name: "Unicode normalization forms",
			a:    "https://example.com/é",
			b:    "https://example.com/é",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a, err := NormalizeURL(tt.a)
			if err != nil {
				t.Fatalf("NormalizeURL(%q): %v", tt.a, err)
			}
			b, err := NormalizeURL(tt.b)
			if err != nil {
				t.Fatalf("NormalizeURL(%q): %v", tt.b, err)
			}
			if (a == b) != tt.wantSame {
				t.Errorf("same identity = %t for %q and %q; keys %q and %q, want %t",
					a == b, tt.a, tt.b, a, b, tt.wantSame,
				)
			}
		})
	}
}

func TestNewURLSourceUsesNormalizedURL(t *testing.T) {
	t.Parallel()

	source, err := NewURLSource("HTTPS://EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	if source.OriginalURL != "HTTPS://EXAMPLE.COM" || source.NormalizedURL != "https://example.com/" {
		t.Fatalf("NewURLSource() = %+v", source)
	}
}
