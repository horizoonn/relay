package domain

import "testing"

func FuzzNormalizeURLIdempotent(f *testing.F) {
	for _, seed := range []string{
		"HTTPS://EXAMPLE.COM:443/a/../b?x=%7e#fragment",
		"https://bücher.example/%c3%a9",
		"http://[2001:db8::1]/a/./b",
		"https://example.com/a%2Fb?x=%25",
		"https://example.com/%",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		normalized, err := NormalizeURL(input)
		if err != nil {
			return
		}
		second, err := NormalizeURL(normalized)
		if err != nil || second != normalized {
			t.Fatalf("NormalizeURL(%q) = %q; second pass = %q, %v", input, normalized, second, err)
		}
	})
}
