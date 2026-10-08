package domain

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

func NormalizeURL(original string) (string, error) {
	u, scheme, err := parseCaptureURL(original)
	if err != nil {
		return "", err
	}
	host, err := normalizeAuthority(u, scheme)
	if err != nil {
		return "", err
	}
	path, err := normalizeEscapes(u.EscapedPath())
	if err != nil {
		return "", err
	}
	if path == "" {
		path = "/"
	}
	path = removeDotSegments(path)
	query, err := normalizeEscapes(u.RawQuery)
	if err != nil {
		return "", err
	}
	fragment, err := normalizeEscapes(u.EscapedFragment())
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.Grow(len(original))
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(host)
	b.WriteString(path)
	if u.ForceQuery || u.RawQuery != "" {
		b.WriteByte('?')
		b.WriteString(query)
	}
	if strings.Contains(original, "#") {
		b.WriteByte('#')
		b.WriteString(fragment)
	}
	return b.String(), nil
}

func parseCaptureURL(original string) (*url.URL, string, error) {
	if !utf8.ValidString(original) || len(original) == 0 || len(original) > 8192 {
		return nil, "", fmt.Errorf("%w: invalid URL length or UTF-8", ErrInvalidSource)
	}
	for _, r := range original {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '\\' {
			return nil, "", fmt.Errorf(
				"%w: URL contains a space, control character, or backslash",
				ErrInvalidSource,
			)
		}
	}
	u, err := url.Parse(original)
	if err != nil {
		return nil, "", fmt.Errorf("%w: parse URL: %w", ErrInvalidSource, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Opaque != "" ||
		u.User != nil || u.Hostname() == "" {
		return nil, "", fmt.Errorf(
			"%w: URL must have an HTTP(S) scheme and host without userinfo",
			ErrInvalidSource,
		)
	}
	return u, scheme, nil
}

func normalizeAuthority(u *url.URL, scheme string) (string, error) {
	host, err := normalizeHost(u.Hostname(), u.Host)
	if err != nil {
		return "", err
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("%w: empty port", ErrInvalidSource)
	}
	if port == "" {
		return host, nil
	}
	n, parseErr := strconv.Atoi(port)
	if parseErr != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%w: invalid port", ErrInvalidSource)
	}
	if (scheme == "http" && n == 80) || (scheme == "https" && n == 443) {
		return host, nil
	}
	return host + ":" + strconv.Itoa(n), nil
}

func normalizeHost(host, authority string) (string, error) {
	if strings.Contains(host, ":") {
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() || addr.Zone() != "" || !strings.HasPrefix(authority, "[") {
			return "", fmt.Errorf("%w: invalid IPv6 host", ErrInvalidSource)
		}
		return "[" + addr.String() + "]", nil
	}
	if strings.ContainsAny(host, "%[]") {
		return "", fmt.Errorf("%w: invalid host", ErrInvalidSource)
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || ascii == "" {
		return "", fmt.Errorf("%w: invalid DNS host", ErrInvalidSource)
	}
	ascii = strings.ToLower(ascii)
	if endsInNumber(ascii) {
		addr, err := netip.ParseAddr(ascii)
		if err != nil || !addr.Is4() || host != ascii {
			return "", fmt.Errorf("%w: invalid IPv4 host", ErrInvalidSource)
		}
		return addr.String(), nil
	}
	return ascii, nil
}

func endsInNumber(host string) bool {
	last := strings.TrimSuffix(host, ".")
	if i := strings.LastIndexByte(last, '.'); i >= 0 {
		last = last[i+1:]
	}
	if last == "" {
		return false
	}
	decimal := true
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			decimal = false
			break
		}
	}
	if decimal {
		return true
	}
	if len(last) >= 2 && last[0] == '0' && last[1] == 'x' {
		for i := 2; i < len(last); i++ {
			if _, ok := hexValue(last[i]); !ok {
				return false
			}
		}
		return true
	}
	return false
}

func normalizeEscapes(raw string) (string, error) {
	var b strings.Builder
	b.Grow(len(raw))
	const hex = "0123456789ABCDEF"
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '%':
			if i+2 >= len(raw) {
				return "", fmt.Errorf("%w: malformed percent encoding", ErrInvalidSource)
			}
			hi, okHi := hexValue(raw[i+1])
			lo, okLo := hexValue(raw[i+2])
			if !okHi || !okLo {
				return "", fmt.Errorf("%w: malformed percent encoding", ErrInvalidSource)
			}
			decoded := hi<<4 | lo
			if unreserved(decoded) {
				b.WriteByte(decoded)
			} else {
				b.WriteByte('%')
				b.WriteByte(hex[hi])
				b.WriteByte(hex[lo])
			}
			i += 2
		case c >= utf8.RuneSelf:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

func hexValue(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func unreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

func removeDotSegments(path string) string {
	input, output := path, ""
	for input != "" {
		switch {
		case strings.HasPrefix(input, "../"):
			input = input[3:]
		case strings.HasPrefix(input, "./"):
			input = input[2:]
		case strings.HasPrefix(input, "/./"):
			input = input[2:]
		case input == "/.":
			input = "/"
		case strings.HasPrefix(input, "/../"):
			input = input[3:]
			output = removeLastSegment(output)
		case input == "/..":
			input = "/"
			output = removeLastSegment(output)
		case input == "." || input == "..":
			input = ""
		default:
			end := strings.IndexByte(input[1:], '/')
			if end < 0 {
				output += input
				input = ""
			} else {
				end++
				output += input[:end]
				input = input[end:]
			}
		}
	}
	return output
}

func removeLastSegment(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[:i]
	}
	return ""
}
