package domain

import (
	"strings"
	"unicode/utf8"
)

type SourceType string

const (
	SourceURL  SourceType = "url"
	SourceText SourceType = "text"
)

type Source struct {
	Type          SourceType
	OriginalURL   string
	NormalizedURL string
	Text          string
}

func NewURLSource(originalURL string) (Source, error) {
	normalizedURL, err := NormalizeURL(originalURL)
	if err != nil {
		return Source{}, err
	}
	return Source{
		Type:          SourceURL,
		OriginalURL:   originalURL,
		NormalizedURL: normalizedURL,
	}, nil
}

func NewTextSource(text string) (Source, error) {
	s := Source{
		Type: SourceText,
		Text: text,
	}
	if !s.valid() {
		return Source{}, ErrInvalidSource
	}
	return s, nil
}

func (s Source) valid() bool {
	switch s.Type {
	case SourceURL:
		normalized, err := NormalizeURL(s.OriginalURL)
		return s.Text == "" && err == nil && s.NormalizedURL == normalized
	case SourceText:
		return s.OriginalURL == "" && s.NormalizedURL == "" &&
			utf8.ValidString(s.Text) && len(s.Text) <= 65536 && strings.TrimSpace(s.Text) != ""
	default:
		return false
	}
}
