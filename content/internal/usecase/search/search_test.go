package search

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"uuid"
)

func TestSearchQuery(t *testing.T) {
	t.Parallel()
	repository := &fakeRepository{}
	params := Params{
		OwnerID: uuid.New(),
		Query:   "\u00a0PostgreSQL\u3000",
		Limit:   20,
		After: &Anchor{
			Tier:           MatchTitlePrefix,
			LastCapturedAt: time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC),
			ID:             uuid.New(),
		},
	}
	page, err := NewService(repository).Search(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}
	if repository.calls != 1 || repository.params.Query != "PostgreSQL" ||
		repository.params.OwnerID != params.OwnerID || repository.params.Limit != params.Limit ||
		repository.params.After != params.After {
		t.Fatalf("repository params = %+v", repository.params)
	}
	if page.Items == nil {
		t.Fatal("empty page has nil items")
	}
}

func TestSearchInvalidQuery(t *testing.T) {
	t.Parallel()
	ownerID := uuid.New()
	for _, tt := range []struct {
		name   string
		params Params
	}{
		{
			name: "missing owner",
			params: Params{
				Query: "text",
				Limit: 20,
			},
		},
		{
			name: "zero limit",
			params: Params{
				OwnerID: ownerID,
				Query:   "text",
				Limit:   0,
			},
		},
		{
			name: "limit above maximum",
			params: Params{
				OwnerID: ownerID,
				Query:   "text",
				Limit:   101,
			},
		},
		{
			name: "whitespace query",
			params: Params{
				OwnerID: ownerID,
				Query:   "\u2003",
				Limit:   20,
			},
		},
		{
			name: "invalid UTF-8",
			params: Params{
				OwnerID: ownerID,
				Query:   string([]byte{0xff}),
				Limit:   20,
			},
		},
		{
			name: "query above maximum",
			params: Params{
				OwnerID: ownerID,
				Query:   strings.Repeat("界", 257),
				Limit:   20,
			},
		},
		{
			name: "NUL in query",
			params: Params{
				OwnerID: ownerID,
				Query:   "te\x00xt",
				Limit:   20,
			},
		},
		{
			name: "empty anchor",
			params: Params{
				OwnerID: ownerID,
				Query:   "text",
				Limit:   20,
				After:   &Anchor{},
			},
		},
		{
			name: "short query with text tier",
			params: Params{
				OwnerID: ownerID,
				Query:   "x",
				Limit:   20,
				After: &Anchor{
					Tier:           MatchTextExact,
					LastCapturedAt: time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC),
					ID:             uuid.New(),
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			repository := &fakeRepository{}
			_, err := NewService(repository).Search(t.Context(), tt.params)
			if !errors.Is(err, ErrInvalidQuery) || repository.calls != 0 {
				t.Fatalf("params = %+v, error = %v, calls = %d", tt.params, err, repository.calls)
			}
		})
	}
}

type fakeRepository struct {
	params Params
	calls  int
}

func (f *fakeRepository) Search(
	_ context.Context,
	params Params,
) (Page, error) {
	f.calls++
	f.params = params
	return Page{}, nil
}
