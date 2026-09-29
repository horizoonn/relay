package collection

import (
	"context"
	"errors"
	"testing"
	"time"
	"uuid"
)

func TestCollectionList(t *testing.T) {
	t.Parallel()
	ownerID := uuid.New()
	anchor := &Anchor{
		At: time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC),
		ID: uuid.New(),
	}
	params := ListParams{
		OwnerID: ownerID,
		Limit:   20,
		After:   anchor,
	}

	for _, tt := range []struct {
		name string
		call func(*Service, context.Context, ListParams) (Page, error)
	}{
		{
			name: "recent",
			call: (*Service).ListRecent,
		},
		{
			name: "library",
			call: (*Service).ListLibrary,
		},
		{
			name: "later",
			call: (*Service).ListLater,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reader := &fakeReader{}
			page, err := tt.call(NewService(reader), context.Background(), params)
			if err != nil {
				t.Fatal(err)
			}
			if reader.called != tt.name || reader.params != params {
				t.Fatalf("called = %q, params = %+v", reader.called, reader.params)
			}
			if page.Items == nil {
				t.Fatal("empty page has nil items")
			}
		})
	}
}

func TestCollectionInvalidQuery(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		params ListParams
	}{
		{
			name: "missing owner",
			params: ListParams{
				Limit: 20,
			},
		},
		{
			name: "zero limit",
			params: ListParams{
				OwnerID: uuid.New(),
				Limit:   0,
			},
		},
		{
			name: "limit above maximum",
			params: ListParams{
				OwnerID: uuid.New(),
				Limit:   101,
			},
		},
		{
			name: "empty page anchor",
			params: ListParams{
				OwnerID: uuid.New(),
				Limit:   20,
				After:   &Anchor{},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reader := &fakeReader{}
			_, err := NewService(reader).ListRecent(t.Context(), tt.params)
			if !errors.Is(err, ErrInvalidQuery) || reader.called != "" {
				t.Fatalf("params = %+v, error = %v, called = %q", tt.params, err, reader.called)
			}
		})
	}
}

type fakeReader struct {
	called string
	params ListParams
}

func (f *fakeReader) ListRecent(
	_ context.Context,
	params ListParams,
) (Page, error) {
	f.called, f.params = "recent", params
	return Page{
		Items: nil,
	}, nil
}

func (f *fakeReader) ListLibrary(
	_ context.Context,
	params ListParams,
) (Page, error) {
	f.called, f.params = "library", params
	return Page{
		Items: nil,
	}, nil
}

func (f *fakeReader) ListLater(
	_ context.Context,
	params ListParams,
) (Page, error) {
	f.called, f.params = "later", params
	return Page{
		Items: nil,
	}, nil
}
