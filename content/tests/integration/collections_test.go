//go:build integration

package integration

import (
	"context"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/postgres"

	"github.com/horizoonn/relay/content/internal/domain"
	contentrepo "github.com/horizoonn/relay/content/internal/repository/postgres"
	"github.com/horizoonn/relay/content/internal/usecase/collection"
	"github.com/horizoonn/relay/content/internal/usecase/search"
)

func createTextItem(
	t *testing.T,
	ctx context.Context,
	repo *contentrepo.Repository,
	owner, id uuid.UUID,
	body, title string,
	capturedAt time.Time,
	keep, later bool,
) uuid.UUID {
	t.Helper()
	source, err := domain.NewTextSource(body)
	if err != nil {
		t.Fatal(err)
	}
	value, err := domain.NewItem(id, owner, source, capturedAt)
	if err != nil {
		t.Fatal(err)
	}
	if keep {
		if keepErr := value.SetKeep(true, capturedAt.Add(time.Minute)); keepErr != nil {
			t.Fatal(keepErr)
		}
	}
	if later {
		if reviewErr := value.SetReviewStatus(domain.ReviewLater, capturedAt.Add(2*time.Minute)); reviewErr != nil {
			t.Fatal(reviewErr)
		}
	}
	if title != "" {
		if titleErr := value.SetDisplayTitle(title, capturedAt.Add(3*time.Hour)); titleErr != nil {
			t.Fatal(titleErr)
		}
	}
	created, err := repo.Create(ctx, value)
	if err != nil || !created {
		t.Fatalf("create text Item: %t, %v", created, err)
	}
	return value.ID()
}

func TestCollectionMembershipAndPages(t *testing.T) {
	pool, ctx := testPool(t)
	owner := uuid.New()
	cleanupOwner(t, pool, owner)
	tx := postgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 5*time.Second)
	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	old := createTextItem(t, ctx, repo, owner, uuid.New(), "old", "updated later", base, true, true)
	middle := createTextItem(t, ctx, repo, owner, uuid.New(), "middle", "", base.Add(time.Hour), true, false)
	newest := createTextItem(t, ctx, repo, owner, uuid.New(), "newest", "", base.Add(2*time.Hour), false, true)
	other := uuid.New()
	cleanupOwner(t, pool, other)
	createTextItem(t, ctx, repo, other, uuid.New(), "foreign", "", base.Add(4*time.Hour), true, true)

	checks := []struct {
		name string
		list func(context.Context, collection.ListParams) (collection.Page, error)
		want []uuid.UUID
	}{
		{
			name: "recent",
			list: repo.ListRecent,
			want: []uuid.UUID{newest, middle, old},
		},
		{
			name: "library",
			list: repo.ListLibrary,
			want: []uuid.UUID{middle, old},
		},
		{
			name: "later",
			list: repo.ListLater,
			want: []uuid.UUID{newest, old},
		},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			var after *collection.Anchor
			for index, want := range check.want {
				page, err := check.list(ctx, collection.ListParams{
					OwnerID: owner,
					Limit:   1,
					After:   after,
				})
				if err != nil {
					t.Fatal(err)
				}
				if len(page.Items) != 1 || page.Items[0].ID != want {
					t.Fatalf("page %d = %+v; want %s", index, page.Items, want)
				}
				if (page.Next == nil) != (index == len(check.want)-1) {
					t.Fatalf("page %d next cursor = %+v", index, page.Next)
				}
				after = page.Next
			}
		})
	}
}

func TestSearchTierPages(t *testing.T) {
	pool, ctx := testPool(t)
	owner := uuid.New()
	cleanupOwner(t, pool, owner)
	tx := postgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 5*time.Second)
	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	exact := createTextItem(t, ctx, repo, owner, uuid.New(), "other", "Alpha", base, false, false)
	prefix := createTextItem(t, ctx, repo, owner, uuid.New(), "other", "Alphabet", base.Add(time.Hour), false, false)
	text := createTextItem(t, ctx, repo, owner, uuid.New(), "about alpha", "", base.Add(2*time.Hour), false, false)
	var after *search.Anchor
	for index, want := range []uuid.UUID{exact, prefix, text} {
		page, err := repo.Search(ctx, search.Params{
			OwnerID: owner,
			Query:   "alpha",
			Limit:   1,
			After:   after,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 1 || page.Items[0].ID != want {
			t.Fatalf("tier page %d = %+v; want %s", index, page.Items, want)
		}
		if (page.Next == nil) != (index == 2) {
			t.Fatalf("tier page %d next cursor = %+v", index, page.Next)
		}
		after = page.Next
	}
}

func TestCollectionPagesWithEqualTimestamps(t *testing.T) {
	pool, ctx := testPool(t)
	owner := uuid.New()
	cleanupOwner(t, pool, owner)
	tx := postgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 5*time.Second)
	at := time.Date(2026, time.October, 5, 12, 0, 0, 123456000, time.UTC)
	// Insertion order differs from ID order; every sort timestamp is equal.
	ids := []uuid.UUID{
		uuid.MustParse("00000000-0000-0000-0000-000000000002"),
		uuid.MustParse("00000000-0000-0000-0000-000000000003"),
		uuid.MustParse("00000000-0000-0000-0000-000000000001"),
	}
	for _, id := range ids {
		createTextItem(t, ctx, repo, owner, id, "same timestamp", "", at, true, true)
	}
	want := []uuid.UUID{ids[1], ids[0], ids[2]}
	for _, tt := range []struct {
		name   string
		list   func(context.Context, collection.ListParams) (collection.Page, error)
		sortAt time.Time
	}{
		{"recent", repo.ListRecent, at},
		{"library", repo.ListLibrary, at.Add(time.Minute)},
		{"later", repo.ListLater, at.Add(2 * time.Minute)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var after *collection.Anchor
			for index, id := range want {
				page, err := tt.list(ctx, collection.ListParams{OwnerID: owner, Limit: 1, After: after})
				if err != nil {
					t.Fatal(err)
				}
				if len(page.Items) != 1 || page.Items[0].ID != id {
					t.Fatalf("page %d: got=%+v want ID=%s", index, page.Items, id)
				}
				if index == len(want)-1 {
					if page.Next != nil {
						t.Fatalf("last page has cursor: %+v", page.Next)
					}
				} else if page.Next == nil || page.Next.ID != id || !page.Next.At.Equal(tt.sortAt) {
					t.Fatalf("page %d cursor=%+v; want ID=%s time=%s", index, page.Next, id, tt.sortAt)
				}
				after = page.Next
			}
		})
	}
}

func TestSearchPagesWithinEqualTimestampTier(t *testing.T) {
	pool, ctx := testPool(t)
	owner := uuid.New()
	cleanupOwner(t, pool, owner)
	tx := postgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 5*time.Second)
	at := time.Date(2026, time.October, 5, 12, 0, 0, 123456000, time.UTC)
	first := uuid.MustParse("00000000-0000-0000-0000-000000000004")
	second := uuid.MustParse("00000000-0000-0000-0000-000000000005")
	prefix := uuid.MustParse("00000000-0000-0000-0000-000000000006")
	text := uuid.MustParse("00000000-0000-0000-0000-000000000007")
	createTextItem(t, ctx, repo, owner, first, "other", "Alpha", at, false, false)
	createTextItem(t, ctx, repo, owner, second, "other", "Alpha", at, false, false)
	createTextItem(t, ctx, repo, owner, prefix, "other", "Alphabet", at, false, false)
	createTextItem(t, ctx, repo, owner, text, "about alpha", "", at, false, false)
	want := []uuid.UUID{second, first, prefix, text}
	var after *search.Anchor
	for index, id := range want {
		page, err := repo.Search(ctx, search.Params{OwnerID: owner, Query: "alpha", Limit: 1, After: after})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 1 || page.Items[0].ID != id {
			t.Fatalf("page %d: got=%+v want ID=%s", index, page.Items, id)
		}
		if index == len(want)-1 {
			if page.Next != nil {
				t.Fatalf("last page has cursor: %+v", page.Next)
			}
		} else if page.Next == nil || page.Next.ID != id || !page.Next.LastCapturedAt.Equal(at) {
			t.Fatalf("page %d cursor=%+v; want ID=%s time=%s", index, page.Next, id, at)
		}
		after = page.Next
	}
}
