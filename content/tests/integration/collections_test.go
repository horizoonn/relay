//go:build integration

package integration

import (
	"context"
	"testing"
	"time"
	"uuid"

	platformpostgres "github.com/horizoonn/relay/platform/pkg/postgres"

	"github.com/horizoonn/relay/content/internal/domain"
	contentrepo "github.com/horizoonn/relay/content/internal/repository/postgres"
	"github.com/horizoonn/relay/content/internal/usecase/collection"
	"github.com/horizoonn/relay/content/internal/usecase/search"
)

func createTextItem(
	t *testing.T,
	ctx context.Context,
	repo *contentrepo.Repository,
	owner uuid.UUID,
	body, title string,
	capturedAt time.Time,
	keep, later bool,
) uuid.UUID {
	t.Helper()
	source, err := domain.NewTextSource(body)
	if err != nil {
		t.Fatal(err)
	}
	value, err := domain.NewItem(uuid.New(), owner, source, capturedAt)
	if err != nil {
		t.Fatal(err)
	}
	if keep {
		if err := value.SetKeep(true, capturedAt.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if later {
		if err := value.SetReviewStatus(domain.ReviewLater, capturedAt.Add(2*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if title != "" {
		if err := value.SetDisplayTitle(title, capturedAt.Add(3*time.Hour)); err != nil {
			t.Fatal(err)
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
	tx := platformpostgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 5*time.Second)
	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	old := createTextItem(t, ctx, repo, owner, "old", "updated later", base, true, true)
	middle := createTextItem(t, ctx, repo, owner, "middle", "", base.Add(time.Hour), true, false)
	newest := createTextItem(t, ctx, repo, owner, "newest", "", base.Add(2*time.Hour), false, true)
	other := uuid.New()
	cleanupOwner(t, pool, other)
	createTextItem(t, ctx, repo, other, "foreign", "", base.Add(4*time.Hour), true, true)

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
	tx := platformpostgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 5*time.Second)
	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	exact := createTextItem(t, ctx, repo, owner, "other", "Alpha", base, false, false)
	prefix := createTextItem(t, ctx, repo, owner, "other", "Alphabet", base.Add(time.Hour), false, false)
	text := createTextItem(t, ctx, repo, owner, "about alpha", "", base.Add(2*time.Hour), false, false)
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
