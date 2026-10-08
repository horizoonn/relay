//go:build component

package component

import (
	"encoding/json/v2"
	"net/http"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/ratelimit"

	contentlimit "github.com/horizoonn/relay/content/internal/ratelimit"
)

const rateLimitCaptureBody = `{"source_type":"text","text":"rate limit content"}`

type budgetRequest struct {
	method string
	path   string
	body   string
	media  string
	key    string
}

func oneRequestBudgets() map[contentlimit.Scope]ratelimit.Rule {
	rules := map[contentlimit.Scope]ratelimit.Rule{}
	for _, scope := range []contentlimit.Scope{contentlimit.Capture, contentlimit.Write, contentlimit.Read, contentlimit.Search} {
		rules[scope] = ratelimit.Rule{Rate: 1, Period: time.Hour, Burst: 1}
	}
	return rules
}

func captureForBudgetTest(t *testing.T, f *fixture) string {
	t.Helper()
	status, _, body := f.call(t, f.server, http.MethodPost, "/api/v1/items", rateLimitCaptureBody, "application/json", "first")
	if status != http.StatusCreated {
		t.Fatalf("prepare Item: status=%d body=%s", status, body)
	}
	var receipt struct {
		ItemID uuid.UUID `json:"item_id"`
	}
	if err := json.Unmarshal(body, &receipt); err != nil {
		t.Fatal(err)
	}
	return "/api/v1/items/" + receipt.ItemID.String()
}

func TestContentRateLimitBudgets(t *testing.T) {
	tests := []struct {
		name        string
		first       budgetRequest
		firstStatus int
		rejected    budgetRequest
	}{
		{
			name:     "capture shared across replicas",
			rejected: budgetRequest{http.MethodPost, "/api/v1/items", rateLimitCaptureBody, "application/json", "second"},
		},
		{
			name:        "read shared with recent",
			first:       budgetRequest{method: http.MethodGet, path: "{item}"},
			firstStatus: http.StatusOK,
			rejected:    budgetRequest{method: http.MethodGet, path: "/api/v1/items/recent"},
		},
		{
			name:        "search shared across queries",
			first:       budgetRequest{method: http.MethodGet, path: "/api/v1/items/search?q=content"},
			firstStatus: http.StatusOK,
			rejected:    budgetRequest{method: http.MethodGet, path: "/api/v1/items/search?q=other"},
		},
		{
			name:        "write shared between patch and delete",
			first:       budgetRequest{http.MethodPatch, "{item}", `{"keep":true}`, "application/merge-patch+json", ""},
			firstStatus: http.StatusOK,
			rejected:    budgetRequest{method: http.MethodDelete, path: "{item}"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixtureWithRules(t, oneRequestBudgets())
			itemPath := captureForBudgetTest(t, f)
			if tt.first.method != "" {
				r := tt.first
				status, _, body := f.call(t, f.server, r.method, strings.ReplaceAll(r.path, "{item}", itemPath), r.body, r.media, r.key)
				if status != tt.firstStatus {
					t.Fatalf("consume budget: status=%d body=%s", status, body)
				}
			}
			r := tt.rejected
			status, headers, body := f.call(t, f.replica, r.method, strings.ReplaceAll(r.path, "{item}", itemPath), r.body, r.media, r.key)
			if status != http.StatusTooManyRequests {
				t.Fatalf("shared budget: status=%d body=%s", status, body)
			}
			var problem struct {
				Status int    `json:"status"`
				Code   string `json:"code"`
			}
			if err := json.Unmarshal(body, &problem); err != nil {
				t.Fatal(err)
			}
			if problem.Status != status || problem.Code != "TOO_MANY_REQUESTS" {
				t.Fatalf("problem=%+v", problem)
			}
			if headers.Get("Retry-After") == "" {
				t.Fatal("rate limit response lacks Retry-After")
			}
			if len(headers.Values("Set-Cookie")) != 0 {
				t.Fatal("rate limit response changed cookies")
			}
			var count int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM content.items WHERE owner_id=$1`, f.owner).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("rejected request changed Item count: got=%d want=1", count)
			}
		})
	}
}

func TestRateLimitIsolation(t *testing.T) {
	f := newFixtureWithRules(t, oneRequestBudgets())
	path := captureForBudgetTest(t, f)
	for _, route := range []string{path, "/api/v1/items/search?q=content"} {
		status, _, body := f.call(t, f.server, http.MethodGet, route, "", "", "")
		if status != http.StatusOK {
			t.Fatalf("independent scope %s: status=%d body=%s", route, status, body)
		}
	}
	status, _, body := f.call(t, f.foreign, http.MethodGet, "/api/v1/items/recent", "", "", "")
	if status != http.StatusOK {
		t.Fatalf("different owner: status=%d body=%s", status, body)
	}
}

func TestContentRateLimitFallback(t *testing.T) {
	tests := []struct {
		name    string
		request budgetRequest
		status  int
	}{
		{"read", budgetRequest{method: http.MethodGet, path: "{item}"}, http.StatusOK},
		{"search", budgetRequest{method: http.MethodGet, path: "/api/v1/items/search?q=content"}, http.StatusOK},
		{"capture", budgetRequest{http.MethodPost, "/api/v1/items", rateLimitCaptureBody, "application/json", "fallback"}, http.StatusCreated},
		{"write", budgetRequest{method: http.MethodDelete, path: "{item}"}, http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixtureWithRules(t, oneRequestBudgets())
			itemPath := captureForBudgetTest(t, f)
			if err := f.redis.Close(); err != nil {
				t.Fatal(err)
			}
			r := tt.request
			path := strings.ReplaceAll(r.path, "{item}", itemPath)
			status, _, body := f.call(t, f.server, r.method, path, r.body, r.media, r.key)
			if status != tt.status {
				t.Fatalf("fallback: status=%d body=%s", status, body)
			}
		})
	}
}
