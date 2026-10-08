//go:build component

package component

import (
	"encoding/json/v2"
	"net/http"
	"testing"
	"uuid"
)

func TestNULInputPreservesItems(t *testing.T) {
	f := newFixture(t)
	captureStatus, _, body := f.call(t,
		f.server,
		http.MethodPost,
		"/api/v1/items",
		`{"source_type":"text","text":"original"}`,
		"application/json",
		"valid-text",
	)
	if captureStatus != 201 {
		t.Fatalf("initial capture=%d", captureStatus)
	}
	var receipt struct {
		ItemID uuid.UUID `json:"item_id"`
	}
	if err := json.Unmarshal(body, &receipt); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		method      string
		path        string
		body        string
		contentType string
	}{
		{
			name:        "capture text",
			method:      http.MethodPost,
			path:        "/api/v1/items",
			body:        `{"source_type":"text","text":"a\u0000b"}`,
			contentType: "application/json",
		},
		{
			name:        "patch title",
			method:      http.MethodPatch,
			path:        "/api/v1/items/" + receipt.ItemID.String(),
			body:        `{"display_title":"a\u0000b"}`,
			contentType: "application/merge-patch+json",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, headers, _ := f.call(t, f.server, tc.method, tc.path, tc.body, tc.contentType, "invalid-text")
			if status != 400 || headers.Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d cache=%q", status, headers.Get("Cache-Control"))
			}
			var count int
			if err := f.pool.QueryRow(
				f.ctx,
				`SELECT count(*) FROM content.items WHERE owner_id=$1`,
				f.owner,
			).Scan(&count); err != nil ||
				count != 1 {
				t.Fatalf("items=%d err=%v", count, err)
			}
			var title *string
			if err := f.pool.QueryRow(
				f.ctx,
				`SELECT display_title FROM content.items WHERE id=$1`,
				receipt.ItemID,
			).Scan(&title); err != nil ||
				title != nil {
				t.Fatalf("title changed; err=%v", err)
			}
		})
	}
	status, headers, _ := f.call(t, f.server, http.MethodGet, "/api/v1/items/"+receipt.ItemID.String(), "", "", "")
	if status != 200 || headers.Get("Cache-Control") != "no-store" || headers.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("private GET headers missing")
	}
}
