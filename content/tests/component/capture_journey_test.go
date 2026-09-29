//go:build component

package component

import (
	"encoding/json/v2"
	"net/http"
	"testing"
	"time"
	"uuid"
)

func TestCaptureJourney(t *testing.T) {
	f := newFixture(t)
	url := "https://example.com/relay/" + uuid.New().String()
	request := `{"source_type":"url","url":"` + url + `","keep":true}`
	status, headers, body := f.call(f.server, http.MethodPost, "/api/v1/items", request, "application/json", "create")
	var receipt struct {
		ItemID  uuid.UUID `json:"item_id"`
		Outcome string    `json:"outcome"`
	}
	if err := json.Unmarshal(body, &receipt); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/items/" + receipt.ItemID.String()
	if status != http.StatusCreated || receipt.ItemID == uuid.Nil() ||
		receipt.Outcome != "created" || headers.Get("Location") != path {
		t.Fatalf("create: status=%d headers=%v body=%s", status, headers, body)
	}
	var capturedAt, updatedAt time.Time
	const timestampsQuery = `
		SELECT last_captured_at, updated_at
		FROM content.items
		WHERE id = $1
	`
	if err := f.pool.QueryRow(f.ctx, timestampsQuery, receipt.ItemID).
		Scan(&capturedAt, &updatedAt); err != nil {
		t.Fatal(err)
	}
	status, replayHeaders, replayBody := f.call(
		f.server, http.MethodPost, "/api/v1/items", request, "application/json", "create",
	)
	if status != http.StatusCreated || string(replayBody) != string(body) ||
		replayHeaders.Get("Location") != headers.Get("Location") {
		t.Fatalf("replay: status=%d body=%s", status, replayBody)
	}
	var replayCapturedAt, replayUpdatedAt time.Time
	if err := f.pool.QueryRow(f.ctx, timestampsQuery, receipt.ItemID).
		Scan(&replayCapturedAt, &replayUpdatedAt); err != nil {
		t.Fatal(err)
	}
	if !replayCapturedAt.Equal(capturedAt) || !replayUpdatedAt.Equal(updatedAt) {
		t.Fatalf("replay changed timestamps: captured %s -> %s, updated %s -> %s",
			capturedAt, replayCapturedAt, updatedAt, replayUpdatedAt)
	}

	status, _, foreignBody := f.call(f.foreign, http.MethodGet, path, "", "", "")
	if status != http.StatusNotFound {
		t.Fatalf("foreign GET: %d %s", status, foreignBody)
	}
	status, _, missingBody := f.call(f.server, http.MethodGet, "/api/v1/items/"+uuid.New().String(), "", "", "")
	if status != http.StatusNotFound {
		t.Fatalf("missing GET: %d %s", status, missingBody)
	}
	var foreignProblem, missingProblem struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(foreignBody, &foreignProblem); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(missingBody, &missingProblem); err != nil {
		t.Fatal(err)
	}
	if foreignProblem.Code != "ITEM_NOT_FOUND" || missingProblem.Code != foreignProblem.Code {
		t.Fatalf("foreign and missing errors differ: %q, %q", foreignProblem.Code, missingProblem.Code)
	}

	status, _, body = f.call(
		f.server, http.MethodPatch, path, `{"review_status":"later"}`, "application/merge-patch+json", "",
	)
	if status != http.StatusOK {
		t.Fatalf("PATCH: %d %s", status, body)
	}
	var patched struct {
		Keep         bool   `json:"keep"`
		ReviewStatus string `json:"review_status"`
	}
	if err := json.Unmarshal(body, &patched); err != nil {
		t.Fatal(err)
	}
	if !patched.Keep || patched.ReviewStatus != "later" {
		t.Fatalf("PATCH lost user context: %+v", patched)
	}
	var patchCapturedAt time.Time
	const capturedAtQuery = `
		SELECT last_captured_at
		FROM content.items
		WHERE id = $1
	`
	if err := f.pool.QueryRow(f.ctx, capturedAtQuery, receipt.ItemID).Scan(&patchCapturedAt); err != nil {
		t.Fatal(err)
	}
	if !patchCapturedAt.Equal(capturedAt) {
		t.Fatalf("PATCH changed last_captured_at: %s -> %s", capturedAt, patchCapturedAt)
	}
	for _, surface := range []string{
		"/api/v1/items/search?q=relay",
		"/api/v1/items/recent",
		"/api/v1/items/library",
		"/api/v1/items/later",
	} {
		assertOnlyItem(t, f, surface, receipt.ItemID)
	}
	status, _, body = f.call(f.server, http.MethodDelete, path, "", "", "")
	if status != http.StatusNoContent {
		t.Fatalf("DELETE: %d %s", status, body)
	}
	status, _, body = f.call(f.server, http.MethodGet, path, "", "", "")
	if status != http.StatusNotFound {
		t.Fatalf("GET after DELETE: %d %s", status, body)
	}
	status, _, body = f.call(f.server, http.MethodDelete, path, "", "", "")
	if status != http.StatusNotFound {
		t.Fatalf("repeated DELETE: %d %s", status, body)
	}
	for _, surface := range []string{
		"/api/v1/items/search?q=relay",
		"/api/v1/items/recent",
		"/api/v1/items/library",
		"/api/v1/items/later",
	} {
		assertOnlyItem(t, f, surface, uuid.Nil())
	}
}

func assertOnlyItem(
	t *testing.T,
	f *fixture,
	path string,
	want uuid.UUID,
) {
	t.Helper()
	status, _, body := f.call(f.server, http.MethodGet, path, "", "", "")
	if status != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, status, body)
	}
	var page struct {
		Items []struct {
			ID uuid.UUID `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	if want == uuid.Nil() {
		if len(page.Items) != 0 {
			t.Fatalf("GET %s after deletion: %+v", path, page.Items)
		}
		return
	}
	if len(page.Items) != 1 || page.Items[0].ID != want {
		t.Fatalf("GET %s: %+v; want %s", path, page.Items, want)
	}
}
