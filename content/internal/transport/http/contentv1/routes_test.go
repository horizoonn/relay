package contentv1

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/content/internal/domain"
	"github.com/horizoonn/relay/content/internal/usecase"
	"github.com/horizoonn/relay/content/internal/usecase/capture"
	"github.com/horizoonn/relay/content/internal/usecase/collection"
	"github.com/horizoonn/relay/content/internal/usecase/item"
	"github.com/horizoonn/relay/content/internal/usecase/search"
)

const testOrigin = "https://relay.example"

var (
	routeOwnerID = uuid.MustParse("00000000-0000-0000-0000-000000000001")
	routeItemID  = uuid.MustParse("00000000-0000-0000-0000-000000000002")
)

type routeStore struct {
	item    domain.Item
	deleted bool
	updates int
}

func (s *routeStore) Get(
	_ context.Context,
	ownerID,
	itemID uuid.UUID,
) (domain.Item, error) {
	if s.deleted || ownerID != s.item.OwnerID() || itemID != s.item.ID() {
		return domain.Item{}, item.ErrItemNotFound
	}
	return s.item, nil
}

func (s *routeStore) GetForUpdate(
	ctx context.Context,
	ownerID,
	itemID uuid.UUID,
) (domain.Item, error) {
	return s.Get(ctx, ownerID, itemID)
}

func (s *routeStore) Patch(
	_ context.Context,
	value domain.Item,
	_ item.PatchFields,
) error {
	s.item = value
	s.updates++
	return nil
}

func (s *routeStore) Delete(
	ctx context.Context,
	ownerID,
	itemID uuid.UUID,
) error {
	if _, err := s.Get(ctx, ownerID, itemID); err != nil {
		return err
	}
	s.deleted = true
	return nil
}

type routeTx struct{}

func (routeTx) WithinTransaction(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	return fn(ctx)
}

type routeReader struct {
	params collection.ListParams
	called string
	page   collection.Page
}

func (r *routeReader) ListRecent(
	_ context.Context,
	params collection.ListParams,
) (collection.Page, error) {
	r.called, r.params = "recent", params
	return r.page, nil
}

func (r *routeReader) ListLibrary(
	_ context.Context,
	params collection.ListParams,
) (collection.Page, error) {
	r.called, r.params = "library", params
	return r.page, nil
}

func (r *routeReader) ListLater(
	_ context.Context,
	params collection.ListParams,
) (collection.Page, error) {
	r.called, r.params = "later", params
	return r.page, nil
}

type routeSearch struct {
	params search.Params
	page   search.Page
}

func (r *routeSearch) Search(
	_ context.Context,
	params search.Params,
) (search.Page, error) {
	r.params = params
	return r.page, nil
}

type routeFixture struct {
	server http.Handler
	store  *routeStore
	reader *routeReader
	search *routeSearch
}

func newRouteFixture(t *testing.T) routeFixture {
	t.Helper()
	return newRouteFixtureWithOwner(t, routeOwnerID)
}

func newRouteFixtureWithOwner(
	t *testing.T,
	authenticatedOwner uuid.UUID,
) routeFixture {
	t.Helper()
	source, err := domain.NewTextSource("Original text")
	if err != nil {
		t.Fatal(err)
	}
	value, err := domain.NewItem(
		routeItemID,
		routeOwnerID,
		source,
		time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	store := &routeStore{
		item: value,
	}
	reader := &routeReader{}
	searchRepo := &routeSearch{}
	codec, err := NewCursorCodec([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	captureStore := newCaptureRouteStore()
	handler, err := NewHandler(
		capture.NewService(captureStore, captureStore, routeTx{}),
		item.NewService(store, routeTx{}),
		collection.NewService(reader),
		search.NewService(searchRepo),
		codec,
		testLogger(),
	)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(handler, fakeAuthenticator{
		owner: authenticatedOwner,
		token: "access",
		csrf:  "csrf",
	}, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	return routeFixture{
		server: server,
		store:  store,
		reader: reader,
		search: searchRepo,
	}
}

func routeRequest(method, path, body, contentType string) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequestWithContext(context.Background(), method, path, nil)
	} else {
		req = httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	}
	req.AddCookie(&http.Cookie{
		Name:  "relay_access_token",
		Value: "access",
	})
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", testOrigin)
		req.Header.Set("X-CSRF-Token", "csrf")
	}
	return req
}

func routeResponse(
	t *testing.T,
	server http.Handler,
	req *http.Request,
) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	server.ServeHTTP(response, req)
	return response
}

func TestGetItemResponse(t *testing.T) {
	t.Parallel()
	fixture := newRouteFixture(t)
	path := "/api/v1/items/" + routeItemID.String()
	response := routeResponse(t, fixture.server, routeRequest(http.MethodGet, path, "", ""))
	if response.Code != http.StatusOK || response.Header().Get("Accept-Patch") != "application/merge-patch+json" {
		t.Fatalf(
			"status/Accept-Patch=%d/%q; body=%s",
			response.Code,
			response.Header().Get("Accept-Patch"),
			response.Body.String(),
		)
	}
	var body struct {
		ID     uuid.UUID `json:"id"`
		Source struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"source"`
		Keep bool `json:"keep"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.ID != routeItemID || body.Source.Type != "text" ||
		body.Source.Text != "Original text" || body.Keep {
		t.Fatalf("Item=%+v", body)
	}
	if response.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing request ID")
	}
}

func TestGetItemOwnerScope(t *testing.T) {
	t.Parallel()
	fixture := newRouteFixtureWithOwner(t, uuid.MustParse("00000000-0000-0000-0000-000000000003"))
	response := routeResponse(t,
		fixture.server,
		routeRequest(http.MethodGet, "/api/v1/items/"+routeItemID.String(), "", ""),
	)
	assertProblem(t, response, http.StatusNotFound, "ITEM_NOT_FOUND")
}

func TestPatchFields(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name             string
		body             string
		initialTitle     string
		initialKeep      bool
		wantTitle        string
		wantTitlePresent bool
		wantKeep         bool
		wantUpdates      int
	}{
		{
			name:             "omitted title",
			body:             `{"keep":true}`,
			initialTitle:     "First title",
			wantTitle:        "First title",
			wantTitlePresent: true,
			wantKeep:         true,
			wantUpdates:      1,
		},
		{
			name:         "null title",
			body:         `{"display_title":null}`,
			initialTitle: "First title",
			initialKeep:  true,
			wantKeep:     true,
			wantUpdates:  1,
		},
		{
			name:             "string title",
			body:             `{"display_title":"New title"}`,
			initialKeep:      true,
			wantTitle:        "New title",
			wantTitlePresent: true,
			wantKeep:         true,
			wantUpdates:      1,
		},
		{
			name:        "no-op keep",
			body:        `{"keep":false}`,
			wantUpdates: 0,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixture := newRouteFixture(t)
			value := fixture.store.item
			if tt.initialTitle != "" {
				if err := value.SetDisplayTitle(tt.initialTitle, value.CreatedAt()); err != nil {
					t.Fatal(err)
				}
			}
			if tt.initialKeep {
				if err := value.SetKeep(true, value.CreatedAt()); err != nil {
					t.Fatal(err)
				}
			}
			fixture.store.item = value
			path := "/api/v1/items/" + routeItemID.String()
			response := routeResponse(t,
				fixture.server,
				routeRequest(http.MethodPatch, path, tt.body, "application/merge-patch+json"),
			)
			if response.Code != http.StatusOK {
				t.Fatalf("PATCH status=%d body=%s", response.Code, response.Body.String())
			}
			var body struct {
				DisplayTitle string `json:"display_title"`
				Keep         bool   `json:"keep"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			var fields map[string]jsontext.Value
			if err := json.Unmarshal(response.Body.Bytes(), &fields); err != nil {
				t.Fatal(err)
			}
			_, titlePresent := fields["display_title"]
			if body.DisplayTitle != tt.wantTitle || titlePresent != tt.wantTitlePresent ||
				body.Keep != tt.wantKeep || fixture.store.updates != tt.wantUpdates {
				t.Fatalf("PATCH body=%+v titlePresent=%t updates=%d", body, titlePresent, fixture.store.updates)
			}
		})
	}
}

func TestDeleteItemTwice(t *testing.T) {
	t.Parallel()
	fixture := newRouteFixture(t)
	path := "/api/v1/items/" + routeItemID.String()
	response := routeResponse(t, fixture.server, routeRequest(http.MethodDelete, path, "", ""))
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("DELETE status/body=%d/%q", response.Code, response.Body.String())
	}
	response = routeResponse(t, fixture.server, routeRequest(http.MethodDelete, path, "", ""))
	assertProblem(t, response, http.StatusNotFound, "ITEM_NOT_FOUND")
}

func TestCollections(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		path string
	}{
		{
			name: "recent",
			path: "/api/v1/items/recent",
		},
		{
			name: "library",
			path: "/api/v1/items/library",
		},
		{
			name: "later",
			path: "/api/v1/items/later",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixture := newRouteFixture(t)
			response := routeResponse(t, fixture.server, routeRequest(http.MethodGet, tt.path, "", ""))
			if response.Code != http.StatusOK {
				t.Fatalf("GET %s: status=%d body=%s", tt.path, response.Code, response.Body.String())
			}
			var body struct {
				Items []jsontext.Value `json:"items"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Items == nil || fixture.reader.called != tt.name ||
				fixture.reader.params.OwnerID != routeOwnerID || fixture.reader.params.Limit != 20 {
				t.Fatalf(
					"GET %s: items=%v called=%q params=%+v",
					tt.path,
					body.Items,
					fixture.reader.called,
					fixture.reader.params,
				)
			}
		})
	}
}

func TestCollectionCursor(t *testing.T) {
	t.Parallel()
	fixture := newRouteFixture(t)
	anchor := collection.Anchor{
		At: fixture.store.item.LastCapturedAt(),
		ID: routeItemID,
	}
	fixture.reader.page = collection.Page{
		Items: []usecase.ItemSummary{{
			ID:             routeItemID,
			SourceType:     domain.SourceText,
			Preview:        "Original text",
			ReviewStatus:   domain.ReviewNone,
			CreatedAt:      anchor.At,
			UpdatedAt:      anchor.At,
			LastCapturedAt: anchor.At,
		}},
		Next: &anchor,
	}
	first := routeResponse(t,
		fixture.server,
		routeRequest(http.MethodGet, "/api/v1/items/recent?limit=1", "", ""),
	)
	if first.Code != http.StatusOK {
		t.Fatalf("first page: %d %s", first.Code, first.Body.String())
	}
	var body struct {
		Items []struct {
			ID         uuid.UUID `json:"id"`
			SourceType string    `json:"source_type"`
			Preview    string    `json:"preview"`
		} `json:"items"`
		NextCursor string `json:"next_cursor"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Items) != 1 || body.Items[0].ID != routeItemID ||
		body.Items[0].SourceType != "text" || body.Items[0].Preview != "Original text" ||
		body.NextCursor == "" || fixture.reader.called != "recent" ||
		fixture.reader.params.OwnerID != routeOwnerID || fixture.reader.params.Limit != 1 {
		t.Fatalf("cursor=%q called=%q params=%+v", body.NextCursor, fixture.reader.called, fixture.reader.params)
	}
	fixture.reader.page.Next = nil
	second := routeResponse(t,
		fixture.server,
		routeRequest(http.MethodGet, "/api/v1/items/recent?cursor="+url.QueryEscape(body.NextCursor), "", ""),
	)
	if second.Code != http.StatusOK || fixture.reader.params.After == nil ||
		*fixture.reader.params.After != anchor || fixture.reader.params.Limit != 20 {
		t.Fatalf("second page: status=%d params=%+v body=%s", second.Code, fixture.reader.params, second.Body.String())
	}
	foreignSurface := routeResponse(t,
		fixture.server,
		routeRequest(http.MethodGet, "/api/v1/items/library?cursor="+url.QueryEscape(body.NextCursor), "", ""),
	)
	assertProblem(t, foreignSurface, http.StatusBadRequest, "INVALID_REQUEST")
}

func TestSearchCursor(t *testing.T) {
	t.Parallel()
	fixture := newRouteFixture(t)
	anchor := search.Anchor{
		Tier:           search.MatchTitlePrefix,
		LastCapturedAt: fixture.store.item.LastCapturedAt(),
		ID:             routeItemID,
	}
	fixture.search.page = search.Page{
		Next: &anchor,
	}
	first := routeResponse(t, fixture.server, routeRequest(http.MethodGet, "/api/v1/items/search?q=title", "", ""))
	if first.Code != http.StatusOK {
		t.Fatalf("first search: %d %s", first.Code, first.Body.String())
	}
	var body struct {
		NextCursor string `json:"next_cursor"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.NextCursor == "" || fixture.search.params.Query != "title" || fixture.search.params.OwnerID != routeOwnerID {
		t.Fatalf("cursor=%q search params=%+v", body.NextCursor, fixture.search.params)
	}
	fixture.search.page.Next = nil
	second := routeResponse(t,
		fixture.server,
		routeRequest(http.MethodGet, "/api/v1/items/search?q=title&cursor="+url.QueryEscape(body.NextCursor), "", ""),
	)
	if second.Code != http.StatusOK || fixture.search.params.After == nil || *fixture.search.params.After != anchor {
		t.Fatalf("second search: status=%d params=%+v", second.Code, fixture.search.params)
	}
	changedQuery := routeResponse(t,
		fixture.server,
		routeRequest(http.MethodGet, "/api/v1/items/search?q=other&cursor="+url.QueryEscape(body.NextCursor), "", ""),
	)
	assertProblem(t, changedQuery, http.StatusBadRequest, "INVALID_REQUEST")
}

func TestPatchInvalidInput(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name        string
		body        string
		contentType string
		wantStatus  int
		wantCode    string
	}{
		{
			name:        "wrong media type",
			body:        `{"keep":true}`,
			contentType: "application/json",
			wantStatus:  http.StatusUnsupportedMediaType,
			wantCode:    "UNSUPPORTED_MEDIA_TYPE",
		},
		{
			name:        "oversize body",
			body:        `{"display_title":"` + strings.Repeat("a", maxJSONBodyBytes) + `"}`,
			contentType: "application/merge-patch+json",
			wantStatus:  http.StatusRequestEntityTooLarge,
			wantCode:    "PAYLOAD_TOO_LARGE",
		},
		{
			name:        "null keep",
			body:        `{"keep":null}`,
			contentType: "application/merge-patch+json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "INVALID_REQUEST",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixture := newRouteFixture(t)
			path := "/api/v1/items/" + routeItemID.String()
			response := routeResponse(t, fixture.server, routeRequest(http.MethodPatch, path, tt.body, tt.contentType))
			assertProblem(t, response, tt.wantStatus, tt.wantCode)
			if fixture.store.updates != 0 {
				t.Fatal("invalid HTTP input reached the Item mutation")
			}
		})
	}
}
