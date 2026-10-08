package contentv1

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"net/http"
	"testing"
	"uuid"

	"github.com/horizoonn/relay/content/internal/domain"
	"github.com/horizoonn/relay/content/internal/usecase/capture"
	"github.com/horizoonn/relay/content/internal/usecase/collection"
	"github.com/horizoonn/relay/content/internal/usecase/item"
	"github.com/horizoonn/relay/content/internal/usecase/search"
)

type captureRouteStore struct {
	items    map[uuid.UUID]domain.Item
	receipts map[string]capture.IdempotencyRecord
	claims   map[string]capture.ClaimParams
}

func newCaptureRouteStore() *captureRouteStore {
	return &captureRouteStore{
		items:    make(map[uuid.UUID]domain.Item),
		receipts: make(map[string]capture.IdempotencyRecord),
		claims:   make(map[string]capture.ClaimParams),
	}
}

func (s *captureRouteStore) Claim(
	_ context.Context,
	params capture.ClaimParams,
) (capture.IdempotencyRecord, bool, error) {
	if record, ok := s.receipts[params.Key]; ok {
		return record, false, nil
	}
	s.claims[params.Key] = params
	return capture.IdempotencyRecord{}, true, nil
}

func (s *captureRouteStore) Complete(
	_ context.Context,
	params capture.CompleteParams,
) error {
	claim, ok := s.claims[params.Key]
	if !ok || claim.OwnerID != params.OwnerID {
		return errors.New("capture receipt was not claimed")
	}
	s.receipts[params.Key] = capture.IdempotencyRecord{
		FingerprintVersion: claim.FingerprintVersion,
		Fingerprint:        claim.Fingerprint,
		ItemID:             params.ItemID,
		Outcome:            params.Outcome,
	}
	return nil
}

func (s *captureRouteStore) Create(
	_ context.Context,
	value domain.Item,
) (bool, error) {
	for _, current := range s.items {
		if current.OwnerID() == value.OwnerID() && current.Source().Type == domain.SourceURL &&
			current.Source().NormalizedURL == value.Source().NormalizedURL {
			return false, nil
		}
	}
	s.items[value.ID()] = value
	return true, nil
}

func (s *captureRouteStore) FindByNormalizedURL(
	_ context.Context,
	owner uuid.UUID,
	normalizedURL string,
) (domain.Item, error) {
	hash := sha256.Sum256([]byte(normalizedURL))
	for _, value := range s.items {
		if value.OwnerID() == owner && value.Source().Type == domain.SourceURL &&
			sha256.Sum256([]byte(value.Source().NormalizedURL)) == hash {
			return value, nil
		}
	}
	return domain.Item{}, errors.New("URL Item not found")
}

func (s *captureRouteStore) Update(
	_ context.Context,
	value domain.Item,
) error {
	s.items[value.ID()] = value
	return nil
}

func TestCaptureRoute(t *testing.T) {
	t.Parallel()
	store := newCaptureRouteStore()
	codec, err := NewCursorCodec([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(
		capture.NewService(store, store, routeTx{}),
		item.NewService(&routeStore{}, routeTx{}),
		collection.NewService(&routeReader{}),
		search.NewService(&routeSearch{}),
		codec,
		testLogger(),
	)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(handler, fakeVerifier{
		owner: routeOwnerID,
		token: "access",
		csrf:  testCSRF,
	}, testOrigin, unlimitedLimiter{})
	if err != nil {
		t.Fatal(err)
	}
	call := func(key, body string) (int, string, uuid.UUID) {
		t.Helper()
		req := routeRequest(http.MethodPost, "/api/v1/items", body, "application/json")
		req.Header.Set("Idempotency-Key", key)
		response := routeResponse(t, server, req)
		if response.Code != http.StatusCreated && response.Code != http.StatusOK {
			t.Fatalf("Capture %q: status=%d body=%s", key, response.Code, response.Body.String())
		}
		var receipt struct {
			ItemID  uuid.UUID `json:"item_id"`
			Outcome string    `json:"outcome"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil {
			t.Fatal(err)
		}
		if receipt.ItemID == uuid.Nil() || response.Header().Get("X-Request-ID") == "" {
			t.Fatalf("invalid receipt: %+v", receipt)
		}
		if response.Code == http.StatusCreated &&
			response.Header().Get("Location") != "/api/v1/items/"+receipt.ItemID.String() {
			t.Fatalf("Location=%q", response.Header().Get("Location"))
		}
		return response.Code, receipt.Outcome, receipt.ItemID
	}

	firstBody := `{"source_type":"url","url":"HTTPS://EXAMPLE.COM/a","keep":true}`
	status, outcome, firstID := call("first", firstBody)
	if status != http.StatusCreated || outcome != "created" || len(store.items) != 1 ||
		store.items[firstID].Source().OriginalURL != "HTTPS://EXAMPLE.COM/a" {
		t.Fatalf("created: status=%d outcome=%q items=%d", status, outcome, len(store.items))
	}
	status, outcome, reusedID := call("second", `{"source_type":"url","url":"https://example.com/a","later":true}`)
	if status != http.StatusOK || outcome != "reused" || reusedID != firstID || len(store.items) != 1 ||
		!store.items[firstID].Keep() || store.items[firstID].ReviewStatus() != domain.ReviewLater {
		t.Fatalf("reused: status=%d outcome=%q id=%s", status, outcome, reusedID)
	}
	status, outcome, replayID := call("first", firstBody)
	if status != http.StatusCreated || outcome != "created" || replayID != firstID || len(store.items) != 1 {
		t.Fatalf("replay: status=%d outcome=%q id=%s", status, outcome, replayID)
	}

	req := routeRequest(http.MethodPost, "/api/v1/items", `{"source_type":"text","text":"different"}`, "application/json")
	req.Header.Set("Idempotency-Key", "first")
	assertProblem(t, routeResponse(t, server, req), http.StatusConflict, "IDEMPOTENCY_KEY_REUSED")
}
