package contentv1

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/horizoonn/relay/platform/pkg/ratelimit"
	contentapi "github.com/horizoonn/relay/shared/pkg/openapi/content/v1"
	"go.uber.org/zap"

	"github.com/horizoonn/relay/content/internal/usecase/capture"
	"github.com/horizoonn/relay/content/internal/usecase/item"
)

func TestWrappedUsecaseErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   contentapi.ProblemCode
		retry  string
	}{
		{
			name:   "item not found",
			err:    item.ErrItemNotFound,
			status: http.StatusNotFound,
			code:   contentapi.ProblemCodeITEMNOTFOUND,
		},
		{
			name:   "idempotency conflict",
			err:    capture.ErrIdempotencyKeyReused,
			status: http.StatusConflict,
			code:   contentapi.ProblemCodeIDEMPOTENCYKEYREUSED,
		},
		{
			name:   "invalid patch",
			err:    item.ErrInvalidRequest,
			status: http.StatusBadRequest,
			code:   contentapi.ProblemCodeINVALIDREQUEST,
		},
		{
			name: "rate limit",
			err: &ratelimit.ExceededError{
				RetryAfter: 1500 * time.Millisecond,
			},
			status: http.StatusTooManyRequests,
			code:   contentapi.ProblemCodeTOOMANYREQUESTS,
			retry:  "2",
		},
		{
			name:   "internal failure",
			err:    errors.New("private source content"),
			status: http.StatusInternalServerError,
			code:   contentapi.ProblemCodeINTERNALERROR,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := &Handler{
				log: zap.NewNop(),
			}
			err := fmt.Errorf("handle item operation: %w", fmt.Errorf("repository operation: %w", tc.err))
			problem := handler.NewError(t.Context(), err)
			response := httptest.NewRecorder()
			handler.writeProblem(response, problem)
			assertProblem(t, response, tc.status, string(tc.code))
			if response.Header().Get("Retry-After") != tc.retry {
				t.Fatalf("Retry-After = %q, want %q", response.Header().Get("Retry-After"), tc.retry)
			}
			if strings.Contains(response.Body.String(), "private source content") ||
				strings.Contains(response.Body.String(), "repository operation") {
				t.Fatal("internal error context exposed in HTTP response")
			}
		})
	}
}
