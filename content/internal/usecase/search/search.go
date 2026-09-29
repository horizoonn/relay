package search

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"
	"uuid"

	"github.com/horizoonn/relay/content/internal/usecase"
)

const (
	maxQueryRunes = 256
	maxLimit      = 100
)

func (s *Service) Search(
	ctx context.Context,
	params Params,
) (Page, error) {
	if err := ctx.Err(); err != nil {
		return Page{}, err
	}
	params.Query = strings.TrimSpace(params.Query)
	if err := validateParams(params); err != nil {
		return Page{}, err
	}
	page, err := s.repository.Search(ctx, params)
	if err != nil {
		return Page{}, fmt.Errorf("search items: %w", err)
	}
	if page.Items == nil {
		page.Items = []usecase.ItemSummary{}
	}
	return page, nil
}

func validateParams(params Params) error {
	if params.OwnerID == uuid.Nil() {
		return fmt.Errorf("%w: missing owner ID", ErrInvalidQuery)
	}
	if params.Limit < 1 || params.Limit > maxLimit {
		return fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalidQuery, maxLimit)
	}
	if !utf8.ValidString(params.Query) {
		return fmt.Errorf("%w: query must be UTF-8", ErrInvalidQuery)
	}
	queryRunes := utf8.RuneCountInString(params.Query)
	if queryRunes == 0 || queryRunes > maxQueryRunes || strings.ContainsRune(params.Query, 0) {
		return fmt.Errorf(
			"%w: query must contain 1..%d code points without NUL",
			ErrInvalidQuery,
			maxQueryRunes,
		)
	}
	if params.After != nil && (params.After.Tier < MatchTitleExact || params.After.Tier > MatchURLSubstring ||
		(queryRunes <= 2 && params.After.Tier > MatchTitlePrefix) ||
		params.After.LastCapturedAt.IsZero() || params.After.ID == uuid.Nil()) {
		return fmt.Errorf("%w: invalid page anchor", ErrInvalidQuery)
	}
	return nil
}
