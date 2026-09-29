package collection

import (
	"context"
	"fmt"

	"github.com/horizoonn/relay/content/internal/usecase"
)

func (s *Service) ListLater(
	ctx context.Context,
	params ListParams,
) (Page, error) {
	if err := validateParams(params); err != nil {
		return Page{}, err
	}
	if err := ctx.Err(); err != nil {
		return Page{}, err
	}
	page, err := s.reader.ListLater(ctx, params)
	if err != nil {
		return Page{}, fmt.Errorf("list later items: %w", err)
	}
	if page.Items == nil {
		page.Items = []usecase.ItemSummary{}
	}
	return page, nil
}
