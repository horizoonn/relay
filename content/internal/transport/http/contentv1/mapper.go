package contentv1

import (
	"fmt"

	contentapi "github.com/horizoonn/relay/shared/pkg/openapi/content/v1"

	"github.com/horizoonn/relay/content/internal/domain"
	"github.com/horizoonn/relay/content/internal/usecase"
)

func toAPIItem(item domain.Item) (contentapi.Item, error) {
	source := item.Source()
	var apiSource contentapi.Source
	switch source.Type {
	case domain.SourceURL:
		apiSource = contentapi.NewURLSourceSource(contentapi.URLSource{
			Type: contentapi.URLSourceTypeURL,
			URL:  source.OriginalURL,
		})
	case domain.SourceText:
		apiSource = contentapi.NewTextSourceSource(contentapi.TextSource{
			Type: contentapi.TextSourceTypeText,
			Text: source.Text,
		})
	default:
		return contentapi.Item{}, fmt.Errorf(
			"unsupported item source type %q",
			source.Type,
		)
	}
	result := contentapi.Item{
		ID:             contentapi.ItemID(item.ID()),
		Source:         apiSource,
		Keep:           item.Keep(),
		ReviewStatus:   contentapi.ReviewStatus(item.ReviewStatus()),
		CreatedAt:      item.CreatedAt(),
		UpdatedAt:      item.UpdatedAt(),
		LastCapturedAt: item.LastCapturedAt(),
	}
	if title := item.DisplayTitle(); title != "" {
		result.DisplayTitle = contentapi.NewOptString(title)
	}
	return result, nil
}

func toAPISummary(item usecase.ItemSummary) contentapi.ItemSummary {
	result := contentapi.ItemSummary{
		ID:               contentapi.ItemID(item.ID),
		SourceType:       contentapi.ItemSourceType(item.SourceType),
		Preview:          item.Preview,
		PreviewTruncated: item.PreviewTruncated,
		Keep:             item.Keep,
		ReviewStatus:     contentapi.ReviewStatus(item.ReviewStatus),
		CreatedAt:        item.CreatedAt,
		UpdatedAt:        item.UpdatedAt,
		LastCapturedAt:   item.LastCapturedAt,
	}
	if item.DisplayTitle != "" {
		result.DisplayTitle = contentapi.NewOptString(item.DisplayTitle)
	}
	return result
}
