package capture

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/horizoonn/relay/content/internal/domain"
)

func (s *Service) Capture(
	ctx context.Context,
	command Command,
) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if command.OwnerID == uuid.Nil() || !validKey(command.IdempotencyKey) {
		return Result{}, ErrInvalidCommand
	}
	source, err := sourceFromCommand(command)
	if err != nil {
		return Result{}, err
	}
	fingerprint := commandFingerprint(source, command.Keep, command.Later)
	now := s.now().UTC()
	if now.IsZero() {
		return Result{}, fmt.Errorf("%w: missing capture time", ErrInvalidCommand)
	}

	var result Result
	err = s.transactor.WithinTransaction(ctx, func(ctx context.Context) error {
		var transactionErr error
		result, transactionErr = s.captureInTransaction(ctx, command, source, fingerprint, now)
		return transactionErr
	})
	if err != nil {
		return Result{}, fmt.Errorf("capture item transaction: %w", err)
	}
	return result, nil
}

func (s *Service) captureInTransaction(
	ctx context.Context,
	command Command,
	source domain.Source,
	fingerprint [32]byte,
	now time.Time,
) (Result, error) {
	record, claimed, err := s.idempotency.Claim(ctx, ClaimParams{
		OwnerID:            command.OwnerID,
		Key:                command.IdempotencyKey,
		FingerprintVersion: currentFingerprintVersion,
		Fingerprint:        fingerprint,
		Now:                now,
	})
	if err != nil {
		return Result{}, fmt.Errorf("claim capture key: %w", err)
	}
	if !claimed {
		return replayResult(record, source, command.Keep, command.Later)
	}
	result, err := s.captureItem(ctx, command, source, now)
	if err != nil {
		return Result{}, err
	}
	if err := s.idempotency.Complete(ctx, CompleteParams{
		OwnerID: command.OwnerID,
		Key:     command.IdempotencyKey,
		ItemID:  result.ItemID,
		Outcome: result.Outcome,
	}); err != nil {
		return Result{}, fmt.Errorf("complete capture key: %w", err)
	}
	return result, nil
}

func replayResult(
	record IdempotencyRecord,
	source domain.Source,
	keep, later bool,
) (Result, error) {
	storedFingerprint, err := fingerprintForVersion(record.FingerprintVersion, source, keep, later)
	if err != nil {
		return Result{}, err
	}
	if record.Fingerprint != storedFingerprint {
		return Result{}, ErrIdempotencyKeyReused
	}
	if record.ItemID == uuid.Nil() || (record.Outcome != OutcomeCreated && record.Outcome != OutcomeReused) {
		return Result{}, fmt.Errorf("incomplete capture receipt")
	}
	return Result{
		ItemID:  record.ItemID,
		Outcome: record.Outcome,
	}, nil
}

func (s *Service) captureItem(
	ctx context.Context,
	command Command,
	source domain.Source,
	now time.Time,
) (Result, error) {
	item, err := domain.NewItem(s.newID(), command.OwnerID, source, now)
	if err != nil {
		return Result{}, fmt.Errorf("create item: %w", err)
	}
	if command.Keep || command.Later {
		if applyErr := item.ApplyCapture(command.Keep, command.Later, now); applyErr != nil {
			return Result{}, fmt.Errorf("apply initial capture: %w", applyErr)
		}
	}
	for {
		created, createErr := s.items.Create(ctx, item)
		if createErr != nil {
			return Result{}, fmt.Errorf("insert item: %w", createErr)
		}
		if created {
			return Result{
				ItemID:  item.ID(),
				Outcome: OutcomeCreated,
			}, nil
		}
		if source.Type != domain.SourceURL {
			return Result{}, fmt.Errorf("text capture unexpectedly conflicted")
		}
		existing, findErr := s.items.FindByNormalizedURL(ctx, command.OwnerID, source.NormalizedURL)
		if errors.Is(findErr, ErrURLItemNotFound) {
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
			continue
		}
		if findErr != nil {
			return Result{}, fmt.Errorf("load URL item after create conflict: %w", findErr)
		}
		return s.reuseURLItem(ctx, command, source, now, existing)
	}
}

func (s *Service) reuseURLItem(
	ctx context.Context,
	command Command,
	source domain.Source,
	now time.Time,
	existing domain.Item,
) (Result, error) {
	if existing.OwnerID() != command.OwnerID {
		return Result{}, fmt.Errorf("URL item owner mismatch")
	}
	existingSource := existing.Source()
	if existingSource.Type != domain.SourceURL || existingSource.NormalizedURL != source.NormalizedURL {
		return Result{}, ErrURLHashCollision
	}
	if err := existing.ApplyCapture(command.Keep, command.Later, now); err != nil {
		return Result{}, fmt.Errorf("apply repeated capture: %w", err)
	}
	if err := s.items.Update(ctx, existing); err != nil {
		return Result{}, fmt.Errorf("update reused item: %w", err)
	}
	return Result{
		ItemID:  existing.ID(),
		Outcome: OutcomeReused,
	}, nil
}

func sourceFromCommand(command Command) (domain.Source, error) {
	switch command.SourceType {
	case domain.SourceURL:
		if command.Text != "" {
			return domain.Source{}, ErrInvalidCommand
		}
		return domain.NewURLSource(command.URL)
	case domain.SourceText:
		if command.URL != "" {
			return domain.Source{}, ErrInvalidCommand
		}
		return domain.NewTextSource(command.Text)
	default:
		return domain.Source{}, ErrInvalidCommand
	}
}

func validKey(key string) bool {
	if len(key) < 1 || len(key) > 128 {
		return false
	}
	for i := 0; i < len(key); i++ {
		if key[i] < ' ' || key[i] > '~' {
			return false
		}
	}
	return true
}

const currentFingerprintVersion int16 = 1

var errUnsupportedFingerprintVersion = errors.New("unsupported fingerprint version")

func commandFingerprint(source domain.Source, keep, later bool) [32]byte {
	value := source.Text
	if source.Type == domain.SourceURL {
		value = source.OriginalURL
	}
	data := make([]byte, 0, len(value)+32)
	for _, part := range [...]string{"capture/v1", string(source.Type), value} {
		data = binary.AppendUvarint(data, uint64(len(part)))
		data = append(data, part...)
	}
	if keep {
		data = append(data, 1)
	} else {
		data = append(data, 0)
	}
	if later {
		data = append(data, 1)
	} else {
		data = append(data, 0)
	}
	return sha256.Sum256(data)
}

func fingerprintForVersion(
	version int16,
	source domain.Source,
	keep, later bool,
) ([32]byte, error) {
	if version != currentFingerprintVersion {
		return [32]byte{}, fmt.Errorf("%w: %d", errUnsupportedFingerprintVersion, version)
	}
	return commandFingerprint(source, keep, later), nil
}
