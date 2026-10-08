package domain

import (
	"net/mail"
	"strings"
	"time"
	"uuid"
)

type UserState string

const (
	UserActive   UserState = "active"
	UserDisabled UserState = "disabled"
)

type User struct {
	ID              uuid.UUID
	Email           string
	EmailVerifiedAt *time.Time
	State           UserState
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func NewUser(email string, now time.Time) (User, error) {
	normalized, err := NormalizeEmail(email)
	if err != nil {
		return User{}, err
	}
	u := User{
		ID:        uuid.NewV7(),
		Email:     normalized,
		State:     UserActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	return u, u.Validate()
}

func (u User) Validate() error {
	normalized, err := NormalizeEmail(u.Email)
	if err != nil || normalized != u.Email ||
		u.ID == uuid.Nil() || (u.State != UserActive && u.State != UserDisabled) ||
		u.CreatedAt.IsZero() || u.UpdatedAt.Before(u.CreatedAt) ||
		(u.EmailVerifiedAt != nil && u.EmailVerifiedAt.Before(u.CreatedAt)) {
		return ErrInvalidUser
	}
	return nil
}

func NormalizeEmail(raw string) (string, error) {
	email := strings.TrimSpace(raw)
	if len(email) == 0 || len(email) > 254 || strings.ContainsAny(email, "\r\n") {
		return "", ErrInvalidEmail
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Name != "" || address.Address != email {
		return "", ErrInvalidEmail
	}
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return "", ErrInvalidEmail
	}
	return email[:at+1] + strings.ToLower(email[at+1:]), nil
}
