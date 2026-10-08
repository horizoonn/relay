package email

import (
	"time"
	"uuid"
)

type MailJob struct {
	ID               uuid.UUID
	EncryptedPayload []byte
	PreparedUserID   uuid.UUID
	CreatedAt        time.Time
	ExpiresAt        time.Time
	LeaseToken       uuid.UUID
	Attempts         int
}

type Mail struct {
	ID        uuid.UUID
	CreatedAt time.Time
	To        string
	Subject   string
	Body      string
}
