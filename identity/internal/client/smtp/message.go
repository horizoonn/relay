package smtp

import (
	"errors"
	"io"
	"mime"
	"strings"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/usecase/email"
)

func (s *Sender) writeMessage(body io.WriteCloser, message email.Mail) error {
	id := message.ID
	if id == uuid.Nil() {
		id = uuid.NewV7()
	}
	createdAt := message.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	domain := s.config.From[strings.LastIndexByte(s.config.From, '@')+1:]
	headers := strings.Join([]string{
		"Date: " + createdAt.Format(time.RFC1123Z),
		"Message-ID: <" + id.String() + "@" + domain + ">",
		"From: " + s.config.From,
		"To: " + message.To,
		"Subject: " + mime.QEncoding.Encode("utf-8", message.Subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: 8bit",
		"", "",
	}, "\r\n")
	_, writeErr := io.WriteString(body, headers+message.Body)
	closeErr := body.Close()
	if writeErr != nil && closeErr != nil {
		return errors.Join(deliveryError("body", writeErr), deliveryError("acknowledgement", closeErr))
	}
	if writeErr != nil {
		return deliveryError("body", writeErr)
	}
	if closeErr != nil {
		return deliveryError("acknowledgement", closeErr)
	}
	return nil
}
