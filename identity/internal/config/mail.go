package config

import (
	"errors"
	"time"

	"github.com/horizoonn/relay/identity/internal/client/smtp"
)

type MailConfig struct {
	Address       string        `env:"SMTP_ADDR" envDefault:"mailpit:1025"`
	From          string        `env:"SMTP_FROM" envDefault:"no-reply@relay.local"`
	Username      string        `env:"SMTP_USERNAME"`
	Password      string        `env:"SMTP_PASSWORD"`
	AllowInsecure bool          `env:"SMTP_ALLOW_INSECURE" envDefault:"false"`
	Timeout       time.Duration `env:"SMTP_TIMEOUT" envDefault:"5s"`
	EncryptionKey string        `env:"MAIL_ENCRYPTION_KEY,required,notEmpty"`
}

func (c MailConfig) validate() error {
	if len(c.EncryptionKey) < 32 {
		return errors.New("IDENTITY_MAIL_ENCRYPTION_KEY must contain at least 32 bytes")
	}
	return c.SMTP().Validate()
}

func (c MailConfig) SMTP() smtp.Config {
	return smtp.Config{
		Address:       c.Address,
		From:          c.From,
		Username:      c.Username,
		Password:      c.Password,
		AllowInsecure: c.AllowInsecure,
		Timeout:       c.Timeout,
	}
}
