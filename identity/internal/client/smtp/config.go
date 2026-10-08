package smtp

import (
	"errors"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Address       string
	From          string
	Username      string
	Password      string
	AllowInsecure bool
	Timeout       time.Duration
}

func (c Config) Validate() error {
	host, port, err := net.SplitHostPort(c.Address)
	number, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || host == "" || portErr != nil || number == 0 {
		return errors.New("SMTP address must contain a host and numeric nonzero port")
	}
	if c.Timeout <= 0 || c.Timeout > 10*time.Second {
		return errors.New("SMTP timeout must be positive and at most 10s")
	}
	from, err := mail.ParseAddress(c.From)
	if err != nil || from.Address != c.From || strings.ContainsAny(c.From, "\r\n") {
		return errors.New("invalid SMTP sender address")
	}
	if (c.Username == "") != (c.Password == "") || (c.AllowInsecure && c.Username != "") {
		return errors.New("SMTP credentials require mandatory TLS")
	}
	return nil
}
