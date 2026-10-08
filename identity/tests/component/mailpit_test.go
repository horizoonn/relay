//go:build component

package component

import (
	"encoding/json/v2"
	"net/http"
	"os"
	"testing"
	"time"
)

func mailpitGet(t *testing.T, client *http.Client, path string, destination any) {
	t.Helper()
	base := os.Getenv("RELAY_IDENTITY_TEST_MAILPIT_URL")
	if base == "" {
		t.Fatal("RELAY_IDENTITY_TEST_MAILPIT_URL must point to isolated Mailpit")
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != 200 {
		t.Fatalf("Mailpit status=%d", response.StatusCode)
	}
	if err := json.UnmarshalRead(response.Body, destination); err != nil {
		t.Fatal(err)
	}
}

func waitMailpitToken(
	t *testing.T,
	client *http.Client,
	email, subject string,
) string {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var list struct {
			Messages []struct {
				ID      string
				Subject string
				To      []struct {
					Address string
				}
			} `json:"messages"`
		}
		mailpitGet(t, client, "/api/v1/messages", &list)
		for _, message := range list.Messages {
			if message.Subject != subject {
				continue
			}
			for _, recipient := range message.To {
				if recipient.Address == email {
					var body struct {
						Text string
					}
					mailpitGet(t, client, "/api/v1/message/"+message.ID, &body)
					return mailToken(t, body.Text)
				}
			}
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-deadline.C:
			t.Fatal("Mailpit did not receive account email")
		case <-ticker.C:
		}
	}
}
