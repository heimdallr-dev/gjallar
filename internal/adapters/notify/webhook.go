// Package notify posts Gjallar alerts to chat webhooks: Slack incoming
// webhooks, Microsoft Teams (Workflows "post to a channel when a webhook
// request is received", Adaptive Card) or plain JSON for anything else.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/app"
)

// Webhook implements app.AlertSender.
type Webhook struct {
	HTTP    *http.Client
	LinkURL string // optional UI base URL for "open in Gjallar" links
}

// Send posts one message with all alerts for the target.
func (w Webhook) Send(ctx context.Context, t app.NotifyTarget, alerts []app.Alert) error {
	body, err := Payload(t.Format, alerts, w.LinkURL)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c := w.HTTP
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("webhook %s: %s %s", t.Name, resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// Payload renders alerts for a webhook format.
func Payload(format string, alerts []app.Alert, link string) ([]byte, error) {
	lines := make([]string, 0, len(alerts))
	for _, a := range alerts {
		f := a.Finding
		kev := ""
		if f.KEV {
			kev = " [KEV]"
		}
		fix := "no fix yet"
		if f.FixedIn != "" {
			fix = "fix: " + f.FixedIn
		}
		where := strings.Join(a.Workloads, ", ")
		if where == "" {
			where = a.Repository
		}
		lines = append(lines, fmt.Sprintf("%d %s %s%s in %s %s (%s) - %s - %s",
			f.Risk.Value, f.Risk.Band, f.VulnID, kev, f.Package, f.Version, fix, where, strings.Join(f.Risk.Reasons, "; ")))
	}
	title := fmt.Sprintf("Gjallar: %d new finding(s) to act on", len(alerts))
	if link != "" {
		title += " - " + strings.TrimSuffix(link, "/") + "/#risks"
	}
	switch format {
	case "teams":
		blocks := []map[string]any{{"type": "TextBlock", "text": title, "weight": "Bolder", "wrap": true}}
		for _, l := range lines {
			blocks = append(blocks, map[string]any{"type": "TextBlock", "text": l, "wrap": true})
		}
		return json.Marshal(map[string]any{"type": "message", "attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content":     map[string]any{"type": "AdaptiveCard", "version": "1.4", "body": blocks},
		}}})
	case "json":
		return json.Marshal(map[string]any{"title": title, "alerts": alerts})
	default: // slack, and anything that takes {"text": ...} (Mattermost, Rocket.Chat, Google Chat)
		return json.Marshal(map[string]string{"text": title + "\n" + strings.Join(lines, "\n")})
	}
}
