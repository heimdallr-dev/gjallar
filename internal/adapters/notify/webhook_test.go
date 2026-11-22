package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/heimdallr-dev/gjallar/internal/app"
	"github.com/heimdallr-dev/gjallar/internal/domain"
)

var alerts = []app.Alert{{Repository: "nginx", Workloads: []string{"shop/web"}, Finding: domain.Finding{
	VulnID: "CVE-2025-15467", Package: "libssl3", Version: "3.0.16", FixedIn: "3.0.18", KEV: true,
	Risk: domain.RiskScore{Value: 78, Band: "urgent", Reasons: []string{"package loaded at runtime"}}}}}

func TestPayloads(t *testing.T) {
	var slack map[string]string
	b, _ := Payload("slack", alerts, "https://gjallar.example.com")
	if json.Unmarshal(b, &slack) != nil || !strings.Contains(slack["text"], "78 urgent CVE-2025-15467 [KEV] in libssl3") || !strings.Contains(slack["text"], "#risks") {
		t.Errorf("slack: %s", b)
	}
	var teams struct {
		Attachments []struct {
			ContentType string `json:"contentType"`
			Content     struct {
				Type string           `json:"type"`
				Body []map[string]any `json:"body"`
			} `json:"content"`
		} `json:"attachments"`
	}
	b, _ = Payload("teams", alerts, "")
	if json.Unmarshal(b, &teams) != nil || teams.Attachments[0].Content.Type != "AdaptiveCard" || len(teams.Attachments[0].Content.Body) != 2 {
		t.Errorf("teams: %s", b)
	}
}

func TestSendReportsHTTPErrors(t *testing.T) {
	var got string
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b, _ := io.ReadAll(r.Body); got = string(b) }))
	defer ok.Close()
	if err := (Webhook{}).Send(context.Background(), app.NotifyTarget{Name: "t", URL: ok.URL}, alerts); err != nil || !strings.Contains(got, "CVE-2025-15467") {
		t.Fatalf("send: %v %q", err, got)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "invalid_token", 403) }))
	defer bad.Close()
	if err := (Webhook{}).Send(context.Background(), app.NotifyTarget{Name: "t", URL: bad.URL}, alerts); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403 error, got %v", err)
	}
}
