// Package dtrack exports SBOMs to OWASP Dependency-Track (opt-in), so teams
// that already use it keep their workflow: Gjallar never holds data hostage.
package dtrack

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client uploads CycloneDX BOMs with `PUT /api/v1/bom` (auto-creating projects).
type Client struct {
	URL    string // https://dtrack.example.com (API server)
	APIKey string // team key with BOM_UPLOAD and PROJECT_CREATION_UPLOAD
	HTTP   *http.Client
}

// Upload sends one BOM for project name@version and returns DT's processing token.
func (c Client) Upload(ctx context.Context, project, version string, cdx []byte) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"projectName": project, "projectVersion": version, "autoCreate": true,
		"bom": base64.StdEncoding.EncodeToString(cdx),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, strings.TrimSuffix(c.URL, "/")+"/api/v1/bom", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", c.APIKey)
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("dependency-track upload %s@%s: %s %s", project, version, resp.Status, strings.TrimSpace(string(raw[:min(len(raw), 200)])))
	}
	var tok struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(raw, &tok)
	return tok.Token, nil
}
