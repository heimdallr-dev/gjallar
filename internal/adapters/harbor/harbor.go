// Package harbor lists images in Harbor projects (API v2.0) for registry
// discovery: Gjallar scans what is pushed before it ever runs.
package harbor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// Catalog implements app.RegistryCatalog for one Harbor instance.
type Catalog struct {
	URL      string   // https://harbor.example.com
	Projects []string // projects to scan
	User     string   // robot account, e.g. robot$gjallar+copa
	Password string
	// MaxPerRepo limits artifacts per repository (newest first); 0 = 20.
	MaxPerRepo int
	HTTP       *http.Client
}

// Images returns every tagged artifact (newest first, up to MaxPerRepo per repository).
func (c Catalog) Images(ctx context.Context) ([]domain.ImageRef, error) {
	host := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSuffix(c.URL, "/"), "https://"), "http://")
	max := c.MaxPerRepo
	if max <= 0 {
		max = 20
	}
	var out []domain.ImageRef
	for _, p := range c.Projects {
		var repos []struct {
			Name string `json:"name"` // "project/repo[/sub]"
		}
		if err := c.pages(ctx, "/api/v2.0/projects/"+url.PathEscape(p)+"/repositories?page_size=100", 0, &repos); err != nil {
			return nil, fmt.Errorf("harbor project %s: %w", p, err)
		}
		for _, r := range repos {
			name := strings.TrimPrefix(r.Name, p+"/")
			var arts []struct {
				Digest string `json:"digest"`
				Type   string `json:"type"`
				Tags   []struct {
					Name string `json:"name"`
				} `json:"tags"`
			}
			// Harbor wants "/" inside repository names double-encoded.
			path := "/api/v2.0/projects/" + url.PathEscape(p) + "/repositories/" + url.PathEscape(url.PathEscape(name)) +
				"/artifacts?with_tag=true&page_size=" + fmt.Sprint(min(max, 100)) + "&sort=-push_time"
			if err := c.pages(ctx, path, max, &arts); err != nil {
				return nil, fmt.Errorf("harbor %s: %w", r.Name, err)
			}
			for _, a := range arts {
				if a.Type != "" && a.Type != "IMAGE" || len(a.Tags) == 0 {
					continue // charts, signatures, SBOM referrers, untagged leftovers
				}
				out = append(out, domain.ImageRef{Repository: host + "/" + r.Name, Tag: a.Tags[0].Name, Digest: domain.Digest(a.Digest)})
			}
		}
	}
	return out, nil
}

// pages follows Harbor's Link: <...>; rel="next" until limit items (0 = all).
func (c Catalog) pages(ctx context.Context, path string, limit int, out any) error {
	var all []json.RawMessage
	next := strings.TrimSuffix(c.URL, "/") + path
	for next != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return err
		}
		if c.User != "" {
			req.SetBasicAuth(c.User, c.Password)
		}
		hc := c.HTTP
		if hc == nil {
			hc = &http.Client{Timeout: 30 * time.Second}
		}
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("GET %s: %s %s", path, resp.Status, strings.TrimSpace(string(body[:min(len(body), 200)])))
		}
		var page []json.RawMessage
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		all = append(all, page...)
		next = ""
		if limit > 0 && len(all) >= limit {
			all = all[:limit]
			break
		}
		for _, l := range strings.Split(resp.Header.Get("Link"), ",") {
			if strings.Contains(l, `rel="next"`) {
				if s, e := strings.Index(l, "<"), strings.Index(l, ">"); s >= 0 && e > s {
					next = strings.TrimSuffix(c.URL, "/") + l[s+1:e]
				}
			}
		}
	}
	b, _ := json.Marshal(all)
	return json.Unmarshal(b, out)
}
