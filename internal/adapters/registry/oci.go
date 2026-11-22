// Package registry lists images in any OCI Distribution registry (registry:2,
// Zot, Harbor, GHCR, Quay, GitLab, Gitea, Artifactory...) for discovery,
// with basic auth or the Bearer token challenge most registries use.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// Catalog implements app.RegistryCatalog with the OCI Distribution API.
type Catalog struct {
	URL          string   // https://registry.example.com
	Repositories []string // empty = all from /v2/_catalog (not every registry offers it, e.g. GHCR)
	User         string
	Password     string
	MaxTags      int // newest-looking tags per repository (sorted descending); 0 = 20
	HTTP         *http.Client

	mu     sync.Mutex
	tokens map[string]string // scope → bearer token
}

var accept = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.docker.distribution.manifest.v2+json",
}, ", ")

// Images returns repo:tag@digest for every listed tag.
func (c *Catalog) Images(ctx context.Context) ([]domain.ImageRef, error) {
	host := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSuffix(c.URL, "/"), "https://"), "http://")
	repos := c.Repositories
	if len(repos) == 0 {
		var cat struct {
			Repositories []string `json:"repositories"`
		}
		if _, err := c.do(ctx, http.MethodGet, "/v2/_catalog?n=1000", "registry:catalog:*", &cat); err != nil {
			return nil, fmt.Errorf("catalog (set repositories if the registry has none): %w", err)
		}
		repos = cat.Repositories
	}
	max := c.MaxTags
	if max <= 0 {
		max = 20
	}
	var out []domain.ImageRef
	for _, repo := range repos {
		scope := "repository:" + repo + ":pull"
		var tl struct {
			Tags []string `json:"tags"`
		}
		if _, err := c.do(ctx, http.MethodGet, "/v2/"+repo+"/tags/list", scope, &tl); err != nil {
			return nil, fmt.Errorf("%s tags: %w", repo, err)
		}
		// shortcut: the API has no push dates, so "newest" = highest tag name; fine for semver/date tags.
		sort.Sort(sort.Reverse(sort.StringSlice(tl.Tags)))
		for _, tag := range tl.Tags[:min(max, len(tl.Tags))] {
			h, err := c.do(ctx, http.MethodHead, "/v2/"+repo+"/manifests/"+url.PathEscape(tag), scope, nil)
			if err != nil {
				return nil, fmt.Errorf("%s:%s: %w", repo, tag, err)
			}
			if d := domain.Digest(h.Get("Docker-Content-Digest")); d.Valid() {
				out = append(out, domain.ImageRef{Repository: host + "/" + repo, Tag: tag, Digest: d})
			}
		}
	}
	return out, nil
}

// do sends a request, answering a Bearer challenge once per scope.
func (c *Catalog) do(ctx context.Context, method, path, scope string, out any) (http.Header, error) {
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.URL, "/")+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", accept)
		c.mu.Lock()
		tok := c.tokens[scope]
		c.mu.Unlock()
		switch {
		case tok != "":
			req.Header.Set("Authorization", "Bearer "+tok)
		case c.User != "":
			req.SetBasicAuth(c.User, c.Password)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			if tok, err := c.token(ctx, hc, resp.Header.Get("WWW-Authenticate"), scope); err == nil && tok != "" {
				c.mu.Lock()
				if c.tokens == nil {
					c.tokens = map[string]string{}
				}
				c.tokens[scope] = tok
				c.mu.Unlock()
				continue
			}
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s %s: %s", method, path, resp.Status)
		}
		if out != nil {
			return resp.Header, json.Unmarshal(body, out)
		}
		return resp.Header, nil
	}
	return nil, fmt.Errorf("%s %s: unauthorized", method, path)
}

// token answers `WWW-Authenticate: Bearer realm="...",service="..."`.
func (c *Catalog) token(ctx context.Context, hc *http.Client, challenge, scope string) (string, error) {
	params, ok := strings.CutPrefix(challenge, "Bearer ")
	if !ok {
		return "", fmt.Errorf("not a bearer challenge")
	}
	kv := map[string]string{}
	for _, p := range strings.Split(params, ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(p), "="); ok {
			kv[k] = strings.Trim(v, `"`)
		}
	}
	u, err := url.Parse(kv["realm"])
	if err != nil || kv["realm"] == "" {
		return "", fmt.Errorf("bad realm")
	}
	q := u.Query()
	q.Set("service", kv["service"])
	q.Set("scope", scope)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	if c.User != "" {
		req.SetBasicAuth(c.User, c.Password)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return "", err
	}
	if t.Token != "" {
		return t.Token, nil
	}
	return t.AccessToken, nil
}
