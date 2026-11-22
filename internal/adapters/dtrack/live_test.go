package dtrack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

// TestLiveUpload runs against a real Dependency-Track when
// GJALLAR_DTRACK_LIVE_URL, GJALLAR_DTRACK_LIVE_KEY and GJALLAR_DTRACK_LIVE_SBOM
// (a CycloneDX JSON file) are set; it is skipped otherwise.
func TestLiveUpload(t *testing.T) {
	base, key, path := os.Getenv("GJALLAR_DTRACK_LIVE_URL"), os.Getenv("GJALLAR_DTRACK_LIVE_KEY"), os.Getenv("GJALLAR_DTRACK_LIVE_SBOM")
	if base == "" || key == "" || path == "" {
		t.Skip("set GJALLAR_DTRACK_LIVE_URL, _KEY and _SBOM to run against a real Dependency-Track")
	}
	cdx, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	project, version := "gjallar-live-test", time.Now().UTC().Format("20060102T150405")
	tok, err := Client{URL: base, APIKey: key}.Upload(ctx, project, version, cdx)
	if err != nil || tok == "" {
		t.Fatalf("upload: %v token=%q", err, tok)
	}
	get := func(p string, v any) error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+p, nil)
		req.Header.Set("X-Api-Key", key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("GET %s: %s", p, resp.Status)
		}
		return json.NewDecoder(resp.Body).Decode(v)
	}
	for { // wait until DT has processed the BOM
		var ev struct{ Processing bool }
		if err := get("/api/v1/event/token/"+tok, &ev); err != nil {
			t.Fatal(err)
		}
		if !ev.Processing {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("BOM still processing after 3 minutes")
		case <-time.After(2 * time.Second):
		}
	}
	var proj struct{ UUID string }
	if err := get("/api/v1/project/lookup?name="+url.QueryEscape(project)+"&version="+version, &proj); err != nil {
		t.Fatal(err)
	}
	var comps []struct{ Name, Version, Purl string }
	if err := get("/api/v1/component/project/"+proj.UUID+"?pageSize=500", &comps); err != nil {
		t.Fatal(err)
	}
	if len(comps) == 0 {
		t.Fatal("project created but has no components")
	}
	t.Logf("project %s@%s: %d components (first: %s %s %s)", project, version, len(comps), comps[0].Name, comps[0].Version, comps[0].Purl)
}
