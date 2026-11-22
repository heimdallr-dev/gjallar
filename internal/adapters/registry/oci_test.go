package registry

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestCatalogWithBearerChallenge(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			if u, p, _ := r.BasicAuth(); u != "bot" || p != "pw" || r.URL.Query().Get("scope") == "" {
				http.Error(w, "denied", 401)
				return
			}
			fmt.Fprintf(w, `{"token":"t-%s"}`, r.URL.Query().Get("scope"))
			return
		}
		want := map[string]string{
			"/v2/_catalog":                  "Bearer t-registry:catalog:*",
			"/v2/apps/web/tags/list":        "Bearer t-repository:apps/web:pull",
			"/v2/apps/web/manifests/1.10.0": "Bearer t-repository:apps/web:pull",
			"/v2/apps/web/manifests/1.9.0":  "Bearer t-repository:apps/web:pull",
			"/v2/apps/web/manifests/latest": "Bearer t-repository:apps/web:pull",
		}[r.URL.Path]
		if r.Header.Get("Authorization") != want {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="reg"`, srv.URL))
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v2/_catalog":
			fmt.Fprint(w, `{"repositories":["apps/web"]}`)
		case "/v2/apps/web/tags/list":
			fmt.Fprint(w, `{"name":"apps/web","tags":["1.9.0","1.10.0","latest"]}`)
		default:
			w.Header().Set("Docker-Content-Digest", "sha256:"+fmt.Sprintf("%064d", len(r.URL.Path)))
		}
	}))
	defer srv.Close()
	c := &Catalog{URL: srv.URL, User: "bot", Password: "pw", MaxTags: 2}
	refs, err := c.Images(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Reverse-sorted tags: "latest", "1.9.0" (the documented shortcut ordering).
	if len(refs) != 2 || refs[0].Tag != "latest" || !refs[0].Digest.Valid() {
		t.Fatalf("refs: %+v", refs)
	}
}

// Live: GJALLAR_TEST_REGISTRY=http://127.0.0.1:25000 with team/alpine:3.20 pushed.
func TestLiveRegistry(t *testing.T) {
	u := os.Getenv("GJALLAR_TEST_REGISTRY")
	if u == "" {
		t.Skip("set GJALLAR_TEST_REGISTRY")
	}
	refs, err := (&Catalog{URL: u}).Images(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) == 0 || refs[0].Tag != "3.20" || !refs[0].Digest.Valid() {
		t.Fatalf("refs: %+v", refs)
	}
	t.Logf("discovered %s:%s@%s", refs[0].Repository, refs[0].Tag, refs[0].Digest)
}
