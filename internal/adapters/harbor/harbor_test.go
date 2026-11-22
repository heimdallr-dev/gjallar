package harbor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestImagesPaginatesAndSkipsNonImages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, _ := r.BasicAuth(); u != "robot$x" || p != "s" {
			http.Error(w, "unauthorized", 401)
			return
		}
		switch r.URL.EscapedPath() {
		case "/api/v2.0/projects/apps/repositories":
			if r.URL.Query().Get("page") == "" {
				w.Header().Set("Link", `</api/v2.0/projects/apps/repositories?page=2&page_size=100>; rel="next"`)
				fmt.Fprint(w, `[{"name":"apps/web"}]`)
				return
			}
			fmt.Fprint(w, `[{"name":"apps/team/api"}]`)
		case "/api/v2.0/projects/apps/repositories/web/artifacts":
			fmt.Fprint(w, `[{"digest":"sha256:aa","type":"IMAGE","tags":[{"name":"1.2"}]},{"digest":"sha256:bb","type":"IMAGE","tags":[]},{"digest":"sha256:cc","type":"CHART","tags":[{"name":"0.1"}]}]`)
		case "/api/v2.0/projects/apps/repositories/team%252Fapi/artifacts": // nested name, double-encoded
			fmt.Fprint(w, `[{"digest":"sha256:dd","type":"IMAGE","tags":[{"name":"v3"}]}]`)
		default:
			http.Error(w, r.URL.EscapedPath(), 404)
		}
	}))
	defer srv.Close()
	refs, err := Catalog{URL: srv.URL, Projects: []string{"apps"}, User: "robot$x", Password: "s"}.Images(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 || refs[0].Tag != "1.2" || refs[1].Repository[len(refs[1].Repository)-13:] != "apps/team/api" || refs[1].Digest != "sha256:dd" {
		t.Fatalf("refs: %+v", refs)
	}
}
