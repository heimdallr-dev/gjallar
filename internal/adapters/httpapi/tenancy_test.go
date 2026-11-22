package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/heimdallr-dev/gjallar/internal/adapters/memory"
	"github.com/heimdallr-dev/gjallar/internal/adapters/oidc"
	"github.com/heimdallr-dev/gjallar/internal/app"
	"github.com/heimdallr-dev/gjallar/internal/domain"
)

func TestTenancyFiltersEveryRead(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewRepo()
	add := func(ns, c string) domain.Digest {
		d := domain.Digest("sha256:" + strings.Repeat(c, 64))
		img := domain.ImageRef{Repository: "harbor.local/" + ns + "/app", Tag: "1", Digest: d}
		_ = repo.UpsertWorkload(ctx, domain.Workload{Cluster: "c", Namespace: ns, Kind: "Deployment", Name: "app", Containers: []domain.Container{{Name: "app", Image: img}}})
		_, _ = repo.EnsureImage(ctx, img)
		_ = repo.SaveFindings(ctx, d, "db", []domain.Finding{{ID: domain.FindingID(d, "CVE-"+ns, "p", "1"), Digest: d, VulnID: "CVE-" + ns, Package: "p", Version: "1",
			State: domain.StateOpen, Risk: domain.RiskScore{Value: 80, Band: "urgent"}}})
		_ = repo.SavePosture(ctx, "c/"+ns+"/Deployment/app", []domain.PostureViolation{{WorkloadID: "c/" + ns + "/Deployment/app", CheckID: "GJ-001"}})
		return d
	}
	shop, pay := add("shop", "a"), add("payments", "b")
	a := &API{Repo: repo, Tenancy: &app.Tenancy{Groups: map[string][]string{"team-shop": {"shop"}}, GlobalRoles: []string{"gjallar-admin"}}}
	as := func(p oidc.Principal, h http.HandlerFunc, path string, digest domain.Digest) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil).WithContext(oidc.WithPrincipal(ctx, p))
		if digest != "" {
			r.SetPathValue("digest", string(digest))
		}
		w := httptest.NewRecorder()
		h(w, r)
		return w
	}
	shopUser := oidc.Principal{Username: "ana", Roles: []string{"gjallar-viewer"}, Groups: []string{"/team-shop"}}
	admin := oidc.Principal{Username: "root", Roles: []string{"gjallar-admin"}}

	var fs []app.FindingView
	_ = json.Unmarshal(as(shopUser, a.findings, "/api/v1/findings", "").Body.Bytes(), &fs)
	if len(fs) != 1 || fs[0].VulnID != "CVE-shop" {
		t.Errorf("findings for team-shop: %+v", fs)
	}
	_ = json.Unmarshal(as(admin, a.findings, "/api/v1/findings", "").Body.Bytes(), &fs)
	if len(fs) != 2 {
		t.Errorf("admin sees %d findings, want 2", len(fs))
	}
	var s app.Summary
	_ = json.Unmarshal(as(shopUser, a.summary, "/api/v1/summary", "").Body.Bytes(), &s)
	if s.OpenFindings != 1 || s.Workloads != 1 || s.Images != 1 || s.Posture != 1 {
		t.Errorf("scoped summary: %+v", s)
	}
	var ws []domain.Workload
	_ = json.Unmarshal(as(shopUser, a.workloads, "/api/v1/workloads", "").Body.Bytes(), &ws)
	if len(ws) != 1 || ws[0].Namespace != "shop" {
		t.Errorf("workloads: %+v", ws)
	}
	var is []domain.Image
	_ = json.Unmarshal(as(shopUser, a.images, "/api/v1/images", "").Body.Bytes(), &is)
	if len(is) != 1 || is[0].Digest != shop {
		t.Errorf("images: %+v", is)
	}
	if code := as(shopUser, a.image, "/api/v1/images/x", pay).Code; code != 404 {
		t.Errorf("other team's image: %d, want 404", code)
	}
	if code := as(shopUser, a.image, "/api/v1/images/x", shop).Code; code != 200 {
		t.Errorf("own image: %d", code)
	}
}
