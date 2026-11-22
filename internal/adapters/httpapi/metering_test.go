package httpapi

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/heimdallr-dev/gjallar/internal/adapters/memory"
	"github.com/heimdallr-dev/gjallar/internal/domain"
	"github.com/heimdallr-dev/gjallar/internal/platform/telemetry"
)

func TestNamespaceMetering(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewRepo()
	d := domain.Digest("sha256:" + strings.Repeat("a", 64))
	img := domain.ImageRef{Repository: "harbor.local/shop/web", Tag: "1.0", Digest: d}
	for _, w := range []domain.Workload{
		{Cluster: "c", Namespace: "shop", Kind: "Deployment", Name: "web", Containers: []domain.Container{{Name: "web", Image: img}}},
		{Cluster: "c", Namespace: "shop", Kind: "Deployment", Name: "web-canary", Containers: []domain.Container{{Name: "web", Image: img}}},
	} {
		if err := repo.UpsertWorkload(ctx, w); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := repo.EnsureImage(ctx, img); err != nil {
		t.Fatal(err)
	}
	f := domain.Finding{ID: domain.FindingID(d, "CVE-1", "openssl", "1"), VulnID: "CVE-1", Package: "openssl", Version: "1",
		State: domain.StateOpen, Risk: domain.RiskScore{Value: 80, Band: "urgent"}}
	if err := repo.SaveFindings(ctx, d, "db", []domain.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if err := refreshNamespaceUsage(ctx, repo); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	telemetry.MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	out := rec.Body.String()
	for _, want := range []string{
		`gjallar_namespace_workloads{namespace="shop"} 2`,
		`gjallar_namespace_images{namespace="shop"} 1`,
		`gjallar_namespace_open_findings{namespace="shop",band="urgent"} 1`, // one finding, counted once per namespace
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in:\n%s", want, grep(out, "gjallar_namespace"))
		}
	}
}

func grep(s, sub string) string {
	var b strings.Builder
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}
