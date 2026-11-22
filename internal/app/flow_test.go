package app_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/heimdallr-dev/gjallar/internal/adapters/memory"
	"github.com/heimdallr-dev/gjallar/internal/app"
	"github.com/heimdallr-dev/gjallar/internal/domain"
)

const dg = domain.Digest("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

type fakeGen struct{}

func (fakeGen) Generate(_ context.Context, ref domain.ImageRef) (domain.SBOM, error) {
	return domain.SBOM{Digest: dg, Distro: "debian 12", Raw: []byte(`{"fake":true}`), Packages: []domain.Package{
		{Name: "openssl", Version: "3.0.11", Type: "deb", Licenses: []string{"Apache-2.0"}},
		{Name: "readline", Version: "8.2", Type: "deb", Licenses: []string{"GPL-3.0-only"}},
	}}, nil
}

type fakeMatcher struct{ fs []domain.Finding }

func (m fakeMatcher) Match(context.Context, []byte) (string, []domain.Finding, error) {
	return "v6.1.0", append([]domain.Finding(nil), m.fs...), nil
}

type builtinLic struct{}

func (builtinLic) Evaluate(_ context.Context, s domain.SBOM, p domain.LicensePolicy) ([]domain.LicenseResult, error) {
	return p.Evaluate(s), nil
}

type fakePatcher struct{}

func (fakePatcher) Patch(_ context.Context, ref domain.ImageRef, _ []domain.Finding) (string, error) {
	return ref.Repository + ":patched", nil
}

// TestEndToEndFlow wires the hub and all workers over the in-memory bus and
// walks one image from discovery to scored findings, licenses and a patch.
func TestEndToEndFlow(t *testing.T) {
	ctx := context.Background()
	repo, bus, store := memory.NewRepo(), memory.NewBus(), memory.NewStore()
	hub := app.NewHub(repo, bus, nil, nil)
	matcher := &fakeMatcher{fs: []domain.Finding{
		{VulnID: "CVE-2024-0001", Package: "openssl", Version: "3.0.11", PkgType: "deb", FixedIn: "3.0.13", CVSS: 7.5, EPSS: 0.4, KEV: true, Severity: domain.SeverityHigh},
		{VulnID: "CVE-2024-0002", Package: "readline", Version: "8.2", PkgType: "deb", CVSS: 9.8, EPSS: 0.0005, Severity: domain.SeverityCritical},
	}}

	sbomW := app.SBOMWorker{Gen: fakeGen{}, Store: store, Bus: bus}
	vulnW := app.VulnWorker{Matcher: matcher, Store: store, Bus: bus}
	licW := app.LicenseWorker{Checker: builtinLic{}, Store: store, Bus: bus, Policy: domain.DefaultLicensePolicy(),
		Parse: func([]byte) (domain.SBOM, error) { s, _ := fakeGen{}.Generate(ctx, domain.ImageRef{}); return s, nil }}
	patchW := app.PatchWorker{Patcher: fakePatcher{}, Bus: bus}

	job := func(fn func(context.Context, domain.ScanJob) error) func(context.Context, []byte) error {
		return func(ctx context.Context, b []byte) error {
			var j domain.ScanJob
			if err := json.Unmarshal(b, &j); err != nil {
				return err
			}
			return fn(ctx, j)
		}
	}
	bus.Subscribe(domain.SubjJobSBOM, job(sbomW.Handle))
	bus.Subscribe(domain.SubjJobVuln, job(vulnW.Handle))
	bus.Subscribe(domain.SubjJobLicense, job(licW.Handle))
	bus.Subscribe(domain.SubjJobPatch, job(patchW.Handle))
	bus.Subscribe(domain.SubjSBOMDone, decode(hub.HandleSBOM))
	bus.Subscribe(domain.SubjVulnDone, decode(hub.HandleFindings))
	bus.Subscribe(domain.SubjLicDone, decode(hub.HandleLicenses))
	bus.Subscribe(domain.SubjPatchDone, decode(hub.HandlePatch))

	w := domain.Workload{Cluster: "homelab", Namespace: "shop", Kind: "Deployment", Name: "web", Exposed: true,
		Containers: []domain.Container{{Name: "app", Image: domain.ImageRef{Repository: "harbor.local/shop/web", Tag: "1.0", Digest: dg}}}}
	if err := hub.HandleInventory(ctx, w); err != nil {
		t.Fatal(err)
	}
	// Same workload again must not queue a second SBOM job.
	if err := hub.HandleInventory(ctx, w); err != nil {
		t.Fatal(err)
	}
	if n := bus.Count(domain.SubjJobSBOM); n != 1 {
		t.Fatalf("expected exactly 1 sbom job, got %d", n)
	}

	fs, _ := repo.ListFindings(ctx, app.FindingFilter{})
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(fs))
	}
	if fs[0].VulnID != "CVE-2024-0001" || fs[0].Risk.Band != domain.BandUrgent {
		t.Fatalf("exploited exposed openssl should rank first and urgent, got %s %s %d", fs[0].VulnID, fs[0].Risk.Band, fs[0].Risk.Value)
	}
	if len(fs[0].Workloads) != 1 || fs[0].Workloads[0] != "shop/web" {
		t.Fatalf("finding should know where it runs: %+v", fs[0].Workloads)
	}
	v, err := hub.Admission(ctx, domain.ImageRef{Repository: "harbor.local/shop/web", Tag: "1.0"}, false)
	if err != nil || v.Allowed || v.KEV != 1 {
		t.Fatalf("admission should deny the KEV image by tag: %+v %v", v, err)
	}
	if v, _ := hub.Admission(ctx, domain.ImageRef{Repository: "never/seen", Tag: "1"}, false); !v.Allowed || v.Known {
		t.Fatalf("unknown image should be allowed and queued: %+v", v)
	}
	denied, _ := repo.ListLicenses(ctx, "denied")
	if len(denied) != 1 || denied[0].Package != "readline" {
		t.Fatalf("expected readline GPL denied, got %+v", denied)
	}
	if pv, _ := repo.ListPosture(ctx); len(pv) == 0 {
		t.Fatal("expected posture violations for an unhardened workload")
	}

	// Rematch after a DB update: CVE-1 got fixed upstream and disappears.
	matcher.fs = matcher.fs[1:]
	if n, err := hub.Rematch(ctx); err != nil || n != 1 {
		t.Fatalf("rematch: n=%d err=%v", n, err)
	}
	all, _ := repo.ListFindings(ctx, app.FindingFilter{State: "fixed"})
	if len(all) != 1 || all[0].VulnID != "CVE-2024-0001" || all[0].FixedAt == nil {
		t.Fatalf("CVE-0001 should now be fixed: %+v", all)
	}

	// Patch: only fixable OS findings qualify; none left → error.
	if _, err := hub.RequestPatch(ctx, dg); err == nil {
		t.Fatal("expected no fixable findings error")
	}
	matcher.fs = append(matcher.fs, domain.Finding{VulnID: "CVE-2024-0003", Package: "zlib", Version: "1.2", PkgType: "deb", FixedIn: "1.3", CVSS: 5})
	if _, err := hub.Rematch(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := hub.RequestPatch(ctx, dg); err != nil {
		t.Fatalf("patch: %v", err)
	}
	ps, _ := repo.ListPatches(ctx)
	if len(ps) != 1 || ps[0].Status != "done" || ps[0].PatchedRef == "" {
		t.Fatalf("patch should complete: %+v", ps)
	}
}

func decode[T any](fn func(context.Context, T) error) func(context.Context, []byte) error {
	return func(ctx context.Context, b []byte) error {
		var v T
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		return fn(ctx, v)
	}
}
