package domain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestScoreOrdersByRealRisk(t *testing.T) {
	// An exploited, exposed, loaded medium must outrank an unreachable critical.
	exploitedMedium := Score(RiskInput{CVSS: 6.5, KEV: true, RuntimeLoaded: TriYes, Exposed: true})
	quietCritical := Score(RiskInput{CVSS: 9.8, EPSS: 0.001, RuntimeLoaded: TriNo})
	if exploitedMedium.Value <= quietCritical.Value {
		t.Fatalf("expected exploited medium (%d) > quiet critical (%d)", exploitedMedium.Value, quietCritical.Value)
	}
	if exploitedMedium.Band != BandUrgent {
		t.Fatalf("exploited exposed medium should be urgent, got %s (%d)", exploitedMedium.Band, exploitedMedium.Value)
	}
	if quietCritical.Band != BandLow {
		t.Fatalf("unreachable critical with tiny EPSS should be low, got %s (%d)", quietCritical.Band, quietCritical.Value)
	}
}

func TestScoreBoundsAndFallback(t *testing.T) {
	s := Score(RiskInput{CVSS: 10, KEV: true, RuntimeLoaded: TriYes, Exposed: true, FixAvailable: true})
	if s.Value != 100 || !s.Actionable {
		t.Fatalf("expected capped 100 actionable, got %+v", s)
	}
	f := Score(RiskInput{Severity: SeverityHigh})
	if f.Value == 0 || len(f.Reasons) == 0 {
		t.Fatalf("severity fallback should score and explain, got %+v", f)
	}
}

func TestParseImageRef(t *testing.T) {
	cases := map[string]ImageRef{
		"nginx":                         {Repository: "nginx"},
		"nginx:1.27":                    {Repository: "nginx", Tag: "1.27"},
		"harbor.local:5000/app/api:v1":  {Repository: "harbor.local:5000/app/api", Tag: "v1"},
		"ghcr.io/x/y@sha256:" + hex64(): {Repository: "ghcr.io/x/y", Digest: Digest("sha256:" + hex64())},
	}
	for in, want := range cases {
		got, err := ParseImageRef(in)
		if err != nil || got != want {
			t.Errorf("ParseImageRef(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	if !(ImageRef{Repository: "nginx", Tag: "latest"}).UsesMutableTag() {
		t.Error("latest should be mutable")
	}
}

func TestReconcileLifecycle(t *testing.T) {
	d := Digest("sha256:" + hex64())
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(24 * time.Hour)
	a := Finding{ID: FindingID(d, "CVE-1", "openssl", "3.0.2"), VulnID: "CVE-1"}
	b := Finding{ID: FindingID(d, "CVE-2", "zlib", "1.2"), VulnID: "CVE-2"}
	first := Reconcile(nil, []Finding{a, b}, t0)
	first[1].State = StateAccepted
	second := Reconcile(first, []Finding{b}, t1)
	byID := map[string]Finding{}
	for _, f := range second {
		byID[f.ID] = f
	}
	if got := byID[a.ID]; got.State != StateFixed || got.FixedAt == nil || !got.FixedAt.Equal(t1) {
		t.Fatalf("a should be fixed at t1: %+v", got)
	}
	if got := byID[b.ID]; got.State != StateAccepted || !got.FirstSeen.Equal(t0) {
		t.Fatalf("b should stay accepted with first seen t0: %+v", got)
	}
}

func TestLicensePolicy(t *testing.T) {
	p := DefaultLicensePolicy()
	s := SBOM{Digest: "sha256:x", Packages: []Package{
		{Name: "a", Licenses: []string{"MIT"}},
		{Name: "b", Licenses: []string{"GPL-3.0-only"}},
		{Name: "c", Licenses: []string{"MIT OR GPL-2.0-only"}},
		{Name: "d"},
		{Name: "e", Licenses: []string{"Apache-2.0 AND AGPL-3.0-only"}},
	}}
	want := map[string]LicenseVerdict{"a": LicenseAllowed, "b": LicenseDenied, "c": LicenseAllowed, "d": LicenseUnknown, "e": LicenseDenied}
	for _, r := range p.Evaluate(s) {
		if want[r.Package] != r.Verdict {
			t.Errorf("%s (%s): got %s want %s", r.Package, r.License, r.Verdict, want[r.Package])
		}
	}
}

func TestPosture(t *testing.T) {
	w := Workload{Cluster: "c", Namespace: "ns", Kind: "Deployment", Name: "web", HostNetwork: true,
		Containers: []Container{{Name: "app", Image: ImageRef{Repository: "nginx", Tag: "latest"}, Privileged: true, AddedCapabilities: []string{"NET_ADMIN"}}}}
	got := map[string]bool{}
	for _, v := range EvaluatePosture(w) {
		got[v.CheckID] = true
	}
	for _, id := range []string{"GJ-001", "GJ-002", "GJ-004", "GJ-006", "GJ-007", "GJ-008"} {
		if !got[id] {
			t.Errorf("expected %s", id)
		}
	}
	hardened := Workload{Containers: []Container{{Name: "app", Image: ImageRef{Repository: "x", Digest: Digest("sha256:" + hex64())},
		RunAsNonRoot: true, HasLimits: true, ReadOnlyRootFS: true}}}
	if v := EvaluatePosture(hardened); len(v) != 0 {
		t.Errorf("hardened workload should pass, got %+v", v)
	}
}

func TestSeverityJSON(t *testing.T) {
	b, _ := json.Marshal(Finding{Severity: SeverityHigh})
	var f Finding
	if err := json.Unmarshal(b, &f); err != nil || f.Severity != SeverityHigh {
		t.Fatalf("roundtrip failed: %s %v", b, err)
	}
}

func hex64() string { return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
