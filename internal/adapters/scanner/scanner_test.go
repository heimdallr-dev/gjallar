package scanner

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

const syftFixture = `{
 "artifacts":[
  {"name":"openssl","version":"3.0.11-1~deb12u2","type":"deb","purl":"pkg:deb/debian/openssl@3.0.11-1~deb12u2",
   "licenses":[{"value":"Apache-2.0","spdxExpression":"Apache-2.0"}]},
  {"name":"requests","version":"2.31.0","type":"python","licenses":["Apache-2.0"]},
  {"name":"bash","version":"5.2","type":"deb","licenses":[{"value":"GPL-3.0-or-later","spdxExpression":"GPL-3.0-or-later"}]}
 ],
 "distro":{"id":"debian","versionID":"12"},
 "source":{"metadata":{"manifestDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111",
   "repoDigests":["docker.io/library/app@sha256:2222222222222222222222222222222222222222222222222222222222222222"]}}
}`

const grypeFixture = `{
 "matches":[
  {"vulnerability":{"id":"CVE-2024-5535","severity":"Critical","cvss":[{"version":"3.1","metrics":{"baseScore":9.1}}],
    "fix":{"versions":["3.0.14-1~deb12u1"],"state":"fixed"},"epss":[{"epss":0.02}],"knownExploited":[]},
   "artifact":{"name":"openssl","version":"3.0.11-1~deb12u2","type":"deb"}},
  {"vulnerability":{"id":"DSA-1234","severity":"High","fix":{"state":"not-fixed"}},
   "relatedVulnerabilities":[{"id":"CVE-2023-4863","cvss":[{"version":"3.0","metrics":{"baseScore":7.0}},{"version":"3.1","metrics":{"baseScore":8.8}}],
     "epss":[{"epss":0.93}],"knownExploited":[{"cve":"CVE-2023-4863"}]}],
   "artifact":{"name":"libwebp7","version":"1.2.4","type":"deb"}},
  {"vulnerability":{"id":"DSA-1234","severity":"High"},"artifact":{"name":"libwebp7","version":"1.2.4","type":"deb"}}
 ],
 "descriptor":{"version":"0.92.0","db":{"status":{"built":"2026-11-20T01:23:45Z","schemaVersion":"v6.0.2"}}}
}`

func TestParseSyft(t *testing.T) {
	s, err := ParseSyftJSON([]byte(syftFixture))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(s.Digest), "sha256:2222") {
		t.Errorf("should prefer repo digest, got %s", s.Digest)
	}
	if s.Distro != "debian 12" || len(s.Packages) != 3 {
		t.Errorf("distro/packages: %q %d", s.Distro, len(s.Packages))
	}
	if s.Packages[1].Licenses[0] != "Apache-2.0" || s.Packages[2].Licenses[0] != "GPL-3.0-or-later" {
		t.Errorf("licenses: %+v", s.Packages)
	}
}

func TestParseGrype(t *testing.T) {
	dbv, fs, err := ParseGrypeJSON([]byte(grypeFixture))
	if err != nil {
		t.Fatal(err)
	}
	if dbv != "2026-11-20T01:23:45Z" {
		t.Errorf("db version %q", dbv)
	}
	if len(fs) != 2 {
		t.Fatalf("dedupe failed, got %d findings", len(fs))
	}
	if fs[0].FixedIn == "" || fs[0].CVSS != 9.1 || fs[0].Severity != domain.SeverityCritical {
		t.Errorf("openssl: %+v", fs[0])
	}
	if !fs[1].KEV || fs[1].CVSS != 8.8 || fs[1].EPSS != 0.93 || fs[1].FixedIn != "" {
		t.Errorf("libwebp should borrow KEV/CVSS/EPSS from related CVE: %+v", fs[1])
	}
}

func TestSyftArgs(t *testing.T) {
	var got []string
	s := Syft{Source: "registry", Scope: "all-layers", Run: func(_ context.Context, _ []string, name string, args ...string) ([]byte, error) {
		got = append([]string{name}, args...)
		return []byte(syftFixture), nil
	}}
	ref := domain.ImageRef{Repository: "harbor.local/app", Tag: "1.0"}
	if _, err := s.Generate(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	want := "syft scan registry:harbor.local/app:1.0 -o syft-json -q --scope all-layers"
	if strings.Join(got, " ") != want {
		t.Errorf("got %q want %q", strings.Join(got, " "), want)
	}
}

func TestCopaArgs(t *testing.T) {
	var calls []string
	c := Copa{BuildkitAddr: "tcp://bk:1234", Push: true, Run: func(_ context.Context, _ []string, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return []byte(`{}`), nil
	}}
	ref, err := c.Patch(context.Background(), domain.ImageRef{Repository: "harbor.local/app", Tag: "1.0", Digest: "sha256:x"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ref != "harbor.local/app:1.0-patched" || len(calls) != 2 {
		t.Fatalf("ref=%s calls=%v", ref, calls)
	}
	if !strings.Contains(calls[1], "copa patch -i harbor.local/app:1.0 -r ") || !strings.Contains(calls[1], "--push") {
		t.Errorf("copa call: %s", calls[1])
	}
	if _, err := (Copa{}).Patch(context.Background(), domain.ImageRef{}, nil); err == nil {
		t.Error("missing buildkit should error")
	}

	calls = nil
	c.TargetRepo = "harbor.example.com/gjallar/"
	ref, err = c.Patch(context.Background(), domain.ImageRef{Repository: "docker.io/library/nginx", Tag: "1.27"}, nil)
	if err != nil || ref != "harbor.example.com/gjallar/nginx:1.27-patched" || !strings.Contains(calls[1], " -t harbor.example.com/gjallar/nginx:1.27-patched ") {
		t.Fatalf("target repo: ref=%s err=%v calls=%v", ref, err, calls)
	}
}

func TestGrypeUpdatesDBOnceThenMatchesOffline(t *testing.T) {
	var calls []string
	run := func(_ context.Context, env []string, _ string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(append(env, args...), " "))
		if args[0] == "db" {
			return nil, nil
		}
		return []byte(grypeFixture), nil
	}
	if _, fs, err := (Grype{Run: run}).Match(context.Background(), []byte("{}")); err != nil || len(fs) == 0 {
		t.Fatalf("match: %v, %d findings", err, len(fs))
	}
	if len(calls) != 2 || calls[0] != "db update -q" || !strings.HasPrefix(calls[1], "GRYPE_DB_AUTO_UPDATE=false sbom:") {
		t.Fatalf("calls = %q", calls)
	}
}

func TestFileOwners(t *testing.T) {
	sbom := `{"artifacts":[
	 {"name":"libc6","type":"deb","locations":[{"path":"/var/lib/dpkg/status"}],
	  "metadata":{"files":[{"path":"/lib/x86_64-linux-gnu/libc.so.6"}]}},
	 {"name":"libpcre2-8-0","type":"deb","metadata":{"files":[{"path":"/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2"}]}},
	 {"name":"log4j-core","type":"java-archive","locations":[{"path":"/app/lib/log4j-core-2.14.1.jar"}],"metadata":{}},
	 {"name":"requests","type":"python","metadata":{"files":[{"path":"requests/__init__.py"}]}}]}`
	owner, err := FileOwners([]byte(sbom))
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		"/usr/lib/x86_64-linux-gnu/libc.so.6":   "libc6",        // merged /usr alias
		"/lib/x86_64-linux-gnu/libc.so.6":       "libc6",        // as listed
		"/lib/x86_64-linux-gnu/libpcre2-8.so.0": "libpcre2-8-0", // SONAME symlink
		"/app/lib/log4j-core-2.14.1.jar":        "log4j-core",   // language package location
		"/var/lib/dpkg/status":                  "",             // OS package DB is not a load
		"/etc/passwd":                           "",
	} {
		if got := owner(path); got != want {
			t.Errorf("%s: got %q, want %q", path, got, want)
		}
	}
}

func TestCosignAttestArgs(t *testing.T) {
	var got string
	c := Cosign{Key: "env://COSIGN_PRIVATE_KEY", Insecure: true, Run: func(_ context.Context, _ []string, name string, args ...string) ([]byte, error) {
		got = name + " " + strings.Join(args, " ")
		return nil, nil
	}}
	err := c.Attest(context.Background(), domain.ImageRef{Repository: "registry.local/apps/web", Tag: "1", Digest: domain.Digest("sha256:" + strings.Repeat("c", 64))}, "https://syft.dev/bom", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"cosign attest --yes --key env://COSIGN_PRIVATE_KEY --type https://syft.dev/bom --predicate ", "--tlog-upload=false", "--allow-http-registry", " registry.local/apps/web@sha256:ccc"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	if err := (Cosign{}).Attest(context.Background(), domain.ImageRef{Repository: "x"}, "t", nil); err == nil {
		t.Error("attesting without a digest must fail")
	}
}

// Trimmed from real osv-scanner v2.7.0 output (nginx:1.27, Debian 12).
const osvFixture = `{"results":[{"packages":[{"package":{"name":"openssl","version":"3.0.16-1~deb12u1","ecosystem":"Debian:12"},
 "vulnerabilities":[{"id":"DSA-6335-1","affected":[{"package":{"name":"openssl"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"3.0.20-1~deb12u2"}]}]}]}],
 "groups":[{"ids":["DSA-6335-1","DEBIAN-CVE-2026-34180"],"aliases":["CVE-2026-34180","CVE-2026-34182","DEBIAN-CVE-2026-34180","DSA-6335-1"],"max_severity":"9.1"}]}]}]}`

func TestParseOSV(t *testing.T) {
	fs, err := ParseOSVJSON([]byte(osvFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 || fs[0].VulnID != "CVE-2026-34180" || fs[1].VulnID != "CVE-2026-34182" {
		t.Fatalf("one finding per CVE alias: %+v", fs)
	}
	f := fs[0]
	if f.Package != "openssl" || f.PkgType != "deb" || f.FixedIn != "3.0.20-1~deb12u2" || f.CVSS != 9.1 || f.Severity != domain.SeverityCritical || f.Source != "osv" {
		t.Fatalf("finding: %+v", f)
	}
}

// Live: GJALLAR_TEST_OSV_SBOM=<syft cyclonedx-json of a Debian image> with osv-scanner on PATH.
func TestOSVLive(t *testing.T) {
	p := os.Getenv("GJALLAR_TEST_OSV_SBOM")
	if p == "" {
		t.Skip("set GJALLAR_TEST_OSV_SBOM")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	_, fs, err := (OSV{CacheDir: os.Getenv("GJALLAR_TEST_OSV_CACHE")}).Match(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) < 50 {
		t.Fatalf("expected many Debian findings once distro qualifiers are normalised, got %d", len(fs))
	}
	t.Logf("OSV findings: %d (first: %s in %s, fix %s)", len(fs), fs[0].VulnID, fs[0].Package, fs[0].FixedIn)
}

// Trimmed from real Trivy 0.69.3 `trivy sbom` output (nginx:1.27 CycloneDX 1.6).
const trivyFixture = `{"Trivy":{"Version":"0.69.3"},"Results":[{"Type":"debian","Vulnerabilities":[
 {"VulnerabilityID":"CVE-2026-109518","PkgName":"apt","InstalledVersion":"2.6.1","FixedVersion":"2.6.2","Severity":"HIGH",
  "PkgIdentifier":{"PURL":"pkg:deb/debian/apt@2.6.1?arch=amd64&distro=debian-12.11"},"CVSS":{"redhat":{"V3Score":8.1}}}]}]}`

func TestParseTrivy(t *testing.T) {
	db, fs, err := ParseTrivyJSON([]byte(trivyFixture))
	if err != nil || db != "trivy 0.69.3" || len(fs) != 1 {
		t.Fatalf("%v %s %+v", err, db, fs)
	}
	f := fs[0]
	if f.VulnID != "CVE-2026-109518" || f.Package != "apt" || f.FixedIn != "2.6.2" || f.PkgType != "deb" || f.CVSS != 8.1 || f.Severity != domain.SeverityHigh {
		t.Fatalf("finding: %+v", f)
	}
}

// Live: GJALLAR_TEST_TRIVY_SBOM=<CycloneDX 1.6 SBOM> with trivy on PATH.
func TestTrivyLive(t *testing.T) {
	p := os.Getenv("GJALLAR_TEST_TRIVY_SBOM")
	if p == "" {
		t.Skip("set GJALLAR_TEST_TRIVY_SBOM")
	}
	raw, _ := os.ReadFile(p)
	db, fs, err := (Trivy{CacheDir: os.Getenv("GJALLAR_TEST_TRIVY_CACHE")}).Match(context.Background(), raw)
	if err != nil || len(fs) < 50 {
		t.Fatalf("trivy: %v, %d findings", err, len(fs))
	}
	t.Logf("%s: %d findings", db, len(fs))
}
