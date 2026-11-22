package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// Trivy implements app.VulnMatcher with `trivy sbom` over a CycloneDX SBOM,
// as an alternative to Grype (freedom of tools). It reads CycloneDX ≤ 1.6;
// Gjallar stores its CycloneDX copy as 1.6 for that reason.
type Trivy struct {
	Bin          string // default "trivy"
	CacheDir     string // TRIVY_CACHE_DIR
	DBRepository string // TRIVY_DB_REPOSITORY: an internal mirror for air-gapped sites
	Run          Runner
}

// Match scans a CycloneDX JSON SBOM.
func (t Trivy) Match(ctx context.Context, cdx []byte) (string, []domain.Finding, error) {
	run := t.Run
	if run == nil {
		run = ExecRunner
	}
	dir, err := os.MkdirTemp("", "gjallar-trivy-")
	if err != nil {
		return "", nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "sbom.cdx.json")
	if err := os.WriteFile(path, cdx, 0o600); err != nil {
		return "", nil, err
	}
	env := []string{"TRIVY_DISABLE_VEX_NOTICE=true"}
	if t.CacheDir != "" {
		env = append(env, "TRIVY_CACHE_DIR="+t.CacheDir)
	}
	if t.DBRepository != "" {
		env = append(env, "TRIVY_DB_REPOSITORY="+t.DBRepository)
	}
	out, err := run(ctx, env, or(t.Bin, "trivy"), "sbom", path, "--scanners", "vuln", "--format", "json", "--quiet")
	if err != nil {
		return "", nil, err
	}
	return ParseTrivyJSON(out)
}

type trivyDoc struct {
	Trivy struct {
		Version string `json:"Version"`
	} `json:"Trivy"`
	Results []struct {
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			PkgIdentifier    struct {
				PURL string `json:"PURL"`
			} `json:"PkgIdentifier"`
			CVSS map[string]struct {
				V3Score  float64 `json:"V3Score"`
				V40Score float64 `json:"V40Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// ParseTrivyJSON turns Trivy JSON into findings (CVSS: NVD first, then the highest vendor score).
func ParseTrivyJSON(raw []byte) (string, []domain.Finding, error) {
	var doc trivyDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", nil, fmt.Errorf("parse trivy json: %w", err)
	}
	var out []domain.Finding
	for _, r := range doc.Results {
		for _, v := range r.Vulnerabilities {
			cvss := v.CVSS["nvd"].V3Score
			if cvss == 0 {
				for _, c := range v.CVSS {
					cvss = max(cvss, c.V3Score, c.V40Score)
				}
			}
			out = append(out, domain.Finding{
				VulnID: v.VulnerabilityID, Package: v.PkgName, Version: v.InstalledVersion, FixedIn: v.FixedVersion,
				PkgType: purlType(v.PkgIdentifier.PURL), CVSS: cvss, Severity: domain.ParseSeverity(strings.ToLower(v.Severity)), State: domain.StateOpen,
			})
		}
	}
	return "trivy " + doc.Trivy.Version, out, nil
}

// purlType reads "deb" from "pkg:deb/debian/apt@2.6.1".
func purlType(purl string) string {
	t, _, _ := strings.Cut(strings.TrimPrefix(purl, "pkg:"), "/")
	return t
}
