package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// OSV implements app.VulnMatcher with OSV-Scanner over a CycloneDX SBOM,
// always offline: it downloads the public OSV database and matches locally,
// so no package list ever leaves your network (no api.osv.dev queries).
type OSV struct {
	Bin      string // default "osv-scanner"
	CacheDir string // OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY; keep it on a volume
	Run      Runner
}

// Syft writes distro=debian-12.11; OSV indexes Debian:12 and Alpine:v3.20.
var (
	debianDistro = regexp.MustCompile(`distro=debian-(\d+)\.\d+`)
	alpineDistro = regexp.MustCompile(`distro=alpine-(\d+\.\d+)\.\d+`)
)

// Match scans a CycloneDX JSON SBOM. dbVersion is "osv".
func (o OSV) Match(ctx context.Context, cdx []byte) (string, []domain.Finding, error) {
	run := o.Run
	if run == nil {
		run = ExecRunner
	}
	norm := debianDistro.ReplaceAll(cdx, []byte("distro=debian-$1"))
	norm = alpineDistro.ReplaceAll(norm, []byte("distro=alpine-$1"))
	dir, err := os.MkdirTemp("", "gjallar-osv-")
	if err != nil {
		return "", nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "sbom.cdx.json") // OSV-Scanner recognises SBOMs by file name
	if err := os.WriteFile(path, norm, 0o600); err != nil {
		return "", nil, err
	}
	var env []string
	if o.CacheDir != "" {
		env = append(env, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="+o.CacheDir)
	}
	out, err := run(ctx, env, or(o.Bin, "osv-scanner"), "scan", "-L", path,
		"--offline-vulnerabilities", "--download-offline-databases", "--data-source", "native", "--format", "json")
	fs, perr := ParseOSVJSON(out)
	if perr != nil {
		if err != nil {
			return "", nil, err
		}
		return "", nil, perr
	}
	// Exit code 1 means "vulnerabilities found"; the JSON parsed, so it is not a failure.
	return "osv", fs, nil
}

type osvDoc struct {
	Results []struct {
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID       string `json:"id"`
				Affected []struct {
					Package struct {
						Name string `json:"name"`
					} `json:"package"`
					Ranges []struct {
						Events []map[string]string `json:"events"`
					} `json:"ranges"`
				} `json:"affected"`
			} `json:"vulnerabilities"`
			Groups []struct {
				IDs         []string `json:"ids"`
				Aliases     []string `json:"aliases"`
				MaxSeverity string   `json:"max_severity"`
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

// ParseOSVJSON turns OSV-Scanner JSON into findings: one per CVE in each
// group (so they line up with Grype's CVE findings), else one per group.
func ParseOSVJSON(raw []byte) ([]domain.Finding, error) {
	var doc osvDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse osv-scanner json: %w", err)
	}
	var out []domain.Finding
	for _, r := range doc.Results {
		for _, p := range r.Packages {
			fixed := map[string]string{} // vuln id → fixed version for this package
			for _, v := range p.Vulnerabilities {
				for _, a := range v.Affected {
					if a.Package.Name != "" && a.Package.Name != p.Package.Name {
						continue
					}
					for _, rg := range a.Ranges {
						for _, e := range rg.Events {
							if f := e["fixed"]; f != "" {
								fixed[v.ID] = f
							}
						}
					}
				}
			}
			for _, g := range p.Groups {
				cvss, _ := strconv.ParseFloat(g.MaxSeverity, 64)
				fix := ""
				for _, id := range g.IDs {
					if f := fixed[id]; f != "" {
						fix = f
						break
					}
				}
				ids := cves(g.Aliases)
				if len(ids) == 0 && len(g.IDs) > 0 {
					ids = []string{g.IDs[0]}
				}
				for _, id := range ids {
					out = append(out, domain.Finding{
						VulnID: id, Package: p.Package.Name, Version: p.Package.Version, PkgType: ecosystemType(p.Package.Ecosystem),
						FixedIn: fix, CVSS: cvss, Severity: severityFromCVSS(cvss), State: domain.StateOpen, Source: "osv",
					})
				}
			}
		}
	}
	return out, nil
}

func cves(ids []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range ids {
		if strings.HasPrefix(id, "CVE-") && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func ecosystemType(eco string) string {
	switch e, _, _ := strings.Cut(eco, ":"); e {
	case "Debian", "Ubuntu":
		return "deb"
	case "Alpine":
		return "apk"
	case "Red Hat", "AlmaLinux", "Rocky Linux":
		return "rpm"
	case "PyPI":
		return "python"
	case "npm":
		return "npm"
	case "Maven":
		return "java-archive"
	case "Go":
		return "go-module"
	default:
		return strings.ToLower(e)
	}
}

func severityFromCVSS(s float64) domain.Severity {
	switch {
	case s >= 9:
		return domain.SeverityCritical
	case s >= 7:
		return domain.SeverityHigh
	case s >= 4:
		return domain.SeverityMedium
	case s > 0:
		return domain.SeverityLow
	default:
		return domain.SeverityUnknown
	}
}
