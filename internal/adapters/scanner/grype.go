package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// Grype implements app.VulnMatcher. It matches a stored SBOM, never the
// image, so re-matching after a DB update needs no registry pull.
// Point it at your mirror with GRYPE_DB_UPDATE_URL in the environment.
type Grype struct {
	Bin string // default "grype"
	Run Runner
}

// dbMu serialises DB updates: concurrent matches would otherwise each
// download and unpack their own copy of the (~3 GB unpacked) database.
var dbMu sync.Mutex

// Match updates the DB once (cheap when current), then runs
// `grype sbom:<file> -o json` against the shared cached DB.
func (g Grype) Match(ctx context.Context, sbomRaw []byte) (string, []domain.Finding, error) {
	bin, run := or(g.Bin, "grype"), g.Run
	if run == nil {
		run = ExecRunner
	}
	path, cleanup, err := writeTemp("gjallar-sbom-*.json", sbomRaw)
	if err != nil {
		return "", nil, err
	}
	defer cleanup()
	dbMu.Lock()
	_, err = run(ctx, nil, bin, "db", "update", "-q")
	dbMu.Unlock()
	if err != nil {
		return "", nil, fmt.Errorf("grype db update: %w", err)
	}
	out, err := run(ctx, []string{"GRYPE_DB_AUTO_UPDATE=false"}, bin, "sbom:"+path, "-o", "json", "-q")
	if err != nil {
		return "", nil, err
	}
	return ParseGrypeJSON(out)
}

type grypeCVSS struct {
	Version string `json:"version"`
	Metrics struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"metrics"`
}

type grypeDoc struct {
	Matches []struct {
		Vulnerability struct {
			ID       string      `json:"id"`
			Severity string      `json:"severity"`
			CVSS     []grypeCVSS `json:"cvss"`
			Fix      struct {
				Versions []string `json:"versions"`
				State    string   `json:"state"`
			} `json:"fix"`
			EPSS []struct {
				EPSS float64 `json:"epss"`
			} `json:"epss"`
			KnownExploited []json.RawMessage `json:"knownExploited"`
		} `json:"vulnerability"`
		RelatedVulnerabilities []struct {
			ID   string      `json:"id"`
			CVSS []grypeCVSS `json:"cvss"`
			EPSS []struct {
				EPSS float64 `json:"epss"`
			} `json:"epss"`
			KnownExploited []json.RawMessage `json:"knownExploited"`
		} `json:"relatedVulnerabilities"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"artifact"`
	} `json:"matches"`
	Descriptor struct {
		Version string         `json:"version"`
		DB      map[string]any `json:"db"`
	} `json:"descriptor"`
}

// ParseGrypeJSON converts Grype output to findings. EPSS and KEV come from
// Grype DB schema v6; older DBs simply leave them zero.
func ParseGrypeJSON(raw []byte) (string, []domain.Finding, error) {
	var doc grypeDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", nil, fmt.Errorf("parse grype json: %w", err)
	}
	seen := map[string]bool{}
	var out []domain.Finding
	for _, m := range doc.Matches {
		v := m.Vulnerability
		key := v.ID + "|" + m.Artifact.Name + "|" + m.Artifact.Version
		if seen[key] {
			continue // Grype can report one vuln via several matchers
		}
		seen[key] = true
		f := domain.Finding{
			VulnID: v.ID, Package: m.Artifact.Name, Version: m.Artifact.Version, PkgType: m.Artifact.Type,
			Severity: domain.ParseSeverity(v.Severity), CVSS: bestCVSS(v.CVSS), KEV: len(v.KnownExploited) > 0,
		}
		if v.Fix.State == "fixed" && len(v.Fix.Versions) > 0 {
			f.FixedIn = strings.Join(v.Fix.Versions, ", ")
		}
		for _, e := range v.EPSS {
			f.EPSS = max(f.EPSS, e.EPSS)
		}
		// Distro/GHSA records often lack CVSS/EPSS/KEV; borrow from the
		// related NVD CVE record.
		for _, r := range m.RelatedVulnerabilities {
			if f.CVSS == 0 {
				f.CVSS = bestCVSS(r.CVSS)
			}
			for _, e := range r.EPSS {
				f.EPSS = max(f.EPSS, e.EPSS)
			}
			if len(r.KnownExploited) > 0 {
				f.KEV = true
			}
		}
		out = append(out, f)
	}
	return dbVersion(doc.Descriptor.DB), out, nil
}

func bestCVSS(cs []grypeCVSS) float64 {
	best, bestVer := 0.0, ""
	for _, c := range cs {
		// Prefer the newest CVSS version present (4.0 > 3.1 > 3.0 > 2.0).
		if c.Metrics.BaseScore > 0 && c.Version >= bestVer {
			best, bestVer = c.Metrics.BaseScore, c.Version
		}
	}
	return best
}

func dbVersion(db map[string]any) string {
	pick := func(m map[string]any) string {
		for _, k := range []string{"built", "Built", "schemaVersion", "SchemaVersion"} {
			if s, ok := m[k].(string); ok && s != "" {
				return s
			}
		}
		return ""
	}
	if db == nil {
		return ""
	}
	if s := pick(db); s != "" {
		return s
	}
	if st, ok := db["status"].(map[string]any); ok {
		return pick(st)
	}
	return ""
}
