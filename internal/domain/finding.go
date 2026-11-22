package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// Severity follows the vendor-neutral scale Grype reports.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityNegligible
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = []string{"unknown", "negligible", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

// ParseSeverity is case-insensitive and maps anything unrecognised to unknown.
func ParseSeverity(s string) Severity {
	s = strings.ToLower(strings.TrimSpace(s))
	for i, n := range severityNames {
		if n == s {
			return Severity(i)
		}
	}
	return SeverityUnknown
}

// FallbackCVSS gives a representative base score when an advisory has none.
func (s Severity) FallbackCVSS() float64 {
	switch s {
	case SeverityCritical:
		return 9.5
	case SeverityHigh:
		return 7.5
	case SeverityMedium:
		return 5.0
	case SeverityLow:
		return 2.5
	case SeverityNegligible:
		return 0.5
	default:
		return 4.0
	}
}

// Package is one entry of an SBOM.
type Package struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Type     string   `json:"type"`
	PURL     string   `json:"purl,omitempty"`
	Licenses []string `json:"licenses,omitempty"`
}

// SBOM is the inventory of an image. Raw holds the original document
// (Syft JSON) so it can be re-matched later without pulling the image.
type SBOM struct {
	Digest   Digest    `json:"digest"`
	Distro   string    `json:"distro,omitempty"`
	Packages []Package `json:"packages"`
	Raw      []byte    `json:"-"`
}

// FindingState is the lifecycle of a finding.
type FindingState string

const (
	StateOpen     FindingState = "open"
	StateFixed    FindingState = "fixed"
	StateAccepted FindingState = "accepted" // covered by a VEX exception
)

// Finding is one vulnerability matched against one package in one image.
type Finding struct {
	ID        string       `json:"id"`
	Digest    Digest       `json:"digest"`
	VulnID    string       `json:"vuln_id"`
	Package   string       `json:"package"`
	Version   string       `json:"version"`
	PkgType   string       `json:"pkg_type,omitempty"`
	FixedIn   string       `json:"fixed_in,omitempty"`
	Severity  Severity     `json:"severity"`
	CVSS      float64      `json:"cvss"`
	EPSS      float64      `json:"epss"`
	KEV       bool         `json:"kev"`
	State     FindingState `json:"state"`
	Risk      RiskScore    `json:"risk"`
	FirstSeen time.Time    `json:"first_seen"`
	LastSeen  time.Time    `json:"last_seen"`
	FixedAt   *time.Time   `json:"fixed_at,omitempty"`
	// Source is the matcher that reported it when not the primary one (e.g. "osv").
	Source string `json:"source,omitempty"`
}

// FindingID is deterministic so re-matching updates rather than duplicates.
func FindingID(d Digest, vulnID, pkg, version string) string {
	h := sha256.Sum256([]byte(string(d) + "|" + vulnID + "|" + pkg + "|" + version))
	return hex.EncodeToString(h[:12])
}

// FixAvailable reports whether upgrading would resolve the finding.
func (f Finding) FixAvailable() bool { return f.FixedIn != "" }

// Reconcile merges a fresh match result with what was stored before.
// Findings that disappeared are marked fixed; new ones are opened;
// existing ones keep their first-seen time and accepted state.
func Reconcile(previous, current []Finding, now time.Time) []Finding {
	prev := make(map[string]Finding, len(previous))
	for _, f := range previous {
		prev[f.ID] = f
	}
	out := make([]Finding, 0, len(current)+len(previous))
	seen := make(map[string]bool, len(current))
	for _, f := range current {
		seen[f.ID] = true
		f.LastSeen = now
		if old, ok := prev[f.ID]; ok {
			f.FirstSeen = old.FirstSeen
			if old.State == StateAccepted {
				f.State = StateAccepted
			} else {
				f.State = StateOpen
			}
		} else {
			f.FirstSeen = now
			f.State = StateOpen
		}
		f.FixedAt = nil
		out = append(out, f)
	}
	for _, f := range previous {
		if seen[f.ID] || f.State == StateFixed {
			continue
		}
		t := now
		f.State = StateFixed
		f.FixedAt = &t
		out = append(out, f)
	}
	return out
}

// MarshalJSON encodes severity as its name.
func (s Severity) MarshalJSON() ([]byte, error) { return []byte(`"` + s.String() + `"`), nil }

// UnmarshalJSON accepts the name.
func (s *Severity) UnmarshalJSON(b []byte) error {
	*s = ParseSeverity(strings.Trim(string(b), `"`))
	return nil
}
