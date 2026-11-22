package domain

import (
	"fmt"
	"strings"
)

// ---- License policy ----------------------------------------------------

// LicenseVerdict is the outcome for one package license.
type LicenseVerdict string

const (
	LicenseAllowed LicenseVerdict = "allowed"
	LicenseDenied  LicenseVerdict = "denied"
	LicenseUnknown LicenseVerdict = "unknown"
)

// LicensePolicy is an allow/deny list of SPDX IDs (glob "*" suffix allowed,
// e.g. "GPL-*"). Deny wins over allow. Packages with no license are
// reported as unknown rather than silently passing.
type LicensePolicy struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

// DefaultLicensePolicy blocks strong copyleft, which is the usual
// platform-team concern for images that get redistributed.
func DefaultLicensePolicy() LicensePolicy {
	return LicensePolicy{Deny: []string{"AGPL-*", "GPL-*", "SSPL-*"}}
}

// LicenseResult is one evaluated package/license pair.
type LicenseResult struct {
	Digest  Digest         `json:"digest"`
	Package string         `json:"package"`
	Version string         `json:"version"`
	License string         `json:"license"`
	Verdict LicenseVerdict `json:"verdict"`
}

// Evaluate applies the policy to every package of an SBOM.
func (p LicensePolicy) Evaluate(s SBOM) []LicenseResult {
	var out []LicenseResult
	for _, pkg := range s.Packages {
		if len(pkg.Licenses) == 0 {
			out = append(out, LicenseResult{s.Digest, pkg.Name, pkg.Version, "", LicenseUnknown})
			continue
		}
		for _, lic := range pkg.Licenses {
			out = append(out, LicenseResult{s.Digest, pkg.Name, pkg.Version, lic, p.verdict(lic)})
		}
	}
	return out
}

func (p LicensePolicy) verdict(expr string) LicenseVerdict {
	// SPDX expressions: "MIT OR GPL-2.0-only" passes if any OR branch passes;
	// "A AND B" fails if any AND part is denied. Keep it simple and safe:
	// treat AND parts as all required, OR parts as alternatives.
	for _, alt := range splitAny(expr, " OR ", " or ") {
		denied := false
		for _, id := range splitAny(alt, " AND ", " and ") {
			if matchAny(p.Deny, cleanSPDX(id)) {
				denied = true
				break
			}
		}
		if !denied {
			if len(p.Allow) == 0 {
				return LicenseAllowed
			}
			for _, id := range splitAny(alt, " AND ", " and ") {
				if !matchAny(p.Allow, cleanSPDX(id)) {
					return LicenseUnknown
				}
			}
			return LicenseAllowed
		}
	}
	return LicenseDenied
}

func cleanSPDX(s string) string {
	return strings.Trim(strings.TrimSpace(s), "()")
}

func splitAny(s string, seps ...string) []string {
	parts := []string{s}
	for _, sep := range seps {
		var next []string
		for _, p := range parts {
			next = append(next, strings.Split(p, sep)...)
		}
		parts = next
	}
	return parts
}

func matchAny(patterns []string, id string) bool {
	for _, p := range patterns {
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(strings.ToUpper(id), strings.ToUpper(strings.TrimSuffix(p, "*"))) {
				return true
			}
		} else if strings.EqualFold(p, id) {
			return true
		}
	}
	return false
}

// ---- Posture checks ----------------------------------------------------

// PostureViolation is one failed configuration check on a workload.
type PostureViolation struct {
	WorkloadID string   `json:"workload_id"`
	CheckID    string   `json:"check_id"`
	Severity   Severity `json:"severity"`
	Container  string   `json:"container,omitempty"`
	Message    string   `json:"message"`
}

// PostureCheck describes a built-in control.
type PostureCheck struct {
	ID       string
	Title    string
	Severity Severity
}

// PostureChecks is the built-in control set. Kyverno enforces at admission;
// these report on what is already running.
var PostureChecks = []PostureCheck{
	{"GJ-001", "Privileged container", SeverityCritical},
	{"GJ-002", "Host namespaces (network/PID)", SeverityHigh},
	{"GJ-003", "hostPath volume mounted", SeverityHigh},
	{"GJ-004", "Container may run as root", SeverityMedium},
	{"GJ-005", "Privilege escalation allowed", SeverityMedium},
	{"GJ-006", "No CPU/memory limits", SeverityLow},
	{"GJ-007", "Mutable image tag (latest or none)", SeverityMedium},
	{"GJ-008", "Dangerous capability added", SeverityHigh},
	{"GJ-009", "Writable root filesystem", SeverityLow},
}

var dangerousCaps = map[string]bool{"SYS_ADMIN": true, "NET_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true, "ALL": true}

// EvaluatePosture runs every check against a workload.
func EvaluatePosture(w Workload) []PostureViolation {
	id := w.ID()
	var out []PostureViolation
	add := func(check, container, msg string) {
		for _, c := range PostureChecks {
			if c.ID == check {
				out = append(out, PostureViolation{id, check, c.Severity, container, msg})
				return
			}
		}
	}
	if w.HostNetwork || w.HostPID {
		add("GJ-002", "", "pod shares host network or PID namespace")
	}
	if w.HostPath {
		add("GJ-003", "", "pod mounts a hostPath volume")
	}
	for _, c := range w.Containers {
		if c.Privileged {
			add("GJ-001", c.Name, "privileged: true")
		}
		if !c.RunAsNonRoot {
			add("GJ-004", c.Name, "runAsNonRoot is not set")
		}
		if c.AllowPrivilegeEscalation {
			add("GJ-005", c.Name, "allowPrivilegeEscalation is not false")
		}
		if !c.HasLimits {
			add("GJ-006", c.Name, "resources.limits missing")
		}
		if c.Image.UsesMutableTag() {
			add("GJ-007", c.Name, fmt.Sprintf("image %s is not pinned", c.Image))
		}
		for _, capb := range c.AddedCapabilities {
			if dangerousCaps[strings.ToUpper(capb)] {
				add("GJ-008", c.Name, "adds capability "+capb)
			}
		}
		if !c.ReadOnlyRootFS {
			add("GJ-009", c.Name, "readOnlyRootFilesystem is not true")
		}
	}
	return out
}
