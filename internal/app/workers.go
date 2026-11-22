package app

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// Workers are stateless: they take a job, call one engine, publish a result.
// Failures are published as results with Error set so the hub always knows.

// SBOMWorker runs Syft and stores the raw SBOM for later re-matching.
type SBOMWorker struct {
	Gen   SBOMGenerator
	Store SBOMStore
	Bus   EventBus
	// Optional: sign the SBOM as a cosign attestation for images whose
	// repository starts with one of AttestRepos (registries you can push to).
	Attest      Attestor
	AttestRepos []string
	// Optional: also store CycloneDX and SPDX copies (freedom of data).
	Convert SBOMConverter
}

// PredicateSyft is the in-toto predicate type for a Syft JSON SBOM.
const PredicateSyft = "https://syft.dev/bom"

// Handle processes one SBOM job.
func (w SBOMWorker) Handle(ctx context.Context, job domain.ScanJob) error {
	ev := domain.SBOMGenerated{Image: job.Image, Digest: job.Digest, At: time.Now()}
	sbom, err := w.Gen.Generate(ctx, job.Image)
	if err == nil && !sbom.Digest.Valid() {
		sbom.Digest = job.Digest
	}
	if err == nil && !sbom.Digest.Valid() {
		err = fmt.Errorf("could not determine image digest")
	}
	if err == nil {
		err = w.Store.Put(ctx, sbom.Digest, sbom.Raw)
	}
	if err != nil {
		ev.Error = err.Error()
	} else {
		ev.Digest, ev.Distro, ev.Packages = sbom.Digest, sbom.Distro, len(sbom.Packages)
		ev.Image.Digest = sbom.Digest
		if w.Convert != nil {
			for _, f := range SBOMFormats {
				// A failed conversion only means that format is not offered; Syft JSON stays the source of truth.
				if out, cerr := w.Convert.Convert(ctx, sbom.Raw, f); cerr == nil {
					_ = w.Store.Put(ctx, SBOMKey(sbom.Digest, f), out)
				}
			}
		}
		if w.Attest != nil && hasPrefix(job.Image.Repository, w.AttestRepos) {
			// A failed signature doesn't fail the scan; the hub sees it in the event.
			if aerr := w.Attest.Attest(ctx, ev.Image, PredicateSyft, sbom.Raw); aerr != nil {
				ev.AttestError = aerr.Error()
			} else {
				ev.Attested = true
			}
		}
	}
	return w.Bus.Publish(ctx, domain.SubjSBOMDone, ev)
}

// VulnWorker matches a stored SBOM with Grype.
type VulnWorker struct {
	Matcher VulnMatcher
	Store   SBOMStore
	Bus     EventBus
	// Input is the SBOM format the matcher reads: "" = Syft JSON (Grype),
	// "cyclonedx-json" (Trivy), read from the stored converted copy.
	Input string
	// Optional second source (OSV) over the stored CycloneDX copy. Its
	// findings fill gaps; the primary matcher wins for the same package + CVE
	// because it carries EPSS and KEV.
	Second VulnMatcher
}

// Handle processes one vulnerability job.
func (w VulnWorker) Handle(ctx context.Context, job domain.ScanJob) error {
	ev := domain.FindingsMatched{Digest: job.Digest, At: time.Now()}
	raw, err := w.Store.Get(ctx, SBOMKey(job.Digest, w.Input))
	if err == nil {
		ev.DBVersion, ev.Findings, err = w.Matcher.Match(ctx, raw)
	}
	if err == nil && w.Second != nil {
		// A failing second source never fails the scan; it only adds coverage.
		if cdx, cerr := w.Store.Get(ctx, SBOMKey(job.Digest, "cyclonedx-json")); cerr == nil {
			if _, extra, serr := w.Second.Match(ctx, cdx); serr == nil {
				ev.Findings = MergeFindings(ev.Findings, extra)
			}
		}
	}
	if err != nil {
		ev.Error = err.Error()
	}
	for i := range ev.Findings {
		ev.Findings[i].Digest = job.Digest
		ev.Findings[i].ID = domain.FindingID(job.Digest, ev.Findings[i].VulnID, ev.Findings[i].Package, ev.Findings[i].Version)
	}
	return w.Bus.Publish(ctx, domain.SubjVulnDone, ev)
}

// LicenseWorker evaluates licenses of a stored SBOM.
type LicenseWorker struct {
	Checker LicenseChecker
	Parse   func(raw []byte) (domain.SBOM, error)
	Store   SBOMStore
	Bus     EventBus
	Policy  domain.LicensePolicy
}

// Handle processes one license job.
func (w LicenseWorker) Handle(ctx context.Context, job domain.ScanJob) error {
	ev := domain.LicensesEvaluated{Digest: job.Digest, At: time.Now()}
	raw, err := w.Store.Get(ctx, job.Digest)
	var sbom domain.SBOM
	if err == nil {
		sbom, err = w.Parse(raw)
	}
	if err == nil {
		sbom.Digest, sbom.Raw = job.Digest, raw
		ev.Results, err = w.Checker.Evaluate(ctx, sbom, w.Policy)
	}
	if err != nil {
		ev.Error = err.Error()
	}
	return w.Bus.Publish(ctx, domain.SubjLicDone, ev)
}

// PatchWorker runs Copa.
type PatchWorker struct {
	Patcher Patcher
	Bus     EventBus
}

// Handle processes one patch job.
func (w PatchWorker) Handle(ctx context.Context, job domain.ScanJob) error {
	ev := domain.PatchResult{Digest: job.Digest, At: time.Now()}
	ref, err := w.Patcher.Patch(ctx, job.Image, job.Findings)
	if err != nil {
		ev.Error = err.Error()
	} else {
		ev.PatchedRef, ev.Fixed = ref, len(job.Findings)
	}
	return w.Bus.Publish(ctx, domain.SubjPatchDone, ev)
}

// ---- Local mode (CLI) -------------------------------------------------

// LocalReport is the result of an in-process scan with no hub.
type LocalReport struct {
	Image     domain.ImageRef        `json:"image"`
	Digest    domain.Digest          `json:"digest"`
	Distro    string                 `json:"distro"`
	Packages  int                    `json:"packages"`
	DBVersion string                 `json:"db_version"`
	Findings  []domain.Finding       `json:"findings"`
	Licenses  []domain.LicenseResult `json:"licenses"`
}

// LocalScan runs Syft → Grype → licenses in-process and ranks by risk.
// Runtime and exposure are unknown on a laptop, so scoring uses neutral context.
func LocalScan(ctx context.Context, gen SBOMGenerator, m VulnMatcher, lc LicenseChecker, pol domain.LicensePolicy, ref domain.ImageRef) (LocalReport, error) {
	sbom, err := gen.Generate(ctx, ref)
	if err != nil {
		return LocalReport{}, fmt.Errorf("sbom: %w", err)
	}
	rep := LocalReport{Image: ref, Digest: sbom.Digest, Distro: sbom.Distro, Packages: len(sbom.Packages)}
	rep.DBVersion, rep.Findings, err = m.Match(ctx, sbom.Raw)
	if err != nil {
		return rep, fmt.Errorf("match: %w", err)
	}
	for i, f := range rep.Findings {
		f.Digest = sbom.Digest
		f.ID = domain.FindingID(sbom.Digest, f.VulnID, f.Package, f.Version)
		f.State = domain.StateOpen
		f.Risk = domain.Score(domain.RiskInput{CVSS: f.CVSS, Severity: f.Severity, EPSS: f.EPSS, KEV: f.KEV, FixAvailable: f.FixAvailable()})
		rep.Findings[i] = f
	}
	SortByRisk(rep.Findings)
	if lc != nil {
		if rep.Licenses, err = lc.Evaluate(ctx, sbom, pol); err != nil {
			return rep, fmt.Errorf("licenses: %w", err)
		}
	}
	return rep, nil
}

// SortByRisk orders findings most urgent first.
func SortByRisk(fs []domain.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Risk.Value != fs[j].Risk.Value {
			return fs[i].Risk.Value > fs[j].Risk.Value
		}
		return fs[i].VulnID < fs[j].VulnID
	})
}

func hasPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// MergeFindings adds secondary findings whose package + vulnerability the
// primary matcher did not report.
func MergeFindings(primary, extra []domain.Finding) []domain.Finding {
	have := make(map[string]bool, len(primary))
	for _, f := range primary {
		have[f.Package+"|"+f.VulnID] = true
	}
	out := primary
	for _, f := range extra {
		if k := f.Package + "|" + f.VulnID; !have[k] {
			have[k] = true
			out = append(out, f)
		}
	}
	return out
}
