// Package app holds Gjallar's use cases and the ports (interfaces) they
// need. Adapters in internal/adapters implement the ports; nothing in this
// package imports an adapter.
package app

import (
	"context"
	"errors"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// ErrNotFound is returned by repositories and stores for missing records.
var ErrNotFound = errors.New("not found")

// ---- Driven ports: scanners -------------------------------------------

// SBOMGenerator builds an SBOM for an image (Syft).
type SBOMGenerator interface {
	Generate(ctx context.Context, ref domain.ImageRef) (domain.SBOM, error)
}

// VulnMatcher matches a stored SBOM against the vulnerability DB (Grype).
type VulnMatcher interface {
	Match(ctx context.Context, sbomRaw []byte) (dbVersion string, findings []domain.Finding, err error)
}

// LicenseChecker evaluates licenses in an SBOM (Grant, or the built-in policy).
type LicenseChecker interface {
	Evaluate(ctx context.Context, sbom domain.SBOM, policy domain.LicensePolicy) ([]domain.LicenseResult, error)
}

// Patcher patches OS packages in an image without a rebuild (Copa).
type Patcher interface {
	Patch(ctx context.Context, ref domain.ImageRef, findings []domain.Finding) (patchedRef string, err error)
}

// RuntimeSignal reports which packages of an image were seen loading at
// runtime (Inspektor Gadget). known=false means "no data", not "not loaded".
type RuntimeSignal interface {
	Loaded(ctx context.Context, d domain.Digest) (loaded map[string]bool, known bool, err error)
}

// SBOMConverter re-encodes a stored SBOM in an open standard format
// (cyclonedx-json, spdx-json) so users can take their data elsewhere.
type SBOMConverter interface {
	Convert(ctx context.Context, sbomRaw []byte, format string) ([]byte, error)
}

// SBOMFormats are the extra formats stored next to Syft JSON.
var SBOMFormats = []string{"cyclonedx-json", "spdx-json"}

// SBOMKey is the store key of an SBOM in another format.
func SBOMKey(d domain.Digest, format string) domain.Digest {
	if format == "" || format == "syft-json" {
		return d
	}
	return domain.Digest(string(d) + "." + format)
}

// Attestor signs a statement about an image and stores it next to the image
// in its registry (cosign attest), so admission can verify it offline.
type Attestor interface {
	Attest(ctx context.Context, ref domain.ImageRef, predicateType string, predicate []byte) error
}

// ---- Driven ports: infrastructure -------------------------------------

// EventBus publishes domain events and jobs.
type EventBus interface {
	Publish(ctx context.Context, subject string, v any) error
}

// SBOMStore keeps raw SBOM documents by digest (NATS object store, S3...).
type SBOMStore interface {
	Put(ctx context.Context, d domain.Digest, raw []byte) error
	Get(ctx context.Context, d domain.Digest) ([]byte, error)
}

// Repository is the operational store (Postgres).
type Repository interface {
	UpsertWorkload(ctx context.Context, w domain.Workload) error
	// EnsureImage records an image; it returns true when an SBOM job should
	// be queued (no SBOM yet and none queued recently).
	EnsureImage(ctx context.Context, ref domain.ImageRef) (queue bool, err error)
	MarkSBOM(ctx context.Context, ev domain.SBOMGenerated) error
	Exposure(ctx context.Context, d domain.Digest) (bool, error)
	Findings(ctx context.Context, d domain.Digest) ([]domain.Finding, error)
	SaveFindings(ctx context.Context, d domain.Digest, dbVersion string, fs []domain.Finding) error
	AcceptFinding(ctx context.Context, id, reason, author string, expires *time.Time) error
	SaveLicenses(ctx context.Context, d domain.Digest, rs []domain.LicenseResult) error
	SavePosture(ctx context.Context, workloadID string, vs []domain.PostureViolation) error
	CreatePatch(ctx context.Context, d domain.Digest) (int64, error)
	SavePatch(ctx context.Context, r domain.PatchResult) error
	SBOMDigests(ctx context.Context) ([]domain.Digest, error)
	Image(ctx context.Context, d domain.Digest) (domain.Image, error)
	// ImageByRef finds the most recently scanned image for repository:tag.
	ImageByRef(ctx context.Context, repository, tag string) (domain.Image, error)

	// Read side
	Summary(ctx context.Context) (Summary, error)
	ListFindings(ctx context.Context, f FindingFilter) ([]FindingView, error)
	ListImages(ctx context.Context) ([]domain.Image, error)
	ListWorkloads(ctx context.Context) ([]domain.Workload, error)
	ListPosture(ctx context.Context) ([]domain.PostureViolation, error)
	ListLicenses(ctx context.Context, verdict string) ([]domain.LicenseResult, error)
	ListPatches(ctx context.Context) ([]PatchView, error)
}

// ---- Read models -------------------------------------------------------

// Summary is the dashboard headline.
type Summary struct {
	Images       int            `json:"images"`
	Workloads    int            `json:"workloads"`
	OpenFindings int            `json:"open_findings"`
	ByBand       map[string]int `json:"by_band"`
	BySeverity   map[string]int `json:"by_severity"`
	KEV          int            `json:"kev"`
	Fixable      int            `json:"fixable"`
	Posture      int            `json:"posture_violations"`
	LicDenied    int            `json:"licenses_denied"`
	MedianTTFH   float64        `json:"median_time_to_fix_hours"`
}

// FindingFilter narrows ListFindings.
type FindingFilter struct {
	Band      string
	Namespace string
	Package   string
	Digest    domain.Digest
	State     string
	Limit     int
}

// FindingView is a finding plus where it runs.
type FindingView struct {
	domain.Finding
	Repository string   `json:"repository"`
	Workloads  []string `json:"workloads"`
}

// PatchView is a patch request and its outcome.
type PatchView struct {
	ID         int64     `json:"id"`
	Digest     string    `json:"digest"`
	Status     string    `json:"status"`
	PatchedRef string    `json:"patched_ref,omitempty"`
	Message    string    `json:"message,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// NoRuntime is the RuntimeSignal used when Inspektor Gadget is not deployed.
type NoRuntime struct{}

// Loaded always reports unknown.
func (NoRuntime) Loaded(context.Context, domain.Digest) (map[string]bool, bool, error) {
	return nil, false, nil
}
