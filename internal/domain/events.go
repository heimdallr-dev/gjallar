package domain

import (
	"encoding/json"
	"time"
)

// Domain events travel between bounded contexts over the event bus.
// Subjects are defined here so every adapter agrees on them.
const (
	SubjInventory  = "gjallar.inventory.workload"
	SubjJobSBOM    = "gjallar.jobs.sbom"
	SubjJobVuln    = "gjallar.jobs.vuln"
	SubjJobLicense = "gjallar.jobs.license"
	SubjJobPatch   = "gjallar.jobs.patch"
	SubjJobVEX     = "gjallar.jobs.vex"
	SubjSBOMDone   = "gjallar.results.sbom"
	SubjVulnDone   = "gjallar.results.vuln"
	SubjLicDone    = "gjallar.results.license"
	SubjPatchDone  = "gjallar.results.patch"
	SubjPosture    = "gjallar.results.posture"
	SubjScored     = "gjallar.results.scored"
	SubjDBUpdated  = "gjallar.events.db_updated"
	SubjRuntime    = "gjallar.events.runtime"
	SubjAudit      = "gjallar.events.audit"
)

// ScanJob asks a worker to process one image.
type ScanJob struct {
	Image    ImageRef  `json:"image"`
	Digest   Digest    `json:"digest"`
	Attempt  int       `json:"attempt,omitempty"`
	Reason   string    `json:"reason,omitempty"`   // discovered, rematch, manual
	Findings []Finding `json:"findings,omitempty"` // patch jobs carry what to fix
}

// SBOMGenerated is published by the SBOM worker.
type SBOMGenerated struct {
	Digest   Digest    `json:"digest"`
	Image    ImageRef  `json:"image"`
	Distro   string    `json:"distro"`
	Packages int       `json:"packages"`
	At       time.Time `json:"at"`
	Error    string    `json:"error,omitempty"`
	// Attested: the SBOM was signed and pushed as a cosign attestation.
	Attested    bool   `json:"attested,omitempty"`
	AttestError string `json:"attest_error,omitempty"`
}

// FindingsMatched is published by the vulnerability worker.
type FindingsMatched struct {
	Digest    Digest    `json:"digest"`
	DBVersion string    `json:"db_version"`
	Findings  []Finding `json:"findings"`
	At        time.Time `json:"at"`
	Error     string    `json:"error,omitempty"`
}

// LicensesEvaluated is published by the license worker.
type LicensesEvaluated struct {
	Digest  Digest          `json:"digest"`
	Results []LicenseResult `json:"results"`
	At      time.Time       `json:"at"`
	Error   string          `json:"error,omitempty"`
}

// PatchResult is published by the patch worker.
type PatchResult struct {
	Digest     Digest    `json:"digest"`
	PatchedRef string    `json:"patched_ref,omitempty"`
	Fixed      int       `json:"fixed"`
	At         time.Time `json:"at"`
	Error      string    `json:"error,omitempty"`
}

// PostureEvaluated is published by the core when a workload is checked.
type PostureEvaluated struct {
	WorkloadID string             `json:"workload_id"`
	Violations []PostureViolation `json:"violations"`
	At         time.Time          `json:"at"`
}

// FindingsScored is published by the core after reconciliation and scoring;
// it is the analytics feed (one row per finding per change).
type FindingsScored struct {
	Digest     Digest    `json:"digest"`
	Repository string    `json:"repository"`
	DBVersion  string    `json:"db_version"`
	Findings   []Finding `json:"findings"`
	At         time.Time `json:"at"`
}

// RuntimeObserved is published by the agent when packages are first seen
// loading in an image (Inspektor Gadget); analytics keeps the history.
type RuntimeObserved struct {
	Digest   Digest    `json:"digest"`
	Packages []string  `json:"packages"` // newly observed only
	At       time.Time `json:"at"`
}

// AuditEvent records one state-changing API call: who, from which client, what, result.
type AuditEvent struct {
	At     time.Time `json:"at"`
	User   string    `json:"user"`
	Client string    `json:"client,omitempty"`
	Method string    `json:"method"`
	Path   string    `json:"path"`
	Status int       `json:"status"`
}

// VEXJob asks the attesting worker to sign an image's OpenVEX document and
// store it next to the image (cosign attestation).
type VEXJob struct {
	Image    ImageRef        `json:"image"`
	Document json.RawMessage `json:"document"`
}
