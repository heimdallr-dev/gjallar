package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// Hub is the orchestration core. It reacts to inventory and worker results
// and decides what to queue next. It never calls a scanner directly.
type Hub struct {
	Repo    Repository
	Bus     EventBus
	Runtime RuntimeSignal
	Now     func() time.Time
	Log     *slog.Logger
}

// NewHub wires a hub with sensible defaults.
func NewHub(repo Repository, bus EventBus, rt RuntimeSignal, log *slog.Logger) *Hub {
	if rt == nil {
		rt = NoRuntime{}
	}
	if log == nil {
		log = slog.Default()
	}
	return &Hub{Repo: repo, Bus: bus, Runtime: rt, Now: time.Now, Log: log}
}

// HandleInventory stores a workload, checks its posture and queues SBOM
// jobs for any image digest not seen before.
func (h *Hub) HandleInventory(ctx context.Context, w domain.Workload) error {
	if w.LastSeen.IsZero() {
		w.LastSeen = h.Now()
	}
	if err := h.Repo.UpsertWorkload(ctx, w); err != nil {
		return fmt.Errorf("upsert workload: %w", err)
	}
	violations := append(domain.EvaluatePosture(w), w.ExternalPosture...)
	if err := h.Repo.SavePosture(ctx, w.ID(), violations); err != nil {
		return fmt.Errorf("save posture: %w", err)
	}
	_ = h.Bus.Publish(ctx, domain.SubjPosture, domain.PostureEvaluated{WorkloadID: w.ID(), Violations: violations, At: h.Now()})

	for _, c := range w.Containers {
		if !c.Image.Digest.Valid() {
			continue // agent could not resolve a digest yet; next pass will
		}
		queue, err := h.Repo.EnsureImage(ctx, c.Image)
		if err != nil {
			return fmt.Errorf("ensure image: %w", err)
		}
		if queue {
			job := domain.ScanJob{Image: c.Image, Digest: c.Image.Digest, Reason: "discovered"}
			if err := h.Bus.Publish(ctx, domain.SubjJobSBOM, job); err != nil {
				return err
			}
			h.Log.Info("queued sbom", "image", c.Image.String())
		}
		// Exposure may have changed: rescore what we already know.
		if err := h.rescore(ctx, c.Image.Digest); err != nil {
			h.Log.Warn("rescore failed", "digest", c.Image.Digest, "err", err)
		}
	}
	return nil
}

// HandleSBOM fans out vulnerability and license jobs once an SBOM exists.
func (h *Hub) HandleSBOM(ctx context.Context, ev domain.SBOMGenerated) error {
	if err := h.Repo.MarkSBOM(ctx, ev); err != nil {
		return err
	}
	if ev.Error != "" {
		h.Log.Warn("sbom failed", "image", ev.Image.String(), "err", ev.Error)
		return nil
	}
	job := domain.ScanJob{Image: ev.Image, Digest: ev.Digest, Reason: "sbom"}
	if err := h.Bus.Publish(ctx, domain.SubjJobVuln, job); err != nil {
		return err
	}
	return h.Bus.Publish(ctx, domain.SubjJobLicense, job)
}

// HandleFindings scores, reconciles and stores a vulnerability match.
func (h *Hub) HandleFindings(ctx context.Context, ev domain.FindingsMatched) error {
	if ev.Error != "" {
		h.Log.Warn("vuln match failed", "digest", ev.Digest, "err", ev.Error)
		return nil
	}
	prev, err := h.Repo.Findings(ctx, ev.Digest)
	if err != nil {
		return err
	}
	scored, err := h.score(ctx, ev.Digest, ev.Findings)
	if err != nil {
		return err
	}
	merged := domain.Reconcile(prev, scored, h.Now())
	if err := h.Repo.SaveFindings(ctx, ev.Digest, ev.DBVersion, merged); err != nil {
		return err
	}
	h.publishScored(ctx, ev.Digest, ev.DBVersion, merged)
	return nil
}

func (h *Hub) publishScored(ctx context.Context, d domain.Digest, dbv string, fs []domain.Finding) {
	repo := ""
	if img, err := h.Repo.Image(ctx, d); err == nil {
		repo = img.Repository
	}
	if err := h.Bus.Publish(ctx, domain.SubjScored, domain.FindingsScored{Digest: d, Repository: repo, DBVersion: dbv, Findings: fs, At: h.Now()}); err != nil {
		h.Log.Warn("publish scored failed", "err", err)
	}
}

// HandleLicenses stores license verdicts.
func (h *Hub) HandleLicenses(ctx context.Context, ev domain.LicensesEvaluated) error {
	if ev.Error != "" {
		h.Log.Warn("license check failed", "digest", ev.Digest, "err", ev.Error)
		return nil
	}
	return h.Repo.SaveLicenses(ctx, ev.Digest, ev.Results)
}

// HandlePatch stores a patch outcome.
func (h *Hub) HandlePatch(ctx context.Context, ev domain.PatchResult) error {
	return h.Repo.SavePatch(ctx, ev)
}

// Rematch re-queues vulnerability matching for every image with an SBOM.
// Triggered after the Grype DB mirror updates: no image is pulled again.
func (h *Hub) Rematch(ctx context.Context) (int, error) {
	ds, err := h.Repo.SBOMDigests(ctx)
	if err != nil {
		return 0, err
	}
	for _, d := range ds {
		img, err := h.Repo.Image(ctx, d)
		if err != nil {
			continue
		}
		job := domain.ScanJob{Image: domain.ImageRef{Repository: img.Repository, Tag: img.Tag, Digest: d}, Digest: d, Reason: "rematch"}
		if err := h.Bus.Publish(ctx, domain.SubjJobVuln, job); err != nil {
			return 0, err
		}
	}
	return len(ds), nil
}

// RequestScan queues a manual scan of any image reference.
// DiscoverImage queues an image found in a registry (not yet running
// anywhere), using the same atomic claim as inventory so replicas and
// repeated discovery passes queue each digest once.
func (h *Hub) DiscoverImage(ctx context.Context, ref domain.ImageRef) (bool, error) {
	if !ref.Digest.Valid() {
		return false, fmt.Errorf("discover %s: no digest", ref.String())
	}
	queue, err := h.Repo.EnsureImage(ctx, ref)
	if err != nil || !queue {
		return false, err
	}
	return true, h.Bus.Publish(ctx, domain.SubjJobSBOM, domain.ScanJob{Image: ref, Digest: ref.Digest, Reason: "registry"})
}

func (h *Hub) RequestScan(ctx context.Context, ref domain.ImageRef) error {
	if ref.Digest.Valid() {
		if _, err := h.Repo.EnsureImage(ctx, ref); err != nil {
			return err
		}
	}
	return h.Bus.Publish(ctx, domain.SubjJobSBOM, domain.ScanJob{Image: ref, Digest: ref.Digest, Reason: "manual"})
}

// RequestPatch queues a Copa patch for the fixable OS-package findings of an image.
func (h *Hub) RequestPatch(ctx context.Context, d domain.Digest) (int64, error) {
	img, err := h.Repo.Image(ctx, d)
	if err != nil {
		return 0, err
	}
	fs, err := h.Repo.Findings(ctx, d)
	if err != nil {
		return 0, err
	}
	var fixable []domain.Finding
	for _, f := range fs {
		if f.State == domain.StateOpen && f.FixAvailable() && osPackage(f.PkgType) {
			fixable = append(fixable, f)
		}
	}
	if len(fixable) == 0 {
		return 0, fmt.Errorf("no fixable OS-package findings for %s", d.Short())
	}
	id, err := h.Repo.CreatePatch(ctx, d)
	if err != nil {
		return 0, err
	}
	job := domain.ScanJob{Image: domain.ImageRef{Repository: img.Repository, Tag: img.Tag, Digest: d}, Digest: d, Reason: "patch", Findings: fixable}
	return id, h.Bus.Publish(ctx, domain.SubjJobPatch, job)
}

// AcceptRisk records a VEX-style exception for a finding.
func (h *Hub) AcceptRisk(ctx context.Context, id, reason, author string, expires *time.Time) error {
	if reason == "" {
		return fmt.Errorf("a reason is required to accept a risk")
	}
	if err := h.Repo.AcceptFinding(ctx, id, reason, author, expires); err != nil {
		return err
	}
	// shortcut: finds the image by listing accepted findings (no FindingByID port); fine at human accept rates.
	fs, err := h.Repo.ListFindings(ctx, FindingFilter{State: string(domain.StateAccepted), Limit: 1000000})
	if err != nil {
		return err
	}
	for _, f := range fs {
		if f.ID == id {
			if err := h.publishVEX(ctx, f.Digest); err != nil {
				h.Log.Warn("vex attestation not queued", "digest", f.Digest, "err", err)
			}
			break
		}
	}
	return nil
}

func (h *Hub) rescore(ctx context.Context, d domain.Digest) error {
	fs, err := h.Repo.Findings(ctx, d)
	if err != nil || len(fs) == 0 {
		return err
	}
	img, err := h.Repo.Image(ctx, d)
	if err != nil {
		return err
	}
	scored, err := h.score(ctx, d, fs)
	if err != nil {
		return err
	}
	changed := false
	for i := range scored {
		if scored[i].Risk.Value != fs[i].Risk.Value {
			changed = true
			break
		}
	}
	if !changed {
		return nil // nothing moved; avoid write amplification on every inventory pass
	}
	if err := h.Repo.SaveFindings(ctx, d, img.DBVersion, scored); err != nil {
		return err
	}
	h.publishScored(ctx, d, img.DBVersion, scored)
	return nil
}

func (h *Hub) score(ctx context.Context, d domain.Digest, fs []domain.Finding) ([]domain.Finding, error) {
	exposed, err := h.Repo.Exposure(ctx, d)
	if err != nil {
		return nil, err
	}
	loaded, known, err := h.Runtime.Loaded(ctx, d)
	if err != nil {
		h.Log.Warn("runtime signal unavailable", "err", err)
		known = false
	}
	out := make([]domain.Finding, len(fs))
	for i, f := range fs {
		rt := domain.TriUnknown
		if known {
			rt = domain.TriNo
			if loaded[f.Package] {
				rt = domain.TriYes
			}
		}
		f.Risk = domain.Score(domain.RiskInput{
			CVSS: f.CVSS, Severity: f.Severity, EPSS: f.EPSS, KEV: f.KEV,
			RuntimeLoaded: rt, Exposed: exposed, FixAvailable: f.FixAvailable(), Source: f.Source,
		})
		out[i] = f
	}
	return out, nil
}

func osPackage(t string) bool {
	switch t {
	case "deb", "rpm", "apk", "alpm":
		return true
	}
	return false
}

// AdmissionVerdict answers "may this image run?" for admission controllers.
type AdmissionVerdict struct {
	Image   string `json:"image"`
	Known   bool   `json:"known"`
	Allowed bool   `json:"allowed"`
	Urgent  int    `json:"urgent"`
	KEV     int    `json:"kev"`
	Reason  string `json:"reason"`
}

// Admission evaluates an image against the gate: deny when any open finding
// is urgent or KEV-listed. Unknown images are allowed (and queued for a
// scan) unless denyUnknown is set, so the gate never blocks a cold cluster.
func (h *Hub) Admission(ctx context.Context, ref domain.ImageRef, denyUnknown bool) (AdmissionVerdict, error) {
	v := AdmissionVerdict{Image: ref.String(), Allowed: true}
	var img domain.Image
	var err error
	if ref.Digest.Valid() {
		img, err = h.Repo.Image(ctx, ref.Digest)
	} else {
		img, err = h.Repo.ImageByRef(ctx, ref.Repository, ref.Tag)
	}
	if err != nil || !img.SBOMReady {
		v.Allowed, v.Reason = !denyUnknown, "image not scanned yet"
		_ = h.RequestScan(ctx, ref)
		return v, nil
	}
	v.Known = true
	fs, err := h.Repo.Findings(ctx, img.Digest)
	if err != nil {
		return v, err
	}
	for _, f := range fs {
		if f.State != domain.StateOpen {
			continue
		}
		if f.Risk.Band == domain.BandUrgent {
			v.Urgent++
		}
		if f.KEV {
			v.KEV++
		}
	}
	if v.Urgent > 0 || v.KEV > 0 {
		v.Allowed = false
		v.Reason = fmt.Sprintf("%d urgent and %d known-exploited open findings", v.Urgent, v.KEV)
	} else {
		v.Reason = "no urgent or known-exploited findings"
	}
	return v, nil
}
