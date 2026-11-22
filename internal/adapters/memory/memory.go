// Package memory provides in-process adapters: a repository, an SBOM store
// and an event bus. Used by tests and by `--store=memory` dev mode.
package memory

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/app"
	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// ---- Bus ----------------------------------------------------------------

// Bus records published messages and optionally dispatches them.
type Bus struct {
	mu       sync.Mutex
	Messages []Message
	handlers map[string][]func(context.Context, []byte) error
}

// Message is one published event.
type Message struct {
	Subject string
	Data    []byte
}

// NewBus returns an empty bus.
func NewBus() *Bus { return &Bus{handlers: map[string][]func(context.Context, []byte) error{}} }

// Subscribe registers a synchronous handler for a subject.
func (b *Bus) Subscribe(subject string, fn func(context.Context, []byte) error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[subject] = append(b.handlers[subject], fn)
}

// Publish stores the message and runs handlers synchronously.
func (b *Bus) Publish(ctx context.Context, subject string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.Messages = append(b.Messages, Message{subject, data})
	hs := append([]func(context.Context, []byte) error(nil), b.handlers[subject]...)
	b.mu.Unlock()
	for _, h := range hs {
		if err := h(ctx, data); err != nil {
			return err
		}
	}
	return nil
}

// Count returns how many messages went to a subject.
func (b *Bus) Count(subject string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, m := range b.Messages {
		if m.Subject == subject {
			n++
		}
	}
	return n
}

// ---- SBOM store ---------------------------------------------------------

// Store is a map-backed SBOM store.
type Store struct {
	mu sync.Mutex
	m  map[domain.Digest][]byte
}

// NewStore returns an empty store.
func NewStore() *Store { return &Store{m: map[domain.Digest][]byte{}} }

// Put stores raw bytes.
func (s *Store) Put(_ context.Context, d domain.Digest, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[d] = append([]byte(nil), raw...)
	return nil
}

// Get returns raw bytes or app.ErrNotFound.
func (s *Store) Get(_ context.Context, d domain.Digest) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.m[d]
	if !ok {
		return nil, app.ErrNotFound
	}
	return b, nil
}

// ---- Repository ---------------------------------------------------------

// Repo is an in-memory implementation of app.Repository.
type Repo struct {
	mu        sync.Mutex
	workloads map[string]domain.Workload
	images    map[domain.Digest]domain.Image
	queued    map[domain.Digest]time.Time
	findings  map[domain.Digest][]domain.Finding
	licenses  map[domain.Digest][]domain.LicenseResult
	posture   map[string][]domain.PostureViolation
	patches   []app.PatchView
	Now       func() time.Time
}

// NewRepo returns an empty repository.
func NewRepo() *Repo {
	return &Repo{
		workloads: map[string]domain.Workload{}, images: map[domain.Digest]domain.Image{},
		queued: map[domain.Digest]time.Time{}, findings: map[domain.Digest][]domain.Finding{},
		licenses: map[domain.Digest][]domain.LicenseResult{}, posture: map[string][]domain.PostureViolation{},
		Now: time.Now,
	}
}

var _ app.Repository = (*Repo)(nil)

func (r *Repo) UpsertWorkload(_ context.Context, w domain.Workload) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.workloads[w.ID()] = w
	return nil
}

func (r *Repo) EnsureImage(_ context.Context, ref domain.ImageRef) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	img, ok := r.images[ref.Digest]
	if !ok {
		img = domain.Image{Digest: ref.Digest, Repository: ref.Repository, Tag: ref.Tag, FirstSeen: r.Now()}
		r.images[ref.Digest] = img
	}
	if img.SBOMReady {
		return false, nil
	}
	if t, ok := r.queued[ref.Digest]; ok && r.Now().Sub(t) < 15*time.Minute {
		return false, nil
	}
	r.queued[ref.Digest] = r.Now()
	return true, nil
}

func (r *Repo) MarkSBOM(_ context.Context, ev domain.SBOMGenerated) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ev.Error != "" {
		delete(r.queued, ev.Digest)
		return nil
	}
	img, ok := r.images[ev.Digest]
	if !ok {
		img = domain.Image{Digest: ev.Digest, Repository: ev.Image.Repository, Tag: ev.Image.Tag, FirstSeen: r.Now()}
	}
	img.SBOMReady, img.Distro, img.Packages = true, ev.Distro, ev.Packages
	r.images[ev.Digest] = img
	return nil
}

func (r *Repo) Exposure(_ context.Context, d domain.Digest) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, w := range r.workloads {
		for _, c := range w.Containers {
			if c.Image.Digest == d && w.Exposed {
				return true, nil
			}
		}
	}
	return false, nil
}

func (r *Repo) Findings(_ context.Context, d domain.Digest) ([]domain.Finding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]domain.Finding(nil), r.findings[d]...), nil
}

func (r *Repo) SaveFindings(_ context.Context, d domain.Digest, dbv string, fs []domain.Finding) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.findings[d] = append([]domain.Finding(nil), fs...)
	if img, ok := r.images[d]; ok {
		img.DBVersion, img.LastScanned = dbv, r.Now()
		r.images[d] = img
	}
	return nil
}

func (r *Repo) AcceptFinding(_ context.Context, id, _, _ string, _ *time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for d, fs := range r.findings {
		for i := range fs {
			if fs[i].ID == id {
				fs[i].State = domain.StateAccepted
				r.findings[d] = fs
				return nil
			}
		}
	}
	return app.ErrNotFound
}

func (r *Repo) SaveLicenses(_ context.Context, d domain.Digest, rs []domain.LicenseResult) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.licenses[d] = rs
	return nil
}

func (r *Repo) SavePosture(_ context.Context, id string, vs []domain.PostureViolation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.posture[id] = vs
	return nil
}

func (r *Repo) CreatePatch(_ context.Context, d domain.Digest) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := int64(len(r.patches) + 1)
	r.patches = append(r.patches, app.PatchView{ID: id, Digest: string(d), Status: "queued", CreatedAt: r.Now()})
	return id, nil
}

func (r *Repo) SavePatch(_ context.Context, res domain.PatchResult) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.patches) - 1; i >= 0; i-- {
		if r.patches[i].Digest == string(res.Digest) && r.patches[i].Status == "queued" {
			r.patches[i].Status, r.patches[i].PatchedRef, r.patches[i].Message = "done", res.PatchedRef, ""
			if res.Error != "" {
				r.patches[i].Status, r.patches[i].Message = "failed", res.Error
			}
			return nil
		}
	}
	return nil
}

func (r *Repo) SBOMDigests(context.Context) ([]domain.Digest, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []domain.Digest
	for d, img := range r.images {
		if img.SBOMReady {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func (r *Repo) Image(_ context.Context, d domain.Digest) (domain.Image, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	img, ok := r.images[d]
	if !ok {
		return img, app.ErrNotFound
	}
	return img, nil
}

func (r *Repo) ImageByRef(_ context.Context, repo, tag string) (domain.Image, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var best domain.Image
	found := false
	for _, i := range r.images {
		if i.Repository == repo && i.Tag == tag && (!found || i.LastScanned.After(best.LastScanned)) {
			best, found = i, true
		}
	}
	if !found {
		return best, app.ErrNotFound
	}
	return best, nil
}

func (r *Repo) Summary(context.Context) (app.Summary, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := app.Summary{Images: len(r.images), Workloads: len(r.workloads), ByBand: map[string]int{}, BySeverity: map[string]int{}}
	for _, fs := range r.findings {
		for _, f := range fs {
			if f.State != domain.StateOpen {
				continue
			}
			s.OpenFindings++
			s.ByBand[string(f.Risk.Band)]++
			s.BySeverity[f.Severity.String()]++
			if f.KEV {
				s.KEV++
			}
			if f.FixAvailable() {
				s.Fixable++
			}
		}
	}
	for _, vs := range r.posture {
		s.Posture += len(vs)
	}
	for _, ls := range r.licenses {
		for _, l := range ls {
			if l.Verdict == domain.LicenseDenied {
				s.LicDenied++
			}
		}
	}
	return s, nil
}

func (r *Repo) ListFindings(_ context.Context, f app.FindingFilter) ([]app.FindingView, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []app.FindingView
	for d, fs := range r.findings {
		img := r.images[d]
		var wls []string
		for _, w := range r.workloads {
			for _, c := range w.Containers {
				if c.Image.Digest == d && (f.Namespace == "" || w.Namespace == f.Namespace) {
					wls = append(wls, w.Namespace+"/"+w.Name)
				}
			}
		}
		if f.Namespace != "" && len(wls) == 0 {
			continue
		}
		for _, x := range fs {
			state := f.State
			if state == "" {
				state = string(domain.StateOpen)
			}
			if string(x.State) != state && state != "all" ||
				f.Band != "" && string(x.Risk.Band) != f.Band ||
				f.Package != "" && !strings.Contains(x.Package, f.Package) ||
				f.Digest != "" && x.Digest != f.Digest {
				continue
			}
			out = append(out, app.FindingView{Finding: x, Repository: img.Repository, Workloads: wls})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Risk.Value > out[j].Risk.Value })
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func (r *Repo) ListImages(context.Context) ([]domain.Image, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []domain.Image
	for _, i := range r.images {
		out = append(out, i)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repository < out[j].Repository })
	return out, nil
}

func (r *Repo) ListWorkloads(context.Context) ([]domain.Workload, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []domain.Workload
	for _, w := range r.workloads {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out, nil
}

func (r *Repo) ListPosture(context.Context) ([]domain.PostureViolation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []domain.PostureViolation
	for _, vs := range r.posture {
		out = append(out, vs...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Severity > out[j].Severity })
	return out, nil
}

func (r *Repo) ListLicenses(_ context.Context, verdict string) ([]domain.LicenseResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []domain.LicenseResult
	for _, ls := range r.licenses {
		for _, l := range ls {
			if verdict == "" || string(l.Verdict) == verdict {
				out = append(out, l)
			}
		}
	}
	return out, nil
}

func (r *Repo) ListPatches(context.Context) ([]app.PatchView, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]app.PatchView(nil), r.patches...), nil
}
