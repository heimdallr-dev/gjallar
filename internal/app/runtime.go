package app

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// ContainerDigests resolves which image digest a running container uses.
// It returns "" when the pod or container no longer exists.
type ContainerDigests interface {
	ContainerDigest(ctx context.Context, ns, pod, container string) (domain.Digest, error)
}

// RuntimeStore is the RuntimeSignal plus a writer (NATS KV).
type RuntimeStore interface {
	RuntimeSignal
	Record(ctx context.Context, d domain.Digest, pkgs []string) error
}

// FileIndex turns a raw SBOM into a path → package-name lookup.
type FileIndex func(sbomRaw []byte) (func(path string) string, error)

// maxPathsPerContainer bounds memory between flushes; trace_open is noisy.
const maxPathsPerContainer = 20000

// RuntimeRecorder turns observed file opens into "package loaded" facts
// per image digest. The hub's next scoring pass (every inventory cycle)
// reads them: loaded ×1.0, never loaded ×0.3.
type RuntimeRecorder struct {
	Digests ContainerDigests
	SBOMs   SBOMStore
	Store   RuntimeStore
	Index   FileIndex
	Bus     EventBus // optional: publishes RuntimeObserved for analytics
	Log     *slog.Logger
	Now     func() time.Time

	mu      sync.Mutex
	pending map[ctrKey]map[string]bool
	indexes map[domain.Digest]func(string) string
}

type ctrKey struct{ ns, pod, ctr string }

// Observe records one file open. Safe for concurrent use.
func (r *RuntimeRecorder) Observe(ns, pod, ctr, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		r.pending = map[ctrKey]map[string]bool{}
	}
	k := ctrKey{ns, pod, ctr}
	ps := r.pending[k]
	if ps == nil {
		ps = map[string]bool{}
		r.pending[k] = ps
	}
	if len(ps) < maxPathsPerContainer {
		ps[path] = true
	}
}

// Flush maps pending opens to packages and merges them into the store.
// Containers whose image has no SBOM yet stay pending for the next flush.
// It returns how many digests got new packages.
func (r *RuntimeRecorder) Flush(ctx context.Context) (int, error) {
	r.mu.Lock()
	batch := r.pending
	r.pending = nil
	r.mu.Unlock()

	byDigest := map[domain.Digest]map[string]bool{}
	var errs []error
	for k, paths := range batch {
		d, err := r.Digests.ContainerDigest(ctx, k.ns, k.pod, k.ctr)
		if err != nil {
			errs = append(errs, err)
			r.requeue(k, paths)
			continue
		}
		if d == "" {
			continue // pod gone
		}
		lookup, err := r.index(ctx, d)
		if errors.Is(err, ErrNotFound) {
			r.requeue(k, paths) // not scanned yet
			continue
		}
		if err != nil {
			errs = append(errs, err)
			r.requeue(k, paths)
			continue
		}
		for p := range paths {
			if pkg := lookup(p); pkg != "" {
				if byDigest[d] == nil {
					byDigest[d] = map[string]bool{}
				}
				byDigest[d][pkg] = true
			}
		}
	}

	updated := 0
	for d, pkgs := range byDigest {
		known, _, err := r.Store.Loaded(ctx, d)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var added []string
		for p := range pkgs {
			if !known[p] {
				added = append(added, p)
			}
		}
		if len(added) == 0 {
			continue
		}
		for p := range known {
			pkgs[p] = true
		}
		list := make([]string, 0, len(pkgs))
		for p := range pkgs {
			list = append(list, p)
		}
		sort.Strings(list)
		if err := r.Store.Record(ctx, d, list); err != nil {
			errs = append(errs, err)
			continue
		}
		updated++
		if r.Bus != nil {
			sort.Strings(added)
			now := time.Now
			if r.Now != nil {
				now = r.Now
			}
			if err := r.Bus.Publish(ctx, domain.SubjRuntime, domain.RuntimeObserved{Digest: d, Packages: added, At: now()}); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return updated, errors.Join(errs...)
}

func (r *RuntimeRecorder) requeue(k ctrKey, paths map[string]bool) {
	for p := range paths {
		r.Observe(k.ns, k.pod, k.ctr, p)
	}
}

// index caches one path lookup per digest (SBOMs are immutable per digest).
func (r *RuntimeRecorder) index(ctx context.Context, d domain.Digest) (func(string) string, error) {
	r.mu.Lock()
	f := r.indexes[d]
	r.mu.Unlock()
	if f != nil {
		return f, nil
	}
	raw, err := r.SBOMs.Get(ctx, d)
	if err != nil {
		return nil, err
	}
	if f, err = r.Index(raw); err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.indexes == nil || len(r.indexes) > 500 {
		r.indexes = map[domain.Digest]func(string) string{} // shortcut: crude cache reset, fine for <500 live images per cluster
	}
	r.indexes[d] = f
	r.mu.Unlock()
	return f, nil
}
