package app

import (
	"context"
	"reflect"
	"testing"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

type fakeDigests map[string]domain.Digest

func (f fakeDigests) ContainerDigest(_ context.Context, ns, pod, ctr string) (domain.Digest, error) {
	return f[ns+"/"+pod+"/"+ctr], nil
}

type fakeSBOMs map[domain.Digest][]byte

func (f fakeSBOMs) Put(context.Context, domain.Digest, []byte) error { return nil }
func (f fakeSBOMs) Get(_ context.Context, d domain.Digest) ([]byte, error) {
	if b, ok := f[d]; ok {
		return b, nil
	}
	return nil, ErrNotFound
}

type fakeRuntime map[domain.Digest][]string

func (f fakeRuntime) Loaded(_ context.Context, d domain.Digest) (map[string]bool, bool, error) {
	m := map[string]bool{}
	for _, p := range f[d] {
		m[p] = true
	}
	return m, len(f[d]) > 0, nil
}
func (f fakeRuntime) Record(_ context.Context, d domain.Digest, pkgs []string) error {
	f[d] = pkgs
	return nil
}

func TestRuntimeRecorder(t *testing.T) {
	const web, db domain.Digest = "sha256:web", "sha256:db"
	store := fakeRuntime{web: {"zlib1g"}}
	sboms := fakeSBOMs{web: []byte("web")}
	rec := &RuntimeRecorder{
		Digests: fakeDigests{"shop/web-1/web": web, "shop/db-0/db": db},
		SBOMs:   sboms,
		Store:   store,
		Index: func(raw []byte) (func(string) string, error) {
			return func(p string) string {
				return map[string]string{"/lib/libssl.so.3": "libssl3", "/lib/libpq.so.5": "libpq5"}[p]
			}, nil
		},
	}
	rec.Observe("shop", "web-1", "web", "/lib/libssl.so.3")
	rec.Observe("shop", "web-1", "web", "/etc/hosts")
	rec.Observe("shop", "db-0", "db", "/lib/libpq.so.5") // no SBOM yet: must stay pending
	rec.Observe("gone", "x", "y", "/lib/libssl.so.3")    // pod gone: dropped

	if n, err := rec.Flush(context.Background()); err != nil || n != 1 {
		t.Fatalf("flush 1: n=%d err=%v", n, err)
	}
	if want := []string{"libssl3", "zlib1g"}; !reflect.DeepEqual(store[web], want) {
		t.Fatalf("web = %v, want %v (merged with known)", store[web], want)
	}
	if _, ok := store[db]; ok {
		t.Fatal("db recorded before its SBOM existed")
	}

	sboms[db] = []byte("db") // the SBOM worker caught up
	if n, err := rec.Flush(context.Background()); err != nil || n != 1 || !reflect.DeepEqual(store[db], []string{"libpq5"}) {
		t.Fatalf("flush 2: n=%d err=%v db=%v", n, err, store[db])
	}
	if n, _ := rec.Flush(context.Background()); n != 0 {
		t.Fatalf("flush 3 should be a no-op, got %d", n)
	}
}
