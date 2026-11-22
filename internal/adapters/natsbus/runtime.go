package natsbus

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// BucketRuntime holds runtime observations: key = image digest (":" → "_"),
// value = JSON array of package names seen loading (from Inspektor Gadget).
const BucketRuntime = "gjallar-runtime"

// RuntimeKV implements app.RuntimeSignal over a NATS KV bucket. Any
// producer can feed it: the agent's Inspektor Gadget integration, a script,
// or another eBPF tool. Missing keys mean "unknown", never "not loaded".
type RuntimeKV struct{ kv jetstream.KeyValue }

// Runtime opens (or creates) the runtime bucket.
func (b *Bus) Runtime(ctx context.Context) (*RuntimeKV, error) {
	kv, err := b.JS.KeyValue(ctx, BucketRuntime) // bind first: agents may not create buckets
	if errors.Is(err, jetstream.ErrBucketNotFound) {
		kv, err = b.JS.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: BucketRuntime, Description: "Packages observed at runtime per image digest", History: 1})
	}
	if err != nil {
		return nil, err
	}
	return &RuntimeKV{kv: kv}, nil
}

// Loaded implements app.RuntimeSignal.
func (r *RuntimeKV) Loaded(ctx context.Context, d domain.Digest) (map[string]bool, bool, error) {
	e, err := r.kv.Get(ctx, key(d))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var pkgs []string
	if err := json.Unmarshal(e.Value(), &pkgs); err != nil {
		return nil, false, err
	}
	m := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		m[p] = true
	}
	return m, true, nil
}

// Record stores the observed packages for a digest.
func (r *RuntimeKV) Record(ctx context.Context, d domain.Digest, pkgs []string) error {
	b, _ := json.Marshal(pkgs)
	_, err := r.kv.Put(ctx, key(d), b)
	return err
}

// BucketNotified records which alerts were sent (key = target.findingID).
const BucketNotified = "gjallar-notified"

// Ledger implements app.AlertLedger with an atomic KV Create, so several
// hub replicas never send the same alert twice.
type Ledger struct{ kv jetstream.KeyValue }

// Ledger opens (or creates) the notification ledger; entries expire after ttl.
func (b *Bus) Ledger(ctx context.Context, ttl time.Duration) (*Ledger, error) {
	kv, err := b.JS.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: BucketNotified, Description: "Alerts already sent", History: 1, TTL: ttl})
	if err != nil {
		return nil, err
	}
	return &Ledger{kv: kv}, nil
}

// Forget removes a key so the alert can be sent again.
func (l *Ledger) Forget(ctx context.Context, key string) error {
	return l.kv.Delete(ctx, ledgerKey(key))
}

func ledgerKey(key string) string { return strings.NewReplacer(":", "_", "/", "_").Replace(key) }

// MarkNew returns true the first time key is seen.
func (l *Ledger) MarkNew(ctx context.Context, key string) (bool, error) {
	_, err := l.kv.Create(ctx, ledgerKey(key), []byte{1})
	if errors.Is(err, jetstream.ErrKeyExists) {
		return false, nil
	}
	return err == nil, err
}
