package natsbus

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/domain"
	"github.com/heimdallr-dev/gjallar/internal/platform/telemetry"
)

// Needs nats-server -c testdata/users.conf (GJALLAR_TEST_NATS_USERS_URL); skipped otherwise.
// Proves the agent user can do its job and nothing else.
func TestAgentUserPermissions(t *testing.T) {
	url := os.Getenv("GJALLAR_TEST_NATS_USERS_URL")
	if url == "" {
		t.Skip("set GJALLAR_TEST_NATS_USERS_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	log := telemetry.NewLogger("t")
	d := domain.Digest("sha256:" + time.Now().Format("150405.000000000"))

	t.Setenv("GJALLAR_NATS_USER", "gjallar")
	t.Setenv("GJALLAR_NATS_PASSWORD", "svc-pass")
	hub, err := Connect(ctx, url, "hub", log)
	if err != nil {
		t.Fatalf("service connect: %v", err)
	}
	defer hub.Close()
	if _, err := hub.Runtime(ctx); err != nil {
		t.Fatalf("service creates runtime KV: %v", err)
	}
	if err := hub.Put(ctx, d, []byte(`{"artifacts":[]}`)); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GJALLAR_NATS_USER", "agent")
	t.Setenv("GJALLAR_NATS_PASSWORD", "wrong")
	short, c2 := context.WithTimeout(ctx, 3*time.Second)
	if b, err := ConnectClient(short, url, "agent-bad", log); err == nil {
		b.Close()
		t.Fatal("wrong agent password must be refused")
	}
	c2()
	t.Setenv("GJALLAR_NATS_PASSWORD", "agent-pass")
	ag, err := ConnectClient(ctx, url, "agent", log)
	if err != nil {
		t.Fatalf("agent connect: %v", err)
	}
	defer ag.Close()

	// Allowed: what the agent is for.
	if err := ag.Publish(ctx, domain.SubjInventory, map[string]string{"cluster": "spoke"}); err != nil {
		t.Errorf("publish inventory: %v", err)
	}
	if err := ag.Publish(ctx, domain.SubjRuntime, domain.RuntimeObserved{Digest: d}); err != nil {
		t.Errorf("publish runtime event: %v", err)
	}
	rt, err := ag.Runtime(ctx)
	if err != nil {
		t.Fatalf("agent binds runtime KV: %v", err)
	}
	if err := rt.Record(ctx, d, []string{"libssl3"}); err != nil {
		t.Errorf("record runtime: %v", err)
	}
	if got, ok, err := rt.Loaded(ctx, d); err != nil || !ok || !got["libssl3"] {
		t.Errorf("read runtime: %v %v %v", got, ok, err)
	}
	if sb, err := ag.Get(ctx, d); err != nil || string(sb) != `{"artifacts":[]}` {
		t.Errorf("read SBOM: %q %v", sb, err)
	}

	// Denied: forging jobs or results, or touching streams.
	deny := func(what string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s must be denied", what)
		}
	}
	short, c3 := context.WithTimeout(ctx, 5*time.Second)
	defer c3()
	deny("publish job", ag.Publish(short, domain.SubjJobSBOM, domain.ScanJob{Digest: d}))
	deny("publish result", ag.Publish(short, "gjallar.results.vuln", map[string]string{}))
	deny("delete stream", ag.JS.DeleteStream(short, StreamJobs))
	deny("put SBOM", ag.Put(short, d, []byte("forged")))
	if s, err := ag.JS.Stream(short, StreamEvents); err == nil {
		deny("purge events", s.Purge(short))
	}
}
