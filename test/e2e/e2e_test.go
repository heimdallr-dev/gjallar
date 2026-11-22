//go:build e2e

// End-to-end test against running Gjallar services (see scripts/e2e.sh):
// inventory → SBOM → match → risk → Postgres → API → MCP → analytics.
package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/flight/flightsql"
	"github.com/heimdallr-dev/gjallar/internal/adapters/natsbus"
	"github.com/heimdallr-dev/gjallar/internal/app"
	"github.com/heimdallr-dev/gjallar/internal/client"
	"github.com/heimdallr-dev/gjallar/internal/domain"
	"github.com/heimdallr-dev/gjallar/internal/platform/telemetry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const digest = "sha256:e2e0000000000000000000000000000000000000000000000000000000000001"

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func TestEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	bus, err := natsbus.Connect(ctx, env("GJALLAR_NATS_URL", "nats://127.0.0.1:54222"), "e2e", telemetry.NewLogger("e2e"))
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()

	hooks := make(chan string, 10)
	if addr := os.Getenv("GJALLAR_E2E_HOOK"); addr != "" {
		srv := &http.Server{Addr: addr, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			hooks <- string(b)
		})}
		go srv.ListenAndServe()
		defer srv.Close()
	}
	api := client.New(env("GJALLAR_URL", "http://127.0.0.1:18080"), "")
	mcpURL := env("GJALLAR_MCP_URL", "http://127.0.0.1:18082")

	// 1. Agent's job, simulated: publish one exposed workload.
	w := domain.Workload{Cluster: "e2e", Namespace: "shop", Kind: "Deployment", Name: "web", Exposed: true,
		Containers: []domain.Container{{Name: "app", Image: domain.ImageRef{Repository: "harbor.local/shop/web", Tag: "1.0", Digest: digest}}}}
	if err := bus.Publish(ctx, domain.SubjInventory, w); err != nil {
		t.Fatal(err)
	}

	// 2. Wait for workers + hub to finish the pipeline.
	var fs []app.FindingView
	waitFor(t, ctx, "scored findings in API", func() bool {
		fs = nil
		return api.Get(ctx, "/api/v1/findings", &fs) == nil && len(fs) == 2
	})
	if fs[0].VulnID != "CVE-2023-4863" || fs[0].Risk.Band != domain.BandUrgent || !fs[0].KEV {
		t.Fatalf("KEV+exposed libwebp must rank first as urgent: %+v", fs[0])
	}
	if fs[1].VulnID != "CVE-2099-0001" || domain.BandRank(fs[1].Risk.Band) >= domain.BandRank(domain.BandHigh) {
		t.Fatalf("quiet critical must rank below: %+v", fs[1].Risk)
	}
	if len(fs[0].Workloads) != 1 || fs[0].Workloads[0] != "shop/web" {
		t.Fatalf("finding must know where it runs: %v", fs[0].Workloads)
	}
	t.Logf("ranked: %s=%d (%s), %s=%d (%s)", fs[0].VulnID, fs[0].Risk.Value, fs[0].Risk.Band, fs[1].VulnID, fs[1].Risk.Value, fs[1].Risk.Band)

	var lic []domain.LicenseResult
	waitFor(t, ctx, "license denial", func() bool {
		return api.Get(ctx, "/api/v1/licenses?verdict=denied", &lic) == nil && len(lic) == 1
	})
	if lic[0].Package != "readline" {
		t.Fatalf("readline GPL should be denied: %+v", lic)
	}
	var posture []domain.PostureViolation
	if err := api.Get(ctx, "/api/v1/posture", &posture); err != nil || len(posture) == 0 {
		t.Fatalf("posture: %v %d", err, len(posture))
	}

	// 3. The summary (the web UI's landing data; its proxy is tested in gjallar-web).
	var sum app.Summary
	if err := api.Get(ctx, "/api/v1/summary", &sum); err != nil || sum.OpenFindings != 2 || sum.KEV != 1 {
		t.Fatalf("summary: %+v %v", sum, err)
	}

	// 4. MCP: tools/call top_risks.
	mc := client.New(mcpURL, "")
	var rpc struct {
		Result struct {
			Content []struct{ Text string } `json:"content"`
		} `json:"result"`
	}
	if err := mc.Post(ctx, "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "top_risks", "arguments": map[string]any{"band": "urgent"}}}, &rpc); err != nil {
		t.Fatal(err)
	}
	if len(rpc.Result.Content) == 0 || !strings.Contains(rpc.Result.Content[0].Text, "CVE-2023-4863") {
		t.Fatalf("mcp top_risks: %+v", rpc)
	}

	// 5. Copa patch flow (fake copa, real worker).
	var pr map[string]any
	if err := api.Post(ctx, "/api/v1/images/"+digest+"/patch", map[string]any{}, &pr); err != nil {
		t.Fatal(err)
	}
	var patches []app.PatchView
	waitFor(t, ctx, "patch done", func() bool {
		return api.Get(ctx, "/api/v1/patches", &patches) == nil && len(patches) > 0 && patches[0].Status != "queued"
	})
	if patches[0].Status != "done" || !strings.HasSuffix(patches[0].PatchedRef, ":1.0-patched") {
		t.Fatalf("patch: %+v", patches[0])
	}

	// 5b. Kyverno-style admission check by tag: KEV image must be denied.
	var adm map[string]any
	if err := api.Get(ctx, "/api/v1/admission?image=harbor.local/shop/web:1.0", &adm); err != nil || adm["allowed"] != false {
		t.Fatalf("admission: %+v %v", adm, err)
	}
	t.Logf("admission: %v", adm["reason"])

	// 6. Accept a risk → VEX document.
	if err := api.Post(ctx, "/api/v1/findings/"+fs[1].ID+"/accept", map[string]string{"reason": "openssl path not reachable in this service"}, nil); err != nil {
		t.Fatal(err)
	}
	var vex map[string]any
	if err := api.Get(ctx, "/api/v1/images/"+digest+"/vex", &vex); err != nil || len(vex["statements"].([]any)) != 1 {
		t.Fatalf("vex: %+v %v", vex, err)
	}

	// 7. Rematch (DB update path) keeps the accepted state.
	if err := api.Post(ctx, "/api/v1/rematch", map[string]any{}, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	var accepted []app.FindingView
	if err := api.Get(ctx, "/api/v1/findings?state=accepted", &accepted); err != nil || len(accepted) != 1 {
		t.Fatalf("accepted must survive rematch: %d %v", len(accepted), err)
	}

	// 8. Analytics through the API proxy: DuckDB over Parquet.
	var rows []map[string]any
	waitFor(t, ctx, "analytics rows", func() bool {
		rows = nil
		return api.Post(ctx, "/api/v1/analytics/query", map[string]string{"sql": "SELECT vuln_id, max(risk) AS risk FROM finding_events GROUP BY vuln_id ORDER BY risk DESC"}, &rows) == nil && len(rows) == 2
	})
	if rows[0]["vuln_id"] != "CVE-2023-4863" {
		t.Fatalf("analytics order: %+v", rows)
	}
	var kev []map[string]any
	if err := api.Get(ctx, "/api/v1/analytics/reports/kev_exposure", &kev); err != nil || len(kev) != 1 {
		t.Fatalf("kev report: %+v %v", kev, err)
	}
	// 8b. Lakehouse tables from the design: SBOM packages, scores with inputs, runtime history.
	if err := bus.Publish(ctx, domain.SubjRuntime, domain.RuntimeObserved{Digest: domain.Digest(digest), Packages: []string{"libwebp7"}, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"SELECT package FROM sbom_packages WHERE package = 'libwebp7'",
		"SELECT vuln_id, runtime, fix_available FROM risk_scores WHERE vuln_id = 'CVE-2023-4863' AND fix_available",
		"SELECT package FROM runtime_loaded WHERE package = 'libwebp7'",
		"SELECT path FROM audit_events WHERE method = 'POST' AND path LIKE '%/accept' AND status = 200",
	} {
		waitFor(t, ctx, q, func() bool {
			rows = nil
			return api.Post(ctx, "/api/v1/analytics/query", map[string]string{"sql": q}, &rows) == nil && len(rows) > 0
		})
	}
	// 8c. Arrow Flight SQL against the real lakehouse (DuckDB → Parquet → Arrow).
	if addr := os.Getenv("GJALLAR_FLIGHT"); addr != "" {
		cl, err := flightsql.NewClient(addr, nil, nil, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		info, err := cl.Execute(ctx, "SELECT vuln_id, max(risk) AS risk FROM finding_events GROUP BY vuln_id ORDER BY risk DESC")
		if err != nil {
			t.Fatalf("flight sql: %v", err)
		}
		rdr, err := cl.DoGet(ctx, info.Endpoint[0].Ticket)
		if err != nil {
			t.Fatal(err)
		}
		if !rdr.Next() || rdr.Record().NumRows() != 2 || rdr.Record().Column(0).(*array.String).Value(0) != "CVE-2023-4863" {
			t.Fatalf("flight sql rows: %v", rdr.Record())
		}
		rdr.Release()
		cl.Close()
	}
	// 8d. Freedom of data: the SBOM in open standard formats.
	for f, want := range map[string]string{"cyclonedx-json": "bomFormat", "spdx-json": "spdxVersion", "": "artifacts"} {
		var doc map[string]any
		if err := api.Get(ctx, "/api/v1/images/"+digest+"/sbom?format="+f, &doc); err != nil || doc[want] == nil {
			t.Fatalf("sbom %q: %v (keys %d)", f, err, len(doc))
		}
	}
	var effect []map[string]any
	if err := api.Get(ctx, "/api/v1/analytics/reports/runtime_effect", &effect); err != nil || len(effect) == 0 {
		t.Fatalf("runtime_effect report: %+v %v", effect, err)
	}
	var bad json.RawMessage
	if err := api.Post(ctx, "/api/v1/analytics/query", map[string]string{"sql": "DROP TABLE finding_events"}, &bad); err == nil {
		t.Fatal("write SQL must be rejected")
	}
	// 9. Notification: one Slack-format message for the urgent KEV finding, sent once.
	if os.Getenv("GJALLAR_E2E_HOOK") != "" {
		select {
		case msg := <-hooks:
			if !strings.Contains(msg, "CVE-2023-4863 [KEV]") || strings.Contains(msg, "CVE-2099-0001") {
				t.Fatalf("notification: %s", msg)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("no notification received")
		}
		select {
		case msg := <-hooks:
			t.Fatalf("duplicate notification after rematch/rescoring: %s", msg)
		case <-time.After(3 * time.Second):
		}
	}
	t.Log("end-to-end OK")
}

func waitFor(t *testing.T, ctx context.Context, what string, cond func() bool) {
	t.Helper()
	for {
		if cond() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s", what)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// A job that runs longer than any retry delay must run once, not again in
// parallel (regression: consumer BackOff replaced AckWait as the redelivery timeout).
func TestLongJobDeliveredOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bus, err := natsbus.Connect(ctx, env("GJALLAR_NATS_URL", "nats://127.0.0.1:54222"), "e2e-long", telemetry.NewLogger("e2e"))
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	const subj = "gjallar.jobs.e2e-long"
	var runs atomic.Int32
	done := make(chan struct{})
	cctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		_ = bus.Consume(cctx, natsbus.ConsumeOpts{Stream: natsbus.StreamJobs, Durable: "e2e-long", Subjects: []string{subj}, AckWait: 30 * time.Second, MaxDeliver: 4},
			func(context.Context, []byte) error {
				if runs.Add(1) == 1 {
					time.Sleep(20 * time.Second) // longer than the old 10 s first BackOff step
					close(done)
				}
				return nil
			})
	}()
	time.Sleep(time.Second)
	if err := bus.Publish(ctx, subj, map[string]string{"job": "long"}); err != nil {
		t.Fatal(err)
	}
	<-done
	time.Sleep(2 * time.Second)
	if n := runs.Load(); n != 1 {
		t.Fatalf("long job ran %d times, want 1", n)
	}
	_ = bus.JS.DeleteConsumer(ctx, natsbus.StreamJobs, "e2e-long")
}
