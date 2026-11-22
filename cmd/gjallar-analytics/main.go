// gjallar-analytics turns Gjallar's event stream into a DuckDB/Parquet
// lakehouse (DuckLake) and serves read-only SQL, curated reports and Parquet
// exports.
//
//	gjallar-analytics serve     # writer (NATS → Parquet) + query API
//	gjallar-analytics maintain  # daily snapshot + compaction (CronJob)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/adapters/analytics"
	"github.com/heimdallr-dev/gjallar/internal/adapters/flightsql"
	"github.com/heimdallr-dev/gjallar/internal/adapters/natsbus"
	"github.com/heimdallr-dev/gjallar/internal/adapters/oidc"
	"github.com/heimdallr-dev/gjallar/internal/adapters/scanner"
	"github.com/heimdallr-dev/gjallar/internal/app"
	"github.com/heimdallr-dev/gjallar/internal/domain"
	"github.com/heimdallr-dev/gjallar/internal/platform/httpx"
	"github.com/heimdallr-dev/gjallar/internal/platform/telemetry"
)

var version = "dev"

var rowsWritten = telemetry.NewCounter("gjallar_analytics_rows_total", "Rows written to the lakehouse", "table")

func main() {
	log := telemetry.NewLogger("gjallar-analytics").With("version", version)
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	store, err := analytics.New(analytics.Config{
		Bin: httpx.Env("GJALLAR_DUCKDB_BIN", "duckdb"), Mode: httpx.Env("GJALLAR_LAKE_MODE", "parquet"),
		Catalog: os.Getenv("GJALLAR_LAKE_CATALOG"), DataPath: httpx.Env("GJALLAR_LAKE_DATA", "/data/lake/"),
		S3Endpoint: os.Getenv("GJALLAR_S3_ENDPOINT"), S3Region: os.Getenv("GJALLAR_S3_REGION"),
		S3KeyID: os.Getenv("GJALLAR_S3_ACCESS_KEY"), S3Secret: os.Getenv("GJALLAR_S3_SECRET_KEY"),
		S3UseSSL: httpx.EnvBool("GJALLAR_S3_USE_SSL", false),
	})
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	ctx, cancel := httpx.SignalContext()
	defer cancel()
	if err := store.Init(ctx); err != nil {
		log.Error("init lakehouse", "err", err)
		os.Exit(1)
	}
	switch cmd {
	case "serve":
		err = serve(ctx, log, store)
	case "maintain":
		retain, _ := time.ParseDuration(httpx.Env("GJALLAR_LAKE_RETAIN", "720h"))
		err = store.Maintain(ctx, retain)
		if err == nil {
			log.Info("maintenance done")
		}
	default:
		err = fmt.Errorf("unknown command %q (serve|maintain)", cmd)
	}
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// writer batches events per table and flushes them as Parquet.
type writer struct {
	store *analytics.Store
	log   *slog.Logger
	mu    sync.Mutex
	rows  map[string][]map[string]any
	ns    map[domain.Digest][]string // digest → namespaces, from inventory
}

func (w *writer) add(table string, rs ...map[string]any) {
	w.mu.Lock()
	w.rows[table] = append(w.rows[table], rs...)
	w.mu.Unlock()
}

func (w *writer) flush(ctx context.Context) {
	w.mu.Lock()
	batch := w.rows
	w.rows = map[string][]map[string]any{}
	w.mu.Unlock()
	for table, rs := range batch {
		if err := w.store.Append(ctx, table, rs); err != nil {
			w.log.Error("append failed; re-queueing", "table", table, "rows", len(rs), "err", err)
			w.add(table, rs...)
			continue
		}
		rowsWritten.Add(float64(len(rs)), table)
	}
}

func row(at time.Time, kv map[string]any) map[string]any {
	kv["ts"] = at.UTC().Format(time.RFC3339Nano)
	kv["day"] = at.UTC().Format("2006-01-02")
	return kv
}

// riskRow keeps a score with its inputs, so trends can be explained later.
func riskRow(ev domain.FindingsScored, f domain.Finding) map[string]any {
	runtime, exposed, fix := "unknown", false, false
	for _, r := range f.Risk.Reasons {
		switch r {
		case domain.ReasonLoaded:
			runtime = "loaded"
		case domain.ReasonNeverLoaded:
			runtime = "not_loaded"
		case domain.ReasonExposed:
			exposed = true
		case domain.ReasonFix:
			fix = true
		}
	}
	return row(ev.At, map[string]any{"id": f.ID, "digest": string(ev.Digest), "repository": ev.Repository, "vuln_id": f.VulnID,
		"package": f.Package, "risk": f.Risk.Value, "band": string(f.Risk.Band), "cvss": f.CVSS, "epss": f.EPSS, "kev": f.KEV,
		"runtime": runtime, "exposed": exposed, "fix_available": fix, "reasons": append([]string{}, f.Risk.Reasons...)})
}

func ts(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func serve(ctx context.Context, log *slog.Logger, store *analytics.Store) error {
	bus, err := natsbus.Connect(ctx, httpx.Env("GJALLAR_NATS_URL", "nats://localhost:4222"), "gjallar-analytics", log)
	if err != nil {
		return err
	}
	defer bus.Close()
	w := &writer{store: store, log: log, rows: map[string][]map[string]any{}, ns: map[domain.Digest][]string{}}

	handlers := map[string]natsbus.Handler{
		domain.SubjInventory: natsbus.JSON(func(_ context.Context, wl domain.Workload) error {
			for _, c := range wl.Containers {
				w.add("workload_images", row(wl.LastSeen, map[string]any{"cluster": wl.Cluster, "namespace": wl.Namespace, "kind": wl.Kind,
					"name": wl.Name, "container": c.Name, "repository": c.Image.Repository, "tag": c.Image.Tag, "digest": string(c.Image.Digest), "exposed": wl.Exposed}))
				if c.Image.Digest != "" {
					w.mu.Lock()
					w.ns[c.Image.Digest] = appendUnique(w.ns[c.Image.Digest], wl.Namespace)
					w.mu.Unlock()
				}
			}
			return nil
		}),
		domain.SubjScored: natsbus.JSON(func(_ context.Context, ev domain.FindingsScored) error {
			w.mu.Lock()
			ns := append([]string{}, w.ns[ev.Digest]...)
			w.mu.Unlock()
			for _, f := range ev.Findings {
				w.add("risk_scores", riskRow(ev, f))
				first := f.FirstSeen
				w.add("finding_events", row(ev.At, map[string]any{"id": f.ID, "digest": string(ev.Digest), "repository": ev.Repository,
					"namespaces": ns, "vuln_id": f.VulnID, "package": f.Package, "version": f.Version, "pkg_type": f.PkgType,
					"severity": f.Severity.String(), "cvss": f.CVSS, "epss": f.EPSS, "kev": f.KEV, "fixed_in": f.FixedIn,
					"risk": f.Risk.Value, "band": string(f.Risk.Band), "state": string(f.State),
					"first_seen": ts(&first), "fixed_at": ts(f.FixedAt), "db_version": ev.DBVersion, "source": f.Source}))
			}
			return nil
		}),
		domain.SubjLicDone: natsbus.JSON(func(_ context.Context, ev domain.LicensesEvaluated) error {
			for _, l := range ev.Results {
				w.add("package_licenses", row(ev.At, map[string]any{"digest": string(ev.Digest), "package": l.Package,
					"version": l.Version, "license": l.License, "verdict": string(l.Verdict)}))
			}
			return nil
		}),
		domain.SubjPosture: natsbus.JSON(func(_ context.Context, ev domain.PostureEvaluated) error {
			ns := ""
			if parts := strings.Split(ev.WorkloadID, "/"); len(parts) > 1 {
				ns = parts[1]
			}
			for _, v := range ev.Violations {
				w.add("posture_events", row(ev.At, map[string]any{"workload_id": ev.WorkloadID, "namespace": ns, "check_id": v.CheckID,
					"severity": v.Severity.String(), "container": v.Container, "message": v.Message}))
			}
			return nil
		}),
		domain.SubjSBOMDone: natsbus.JSON(func(ctx context.Context, ev domain.SBOMGenerated) error {
			if ev.Error != "" {
				return nil
			}
			raw, err := bus.Get(ctx, ev.Digest)
			if errors.Is(err, app.ErrNotFound) {
				return nil // SBOM evicted; nothing to record
			}
			if err != nil {
				return err
			}
			sb, err := scanner.ParseSyftJSON(raw)
			if err != nil {
				return err
			}
			for _, p := range sb.Packages {
				w.add("sbom_packages", row(ev.At, map[string]any{"digest": string(ev.Digest), "repository": ev.Image.Repository,
					"package": p.Name, "version": p.Version, "pkg_type": p.Type, "purl": p.PURL}))
			}
			return nil
		}),
		domain.SubjAudit: natsbus.JSON(func(_ context.Context, ev domain.AuditEvent) error {
			w.add("audit_events", row(ev.At, map[string]any{"user": ev.User, "client": ev.Client, "method": ev.Method, "path": ev.Path, "status": ev.Status}))
			return nil
		}),
		domain.SubjRuntime: natsbus.JSON(func(_ context.Context, ev domain.RuntimeObserved) error {
			for _, p := range ev.Packages {
				w.add("runtime_loaded", row(ev.At, map[string]any{"digest": string(ev.Digest), "package": p}))
			}
			return nil
		}),
		domain.SubjPatchDone: natsbus.JSON(func(_ context.Context, ev domain.PatchResult) error {
			w.add("patch_events", row(ev.At, map[string]any{"digest": string(ev.Digest), "patched_ref": ev.PatchedRef, "fixed": ev.Fixed, "error": ev.Error}))
			return nil
		}),
	}
	for subj, h := range handlers {
		durable := "analytics-" + strings.ReplaceAll(strings.TrimPrefix(subj, "gjallar."), ".", "-")
		go func(subj, durable string, h natsbus.Handler) {
			if err := bus.Consume(ctx, natsbus.ConsumeOpts{Stream: natsbus.StreamEvents, Durable: durable, Subjects: []string{subj}, AckWait: time.Minute, Parallel: 4}, h); err != nil {
				log.Error("consumer stopped", "durable", durable, "err", err)
			}
		}(subj, durable, h)
	}

	flushEvery, _ := time.ParseDuration(httpx.Env("GJALLAR_LAKE_FLUSH", "30s"))
	go func() {
		t := time.NewTicker(flushEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				w.flush(context.Background())
				return
			case <-t.C:
				w.flush(ctx)
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(rw http.ResponseWriter, _ *http.Request) { httpx.JSON(rw, 200, map[string]string{"status": "ok"}) })
	mux.Handle("GET /metrics", telemetry.MetricsHandler())
	mux.HandleFunc("GET /api/v1/analytics/reports", func(rw http.ResponseWriter, _ *http.Request) {
		names := make([]string, 0, len(analytics.Reports))
		for k := range analytics.Reports {
			names = append(names, k)
		}
		httpx.JSON(rw, 200, map[string]any{"reports": names, "tables": tableNames()})
	})
	mux.HandleFunc("GET /api/v1/analytics/reports/{name}", func(rw http.ResponseWriter, r *http.Request) {
		rows, err := store.Report(r.Context(), r.PathValue("name"))
		if err != nil {
			httpx.Error(rw, 400, err.Error())
			return
		}
		httpx.JSON(rw, 200, rows)
	})
	mux.HandleFunc("POST /api/v1/analytics/query", func(rw http.ResponseWriter, r *http.Request) {
		var body struct {
			SQL     string `json:"sql"`
			MaxRows int    `json:"max_rows"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			httpx.Error(rw, 400, `body must be {"sql": "SELECT ..."}`)
			return
		}
		rows, err := store.Query(r.Context(), body.SQL, body.MaxRows)
		if err != nil {
			httpx.Error(rw, 400, err.Error())
			return
		}
		httpx.JSON(rw, 200, rows)
	})
	mux.HandleFunc("POST /api/v1/analytics/export", func(rw http.ResponseWriter, r *http.Request) {
		var body struct {
			SQL string `json:"sql"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			httpx.Error(rw, 400, `body must be {"sql": "SELECT ..."}`)
			return
		}
		dir, err := os.MkdirTemp("", "gjallar-export-")
		if err != nil {
			httpx.Error(rw, 500, err.Error())
			return
		}
		defer os.RemoveAll(dir)
		path := filepath.Join(dir, "export.parquet")
		if err := store.ExportParquet(r.Context(), body.SQL, path); err != nil {
			httpx.Error(rw, 400, err.Error())
			return
		}
		rw.Header().Set("Content-Type", "application/vnd.apache.parquet")
		rw.Header().Set("Content-Disposition", `attachment; filename="gjallar-export.parquet"`)
		http.ServeFile(rw, r, path)
	})
	if addr := httpx.Env("GJALLAR_FLIGHT_ADDR", ":8815"); addr != "off" {
		fsrv := flightsql.New(store.ExportParquet, os.TempDir())
		fsrv.Validate = analytics.ValidateQuery
		go func() {
			if err := flightsql.Serve(ctx, addr, fsrv, flightAuth(log)); err != nil && ctx.Err() == nil {
				log.Error("flight sql stopped", "err", err)
			}
		}()
		log.Info("flight sql listening", "addr", addr)
	}
	return httpx.Serve(ctx, log, httpx.Env("GJALLAR_HTTP_ADDR", ":8081"), httpx.Observe(log, mux))
}

func tableNames() []string {
	out := make([]string, len(analytics.Tables))
	for i, t := range analytics.Tables {
		out[i] = t.Name
	}
	return out
}

func appendUnique(xs []string, x string) []string {
	for _, v := range xs {
		if v == x {
			return xs
		}
	}
	return append(xs, x)
}

// flightAuth: with an issuer configured, Flight SQL needs a valid token with a
// fleet-wide role (same rule as the analytics API: raw SQL sees all namespaces).
func flightAuth(log *slog.Logger) flightsql.Authorizer {
	issuer := os.Getenv("GJALLAR_OIDC_ISSUER")
	if issuer == "" {
		log.Warn("GJALLAR_OIDC_ISSUER not set: Flight SQL is unauthenticated (dev only)")
		return nil
	}
	v := oidc.NewVerifier(issuer, httpx.Env("GJALLAR_OIDC_CLIENT_ID", "gjallar"))
	roles := strings.Split(httpx.Env("GJALLAR_FLIGHT_ROLES", httpx.Env("GJALLAR_OIDC_ADMIN_ROLE", "gjallar-admin")), ",")
	return func(ctx context.Context, bearer string) error {
		p, err := v.Verify(ctx, bearer)
		if err != nil {
			return err
		}
		for _, r := range roles {
			if p.HasRole(r) {
				return nil
			}
		}
		return fmt.Errorf("needs one of roles %v", roles)
	}
}
