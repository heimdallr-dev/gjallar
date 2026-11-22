// gjallar-agent runs once per cluster. It reads running workloads from the
// Kubernetes API and publishes them to the hub over NATS (outbound only;
// use a NATS leaf node for remote clusters). It never scans anything itself.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/adapters/gadget"
	"github.com/heimdallr-dev/gjallar/internal/adapters/k8s"
	"github.com/heimdallr-dev/gjallar/internal/adapters/natsbus"
	"github.com/heimdallr-dev/gjallar/internal/adapters/rego"
	"github.com/heimdallr-dev/gjallar/internal/adapters/scanner"
	"github.com/heimdallr-dev/gjallar/internal/app"
	"github.com/heimdallr-dev/gjallar/internal/domain"
	"github.com/heimdallr-dev/gjallar/internal/platform/httpx"
	"github.com/heimdallr-dev/gjallar/internal/platform/telemetry"
)

var version = "dev"

var (
	published = telemetry.NewCounter("gjallar_agent_workloads_published_total", "Workloads published to the hub")
	errorsC   = telemetry.NewCounter("gjallar_agent_errors_total", "Inventory errors")
)

func main() {
	log := telemetry.NewLogger("gjallar-agent").With("version", version)
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, cancel := httpx.SignalContext()
	defer cancel()
	cluster := httpx.Env("GJALLAR_CLUSTER", "default")
	interval, err := time.ParseDuration(httpx.Env("GJALLAR_INTERVAL", "5m"))
	if err != nil {
		return err
	}
	skip := map[string]bool{}
	for _, ns := range strings.Split(httpx.Env("GJALLAR_SKIP_NAMESPACES", "kube-system"), ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			skip[ns] = true
		}
	}
	kc, err := k8s.InCluster()
	if err != nil {
		return err
	}
	bus, err := natsbus.Connect(ctx, httpx.Env("GJALLAR_NATS_URL", "nats://localhost:4222"), "gjallar-agent-"+cluster, log)
	if err != nil {
		return err
	}
	defer bus.Close()

	go func() {
		_ = httpx.Serve(ctx, log, httpx.Env("GJALLAR_HTTP_ADDR", ":9090"), telemetry.MetricsHandler())
	}()

	if httpx.Env("GJALLAR_RUNTIME_GADGET", "") == "true" {
		rt, err := bus.Runtime(ctx)
		if err != nil {
			return err
		}
		go runtimeLoop(ctx, log, &app.RuntimeRecorder{Digests: kc, SBOMs: bus, Store: rt, Index: scanner.FileOwners, Bus: bus, Log: log})
	}

	var policy *rego.Engine
	if dir := os.Getenv("GJALLAR_REGOLIBRARY"); dir != "" {
		if policy, err = rego.Load(ctx, httpx.Env("GJALLAR_OPA_BIN", "opa"), dir); err != nil {
			return fmt.Errorf("regolibrary: %w", err)
		}
		log.Info("regolibrary controls on", "rules", policy.Rules, "dropped", len(policy.Dropped))
	}

	log.Info("agent started", "cluster", cluster, "interval", interval.String())
	for {
		ws, err := kc.Collect(ctx, cluster, skip)
		if err == nil && policy != nil {
			if objs, owners, perr := kc.RawObjects(ctx, skip); perr != nil {
				log.Warn("regolibrary: list objects", "err", perr)
			} else if rs, perr := policy.Evaluate(ctx, objs); perr != nil {
				errorsC.Inc()
				log.Warn("regolibrary: evaluate", "err", perr)
			} else {
				attachPosture(ws, rs, owners)
			}
		}
		if err != nil {
			errorsC.Inc()
			log.Error("inventory failed", "err", err)
		} else {
			n := 0
			for _, w := range ws {
				if err := bus.Publish(ctx, domain.SubjInventory, w); err != nil {
					errorsC.Inc()
					log.Error("publish failed", "workload", w.ID(), "err", err)
					continue
				}
				n++
			}
			published.Add(float64(n))
			log.Info("inventory published", "workloads", n)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

var runtimeRecorded = telemetry.NewCounter("gjallar_agent_runtime_images_updated_total", "Image digests whose loaded-package set grew")

// runtimeLoop streams Inspektor Gadget trace_open events (restarting the
// gadget if it exits) and flushes them to the runtime KV periodically.
func runtimeLoop(ctx context.Context, log *slog.Logger, rec *app.RuntimeRecorder) {
	bin := httpx.Env("GJALLAR_GADGET_BIN", "kubectl-gadget")
	image := httpx.Env("GJALLAR_GADGET_IMAGE", "trace_open:v0.58.0")
	every, err := time.ParseDuration(httpx.Env("GJALLAR_RUNTIME_FLUSH", "1m"))
	if err != nil {
		every = time.Minute
	}
	go func() {
		for ctx.Err() == nil {
			err := gadget.Stream(ctx, bin, image, func(o gadget.Open) { rec.Observe(o.Namespace, o.Pod, o.Container, o.Path) })
			if ctx.Err() != nil {
				return
			}
			errorsC.Inc()
			log.Error("gadget stopped, restarting in 30s", "err", err)
			select {
			case <-ctx.Done():
			case <-time.After(30 * time.Second):
			}
		}
	}()
	log.Info("runtime observation on", "gadget", image, "flush", every.String())
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
		n, err := rec.Flush(ctx)
		if err != nil {
			errorsC.Inc()
			log.Warn("runtime flush", "err", err)
		}
		if n > 0 {
			runtimeRecorded.Add(float64(n))
			log.Info("runtime packages recorded", "images", n)
		}
	}
}

// attachPosture adds regolibrary results to the workloads they belong to,
// once per control and message (replicas of one workload report alike).
func attachPosture(ws []domain.Workload, rs []rego.Result, owners map[string]string) {
	idx := map[string]int{}
	for i, w := range ws {
		idx[w.Namespace+"/"+w.Kind+"/"+w.Name] = i
	}
	seen := map[string]bool{}
	for _, r := range rs {
		o, ok := owners[r.Kind+"/"+r.Namespace+"/"+r.Name]
		if !ok {
			continue
		}
		i, ok := idx[r.Namespace+"/"+o]
		if !ok {
			continue
		}
		key := ws[i].ID() + "|" + r.ControlID + "|" + r.Message
		if seen[key] {
			continue
		}
		seen[key] = true
		ws[i].ExternalPosture = append(ws[i].ExternalPosture, domain.PostureViolation{
			WorkloadID: ws[i].ID(), CheckID: r.ControlID, Severity: r.Severity, Message: r.Message})
	}
}
