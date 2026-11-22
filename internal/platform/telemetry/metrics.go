// Package telemetry provides structured logging, Prometheus-format metrics
// and OTLP/HTTP tracing with the standard library only, keeping every
// Gjallar binary small. Point OTEL_EXPORTER_OTLP_ENDPOINT at an OpenTelemetry
// Collector or straight at Grafana Tempo.
package telemetry

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
)

// NewLogger returns a JSON logger at the level in GJALLAR_LOG_LEVEL.
func NewLogger(service string) *slog.Logger {
	lvl := slog.LevelInfo
	switch strings.ToLower(os.Getenv("GJALLAR_LOG_LEVEL")) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})).With("service", service)
}

// CounterVec is a labelled monotonic counter.
type CounterVec struct {
	name, help string
	labels     []string
	mu         sync.Mutex
	vals       map[string]float64
}

// GaugeVec is a labelled gauge.
type GaugeVec struct{ CounterVec }

var (
	regMu    sync.Mutex
	counters []*CounterVec
	gauges   []*GaugeVec
)

// NewCounter registers a counter.
func NewCounter(name, help string, labels ...string) *CounterVec {
	c := &CounterVec{name: name, help: help, labels: labels, vals: map[string]float64{}}
	regMu.Lock()
	counters = append(counters, c)
	regMu.Unlock()
	return c
}

// NewGauge registers a gauge.
func NewGauge(name, help string, labels ...string) *GaugeVec {
	g := &GaugeVec{CounterVec{name: name, help: help, labels: labels, vals: map[string]float64{}}}
	regMu.Lock()
	gauges = append(gauges, g)
	regMu.Unlock()
	return g
}

// Inc adds one for the label values.
func (c *CounterVec) Inc(lv ...string) { c.Add(1, lv...) }

// Add adds v for the label values.
func (c *CounterVec) Add(v float64, lv ...string) {
	c.mu.Lock()
	c.vals[strings.Join(lv, "\xff")] += v
	c.mu.Unlock()
}

// Set sets a gauge value.
func (g *GaugeVec) Set(v float64, lv ...string) {
	g.mu.Lock()
	g.vals[strings.Join(lv, "\xff")] = v
	g.mu.Unlock()
}

// Reset clears all series of a gauge (before re-publishing a snapshot).
func (g *GaugeVec) Reset() {
	g.mu.Lock()
	g.vals = map[string]float64{}
	g.mu.Unlock()
}

func (c *CounterVec) write(b *strings.Builder, typ string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", c.name, c.help, c.name, typ)
	keys := make([]string, 0, len(c.vals))
	for k := range c.vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(c.name)
		if len(c.labels) > 0 {
			parts := strings.Split(k, "\xff")
			b.WriteByte('{')
			for i, l := range c.labels {
				if i > 0 {
					b.WriteByte(',')
				}
				v := ""
				if i < len(parts) {
					v = parts[i]
				}
				fmt.Fprintf(b, "%s=%q", l, v)
			}
			b.WriteByte('}')
		}
		fmt.Fprintf(b, " %g\n", c.vals[k])
	}
}

// MetricsHandler serves all registered metrics in Prometheus text format.
func MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var b strings.Builder
		regMu.Lock()
		cs, gs := append([]*CounterVec(nil), counters...), append([]*GaugeVec(nil), gauges...)
		regMu.Unlock()
		for _, c := range cs {
			c.write(&b, "counter")
		}
		for _, g := range gs {
			g.write(&b, "gauge")
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(b.String()))
	})
}

// Shared metrics used across services.
var (
	Jobs         = NewCounter("gjallar_messages_total", "Messages processed by consumer and outcome", "consumer", "outcome")
	HTTPRequests = NewCounter("gjallar_http_requests_total", "HTTP requests by route and status class", "route", "code")
	Findings     = NewGauge("gjallar_open_findings", "Open findings by risk band", "band")
	KEVFindings  = NewGauge("gjallar_open_kev_findings", "Open findings listed in CISA KEV")
	Images       = NewGauge("gjallar_images", "Images known to Gjallar")
	Posture      = NewGauge("gjallar_posture_violations", "Posture violations on running workloads")
	LicDenied    = NewGauge("gjallar_licenses_denied", "Package licenses denied by policy")

	// Metering: who uses Gjallar and what it costs to run.
	APIUsage      = NewCounter("gjallar_api_requests_by_client_total", "Authenticated API requests by OIDC client (web, cli, mcp), user and kind", "client", "user", "kind")
	EngineRuns    = NewCounter("gjallar_engine_runs_total", "Engine subprocess runs (syft, grype, copa, trivy, grant)", "engine", "outcome")
	EngineSeconds = NewCounter("gjallar_engine_seconds_total", "Wall-clock seconds spent in engine subprocesses", "engine")
	NSImages      = NewGauge("gjallar_namespace_images", "Distinct images running per namespace", "namespace")
	NSWorkloads   = NewGauge("gjallar_namespace_workloads", "Workloads per namespace", "namespace")
	NSFindings    = NewGauge("gjallar_namespace_open_findings", "Open findings per namespace and risk band", "namespace", "band")
)
