package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// A tiny OpenTelemetry-compatible tracer. It speaks W3C traceparent for
// propagation (HTTP and NATS headers) and exports OTLP/HTTP JSON, which
// both the OpenTelemetry Collector and Grafana Tempo accept on /v1/traces.

type spanCtxKey struct{}

type spanContext struct {
	TraceID, SpanID string
}

// Span is an in-flight span.
type Span struct {
	name, traceID, spanID, parentID string
	start                           time.Time
	attrs                           map[string]string
}

var exporter = newExporter()

// Start begins a span as a child of whatever is in ctx.
func Start(ctx context.Context, name string, kv ...string) (context.Context, *Span) {
	parent, _ := ctx.Value(spanCtxKey{}).(spanContext)
	s := &Span{name: name, traceID: parent.TraceID, parentID: parent.SpanID, spanID: randHex(8), start: time.Now(), attrs: map[string]string{}}
	if s.traceID == "" {
		s.traceID = randHex(16)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		s.attrs[kv[i]] = kv[i+1]
	}
	return context.WithValue(ctx, spanCtxKey{}, spanContext{s.traceID, s.spanID}), s
}

// End finishes the span and queues it for export.
func (s *Span) End(err error) {
	if s == nil || exporter == nil {
		return
	}
	exporter.add(s, time.Now(), err)
}

// Header is the subset of http.Header / nats.Header we need.
type Header interface {
	Get(string) string
	Set(string, string)
}

// Inject writes traceparent into headers.
func Inject(ctx context.Context, h Header) {
	if sc, ok := ctx.Value(spanCtxKey{}).(spanContext); ok && sc.TraceID != "" {
		h.Set("traceparent", "00-"+sc.TraceID+"-"+sc.SpanID+"-01")
	}
}

// Extract reads traceparent from headers into ctx.
func Extract(ctx context.Context, h Header) context.Context {
	if h == nil {
		return ctx
	}
	p := strings.Split(h.Get("traceparent"), "-")
	if len(p) == 4 && len(p[1]) == 32 && len(p[2]) == 16 {
		return context.WithValue(ctx, spanCtxKey{}, spanContext{p[1], p[2]})
	}
	return ctx
}

// TraceID returns the current trace ID for log correlation.
func TraceID(ctx context.Context) string {
	sc, _ := ctx.Value(spanCtxKey{}).(spanContext)
	return sc.TraceID
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type finished struct {
	s   *Span
	end time.Time
	err error
}

type otlpExporter struct {
	url, service string
	mu           sync.Mutex
	buf          []finished
	client       *http.Client
}

func newExporter() *otlpExporter {
	ep := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	if ep == "" {
		if base := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); base != "" {
			ep = strings.TrimSuffix(base, "/") + "/v1/traces"
		}
	}
	if ep == "" {
		return nil // tracing disabled
	}
	svc := os.Getenv("OTEL_SERVICE_NAME")
	if svc == "" {
		svc = "gjallar"
	}
	e := &otlpExporter{url: ep, service: svc, client: &http.Client{Timeout: 5 * time.Second}}
	go e.loop()
	return e
}

func (e *otlpExporter) add(s *Span, end time.Time, err error) {
	e.mu.Lock()
	e.buf = append(e.buf, finished{s, end, err})
	full := len(e.buf) >= 256
	e.mu.Unlock()
	if full {
		go e.flush()
	}
}

func (e *otlpExporter) loop() {
	for range time.Tick(5 * time.Second) {
		e.flush()
	}
}

// Flush exports pending spans now (call before exit).
func Flush() {
	if exporter != nil {
		exporter.flush()
	}
}

func (e *otlpExporter) flush() {
	e.mu.Lock()
	batch := e.buf
	e.buf = nil
	e.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	type kv struct {
		Key   string            `json:"key"`
		Value map[string]string `json:"value"`
	}
	attr := func(k, v string) kv { return kv{k, map[string]string{"stringValue": v}} }
	spans := make([]map[string]any, 0, len(batch))
	for _, f := range batch {
		var attrs []kv
		for k, v := range f.s.attrs {
			attrs = append(attrs, attr(k, v))
		}
		status := map[string]any{"code": 1}
		if f.err != nil {
			status = map[string]any{"code": 2, "message": f.err.Error()}
		}
		sp := map[string]any{
			"traceId": f.s.traceID, "spanId": f.s.spanID, "name": f.s.name, "kind": 1,
			"startTimeUnixNano": f.s.start.UnixNano(), "endTimeUnixNano": f.end.UnixNano(),
			"attributes": attrs, "status": status,
		}
		if f.s.parentID != "" {
			sp["parentSpanId"] = f.s.parentID
		}
		spans = append(spans, sp)
	}
	body, _ := json.Marshal(map[string]any{"resourceSpans": []any{map[string]any{
		"resource":   map[string]any{"attributes": []kv{attr("service.name", e.service)}},
		"scopeSpans": []any{map[string]any{"scope": map[string]string{"name": "gjallar"}, "spans": spans}},
	}}})
	req, err := http.NewRequest(http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if resp, err := e.client.Do(req); err == nil {
		resp.Body.Close()
	}
}
