// Package mcp exposes Gjallar to AI assistants over the Model Context
// Protocol (Streamable HTTP transport, JSON responses). Every tool call is
// forwarded to the Gjallar API with the caller's own bearer token, so
// Keycloak roles apply exactly as they do in the web UI.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/heimdallr-dev/gjallar/internal/client"
)

const protocolVersion = "2025-06-18"

// Server is the MCP endpoint.
type Server struct {
	API     *client.Client
	Version string
	Log     *slog.Logger
	// RequireAuth rejects calls without a bearer token (set when OIDC is on).
	RequireAuth bool
}

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type tool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
	call        func(ctx context.Context, c *client.Client, args map[string]any) (any, error)
}

func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

func readOnly() map[string]any { return map[string]any{"readOnlyHint": true, "openWorldHint": false} }

func arg(a map[string]any, k string) string {
	v, _ := a[k].(string)
	return strings.TrimSpace(v)
}

var tools = []tool{
	{
		Name: "security_summary", Title: "Security summary",
		Description: "Headline numbers: images, workloads, open findings by risk band and severity, KEV count, fixable count, posture and license violations, median time to fix.",
		InputSchema: obj(map[string]any{}), Annotations: readOnly(),
		call: func(ctx context.Context, c *client.Client, _ map[string]any) (any, error) {
			var out json.RawMessage
			return out, c.Get(ctx, "/api/v1/summary", &out)
		},
	},
	{
		Name: "top_risks", Title: "Top risks",
		Description: "Open vulnerability findings ranked by Gjallar risk score (CVSS × EPSS/KEV × runtime × exposure), with where each image runs and why it scored that way.",
		InputSchema: obj(map[string]any{
			"band":      map[string]any{"type": "string", "enum": []string{"urgent", "high", "medium", "low"}, "description": "Only this risk band"},
			"namespace": str("Only images running in this namespace"),
			"limit":     map[string]any{"type": "integer", "minimum": 1, "maximum": 200, "default": 20},
		}), Annotations: readOnly(),
		call: func(ctx context.Context, c *client.Client, a map[string]any) (any, error) {
			q := url.Values{}
			if b := arg(a, "band"); b != "" {
				q.Set("band", b)
			}
			if ns := arg(a, "namespace"); ns != "" {
				q.Set("namespace", ns)
			}
			limit := 20
			if l, ok := a["limit"].(float64); ok && l > 0 {
				limit = int(l)
			}
			q.Set("limit", fmt.Sprint(limit))
			var out json.RawMessage
			return out, c.Get(ctx, "/api/v1/findings?"+q.Encode(), &out)
		},
	},
	{
		Name: "find_package", Title: "Find a package",
		Description: "Where is a package running? Returns open findings for packages whose name contains the query (e.g. log4j, openssl), with images and workloads.",
		InputSchema: obj(map[string]any{"package": str("Package name or substring")}, "package"), Annotations: readOnly(),
		call: func(ctx context.Context, c *client.Client, a map[string]any) (any, error) {
			var out json.RawMessage
			return out, c.Get(ctx, "/api/v1/findings?state=all&limit=200&package="+url.QueryEscape(arg(a, "package")), &out)
		},
	},
	{
		Name: "image_report", Title: "Image report",
		Description: "Everything known about one image digest: metadata and all findings (open, fixed, accepted).",
		InputSchema: obj(map[string]any{"digest": str("Image digest, sha256:...")}, "digest"), Annotations: readOnly(),
		call: func(ctx context.Context, c *client.Client, a map[string]any) (any, error) {
			var out json.RawMessage
			return out, c.Get(ctx, "/api/v1/images/"+url.PathEscape(arg(a, "digest")), &out)
		},
	},
	{
		Name: "posture_violations", Title: "Posture violations",
		Description: "Configuration problems on running workloads (privileged, host namespaces, root, missing limits, mutable tags...).",
		InputSchema: obj(map[string]any{}), Annotations: readOnly(),
		call: func(ctx context.Context, c *client.Client, _ map[string]any) (any, error) {
			var out json.RawMessage
			return out, c.Get(ctx, "/api/v1/posture", &out)
		},
	},
	{
		Name: "license_denials", Title: "License denials",
		Description: "Packages whose license is denied by policy.",
		InputSchema: obj(map[string]any{}), Annotations: readOnly(),
		call: func(ctx context.Context, c *client.Client, _ map[string]any) (any, error) {
			var out json.RawMessage
			return out, c.Get(ctx, "/api/v1/licenses?verdict=denied", &out)
		},
	},
	{
		Name: "analytics_report", Title: "Analytics report",
		Description: "Run a curated lakehouse report: risk_trend, time_to_fix, top_packages, kev_exposure, license_denials, posture_by_check, package_inventory, runtime_effect, runtime_loaded_packages.",
		InputSchema: obj(map[string]any{"name": map[string]any{"type": "string", "enum": []string{"risk_trend", "time_to_fix", "top_packages", "kev_exposure", "license_denials", "posture_by_check", "package_inventory", "runtime_effect", "runtime_loaded_packages"}}}, "name"),
		Annotations: readOnly(),
		call: func(ctx context.Context, c *client.Client, a map[string]any) (any, error) {
			var out json.RawMessage
			return out, c.Get(ctx, "/api/v1/analytics/reports/"+url.PathEscape(arg(a, "name")), &out)
		},
	},
	{
		Name: "analytics_query", Title: "Analytics SQL",
		Description: "Run one read-only DuckDB SQL query over the lakehouse. Tables: finding_events, finding_daily, risk_scores (score with its inputs), sbom_packages, runtime_loaded, package_licenses, posture_events, workload_images, patch_events, audit_events. Use DESCRIBE <table> to see columns.",
		InputSchema: obj(map[string]any{"sql": str("A single SELECT/WITH/FROM/DESCRIBE/SUMMARIZE statement")}, "sql"), Annotations: readOnly(),
		call: func(ctx context.Context, c *client.Client, a map[string]any) (any, error) {
			var out json.RawMessage
			return out, c.Post(ctx, "/api/v1/analytics/query", map[string]any{"sql": arg(a, "sql"), "max_rows": 500}, &out)
		},
	},
	{
		Name: "request_patch", Title: "Request a Copa patch",
		Description: "Queue an OS-package patch (Copacetic) for an image digest. Requires the gjallar-admin role. Produces a new <tag>-patched image; it does not change running workloads.",
		InputSchema: obj(map[string]any{"digest": str("Image digest, sha256:...")}, "digest"),
		Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false},
		call: func(ctx context.Context, c *client.Client, a map[string]any) (any, error) {
			var out json.RawMessage
			return out, c.Post(ctx, "/api/v1/images/"+url.PathEscape(arg(a, "digest"))+"/patch", map[string]any{}, &out)
		},
	},
}

// ServeHTTP handles POST /mcp (JSON-RPC). GET returns 405 because this
// server does not push server-initiated messages.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if s.RequireAuth && tok == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="gjallar"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req rpcReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeRPC(w, nil, nil, &rpcErr{-32700, "parse error"})
		return
	}
	if len(req.ID) == 0 { // notification
		w.WriteHeader(http.StatusAccepted)
		return
	}
	c := s.API.WithToken(tok)
	switch req.Method {
	case "initialize":
		writeRPC(w, req.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "gjallar", "title": "Gjallar Kubernetes security", "version": s.Version},
			"instructions":    "Gjallar ranks Kubernetes vulnerabilities by real risk. Start with security_summary, then top_risks with band=urgent.",
		}, nil)
	case "ping":
		writeRPC(w, req.ID, map[string]any{}, nil)
	case "tools/list":
		writeRPC(w, req.ID, map[string]any{"tools": tools}, nil)
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			writeRPC(w, req.ID, nil, &rpcErr{-32602, "invalid params"})
			return
		}
		for _, t := range tools {
			if t.Name != p.Name {
				continue
			}
			if p.Arguments == nil {
				p.Arguments = map[string]any{}
			}
			res, err := t.call(r.Context(), c, p.Arguments)
			if err != nil {
				// Tool errors are results, so the model can see and react.
				writeRPC(w, req.ID, map[string]any{"isError": true, "content": []map[string]string{{"type": "text", "text": err.Error()}}}, nil)
				return
			}
			b, _ := json.Marshal(res)
			text := string(b)
			if len(text) > 200_000 {
				text = text[:200_000] + "\n…truncated; narrow the query"
			}
			writeRPC(w, req.ID, map[string]any{"content": []map[string]string{{"type": "text", "text": text}}}, nil)
			return
		}
		writeRPC(w, req.ID, nil, &rpcErr{-32602, "unknown tool " + p.Name})
	default:
		writeRPC(w, req.ID, nil, &rpcErr{-32601, "method not found: " + req.Method})
	}
}

func writeRPC(w http.ResponseWriter, id json.RawMessage, result any, e *rpcErr) {
	resp := map[string]any{"jsonrpc": "2.0", "id": id}
	if e != nil {
		resp["error"] = e
	} else {
		resp["result"] = result
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
