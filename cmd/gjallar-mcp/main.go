// gjallar-mcp serves Gjallar's tools to AI assistants over MCP (Streamable
// HTTP at /mcp). It holds no data and no credentials of its own: it forwards
// each caller's Keycloak token to the Gjallar API.
package main

import (
	"net/http"
	"os"

	"github.com/heimdallr-dev/gjallar/internal/adapters/mcp"
	"github.com/heimdallr-dev/gjallar/internal/client"
	"github.com/heimdallr-dev/gjallar/internal/platform/httpx"
	"github.com/heimdallr-dev/gjallar/internal/platform/telemetry"
)

var version = "dev"

func main() {
	log := telemetry.NewLogger("gjallar-mcp").With("version", version)
	ctx, cancel := httpx.SignalContext()
	defer cancel()

	issuer := os.Getenv("GJALLAR_OIDC_ISSUER")
	srv := &mcp.Server{API: client.New(httpx.Env("GJALLAR_API_URL", "http://gjallar-api:8080"), ""), Version: version, Log: log, RequireAuth: issuer != ""}

	mux := http.NewServeMux()
	mux.Handle("/mcp", srv)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { httpx.JSON(w, 200, map[string]string{"status": "ok"}) })
	mux.Handle("GET /metrics", telemetry.MetricsHandler())
	// RFC 9728 protected resource metadata: tells MCP clients which
	// authorization server (Keycloak realm) issues tokens for this server.
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		if issuer == "" {
			http.NotFound(w, r)
			return
		}
		httpx.JSON(w, 200, map[string]any{
			"resource":                 httpx.Env("GJALLAR_MCP_PUBLIC_URL", "https://"+r.Host+"/mcp"),
			"authorization_servers":    []string{issuer},
			"bearer_methods_supported": []string{"header"},
			"scopes_supported":         []string{"openid", "profile"},
		})
	})
	if err := httpx.Serve(ctx, log, httpx.Env("GJALLAR_HTTP_ADDR", ":8082"), httpx.Observe(log, mux)); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}
