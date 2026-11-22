// gjallar-web serves the single-page UI and reverse-proxies /api to the
// Gjallar API so the browser stays same-origin. Login is OIDC Authorization
// Code + PKCE against Keycloak, done in the browser; this server holds no
// secrets.
package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/heimdallr-dev/gjallar/internal/platform/httpx"
	"github.com/heimdallr-dev/gjallar/internal/platform/telemetry"
)

var version = "dev"

//go:embed static
var static embed.FS

func main() {
	log := telemetry.NewLogger("gjallar-web").With("version", version)
	ctx, cancel := httpx.SignalContext()
	defer cancel()

	apiURL, err := url.Parse(httpx.Env("GJALLAR_API_URL", "http://gjallar-api:8080"))
	if err != nil {
		log.Error("bad GJALLAR_API_URL", "err", err)
		os.Exit(1)
	}
	sub, _ := fs.Sub(static, "static")
	cfg, _ := json.Marshal(map[string]string{
		"issuer":   os.Getenv("GJALLAR_OIDC_ISSUER"),
		"clientId": httpx.Env("GJALLAR_OIDC_WEB_CLIENT_ID", "gjallar-web"),
		"version":  version,
	})

	mux := http.NewServeMux()
	mux.Handle("/api/", httputil.NewSingleHostReverseProxy(apiURL))
	mux.HandleFunc("GET /config.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(cfg)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	files := http.FileServer(http.FS(sub))
	policy := csp(os.Getenv("GJALLAR_OIDC_ISSUER"))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", policy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		files.ServeHTTP(w, r)
	}))
	if err := httpx.Serve(ctx, log, httpx.Env("GJALLAR_HTTP_ADDR", ":8083"), httpx.Observe(log, mux)); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// csp allows the browser to call the API (same origin) and the identity
// provider. The issuer gets a trailing "/": in CSP a path without one matches
// only that exact URL, which blocked discovery and the token endpoint.
func csp(issuer string) string {
	if issuer != "" {
		issuer = " " + strings.TrimSuffix(issuer, "/") + "/"
	}
	return "default-src 'self'; connect-src 'self'" + issuer + "; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
}
