// Package httpapi is the REST driving adapter. Web, MCP and CLI all use it.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/adapters/oidc"
	"github.com/heimdallr-dev/gjallar/internal/app"
	"github.com/heimdallr-dev/gjallar/internal/domain"
	"github.com/heimdallr-dev/gjallar/internal/platform/httpx"
	"github.com/heimdallr-dev/gjallar/internal/platform/telemetry"
)

// Version is set at build time.
var Version = "dev"

// API serves /api/v1.
type API struct {
	Hub       *app.Hub
	Repo      app.Repository
	Auth      oidc.Auth
	Analytics *url.URL      // optional: proxied under /api/v1/analytics/
	Tenancy   *app.Tenancy  // optional: Keycloak groups → namespaces
	SBOMs     app.SBOMStore // optional: serves stored SBOMs (Syft, CycloneDX, SPDX)
	Ready     func() error
	Log       *slog.Logger
}

// Handler builds the router.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { httpx.JSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if a.Ready != nil {
			if err := a.Ready(); err != nil {
				httpx.Error(w, 503, err.Error())
				return
			}
		}
		httpx.JSON(w, 200, map[string]string{"status": "ready"})
	})
	mux.Handle("GET /metrics", telemetry.MetricsHandler())

	mux.HandleFunc("GET /api/v1/version", func(w http.ResponseWriter, _ *http.Request) {
		httpx.JSON(w, 200, map[string]string{"name": "gjallar", "version": Version})
	})
	mux.HandleFunc("GET /api/v1/me", func(w http.ResponseWriter, r *http.Request) {
		p, _ := oidc.FromContext(r.Context())
		sc := a.scope(r)
		httpx.JSON(w, 200, struct {
			oidc.Principal
			AllNamespaces bool     `json:"all_namespaces"`
			Namespaces    []string `json:"namespaces,omitempty"`
		}{p, sc.All, scopeList(sc.NS).names()})
	})
	mux.HandleFunc("GET /api/v1/summary", a.summary)
	mux.HandleFunc("GET /api/v1/findings", a.findings)
	mux.HandleFunc("GET /api/v1/images", a.images)
	mux.HandleFunc("GET /api/v1/images/{digest}", a.image)
	mux.HandleFunc("GET /api/v1/images/{digest}/vex", a.vex)
	mux.HandleFunc("GET /api/v1/images/{digest}/sbom", a.sbom)
	mux.HandleFunc("POST /api/v1/images/{digest}/patch", a.patch)
	mux.HandleFunc("GET /api/v1/workloads", a.workloads)
	mux.HandleFunc("GET /api/v1/posture", a.posture)
	mux.HandleFunc("GET /api/v1/licenses", a.licenses)
	mux.HandleFunc("GET /api/v1/patches", a.patches)
	mux.HandleFunc("POST /api/v1/scan", a.scan)
	mux.HandleFunc("POST /api/v1/rematch", a.rematch)
	mux.HandleFunc("POST /api/v1/findings/{id}/accept", a.accept)
	mux.HandleFunc("GET /api/v1/admission", a.admission)
	if a.Analytics != nil {
		proxy := httputil.NewSingleHostReverseProxy(a.Analytics)
		mux.Handle("/api/v1/analytics/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Raw lakehouse SQL can't be filtered per namespace; it is for fleet-wide roles only.
			if !a.scope(r).All {
				httpx.Error(w, http.StatusForbidden, "analytics is fleet-wide; ask for a global role")
				return
			}
			proxy.ServeHTTP(w, r)
		}))
	}
	return httpx.Observe(a.Log, a.Auth.Middleware(a.audit(mux)))
}

func (a *API) fail(w http.ResponseWriter, err error) {
	if errors.Is(err, app.ErrNotFound) {
		httpx.Error(w, 404, "not found")
		return
	}
	a.Log.Error("request failed", "err", err)
	httpx.Error(w, 500, err.Error())
}

func (a *API) summary(w http.ResponseWriter, r *http.Request) {
	var s app.Summary
	var err error
	if sc := a.scope(r); sc.All {
		s, err = a.Repo.Summary(r.Context())
	} else {
		s, err = a.scopedSummary(r.Context(), sc)
	}
	if err != nil {
		a.fail(w, err)
		return
	}
	httpx.JSON(w, 200, s)
}

func (a *API) findings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	fs, err := a.Repo.ListFindings(r.Context(), app.FindingFilter{
		Band: q.Get("band"), Namespace: q.Get("namespace"), Package: q.Get("package"),
		Digest: domain.Digest(q.Get("digest")), State: q.Get("state"), Limit: limit,
	})
	if err != nil {
		a.fail(w, err)
		return
	}
	if sc := a.scope(r); !sc.All {
		kept := fs[:0]
		for _, f := range fs {
			if sc.AnyWorkload(f.Workloads) {
				kept = append(kept, f)
			}
		}
		fs = kept
	}
	if fs == nil {
		fs = []app.FindingView{}
	}
	httpx.JSON(w, 200, fs)
}

func (a *API) images(w http.ResponseWriter, r *http.Request) {
	is, err := a.Repo.ListImages(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	if sc := a.scope(r); !sc.All {
		ds, err := a.visible(r.Context(), sc)
		if err != nil {
			a.fail(w, err)
			return
		}
		kept := is[:0]
		for _, i := range is {
			if ds[i.Digest] {
				kept = append(kept, i)
			}
		}
		is = kept
	}
	if is == nil {
		is = []domain.Image{}
	}
	httpx.JSON(w, 200, is)
}

func (a *API) image(w http.ResponseWriter, r *http.Request) {
	d := domain.Digest(r.PathValue("digest"))
	if !a.canSee(w, r, d) {
		return
	}
	img, err := a.Repo.Image(r.Context(), d)
	if err != nil {
		a.fail(w, err)
		return
	}
	fs, err := a.Repo.ListFindings(r.Context(), app.FindingFilter{Digest: d, State: "all", Limit: 5000})
	if err != nil {
		a.fail(w, err)
		return
	}
	httpx.JSON(w, 200, map[string]any{"image": img, "findings": fs})
}

// vex renders accepted findings of an image as an OpenVEX document so other
// tools (Grype with --vex, Kyverno) honour the same exceptions.
func (a *API) vex(w http.ResponseWriter, r *http.Request) {
	d := domain.Digest(r.PathValue("digest"))
	if !a.canSee(w, r, d) {
		return
	}
	img, err := a.Repo.Image(r.Context(), d)
	if err != nil {
		a.fail(w, err)
		return
	}
	fs, err := a.Repo.ListFindings(r.Context(), app.FindingFilter{Digest: d, State: "accepted", Limit: 5000})
	if err != nil {
		a.fail(w, err)
		return
	}
	httpx.JSON(w, 200, app.OpenVEX(img.Repository, d, fs, time.Now()))
}

func (a *API) workloads(w http.ResponseWriter, r *http.Request) {
	ws, err := a.Repo.ListWorkloads(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	if sc := a.scope(r); !sc.All {
		kept := ws[:0]
		for _, x := range ws {
			if sc.Namespace(x.Namespace) {
				kept = append(kept, x)
			}
		}
		ws = kept
	}
	if ws == nil {
		ws = []domain.Workload{}
	}
	httpx.JSON(w, 200, ws)
}

func (a *API) posture(w http.ResponseWriter, r *http.Request) {
	vs, err := a.Repo.ListPosture(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	if sc := a.scope(r); !sc.All {
		kept := vs[:0]
		for _, v := range vs {
			if sc.Namespace(workloadNamespace(v.WorkloadID)) {
				kept = append(kept, v)
			}
		}
		vs = kept
	}
	if vs == nil {
		vs = []domain.PostureViolation{}
	}
	httpx.JSON(w, 200, vs)
}

func (a *API) licenses(w http.ResponseWriter, r *http.Request) {
	ls, err := a.Repo.ListLicenses(r.Context(), r.URL.Query().Get("verdict"))
	if err != nil {
		a.fail(w, err)
		return
	}
	if sc := a.scope(r); !sc.All {
		ds, err := a.visible(r.Context(), sc)
		if err != nil {
			a.fail(w, err)
			return
		}
		kept := ls[:0]
		for _, l := range ls {
			if ds[l.Digest] {
				kept = append(kept, l)
			}
		}
		ls = kept
	}
	if ls == nil {
		ls = []domain.LicenseResult{}
	}
	httpx.JSON(w, 200, ls)
}

func (a *API) patches(w http.ResponseWriter, r *http.Request) {
	ps, err := a.Repo.ListPatches(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	if sc := a.scope(r); !sc.All {
		ds, err := a.visible(r.Context(), sc)
		if err != nil {
			a.fail(w, err)
			return
		}
		kept := ps[:0]
		for _, p := range ps {
			if ds[domain.Digest(p.Digest)] {
				kept = append(kept, p)
			}
		}
		ps = kept
	}
	if ps == nil {
		ps = []app.PatchView{}
	}
	httpx.JSON(w, 200, ps)
}

func (a *API) scan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Image string `json:"image"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, 400, "body must be {\"image\": \"repo:tag\"}")
		return
	}
	ref, err := domain.ParseImageRef(body.Image)
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	if err := a.Hub.RequestScan(r.Context(), ref); err != nil {
		a.fail(w, err)
		return
	}
	httpx.JSON(w, 202, map[string]string{"status": "queued", "image": ref.String()})
}

func (a *API) rematch(w http.ResponseWriter, r *http.Request) {
	n, err := a.Hub.Rematch(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	httpx.JSON(w, 202, map[string]any{"status": "queued", "images": n})
}

func (a *API) patch(w http.ResponseWriter, r *http.Request) {
	id, err := a.Hub.RequestPatch(r.Context(), domain.Digest(r.PathValue("digest")))
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			a.fail(w, err)
			return
		}
		httpx.Error(w, 409, err.Error())
		return
	}
	httpx.JSON(w, 202, map[string]any{"status": "queued", "patch_id": id})
}

func (a *API) accept(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason  string     `json:"reason"`
		Expires *time.Time `json:"expires,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, 400, "body must be {\"reason\": \"...\", \"expires\": \"RFC3339 (optional)\"}")
		return
	}
	p, _ := oidc.FromContext(r.Context())
	if err := a.Hub.AcceptRisk(r.Context(), r.PathValue("id"), body.Reason, p.Username, body.Expires); err != nil {
		if errors.Is(err, app.ErrNotFound) {
			a.fail(w, err)
			return
		}
		httpx.Error(w, 400, err.Error())
		return
	}
	httpx.JSON(w, 200, map[string]string{"status": "accepted"})
}

func (a *API) admission(w http.ResponseWriter, r *http.Request) {
	ref, err := domain.ParseImageRef(r.URL.Query().Get("image"))
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	v, err := a.Hub.Admission(r.Context(), ref, r.URL.Query().Get("deny_unknown") == "true")
	if err != nil {
		a.fail(w, err)
		return
	}
	httpx.JSON(w, 200, v)
}

// RefreshMetrics publishes summary gauges for Prometheus/Grafana.
func RefreshMetrics(ctx context.Context, repo app.Repository) error {
	s, err := repo.Summary(ctx)
	if err != nil {
		return fmt.Errorf("summary: %w", err)
	}
	telemetry.Findings.Reset()
	for _, b := range []string{"urgent", "high", "medium", "low"} {
		telemetry.Findings.Set(float64(s.ByBand[b]), b)
	}
	telemetry.KEVFindings.Set(float64(s.KEV))
	telemetry.Images.Set(float64(s.Images))
	telemetry.Posture.Set(float64(s.Posture))
	telemetry.LicDenied.Set(float64(s.LicDenied))
	return refreshNamespaceUsage(ctx, repo)
}

// refreshNamespaceUsage meters usage per namespace (team): images, workloads
// and open findings by band.
// shortcut: recomputes from the full open-finding list every 30 s; fine to ~100k findings, move to a SQL GROUP BY beyond that.
func refreshNamespaceUsage(ctx context.Context, repo app.Repository) error {
	ws, err := repo.ListWorkloads(ctx)
	if err != nil {
		return fmt.Errorf("workloads: %w", err)
	}
	images := map[string]map[domain.Digest]bool{}
	workloads := map[string]int{}
	for _, w := range ws {
		workloads[w.Namespace]++
		if images[w.Namespace] == nil {
			images[w.Namespace] = map[domain.Digest]bool{}
		}
		for _, c := range w.Containers {
			if c.Image.Digest != "" {
				images[w.Namespace][c.Image.Digest] = true
			}
		}
	}
	fs, err := repo.ListFindings(ctx, app.FindingFilter{State: "open", Limit: 1000000})
	if err != nil {
		return fmt.Errorf("findings: %w", err)
	}
	type key struct{ ns, band string }
	counts := map[key]int{}
	for _, f := range fs {
		seen := map[string]bool{}
		for _, wl := range f.Workloads {
			ns, _, _ := strings.Cut(wl, "/")
			if !seen[ns] {
				seen[ns] = true
				counts[key{ns, string(f.Risk.Band)}]++
			}
		}
	}
	telemetry.NSImages.Reset()
	telemetry.NSWorkloads.Reset()
	telemetry.NSFindings.Reset()
	for ns, n := range workloads {
		telemetry.NSWorkloads.Set(float64(n), ns)
		telemetry.NSImages.Set(float64(len(images[ns])), ns)
	}
	for k, n := range counts {
		telemetry.NSFindings.Set(float64(n), k.ns, k.band)
	}
	return nil
}
