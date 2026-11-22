package httpapi

import (
	"context"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/adapters/oidc"
	"github.com/heimdallr-dev/gjallar/internal/app"
	"github.com/heimdallr-dev/gjallar/internal/domain"
	"github.com/heimdallr-dev/gjallar/internal/platform/httpx"
)

// scope is what the caller may see (everything when tenancy is off).
func (a *API) scope(r *http.Request) app.Scope {
	p, _ := oidc.FromContext(r.Context())
	return a.Tenancy.ScopeFor(p.Roles, p.Groups)
}

// visible returns the image digests running in the caller's namespaces.
func (a *API) visible(ctx context.Context, s app.Scope) (map[domain.Digest]bool, error) {
	ws, err := a.Repo.ListWorkloads(ctx)
	if err != nil {
		return nil, err
	}
	ds := map[domain.Digest]bool{}
	for _, w := range ws {
		if s.Namespace(w.Namespace) {
			for _, c := range w.Containers {
				ds[c.Image.Digest] = true
			}
		}
	}
	return ds, nil
}

// scopedSummary recomputes the dashboard numbers for a namespace-scoped caller.
// Time to fix is a fleet-wide statistic and is left at 0 here.
func (a *API) scopedSummary(ctx context.Context, s app.Scope) (app.Summary, error) {
	out := app.Summary{ByBand: map[string]int{}, BySeverity: map[string]int{}}
	ws, err := a.Repo.ListWorkloads(ctx)
	if err != nil {
		return out, err
	}
	ds := map[domain.Digest]bool{}
	for _, w := range ws {
		if s.Namespace(w.Namespace) {
			out.Workloads++
			for _, c := range w.Containers {
				ds[c.Image.Digest] = true
			}
		}
	}
	out.Images = len(ds)
	fs, err := a.Repo.ListFindings(ctx, app.FindingFilter{State: "open", Limit: 1000000})
	if err != nil {
		return out, err
	}
	for _, f := range fs {
		if !s.AnyWorkload(f.Workloads) {
			continue
		}
		out.OpenFindings++
		out.ByBand[string(f.Risk.Band)]++
		out.BySeverity[strings.ToLower(f.Severity.String())]++
		if f.KEV {
			out.KEV++
		}
		if f.FixAvailable() {
			out.Fixable++
		}
	}
	vs, err := a.Repo.ListPosture(ctx)
	if err != nil {
		return out, err
	}
	for _, v := range vs {
		if s.Namespace(workloadNamespace(v.WorkloadID)) {
			out.Posture++
		}
	}
	ls, err := a.Repo.ListLicenses(ctx, "denied")
	if err != nil {
		return out, err
	}
	for _, l := range ls {
		if ds[l.Digest] {
			out.LicDenied++
		}
	}
	return out, nil
}

// workloadNamespace reads the namespace from "cluster/namespace/kind/name".
func workloadNamespace(id string) string {
	if parts := strings.Split(id, "/"); len(parts) > 1 {
		return parts[1]
	}
	return ""
}

func (s scopeList) names() []string {
	out := make([]string, 0, len(s))
	for ns := range s {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

type scopeList map[string]bool

// canSee answers 404 for images outside the caller's namespaces, so scoped
// users can't probe which images other teams run.
func (a *API) canSee(w http.ResponseWriter, r *http.Request, d domain.Digest) bool {
	sc := a.scope(r)
	if sc.All {
		return true
	}
	ds, err := a.visible(r.Context(), sc)
	if err != nil {
		a.fail(w, err)
		return false
	}
	if !ds[d] {
		httpx.Error(w, http.StatusNotFound, "not found")
		return false
	}
	return true
}

// audit records every state-changing call (accept, patch, scan, rematch) in
// the log and as an event the lakehouse keeps (table audit_events).
func (a *API) audit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || strings.HasPrefix(r.URL.Path, "/api/v1/analytics/") {
			next.ServeHTTP(w, r) // reads, and read-only SQL sent as POST
			return
		}
		rec := &statusRec{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rec, r)
		p, _ := oidc.FromContext(r.Context())
		ev := domain.AuditEvent{At: time.Now().UTC(), User: p.Username, Client: p.Client, Method: r.Method, Path: r.URL.Path, Status: rec.code}
		if a.Log != nil {
			a.Log.Info("audit", "user", ev.User, "client", ev.Client, "method", ev.Method, "path", ev.Path, "status", ev.Status)
		}
		if a.Hub != nil && a.Hub.Bus != nil {
			_ = a.Hub.Bus.Publish(r.Context(), domain.SubjAudit, ev)
		}
	})
}

type statusRec struct {
	http.ResponseWriter
	code int
}

func (s *statusRec) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }

// sbom serves the stored SBOM: ?format=syft-json (default), cyclonedx-json or spdx-json.
func (a *API) sbom(w http.ResponseWriter, r *http.Request) {
	d := domain.Digest(r.PathValue("digest"))
	if a.SBOMs == nil || !d.Valid() {
		httpx.Error(w, http.StatusNotFound, "not found")
		return
	}
	if !a.canSee(w, r, d) {
		return
	}
	format := r.URL.Query().Get("format")
	if format != "" && format != "syft-json" && !slices.Contains(app.SBOMFormats, format) {
		httpx.Error(w, http.StatusBadRequest, "format must be syft-json, "+strings.Join(app.SBOMFormats, " or "))
		return
	}
	raw, err := a.SBOMs.Get(r.Context(), app.SBOMKey(d, format))
	if err != nil {
		httpx.Error(w, http.StatusNotFound, "no SBOM in that format for this image")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(string(d), ":", "_")+"."+cmpOr(format, "syft-json")+`.json"`)
	_, _ = w.Write(raw)
}

func cmpOr(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
