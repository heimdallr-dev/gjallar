// Package postgres implements app.Repository on PostgreSQL (CloudNativePG
// in-cluster, or any Postgres 14+).
package postgres

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/heimdallr-dev/gjallar/internal/app"
	"github.com/heimdallr-dev/gjallar/internal/domain"
)

//go:embed schema.sql
var schema string

// Repo is the Postgres repository.
type Repo struct{ db *pgxpool.Pool }

var _ app.Repository = (*Repo)(nil)

// Open connects, migrates and returns a repository.
func Open(ctx context.Context, dsn string) (*Repo, error) {
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for i := 0; i < 30; i++ { // wait for Postgres on first boot
		if lastErr = db.Ping(ctx); lastErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("postgres ping: %w", lastErr)
	}
	if _, err := db.Exec(ctx, schema); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Repo{db: db}, nil
}

// Close releases the pool.
func (r *Repo) Close() { r.db.Close() }

// Ping checks connectivity for readiness probes.
func (r *Repo) Ping(ctx context.Context) error { return r.db.Ping(ctx) }

func (r *Repo) UpsertWorkload(ctx context.Context, w domain.Workload) error {
	spec, _ := json.Marshal(w)
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO workloads (id, cluster, namespace, kind, name, exposed, spec, last_seen)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (id) DO UPDATE SET exposed=EXCLUDED.exposed, spec=EXCLUDED.spec, last_seen=EXCLUDED.last_seen`,
		w.ID(), w.Cluster, w.Namespace, w.Kind, w.Name, w.Exposed, spec, w.LastSeen); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM workload_images WHERE workload_id=$1`, w.ID()); err != nil {
		return err
	}
	for _, c := range w.Containers {
		if !c.Image.Digest.Valid() {
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO workload_images (workload_id, container, digest) VALUES ($1,$2,$3)
			ON CONFLICT DO NOTHING`, w.ID(), c.Name, string(c.Image.Digest)); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (r *Repo) EnsureImage(ctx context.Context, ref domain.ImageRef) (bool, error) {
	// Insert if new; claim the SBOM job atomically when no SBOM exists and
	// nothing was queued in the last 15 minutes. Safe with several hub replicas.
	_, err := r.db.Exec(ctx, `INSERT INTO images (digest, repository, tag) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
		string(ref.Digest), ref.Repository, ref.Tag)
	if err != nil {
		return false, err
	}
	tag, err := r.db.Exec(ctx, `UPDATE images SET sbom_queued=now()
		WHERE digest=$1 AND NOT sbom_ready AND (sbom_queued IS NULL OR sbom_queued < now() - interval '15 minutes')`,
		string(ref.Digest))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (r *Repo) MarkSBOM(ctx context.Context, ev domain.SBOMGenerated) error {
	if ev.Error != "" {
		_, err := r.db.Exec(ctx, `UPDATE images SET sbom_queued=NULL WHERE digest=$1`, string(ev.Digest))
		return err
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO images (digest, repository, tag, distro, packages, sbom_ready) VALUES ($1,$2,$3,$4,$5,TRUE)
		ON CONFLICT (digest) DO UPDATE SET distro=EXCLUDED.distro, packages=EXCLUDED.packages, sbom_ready=TRUE`,
		string(ev.Digest), ev.Image.Repository, ev.Image.Tag, ev.Distro, ev.Packages)
	return err
}

func (r *Repo) Exposure(ctx context.Context, d domain.Digest) (bool, error) {
	var exposed bool
	err := r.db.QueryRow(ctx, `SELECT COALESCE(bool_or(w.exposed), FALSE) FROM workload_images wi
		JOIN workloads w ON w.id = wi.workload_id WHERE wi.digest=$1`, string(d)).Scan(&exposed)
	return exposed, err
}

const findingCols = `id, digest, vuln_id, package, version, pkg_type, fixed_in, severity, cvss, epss, kev,
	state, risk, band, actionable, reasons, first_seen, last_seen, fixed_at, source`

func scanFinding(row pgx.Row) (domain.Finding, error) {
	var f domain.Finding
	var sev, band string
	var reasons []byte
	var dg string
	err := row.Scan(&f.ID, &dg, &f.VulnID, &f.Package, &f.Version, &f.PkgType, &f.FixedIn, &sev, &f.CVSS, &f.EPSS, &f.KEV,
		&f.State, &f.Risk.Value, &band, &f.Risk.Actionable, &reasons, &f.FirstSeen, &f.LastSeen, &f.FixedAt, &f.Source)
	f.Digest, f.Severity, f.Risk.Band = domain.Digest(dg), domain.ParseSeverity(sev), domain.RiskBand(band)
	_ = json.Unmarshal(reasons, &f.Risk.Reasons)
	return f, err
}

func (r *Repo) Findings(ctx context.Context, d domain.Digest) ([]domain.Finding, error) {
	rows, err := r.db.Query(ctx, `SELECT `+findingCols+` FROM findings WHERE digest=$1`, string(d))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (r *Repo) SaveFindings(ctx context.Context, d domain.Digest, dbv string, fs []domain.Finding) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	batch := &pgx.Batch{}
	for _, f := range fs {
		reasons, _ := json.Marshal(f.Risk.Reasons)
		batch.Queue(`INSERT INTO findings (`+findingCols+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
			ON CONFLICT (id) DO UPDATE SET fixed_in=EXCLUDED.fixed_in, severity=EXCLUDED.severity, cvss=EXCLUDED.cvss,
			  epss=EXCLUDED.epss, kev=EXCLUDED.kev, state=EXCLUDED.state, risk=EXCLUDED.risk, band=EXCLUDED.band,
			  actionable=EXCLUDED.actionable, reasons=EXCLUDED.reasons, last_seen=EXCLUDED.last_seen, fixed_at=EXCLUDED.fixed_at, source=EXCLUDED.source`,
			f.ID, string(d), f.VulnID, f.Package, f.Version, f.PkgType, f.FixedIn, f.Severity.String(), f.CVSS, f.EPSS, f.KEV,
			string(f.State), f.Risk.Value, string(f.Risk.Band), f.Risk.Actionable, reasons, f.FirstSeen, f.LastSeen, f.FixedAt, f.Source)
	}
	batch.Queue(`UPDATE images SET db_version=$2, last_scanned=now() WHERE digest=$1`, string(d), dbv)
	if err := tx.SendBatch(ctx, batch).Close(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *Repo) AcceptFinding(ctx context.Context, id, reason, author string, expires *time.Time) error {
	tag, err := r.db.Exec(ctx, `UPDATE findings SET state='accepted' WHERE id=$1 AND state <> 'fixed'`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return app.ErrNotFound
	}
	_, err = r.db.Exec(ctx, `INSERT INTO exceptions (finding_id, reason, author, expires_at) VALUES ($1,$2,$3,$4)
		ON CONFLICT (finding_id) DO UPDATE SET reason=EXCLUDED.reason, author=EXCLUDED.author, expires_at=EXCLUDED.expires_at`,
		id, reason, author, expires)
	return err
}

func (r *Repo) SaveLicenses(ctx context.Context, d domain.Digest, rs []domain.LicenseResult) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM licenses WHERE digest=$1`, string(d)); err != nil {
		return err
	}
	batch := &pgx.Batch{}
	for _, l := range rs {
		batch.Queue(`INSERT INTO licenses (digest, package, version, license, verdict) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
			string(d), l.Package, l.Version, l.License, string(l.Verdict))
	}
	if err := tx.SendBatch(ctx, batch).Close(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *Repo) SavePosture(ctx context.Context, id string, vs []domain.PostureViolation) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM posture WHERE workload_id=$1`, id); err != nil {
		return err
	}
	for _, v := range vs {
		if _, err := tx.Exec(ctx, `INSERT INTO posture (workload_id, check_id, container, severity, message) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT DO NOTHING`, id, v.CheckID, v.Container, v.Severity.String(), v.Message); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (r *Repo) CreatePatch(ctx context.Context, d domain.Digest) (int64, error) {
	var id int64
	err := r.db.QueryRow(ctx, `INSERT INTO patches (digest) VALUES ($1) RETURNING id`, string(d)).Scan(&id)
	return id, err
}

func (r *Repo) SavePatch(ctx context.Context, p domain.PatchResult) error {
	status, msg := "done", ""
	if p.Error != "" {
		status, msg = "failed", p.Error
	}
	_, err := r.db.Exec(ctx, `UPDATE patches SET status=$2, patched_ref=$3, message=$4, updated_at=now()
		WHERE id = (SELECT id FROM patches WHERE digest=$1 AND status='queued' ORDER BY id DESC LIMIT 1)`,
		string(p.Digest), status, p.PatchedRef, msg)
	return err
}

func (r *Repo) SBOMDigests(ctx context.Context) ([]domain.Digest, error) {
	rows, err := r.db.Query(ctx, `SELECT digest FROM images WHERE sbom_ready ORDER BY digest`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (domain.Digest, error) {
		var s string
		err := row.Scan(&s)
		return domain.Digest(s), err
	})
}

const imageCols = `digest, repository, tag, distro, packages, sbom_ready, db_version, first_seen, COALESCE(last_scanned, 'epoch')`

func scanImage(row pgx.Row) (domain.Image, error) {
	var i domain.Image
	var d string
	err := row.Scan(&d, &i.Repository, &i.Tag, &i.Distro, &i.Packages, &i.SBOMReady, &i.DBVersion, &i.FirstSeen, &i.LastScanned)
	i.Digest = domain.Digest(d)
	return i, err
}

func (r *Repo) Image(ctx context.Context, d domain.Digest) (domain.Image, error) {
	i, err := scanImage(r.db.QueryRow(ctx, `SELECT `+imageCols+` FROM images WHERE digest=$1`, string(d)))
	if errors.Is(err, pgx.ErrNoRows) {
		return i, app.ErrNotFound
	}
	return i, err
}

func (r *Repo) ImageByRef(ctx context.Context, repo, tag string) (domain.Image, error) {
	i, err := scanImage(r.db.QueryRow(ctx, `SELECT `+imageCols+` FROM images WHERE repository=$1 AND tag=$2
		ORDER BY last_scanned DESC NULLS LAST LIMIT 1`, repo, tag))
	if errors.Is(err, pgx.ErrNoRows) {
		return i, app.ErrNotFound
	}
	return i, err
}

func (r *Repo) Summary(ctx context.Context) (app.Summary, error) {
	s := app.Summary{ByBand: map[string]int{}, BySeverity: map[string]int{}}
	err := r.db.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM images), (SELECT count(*) FROM workloads),
		(SELECT count(*) FROM findings WHERE state='open'),
		(SELECT count(*) FROM findings WHERE state='open' AND kev),
		(SELECT count(*) FROM findings WHERE state='open' AND fixed_in <> ''),
		(SELECT count(*) FROM posture),
		(SELECT count(*) FROM licenses WHERE verdict='denied'),
		(SELECT COALESCE(percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM fixed_at - first_seen)/3600), 0)
		   FROM findings WHERE state='fixed' AND fixed_at > now() - interval '90 days')`).
		Scan(&s.Images, &s.Workloads, &s.OpenFindings, &s.KEV, &s.Fixable, &s.Posture, &s.LicDenied, &s.MedianTTFH)
	if err != nil {
		return s, err
	}
	for _, q := range []struct {
		sql string
		m   map[string]int
	}{
		{`SELECT band, count(*) FROM findings WHERE state='open' GROUP BY band`, s.ByBand},
		{`SELECT severity, count(*) FROM findings WHERE state='open' GROUP BY severity`, s.BySeverity},
	} {
		rows, err := r.db.Query(ctx, q.sql)
		if err != nil {
			return s, err
		}
		for rows.Next() {
			var k string
			var n int
			if err := rows.Scan(&k, &n); err != nil {
				rows.Close()
				return s, err
			}
			q.m[k] = n
		}
		rows.Close()
	}
	return s, nil
}

func (r *Repo) ListFindings(ctx context.Context, f app.FindingFilter) ([]app.FindingView, error) {
	var where []string
	var args []any
	arg := func(v any) string { args = append(args, v); return fmt.Sprintf("$%d", len(args)) }
	switch f.State {
	case "", "open":
		where = append(where, "f.state='open'")
	case "all":
	default:
		where = append(where, "f.state="+arg(f.State))
	}
	if f.Band != "" {
		where = append(where, "f.band="+arg(f.Band))
	}
	if f.Package != "" {
		where = append(where, "f.package ILIKE "+arg("%"+f.Package+"%"))
	}
	if f.Digest != "" {
		where = append(where, "f.digest="+arg(string(f.Digest)))
	}
	if f.Namespace != "" {
		where = append(where, "EXISTS (SELECT 1 FROM workload_images wi JOIN workloads w ON w.id=wi.workload_id WHERE wi.digest=f.digest AND w.namespace="+arg(f.Namespace)+")")
	}
	limit := f.Limit
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	q := `SELECT ` + prefixed("f.", findingCols) + `, COALESCE(i.repository,''),
		COALESCE((SELECT array_agg(DISTINCT w.namespace || '/' || w.name) FROM workload_images wi
		          JOIN workloads w ON w.id=wi.workload_id WHERE wi.digest=f.digest), '{}')
		FROM findings f LEFT JOIN images i ON i.digest=f.digest`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY f.risk DESC, f.vuln_id LIMIT %d", limit)
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.FindingView
	for rows.Next() {
		var v app.FindingView
		var sev, band, dg string
		var reasons []byte
		if err := rows.Scan(&v.ID, &dg, &v.VulnID, &v.Package, &v.Version, &v.PkgType, &v.FixedIn, &sev, &v.CVSS, &v.EPSS, &v.KEV,
			&v.State, &v.Risk.Value, &band, &v.Risk.Actionable, &reasons, &v.FirstSeen, &v.LastSeen, &v.FixedAt, &v.Source,
			&v.Repository, &v.Workloads); err != nil {
			return nil, err
		}
		v.Digest, v.Severity, v.Risk.Band = domain.Digest(dg), domain.ParseSeverity(sev), domain.RiskBand(band)
		_ = json.Unmarshal(reasons, &v.Risk.Reasons)
		out = append(out, v)
	}
	return out, rows.Err()
}

func prefixed(p, cols string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = p + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}

func (r *Repo) ListImages(ctx context.Context) ([]domain.Image, error) {
	rows, err := r.db.Query(ctx, `SELECT `+imageCols+` FROM images ORDER BY repository, tag LIMIT 5000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Image
	for rows.Next() {
		i, err := scanImage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (r *Repo) ListWorkloads(ctx context.Context) ([]domain.Workload, error) {
	rows, err := r.db.Query(ctx, `SELECT spec FROM workloads ORDER BY id LIMIT 5000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Workload
	for rows.Next() {
		var b []byte
		var w domain.Workload
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		if json.Unmarshal(b, &w) == nil {
			out = append(out, w)
		}
	}
	return out, rows.Err()
}

func (r *Repo) ListPosture(ctx context.Context) ([]domain.PostureViolation, error) {
	rows, err := r.db.Query(ctx, `SELECT workload_id, check_id, container, severity, message FROM posture
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, workload_id LIMIT 5000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.PostureViolation
	for rows.Next() {
		var v domain.PostureViolation
		var sev string
		if err := rows.Scan(&v.WorkloadID, &v.CheckID, &v.Container, &sev, &v.Message); err != nil {
			return nil, err
		}
		v.Severity = domain.ParseSeverity(sev)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (r *Repo) ListLicenses(ctx context.Context, verdict string) ([]domain.LicenseResult, error) {
	q, args := `SELECT digest, package, version, license, verdict FROM licenses`, []any{}
	if verdict != "" {
		q += ` WHERE verdict=$1`
		args = append(args, verdict)
	}
	rows, err := r.db.Query(ctx, q+` ORDER BY package LIMIT 5000`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.LicenseResult
	for rows.Next() {
		var l domain.LicenseResult
		var d, v string
		if err := rows.Scan(&d, &l.Package, &l.Version, &l.License, &v); err != nil {
			return nil, err
		}
		l.Digest, l.Verdict = domain.Digest(d), domain.LicenseVerdict(v)
		out = append(out, l)
	}
	return out, rows.Err()
}

func (r *Repo) ListPatches(ctx context.Context) ([]app.PatchView, error) {
	rows, err := r.db.Query(ctx, `SELECT id, digest, status, patched_ref, message, created_at FROM patches ORDER BY id DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.PatchView
	for rows.Next() {
		var p app.PatchView
		if err := rows.Scan(&p.ID, &p.Digest, &p.Status, &p.PatchedRef, &p.Message, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
