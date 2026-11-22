// Package analytics implements Gjallar's analytics store with DuckDB over
// Parquet. Two modes:
//
//   - ducklake: tables in a DuckLake lakehouse (catalog in Postgres, data as
//     Parquet on S3/MinIO/Ceph RGW). Transactions, schema evolution, time travel.
//   - parquet:  plain hive-partitioned Parquet files, no catalog. Lightest
//     profile for laptops and edge sites.
//
// DuckDB runs as a subprocess (the official CLI), so the Go binaries stay
// CGO-free and DuckDB can be upgraded by swapping the image.
package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Config selects the storage mode.
type Config struct {
	Bin  string // duckdb binary, default "duckdb"
	Mode string // "ducklake" or "parquet"
	// Catalog is the DuckLake catalog, e.g. "postgres:dbname=gjallar host=pg user=gjallar password=..."
	// or a local file "metadata.ducklake" for single-node use.
	Catalog string
	// DataPath is where Parquet files live: "s3://gjallar-lake/" or "/data/lake/".
	DataPath string
	// S3 settings for MinIO / Ceph RGW.
	S3Endpoint, S3Region, S3KeyID, S3Secret string
	S3UseSSL                                bool
}

// Store is the DuckDB-backed analytics store.
type Store struct {
	cfg Config
}

// New validates config.
func New(cfg Config) (*Store, error) {
	if cfg.Bin == "" {
		cfg.Bin = "duckdb"
	}
	if cfg.Mode == "" {
		cfg.Mode = "parquet"
	}
	if cfg.DataPath == "" {
		return nil, fmt.Errorf("analytics: DataPath is required")
	}
	if cfg.Mode == "ducklake" && cfg.Catalog == "" {
		return nil, fmt.Errorf("analytics: ducklake mode needs a Catalog")
	}
	if !strings.HasSuffix(cfg.DataPath, "/") {
		cfg.DataPath += "/"
	}
	if !strings.HasPrefix(cfg.DataPath, "s3://") {
		if err := os.MkdirAll(cfg.DataPath, 0o755); err != nil {
			return nil, err
		}
	}
	return &Store{cfg: cfg}, nil
}

// Table describes one analytics table and its columns (DuckDB types).
type Table struct {
	Name    string
	Columns [][2]string
}

// Tables is Gjallar's analytics schema. Append-only event tables; daily
// snapshots are derived by Maintain.
var Tables = []Table{
	{"finding_events", [][2]string{
		{"ts", "TIMESTAMPTZ"}, {"day", "DATE"}, {"id", "VARCHAR"}, {"digest", "VARCHAR"}, {"repository", "VARCHAR"},
		{"namespaces", "VARCHAR[]"}, {"vuln_id", "VARCHAR"}, {"package", "VARCHAR"}, {"version", "VARCHAR"},
		{"pkg_type", "VARCHAR"}, {"severity", "VARCHAR"}, {"cvss", "DOUBLE"}, {"epss", "DOUBLE"}, {"kev", "BOOLEAN"},
		{"fixed_in", "VARCHAR"}, {"risk", "INTEGER"}, {"band", "VARCHAR"}, {"state", "VARCHAR"},
		{"first_seen", "TIMESTAMPTZ"}, {"fixed_at", "TIMESTAMPTZ"}, {"db_version", "VARCHAR"},
	}},
	{"package_licenses", [][2]string{
		{"ts", "TIMESTAMPTZ"}, {"day", "DATE"}, {"digest", "VARCHAR"}, {"package", "VARCHAR"}, {"version", "VARCHAR"},
		{"license", "VARCHAR"}, {"verdict", "VARCHAR"},
	}},
	{"posture_events", [][2]string{
		{"ts", "TIMESTAMPTZ"}, {"day", "DATE"}, {"workload_id", "VARCHAR"}, {"namespace", "VARCHAR"},
		{"check_id", "VARCHAR"}, {"severity", "VARCHAR"}, {"container", "VARCHAR"}, {"message", "VARCHAR"},
	}},
	{"workload_images", [][2]string{
		{"ts", "TIMESTAMPTZ"}, {"day", "DATE"}, {"cluster", "VARCHAR"}, {"namespace", "VARCHAR"}, {"kind", "VARCHAR"},
		{"name", "VARCHAR"}, {"container", "VARCHAR"}, {"repository", "VARCHAR"}, {"tag", "VARCHAR"},
		{"digest", "VARCHAR"}, {"exposed", "BOOLEAN"},
	}},
	{"patch_events", [][2]string{
		{"ts", "TIMESTAMPTZ"}, {"day", "DATE"}, {"digest", "VARCHAR"}, {"patched_ref", "VARCHAR"},
		{"fixed", "INTEGER"}, {"error", "VARCHAR"},
	}},
	{"sbom_packages", [][2]string{
		{"ts", "TIMESTAMPTZ"}, {"day", "DATE"}, {"digest", "VARCHAR"}, {"repository", "VARCHAR"}, {"package", "VARCHAR"},
		{"version", "VARCHAR"}, {"pkg_type", "VARCHAR"}, {"purl", "VARCHAR"},
	}},
	{"risk_scores", [][2]string{
		{"ts", "TIMESTAMPTZ"}, {"day", "DATE"}, {"id", "VARCHAR"}, {"digest", "VARCHAR"}, {"repository", "VARCHAR"},
		{"vuln_id", "VARCHAR"}, {"package", "VARCHAR"}, {"risk", "INTEGER"}, {"band", "VARCHAR"}, {"cvss", "DOUBLE"},
		{"epss", "DOUBLE"}, {"kev", "BOOLEAN"}, {"runtime", "VARCHAR"}, {"exposed", "BOOLEAN"}, {"fix_available", "BOOLEAN"},
		{"reasons", "VARCHAR[]"},
	}},
	{"audit_events", [][2]string{
		{"ts", "TIMESTAMPTZ"}, {"day", "DATE"}, {"user", "VARCHAR"}, {"client", "VARCHAR"}, {"method", "VARCHAR"},
		{"path", "VARCHAR"}, {"status", "INTEGER"},
	}},
	{"runtime_loaded", [][2]string{
		{"ts", "TIMESTAMPTZ"}, {"day", "DATE"}, {"digest", "VARCHAR"}, {"package", "VARCHAR"},
	}},
	{"finding_daily", [][2]string{
		{"day", "DATE"}, {"id", "VARCHAR"}, {"digest", "VARCHAR"}, {"repository", "VARCHAR"}, {"namespaces", "VARCHAR[]"},
		{"vuln_id", "VARCHAR"}, {"package", "VARCHAR"}, {"severity", "VARCHAR"}, {"kev", "BOOLEAN"},
		{"risk", "INTEGER"}, {"band", "VARCHAR"}, {"state", "VARCHAR"}, {"first_seen", "TIMESTAMPTZ"}, {"fixed_at", "TIMESTAMPTZ"},
	}},
}

func table(name string) (Table, bool) {
	for _, t := range Tables {
		if t.Name == name {
			return t, true
		}
	}
	return Table{}, false
}

// setupWrite prepares a session that only writes files (no views needed).
func (s *Store) setupWrite() string {
	if s.cfg.Mode == "ducklake" {
		return s.setup(false)
	}
	return s.s3Setup()
}

func (s *Store) s3Setup() string {
	if !strings.HasPrefix(s.cfg.DataPath, "s3://") {
		return ""
	}
	return fmt.Sprintf("LOAD httpfs;\nCREATE OR REPLACE SECRET gjallar_s3 (TYPE s3, KEY_ID %s, SECRET %s, REGION %s, ENDPOINT %s, URL_STYLE 'path', USE_SSL %t);\n",
		lit(s.cfg.S3KeyID), lit(s.cfg.S3Secret), lit(orDef(s.cfg.S3Region, "us-east-1")), lit(s.cfg.S3Endpoint), s.cfg.S3UseSSL)
}

// setup returns the statements that prepare a session.
func (s *Store) setup(readOnly bool) string {
	var b strings.Builder
	b.WriteString(s.s3Setup())
	if s.cfg.Mode == "ducklake" {
		b.WriteString("LOAD ducklake;\n")
		if strings.HasPrefix(s.cfg.Catalog, "postgres:") {
			b.WriteString("LOAD postgres;\n")
		}
		opts := "DATA_PATH " + lit(s.cfg.DataPath)
		if readOnly {
			opts += ", READ_ONLY"
		}
		fmt.Fprintf(&b, "ATTACH %s AS lake (%s);\nUSE lake;\n", lit("ducklake:"+s.cfg.Catalog), opts)
	} else {
		// Parquet mode: expose each table as a view over its partitions.
		for _, t := range Tables {
			fmt.Fprintf(&b, "CREATE OR REPLACE VIEW %s AS SELECT * FROM read_parquet(%s, hive_partitioning=true, union_by_name=true);\n",
				t.Name, lit(s.cfg.DataPath+t.Name+"/**/*.parquet"))
		}
	}
	if readOnly {
		// Read-only by construction, not only by keyword checks: after the lake
		// is attached, queries may touch nothing but the lake and the export
		// folder, and cannot change that (verified against Ceph RGW: other
		// buckets and local files are refused, the lock cannot be undone).
		fmt.Fprintf(&b, "SET allowed_directories=[%s, %s];\nSET enable_external_access=false;\nSET lock_configuration=true;\n",
			lit(s.cfg.DataPath), lit(strings.TrimSuffix(os.TempDir(), "/")+"/"))
	}
	return b.String()
}

// Init creates DuckLake tables, or in parquet mode writes one empty, typed
// seed file per table so views resolve before any data arrives.
func (s *Store) Init(ctx context.Context) error {
	if s.cfg.Mode != "ducklake" {
		var b strings.Builder
		for _, t := range Tables {
			cols := make([]string, 0, len(t.Columns))
			for _, c := range t.Columns {
				if c[0] != "day" {
					cols = append(cols, fmt.Sprintf("CAST(NULL AS %s) AS %s", c[1], c[0]))
				}
			}
			out := s.cfg.DataPath + t.Name + "/day=1970-01-01/_seed.parquet"
			if !strings.HasPrefix(out, "s3://") {
				if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
					return err
				}
			}
			fmt.Fprintf(&b, "COPY (SELECT %s WHERE false) TO %s (FORMAT parquet);\n", strings.Join(cols, ", "), lit(out))
		}
		_, err := s.run(ctx, s.setupWrite(), b.String(), false)
		return err
	}
	var b strings.Builder
	for _, t := range Tables {
		cols := make([]string, len(t.Columns))
		for i, c := range t.Columns {
			cols[i] = c[0] + " " + c[1]
		}
		fmt.Fprintf(&b, "CREATE TABLE IF NOT EXISTS %s (%s);\n", t.Name, strings.Join(cols, ", "))
	}
	_, err := s.run(ctx, s.setup(false), b.String(), false)
	return err
}

// Append writes rows (one JSON object per row) into a table. Rows are
// staged as NDJSON, then DuckDB converts them to compressed Parquet.
func (s *Store) Append(ctx context.Context, tableName string, rows []map[string]any) error {
	if len(rows) == 0 {
		return nil
	}
	t, ok := table(tableName)
	if !ok {
		return fmt.Errorf("unknown table %q", tableName)
	}
	f, err := os.CreateTemp("", "gjallar-"+tableName+"-*.ndjson")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	enc := json.NewEncoder(f)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			f.Close()
			return err
		}
	}
	f.Close()

	cols := make([]string, len(t.Columns))
	for i, c := range t.Columns {
		cols[i] = fmt.Sprintf("%s: %s", lit(c[0]), lit(c[1]))
	}
	src := fmt.Sprintf("read_json(%s, format='newline_delimited', columns={%s})", lit(f.Name()), strings.Join(cols, ", "))
	var sql string
	if s.cfg.Mode == "ducklake" {
		sql = fmt.Sprintf("INSERT INTO %s SELECT * FROM %s;", t.Name, src)
	} else {
		day := time.Now().UTC().Format("2006-01-02")
		out := fmt.Sprintf("%s%s/day=%s/%d.parquet", s.cfg.DataPath, t.Name, day, time.Now().UnixNano())
		if !strings.HasPrefix(out, "s3://") {
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				return err
			}
		}
		// day is a hive partition key; drop it from the file body.
		sql = fmt.Sprintf("COPY (SELECT * EXCLUDE (day) FROM %s) TO %s (FORMAT parquet, COMPRESSION zstd);", src, lit(out))
	}
	_, err = s.run(ctx, s.setupWrite(), sql, false)
	return err
}

// Maintain snapshots today's state and compacts files.
func (s *Store) Maintain(ctx context.Context, retainSnapshots time.Duration) error {
	snapshot := `
		SELECT current_date AS day, id, digest, repository, namespaces, vuln_id, package, severity, kev, risk, band, state, first_seen, fixed_at
		FROM (SELECT *, row_number() OVER (PARTITION BY id ORDER BY ts DESC) AS rn FROM finding_events) WHERE rn = 1`
	var sql string
	if s.cfg.Mode == "ducklake" {
		sql = fmt.Sprintf(`DELETE FROM finding_daily WHERE day = current_date;
INSERT INTO finding_daily %s;
CALL ducklake_merge_adjacent_files('lake');
CALL ducklake_expire_snapshots('lake', older_than => now() - INTERVAL '%d hours');
CALL ducklake_cleanup_old_files('lake', cleanup_all => true);`, snapshot, int(retainSnapshots.Hours()))
	} else {
		day := time.Now().UTC().Format("2006-01-02")
		out := fmt.Sprintf("%sfinding_daily/day=%s/snapshot.parquet", s.cfg.DataPath, day)
		if !strings.HasPrefix(out, "s3://") {
			_ = os.MkdirAll(filepath.Dir(out), 0o755)
		}
		sql = fmt.Sprintf("COPY (SELECT * EXCLUDE (day) FROM (%s)) TO %s (FORMAT parquet, COMPRESSION zstd);", snapshot, lit(out))
	}
	_, err := s.run(ctx, s.setup(false), sql, false)
	return err
}

// ---- Read side -------------------------------------------------------------

var (
	allowedStart = regexp.MustCompile(`(?is)^\s*(SELECT|WITH|FROM|DESCRIBE|SUMMARIZE|SHOW|PIVOT|UNPIVOT|VALUES)\b`)
	// Block anything that writes, reconfigures, or reads arbitrary files.
	forbidden = regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|MERGE|CREATE|DROP|ALTER|ATTACH|DETACH|COPY|EXPORT|IMPORT|INSTALL|LOAD|PRAGMA|SET|RESET|CALL|CHECKPOINT|VACUUM|USE|GRANT|SECRET|read_\w+|glob|getenv|parquet_\w+|sniff_csv|duckdb_secrets)\b`)
)

// ValidateQuery enforces read-only, single-statement SQL.
func ValidateQuery(q string) error {
	q = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(q), ";"))
	switch {
	case q == "":
		return fmt.Errorf("empty query")
	case strings.Contains(q, ";"):
		return fmt.Errorf("only one statement is allowed")
	case strings.Contains(q, "--") || strings.Contains(q, "/*"):
		return fmt.Errorf("comments are not allowed")
	case !allowedStart.MatchString(q):
		return fmt.Errorf("only read-only queries (SELECT, WITH, FROM, DESCRIBE, SUMMARIZE) are allowed")
	case forbidden.MatchString(q):
		return fmt.Errorf("query uses a forbidden keyword or function: %s", forbidden.FindString(q))
	}
	return nil
}

// Query runs a validated read-only query and returns rows as JSON objects.
// Results are capped at maxRows.
func (s *Store) Query(ctx context.Context, q string, maxRows int) ([]map[string]any, error) {
	if err := ValidateQuery(q); err != nil {
		return nil, err
	}
	if maxRows <= 0 || maxRows > 50000 {
		maxRows = 10000
	}
	q = strings.TrimSuffix(strings.TrimSpace(q), ";")
	body := q + ";"
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(q)), "DESCRIBE") && !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(q)), "SHOW") && !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(q)), "SUMMARIZE") {
		body = fmt.Sprintf("SELECT * FROM (%s) LIMIT %d;", q, maxRows)
	}
	out, err := s.run(ctx, s.setup(true), body, true)
	if err != nil {
		return nil, err
	}
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return []map[string]any{}, nil
	}
	var rows []map[string]any
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("decode duckdb output: %w", err)
	}
	return rows, nil
}

// ExportParquet writes a query result to a Parquet file for notebooks
// (pyarrow, polars, pandas read it as Arrow with zero conversion).
func (s *Store) ExportParquet(ctx context.Context, q, path string) error {
	if err := ValidateQuery(q); err != nil {
		return err
	}
	q = strings.TrimSuffix(strings.TrimSpace(q), ";")
	_, err := s.run(ctx, s.setup(true), fmt.Sprintf("COPY (%s) TO %s (FORMAT parquet, COMPRESSION zstd);", q, lit(path)), false)
	return err
}

// Reports are named, curated queries for dashboards and the MCP server.
var Reports = map[string]string{
	"risk_trend": `SELECT day, band, count(*) AS findings FROM finding_daily WHERE state = 'open'
		GROUP BY ALL ORDER BY day, band`,
	"time_to_fix": `SELECT unnest(namespaces) AS namespace, count(*) AS fixed,
		round(median(epoch(fixed_at - first_seen)) / 3600, 1) AS median_hours
		FROM finding_daily WHERE state = 'fixed' AND fixed_at IS NOT NULL GROUP BY ALL ORDER BY median_hours DESC`,
	"top_packages": `SELECT package, count(DISTINCT digest) AS images, count(*) AS findings, max(risk) AS max_risk
		FROM (SELECT *, row_number() OVER (PARTITION BY id ORDER BY ts DESC) rn FROM finding_events) WHERE rn = 1 AND state = 'open'
		GROUP BY package ORDER BY max_risk DESC, images DESC LIMIT 50`,
	"kev_exposure": `SELECT vuln_id, package, count(DISTINCT digest) AS images, list(DISTINCT repository) AS repositories
		FROM (SELECT *, row_number() OVER (PARTITION BY id ORDER BY ts DESC) rn FROM finding_events) WHERE rn = 1 AND state = 'open' AND kev
		GROUP BY ALL ORDER BY images DESC`,
	"license_denials": `SELECT license, count(DISTINCT package) AS packages, count(DISTINCT digest) AS images
		FROM package_licenses WHERE verdict = 'denied' GROUP BY license ORDER BY images DESC`,
	"posture_by_check": `SELECT check_id, severity, count(DISTINCT workload_id) AS workloads
		FROM posture_events WHERE day = (SELECT max(day) FROM posture_events) GROUP BY ALL ORDER BY workloads DESC`,
	"package_inventory": `SELECT package, count(DISTINCT digest) AS images, list(DISTINCT version) AS versions, list(DISTINCT repository) AS repositories
		FROM sbom_packages GROUP BY package ORDER BY images DESC LIMIT 200`,
	"runtime_effect": `SELECT runtime, band, count(*) AS findings, round(avg(risk), 1) AS avg_risk
		FROM (SELECT *, row_number() OVER (PARTITION BY id ORDER BY ts DESC) rn FROM risk_scores) WHERE rn = 1
		GROUP BY ALL ORDER BY runtime, band`,
	"runtime_loaded_packages": `SELECT package, count(DISTINCT digest) AS images, min(ts) AS first_seen_loading
		FROM runtime_loaded GROUP BY package ORDER BY images DESC LIMIT 200`,
}

// Report runs a named report.
func (s *Store) Report(ctx context.Context, name string) ([]map[string]any, error) {
	q, ok := Reports[name]
	if !ok {
		return nil, fmt.Errorf("unknown report %q", name)
	}
	return s.Query(ctx, q, 10000)
}

// ---- process plumbing ------------------------------------------------------

func (s *Store) run(ctx context.Context, setup, sql string, jsonOut bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	// Silence setup statements so only the query result reaches stdout.
	script := ".bail on\n.output /dev/null\n" + setup + ".output\n" + sql + "\n"
	args := []string{"-noheader"}
	if jsonOut {
		args = []string{"-json"}
	}
	args = append(args, ":memory:")
	cmd := exec.CommandContext(ctx, s.cfg.Bin, args...)
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = cleanEnv()
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("duckdb: %w: %s", err, strings.TrimSpace(errb.String()+" "+out.String()))
	}
	return out.Bytes(), nil
}

// cleanEnv drops variables that change DuckDB CLI output formatting.
func cleanEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "AI_AGENT=") || strings.HasPrefix(kv, "CLAUDECODE=") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

func lit(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func orDef(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
