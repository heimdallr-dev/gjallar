package analytics

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestValidateQuery(t *testing.T) {
	ok := []string{
		"SELECT * FROM finding_events",
		"with x as (select 1) select * from x;",
		"FROM finding_daily SELECT day, count(*) GROUP BY ALL",
		"SUMMARIZE finding_events",
	}
	bad := []string{
		"", "DROP TABLE finding_events", "SELECT 1; DROP TABLE x", "SELECT * FROM read_csv('/etc/passwd')",
		"COPY finding_events TO '/tmp/x'", "SELECT getenv('HOME')", "ATTACH 'x' AS y", "SELECT 1 -- hi",
		"INSTALL httpfs", "SELECT * FROM glob('/**')", "SELECT * FROM duckdb_secrets()",
	}
	for _, q := range ok {
		if err := ValidateQuery(q); err != nil {
			t.Errorf("should allow %q: %v", q, err)
		}
	}
	for _, q := range bad {
		if ValidateQuery(q) == nil {
			t.Errorf("should reject %q", q)
		}
	}
}

// TestParquetRoundtrip exercises the real DuckDB CLI when it is installed.
func TestParquetRoundtrip(t *testing.T) {
	if _, err := exec.LookPath("duckdb"); err != nil {
		t.Skip("duckdb CLI not installed")
	}
	ctx := context.Background()
	s, err := New(Config{Mode: "parquet", DataPath: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Init(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	row := func(id, state string, risk int, kev bool) map[string]any {
		ts := now
		if state == "fixed" {
			ts = now.Add(time.Second)
		}
		return map[string]any{"ts": ts.Format(time.RFC3339Nano), "day": now.Format("2006-01-02"), "id": id, "digest": "sha256:aa",
			"repository": "harbor.local/shop/web", "namespaces": []string{"shop"}, "vuln_id": "CVE-" + id, "package": "openssl",
			"version": "3.0.11", "pkg_type": "deb", "severity": "high", "cvss": 7.5, "epss": 0.4, "kev": kev, "fixed_in": "3.0.13",
			"risk": risk, "band": "urgent", "state": state, "first_seen": now.Add(-48 * time.Hour).Format(time.RFC3339Nano),
			"fixed_at": nil, "db_version": "v6"}
	}
	if err := s.Append(ctx, "finding_events", []map[string]any{row("1", "open", 82, true), row("2", "open", 30, false)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ctx, "finding_events", []map[string]any{row("2", "fixed", 30, false)}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Report(ctx, "kev_exposure")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["vuln_id"] != "CVE-1" {
		t.Fatalf("kev_exposure: %+v", rows)
	}
	rows, err = s.Query(ctx, "SELECT count(*) AS n FROM finding_events", 10)
	if err != nil || len(rows) != 1 || rows[0]["n"] != float64(3) {
		t.Fatalf("count: %+v %v", rows, err)
	}
	if err := s.Maintain(ctx, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	rows, err = s.Query(ctx, "SELECT state, count(*) AS n FROM finding_daily GROUP BY ALL ORDER BY state", 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("daily snapshot: %+v %v", rows, err)
	}
	if _, err := s.Query(ctx, "DROP TABLE finding_events", 10); err == nil {
		t.Fatal("write query must be rejected")
	}
}

// Even with the keyword check bypassed, a read session cannot reach files
// outside the lake, nor unlock itself.
func TestReadSessionSandbox(t *testing.T) {
	if _, err := exec.LookPath("duckdb"); err != nil {
		t.Skip("duckdb CLI not on PATH")
	}
	s, err := New(Config{Mode: "parquet", DataPath: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, q := range []string{
		"SELECT count(*) FROM read_csv('/etc/passwd');",
		"SET enable_external_access=true; SELECT 1;",
	} {
		if _, err := s.run(ctx, s.setup(true), q, true); err == nil {
			t.Errorf("sandbox let through: %s", q)
		}
	}
}
