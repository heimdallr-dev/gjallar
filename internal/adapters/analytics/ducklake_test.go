package analytics

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestDuckLakeEvolveAndFlush: a lake made by an older version gains new
// columns on Init, and Maintain moves rows inlined in the catalog out to
// Parquet files. Needs the duckdb CLI with the ducklake extension.
func TestDuckLakeEvolveAndFlush(t *testing.T) {
	if _, err := exec.LookPath("duckdb"); err != nil {
		t.Skip("duckdb CLI not installed")
	}
	ctx := context.Background()
	dir := t.TempDir()
	s, err := New(Config{Mode: "ducklake", Catalog: filepath.Join(dir, "meta.ducklake"), DataPath: filepath.Join(dir, "data") + "/"})
	if err != nil {
		t.Fatal(err)
	}
	// An "old" lake: finding_events without the source column.
	if _, err := s.run(ctx, s.setup(false), "CREATE TABLE finding_events (ts TIMESTAMPTZ, day DATE, id VARCHAR);", false); err != nil {
		t.Fatal(err)
	}
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init on old lake: %v", err)
	}
	now := time.Now().UTC()
	if err := s.Append(ctx, "finding_events", []map[string]any{{"ts": now.Format(time.RFC3339Nano), "day": now.Format("2006-01-02"),
		"id": "1", "vuln_id": "CVE-1", "package": "openssl", "state": "open", "source": "osv"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Maintain(ctx, 24*time.Hour); err != nil {
		t.Fatalf("maintain: %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "data", "main", "finding_events", "*.parquet"))
	if len(files) == 0 {
		t.Fatal("after Maintain the rows must be in Parquet, not only inlined in the catalog")
	}
	rows, err := s.Query(ctx, "SELECT source FROM finding_events WHERE id = '1'", 10)
	if err != nil || len(rows) != 1 || rows[0]["source"] != "osv" {
		t.Fatalf("source column: %+v %v", rows, err)
	}
}
