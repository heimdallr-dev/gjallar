package flightsql

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/flight"
	fsql "github.com/apache/arrow-go/v18/arrow/flight/flightsql"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/apache/arrow-go/v18/parquet/pqarrow"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// fakeExport writes a two-row table, standing in for DuckDB's COPY ... TO parquet.
func fakeExport(_ context.Context, q, path string) error {
	schema := arrow.NewSchema([]arrow.Field{{Name: "vuln_id", Type: arrow.BinaryTypes.String}, {Name: "risk", Type: arrow.PrimitiveTypes.Int32}}, nil)
	b := array.NewRecordBuilder(memory.DefaultAllocator, schema)
	defer b.Release()
	b.Field(0).(*array.StringBuilder).AppendValues([]string{"CVE-2023-4863", "CVE-2099-0001"}, nil)
	b.Field(1).(*array.Int32Builder).AppendValues([]int32{88, 20}, nil)
	rec := b.NewRecord()
	defer rec.Release()
	tbl := array.NewTableFromRecords(schema, []arrow.Record{rec})
	defer tbl.Release()
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pqarrow.WriteTable(tbl, f, 1024, nil, pqarrow.DefaultWriterProps())
}

func TestFlightSQLQueryAndAuth(t *testing.T) {
	dir := t.TempDir()
	srv := New(fakeExport, dir)
	srv.Validate = func(q string) error {
		if q == "DROP TABLE x" {
			return errors.New("only read-only queries are allowed")
		}
		return nil
	}
	auth := func(_ context.Context, bearer string) error {
		if bearer != "good" {
			return errors.New("bad token")
		}
		return nil
	}
	fs := flight.NewServerWithMiddleware(nil, Interceptors(auth)...)
	fs.RegisterFlightService(fsql.NewFlightServer(srv))
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	fs.InitListener(lis)
	go fs.Serve()
	defer fs.Shutdown()

	cl, err := fsql.NewClient(lis.Addr().String(), nil, nil, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	if _, err := cl.Execute(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("no token must be rejected")
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer good")
	if _, err := cl.Execute(ctx, "DROP TABLE x"); err == nil {
		t.Fatal("write SQL must be rejected")
	}
	info, err := cl.Execute(ctx, "SELECT vuln_id, risk FROM finding_events")
	if err != nil {
		t.Fatal(err)
	}
	rdr, err := cl.DoGet(ctx, info.Endpoint[0].Ticket)
	if err != nil {
		t.Fatal(err)
	}
	defer rdr.Release()
	rows := 0
	for rdr.Next() {
		rec := rdr.Record()
		rows += int(rec.NumRows())
		if rec.Column(0).(*array.String).Value(0) != "CVE-2023-4863" || rec.Column(1).(*array.Int32).Value(0) != 88 {
			t.Fatalf("unexpected first row: %v", rec)
		}
	}
	if rows != 2 {
		t.Fatalf("rows = %d", rows)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("result files must be deleted after DoGet: %v", left)
	}
	if _, err := cl.DoGet(ctx, info.Endpoint[0].Ticket); err == nil {
		t.Fatal("a ticket is single-use")
	}
}
