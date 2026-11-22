// Package flightsql serves the lakehouse over Arrow Flight SQL, so notebooks
// (Python ADBC, pyarrow, Polars, DBeaver/JDBC) pull results as Arrow record
// batches instead of JSON. DuckDB writes each result to a temporary Parquet
// file (exact column types), which is streamed as Arrow and then deleted.
package flightsql

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/flight"
	"github.com/apache/arrow-go/v18/arrow/flight/flightsql"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/apache/arrow-go/v18/parquet/file"
	"github.com/apache/arrow-go/v18/parquet/pqarrow"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Exporter writes a read-only query result to a Parquet file (analytics.Store.ExportParquet).
type Exporter func(ctx context.Context, query, path string) error

// Authorizer checks the bearer token from the "authorization" header.
// nil = no authentication (dev only).
type Authorizer func(ctx context.Context, bearer string) error

// Server implements the Flight SQL statement API (ad-hoc queries).
type Server struct {
	flightsql.BaseServer
	Export   Exporter
	Validate func(query string) error // optional: reject non-read-only SQL up front
	Dir      string                   // temp folder for result files
	TTL      time.Duration

	mu      sync.Mutex
	results map[string]result
}

type result struct {
	path    string
	schema  *arrow.Schema
	created time.Time
}

// New returns a server keeping results for ttl between GetFlightInfo and DoGet.
func New(export Exporter, dir string) *Server {
	s := &Server{Export: export, Dir: dir, TTL: 10 * time.Minute, results: map[string]result{}}
	_ = s.RegisterSqlInfo(flightsql.SqlInfoFlightSqlServerName, "Gjallar lakehouse")
	_ = s.RegisterSqlInfo(flightsql.SqlInfoFlightSqlServerReadOnly, true)
	return s
}

// GetFlightInfoStatement runs the query and returns its schema and ticket.
func (s *Server) GetFlightInfoStatement(ctx context.Context, cmd flightsql.StatementQuery, desc *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	if s.Validate != nil {
		if err := s.Validate(cmd.GetQuery()); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}
	id := newID()
	path := filepath.Join(s.Dir, "gjallar-flight-"+id+".parquet")
	if err := s.Export(ctx, cmd.GetQuery(), path); err != nil {
		_ = os.Remove(path)
		return nil, status.Error(codes.Internal, err.Error())
	}
	schema, err := readSchema(path)
	if err != nil {
		_ = os.Remove(path)
		return nil, status.Error(codes.Internal, err.Error())
	}
	s.gc()
	s.mu.Lock()
	s.results[id] = result{path: path, schema: schema, created: time.Now()}
	s.mu.Unlock()
	tkt, err := flightsql.CreateStatementQueryTicket([]byte(id))
	if err != nil {
		return nil, err
	}
	return &flight.FlightInfo{
		Schema:           flight.SerializeSchema(schema, memory.DefaultAllocator),
		FlightDescriptor: desc,
		Endpoint:         []*flight.FlightEndpoint{{Ticket: &flight.Ticket{Ticket: tkt}}},
		TotalRecords:     -1, TotalBytes: -1,
	}, nil
}

// DoGetStatement streams a prepared result once, then deletes it.
func (s *Server) DoGetStatement(ctx context.Context, tkt flightsql.StatementQueryTicket) (*arrow.Schema, <-chan flight.StreamChunk, error) {
	id := string(tkt.GetStatementHandle())
	s.mu.Lock()
	r, ok := s.results[id]
	delete(s.results, id)
	s.mu.Unlock()
	if !ok {
		return nil, nil, status.Error(codes.NotFound, "unknown or expired ticket; call GetFlightInfo again")
	}
	f, err := file.OpenParquetFile(r.path, false)
	_ = os.Remove(r.path) // unlink now: the open file stays readable, and nothing is left behind if the client goes away
	if err != nil {
		return nil, nil, status.Error(codes.Internal, err.Error())
	}
	fr, err := pqarrow.NewFileReader(f, pqarrow.ArrowReadProperties{BatchSize: 64 * 1024}, memory.DefaultAllocator)
	if err != nil {
		f.Close()
		return nil, nil, status.Error(codes.Internal, err.Error())
	}
	rr, err := fr.GetRecordReader(ctx, nil, nil)
	if err != nil {
		f.Close()
		return nil, nil, status.Error(codes.Internal, err.Error())
	}
	ch := make(chan flight.StreamChunk)
	go func() {
		defer close(ch)
		defer f.Close()
		defer rr.Release()
		for rr.Next() {
			rec := rr.Record()
			rec.Retain()
			select {
			case ch <- flight.StreamChunk{Data: rec}:
			case <-ctx.Done():
				rec.Release()
				return
			}
		}
		if err := rr.Err(); err != nil {
			ch <- flight.StreamChunk{Err: err}
		}
	}()
	return rr.Schema(), ch, nil
}

// gc removes results nobody fetched.
func (s *Server) gc() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.results {
		if time.Since(r.created) > s.TTL {
			_ = os.Remove(r.path)
			delete(s.results, id)
		}
	}
}

func readSchema(path string) (*arrow.Schema, error) {
	f, err := file.OpenParquetFile(path, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fr, err := pqarrow.NewFileReader(f, pqarrow.ArrowReadProperties{}, memory.DefaultAllocator)
	if err != nil {
		return nil, err
	}
	return fr.Schema()
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Interceptors authenticate every call with a bearer token.
func Interceptors(auth Authorizer) []grpc.ServerOption {
	check := func(ctx context.Context) error {
		if auth == nil {
			return nil
		}
		md, _ := metadata.FromIncomingContext(ctx)
		var bearer string
		for _, v := range md.Get("authorization") {
			if t, ok := strings.CutPrefix(v, "Bearer "); ok {
				bearer = t
			}
		}
		if bearer == "" {
			return status.Error(codes.Unauthenticated, "missing bearer token")
		}
		if err := auth(ctx, bearer); err != nil {
			return status.Error(codes.PermissionDenied, err.Error())
		}
		return nil
	}
	return []grpc.ServerOption{
		grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			if err := check(ctx); err != nil {
				return nil, err
			}
			return h(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			if err := check(ss.Context()); err != nil {
				return err
			}
			return h(srv, ss)
		}),
	}
}

// Serve starts Flight SQL on addr until ctx ends.
func Serve(ctx context.Context, addr string, srv *Server, auth Authorizer) error {
	fs := flight.NewServerWithMiddleware(nil, Interceptors(auth)...)
	fs.RegisterFlightService(flightsql.NewFlightServer(srv))
	if err := fs.Init(addr); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		fs.Shutdown()
	}()
	return fs.Serve()
}
