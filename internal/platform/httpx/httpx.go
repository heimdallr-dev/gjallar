// Package httpx holds small HTTP helpers shared by Gjallar services.
package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/platform/telemetry"
)

// Env returns an environment variable or a default.
func Env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// EnvInt returns an integer environment variable or a default.
func EnvInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

// EnvBool returns a boolean environment variable or a default.
func EnvBool(key string, def bool) bool {
	if v, err := strconv.ParseBool(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

// SignalContext is cancelled on SIGINT/SIGTERM.
func SignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// JSON writes v with a status code.
func JSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// Error writes {"error": msg}.
func Error(w http.ResponseWriter, code int, msg string) {
	JSON(w, code, map[string]string{"error": msg})
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }

// Flush supports streaming responses through the middleware.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Observe adds tracing, access logs and request metrics.
func Observe(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := telemetry.Extract(r.Context(), r.Header)
		ctx, span := telemetry.Start(ctx, r.Method+" "+r.URL.Path, "http.method", r.Method, "http.route", r.URL.Path)
		rec := &statusRecorder{ResponseWriter: w, code: 200}
		next.ServeHTTP(rec, r.WithContext(ctx))
		var err error
		if rec.code >= 500 {
			err = errors.New(http.StatusText(rec.code))
		}
		span.End(err)
		route := r.Pattern
		if route == "" {
			route = "other"
		}
		telemetry.HTTPRequests.Inc(route, strconv.Itoa(rec.code/100)+"xx")
		if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" && r.URL.Path != "/metrics" {
			log.Info("http", "method", r.Method, "path", r.URL.Path, "code", rec.code, "ms", time.Since(start).Milliseconds(), "trace_id", telemetry.TraceID(ctx))
		}
	})
}

// Serve runs an HTTP server until ctx is cancelled, then shuts down gracefully.
func Serve(ctx context.Context, log *slog.Logger, addr string, h http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", addr)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		telemetry.Flush()
		return srv.Shutdown(sctx)
	}
}
