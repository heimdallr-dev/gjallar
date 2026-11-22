package natsbus

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/heimdallr-dev/gjallar/internal/platform/telemetry"
)

// Needs a token-protected NATS (GJALLAR_TEST_NATS_AUTH_URL); skipped otherwise.
func TestTokenAuth(t *testing.T) {
	url := os.Getenv("GJALLAR_TEST_NATS_AUTH_URL")
	if url == "" {
		t.Skip("set GJALLAR_TEST_NATS_AUTH_URL")
	}
	if nc, err := nats.Connect(url, nats.Timeout(2*time.Second)); err == nil {
		nc.Close()
		t.Fatal("connect without token must fail")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	t.Setenv("GJALLAR_NATS_TOKEN", "s3cret")
	b, err := Connect(ctx, url, "auth-test", telemetry.NewLogger("t"))
	if err != nil {
		t.Fatalf("connect with token: %v", err)
	}
	b.Close()
}
