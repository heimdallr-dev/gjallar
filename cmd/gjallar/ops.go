package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/adapters/k8s"
	"github.com/heimdallr-dev/gjallar/internal/adapters/natsbus"
	"github.com/heimdallr-dev/gjallar/internal/domain"
	"github.com/heimdallr-dev/gjallar/internal/platform/telemetry"
)

// ops refresh-db is what the daily CronJob runs in-cluster:
//  1. rolling-restart the Grype DB mirror (it pulls the newest DB image),
//  2. wait until the rollout is done and the listing answers,
//  3. publish db_updated on NATS so the hub re-matches every stored SBOM.
func ops(ctx context.Context, args []string, out io.Writer) (int, error) {
	if len(args) == 0 || args[0] != "refresh-db" {
		return 2, fmt.Errorf("usage: gjallar ops refresh-db [--namespace ns] [--deployment name] [--mirror-url url] [--nats url]")
	}
	fs := flag.NewFlagSet("refresh-db", flag.ContinueOnError)
	ns := fs.String("namespace", os.Getenv("POD_NAMESPACE"), "namespace of the mirror deployment")
	dep := fs.String("deployment", "gjallar-grype-db", "mirror deployment name (empty: skip restart)")
	mirror := fs.String("mirror-url", "http://gjallar-grype-db:8080/databases/v6/latest.json", "listing URL to probe")
	natsURL := fs.String("nats", envOr("GJALLAR_NATS_URL", "nats://gjallar-nats:4222"), "NATS URL")
	timeout := fs.Duration("timeout", 15*time.Minute, "overall timeout")
	if err := fs.Parse(args[1:]); err != nil {
		return 2, err
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	if *dep != "" {
		kc, err := k8s.InCluster()
		if err != nil {
			return 1, err
		}
		if err := kc.RestartDeployment(ctx, *ns, *dep); err != nil {
			return 1, err
		}
		fmt.Fprintf(out, "restarted %s/%s\n", *ns, *dep)
		time.Sleep(5 * time.Second)
		if err := poll(ctx, func() bool { ok, _ := kc.DeploymentRolledOut(ctx, *ns, *dep); return ok }); err != nil {
			return 1, fmt.Errorf("waiting for rollout: %w", err)
		}
	}
	if *mirror != "" {
		if err := poll(ctx, func() bool {
			resp, err := http.Get(*mirror)
			if err != nil {
				return false
			}
			resp.Body.Close()
			return resp.StatusCode == http.StatusOK
		}); err != nil {
			return 1, fmt.Errorf("mirror never answered %s: %w", *mirror, err)
		}
	}
	bus, err := natsbus.Connect(ctx, *natsURL, "gjallar-ops", telemetry.NewLogger("gjallar-ops"))
	if err != nil {
		return 1, err
	}
	defer bus.Close()
	if err := bus.Publish(ctx, domain.SubjDBUpdated, map[string]any{"at": time.Now().UTC(), "mirror": *mirror}); err != nil {
		return 1, err
	}
	fmt.Fprintln(out, "db_updated published; the hub will re-match all stored SBOMs")
	return 0, nil
}

func poll(ctx context.Context, ok func() bool) error {
	for {
		if ok() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
