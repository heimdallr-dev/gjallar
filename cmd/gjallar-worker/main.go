// gjallar-worker runs one engine role, pulling jobs from the JetStream work
// queue. Scale each role with KEDA on queue depth (scale to zero when idle).
//
//	gjallar-worker sbom     # Syft
//	gjallar-worker vuln     # Grype (reads stored SBOMs; uses GRYPE_DB_UPDATE_URL)
//	gjallar-worker license  # built-in policy, optionally Grant
//	gjallar-worker patch    # Copa + BuildKit
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/adapters/natsbus"
	"github.com/heimdallr-dev/gjallar/internal/adapters/scanner"
	"github.com/heimdallr-dev/gjallar/internal/app"
	"github.com/heimdallr-dev/gjallar/internal/domain"
	"github.com/heimdallr-dev/gjallar/internal/platform/httpx"
	"github.com/heimdallr-dev/gjallar/internal/platform/telemetry"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gjallar-worker sbom|vuln|license|patch")
		os.Exit(2)
	}
	role := os.Args[1]
	log := telemetry.NewLogger("gjallar-worker-"+role).With("version", version)
	if err := run(role, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(role string, log *slog.Logger) error {
	ctx, cancel := httpx.SignalContext()
	defer cancel()
	bus, err := natsbus.Connect(ctx, httpx.Env("GJALLAR_NATS_URL", "nats://localhost:4222"), "gjallar-worker-"+role, log)
	if err != nil {
		return err
	}
	defer bus.Close()

	var subject string
	var h natsbus.Handler
	ackWait := 10 * time.Minute
	switch role {
	case "sbom":
		subject = domain.SubjJobSBOM
		syft := scanner.Syft{Source: httpx.Env("GJALLAR_SYFT_SOURCE", "registry"), Scope: os.Getenv("GJALLAR_SYFT_SCOPE")}
		w := app.SBOMWorker{Gen: syft, Convert: syft, Store: bus, Bus: bus}
		if repos := os.Getenv("GJALLAR_ATTEST_REPOS"); repos != "" {
			w.AttestRepos = strings.Split(repos, ",")
			w.Attest = scanner.Cosign{Key: httpx.Env("GJALLAR_COSIGN_KEY", "env://COSIGN_PRIVATE_KEY"), Insecure: httpx.EnvBool("GJALLAR_COSIGN_INSECURE", false)}
			// Same signer for accepted risks: OpenVEX attestations next to the image.
			vw := app.VEXWorker{Attest: w.Attest, AttestRepos: w.AttestRepos}
			go func() {
				if err := bus.Consume(ctx, natsbus.ConsumeOpts{Stream: natsbus.StreamJobs, Durable: "worker-vex", Subjects: []string{domain.SubjJobVEX},
					AckWait: 5 * time.Minute, MaxDeliver: 4, Parallel: 1}, natsbus.JSON(vw.Handle)); err != nil {
					log.Error("vex consumer stopped", "err", err)
				}
			}()
		}
		h = natsbus.JSON(w.Handle)
	case "vuln":
		subject = domain.SubjJobVuln
		w := app.VulnWorker{Matcher: scanner.Grype{}, Store: bus, Bus: bus}
		if httpx.Env("GJALLAR_MATCHER", "grype") == "trivy" {
			w.Matcher, w.Input = scanner.Trivy{CacheDir: httpx.Env("TRIVY_CACHE_DIR", "/tmp/trivy"), DBRepository: os.Getenv("TRIVY_DB_REPOSITORY")}, "cyclonedx-json"
		}
		if httpx.EnvBool("GJALLAR_OSV", false) {
			w.Second = scanner.OSV{CacheDir: httpx.Env("GJALLAR_OSV_CACHE", "/tmp/osv-db")}
		}
		h = natsbus.JSON(w.Handle)
		ackWait = 5 * time.Minute
	case "license":
		subject = domain.SubjJobLicense
		pol, err := loadPolicy(os.Getenv("GJALLAR_LICENSE_POLICY"))
		if err != nil {
			return err
		}
		var checker app.LicenseChecker = scanner.BuiltinLicenses{}
		if cfg := os.Getenv("GJALLAR_GRANT_CONFIG"); cfg != "" {
			checker = scanner.Grant{ConfigPath: cfg}
		}
		w := app.LicenseWorker{Checker: checker, Parse: scanner.ParseSyftJSON, Store: bus, Bus: bus, Policy: pol}
		h = natsbus.JSON(w.Handle)
		ackWait = 2 * time.Minute
	case "patch":
		subject = domain.SubjJobPatch
		w := app.PatchWorker{Patcher: scanner.Copa{
			BuildkitAddr: os.Getenv("GJALLAR_BUILDKIT_ADDR"), Scanner: httpx.Env("GJALLAR_COPA_SCANNER", "trivy"),
			TagSuffix: httpx.Env("GJALLAR_COPA_TAG_SUFFIX", "-patched"), Push: httpx.EnvBool("GJALLAR_COPA_PUSH", true),
			TargetRepo: os.Getenv("GJALLAR_COPA_TARGET_REPO"), Timeout: httpx.Env("GJALLAR_COPA_TIMEOUT", "20m"),
		}, Bus: bus}
		h = natsbus.JSON(w.Handle)
		ackWait = 30 * time.Minute
	default:
		return fmt.Errorf("unknown role %q", role)
	}

	// Liveness + metrics for KEDA/Prometheus.
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
		mux.Handle("GET /metrics", telemetry.MetricsHandler())
		_ = httpx.Serve(ctx, log, httpx.Env("GJALLAR_HTTP_ADDR", ":9090"), mux)
	}()

	log.Info("worker started", "role", role, "subject", subject)
	return bus.Consume(ctx, natsbus.ConsumeOpts{
		Stream: natsbus.StreamJobs, Durable: "worker-" + role, Subjects: []string{subject},
		AckWait: ackWait, MaxDeliver: httpx.EnvInt("GJALLAR_MAX_DELIVER", 4), Parallel: httpx.EnvInt("GJALLAR_CONCURRENCY", 2),
	}, h)
}

func loadPolicy(path string) (domain.LicensePolicy, error) {
	if path == "" {
		return domain.DefaultLicensePolicy(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return domain.LicensePolicy{}, err
	}
	var p domain.LicensePolicy
	if err := json.Unmarshal(b, &p); err != nil {
		return p, fmt.Errorf("license policy %s: %w", path, err)
	}
	return p, nil
}
