// gjallar-api is the hub: REST API plus the event consumers that drive the
// core (inventory in, worker results in, jobs out). Run 2+ replicas; JetStream
// load-balances the durable consumers and Postgres claims are atomic.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/adapters/dtrack"
	"github.com/heimdallr-dev/gjallar/internal/adapters/harbor"
	"github.com/heimdallr-dev/gjallar/internal/adapters/httpapi"
	"github.com/heimdallr-dev/gjallar/internal/adapters/memory"
	"github.com/heimdallr-dev/gjallar/internal/adapters/natsbus"
	"github.com/heimdallr-dev/gjallar/internal/adapters/notify"
	"github.com/heimdallr-dev/gjallar/internal/adapters/oidc"
	"github.com/heimdallr-dev/gjallar/internal/adapters/postgres"
	"github.com/heimdallr-dev/gjallar/internal/adapters/registry"
	"github.com/heimdallr-dev/gjallar/internal/app"
	"github.com/heimdallr-dev/gjallar/internal/domain"
	"github.com/heimdallr-dev/gjallar/internal/platform/httpx"
	"github.com/heimdallr-dev/gjallar/internal/platform/telemetry"
)

var version = "dev"

func main() {
	log := telemetry.NewLogger("gjallar-api")
	httpapi.Version = version
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, cancel := httpx.SignalContext()
	defer cancel()

	bus, err := natsbus.Connect(ctx, httpx.Env("GJALLAR_NATS_URL", "nats://localhost:4222"), "gjallar-api", log)
	if err != nil {
		return err
	}
	defer bus.Close()

	var repo app.Repository
	ready := func() error { return nil }
	if dsn := os.Getenv("GJALLAR_DATABASE_URL"); dsn != "" {
		pg, err := postgres.Open(ctx, dsn)
		if err != nil {
			return err
		}
		defer pg.Close()
		repo = pg
		ready = func() error { return pg.Ping(context.Background()) }
	} else {
		log.Warn("GJALLAR_DATABASE_URL not set: using in-memory store (dev only, data is lost on restart)")
		repo = memory.NewRepo()
	}

	var rt app.RuntimeSignal = app.NoRuntime{}
	if httpx.EnvBool("GJALLAR_RUNTIME_ENABLED", true) {
		if kv, err := bus.Runtime(ctx); err == nil {
			rt = kv
		} else {
			log.Warn("runtime bucket unavailable", "err", err)
		}
	}
	hub := app.NewHub(repo, bus, rt, log)

	// Event consumers drive the core.
	consume := func(durable, subj string, h natsbus.Handler) {
		go func() {
			if err := bus.Consume(ctx, natsbus.ConsumeOpts{Stream: natsbus.StreamEvents, Durable: durable, Subjects: []string{subj}, AckWait: time.Minute, Parallel: 4}, h); err != nil {
				log.Error("consumer stopped", "durable", durable, "err", err)
				cancel()
			}
		}()
	}
	consume("hub-inventory", domain.SubjInventory, natsbus.JSON(hub.HandleInventory))
	consume("hub-sbom", domain.SubjSBOMDone, natsbus.JSON(hub.HandleSBOM))
	consume("hub-vuln", domain.SubjVulnDone, natsbus.JSON(hub.HandleFindings))
	consume("hub-license", domain.SubjLicDone, natsbus.JSON(hub.HandleLicenses))
	consume("hub-patch", domain.SubjPatchDone, natsbus.JSON(hub.HandlePatch))
	if cfg := os.Getenv("GJALLAR_NOTIFY"); cfg != "" {
		var targets []app.NotifyTarget
		if err := json.Unmarshal([]byte(cfg), &targets); err != nil {
			return fmt.Errorf("GJALLAR_NOTIFY: %w", err)
		}
		ledger, err := bus.Ledger(ctx, 90*24*time.Hour)
		if err != nil {
			return err
		}
		n := &app.Notifier{Repo: repo, Ledger: ledger, Sender: notify.Webhook{LinkURL: os.Getenv("GJALLAR_PUBLIC_URL")}, Targets: targets}
		consume("hub-notify", domain.SubjScored, natsbus.JSON(n.HandleScored))
		log.Info("notifications on", "targets", len(targets))
	}
	// Opt-in export of every new SBOM (CycloneDX 1.6) to Dependency-Track.
	if u := os.Getenv("GJALLAR_DTRACK_URL"); u != "" {
		dt := dtrack.Client{URL: u, APIKey: os.Getenv("GJALLAR_DTRACK_API_KEY")}
		consume("hub-dtrack", domain.SubjSBOMDone, natsbus.JSON(func(ctx context.Context, ev domain.SBOMGenerated) error {
			if ev.Error != "" {
				return nil
			}
			cdx, err := bus.Get(ctx, app.SBOMKey(ev.Digest, "cyclonedx-json"))
			if errors.Is(err, app.ErrNotFound) {
				return nil // conversion not available for this image
			}
			if err != nil {
				return err
			}
			version := ev.Image.Tag
			if version == "" {
				version = string(ev.Digest)
			}
			_, err = dt.Upload(ctx, ev.Image.Repository, version, cdx)
			return err
		}))
		log.Info("dependency-track export on", "url", u)
	}

	// Registry discovery: Harbor's API, and/or any OCI Distribution registry.
	var catalogs []app.RegistryCatalog
	if u := os.Getenv("GJALLAR_HARBOR_URL"); u != "" {
		catalogs = append(catalogs, harbor.Catalog{URL: u, Projects: strings.Split(os.Getenv("GJALLAR_HARBOR_PROJECTS"), ","),
			User: os.Getenv("GJALLAR_HARBOR_USER"), Password: os.Getenv("GJALLAR_HARBOR_PASSWORD"), MaxPerRepo: httpx.EnvInt("GJALLAR_HARBOR_MAX_PER_REPO", 20)})
	}
	if u := os.Getenv("GJALLAR_REGISTRY_URL"); u != "" {
		var repos []string
		if r := os.Getenv("GJALLAR_REGISTRY_REPOSITORIES"); r != "" {
			repos = strings.Split(r, ",")
		}
		catalogs = append(catalogs, &registry.Catalog{URL: u, Repositories: repos, User: os.Getenv("GJALLAR_REGISTRY_USER"),
			Password: os.Getenv("GJALLAR_REGISTRY_PASSWORD"), MaxTags: httpx.EnvInt("GJALLAR_REGISTRY_MAX_TAGS", 20)})
	}
	if len(catalogs) > 0 {
		every, err := time.ParseDuration(httpx.Env("GJALLAR_DISCOVERY_INTERVAL", "1h"))
		if err != nil {
			return fmt.Errorf("GJALLAR_DISCOVERY_INTERVAL: %w", err)
		}
		go func() {
			for {
				for _, c := range catalogs {
					n, err := (&app.RegistryDiscovery{Catalog: c, Hub: hub, Log: log}).Run(ctx)
					if err != nil && ctx.Err() == nil {
						log.Warn("registry discovery", "err", err)
					}
					log.Info("registry discovery pass", "queued", n)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(every):
				}
			}
		}()
	}
	consume("hub-dbupdated", domain.SubjDBUpdated, func(ctx context.Context, _ []byte) error {
		n, err := hub.Rematch(ctx)
		log.Info("rematch after db update", "images", n, "err", err)
		return err
	})

	// Summary gauges for Prometheus / Grafana.
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			if err := httpapi.RefreshMetrics(ctx, repo); err != nil && ctx.Err() == nil {
				log.Warn("metrics refresh", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	auth := oidc.Auth{AdminRole: httpx.Env("GJALLAR_OIDC_ADMIN_ROLE", "gjallar-admin"), ViewerRole: os.Getenv("GJALLAR_OIDC_VIEWER_ROLE"), OpenPaths: map[string]bool{}}
	if httpx.EnvBool("GJALLAR_ADMISSION_OPEN", false) {
		auth.OpenPaths["/api/v1/admission"] = true // Kyverno apiCall; restrict with a NetworkPolicy
	}
	if iss := os.Getenv("GJALLAR_OIDC_ISSUER"); iss != "" {
		auth.Verifier = oidc.NewVerifier(iss, httpx.Env("GJALLAR_OIDC_CLIENT_ID", "gjallar"))
	} else {
		log.Warn("GJALLAR_OIDC_ISSUER not set: authentication is DISABLED (dev only)")
	}
	api := &httpapi.API{Hub: hub, Repo: repo, Auth: auth, Ready: ready, Log: log, SBOMs: bus}
	if u := os.Getenv("GJALLAR_ANALYTICS_URL"); u != "" {
		if api.Analytics, err = url.Parse(u); err != nil {
			return err
		}
	}
	if cfg := os.Getenv("GJALLAR_TENANTS"); cfg != "" {
		api.Tenancy = &app.Tenancy{GlobalRoles: strings.Split(httpx.Env("GJALLAR_TENANCY_GLOBAL_ROLES", httpx.Env("GJALLAR_OIDC_ADMIN_ROLE", "gjallar-admin")), ",")}
		if err := json.Unmarshal([]byte(cfg), &api.Tenancy.Groups); err != nil {
			return fmt.Errorf("GJALLAR_TENANTS: %w", err)
		}
		log.Info("multi-tenancy on", "groups", len(api.Tenancy.Groups), "global_roles", api.Tenancy.GlobalRoles)
	}
	return httpx.Serve(ctx, log, httpx.Env("GJALLAR_HTTP_ADDR", ":8080"), api.Handler())
}
