# ᚷ Gjallar

**Kubernetes vulnerability, license and posture platform that ranks findings by real risk.**

> **Security without chains.** See clearly, understand why, and stay free to choose. Gjallar sounds the horn when danger is real; what you do next is always yours. ([The Gjallar Philosophy](https://github.com/heimdallr-dev/gjallar-docs/blob/main/docs/philosophy.md))

Named after *Gjallarhorn*, the horn Heimdall sounds when danger approaches Asgard.
Gjallar watches every image running in your clusters and tells you which 20
findings matter, out of the 4,000 a scanner reports.

```
RISK  BAND    VULN                 PACKAGE         FIX                WHERE
88    urgent  CVE-2023-4863 [KEV]  libwebp7 1.2.4  1.2.4-0.2+deb12u1  shop/web
20    medium  CVE-2099-0001        openssl 3.0.11  –                  shop/web
```

The critical CVE ranks *below* the high one: nobody is exploiting it, and the high one is
in CISA KEV, has a fix, and sits behind an Ingress.

## Why another tool

| | Kubescape-style scanners | Gjallar |
|---|---|---|
| Scanning | Re-pull and re-scan images | **Syft once per digest**; Grype re-matches stored SBOMs when the DB updates, with no image pulls |
| Prioritisation | CVSS / severity | **Risk score** = CVSS × (KEV or EPSS) × runtime × exposure, with reasons |
| Architecture | Monolithic operator | **Hexagonal core + event-driven workers** on NATS JetStream; every engine is a plug-in worker |
| Scale | Per-cluster | **Hub + outbound-only agents**; workers scale to zero with KEDA |
| Analytics | Current state only | **Lakehouse** (DuckDB + Parquet / DuckLake): trends, time-to-fix, history, SQL |
| Interfaces | CLI, CRDs | Web UI, REST, **MCP server for AI assistants**, CLI with CI gate |
| Identity | — | **Keycloak OIDC** (PKCE web, device-flow CLI, role-based writes) |
| Enforcement | Separate | **Kyverno** asks Gjallar at admission; OpenVEX for accepted risks |

## Components (each one is its own pod)

| Pod | What it does |
|---|---|
| `gjallar-api` | Hub: REST API plus the event consumers that drive the core |
| `gjallar-worker-sbom` | Syft: image → SBOM, stored in the NATS object store by digest |
| `gjallar-worker-vuln` | Grype: SBOM → findings, using your in-cluster DB mirror |
| `gjallar-worker-license` | License policy over Syft's license data, optional Grant second opinion |
| `gjallar-worker-patch` | Copa + rootless BuildKit: patch OS packages, push `:tag-patched` |
| `gjallar-agent` | One per cluster: running workloads, digests, exposure, security context; optional runtime mode records which packages load (Inspektor Gadget) |
| `gjallar-analytics` | Event stream → Parquet/DuckLake; read-only SQL, reports, Parquet export |
| `gjallar-web` | Single-page UI (no build step), OIDC PKCE login |
| `gjallar-mcp` | Model Context Protocol server: 9 tools, forwards the caller's token |
| `nats`, `postgres`, `grype-db` | JetStream bus/KV/object store, operational DB, Grype DB mirror |
| CronJobs | DB refresh + rematch, analytics snapshot/compaction, backup, Vunnel build |

## Quick start

**On your machine (WSL2 + Docker):**
```bash
make build dev                              # CLI into ./bin, images + stack in Docker
GJALLAR_URL=http://localhost:8080 bin/gjallar submit nginx:1.27
open http://localhost:8083
```

**WSL2 with containerd instead of Docker** (nerdctl + BuildKit, optional kind cluster):
```bash
make build images BUILDER=nerdctl
scripts/kind-dev.sh up                      # local Kubernetes with Gjallar installed
```

**CI gate, no server needed** (Syft and Grype on PATH):
```bash
gjallar scan registry.example.com/app:1.4 --fail-on urgent    # exit 3 on urgent findings
```

**On Kubernetes:**
```bash
make push   REGISTRY=harbor.local/gjallar
make deploy REGISTRY=harbor.local/gjallar HELM_ARGS="-f my-values.yaml"
```

The full walkthrough, from a fresh WSL install to a running cluster deployment, is in
[install-wsl.md](https://github.com/heimdallr-dev/gjallar-docs/blob/main/docs/install-wsl.md).

## Repositories

| Repo | What |
|---|---|
| [gjallar](https://github.com/heimdallr-dev/gjallar) | Core: every service, CLI, web UI, Dockerfile, tests (this repo) |
| [gjallar-helm](https://github.com/heimdallr-dev/gjallar-helm) | Helm chart, Kyverno policies, Keycloak realm |
| [gjallar-docs](https://github.com/heimdallr-dev/gjallar-docs) | Documentation site |
| [gjallar-grafana](https://github.com/heimdallr-dev/gjallar-grafana) | Dashboards and alert rules |
| [gjallar-analytics](https://github.com/heimdallr-dev/gjallar-analytics) | Notebooks, SQL and Flight SQL/DuckLake examples |
| [gjallar-vunnel](https://github.com/heimdallr-dev/gjallar-vunnel) | Build the Grype vulnerability DB yourself (fork of anchore/vunnel) |
| [gjallar-mcp](https://github.com/heimdallr-dev/gjallar-mcp) | Connect AI assistants (MCP): client configs, tools, safety model |
| [gjallar-opa](https://github.com/heimdallr-dev/gjallar-opa) | Gjallar policies as plain Rego for OPA, Conftest, Gatekeeper; CI gate |
| [gjallar-e2e](https://github.com/heimdallr-dev/gjallar-e2e) | Cluster-level end-to-end suites (kind, Playwright) |
| [gjallar-skills](https://github.com/heimdallr-dev/gjallar-skills) | Agent skills: the Gjallar Philosophy, triage, contributing (Claude Code plugin) |
| [gjallar-web](https://github.com/heimdallr-dev/gjallar-web) | Future standalone UI (today the UI ships inside this repo) |

For local work, clone `gjallar` and `gjallar-helm` side by side.

## Documentation

| Doc | |
|---|---|
| [Architecture](https://github.com/heimdallr-dev/gjallar-docs/blob/main/docs/architecture.md) | Hexagonal layout, bounded contexts, event flow, risk formula |
| [Install: WSL → Kubernetes](https://github.com/heimdallr-dev/gjallar-docs/blob/main/docs/install-wsl.md) | Build, test, images, Helm, Keycloak, Kyverno |
| [Configuration](https://github.com/heimdallr-dev/gjallar-docs/blob/main/docs/configuration.md) | Every environment variable and the important Helm values |
| [Operations](https://github.com/heimdallr-dev/gjallar-docs/blob/main/docs/operations.md) | CronJobs, DB mirror, scaling, backups, upgrades, troubleshooting |
| [Analytics](https://github.com/heimdallr-dev/gjallar-docs/blob/main/docs/analytics.md) | Tables, DuckLake vs Parquet, SQL, notebooks |
| [Interfaces](https://github.com/heimdallr-dev/gjallar-docs/blob/main/docs/interfaces.md) | REST API, MCP tools, CLI reference |
| [Development](https://github.com/heimdallr-dev/gjallar-docs/blob/main/docs/development.md) | Code layout, adding an engine, tests |
| [Philosophy](https://github.com/heimdallr-dev/gjallar-docs/blob/main/docs/philosophy.md) | The nine freedoms every change is held to |
| [Security policy](SECURITY.md) | Reporting vulnerabilities, verifying releases |
| [Status and roadmap](https://github.com/heimdallr-dev/gjallar-docs/blob/main/docs/roadmap.md) | What is done, verified, open, next |
| [Verification report 2026-11](https://github.com/heimdallr-dev/gjallar-docs/blob/main/docs/verification-2026-11.md) | First real-environment run: results, defects fixed, environment findings |

## License

Apache-2.0. Gjallar orchestrates [Syft](https://github.com/anchore/syft),
[Grype](https://github.com/anchore/grype), [Grant](https://github.com/anchore/grant),
[Vunnel](https://github.com/anchore/vunnel), [Copacetic](https://github.com/project-copacetic/copacetic),
[NATS](https://nats.io), [DuckDB](https://duckdb.org)/[DuckLake](https://ducklake.select),
[Keycloak](https://www.keycloak.org) and [Kyverno](https://kyverno.io). Each keeps its own license.
