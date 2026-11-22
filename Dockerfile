# syntax=docker/dockerfile:1.7
# One Dockerfile, one target per component:
#   docker build --target api -t gjallar-api .
# Targets: api, agent, mcp, analytics, worker-sbom, worker-vuln,
#          worker-license, worker-patch, cli
# The web UI is built in github.com/heimdallr-dev/gjallar-web.
# Everything Go is static (CGO off). Core services run on distroless as
# non-root; each worker image carries only the engine it needs.

ARG GO_VERSION=1.26.11
ARG SYFT_VERSION=1.57.2
ARG GRYPE_VERSION=0.122.1
ARG GRANT_VERSION=0.8.0
ARG COPA_VERSION=0.15.0
# 0.69.4–0.69.6 were malicious (CVE-2026-33634). Only move to a release you have verified.
ARG TRIVY_VERSION=0.69.3
ARG DUCKDB_VERSION=2.0.1
ARG GADGET_VERSION=0.58.0
ARG COSIGN_VERSION=2.4.1
ARG OSV_SCANNER_VERSION=2.7.0
ARG OPA_VERSION=1.4.2
# Kubescape publishes the library under a moving "v2" release; files are checked against its checksums.txt.
ARG REGOLIBRARY_VERSION=v2

# ---------------------------------------------------------------- build
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -mod=vendor -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/ ./cmd/...

# ---------------------------------------------------------------- core services
FROM gcr.io/distroless/static-debian12:nonroot AS distroless

FROM distroless AS api
COPY --from=build /out/gjallar-api /gjallar-api
EXPOSE 8080
ENTRYPOINT ["/gjallar-api"]

FROM alpine:3.22 AS fetch-gadget
ARG GADGET_VERSION TARGETARCH
RUN set -eux; apk add --no-cache curl; cd /tmp; \
    F="kubectl-gadget-linux-${TARGETARCH}-v${GADGET_VERSION}.tar.gz"; \
    curl -sSfLO "https://github.com/inspektor-gadget/inspektor-gadget/releases/download/v${GADGET_VERSION}/${F}"; \
    curl -sSfLO "https://github.com/inspektor-gadget/inspektor-gadget/releases/download/v${GADGET_VERSION}/SHA256SUMS"; \
    grep " ${F}\$" SHA256SUMS | sha256sum -c -; \
    tar -xzf "$F" -C /usr/local/bin kubectl-gadget

FROM alpine:3.22 AS fetch-policy
ARG OPA_VERSION REGOLIBRARY_VERSION TARGETARCH
RUN set -eux; apk add --no-cache curl; mkdir -p /out/regolibrary; cd /tmp; \
    curl -sSfL -o opa "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_${TARGETARCH}_static"; \
    echo "$(curl -sSfL "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_${TARGETARCH}_static.sha256" | cut -d' ' -f1)  opa" | sha256sum -c -; \
    install -m 0755 opa /out/opa; \
    cd /out/regolibrary; base="https://github.com/kubescape/regolibrary/releases/download/${REGOLIBRARY_VERSION}"; \
    curl -sSfLO "$base/checksums.txt"; \
    for f in rules controls default_config_inputs; do curl -sSfLO "$base/$f"; grep " $f\$" checksums.txt | sha256sum -c -; done; \
    rm checksums.txt

FROM distroless AS agent
COPY --from=build /out/gjallar-agent /gjallar-agent
# Only used when GJALLAR_RUNTIME_GADGET=true (agent.runtime.enabled).
COPY --from=fetch-gadget /usr/local/bin/kubectl-gadget /usr/local/bin/kubectl-gadget
# Only used when GJALLAR_REGOLIBRARY is set (agent.regolibrary.enabled).
COPY --from=fetch-policy /out/opa /usr/local/bin/opa
COPY --from=fetch-policy /out/regolibrary /usr/local/share/regolibrary
ENTRYPOINT ["/gjallar-agent"]

FROM distroless AS mcp
COPY --from=build /out/gjallar-mcp /gjallar-mcp
EXPOSE 8082
ENTRYPOINT ["/gjallar-mcp"]

FROM distroless AS cli
COPY --from=build /out/gjallar /gjallar
ENTRYPOINT ["/gjallar"]

# ---------------------------------------------------------------- engines
FROM alpine:3.22 AS engine-base
RUN apk add --no-cache ca-certificates curl tar \
 && adduser -D -u 65532 nonroot

# Anchore tools: release tarball, verified against the release's checksums file
# (never a moving install.sh from a branch).
FROM engine-base AS fetch-anchore
ARG SYFT_VERSION GRYPE_VERSION GRANT_VERSION TARGETARCH
RUN set -eux; cd /tmp; \
    for t in "syft ${SYFT_VERSION}" "grype ${GRYPE_VERSION}" "grant ${GRANT_VERSION}"; do \
      set -- $t; f="${1}_${2}_linux_${TARGETARCH}.tar.gz"; base="https://github.com/anchore/${1}/releases/download/v${2}"; \
      curl -sSfLO "$base/$f"; curl -sSfL "$base/${1}_${2}_checksums.txt" | grep " ${f}\$" | sha256sum -c -; \
      tar -xzf "$f" -C /usr/local/bin "$1"; rm "$f"; \
    done; syft version; grype version; grant version

FROM engine-base AS fetch-patch
ARG COPA_VERSION TRIVY_VERSION TARGETARCH
RUN set -eux; \
    case "$TARGETARCH" in amd64) T=64bit ;; arm64) T=ARM64 ;; *) echo "unsupported $TARGETARCH"; exit 1 ;; esac; \
    cd /tmp; \
    curl -sSfLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${T}.tar.gz"; \
    curl -sSfLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"; \
    grep " trivy_${TRIVY_VERSION}_Linux-${T}.tar.gz\$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "trivy_${TRIVY_VERSION}_Linux-${T}.tar.gz" -C /usr/local/bin trivy; \
    curl -sSfL "https://github.com/project-copacetic/copacetic/releases/download/v${COPA_VERSION}/copa_${COPA_VERSION}_linux_${TARGETARCH}.tar.gz" \
      | tar -xz -C /usr/local/bin copa; \
    trivy --version; copa --version

FROM engine-base AS fetch-osv
ARG OSV_SCANNER_VERSION TARGETARCH
RUN set -eux; cd /tmp; f="osv-scanner_linux_${TARGETARCH}"; \
    base="https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}"; \
    curl -sSfLO "$base/$f"; curl -sSfL "$base/osv-scanner_SHA256SUMS" | grep " ${f}\$" | sha256sum -c -; \
    install -m 0755 "$f" /usr/local/bin/osv-scanner

FROM engine-base AS fetch-cosign
ARG COSIGN_VERSION TARGETARCH
RUN set -eux; cd /tmp; \
    curl -sSfLO "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-${TARGETARCH}"; \
    curl -sSfL "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign_checksums.txt" | grep " cosign-linux-${TARGETARCH}\$" | sha256sum -c -; \
    install -m 0755 "cosign-linux-${TARGETARCH}" /usr/local/bin/cosign

FROM engine-base AS worker-sbom
COPY --from=fetch-anchore /usr/local/bin/syft /usr/local/bin/syft
# Signs SBOM attestations when GJALLAR_ATTEST_REPOS is set.
COPY --from=fetch-cosign /usr/local/bin/cosign /usr/local/bin/cosign
COPY --from=build /out/gjallar-worker /usr/local/bin/gjallar-worker
USER 65532
ENTRYPOINT ["gjallar-worker", "sbom"]

FROM engine-base AS worker-vuln
COPY --from=fetch-anchore /usr/local/bin/grype /usr/local/bin/grype
# Optional second source, offline only (GJALLAR_OSV=true).
COPY --from=fetch-osv /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner
# Alternative primary matcher (GJALLAR_MATCHER=trivy); same verified binary as the patch worker.
COPY --from=fetch-patch /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build /out/gjallar-worker /usr/local/bin/gjallar-worker
USER 65532
ENV GRYPE_DB_CACHE_DIR=/tmp/grype-db
ENTRYPOINT ["gjallar-worker", "vuln"]

FROM engine-base AS worker-license
COPY --from=fetch-anchore /usr/local/bin/grant /usr/local/bin/grant
COPY --from=build /out/gjallar-worker /usr/local/bin/gjallar-worker
USER 65532
ENTRYPOINT ["gjallar-worker", "license"]

FROM engine-base AS worker-patch
COPY --from=fetch-patch /usr/local/bin/trivy /usr/local/bin/copa /usr/local/bin/
COPY --from=build /out/gjallar-worker /usr/local/bin/gjallar-worker
USER 65532
ENV TRIVY_CACHE_DIR=/tmp/trivy
ENTRYPOINT ["gjallar-worker", "patch"]

# ---------------------------------------------------------------- analytics (DuckDB needs glibc)
FROM debian:12-slim AS analytics
ARG DUCKDB_VERSION TARGETARCH
RUN set -eux; apt-get update; apt-get install -y --no-install-recommends ca-certificates curl; \
    curl -sSfL "https://github.com/duckdb/duckdb/releases/download/v${DUCKDB_VERSION}/duckdb-cli-linux-${TARGETARCH}.tar.gz" \
      | tar -xz -C /usr/local/bin duckdb; \
    apt-get purge -y curl; apt-get autoremove -y; rm -rf /var/lib/apt/lists/*; \
    useradd -u 65532 -m nonroot
USER 65532
# Bake extensions into the image so the pod works air-gapped.
RUN duckdb -c "INSTALL ducklake; INSTALL postgres; INSTALL httpfs;"
COPY --from=build /out/gjallar-analytics /usr/local/bin/gjallar-analytics
EXPOSE 8081
ENTRYPOINT ["gjallar-analytics"]
CMD ["serve"]
