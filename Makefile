# Gjallar — build, test, package and deploy.
#   make test                    unit tests
#   make e2e                     end-to-end (Docker for NATS+Postgres, duckdb CLI on PATH)
#   make images REGISTRY=harbor.local/gjallar
#   make push   REGISTRY=harbor.local/gjallar
#   make deploy REGISTRY=harbor.local/gjallar HELM_ARGS="-f my-values.yaml"
#   make images BUILDER=nerdctl  containerd + BuildKit instead of Docker (WSL without Docker Desktop)
SHELL      := /bin/bash
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.3.0)
REGISTRY   ?= ghcr.io/heimdallr-dev
NAMESPACE  ?= gjallar
PLATFORMS  ?= linux/amd64
HELM_ARGS  ?=
# Chart, policies and realm live in github.com/heimdallr-dev/gjallar-helm (clone next to this repo).
HELM_REPO  ?= ../gjallar-helm
CHART      ?= $(HELM_REPO)/charts/gjallar
GOFLAGS    := -mod=vendor
COMPONENTS := api agent mcp web analytics cli worker-sbom worker-vuln worker-license worker-patch
export GOFLAGS

# Container tool: docker (default) or nerdctl (containerd; needs buildkitd running).
BUILDER    ?= docker
ifeq ($(BUILDER),nerdctl)
CTR_NAMESPACE ?= default
NERDCTL    ?= sudo nerdctl --namespace $(CTR_NAMESPACE)
BUILD      := $(NERDCTL) build
LOAD       :=
PUSH_FLAG  :=
PUSH_AFTER := $(NERDCTL) push --all-platforms
COMPOSE    := $(NERDCTL) compose
else
BUILD      := docker buildx build
LOAD       := --load
PUSH_FLAG  := --push
PUSH_AFTER := true
COMPOSE    := docker compose
endif

.PHONY: all build test vet e2e images push deploy undeploy kyverno dev dev-down clean help

all: vet test build

help: ## Show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

build: ## Build all binaries into ./bin
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/ ./cmd/...

vet: ## go vet
	go vet ./...

test: ## Unit and adapter tests
	go test ./...

e2e: ## End-to-end: real binaries + NATS + Postgres + DuckDB, fake scanners
	$(COMPOSE) -f deploy/compose/e2e.yml up -d
	@for i in $$(seq 120); do $(COMPOSE) -f deploy/compose/e2e.yml exec -T postgres pg_isready -U gjallar >/dev/null 2>&1 && exit 0; sleep 1; done; echo "postgres not ready"; exit 1
	GJALLAR_NATS_URL=nats://127.0.0.1:14222 \
	GJALLAR_DATABASE_URL="postgres://gjallar:gjallar@127.0.0.1:15432/gjallar?sslmode=disable" \
	  scripts/e2e.sh; rc=$$?; $(COMPOSE) -f deploy/compose/e2e.yml down -v; exit $$rc

images: ## Build all images locally (BUILDER=docker|nerdctl)
	@for c in $(COMPONENTS); do \
	  echo "==> gjallar-$$c"; \
	  $(BUILD) --platform $(PLATFORMS) --target $$c --build-arg VERSION=$(VERSION) \
	    -t $(REGISTRY)/gjallar-$$c:$(VERSION) $(LOAD) . || exit 1; \
	done

push: ## Build and push all images (set PLATFORMS=linux/amd64,linux/arm64 for multi-arch)
	@for c in $(COMPONENTS); do \
	  echo "==> gjallar-$$c"; \
	  $(BUILD) --platform $(PLATFORMS) --target $$c --build-arg VERSION=$(VERSION) \
	    -t $(REGISTRY)/gjallar-$$c:$(VERSION) $(PUSH_FLAG) . && \
	  $(PUSH_AFTER) $(REGISTRY)/gjallar-$$c:$(VERSION) || exit 1; \
	done

deploy: ## helm upgrade --install into $(NAMESPACE)
	helm upgrade --install gjallar $(CHART) -n $(NAMESPACE) --create-namespace \
	  --set image.registry=$(REGISTRY) --set image.tag=$(VERSION) $(HELM_ARGS)

undeploy: ## Remove the release (PVCs are kept)
	helm uninstall gjallar -n $(NAMESPACE)

kyverno: ## Apply the Kyverno policies (Audit mode)
	kubectl apply -f $(HELM_REPO)/policies/kyverno/

dev: ## Run the whole stack with compose (BUILDER=docker|nerdctl)
	$(COMPOSE) -f deploy/compose/docker-compose.yml up -d --build

dev-down: ## Stop the compose stack
	$(COMPOSE) -f deploy/compose/docker-compose.yml down

clean:
	rm -rf bin
