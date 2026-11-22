#!/usr/bin/env bash
# End-to-end test: real Gjallar binaries + real NATS JetStream + Postgres +
# DuckDB, with fake syft/grype/copa so no registry or internet is needed.
#
#   GJALLAR_NATS_URL=nats://127.0.0.1:4222 \
#   GJALLAR_DATABASE_URL=postgres://gjallar@127.0.0.1:5432/gjallar \
#   scripts/e2e.sh
#
# `make e2e` starts NATS and Postgres in Docker and runs this for you.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GJALLAR_NATS_URL:?set GJALLAR_NATS_URL}"
: "${GJALLAR_DATABASE_URL:?set GJALLAR_DATABASE_URL}"
command -v duckdb >/dev/null || { echo "duckdb CLI is required on PATH"; exit 1; }

BIN=$(mktemp -d)
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$BIN" "$WORK"' EXIT
CGO_ENABLED=0 go build -o "$BIN/" ./cmd/...

export PATH="$PWD/test/e2e/fakebin:$PATH"
export GJALLAR_LOG_LEVEL=warn GJALLAR_RUNTIME_ENABLED=true
start() { local name=$1; shift; "$@" >"$WORK/$name.log" 2>&1 & }

# API, analytics and MCP listen on P..P+2. Override when a port is taken.
P=${GJALLAR_E2E_PORT:-18080}
for port in $P $((P+1)) $((P+2)) $((P+3)); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "port $port is already in use; rerun with GJALLAR_E2E_PORT=<free base port>"; exit 1
  fi
done
export GJALLAR_URL=http://127.0.0.1:$P GJALLAR_MCP_URL=http://127.0.0.1:$((P+2))
# The test listens on P+4 for the notification webhook.
export GJALLAR_E2E_HOOK=127.0.0.1:$((P+4))
NOTIFY='[{"name":"e2e","url":"http://'$GJALLAR_E2E_HOOK'/hook","format":"slack","min_band":"urgent","kev":true}]'

start api       env GJALLAR_NOTIFY="$NOTIFY" GJALLAR_HTTP_ADDR=:$P GJALLAR_ANALYTICS_URL=http://127.0.0.1:$((P+1)) "$BIN/gjallar-api"
export GJALLAR_FLIGHT=127.0.0.1:$((P+5))
start analytics env GJALLAR_FLIGHT_ADDR=$GJALLAR_FLIGHT GJALLAR_HTTP_ADDR=:$((P+1)) GJALLAR_LAKE_MODE=parquet GJALLAR_LAKE_DATA="$WORK/lake/" GJALLAR_LAKE_FLUSH=1s "$BIN/gjallar-analytics" serve
start mcp       env GJALLAR_HTTP_ADDR=:$((P+2)) GJALLAR_API_URL=$GJALLAR_URL "$BIN/gjallar-mcp"
for role in sbom vuln license; do
  start "worker-$role" env GJALLAR_HTTP_ADDR=:0 "$BIN/gjallar-worker" "$role"
done
start worker-patch env GJALLAR_HTTP_ADDR=:0 GJALLAR_BUILDKIT_ADDR=tcp://fake:1234 GJALLAR_COPA_PUSH=false "$BIN/gjallar-worker" patch

for port in $P $((P+1)) $((P+2)); do
  for _ in $(seq 1 60); do curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
done

if ! go test -tags e2e -count=1 -v ./test/e2e/; then
  for f in "$WORK"/*.log; do echo "=== $f"; tail -30 "$f"; done
  exit 1
fi
"$BIN/gjallar-analytics" maintain >/dev/null 2>&1 || true
