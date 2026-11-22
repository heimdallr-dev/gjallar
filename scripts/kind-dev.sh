#!/usr/bin/env bash
# Local Kubernetes for Gjallar on WSL containerd (no Docker): kind + nerdctl.
#
#   scripts/kind-dev.sh up      recreate cluster, load images, helm install
#   scripts/kind-dev.sh load    reload rebuilt images and restart the pods
#   scripts/kind-dev.sh down    delete the cluster
#
# Build images first: make images BUILDER=nerdctl
# Why recreate on every `up`: containerd's CNI gives the node a new IP after a
# WSL restart and a kubeadm control plane cannot survive its IP changing.
set -euo pipefail
cd "$(dirname "$0")/.."
CHART=${HELM_REPO:-../gjallar-helm}/charts/gjallar   # github.com/heimdallr-dev/gjallar-helm
NAME=${KIND_CLUSTER:-gjallar}
REGISTRY=${REGISTRY:-ghcr.io/heimdallr-dev}
VERSION=${VERSION:-0.3.0}
export KIND_EXPERIMENTAL_PROVIDER=nerdctl

# kind calls `nerdctl` directly; rootful containerd needs sudo (NOPASSWD rule, see gjallar-docs install-wsl.md).
WRAP=$(mktemp -d)
trap 'rm -rf "$WRAP"' EXIT
printf '#!/bin/sh\nexec sudo -n %s "$@"\n' "$(command -v nerdctl)" > "$WRAP/nerdctl"
chmod +x "$WRAP/nerdctl"
export PATH="$WRAP:$PATH"
N="sudo -n nerdctl"

load() {
  local tar="$WRAP/images.tar" imgs
  imgs=$($N images --format '{{.Repository}}:{{.Tag}}' | grep "^$REGISTRY/gjallar-.*:$VERSION$" | sort -u)
  [ -n "$imgs" ] || { echo "no $REGISTRY/gjallar-*:$VERSION images; run: make images BUILDER=nerdctl"; exit 1; }
  # shellcheck disable=SC2086
  $N save -o "$tar" $imgs
  # Not `kind load`: it imports --all-platforms and fails on multi-arch images
  # pulled from GHCR, where only this host's platform is stored locally.
  $N exec -i "$NAME-control-plane" ctr --namespace=k8s.io images import \
    --platform "linux/$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" --digests --snapshotter=overlayfs - < "$tar" >/dev/null
}

case ${1:-up} in
  up)
    # After a WSL restart the node is "Created" (never started), which kind's
    # nerdctl provider cannot delete; remove the container directly first.
    $N rm -f "$NAME-control-plane" >/dev/null 2>&1 || true
    kind delete cluster --name "$NAME" >/dev/null 2>&1 || true
    kind create cluster --name "$NAME" --wait 180s
    # The node copies WSL's resolv.conf at create time; fail early if it cannot resolve.
    $N exec "$NAME-control-plane" getent hosts quay.io >/dev/null \
      || { echo "kind node has no working DNS: check /etc/resolv.conf in WSL"; exit 1; }
    load
    helm upgrade --install gjallar "$CHART" -n gjallar --create-namespace -f "$CHART/values-kind.yaml" \
      --set image.registry="$REGISTRY" --set image.tag="$VERSION" --set cluster.name=kind \
      --wait --timeout 10m "${@:2}"
    kubectl -n gjallar get pods
    ;;
  load)
    load
    kubectl -n gjallar rollout restart deploy
    ;;
  down)
    kind delete cluster --name "$NAME"
    ;;
  *) echo "usage: $0 up|load|down [extra helm args]"; exit 2 ;;
esac
