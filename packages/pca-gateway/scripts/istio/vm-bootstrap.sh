#!/usr/bin/env bash
# VM-side bootstrap (run as build.sh by the VM cloud-init): single-node k3s (containerd, no Docker) + istioctl.
set -euxo pipefail
ISTIO_VERSION="${ISTIO_VERSION:-1.31.1}"
K3S_VERSION="${K3S_VERSION:-v1.36.5+k3s1}"
# Pinned checksums. The k3s installer script is verified before it runs (it then verifies the k3s binary
# against the release's sha256sum file); istioctl is verified before it is unpacked. Overriding a
# version requires supplying the matching checksum.
K3S_INSTALL_SHA256="${K3S_INSTALL_SHA256:-e5cc3b3d9dfc1662c2d9be6da5abc9a4cd317d6abc3a5ffc02e3dd3248207fee}"
ISTIOCTL_SHA256="${ISTIOCTL_SHA256:-a44563904f22f2a8bf6ac4fff1b0bad9f718587c2be6aa807b83fe9049910639}"
OUT="${2:-/opt/pca/out}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y && apt-get install -y curl jq
curl -fsSL -o /tmp/k3s-install.sh https://get.k3s.io
echo "${K3S_INSTALL_SHA256}  /tmp/k3s-install.sh" | sha256sum -c -
INSTALL_K3S_VERSION="$K3S_VERSION" INSTALL_K3S_EXEC="--disable traefik --disable servicelb --write-kubeconfig-mode 644" sh /tmp/k3s-install.sh
cd /tmp
curl -fsSL -o istioctl.tgz "https://github.com/istio/istio/releases/download/${ISTIO_VERSION}/istioctl-${ISTIO_VERSION}-linux-amd64.tar.gz"
echo "${ISTIOCTL_SHA256}  istioctl.tgz" | sha256sum -c -
tar -xzf istioctl.tgz
install istioctl /usr/local/bin/istioctl
ln -sf /usr/local/bin/k3s /usr/local/bin/kubectl 2>/dev/null || true
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
for i in $(seq 1 60); do kubectl get nodes 2>/dev/null | grep -q ' Ready' && break; sleep 5; done
kubectl get nodes -o wide | tee "$OUT/nodes.txt"
istioctl version --remote=false | tee "$OUT/istioctl.txt"
mkdir -p /opt/pca-mesh/authz /opt/pca-mesh/upstream /opt/pca-mesh/out
chown -R 1000:1000 /opt/pca-mesh
echo bootstrap-ok
