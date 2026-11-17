#!/bin/sh
# Starts one role of the box. Secrets come from the data volume (tools/init-keys.mjs), never from the image or the compose file.
set -eu
role="$1"; shift || true
K=/data/keys
load() { [ -f "$K/$1" ] || { echo "missing $K/$1: the keys service has not run" >&2; exit 1; }; cat "$K/$1"; }
case "$role" in
  orders-api)
    UPSTREAM_TOKEN="$(load upstream.token)" exec node /box/sample/orders-api.mjs ;;
  proxy)
    export UPSTREAM_TOKEN="$(load upstream.token)" PCA_PRINCIPAL_KEY="$(load principal.key)" PCA_STATE_HMAC="$(load state-hmac.key)"
    # the config lives in the volume so `make enforce` can switch it; first start is observe mode
    [ -f /data/config/pca-proxy.yaml ] || cp /box/config/pca-proxy.observe.yaml /data/config/pca-proxy.yaml
    exec pca-proxy http --config /data/config/pca-proxy.yaml ;;
  dashboard)
    exec node /box/tools/dashboard.mjs ;;
  directory-log)
    export HOST=0.0.0.0
    exec pca-directory-log --id box-log --key "$K/log.key" --data /data/log --port 8080 ;;
  directory-witness)
    export HOST=0.0.0.0
    exec pca-directory-witness --key "$K/witness.key" --state /data/witness/state.json --log "http://directory-log:8080=$(load log.pub)" --port 8081 --interval 10 ;;
  agent)
    export PCA_PRINCIPAL_KEY="$(load principal.key)" PCA_STATE_HMAC="$(load state-hmac.key)" PCA_BOX_PROXY_URL=http://pca-proxy:8788
    [ -f /data/config/pca-proxy-mcp.yaml ] || node /box/tools/mcp-config.mjs observe
    exec node /box/sample/agent.mjs "$@" ;;
  tools)
    export PCA_PRINCIPAL_KEY="$(load principal.key)" PCA_STATE_HMAC="$(load state-hmac.key)"
    exec "$@" ;;
  *) echo "unknown role $role" >&2; exit 2 ;;
esac
