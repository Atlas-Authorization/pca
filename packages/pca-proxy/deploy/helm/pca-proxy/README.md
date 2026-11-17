# pca-proxy Helm chart

Runs `pca-proxy` in front of an HTTP API as a **gateway** (its own Deployment and Service) or hands you the config and the
container to run it as a **sidecar** in your own pod, with an optional **control-plane agent** that reports every decision
to a PCA control plane.

```sh
# 1. keys (a Secret you own; nothing secret is in values)
kubectl create secret generic pca-proxy-keys \
  --from-literal=principal.key="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d =)" \
  --from-literal=state-hmac.key="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d =)"

# 2. install in observe mode (the default config forwards everything and records what enforce would refuse)
helm install pca ./deploy/helm/pca-proxy \
  --set agent.principalKeySecret.name=pca-proxy-keys --set agent.stateHmacSecret.name=pca-proxy-keys \
  --set config.audience=orders-api --set config.http.upstream=http://orders.default.svc:8080 \
  --set-file openapi=./openapi.yaml
```

Put the actions in `config.http.actions` (anything unlisted is refused), read the audit log, have a human sign the autopilot
review, then set `config.mode: enforce` and `helm upgrade`. See the pca-proxy README for every `config` key.

| Value | What it does |
|---|---|
| `mode` | `gateway` (Deployment + Service) or `sidecar` (ConfigMap only; NOTES.txt prints the container and volumes to add, or `include "pca-proxy.container"` from a parent chart) |
| `config` | the whole `pca-proxy.yaml`; the chart fixes only the audit, state and approvals paths and the listen address |
| `openapi` | the OpenAPI document text the actions map onto |
| `agent.*` | the grant's goal, the Secret with the principal key (required) and the state MAC key, an optional revocation file |
| `persistence.*` | keep audit, approvals and state across restarts (one replica) |
| `controlPlane.*` | a second container that follows the audit log and reports signed batches with `pca-control-plane report --follow` |
| `networkPolicy.*` | limit who can reach the gateway |

Every replica is its own proxy with its own budget, replay counters and audit chain. The container runs as non-root with a
read-only root filesystem and no capabilities.
