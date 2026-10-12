#!/usr/bin/env bash
# Real Istio ext_authz CUSTOM-provider test. Runs ON a single-node cluster host (k3s) that has kubectl and istioctl,
# with /opt/pca-mesh/authz/mesh-authz.js (esbuild bundle of scripts/istio/mesh-authz.ts) and
# /opt/pca-mesh/upstream/upstream.mjs in place. Idempotent; prints PASS/FAIL per scenario and a JSON summary.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-/opt/pca-mesh/out}"; mkdir -p "$OUT"
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"

ISTIO_SETS=(
  --set profile=minimal
  --set 'meshConfig.extensionProviders[0].name=pca-ext-authz'
  --set 'meshConfig.extensionProviders[0].envoyExtAuthzHttp.service=pca-authz.authz.svc.cluster.local'
  --set 'meshConfig.extensionProviders[0].envoyExtAuthzHttp.port=8000'
  --set 'meshConfig.extensionProviders[0].envoyExtAuthzHttp.includeRequestHeadersInCheck[0]=pca-action'
  --set 'meshConfig.extensionProviders[0].envoyExtAuthzHttp.includeRequestHeadersInCheck[1]=x-request-id'
  --set 'meshConfig.extensionProviders[0].envoyExtAuthzHttp.headersToUpstreamOnAllow[0]=x-pca-verdict'
  --set 'meshConfig.extensionProviders[0].envoyExtAuthzHttp.headersToUpstreamOnAllow[1]=x-pca-verb'
  --set 'meshConfig.extensionProviders[0].envoyExtAuthzHttp.headersToUpstreamOnAllow[2]=x-pca-grant'
  --set 'meshConfig.extensionProviders[0].envoyExtAuthzHttp.headersToDownstreamOnDeny[0]=www-authenticate'
  --set 'meshConfig.extensionProviders[0].envoyExtAuthzHttp.headersToDownstreamOnDeny[1]=content-type'
)
echo "== istioctl install (minimal profile + PCA extension provider) =="
istioctl install -y "${ISTIO_SETS[@]}" 2>&1 | tail -5
kubectl -n istio-system rollout status deploy/istiod --timeout=300s
istioctl version 2>&1 | head -3 | tee "$OUT/istio-version.txt"

echo "== workloads =="
kubectl apply -f "$HERE/manifests.yaml" >/dev/null
kubectl -n authz rollout status deploy/pca-authz --timeout=300s
kubectl -n foo rollout status deploy/upstream --timeout=300s
kubectl -n foo rollout status deploy/client --timeout=300s
kubectl -n foo get pods -o wide | tee "$OUT/pods.txt"
sleep 5

AUTHZ_POD="$(kubectl -n authz get pod -l app=pca-authz -o name | head -1)"
CLIENT_POD="$(kubectl -n foo get pod -l app=client -o name | head -1)"
UP_POD="$(kubectl -n foo get pod -l app=upstream -o name | head -1)"
admin() { kubectl -n foo exec "$CLIENT_POD" -c curl -- curl -s "http://pca-authz.authz.svc.cluster.local:8001$1"; }
cx()    { kubectl -n foo exec "$CLIENT_POD" -c curl -- curl -s -o /tmp/b -w '%{http_code}' "$@" ; }
cxb()   { kubectl -n foo exec "$CLIENT_POD" -c curl -- sh -c "curl -s -D /tmp/h -o /tmp/b $*; cat /tmp/h; echo; cat /tmp/b"; }
ulog()  { kubectl -n foo exec "$CLIENT_POD" -c curl -- curl -s http://upstream.foo.svc.cluster.local:8080/_log; }
ucount(){ ulog | grep -o '"method"' | wc -l | tr -d ' '; }
U=http://upstream.foo.svc.cluster.local:8080
FAILS=0; : > "$OUT/results.jsonl"
check() { # name actual expected
  if [ "$2" = "$3" ]; then echo "PASS  $1 (got $2)"; else echo "FAIL  $1 (got $2, want $3)"; FAILS=$((FAILS+1)); fi
  printf '{"scenario":"%s","got":"%s","want":"%s"}\n' "$1" "$2" "$3" >> "$OUT/results.jsonl"
}

echo "== scenarios (client sidecar -> upstream sidecar enforcing CUSTOM) =="
before=$(ucount)
P=$(admin '/mint'); s=$(cx -X POST -H "PCA-Action: $P" "$U/refunds?currency=usd&note=a%20b"); check "allow valid proof, query string" "$s" 200
check "upstream received the allowed request" "$(( $(ucount) - before ))" 1
ulog | grep -o '"url":"/refunds?currency=usd&note=a%20b"' | head -1 | sed 's/^/      upstream saw: /'
ulog | grep -o '"x-pca-verb":"[^"]*"' | tail -1 | sed 's/^/      injected: /'

before=$(ucount); s=$(cx -X POST "$U/refunds"); check "deny missing proof" "$s" 401
kubectl -n foo exec "$CLIENT_POD" -c curl -- cat /tmp/b | head -c 200; echo
P=$(admin '/mint?tamper=1'); s=$(cx -X POST -H "PCA-Action: $P" "$U/refunds"); check "deny tampered proof" "$s" 401
P=$(admin '/mint?aud=ins_other'); s=$(cx -X POST -H "PCA-Action: $P" "$U/refunds"); check "deny wrong audience" "$s" 403
P=$(admin '/mint'); s=$(cx -X POST -H "PCA-Action: $P" "$U/payouts"); check "deny refund proof at payouts" "$s" 403
P=$(admin '/mint'); s=$(cx -X POST -H "PCA-Action: $P" "$U/admin"); check "deny unmapped-but-policed route /admin with a valid proof" "$s" 403
P=$(admin '/mint'); s1=$(cx -X POST -H "PCA-Action: $P" "$U/refunds"); s2=$(cx -X POST -H "PCA-Action: $P" "$U/refunds")
check "replay: first use" "$s1" 200; check "replay: second use denied" "$s2" 403
check "denied requests never reached upstream" "$(( $(ucount) - before ))" 1   # only the replay-first-use

s=$(cx -X POST -H 'PCA-ACTION: nope' "$U/refunds"); check "deny undecodable proof (header name upper-case)" "$s" 401

echo "== forged x-pca-* on a path the policy does not police =="
s=$(cx -H 'x-pca-verdict: {"allow":true,"forged":true}' "$U/health"); check "unpoliced path passes without a proof" "$s" 200
ulog | grep -o '"x-pca-verdict":"[^"]*"' | tail -1 | sed 's/^/      upstream saw (forged header is NOT scrubbed by Istio on unpoliced paths): /'

echo "== path ambiguity vs the policy's path rules =="
for p in '//refunds' '/refunds/../refunds' '/%72efunds' '/./refunds'; do
  before=$(ucount); s=$(cx -X POST "$U$p"); n=$(( $(ucount) - before ))
  echo "      POST $p -> $s (upstream hit: $n)"
  printf '{"scenario":"path-probe %s","status":"%s","reachedUpstream":%s}\n' "$p" "$s" "$n" >> "$OUT/results.jsonl"
done

echo "== mitigation: meshConfig.pathNormalization=MERGE_SLASHES (Istio's documented hardening for path-based policy) =="
istioctl install -y "${ISTIO_SETS[@]}" --set meshConfig.pathNormalization.normalization=MERGE_SLASHES 2>&1 | tail -2
kubectl -n istio-system rollout status deploy/istiod --timeout=300s; sleep 20
for p in '//refunds' '///refunds'; do
  before=$(ucount); s=$(cx -X POST "$U$p"); n=$(( $(ucount) - before ))
  echo "      POST $p -> $s (upstream hit: $n)"
  check "MERGE_SLASHES: $p without a proof is denied" "$s" 401
  printf '{"scenario":"merge-slashes %s","status":"%s","reachedUpstream":%s}\n' "$p" "$s" "$n" >> "$OUT/results.jsonl"
done
P=$(admin '/mint'); s=$(cx -X POST -H "PCA-Action: $P" "$U//refunds"); check "MERGE_SLASHES: //refunds with a valid proof is allowed" "$s" 200

echo "== what Istio's Envoy actually sent to the check service =="
admin '/checks' > "$OUT/istio-check-requests.json"; head -c 1500 "$OUT/istio-check-requests.json"; echo

echo "== fail closed: scale the check service to zero =="
kubectl -n authz scale deploy/pca-authz --replicas=0 >/dev/null; sleep 8
P="dummy"; s=$(cx -X POST -H "PCA-Action: $P" "$U/refunds"); check "provider down -> denied (failOpen=false default)" "$s" 403
kubectl -n authz scale deploy/pca-authz --replicas=1 >/dev/null

echo "FAILS=$FAILS"; echo "{\"fails\":$FAILS}" > "$OUT/summary.json"; touch "$OUT/DONE"; exit $FAILS
