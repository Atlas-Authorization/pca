#!/usr/bin/env bash
# Real AWS Lambda runtime test. Runs ON a throwaway x86_64 Linux VM with docker. Layout (already extracted):
#   $W/lam/{handler.js,mint.js}   esbuild bundles   $W/fx/aws-*.json   $W/drive.mjs   $W/template.yaml
# Stage 1: official public.ecr.aws/lambda/nodejs:{22,20} images with the built-in Runtime Interface Emulator,
#          documented event shapes -> invocations.jsonl.   Stage 2: SAM CLI local API Gateway emulation.
set -uo pipefail
W="${1:-/opt/pca/work}"; OUT="${2:-/opt/pca/out}"; mkdir -p "$OUT"
cd "$W"
export PATH="$HOME/.local/bin:$PATH"
: > "$OUT/invocations.jsonl"
FAILS=0
docker version --format 'docker {{.Server.Version}} {{.Server.Arch}}' | tee "$OUT/versions.txt"
node --version | sed 's/^/driver node /' | tee -a "$OUT/versions.txt"

for TAG in 22 20; do
  IMG="public.ecr.aws/lambda/nodejs:$TAG"
  docker pull -q "$IMG" >/dev/null
  echo "$IMG digest: $(docker image inspect "$IMG" --format '{{index .RepoDigests 0}}')" | tee -a "$OUT/versions.txt"
  docker run --rm --entrypoint node "$IMG" --version | sed "s|^|lambda image nodejs:$TAG runtime node |" | tee -a "$OUT/versions.txt"
  # fresh proofs + grants, minted INSIDE the Lambda image's node
  rm -f lam/grants.json lam/proofs.json
  docker run --rm --entrypoint node -v "$W/lam:/var/task" "$IMG" /var/task/mint.js /var/task
  cp lam/grants.json "$OUT/grants-nodejs$TAG.json"; cp lam/proofs.json "$OUT/proofs-nodejs$TAG.json"
  P=9100
  for H in rest simple restReplay; do
    P=$((P+1)); NAME="pca-lam-$TAG-$H"
    docker rm -f "$NAME" >/dev/null 2>&1
    docker run -d --name "$NAME" -p "127.0.0.1:$P:8080" -e PCA_AUDIENCE=ins_acme -v "$W/lam:/var/task:ro" "$IMG" "handler.$H" >/dev/null
    for i in $(seq 1 30); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 1; done
    node drive.mjs "$P" "$H" "nodejs:$TAG" "$W/fx" lam/proofs.json "$OUT/invocations.jsonl" || FAILS=$((FAILS+1))
    docker logs "$NAME" > "$OUT/runtime-nodejs$TAG-$H.log" 2>&1
    docker rm -f "$NAME" >/dev/null
  done
done
echo "STAGE1 failed-handlers=$FAILS" | tee -a "$OUT/versions.txt"

echo "== stage 2: SAM CLI local API Gateway emulation =="
if ! command -v sam >/dev/null; then
  curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1; export PATH="$HOME/.local/bin:$PATH"
  uv tool install aws-sam-cli >/dev/null 2>&1
fi
sam --version | tee -a "$OUT/versions.txt"
rm -f lam/grants.json lam/proofs.json
docker run --rm --entrypoint node -v "$W/lam:/var/task" public.ecr.aws/lambda/nodejs:22 /var/task/mint.js /var/task
nohup sam local start-api -t template.yaml --port 3000 --skip-pull-image > "$OUT/sam.log" 2>&1 &
SAMPID=$!
for i in $(seq 1 60); do curl -s -o /dev/null http://127.0.0.1:3000/ && break; sleep 1; done
PJ=$(cat lam/proofs.json)
pf() { node -e "console.log(JSON.parse(process.argv[1]).proofs[process.argv[2]])" "$PJ" "$1"; }
: > "$OUT/sam-results.jsonl"
call() { # name method url proofName expectStatus [extraHeaderName]
  local name="$1" url="$2" pn="$3" want="$4" hn="${5:-PCA-Action}"
  local args=(-s -m 120 -o /tmp/body -w '%{http_code}' -X POST)
  [ -n "$pn" ] && args+=(-H "$hn: $(pf "$pn")")
  local got; got=$(curl "${args[@]}" "$url")
  local ok=FAIL; [ "$got" = "$want" ] && ok=PASS
  echo "$ok  $name (got $got, want $want)  body: $(head -c 300 /tmp/body)"
  printf '{"scenario":%s,"got":"%s","want":"%s","pass":%s,"body":%s}\n' "$(node -e 'console.log(JSON.stringify(process.argv[1]))' "$name")" "$got" "$want" "$([ $ok = PASS ] && echo true || echo false)" "$(node -e 'console.log(JSON.stringify(require("fs").readFileSync("/tmp/body","utf8").slice(0,2000)))')" >> "$OUT/sam-results.jsonl"
}
B=http://127.0.0.1:3000
call "REST REQUEST authorizer: valid proof -> backend reached" "$B/rest/refunds" valid 200
call "REST REQUEST authorizer: no proof -> 403" "$B/rest/refunds" "" 401
call "REST REQUEST authorizer: tampered -> 403" "$B/rest/refunds" tampered 403
call "REST REQUEST authorizer: payout-verb proof at /rest/payouts ok" "$B/rest/payouts" payout-verb 200
call "REST REQUEST authorizer: refund proof at /rest/payouts -> 403" "$B/rest/payouts" valid2 403
call "REST TOKEN authorizer: valid proof (unsupported event type, fail closed)" "$B/tok/refunds" valid 403
call "HTTP API 2.0 simple: valid -> backend reached" "$B/h2/refunds" valid 200 pca-action
call "HTTP API 2.0 simple: no proof -> 401/403" "$B/h2/refunds" "" 401
call "HTTP API 2.0 simple: tampered -> 403" "$B/h2/refunds" tampered 403 pca-action
call "HTTP API 1.0 IAM: valid -> backend reached" "$B/h1/refunds" valid 200 pca-action
call "HTTP API 1.0 IAM: wrong audience -> 403" "$B/h1/refunds" wrong-aud 403 pca-action
kill $SAMPID 2>/dev/null; sleep 1
grep -o 'PCA_TRACE_EVENT {.*' "$OUT/sam.log" | sed 's/^PCA_TRACE_EVENT //' > "$OUT/sam-authorizer-events.jsonl"
grep -o 'PCA_TRACE_RESPONSE {.*' "$OUT/sam.log" | sed 's/^PCA_TRACE_RESPONSE //' > "$OUT/sam-authorizer-responses.jsonl"
echo "sam traced authorizer events: $(wc -l < "$OUT/sam-authorizer-events.jsonl")"
touch "$OUT/STAGE12_DONE"
