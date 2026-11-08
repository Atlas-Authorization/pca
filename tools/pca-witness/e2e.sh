#!/bin/sh
# Build the pca-witness image from the repository root and prove it works as a container: unprivileged, read-only root
# filesystem, state on a volume, a cosign round trip over HTTP, the head surviving a container restart.
# Needs docker, node and curl. Prints PASS lines; exits non-zero on the first failure.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
tag=${TAG:-pca-witness:e2e}
work=$(mktemp -d)
cid=""
cleanup() { [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1 || true; docker volume rm -f "pca-witness-e2e-$$" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

docker build -q -f "$here/Dockerfile" -t "$tag" "$root" >/dev/null || fail "image build"
echo "PASS image builds ($(docker image inspect "$tag" --format '{{.Size}}') bytes)"
[ "$(docker image inspect "$tag" --format '{{.Config.User}}')" = "nonroot" ] || [ "$(docker image inspect "$tag" --format '{{.Config.User}}')" = "65532" ] || fail "image does not run as an unprivileged user"
echo "PASS runs as an unprivileged user"

# a guardian key and a log to witness, made with the same library the container bundles
node "$here/e2e-fixture.js" "$work" || fail "fixture"
# the witness key, made by the container itself; only the public key is printed
chmod 777 "$work"
docker run --rm -v "$work:/etc/pca-witness" "$tag" init --key /etc/pca-witness/key > "$work/witness.pub" || fail "init"
chmod 400 "$work/key" 2>/dev/null || true
docker run --rm -v "$work:/etc/pca-witness" "$tag" init --key /etc/pca-witness/key >/dev/null 2>&1 && fail "init overwrote an existing key"
echo "PASS init prints the public key and refuses to overwrite"

vol="pca-witness-e2e-$$"
start() {
  cid=$(docker run -d --read-only --cap-drop ALL --security-opt no-new-privileges -p 127.0.0.1:0:8080 \
    -v "$work:/etc/pca-witness:ro" -v "$vol:/var/lib/witness" "$tag") || fail "start"
  for i in 1 2 3 4 5 6 7 8 9 10; do
    port=$(docker port "$cid" 8080/tcp | head -1 | sed 's/.*://')
    curl -fs "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 && return 0
    sleep 1
  done
  docker logs "$cid" >&2; fail "container did not become healthy"
}
start
echo "PASS starts read-only with all capabilities dropped and answers /healthz"
curl -fs "http://127.0.0.1:$port/v1/key" | grep -q "$(cat "$work/witness.pub")" || fail "/v1/key does not show the public key from init"
code=$(curl -s -o "$work/r1.json" -w '%{http_code}' -H 'content-type: application/json' --data @"$work/head-8.json" "http://127.0.0.1:$port/v1/cosign")
[ "$code" = 200 ] || { cat "$work/r1.json" >&2; fail "first cosign returned $code"; }
echo "PASS first head cosigned"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'content-type: application/json' --data @"$work/head-5.json" "http://127.0.0.1:$port/v1/cosign")
[ "$code" = 409 ] || fail "rollback returned $code, wanted 409"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'content-type: application/json' --data @"$work/head-8-fork.json" "http://127.0.0.1:$port/v1/cosign")
[ "$code" = 409 ] || fail "split view returned $code, wanted 409"
echo "PASS rollback and split view refused"
docker rm -f "$cid" >/dev/null; cid=""
start
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'content-type: application/json' --data @"$work/head-5.json" "http://127.0.0.1:$port/v1/cosign")
[ "$code" = 409 ] || fail "after a restart the witness forgot its head (rollback returned $code)"
code=$(curl -s -o "$work/r2.json" -w '%{http_code}' -H 'content-type: application/json' --data @"$work/head-12.json" "http://127.0.0.1:$port/v1/cosign")
[ "$code" = 200 ] || { cat "$work/r2.json" >&2; fail "extension after restart returned $code"; }
echo "PASS the cosigned head survives a container restart and the next head extends it"
node "$here/e2e-verify.js" "$work" || fail "the returned cosignatures do not verify against the witness policy"
echo "PASS the cosignatures verify (guardian signature + 1-of-1 witness threshold)"
docker logs "$cid" 2>&1 | grep -qi "secret" && fail "the log mentions a secret"
echo "PASS ok"
