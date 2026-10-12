#!/usr/bin/env bash
# Reproducible real-OP run for @atlasauth/pca-ciba: downloads (pinned + sha256-verified) a Temurin JDK and the
# official Keycloak distribution into a cache dir, starts `kc.sh start-dev` (NO docker), configures a realm,
# user and CIBA-enabled client over the admin REST API, runs the gated integration test, then tears down.
#
#   scripts/run-keycloak-ciba.sh            # up + test + down (default)
#   scripts/run-keycloak-ciba.sh up|test|down
#
# Env: PCA_CIBA_KC_DIR (cache, default ~/.cache/pca-ciba-keycloak), PCA_CIBA_KC_PORT (18480),
#      PCA_CIBA_CHANNEL_PORT (18481, the harness' Authentication Channel endpoint), PCA_CIBA_PING_PORT (18482),
#      PCA_CIBA_RECORD=1 re-records fixtures/keycloak-ciba-transcripts.json + PROVENANCE.json, PCA_CIBA_KC_KEEP_DL=1 keeps
#      the downloaded archives, PCA_CIBA_KC_CLEAN=1 deletes the whole cache dir on teardown.
set -euo pipefail

PKG="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KC_VERSION=26.8.0
KC_SHA256=9e41da899f838a58cd510fc98ed4f7cadc715aed5683e42aca20a0c9a2a3980a   # keycloak-26.8.0.tar.gz as downloaded from the official GitHub release
JDK_VERSION=jdk-21.0.12.1+1
JDK_URL="https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_aarch64_mac_hotspot_21.0.12.1_1.tar.gz"
JDK_SHA256=3623232f33a9c3baadf304480b2535f9a3cba8a58d42ecbb438ba267315d9998
if [ "$(uname -s)-$(uname -m)" != "Darwin-arm64" ]; then
  # Only the macOS arm64 JDK is pinned; elsewhere use an existing JAVA_HOME (Java 21+).
  JDK_URL=""
fi

DIR="${PCA_CIBA_KC_DIR:-$HOME/.cache/pca-ciba-keycloak}"
KC_PORT="${PCA_CIBA_KC_PORT:-18480}"
MGMT_PORT="${PCA_CIBA_KC_MGMT_PORT:-18490}"
CHAN_PORT="${PCA_CIBA_CHANNEL_PORT:-18481}"
PING_PORT="${PCA_CIBA_PING_PORT:-18482}"
for p in "$KC_PORT" "$MGMT_PORT" "$CHAN_PORT" "$PING_PORT"; do
  case "$p" in 5442|6389) echo "refusing reserved port $p" >&2; exit 2;; esac
done
ADMIN_USER=admin
ADMIN_PASS=pca-ciba-admin
REALM=pca
CLIENT_ID=pca-ciba
CLIENT_SECRET=pca-ciba-test-secret   # throwaway, local-only
USER_NAME=alice
BASE="http://127.0.0.1:$KC_PORT"

sha_check() { echo "$2  $1" | shasum -a 256 -c - >/dev/null || { echo "sha256 mismatch for $1" >&2; rm -f "$1"; exit 1; }; }

fetch() {
  mkdir -p "$DIR/dl"
  if [ ! -d "$DIR/keycloak-$KC_VERSION" ]; then
    [ -f "$DIR/dl/keycloak.tgz" ] || curl -fL --retry 3 -o "$DIR/dl/keycloak.tgz" "https://github.com/keycloak/keycloak/releases/download/$KC_VERSION/keycloak-$KC_VERSION.tar.gz"
    sha_check "$DIR/dl/keycloak.tgz" "$KC_SHA256"
    mkdir -p "$DIR/x" && tar -xzf "$DIR/dl/keycloak.tgz" -C "$DIR/x" && mv "$DIR/x/keycloak-$KC_VERSION" "$DIR/"
    rmdir "$DIR/x"
  fi
  if [ -z "${JAVA_HOME:-}" ] || ! "$JAVA_HOME/bin/java" -version >/dev/null 2>&1; then
    if /usr/bin/java -version >/dev/null 2>&1; then :; elif [ -n "$JDK_URL" ]; then
      if [ ! -d "$DIR/jdk" ]; then
        [ -f "$DIR/dl/jdk.tgz" ] || curl -fL --retry 3 -o "$DIR/dl/jdk.tgz" "$JDK_URL"
        sha_check "$DIR/dl/jdk.tgz" "$JDK_SHA256"
        mkdir -p "$DIR/jdk" && tar -xzf "$DIR/dl/jdk.tgz" -C "$DIR/jdk" --strip-components=1
      fi
      export JAVA_HOME="$DIR/jdk/Contents/Home"
    else
      echo "no Java 21+ found; set JAVA_HOME" >&2; exit 1
    fi
  fi
  [ -n "${JAVA_HOME:-}" ] && export PATH="$JAVA_HOME/bin:$PATH"
  [ "${PCA_CIBA_KC_KEEP_DL:-}" = 1 ] || rm -rf "$DIR/dl"
}

admin_token() {
  curl -fsS -d client_id=admin-cli -d grant_type=password -d username=$ADMIN_USER -d "password=$ADMIN_PASS" \
    "$BASE/realms/master/protocol/openid-connect/token" | node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(0,"utf8")).access_token)'
}

api() { # api METHOD PATH [json]
  local m=$1 p=$2; shift 2
  curl -fsS -X "$m" -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' ${1:+-d "$1"} "$BASE/admin/realms$p"
}

# api_create LABEL PATH JSON: POST; 201/204 = created, 409 = already exists (idempotent re-run);
# anything else (auth failure, 400, 5xx, no connection) is printed and aborts.
api_create() {
  local label=$1 p=$2 out code
  out=$(mktemp)
  code=$(curl -sS -o "$out" -w '%{http_code}' -X POST -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d "$3" "$BASE/admin/realms$p") || { echo "admin API unreachable while creating $label" >&2; rm -f "$out"; exit 1; }
  case "$code" in
    201|204) echo "($label created)" ;;
    409) echo "($label exists)" ;;
    *) echo "admin API error creating $label: HTTP $code" >&2; cat "$out" >&2; echo >&2; rm -f "$out"; exit 1 ;;
  esac
  rm -f "$out"
}

up() {
  fetch
  if curl -fs "http://127.0.0.1:$MGMT_PORT/health/ready" >/dev/null 2>&1; then echo "keycloak already up"; else
    export KC_BOOTSTRAP_ADMIN_USERNAME=$ADMIN_USER KC_BOOTSTRAP_ADMIN_PASSWORD=$ADMIN_PASS
    export KC_HTTP_PORT=$KC_PORT KC_HTTP_MANAGEMENT_PORT=$MGMT_PORT KC_HTTP_HOST=127.0.0.1 KC_HOSTNAME_STRICT=false KC_HEALTH_ENABLED=true
    nohup "$DIR/keycloak-$KC_VERSION/bin/kc.sh" start-dev \
        --spi-ciba-auth-channel--ciba-http-auth-channel--http-authentication-channel-uri="http://127.0.0.1:$CHAN_PORT/ciba-channel" \
        > "$DIR/keycloak.log" 2>&1 < /dev/null &
    echo $! > "$DIR/kc.pid"
    for i in $(seq 1 120); do curl -fs "http://127.0.0.1:$MGMT_PORT/health/ready" >/dev/null 2>&1 && break; sleep 2; done
    curl -fs "http://127.0.0.1:$MGMT_PORT/health/ready" >/dev/null || { tail -40 "$DIR/keycloak.log"; echo "keycloak did not start" >&2; exit 1; }
  fi
  TOKEN=$(admin_token)
  api_create realm "" "{\"realm\":\"$REALM\",\"enabled\":true,\"accessTokenLifespan\":300,\"attributes\":{
    \"cibaBackchannelTokenDeliveryMode\":\"poll\",\"cibaExpiresIn\":\"120\",\"cibaInterval\":\"2\",\"cibaAuthRequestedUserHint\":\"login_hint\"}}"
  api_create user "/$REALM/users" "{\"username\":\"$USER_NAME\",\"email\":\"alice@example.test\",\"emailVerified\":true,\"firstName\":\"Alice\",\"lastName\":\"Owner\",\"enabled\":true,
    \"credentials\":[{\"type\":\"password\",\"value\":\"alice-pass\",\"temporary\":false}]}"
  api_create client "/$REALM/clients" "{\"clientId\":\"$CLIENT_ID\",\"enabled\":true,\"publicClient\":false,\"secret\":\"$CLIENT_SECRET\",
    \"standardFlowEnabled\":false,\"directAccessGrantsEnabled\":false,\"serviceAccountsEnabled\":false,
    \"attributes\":{\"oidc.ciba.grant.enabled\":\"true\"}}"
  echo "keycloak $KC_VERSION ready at $BASE (realm $REALM)"
}

test_() {
  fetch >/dev/null 2>&1 || true
  ( cd "$PKG" && PCA_CIBA_KEYCLOAK_URL="$BASE" PCA_CIBA_REALM=$REALM PCA_CIBA_CLIENT_ID=$CLIENT_ID PCA_CIBA_CLIENT_SECRET=$CLIENT_SECRET \
      PCA_CIBA_USER=$USER_NAME PCA_CIBA_CHANNEL_PORT=$CHAN_PORT PCA_CIBA_PING_PORT=$PING_PORT PCA_CIBA_KC_VERSION=$KC_VERSION \
      PCA_CIBA_ADMIN_PASSWORD=$ADMIN_PASS PCA_CIBA_RECORD="${PCA_CIBA_RECORD:-}" \
      npx vitest run src/keycloak.integration.test.ts
    if [ "${PCA_CIBA_RECORD:-}" = 1 ]; then node scripts/update-provenance.mjs; fi )
}

down() {
  if [ -f "$DIR/kc.pid" ]; then
    pid=$(cat "$DIR/kc.pid")
    # kc.sh execs java; kill the process group member tree.
    pkill -P "$pid" 2>/dev/null || true; kill "$pid" 2>/dev/null || true
    for i in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    kill -9 "$pid" 2>/dev/null || true
    rm -f "$DIR/kc.pid"
  fi
  [ "${PCA_CIBA_KC_CLEAN:-}" = 1 ] && rm -rf "$DIR" || true
}

case "${1:-all}" in
  up) up;; test) test_;; down) down;;
  all) trap down EXIT; up; test_;;
  *) echo "usage: $0 [up|test|down|all]" >&2; exit 2;;
esac
