#!/usr/bin/env bash
# Regenerate the differential fixtures with the REAL engines (Cedar via the cedar-policy crate, OPA binary).
# Needs: cargo, curl, node. Run on the build box, from packages/pca-policy-bridge/differential.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"
OPA_VERSION=v0.70.0
N_CEDAR=${N_CEDAR:-400}; N_REGO=${N_REGO:-400}; SEED=${SEED:-1}
mkdir -p .work fixtures
( cd cedar-runner && cargo build --release -j 2 -q )
node gen.mjs cedar "$N_CEDAR" "$SEED" > .work/cedar-in.jsonl
./cedar-runner/target/release/cedar-runner < .work/cedar-in.jsonl > .work/cedar-out.jsonl
if [ ! -x .work/opa ]; then
  curl -sSL -o .work/opa "https://github.com/open-policy-agent/opa/releases/download/$OPA_VERSION/opa_linux_amd64_static"
  chmod +x .work/opa
fi
node gen.mjs rego "$N_REGO" "$SEED" > .work/rego-in.jsonl
node merge.mjs "$OPA_VERSION"

# OpenFGA: a real server (in-memory datastore) decides the generated models.
OPENFGA_VERSION=${OPENFGA_VERSION:-v1.8.4}
N_FGA=${N_FGA:-150}
if [ ! -x .work/openfga ]; then
  curl -sSL "https://github.com/openfga/openfga/releases/download/$OPENFGA_VERSION/openfga_${OPENFGA_VERSION#v}_linux_amd64.tar.gz" | tar -xz -C .work openfga
fi
node gen.mjs openfga "$N_FGA" "$SEED" > .work/openfga-in.jsonl
.work/openfga run --datastore-engine memory --playground-enabled=false --http-addr 127.0.0.1:18080 --grpc-addr 127.0.0.1:18081 > .work/openfga.log 2>&1 &
FGA_PID=$!
trap 'kill $FGA_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do curl -sf http://127.0.0.1:18080/healthz >/dev/null && break; sleep 0.2; done
node openfga.mjs http://127.0.0.1:18080 < .work/openfga-in.jsonl
node -e "const f=require('fs');const p='fixtures/ENGINES.json';const j=JSON.parse(f.readFileSync(p));j.openfga=process.argv[1];f.writeFileSync(p,JSON.stringify(j,null,2)+'\n')" "$OPENFGA_VERSION"
