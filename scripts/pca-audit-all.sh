#!/usr/bin/env bash
# Re-run the cheap parts of the PCA "external audit in code" program with ONE command:
#
#     bash scripts/pca-audit-all.sh            # about 2-4 minutes, offline, no downloads
#     bash scripts/pca-audit-all.sh --full     # adds the slow / networked parts (see below)
#
# Cheap parts (default):
#   1  fuzz regression gate      fixed-seed run of every fuzz target (parsers, verifiers, attestation evidence, SCITT/COSE,
#                                policy bridges, glob/regex) + replay of every stored crasher; any untyped throw, hang >1 s,
#                                prototype pollution or accepted-mutant fails
#   2  regression + mutation-kill suites   the unit tests that pin every defect the program found and every Stryker survivor
#   2b mutation-equivalents ledgers checker self-test, then static check of the TS and native ledgers: every justified-
#                                equivalent mutant names exactly ONE site (line text + occurrence) that still exists
#   2c unsafe trusted-root scan    no template/example/doc/README/sample/playground takes the trusted root from the request or cap_chain[0] (R5-B1)
#   2d PQ pinning scan             every PQ verification routes through the pinned choke point (R3-01, widened R5-B2)
#   3  threat-model traceability  every T-001..T-051 attack and G-xx guarantee maps to an existing test
#   4  eslint-plugin-security     any finding not triaged in tools/pca-audit/static/triage.json fails
#   5  supply chain               CycloneDX SBOM per published package, lockfile integrity, install-script scan
#   6  timing harness self-check  the leaky positive control must be flagged by the dudect-style harness
#   7  secret scan                gitleaks over the PCA paths (SKIPPED, never "passed", when the binary is absent)
# --full adds: Stryker mutation scores, long fuzz run (--fuzz-ms), full timing run, osv-scanner, semgrep, cargo clippy
#              -D warnings + cargo deny, pip-audit, and the 8-language conformance run.
#
# Exit status is non-zero if any step FAILED. SKIPPED steps are listed and never counted as passed.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/usr/local/bin:$HOME/.local/bin:/opt/homebrew/bin:$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$HOME/.cargo/bin:$PATH"
FULL=0; FUZZ_MS=20000
for a in "$@"; do case "$a" in --full) FULL=1;; --fuzz-ms=*) FUZZ_MS="${a#*=}";; -h|--help) sed -n 2,26p "$0"; exit 0;; esac; done
TSX="$ROOT/packages/pca/node_modules/.bin/tsx"
VITEST="$ROOT/packages/pca/node_modules/.bin/vitest"
OUT="${PCA_AUDIT_OUT:-$(mktemp -d "${TMPDIR:-/tmp}/pca-audit.XXXXXX")}"
TOOLS="${PCA_AUDIT_TOOLS:-/tmp/pca-audit-tools}"   # optional third-party binaries (gitleaks, osv-scanner, cargo-deny)
declare -a RESULTS
FAILED=0
step() { # step "name" cmd...
  local name="$1"; shift
  local log="$OUT/$(echo "$name" | tr -c 'A-Za-z0-9' '_').log"
  printf '%-44s ' "$name"
  if "$@" >"$log" 2>&1; then echo PASS; RESULTS+=("PASS  $name")
  else local rc=$?; if [ "$rc" = 2 ] && grep -q '^SKIPPED' "$log"; then echo "SKIPPED ($(grep -m1 '^SKIPPED' "$log"))"; RESULTS+=("SKIP  $name")
       else echo "FAIL  (log: $log)"; tail -15 "$log" | sed 's/^/    /'; RESULTS+=("FAIL  $name"); FAILED=1; fi; fi
}
skip() { echo "SKIPPED: $1"; exit 2; }
echo "PCA audit-in-code  |  logs: $OUT"

step "1 fuzz regression gate"           "$TSX" tools/pca-audit/fuzz/fuzz.ts --regress
step "2 regression + mutation-kill tests" bash -c "cd packages/pca && '$VITEST' run src/audit-regressions.test.ts src/fuzz-regressions.test.ts src/mutation-kill-replay.test.ts src/mutation-kill-threshold.test.ts src/mutation-kill-pcactn.test.ts src/threat-model-gaps.test.ts && cd ../pca-policy-bridge && '$VITEST' run && cd ../pca-vc && '$VITEST' run && cd ../pca-analyzer && '$VITEST' run"
step "2b mutation-equivalents ledgers"   bash -c "node tools/pca-audit/check-equivalents.selftest.mjs && node tools/pca-audit/stryker/check-equivalents.mjs && node tools/pca-audit/native-check-equivalents.mjs"
step "2c unsafe trusted-root scan"       bash -c "node scripts/check-unsafe-trusted-root.mjs --self-test && node scripts/check-unsafe-trusted-root.mjs"
step "2d PQ pinning scan"               bash -c "node scripts/check-pq-pinning.mjs --self-test && node scripts/check-pq-pinning.mjs"
step "3 threat-model traceability"       node scripts/check-pca-traceability.mjs
step "4 eslint-plugin-security triage"   node tools/pca-audit/static/check-eslint.mjs
step "5 supply chain (SBOM, lock, scripts)" bash -c "node tools/pca-audit/supply/sbom.mjs --out '$OUT/sbom' && node tools/pca-audit/supply/check.mjs '$OUT/sbom/summary.json'"
step "5b playground bundle fresh"      bash tools/pca-playground/check-fresh.sh
step "6 timing harness self-check"       "$TSX" tools/pca-audit/timing/dudect.ts --n 3000 --only CONTROL
GL="$(command -v gitleaks || ls "$TOOLS"/gl/gitleaks 2>/dev/null || true)"
step "7 secret scan (gitleaks)"          bash -c "[ -n '$GL' ] || { echo 'SKIPPED: gitleaks not installed (set PCA_AUDIT_TOOLS or install it)'; exit 2; }; fail=0; for d in packages/pca packages/pca-* sdks/*pca* docs/pca tools/pca-* scripts/pca-*; do [ -e \"\$d\" ] || continue; '$GL' dir \"\$d\" --config tools/pca-audit/static/gitleaks.toml --no-banner --max-target-megabytes 5 >/dev/null 2>&1 || { echo \"leak(s) in \$d\"; fail=1; }; done; exit \$fail"

if [ "$FULL" = 1 ]; then
  echo "--- full run ---"
  step "F1 long fuzz (${FUZZ_MS} ms per target)" "$TSX" tools/pca-audit/fuzz/fuzz.ts --target all --ms "$FUZZ_MS" --seed 20261009
  step "F2 timing (full)"                "$TSX" tools/pca-audit/timing/dudect.ts --n 20000 --json "$OUT/timing.json"
  # F3: full Stryker re-run of every security-critical module (slow: runs one module at a time), then fail if ANY survivor is not in the equivalents ledger
  # or any ledger entry is stale. Modules: STRYKER_MODULES (space separated, paths relative to packages/pca).
  MODS="${STRYKER_MODULES:-src/pcactn.ts src/server/verify.ts src/server/require-pca.ts src/capability.ts src/threshold.ts src/replay.ts src/hash.ts src/strict-json.ts src/approvals.ts src/ledger.ts src/attestation.ts src/pq.ts src/durable-state.ts src/attest-allowlist.ts src/attest-allowlist-anchor.ts src/attest-intel-dcap.ts src/attest-amd-snp.ts src/hardware-sevsnp.ts src/attest-nvidia-spdm.ts src/attest-azure-maa.ts src/frost.ts}"
  step "F3 stryker (all critical modules) + ledger check" bash -c "set -e; for m in $MODS; do n=\$(basename \$m .ts); bash tools/pca-audit/stryker/run.sh \$n \$m; node tools/pca-audit/stryker/check-equivalents.mjs /tmp/pca-audit-stryker/\$n.json; done"
  OSV="$(command -v osv-scanner || ls "$TOOLS"/osv-scanner_darwin_arm64 2>/dev/null || true)"
  step "F5 osv-scanner (lockfiles)"      bash -c "[ -n '$OSV' ] || { echo 'SKIPPED: osv-scanner not installed'; exit 2; }; '$OSV' scan source --format json --output-file '$OUT/osv.json' -L pnpm-lock.yaml \$(git ls-files '*Cargo.lock' | sed 's/^/-L /') ; test -s '$OUT/osv.json'"
  step "F6 semgrep (js/ts/security-audit)" bash -c "command -v uvx >/dev/null || { echo 'SKIPPED: uvx not installed'; exit 2; }; uvx semgrep scan --metrics=off --config p/javascript --config p/typescript --config p/security-audit --config p/nodejs --exclude '*.test.ts' --exclude node_modules --exclude dist --include '*.ts' --jobs 2 --error packages/pca/src packages/pca-*/src"
  step "F7 cargo clippy -D warnings (rust-pca)" bash -c "command -v cargo >/dev/null || { echo 'SKIPPED: cargo not installed'; exit 2; }; cd sdks/rust-pca && CARGO_TARGET_DIR=\$(mktemp -d) cargo clippy --all-targets --locked -- -D warnings"
  CD="$(command -v cargo-deny || ls "$TOOLS"/cd/*/cargo-deny 2>/dev/null || true)"
  step "F8 cargo deny (rust-pca)"        bash -c "[ -n '$CD' ] || { echo 'SKIPPED: cargo-deny not installed'; exit 2; }; cd sdks/rust-pca && '$CD' check advisories sources bans"
  step "F9 pip-audit (python-pca extras)" bash -c "command -v uv >/dev/null || { echo 'SKIPPED: uv not installed'; exit 2; }; cd sdks/python-pca && uv pip compile pyproject.toml --all-extras -o '$OUT/py.txt' --quiet --python-version 3.12 && uvx pip-audit -r '$OUT/py.txt' --no-deps --disable-pip"
  step "F10 8-language conformance"      bash scripts/pca-conformance-all.sh --fuzz 0 --sweep 0 --no-native --out "$OUT/conf"
fi

echo; echo "== summary =="; printf '%s\n' "${RESULTS[@]}"
[ "$FAILED" = 0 ] && echo "ALL EXECUTED STEPS PASSED (skipped steps are not passes)" || echo "FAILURES PRESENT"
exit "$FAILED"
