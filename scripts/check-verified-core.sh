#!/usr/bin/env bash
# check-verified-core.sh  --  CI gate for the Dafny-proved decision core (docs/pca/security/verified-core.md).
#   (a) formal/dafny/build.sh --check   proves every lemma and fails unless the committed generated JS is byte-identical to a fresh compile
#       formal/dafny/build-ext.sh <C> --check   the same for every standalone model (Regex, Wire, Merkle, Taint, Attest, PolicyVm)
#   (b) differential tests              production (verified-core-backed) vs the frozen pre-wiring TypeScript
#   (c) static wiring scan              packages/pca/src decision paths must still CALL the verified core (a refactor cannot silently bypass it)
# Flags: --no-dafny (skip a), --no-tests (skip b), --scan-only (c only). Heavy steps run through formal/dafny/build.sh (local dafny or cloud box)
# and `pnpm --filter @atlasauth/pca-verified-core test` (set VC_TEST_CMD to run it elsewhere, e.g. on a cloud box).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${PCA_SRC_DIR:-$ROOT/packages/pca/src}"
RUN_DAFNY=1; RUN_TESTS=1
for a in "$@"; do case "$a" in --no-dafny) RUN_DAFNY=0;; --no-tests) RUN_TESTS=0;; --scan-only) RUN_DAFNY=0; RUN_TESTS=0;; *) echo "unknown flag $a" >&2; exit 2;; esac; done
fail=0

if [ "$RUN_DAFNY" = 1 ]; then
  echo "== (a) Dafny proofs + generated-JS reproducibility"
  bash "$ROOT/formal/dafny/build.sh" --check || { echo "FAIL (a)"; fail=1; }
  for C in Regex Wire Merkle Taint Attest PolicyVm Goal; do
    echo "== (a') $C.dfy proofs + generated JS reproducibility"
    bash "$ROOT/formal/dafny/build-ext.sh" "$C" --check || { echo "FAIL (a') $C: generated JS is stale or $C.dfy does not verify"; fail=1; }
  done
fi

if [ "$RUN_TESTS" = 1 ]; then
  echo "== (b) differential tests (production vs frozen legacy)"
  if [ -n "${VC_TEST_CMD:-}" ]; then bash -c "$VC_TEST_CMD" || { echo "FAIL (b)"; fail=1; }
  else (cd "$ROOT" && pnpm --filter @atlasauth/pca-verified-core test) || { echo "FAIL (b)"; fail=1; }; fi
fi

echo "== (c) wiring scan of $SRC"
# need <file> <fixed-string> <why>: the file must contain the string (outside comments-only lines).
need() {
  local f="$SRC/$1" pat="$2" why="$3"
  if [ ! -f "$f" ]; then echo "  MISSING FILE $1"; fail=1; return; fi
  if grep -vE '^[[:space:]]*(//|\*|/\*)' "$f" | grep -qF -- "$pat"; then echo "  ok   $1: $why"; else echo "  FAIL $1: no call to '$pat' ($why)"; fail=1; fi
}
need capability.ts "decideChain<"            "chain walk / depth / attenuation decided by Chain.dfy VerifyChain"
need capability.ts "from '@atlasauth/pca-verified-core'" "imports the verified core"
need capability.ts "pqBinding("              "F-2 PQ-binding rule (Verdict.dfy)"
need capability.ts "suitePolicy("            "F-4 suite policy rule (Verdict.dfy)"
need threshold.ts  "decideThreshold<"        "distinct-role count / signer-set validation decided by Threshold.dfy Verify"
need replay.ts     "replayPre("              "replay pre-checks (no store call before them) decided by Replay.dfy Pre"
need replay.ts     "replayNonceStage("       "consume-once nonce plan decided by Replay.dfy NonceStage"
need replay.ts     "replayDecide("           "replay verdict decided by Replay.dfy Decide"
need pcactn.ts     "CoreState"               "check fold of verifyPCActnCore (Verdict.dfy)"
need pcactn.ts     "capChainStatus<"         "cap_chain status (Verdict.dfy)"
need server/verify.ts "VerdictState"         "verifyPCActn combinator (Verdict.dfy)"
need server/verify.ts "enforceRequired("     "enforceRequired (Verdict.dfy)"
# extension components wired into production by default (docs/pca/security/verified-core.md "Production wiring")
need taint.ts      "computeTaintVerified("   "computeTaint decided by Taint.dfy ComputeSafe"
need pcactn.ts     "taintGateVerified("      "enforce.taint gate decided by Taint.dfy Gate"
need merkle.ts     "verifyInclusionVerified(" "Merkle inclusion decided by Merkle.dfy VerifyInclusion"
need attestation.ts "matchAgentBindingVerified(" "agent_binding match decided by Attest.dfy MatchBinding"
need attestation.ts "requiresAttestationVerified(" "attestation-required flag decided by Attest.dfy RequiresAttestation"
need attestation.ts "createMultiRootVerifierVerified(" "multi-root N-of-M decided by Attest.dfy RunIff"
need attestation.ts "verifyAttestationProved(" "attestation stage order decided by Attest.dfy Order / GateStep"
need attestation.ts "createAttestationVerifierProved(" "hook single-use rule decided by Attest.dfy NeedsConsume / HookFinal"
need attest-allowlist.ts "verifyAllowlistDurableProved(" "durable high-water mark decided by Attest.dfy UpdateFn / DurableStep"
need attest-allowlist-anchor.ts "verifyAllowlistAnchoredProved(" "anchored feed decided by Attest.dfy HeadFreshness / CacheStage / AnchorScan"
need attest-proved.ts "DF.GateStep("         "attestation stages folded by the proved GateStep"
need policy-vm.ts  "requiredThresholdVerified(" "decide() threshold band (PolicyVm.dfy ReqThr)"
need policy-vm.ts  "admitVerified("          "decide() budget admission (PolicyVm.dfy AdmitOf)"
need policy-vm.ts  "decideCoreVerified("     "decide() release / admit / debit (PolicyVm.dfy DecideCore)"
# the legacy decision loops must be GONE from the production files (a re-introduced hand-written copy would bypass the proofs)
absent() {
  local f="$SRC/$1" pat="$2" why="$3"
  if grep -vE '^[[:space:]]*(//|\*|/\*)' "$f" | grep -qE -- "$pat"; then echo "  FAIL $1: hand-written decision logic is back ('$pat'): $why"; fail=1; else echo "  ok   $1: no hand-written '$pat'"; fi
}
absent capability.ts "c\.caveats\.length < parent\.caveats\.length" "caveat-prefix attenuation must live in Chain.dfy"
absent capability.ts "chain\.length > MAX_CHAIN_DEPTH" "depth bound must come from the verified walk"
absent threshold.ts "validKeys\.add|keyOfRole\.set" "distinct-role counting must come from the verified core"
absent replay.ts "p\.iat > opts\.now" "window checks must come from the verified Pre"
absent taint.ts "label: classifyRef\(ref, ctx\)" "computeTaint's classification and join must come from Taint.dfy (joinLabels / classifyRef stay as public helpers only)"
absent merkle.ts "function pathShape" "inclusion path shape must come from Merkle.dfy"
absent policy-vm.ts "const autoAdmit = release && adm\.admit" "release / admit must come from PolicyVm.dfy DecideCore"
absent attestation.ts "if \(doc\.binding !== expectedBinding\)" "attestation stages must come from attest-proved.ts (Attest.dfy)"
[ "$fail" = 0 ] && echo "verified-core check: OK" || { echo "verified-core check: FAILED"; exit 1; }
