#!/usr/bin/env bash
# Queue job (repo root of the job snapshot, --prep full): verify the per-site kill tests written when the TS ledger moved
# to one-entry-per-site keys (the 28 sites whose old text-keyed justification did not hold, plus the gtFromBytes identity
# test). Step 1: plain vitest on just those test files. Step 2: a narrow Stryker run per package, --mutate restricted to
# the exact lines, with only the relevant test files kept (ONLY_TESTS). Reports -> /tmp/pca-audit-stryker/sites-<pkg>.json
#   q submit --prep full --npm-dir tools/pca-audit --cores 2 --mem 6 --wall 5400 --pull /tmp/site-kills-out -- bash tools/pca-audit/stryker/site-kills-box.sh
# (--npm-dir tools/pca-audit is required: Stryker lives in that standalone dir, not in the workspace). SKIP_VITEST=1 skips step 1.
set -uo pipefail
ROOT="$PWD"
# pkg | test files (vitest + ONLY_TESTS) | --mutate line ranges
SPECS=(
  "pca-vdf|src/mutation-kill-sites.test.ts|src/vdf.ts:405-405,src/vdf.ts:458-458"
  "pca-ratchet|src/mutation-kill-sites.test.ts|src/binding.ts:138-139,src/binding.ts:169-170"
  "pca-aggsig|src/mutation-kill-sites.test.ts,src/mutation-kill.test.ts,src/mutation-kill-canon-r2.test.ts|src/chain.ts:186-186,src/chain.ts:200-200,src/core.ts:172-172,src/core.ts:190-190"
  "pca-bbs|src/mutation-kill-sites.test.ts,src/draft-vectors.test.ts,src/bbs.test.ts|src/bbs.ts:184-184,src/credential.ts:155-155,src/credential.ts:234-234"
  "pca-scitt|src/mutation-kill-sites.test.ts|src/index.ts:492-492"
  "pca-sdjwt|src/mutation-kill.test.ts|src/index.ts:337-337"
  "pca-vc|src/mutation-kill-sites.test.ts|src/index.ts:455-455"
  "pca-oprf|src/mutation-kill-sites.test.ts|src/oprf.ts:429-429"
  "pca-pq-threshold|src/mutation-kill-sites.test.ts|src/index.ts:343-343"
  "pca-ciba|src/mutation-kill-sites.test.ts|src/client.ts:288-288"
  "pca-abe|src/mutation-kill-attrs.test.ts|src/bls.ts:203-203"
)
fail=0
echo "=== step 1: vitest"
[ -n "${SKIP_VITEST:-}" ] || for s in "${SPECS[@]}"; do
  IFS='|' read -r pkg tests _ <<<"$s"
  echo "--- $pkg: $tests"
  (cd "packages/$pkg" && npx vitest run ${tests//,/ } 2>&1 | tail -8) || fail=1
done
echo "=== step 2: narrow stryker"
for s in "${SPECS[@]}"; do
  IFS='|' read -r pkg tests mut <<<"$s"
  echo "--- $pkg mutate=$mut"
  # shellcheck disable=SC2086
  PKG="$pkg" ONLY_TESTS="$tests" NO_RELATED=1 bash tools/pca-audit/stryker/run.sh "sites-$pkg" ${mut//,/ } > "/tmp/site-kills-$pkg.log" 2>&1
  [ -f "/tmp/pca-audit-stryker/sites-$pkg.json" ] || { echo "  stryker produced no report:"; tail -15 "/tmp/site-kills-$pkg.log"; continue; }
  node -e '
    const r=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));const c={};
    for(const [f,v] of Object.entries(r.files))for(const m of v.mutants){c[m.status]=(c[m.status]||0)+1;if(m.status==="Survived"||m.status==="NoCoverage")console.log("  SURVIVOR",f+":"+m.location.start.line+":"+m.location.start.column,m.mutatorName,JSON.stringify(m.replacement));}
    console.log("  totals",JSON.stringify(c));' "/tmp/pca-audit-stryker/sites-$pkg.json" || echo "  (no report)"
done
mkdir -p /tmp/site-kills-out && cp /tmp/pca-audit-stryker/sites-*.json /tmp/site-kills-out/ 2>/dev/null
echo "SITE-KILLS DONE fail=$fail"
