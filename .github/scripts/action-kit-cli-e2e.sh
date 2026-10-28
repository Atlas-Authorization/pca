#!/usr/bin/env bash
# action-kit-cli-e2e.sh : the README hello world, from an empty directory to a signed pack, with the BUILT pca CLI
# (packages/pca-cli/dist). Repo root, after `pnpm --filter @atlasauth/pca-cli... run build`. Every step must behave as documented:
# the good path exits 0, a lint error / an edited build / a tampered signature exits non-zero.
set -euo pipefail
REPO="$(pwd)"
CLI="node ${PCA_CLI_JS:-$REPO/packages/pca-cli/dist/cli.js}"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
cd "$W"

step() { echo; echo "== $*"; }
must_fail() { if "$@" >out.txt 2>&1; then echo "EXPECTED FAILURE: $*"; cat out.txt; exit 1; fi; }

step "init"
$CLI actions init --ns acme
test -f actions/acme.yaml && test -f actions/pca.config.json

step "lint (strict), test, explain"
$CLI actions lint --strict | tee lint.txt
grep -q "0 errors, 0 warnings, 1 note" lint.txt
$CLI actions test | tee test.txt
grep -q "PASS  acme.invoice.send example 1: expected allow, got allow" test.txt
! grep -q FAIL test.txt
$CLI actions explain acme.invoice.send | tee explain.txt
grep -q "grant must carry: rate_cap, recipient_scope, resource_scope" explain.txt
grep -q "escalation: confirm" explain.txt

step "build, sign, publish (offline), verify"
$CLI actions build
for f in schema.json pack.json cards.json ontology.json mcp.json types.d.ts; do test -s ".pca/$f"; done
SK="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"
$CLI actions sign --kid site-1 --key "$SK"
$CLI actions publish
test -s .pca/.well-known/pca-actions.json
$CLI schema verify .pca/pca-actions.json .pca/keys.json 2>/dev/null | grep -q "^OK"

step "a tampered signed schema is not published"
cp -r .pca .pca.good
node -e "const f='.pca/pca-actions.json',s=JSON.parse(require('fs').readFileSync(f));s.verbs[0].floors.esc=0;require('fs').writeFileSync(f,JSON.stringify(s))"
must_fail $CLI actions publish
rm -rf .pca && mv .pca.good .pca

step "an edited build is not signed"
node -e "const f='.pca/pack.json',s=JSON.parse(require('fs').readFileSync(f));s.defs[0].title='Send money';require('fs').writeFileSync(f,JSON.stringify(s))"
must_fail $CLI actions sign --kid site-1 --key "$SK"
$CLI actions build

step "a lint error fails, with SARIF"
cat > actions/bad.yaml <<'YAML'
ns: acme
actions:
  - {verb: acme.invoice.remove, title: Remove an invoice, effects: [update], resource: "acme.invoice:*@one", params: {invoice: "id:acme.invoice"}}
YAML
must_fail $CLI actions lint
grep -q "LD-001" out.txt && grep -q "LD-008" out.txt
$CLI actions lint --format sarif > sarif.json || true
node -e "const s=JSON.parse(require('fs').readFileSync('sarif.json'));if(s.version!=='2.1.0'||!s.runs[0].results.some(r=>r.ruleId==='LD-001'))process.exit(1)"
must_fail $CLI actions build
rm actions/bad.yaml

step "import an MCP tool list: drafts are unreviewed and escalate"
cat > tools.json <<'JSON'
{"tools":[{"name":"delete_order","inputSchema":{"type":"object","properties":{"id":{"type":"string","maxLength":40}},"required":["id"]},"annotations":{"destructiveHint":true}}]}
JSON
$CLI actions import tools.json --from mcp --ns shop --out actions/shop.yaml
$CLI actions lint
$CLI actions explain shop.delete_order | tee imp.txt
grep -q "review: unreviewed" imp.txt && grep -q "escalation: cosign" imp.txt
$CLI actions build

step "diff"
cp -r actions actions.old
sed -i.bak 's/max_len: 40/max_len: 400/' actions/shop.yaml && rm actions/shop.yaml.bak
$CLI actions diff actions.old actions | tee diff.txt || true
grep -q "^widen *shop.delete_order" diff.txt
echo "e2e ok"
