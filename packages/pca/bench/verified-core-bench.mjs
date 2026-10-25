// Verified-core cost benchmark: the Dafny-proved implementation (compiled to JS, @atlasauth/pca-verified-core) against
// the hand-written TypeScript it replaces or can replace, one row per production decision point, on the SAME inputs.
//
// Each row reports the median time per call over --rounds rounds (each round runs the function for about --ms ms after a
// warm-up), for the hand-written TypeScript (`ts`) and the proved code (`proved`), and the ratio proved/ts. The results decide
// which modules are wired into production by default and which stay opt-in (PCA_VERIFIED_CORE), see
// docs/pca/security/verified-core.md "Production wiring of the extension components".
//
// The `ts` side is the FROZEN hand-written code (the test oracles under packages/pca-verified-core/test/support/legacy, built to
// dist-legacy by this script's caller) when available, else the production export; the `proved` side is the verified-core
// adapter. Both are pure; no I/O is measured.
//
// Usage (repo root, after `pnpm --filter @atlasauth/pca-verified-core build && pnpm --filter @atlasauth/pca build`):
//   node packages/pca/bench/verified-core-bench.mjs [--ms 300] [--rounds 7] [--out packages/pca/bench/results/verified-core.json]
import { createRequire } from 'node:module';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { cpus, release } from 'node:os';
import { performance } from 'node:perf_hooks';
import * as pca from '../dist/index.js';

const require = createRequire(import.meta.url);
const vc = require('@atlasauth/pca-verified-core');

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), []),
);
const MS = Number(args.ms ?? 300);
const ROUNDS = Number(args.rounds ?? 7);
const OUT = args.out ?? 'packages/pca/bench/results/verified-core.json';
const ONLY = args.only ? new Set(args.only.split(',')) : null;

/** median ns/call of fn over ROUNDS rounds of ~MS ms each (after one warm-up round). */
function measure(fn) {
  let sink = 0;
  const once = () => {
    const r = fn();
    if (r === undefined || r === null || r === false) sink += 1;
    else sink += 2;
  };
  // warm-up and calibration: find a batch size that takes >= 5 ms
  let batch = 1;
  for (;;) {
    const t0 = performance.now();
    for (let i = 0; i < batch; i++) once();
    const dt = performance.now() - t0;
    if (dt >= 5 || batch >= 1 << 22) break;
    batch *= 2;
  }
  const per = [];
  for (let r = 0; r < ROUNDS + 1; r++) {
    let n = 0;
    const t0 = performance.now();
    let t = t0;
    while (t - t0 < MS) {
      for (let i = 0; i < batch; i++) once();
      n += batch;
      t = performance.now();
    }
    if (r > 0) per.push(((t - t0) * 1e6) / n);
  }
  per.sort((a, b) => a - b);
  if (sink === 0) throw new Error('unreachable');
  return { median_ns: per[per.length >> 1], min_ns: per[0], max_ns: per[per.length - 1] };
}

const rows = [];
function row(module, name, note, tsFn, provedFn, check) {
  if (ONLY && !ONLY.has(module)) return;
  const a = tsFn();
  const b = provedFn();
  const same = check ? check(a, b) : JSON.stringify(a) === JSON.stringify(b);
  if (!same) throw new Error(`${module}/${name}: the two implementations disagree on the benchmark input: ${JSON.stringify(a)} vs ${JSON.stringify(b)}`);
  const ts = measure(tsFn);
  const pr = measure(provedFn);
  const r = { module, name, note, ts_ns: Math.round(ts.median_ns), proved_ns: Math.round(pr.median_ns), ratio: +(pr.median_ns / ts.median_ns).toFixed(2) };
  rows.push(r);
  console.log(`${module.padEnd(9)} ${name.padEnd(44)} ts ${String(r.ts_ns).padStart(10)} ns  proved ${String(r.proved_ns).padStart(11)} ns  x${r.ratio}`);
}

// ---------------------------------------------------------------- taint
{
  const reg = new pca.taint.InMemoryTrustedInputRegistry();
  for (let i = 0; i < 8; i++) reg.recordTrusted(`sha256:t${i}`);
  reg.recordTool('sha256:tool0', 'search');
  reg.recordWeb('sha256:web0');
  const graph = { node: (id) => (id.startsWith('res:') ? { id } : undefined) };
  const ctx = { registry: reg, resourceGraph: graph };
  const prov3 = { causal_hash: 'x', trusted_refs: ['sha256:t0', 'sha256:t1', 'res:/acct/1'] };
  const prov12 = { trusted_refs: [...Array.from({ length: 8 }, (_, i) => `sha256:t${i}`), 'sha256:tool0', 'sha256:web0', 'res:/a', 'unknown-ref'] };
  row('taint', 'computeTaint (3 refs)', 'pcactn enforce.taint gate', () => pca.taint.computeTaint(prov3, ctx), () => vc.computeTaintVerified(prov3, ctx));
  row('taint', 'computeTaint (12 refs)', '', () => pca.taint.computeTaint(prov12, ctx), () => vc.computeTaintVerified(prov12, ctx));
}

// ---------------------------------------------------------------- merkle
{
  const leaves = Array.from({ length: 64 }, (_, i) => ({ node: `n${i}`, verb: 'read', resource: `/doc/${i}` }));
  const root = pca.merkleRoot(leaves);
  const proof = pca.merkleProof(leaves, 37);
  const leafBytes = pca.canonicalBytes(leaves[37]);
  row('merkle', 'verifyInclusion (64 leaves, plan proof)', 'pcactn plan check', () => pca.verifyInclusion(root, proof, leaves[37]), () => vc.verifyInclusionVerified(root, proof, pca.canonicalBytes(leaves[37])));
  const big = Array.from({ length: 4096 }, (_, i) => `c${i}`);
  const broot = pca.merkleRoot(big);
  const bproof = pca.merkleProof(big, 3001);
  row('merkle', 'verifyInclusion (4096 leaves)', '', () => pca.verifyInclusion(broot, bproof, big[3001]), () => vc.verifyInclusionVerified(broot, bproof, pca.canonicalBytes(big[3001])));
  // consistency: proved generator (byte-equal to ledger.ts, ext-merkle.diff.test.ts) for a 100 -> 1000 append-only extension
  const lv = Array.from({ length: 1000 }, (_, i) => new Uint8Array([i & 255, i >> 8, 7]));
  const r100 = pca.b64u(vc.merkleRootVerified(lv.slice(0, 100)));
  const r1000 = pca.b64u(vc.merkleRootVerified(lv));
  const cp = vc.consistencyProofVerified(lv, 100);
  row('merkle', 'verifyLedgerConsistency (100 -> 1000)', 'ledger / witness heads', () => pca.verifyLedgerConsistency(r100, r1000, cp), () => vc.verifyConsistencyVerified(r100, r1000, cp));
  // revocation membership
  const rs = new pca.RevocationSet(Array.from({ length: 256 }, (_, i) => `cap_${i}`));
  const mroot = rs.root;
  const mproof = rs.membershipProof('cap_99');
  row('merkle', 'verifyMembership (256 revoked)', 'revocation checker', () => pca.verifyMembership(mroot, mproof, 'cap_99'), () => vc.verifyMembershipVerified(mroot, mproof, pca.canonicalBytes('cap_99')));
}

// ---------------------------------------------------------------- attestation
{
  const id = { model_id: 'm1', weights_digest: 'w1', weights_measured: true, runtime_measurement: '7', operator: 'op', system_prompt_digest: 's1', tool_manifest_digest: 't1' };
  const binding = { model_allowlist: ['m0', 'm1'], min_measurement: { svn: 5 }, operator: 'op', require_measured_weights: true, weights_allowlist: ['w1'], system_prompt_allowlist: ['s1'], tool_manifest_allowlist: ['t1'] };
  row('attest', 'matchAgentBinding (all pins)', 'attestation gate', () => pca.matchAgentBinding(id, binding), () => vc.matchAgentBindingVerified(id, binding));
  row('attest', 'requiresAttestation', '', () => pca.requiresAttestation(binding), () => vc.requiresAttestationVerified(binding));
  // nonce store: consume N distinct nonces into a fresh store (per-call cost grows with the store size if the model copies)
  for (const n of [100, 2000]) {
    let t = 1_800_000_000_000;
    const now = () => t;
    const mk = (S) => () => {
      const s = S();
      let ok = 0;
      for (let i = 0; i < n; i++) {
        t += 1;
        if (s.consume(`nonce-${i}`)) ok++;
      }
      return ok;
    };
    row('attest', `nonce store: ${n} consumes into a fresh store`, 'per batch', mk(() => pca.memoryNonceStore(100_000, { now })), mk(() => new vc.VerifiedMemoryNonceStore(100_000, { now })));
  }
}

// ---------------------------------------------------------------- policy VM
{
  const vm = vc.createPolicyVm({ safeRegex: pca.isSafeRegexSource, regexFullMatch: pca.safeRegexFullMatch });
  const preds = [
    { verb: ['read', 'list'], resource: '/docs/*' },
    { verb: 'transfer', resource: '/acct/*', where: [{ path: 'action.params.amount', op: 'lte', value: 500 }, { any_of: [{ path: 'action.params.currency', op: 'eq', value: 'USD' }, { path: 'action.params.currency', op: 'eq', value: 'EUR' }] }] },
  ];
  const ctx = { action: { verb: 'transfer', resource: '/acct/42', params: { amount: 120, currency: 'EUR' } } };
  row('policyvm', 'evaluatePredicates (2 preds, nested where)', 'decide() step 1', () => pca.evaluatePredicates(preds, ctx), () => vm.evaluatePredicates(preds, ctx), (a, b) => a.allowed === b.allowed);
  const pol = pca.DEFAULT_RISK_POLICY;
  row('policyvm', 'requiredThreshold kernel', 'decide() step 3', () => pca.requiredThreshold(0.42, pol, { irreversible: true }), () => vc.requiredThresholdVerified(0.42, pol.theta1, pol.theta2, true));
  row('policyvm', 'admit + decideCore kernels', 'decide() steps 4-5', () => {
    const rt = pca.requiredThreshold(0.42, pol, { irreversible: false });
    return pca.escalateThreshold(rt, rt.t);
  }, () => {
    const rt = vc.requiredThresholdVerified(0.42, pol.theta1, pol.theta2, false);
    const adm = vc.admitVerified(rt.t, true);
    return vc.decideCoreVerified(true, true, true, true, rt, adm).threshold;
  });
}

// ---------------------------------------------------------------- regex
{
  const src = '[a-z]+/[0-9]{1,4}(/[a-z_]+)?';
  row('regex', 'safeRegexFullMatch (short pattern, 20-char subject)', 're: resource match', () => pca.safeRegexFullMatch(src, 'invoices/2024/q3_list'), () => vc.safeRegexFullMatchVerified(src, 'invoices/2024/q3_list'));
  row('regex', 'isSafeRegexSource (guard)', '', () => pca.isSafeRegexSource(src), () => vc.isSafeRegexSourceVerified(src));
}

// ---------------------------------------------------------------- wire
{
  const doc = {
    v: 2, aud: 'rs-bench', iat: 1_800_000_000_000, exp: 1_800_000_060_000, counter: 7, nonce: 'bm9uY2Utbm9uY2Utbm9uY2U',
    grant_ref: 'cap_root_0123456789', action: { verb: 'transfer', resource: '/acct/42', params: { amount: 120, currency: 'EUR', memo: 'q3 é中' } },
    cap_chain: Array.from({ length: 4 }, (_, i) => ({ id: `cap_${i}`, issuer: 'a'.repeat(43), holder: 'b'.repeat(43), caveats: [{ type: 'expires_at', at: 1_800_000_000_000 + i }], sig: 'c'.repeat(86) })),
    sig: 'd'.repeat(86),
  };
  const text = JSON.stringify(doc);
  row('wire', `strictParse+canonicalizeStrict (${text.length} chars)`, 'every PCActn on the wire', () => pca.canonicalizeStrict(pca.strictParse(text)), () => vc.wireCanonicalOfText(text));
  const arr = JSON.stringify({ items: Array.from({ length: 1000 }, (_, i) => ({ k: i })) });
  row('wire', `strictParse+canonicalize (1000-member array, ${arr.length} chars)`, 'quadratic in members', () => pca.canonicalizeStrict(pca.strictParse(arr)), () => vc.wireCanonicalOfText(arr));
  const b = new Uint8Array(32).map((_, i) => i * 7);
  const s = pca.b64u(b);
  row('wire', 'decodeB64uStrict (32 bytes)', 'every signature / key', () => Array.from(pca.decodeB64uStrict(s, 32)), () => Array.from(vc.wireDecodeB64uStrict(s, 32)));
}

const out = { node: process.version, os: release(), cpu: cpus()[0]?.model, ms: MS, rounds: ROUNDS, rows };
mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify(out, null, 1));
console.log(`wrote ${OUT}`);
