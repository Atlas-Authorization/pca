// Oracle: the pure parts of the 0.6 parity surface that natives were missing: hash-suite agility (hashCanonical under a suite, b64uLen, isHashSuite,
// isCanonicalB64u, strictNumberError), meetAll, isBudgetAllocCaveat, the budget algebra (subBudget, debitConsolidated, debitConsolidatedPath, recharge,
// rechargeFull), the receipt log (receiptFor, appendReceipt, verifyReceiptChain, receiptHead), discovery parsing, detectorPolicyError,
// pcactnCheapClaims, resolveReversibilityClass, agentCaveatContext, collectObligations, decideLayers / decideLayerCeilings. TS reference.
// Written for the Kotlin lane; reusable by any native. No keys, no clock. Out/ref-core-parity-pure.json.gz.
// PORTING (fn(args) -> native entry point; results compared by JSON value, a reference throw = the native throws):
//   hashCanonical(value, suite)            -> base64url digest (suite "sha256" | "sha384" | other = the reference's behaviour)
//   b64uLen(n) / isHashSuite(x) / isCanonicalB64u(s, len|null) / strictNumberError(n)
//   meetAll(list) / isBudgetAllocCaveat(x)
//   subBudget(parent, alloc) / debitConsolidated(parent, sub, c) / debitConsolidatedPath(path, c) / recharge(b, rho, bMax, now) / rechargeFull(b, bMax, now)
//   receiptFor(prev, seq, pcactn, verify {allow, checks?}, at|null) / appendReceipt(log, pcactn, verify, at|null) / verifyReceiptChain(log) / receiptHead(log)
//   parseDiscoveryDocument(v) / parseDiscoveryIntent(v) / acceptsSuite(doc, suite)
//   detectorPolicyError(policy) / detectorReceiptShapeError(r)
//   pcactnCheapClaims(p, {audience, now})  -> null or {check, reason}
//   resolveReversibilityClass(action, plan, nodeId) / agentCaveatContext(base, action)   (the toolCall spells the signed binding toolSignatureDigest)
//   enforceRequired(verdict {allow, checks, reasons}, required[]) -> {allow, checks, reasons}   (the verdict is copied: the reference mutates it)
//   collectObligations(rules, ctx) -> {ok, obligations?, reason?}
//   decideLayers(grant, ctx) / decideLayerCeilings(layers, ctx)
import { Oracle, refWrite } from './lib.mjs';
const H: any = await import('../../../packages/pca/src/hash.ts');
const D: any = await import('../../../packages/pca/src/decision.ts');
const C: any = await import('../../../packages/pca/src/capability.ts');
const R: any = await import('../../../packages/pca/src/risk.ts');
const RC: any = await import('../../../packages/pca/src/receipt.ts');
const DI: any = await import('../../../packages/pca/src/discovery.ts');
const DR: any = await import('../../../packages/pca/src/detector-receipt.ts');
const CC: any = await import('../../../packages/pca/src/pcactn-cheap-claims.ts');
const PV: any = await import('../../../packages/pca/src/policy-vm.ts');
const OB: any = await import('../../../packages/pca/src/obligations.ts');
const IL: any = await import('../../../packages/pca/src/intent-layers.ts');
const SV: any = await import('../../../packages/pca/src/server/verify.ts');

const o = new Oracle('core-parity-pure', 'tools/pca-audit/oracles/core-parity-pure.mts', 'TS-reference oracle for the pure parity surface (hash agility, budgets, receipts, discovery, detector policy, layers).');
const nn = (x: any) => (x === null ? undefined : x);

// ---- hash agility
const vals: any[] = [{ a: 1 }, [], 'x', { b: [1, 2, { c: 'é' }], a: null }, 7, true, null, { n: 1.5 }];
for (const [i, v] of vals.entries()) for (const s of ['sha256', 'sha384']) await o.run('hashCanonical', `v${i}-${s}`, (x: any, su: any) => H.hashCanonical(x, su), [v, s]);
for (const n of [0, 1, 2, 3, 16, 32, 33, 48, 64]) await o.run('b64uLen', `n${n}`, H.b64uLen, [n]);
for (const x of ['sha256', 'sha384', 'sha512', '', null, 5, 'SHA256']) await o.run('isHashSuite', String(x), H.isHashSuite, [x]);
const b32 = Buffer.alloc(32, 7).toString('base64url');
for (const [ci, [s, len]] of ([[b32, 32], [b32, 33], [b32, null], ['', null], ['A', null], ['AB', null], ['AB=', null], ['A+B', null], [' AAAA', null], [5, null], [b32 + 'A', 32], ['AAAA', 3], ['AAB', 2], ['AAA', 2]] as any[]).entries())
  await o.run('isCanonicalB64u', `c${ci}`, (a: any, l: any) => H.isCanonicalB64u(a, nn(l)), [s, len]);
for (const n of [0, 1, -1, 1.5, 0.1, 1e-7, 1e21, 2 ** 53, 2 ** 53 - 1, -(2 ** 53), 123456789.123456789, 0.000001, 1.234567890123456, 5e-324, 1e300, -0.5, 100.25])
  await o.run('strictNumberError', String(n), H.strictNumberError, [n]);

// ---- decisions and caveats
for (const l of [[], ['allow'], ['deny'], ['allow', 'escalate'], ['escalate', 'deny', 'allow'], ['allow', 'allow'], ['bogus'], ['allow', 'bogus']]) await o.run('meetAll', l.join('-') || 'empty', D.meetAll, [l]);
for (const [i, x] of [{ type: 'budget_alloc', limit: 3 }, { type: 'budget_alloc', limit: 0 }, { type: 'budget_alloc', limit: -1 }, { type: 'budget_alloc', limit: '3' }, { type: 'budget_alloc' }, { type: 'expires', limit: 3 }, null, 5, [], { type: 'budget_alloc', limit: 1.5 }].entries())
  await o.run('isBudgetAllocCaveat', `c${i}`, C.isBudgetAllocCaveat, [x]);

// ---- budgets
const B = (b: number, t = 0, a?: number) => (a === undefined ? { B: b, tau: t } : { B: b, tau: t, asOf: a });
for (const [p, al] of [[B(10), 4], [B(10), 10], [B(10), 11], [B(10), -1], [B(10), 0], [B(10, 5, 7), 3], [B(10), 1.5], [B(0), 0], [B(10), 0.001]] as any[]) await o.run('subBudget', `${p.B}-${al}-${p.asOf ?? 'n'}`, R.subBudget, [p, al]);
for (const [p, s, c] of [[B(10), B(4), 3], [B(10), B(4), 5], [B(2), B(4), 3], [B(10), B(4), 4], [B(10), B(4), -1], [B(10), B(4), 0], [B(10, 1, 2), B(4, 3, 5), 2.5], [B(10), B(4), 1e9]] as any[]) await o.run('debitConsolidated', `${p.B}-${s.B}-${c}`, R.debitConsolidated, [p, s, c]);
for (const [path, c] of [[[B(10), B(6), B(3)], 2], [[B(10), B(6), B(3)], 3], [[B(10), B(6), B(3)], 4], [[B(10)], 10], [[B(10)], 11], [[], 5], [[B(10), B(2)], 0], [[B(10), B(6)], -3], [[B(1.5), B(2)], 1.5]] as any[]) await o.run('debitConsolidatedPath', `${path.map((x: any) => x.B).join('.')}-${c}`, R.debitConsolidatedPath, [path, c]);
for (const [b, rho, bm, now] of [[B(1), 0.5, 2, 100], [B(1.8), 0.5, 2, 100], [B(3), 0.5, 2, 100], [B(1), -1, 2, 5], [B(1), 0.5, -2, 5], [B(1), 1, 1, 0], [B(0), 0.25, 1, 1e12]] as any[]) await o.run('recharge', `${b.B}-${rho}-${bm}-${now}`, R.recharge, [b, rho, bm, now]);
for (const [b, bm, now] of [[B(1), 2, 100], [B(3), 2, 100], [B(1), -2, 5], [B(1), 0, 0]] as any[]) await o.run('rechargeFull', `${b.B}-${bm}-${now}`, R.rechargeFull, [b, bm, now]);

// ---- receipts
const pc = (verb: string, resource: string, iat: number, extra: any = {}) => ({ ver: 2, action: { verb, resource, params_digest: 'p', reversibility_class: 'reversible' }, aud: 'rs', iat, exp: iat + 1000, counter: 1, ...extra });
const ver = (allow: boolean, checks?: any) => ({ allow, ...(checks ? { checks } : {}) });
const p1 = pc('stripe.refund', 'charge:1', 1000), p2 = pc('read', 'doc/2', 2000), p3 = pc('é.ü', 'r☃', 3000);
await o.run('receiptFor', 'first', (a: any, b: any, c: any, d: any, e: any) => RC.receiptFor(a, b, c, d, nn(e)), ['', 0, p1, ver(true, { audience: 'pass' }), null]);
await o.run('receiptFor', 'at', (a: any, b: any, c: any, d: any, e: any) => RC.receiptFor(a, b, c, d, nn(e)), ['', 0, p1, ver(false), 77]);
await o.run('receiptFor', 'unicode', (a: any, b: any, c: any, d: any, e: any) => RC.receiptFor(a, b, c, d, nn(e)), ['abc', 4, p3, ver(true, { z: 'pass', a: 'fail' }), null]);
let log: any[] = [];
const logs: any[][] = [[]];
for (const [p, v] of [[p1, ver(true, { audience: 'pass' })], [p2, ver(false)], [p3, ver(true)]] as any[]) { log = RC.appendReceipt(log, p, v); logs.push(log); }
for (const [i, l] of logs.entries()) {
  await o.run('appendReceipt', `log${i}`, (lg: any, p: any, v: any, at: any) => RC.appendReceipt(lg, p, v, nn(at)), [l, p2, ver(true), null]);
  await o.run('verifyReceiptChain', `log${i}`, RC.verifyReceiptChain, [l]);
  await o.run('receiptHead', `log${i}`, RC.receiptHead, [l]);
}
const full = logs[3]!;
const tamper = (f: (l: any[]) => any[]) => f(JSON.parse(JSON.stringify(full)));
await o.run('verifyReceiptChain', 'tamper-outcome', RC.verifyReceiptChain, [tamper((l) => { l[1].outcome = 'allow'; return l; })]);
await o.run('verifyReceiptChain', 'tamper-seq', RC.verifyReceiptChain, [tamper((l) => { l[1].seq = 5; return l; })]);
await o.run('verifyReceiptChain', 'tamper-prev', RC.verifyReceiptChain, [tamper((l) => { l[2].prev = 'x'; return l; })]);
await o.run('verifyReceiptChain', 'drop-first', RC.verifyReceiptChain, [tamper((l) => l.slice(1))]);
await o.run('verifyReceiptChain', 'reorder', RC.verifyReceiptChain, [tamper((l) => [l[1], l[0], l[2]])]);

// ---- discovery
const doc = (over: any = {}) => ({ audience: 'rs', pca_versions: [2], signature_suites: ['ed25519', 'ml-dsa-65'], action_header: 'PCA-Action', ...over });
const docs: [string, any][] = [
  ['min', doc()], ['full', doc({ required_checks: ['replay'], endpoints: { stepup: 'https://x/s' }, trusted_roots: ['k'], metadata: { a: 1 }, obligations_supported: ['log'], intent: { versions: [1, 2], actions_uri: 'https://x/a', evidence_uri: 'https://x/e', question_relay: true, tiers: { read: 0, pay: 3 }, schema_keys: [{ kid: 'k', alg: 'ed25519', pk: 'p' }, { kid: 'k2', alg: 'x', pk: 'p', pq_pk: 'q' }] } })],
  ['no-aud', doc({ audience: '' })], ['aud-num', doc({ audience: 5 })], ['versions-str', doc({ pca_versions: ['2'] })], ['suites-num', doc({ signature_suites: [1] })], ['no-header', doc({ action_header: '' })],
  ['bad-checks-ignored', doc({ required_checks: [1] })], ['endpoints-null', doc({ endpoints: null })], ['metadata-arr', doc({ metadata: [] })], ['obl-bad', doc({ obligations_supported: [1] })], ['obl-str', doc({ obligations_supported: 'x' })],
  ['intent-null', doc({ intent: null })], ['intent-arr', doc({ intent: [] })], ['intent-empty-versions', doc({ intent: { versions: [] } })], ['intent-v3', doc({ intent: { versions: [3] } })], ['intent-unknown', doc({ intent: { versions: [1], extra: 1 } })],
  ['intent-uri-empty', doc({ intent: { versions: [1], actions_uri: '' } })], ['intent-uri-num', doc({ intent: { versions: [1], evidence_uri: 5 } })], ['intent-keys-bad', doc({ intent: { versions: [1], schema_keys: [{ kid: 'k' }] } })], ['intent-keys-notarr', doc({ intent: { versions: [1], schema_keys: {} } })],
  ['intent-relay-bad', doc({ intent: { versions: [1], question_relay: 'yes' } })], ['intent-tiers-bad', doc({ intent: { versions: [1], tiers: { a: 5 } } })], ['intent-tiers-frac', doc({ intent: { versions: [1], tiers: { a: 1.5 } } })], ['intent-tiers-neg', doc({ intent: { versions: [1], tiers: { a: -1 } } })], ['intent-tiers-arr', doc({ intent: { versions: [1], tiers: [] } })],
  ['not-object', 'x'], ['null', null], ['array', []],
];
for (const [n, d] of docs) await o.run('parseDiscoveryDocument', n, DI.parseDiscoveryDocument, [d]);
for (const [n, d] of docs) if (d && typeof d === 'object' && 'intent' in d) await o.run('parseDiscoveryIntent', n, DI.parseDiscoveryIntent, [d.intent]);
for (const s of ['ed25519', 'ml-dsa-65', 'hybrid', '']) await o.run('acceptsSuite', s || 'empty', DI.acceptsSuite, [doc(), s]);

// ---- detector receipts
const dp = (over: any = {}) => ({ detectors: [{ id: 'lakera', keys: [{ pk: 'a' }], on_suspicious: 'deny', max_age_ms: 60000 }], ...over });
const dpol: [string, any][] = [
  ['ok', dp()], ['ok-cats', dp({ detectors: [{ id: 'g', keys: [{ pk: 'a', pq_pk: 'b' }], on_suspicious: 'escalate', max_age_ms: 1, categories: ['injection'] }] })], ['empty', dp({ detectors: [] })], ['extra', dp({ x: 1 })], ['notobj', 'x'], ['null', null],
  ['too-many', dp({ detectors: Array.from({ length: 17 }, (_, i) => ({ id: 'd' + i, keys: [{ pk: 'a' }], on_suspicious: 'deny', max_age_ms: 5 })) })],
  ['dup', dp({ detectors: [{ id: 'a', keys: [{ pk: 'k' }], on_suspicious: 'deny', max_age_ms: 5 }, { id: 'a', keys: [{ pk: 'k' }], on_suspicious: 'deny', max_age_ms: 5 }] })],
  ['id-invalid', dp({ detectors: [{ id: 'invalid', keys: [{ pk: 'k' }], on_suspicious: 'deny', max_age_ms: 5 }] })], ['id-bad', dp({ detectors: [{ id: 'A-b', keys: [{ pk: 'k' }], on_suspicious: 'deny', max_age_ms: 5 }] })],
  ['no-keys', dp({ detectors: [{ id: 'a', keys: [], on_suspicious: 'deny', max_age_ms: 5 }] })], ['keys-9', dp({ detectors: [{ id: 'a', keys: Array.from({ length: 9 }, () => ({ pk: 'k' })), on_suspicious: 'deny', max_age_ms: 5 }] })], ['key-bad', dp({ detectors: [{ id: 'a', keys: [{ pk: 1 }], on_suspicious: 'deny', max_age_ms: 5 }] })],
  ['on-bad', dp({ detectors: [{ id: 'a', keys: [{ pk: 'k' }], on_suspicious: 'ok', max_age_ms: 5 }] })], ['age-0', dp({ detectors: [{ id: 'a', keys: [{ pk: 'k' }], on_suspicious: 'deny', max_age_ms: 0 }] })], ['age-big', dp({ detectors: [{ id: 'a', keys: [{ pk: 'k' }], on_suspicious: 'deny', max_age_ms: 86400001 }] })], ['age-frac', dp({ detectors: [{ id: 'a', keys: [{ pk: 'k' }], on_suspicious: 'deny', max_age_ms: 1.5 }] })],
  ['cats-empty', dp({ detectors: [{ id: 'a', keys: [{ pk: 'k' }], on_suspicious: 'deny', max_age_ms: 5, categories: [] }] })], ['cats-bad', dp({ detectors: [{ id: 'a', keys: [{ pk: 'k' }], on_suspicious: 'deny', max_age_ms: 5, categories: ['A B'] }] })], ['entry-extra', dp({ detectors: [{ id: 'a', keys: [{ pk: 'k' }], on_suspicious: 'deny', max_age_ms: 5, z: 1 }] })],
];
for (const [n, p] of dpol) await o.run('detectorPolicyError', n, DR.detectorPolicyError, [p]);
const D32 = Buffer.alloc(32, 3).toString('base64url');
const rcp = (over: any = {}) => ({ v: 1, kind: 'pca-detector-receipt', detector: 'lakera', version: '1', input_digest: D32, verdict: 'suspicious', categories: ['injection'], iat: 5, sig: 's', ...over });
for (const [n, r] of [['ok', rcp()], ['no-finding', rcp({ verdict: 'no_finding', categories: [] })], ['nf-cats', rcp({ verdict: 'no_finding' })], ['unsorted', rcp({ categories: ['b', 'a'] })], ['dup-cats', rcp({ categories: ['a', 'a'] })], ['cats-9', rcp({ categories: ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'] })], ['bad-id', rcp({ detector: 'A' })], ['bad-version', rcp({ version: '' })], ['bad-digest', rcp({ input_digest: 'x' })], ['bad-verdict', rcp({ verdict: 'x' })], ['iat-neg', rcp({ iat: -1 })], ['iat-frac', rcp({ iat: 1.5 })], ['session', rcp({ session: D32 })], ['session-bad', rcp({ session: 'x' })], ['calib', rcp({ calibration_ref: 'r' })], ['calib-empty', rcp({ calibration_ref: '' })], ['sig-num', rcp({ sig: 1 })], ['unknown', rcp({ z: 1 })], ['missing', { v: 1 }], ['alg-bad', rcp({ alg: 'nope' })], ['alg-ed', rcp({ alg: 'ed25519' })], ['notobj', 'x'], ['null', null], ['kind', rcp({ kind: 'x' })]] as any[])
  await o.run('detectorReceiptShapeError', n, DR.detectorReceiptShapeError, [r]);

// ---- cheap claims, reversibility, agent caveat context
for (const [n, p, aud, now] of [['ok', { aud: 'rs', iat: 1000, exp: 2000 }, 'rs', 1500], ['aud', { aud: 'x', iat: 1000, exp: 2000 }, 'rs', 1500], ['aud-empty', { aud: '', iat: 1000, exp: 2000 }, '', 1500], ['aud-num', { aud: 5, iat: 1000, exp: 2000 }, 'rs', 1500], ['iat-str', { aud: 'rs', iat: '1', exp: 2000 }, 'rs', 1500], ['exp-frac', { aud: 'rs', iat: 1000, exp: 2000.5 }, 'rs', 1500], ['not-greater', { aud: 'rs', iat: 2000, exp: 2000 }, 'rs', 1500], ['too-long', { aud: 'rs', iat: 0, exp: 3600001 }, 'rs', 10], ['max-life', { aud: 'rs', iat: 0, exp: 3600000 }, 'rs', 10], ['future', { aud: 'rs', iat: 100000, exp: 100100 }, 'rs', 10], ['skew-ok', { aud: 'rs', iat: 60010, exp: 61000 }, 'rs', 10], ['skew-edge', { aud: 'rs', iat: 60011, exp: 61000 }, 'rs', 10], ['expired', { aud: 'rs', iat: 1000, exp: 2000 }, 'rs', 2001], ['exp-edge', { aud: 'rs', iat: 1000, exp: 2000 }, 'rs', 2000], ['clock', { aud: 'rs', iat: 1000, exp: 2000 }, 'rs', 1.5]] as any[])
  await o.run('pcactnCheapClaims', n, (pp: any, a: any, nw: any) => CC.pcactnCheapClaims(pp, { audience: a, now: nw }), [p, aud, now]);
const plan = [{ id: 'n1', verb: 'a', resource: 'r', reversibility_class: 'rate_limited' }, { id: 'n2', verb: 'b', resource: 'r' }, { verb: 'c', resource: 'r', reversibility_class: 'irreversible' }];
for (const [n, a, pl, id] of [['own', { action: { verb: 'a', resource: 'r', reversibility_class: 'irreversible' } }, plan, 'n1'], ['node', { action: { verb: 'a', resource: 'r' } }, plan, 'n1'], ['node-none', { action: { verb: 'a', resource: 'r' } }, plan, 'n2'], ['unknown-node', { action: { verb: 'a', resource: 'r' } }, plan, 'zz'], ['no-id', { action: { verb: 'a', resource: 'r' } }, plan, null], ['no-plan', { action: { verb: 'a', resource: 'r' } }, null, 'n1'], ['no-action', null, plan, 'n1'], ['id-num', { action: {} }, plan, 5], ['null-class', { action: { reversibility_class: null } }, plan, 'n1']] as any[])
  await o.run('resolveReversibilityClass', n, (a: any, p: any, i: any) => PV.resolveReversibilityClass(nn(a), nn(p), nn(i)), [a, pl, id]);
for (const [n, base, a] of [['plain', { now: 5 }, { action: { verb: 'v', resource: 'r', params: { amount: 3 } } }], ['override', { now: 5, action: 'x', toolCall: 'y' }, { action: { verb: 'v', params: [] } }], ['no-verb', { now: 1 }, { action: {} }], ['bad-params', { now: 1 }, { action: { verb: 'v', params: 'x' } }], ['binding', { now: 2 }, { action: { verb: 'pay', resource: 'r', params: { n: 1 } }, toolBinding: 'dg1' }], ['binding-non-string', { now: 2 }, { action: { verb: 'pay', params: {} }, toolBinding: 5 }], ['binding-override', { now: 2, toolCall: { tool: 'x', toolSignatureDigest: 'evil' } }, { action: { verb: 'pay', params: {} }, toolBinding: 'good' }], ['no-action', { now: 3 }, {}]] as any[])
  await o.run('agentCaveatContext', n, PV.agentCaveatContext, [base, a]);

// ---- obligations
const ob = (kind: string, params: any = {}) => ({ kind, params });
const rules = (xs: any[]) => xs;
const octx = { action: { verb: 'pay', resource: 'acct/1', params: { amount: 5 } }, subject: { role: 'agent' }, env: { region: 'eu' } };
const w = (op: string, path: string, v: any) => ({ op, path, value: v });
for (const [n, r, c] of [
  ['absent', null, octx], ['not-array', 'x', octx], ['empty', [], octx],
  ['true', rules([{ id: 'r1', when: w('eq', 'action.verb', 'pay'), obligations: [ob('log', { sink: 's' })] }]), octx],
  ['false', rules([{ id: 'r1', when: w('eq', 'action.verb', 'read'), obligations: [ob('log', { sink: 's' })] }]), octx],
  ['unknown', rules([{ id: 'r1', when: w('eq', 'env.missing', 'x'), obligations: [ob('notify', { to: 'a@b' })] }]), octx],
  ['merge', rules([{ id: 'r1', when: w('eq', 'action.verb', 'pay'), obligations: [ob('log', { sink: 's' }), ob('require_receipt')] }, { id: 'r2', when: w('exists', 'action.params.amount', null), obligations: [ob('log', { sink: 's' }), ob('watermark', { id: 'w' })] }]), octx],
  ['dup-id', rules([{ id: 'r1', when: w('eq', 'action.verb', 'pay'), obligations: [ob('log', { sink: 's' })] }, { id: 'r1', when: w('eq', 'action.verb', 'pay'), obligations: [ob('log', { sink: 't' })] }]), octx],
  ['empty-obl', rules([{ id: 'r1', when: w('eq', 'action.verb', 'pay'), obligations: [] }]), octx],
  ['bad-obl', rules([{ id: 'r1', when: w('eq', 'action.verb', 'pay'), obligations: [ob('nope')] }]), octx],
  ['extra-member', rules([{ id: 'r1', when: w('eq', 'action.verb', 'pay'), obligations: [ob('log', { sink: 's' })], z: 1 }]), octx],
  ['no-when', rules([{ id: 'r1', obligations: [ob('log', { sink: 's' })] }]), octx],
  ['id-empty', rules([{ id: '', when: w('eq', 'action.verb', 'pay'), obligations: [ob('log', { sink: 's' })] }]), octx],
  ['rule-not-obj', rules(['x']), octx], ['no-ctx', rules([{ id: 'r1', when: w('eq', 'action.verb', 'pay'), obligations: [ob('log', { sink: 's' })] }]), {}],
] as any[]) await o.run('collectObligations', n, (r: any, c: any) => OB.collectObligations(nn(r), c), [r, c]);

// ---- layers
const any_ = { predicates: [{ verb: '*' }] }, none_ = { predicates: [] }, only = (v: string) => ({ predicates: [{ verb: v }] });
const lctx = { action: { action: { verb: 'read', resource: 'x', params: {} } } };
const lctxs: [string, any][] = [['read', { action: { verb: 'read', resource: 'x', params: {} } }], ['pay', { action: { verb: 'pay', resource: 'x', params: {} } }]];
const grants: [string, any][] = [
  ['task-any', { task: [any_] }], ['task-none', { task: [none_] }], ['task-empty', { task: [] }], ['task-missing', {}], ['task-str', { task: 'x' }], ['task-bad-entry', { task: [{ predicates: 1 }] }], ['task-extra-entry', { task: [{ predicates: [], x: 1 }] }],
  ['org-ok', { org: any_, task: [any_] }], ['org-deny', { org: only('pay'), task: [any_] }], ['site-deny', { org: any_, site: none_, task: [any_] }], ['std-deny', { org: any_, site: any_, std: only('zz'), task: [any_] }], ['org-null', { org: null, task: [any_] }], ['org-bad', { org: { predicates: 5 }, task: [any_] }], ['org-extra', { org: { predicates: [], x: 1 }, task: [any_] }],
  ['denied', { task: [any_], denied: [only('read')] }], ['denied-other', { task: [any_], denied: [only('pay')] }], ['denied-str', { task: [any_], denied: 'x' }], ['denied-bad', { task: [any_], denied: [{}] }], ['delta', { task: [only('pay'), only('read')] }], ['delta-first', { task: [only('read'), any_] }],
  ['unknown-member', { task: [any_], extra: 1 }], ['not-object', 'x'], ['null', null], ['array', []],
];
for (const [gn, g] of grants) for (const [cn, c] of lctxs) await o.run('decideLayers', `${gn}-${cn}`, IL.decideLayers, [g, c]);
for (const [gn, g] of [['empty', {}], ['org', { org: any_ }], ['org-deny', { org: only('pay') }], ['site-null', { site: null }], ['std-empty', { std: none_ }], ['unknown', { x: 1 }], ['not-obj', 'x'], ['null', null], ['arr', []], ['all-ok', { org: any_, site: any_, std: any_ }]] as any[]) for (const [cn, c] of lctxs) await o.run('decideLayerCeilings', `${gn}-${cn}`, IL.decideLayerCeilings, [g, c]);
// ---- enforceRequired (the reference mutates the verdict: each case runs on a fresh copy)
const verdicts: [string, any][] = [
  ['all-pass', { allow: true, checks: { replay: 'pass', revocation: 'pass', audience: 'pass' }, reasons: [] }],
  ['one-fail', { allow: true, checks: { replay: 'fail', revocation: 'pass', audience: 'pass' }, reasons: ['replay: seen'] }],
  ['not-enforced', { allow: true, checks: { replay: 'not-enforced', revocation: 'pass', audience: 'pass' }, reasons: [] }],
  ['unsupported', { allow: true, checks: { replay: 'unsupported', revocation: 'pass', audience: 'pass' }, reasons: [] }],
  ['absent', { allow: true, checks: { revocation: 'pass', audience: 'pass' }, reasons: [] }],
  ['already-denied', { allow: false, checks: { replay: 'pass', revocation: 'fail', audience: 'pass' }, reasons: ['revocation: revoked'] }],
  ['counter-format', { allow: true, checks: { counter_format: 'pass', revocation: 'pass' }, reasons: [] }],
  ['counter-replay', { allow: true, checks: { counter_format: 'pass', replay: 'not-enforced', revocation: 'pass' }, reasons: [] }],
  ['counter-present', { allow: true, checks: { counter: 'fail', revocation: 'pass' }, reasons: ['counter: bad'] }],
  ['empty', { allow: true, checks: {}, reasons: [] }],
];
const reqs: [string, string[]][] = [['none', []], ['replay', ['replay']], ['two', ['replay', 'audience']], ['counter', ['counter']], ['stateful', ['counter_format', 'replay', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound']], ['dup', ['audience', 'audience']]];
for (const [vn, v] of verdicts) for (const [rn, r] of reqs) await o.run('enforceRequired', `${vn}/${rn}`, (vv: any, rr: any) => { const c = JSON.parse(JSON.stringify(vv)); const out = SV.enforceRequired(c, rr); return { allow: out.allow, checks: out.checks, reasons: out.reasons }; }, [v, r]);
void lctx;
refWrite(o, 'core-parity-pure');
