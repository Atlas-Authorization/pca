// Oracle: @atlasauth/pca-grants, the parts a native port implements beyond the verifiers it already had (signing, decision log and
// replay, shadow rollout, list-authorized, the grant management service and its HTTP binding, lease HTTP and renewal, blueprint group
// kill and attestation-gated admission, freshness helpers). Deterministic: fixed clocks (T0), Ed25519 keys derived from labels.
// Conventions shared by every fn: a secret key is a LABEL (string); the key seed is sha256("atlas-pca-conformance/" + label) (`seed(label)` of
// the oracle library) and its public key is the b64u Ed25519 public key. In scenario specs the string "$key:LABEL" stands for that public key
// and an object {"$sign": {kind, label, fields}} stands for the signed record (kind: lease | leaseOver | revocation | blueprint | breakglass |
// review). Stateful objects are driven by a scenario (spec in, JSON out): a step that throws yields {"$err": <code or "x">}.
// PORTING (fn(args) -> native entry point, comparison rule; records are compared by JSON value):
//   signerOf(label)                          Sig.signerOf(key)
//   signBody(domain, body, label)            Sig.signBody
//   verifyBody(domain, body, signer, sig)    Sig.verifyBody (never throws)
//   signLease / signLeaseUnsafeOverCap / signLeaseRevocation / signBlueprint / signBreakGlass / signBreakGlassReview (label, record)
//                                            GrantSigning.sign*; a refusal is a throw
//   signBundle(body, label) assembleBundle(body, sigs) maskRecord(record, classes)     Bundle.*
//   logScenario(spec)                        Bundle.DecisionLog + nextBatch + verifyBatch + verifyRecordInclusion
//   replayScenario(spec)                     Bundle.semanticDiff / auditReplay with table-driven decide functions
//   shadowScenario(spec)                     Shadow.runShadow / ShadowLog / promotionGate / promoteShadow
//   listScenario(spec)                       ListAuthorized.listAuthorized over a paged universe; windowAcc(cap, windowMs, ops) the accumulator
//   grantScenario(spec)                      GrantResource.GrantService over MemoryGrantStore, and GrantHttp.grantResourceHandler
//   leaseScenario(spec)                      Lease.Registry, Leases.renewLease and LeaseHttp.leaseResourceHandler (the diagnostic `reason` /
//                                            `message` text of a refused accept is stripped on the reference side: a native may omit it)
//   blueprintScenario(spec)                  Blueprints.groupKill and Blueprints.AdmissionRegistry
//   admitWithEvidence(blueprint, evidence)   Blueprints.admitWithEvidence ({"$throw":true} evidence throws)
//   mergeFreshAt / gateDecision / freshScenario(spec)   FreshAt.mergeFreshAt / gateDecision / FreshAt.Issuer
import * as M0 from '@atlasauth/pca-grants';
const M: any = (M0 as any).default ?? M0;
const {
  AdmissionRegistry, BlueprintRegistry, DecisionLog, FreshAtIssuer, GRANT_AMEND_DOMAIN, GRANT_REVOKE_DOMAIN, GrantError, GrantService, LeaseRegistry, MemoryBlueprintStore, MemoryGrantStore, NEED_APPROVE_DOMAIN, ShadowLog, WindowReadAccumulator, admitWithEvidence, amendMessage, assembleBundle, auditReplay, bundleDigest, candidatesFromRelation, checkLease, gateDecision, grantRevokeMessage, grantResourceHandler, groupKill, leaseResourceHandler, listAuthorized, maskRecord, memoryLeaseKv, mergeFreshAt, needApproveMessage, nextBatch, promoteShadow, promotionGate, recordCommit, renewLease, runShadow, semanticDiff, signBlueprint, signDomainBody, signBreakGlass, signBreakGlassReview, signBundle, signGrantBody, signLease, signLeaseRevocation, signLeaseUnsafeOverCap, signPromotionApproval, signWideningExplanation, verifyBatch, verifyDomainBody, verifyRecordInclusion, verifyShadowDiff,
} = M;
import * as C0 from '@atlasauth/pca';
const C: any = (C0 as any).default ?? C0;
const signBody = signDomainBody, verifyBody = verifyDomainBody;
const signerOf = (secret: Uint8Array): string => C.b64u(C.publicKeyOf(secret));
import { Oracle, refWrite, seed, variants } from './lib.mjs';

const o = new Oracle('grants', 'tools/pca-audit/oracles/grants.mts', 'TS-reference oracle for the pca-grants operational plane (signing, log, replay, shadow, list-authorized, grant service, lease and blueprint operations).');
const T0 = 1_800_000_000_000;
const sk = (label: string): Uint8Array => seed(label);
const pub = (label: string): string => signerOf(sk(label));

/** Replace "$key:LABEL" strings and {"$sign": ...} objects, recursively. */
function resolve(v: any): any {
  if (typeof v === 'string') return v.startsWith('$key:') ? pub(v.slice(5)) : v;
  if (Array.isArray(v)) return v.map(resolve);
  if (v !== null && typeof v === 'object') {
    if (v.$sign !== undefined) {
      const { kind, label, fields } = v.$sign;
      const s = ({ lease: signLease, leaseOver: signLeaseUnsafeOverCap, revocation: signLeaseRevocation, blueprint: signBlueprint, breakglass: signBreakGlass, review: signBreakGlassReview } as any)[kind as string];
      return s(sk(label), resolve(fields));
    }
    const out: any = {};
    for (const k of Object.keys(v)) out[k] = resolve(v[k]);
    return out;
  }
  return v;
}
const errCode = (e: any): any => ({ $err: e instanceof GrantError ? e.code : e && typeof e.code === 'string' ? e.code : 'x' });
const J = (x: any): any => JSON.parse(JSON.stringify(x === undefined ? null : x));

// ---- pure signing -------------------------------------------------------------------------------------------------------------
const L = 'oracle-key';
const lease = { lease_id: 'l1', path: 'svc/a/b', grant_ref: 'g1', holder: 'agent', requester: 'alice', approvers: ['bob'], justification_digest: 'j1', seq: 1, issued_at: T0, renewed_at: T0, expires_at: T0 + 600_000, max_ttl: 3_600_000 };
const lease2 = { ...lease, seq: 2, renewed_at: T0 + 1000, expires_at: T0 + 700_000, approvers: [] };
const revo = { target: 'prefix', value: 'svc/a', revoked_at: T0 + 5 };
const bp = { id: 'ops-bot', key: 'bpkey', ceiling: [{ type: 'verb', verbs: ['read'] }], epoch: 1, status: 'active', issued_at: T0 };
const bp2 = { ...bp, max_depth: 3, expires_at: T0 + 9_000_000, runtime_pins: [{ runtime_measurement: 'm1', operator: 'op' }, { spiffe_id: 'spiffe://x/y' }] };
const bg = { id: 'bg1', holder: 'agent', grant_ref: 'g1', reason_digest: 'r1', max_uses: 3, issued_at: T0, expires_at: T0 + 3_600_000, review_within: 86_400_000, notify_to: 'https://n.example/x' };
const rv = { id: 'bg1', outcome: 'justified', notes_digest: 'n1', at: T0 + 10 };
const bundleBody = { v: 1, kind: 'pca-policy-bundle', revision: 1, grants: ['g1', 'g2'], template_digests: [], min_verifier_version: '0.5.0', issued_at: T0 };
const bundleBody2 = { ...bundleBody, revision: 2, prev: 'd1', schema_digest: 's1', constitution_digest: 'c1', flow_rules_digest: 'f1', shadow: ['x1', 'x2'] };

const signers: Array<[string, any, any[]]> = [
  ['signLease', signLease, [lease, lease2, { ...lease, expires_at: T0 + 3_600_000 }, { ...lease, expires_at: T0 + 3_600_001 }]],
  ['signLeaseUnsafeOverCap', signLeaseUnsafeOverCap, [lease, { ...lease, expires_at: T0 + 3_600_001 }, { ...lease, expires_at: T0 + 99_000_000 }]],
  ['signLeaseRevocation', signLeaseRevocation, [revo, { target: 'lease', value: 'l1', revoked_at: T0 }, { target: 'grant', value: 'g1', revoked_at: T0 }, { target: 'prefix', value: 'Bad/Path', revoked_at: T0 }]],
  ['signBlueprint', signBlueprint, [bp, bp2, { ...bp, status: 'disabled', epoch: 2 }]],
  ['signBreakGlass', signBreakGlass, [bg, { ...bg, expires_at: T0 + 86_400_001 }, { ...bg, max_uses: 17 }, { ...bg, review_within: 30 * 86_400_000 }, { ...bg, review_within: 30 * 86_400_000 + 1 }]],
  ['signBreakGlassReview', signBreakGlassReview, [rv, { ...rv, outcome: 'unjustified' }, { ...rv, outcome: 'maybe' }]],
];
let n = 0;
for (const [fn, f, seeds] of signers) {
  for (const [si, s] of seeds.entries()) {
    await o.run(fn, `valid#${n++}`, (label: string, r: any) => f(sk(label), r), [L, s]);
    if (si === 0) for (const [vn, v] of variants(s, { lens: [128, 129, 256, 257], maxPaths: 14 })) await o.run(fn, `${vn}#${n++}`, (label: string, r: any) => f(sk(label), r), [L, v]);
  }
}
for (const label of ['a', 'b', 'oracle-key']) await o.run('signerOf', `k#${n++}`, (l: string) => signerOf(sk(l)), [label]);
const bodies: any[] = [{ a: 1 }, { z: [1, 2, 3], a: { b: 'é' } }, {}, [1], 'str', null, 1.5, { n: 1e21 }, { x: '\ud800' }];
for (const d of ['atlas-pca/test/v1\0', '', 'x']) for (const b of bodies) {
  await o.run('signBody', `d#${n++}`, (dom: string, body: any, l: string) => signBody(dom, body, sk(l)), [d, b, 'a']);
  let sig: string;
  try { sig = signBody(d, b, sk('a')); } catch { continue; }
  const so = pub('a');
  const vb = (dom: string, body: any, s: string, g: any) => verifyBody(dom, body, s, g);
  await o.run('verifyBody', `ok#${n++}`, vb, [d, b, so, sig]);
  await o.run('verifyBody', `wrongBody#${n++}`, vb, [d, { other: 1 }, so, sig]);
  await o.run('verifyBody', `wrongSigner#${n++}`, vb, [d, b, pub('b'), sig]);
}
for (const g of [null, 1, '', 'short', 'A'.repeat(86), 'A'.repeat(87), '=' + 'A'.repeat(85), signBody('d', {}, sk('a')) + 'A'])
  await o.run('verifyBody', `sigshape#${n++}`, (dom: string, body: any, s: string, x: any) => verifyBody(dom, body, s, x), ['d', {}, pub('a'), g]);

// ---- bundles --------------------------------------------------------------------------------------------------------------------
const sb = (body: any, l: string) => signBundle(body, sk(l));
for (const [bi, b] of [bundleBody, bundleBody2, { ...bundleBody, revision: 0 }, { ...bundleBody, prev: 'x' }, { ...bundleBody, shadow: [] }, { ...bundleBody, kind: 'x' }].entries()) {
  await o.run('signBundle', `b#${n++}`, sb, [b, 'a']);
  if (bi < 2) for (const [vn, v] of variants(b, { maxPaths: 14 })) await o.run('signBundle', `${vn}#${n++}`, sb, [v, 'a']);
}
const sigsFor = (b: any) => [signBundle(b, sk('a')), signBundle(b, sk('b'))];
await o.run('assembleBundle', `a#${n++}`, (b: any, s: any) => assembleBundle(b, s), [bundleBody, sigsFor(bundleBody)]);
await o.run('assembleBundle', `withsigs#${n++}`, (b: any, s: any) => assembleBundle(b, s), [{ ...bundleBody, sigs: ['stale'] }, sigsFor(bundleBody)]);
await o.run('assembleBundle', `empty#${n++}`, (b: any, s: any) => assembleBundle(b, s), [bundleBody2, []]);
const rec0 = { bundle_revision: 1, bundle_digest: 'bd', action_digest: 'ad0', decision: 'allow', at: T0 };
const recM = { ...rec0, detail: { email: 'a@b.c', n: 5, nested: { x: [1, 2] }, free: 'f' }, classes: { email: 'pii', n: 'metric', nested: 'secret' } };
for (const [i, r] of [rec0, recM, { ...recM, classes: undefined }, { ...recM, detail: undefined }, { ...recM, classes: { email: 5, n: null } }].entries())
  for (const mc of [[], ['pii'], ['pii', 'secret'], ['metric', 'nope']]) await o.run('maskRecord', `r${i}#${n++}`, (r: any, c: any) => maskRecord(r, c), [r, mc]);
await o.run('maskRecord', `badvalue#${n++}`, (r: any, c: any) => maskRecord(r, c), [{ ...recM, detail: { email: 1e21 } }, ['pii']]);

// log scenario
function logScenario(spec: any) {
  const log = new DecisionLog(sk(spec.label), spec.mask ?? []);
  const recs = spec.records.map((r: any) => log.append(r));
  const signer = pub(spec.label);
  const head = log.head(spec.now);
  const out: any = { recs, head, size: log.size };
  out.proofs = (spec.proofs ?? []).map((i: number) => { try { return log.proof(i); } catch { return { $err: true }; } });
  out.incl = (spec.proofs ?? []).map((i: number, k: number) => { const p = out.proofs[k]; return p.$err ? { $err: true } : verifyRecordInclusion(recs[i], p, head, signer); });
  out.batches = (spec.batches ?? []).map((b: any) => {
    try {
      const bt = nextBatch(log, b.from, b.max, spec.now);
      const st = { next: b.from, lastCommit: b.from === 0 ? '' : recordCommit(recs[b.from - 1]) };
      const tampered = bt.records.length ? { ...bt, records: [{ ...bt.records[0], at: 1 }, ...bt.records.slice(1)] } : bt;
      return { bt, verdict: verifyBatch(bt, st, signer), tampered: verifyBatch(tampered, st, signer), wrong: verifyBatch(bt, st, pub('zz')) };
    } catch { return { $err: true }; }
  });
  return out;
}
const R = (i: number, d = 'allow', extra: any = {}) => ({ bundle_revision: 1, bundle_digest: 'bd', action_digest: `ad${i}`, decision: d, at: T0 + i, ...extra });
const logSpecs: any[] = [
  { label: 'log', records: [R(0)], now: T0 + 9, proofs: [0], batches: [{ from: 0, max: 5 }] },
  { label: 'log', records: [R(0), R(1, 'deny', { witness: 'w' }), R(2, 'escalate')], now: T0 + 9, proofs: [0, 1, 2, 3, -1], batches: [{ from: 0, max: 2 }, { from: 2, max: 5 }, { from: 3, max: 1 }, { from: 0, max: 0 }, { from: -1, max: 1 }, { from: 1, max: 1 }] },
  { label: 'log', mask: ['pii'], records: Array.from({ length: 9 }, (_, i) => R(i, ['allow', 'deny', 'escalate'][i % 3]!, { detail: { u: `user${i}`, k: i }, classes: { u: 'pii' } })), now: T0 + 99, proofs: [0, 3, 8], batches: [{ from: 0, max: 4 }, { from: 4, max: 4 }, { from: 8, max: 4 }] },
  { label: 'log', records: Array.from({ length: 33 }, (_, i) => R(i)), now: T0 + 5, proofs: [0, 7, 16, 32, 33], batches: [{ from: 30, max: 10 }] },
  { label: 'log', records: [], now: T0, proofs: [0], batches: [{ from: 0, max: 1 }] },
  { label: 'log', records: [R(0, 'allow', { seq: 99, prev: 'x', v: 2 })], now: T0, proofs: [0], batches: [] },
  { label: 'log', records: [R(0, 'allow', { detail: { x: 1e21 }, classes: { x: 'pii' } })], mask: ['pii'], now: T0, proofs: [], batches: [] },
];
for (const [i, s] of logSpecs.entries()) await o.run('logScenario', `s${i}`, logScenario, [s]);

// replay
function replayScenario(spec: any) {
  const dec = (t: any) => (i: any) => t[i];
  return { diff: semanticDiff(spec.cases, dec(spec.oldT), dec(spec.newT)), audit: auditReplay(spec.records, spec.cases, (i: any, rev: number) => spec.revT[`${i}@${rev}`]) };
}
const cs = [{ action_digest: 'a1', input: 'i1' }, { action_digest: 'a2', input: 'i2' }, { action_digest: 'a3', input: 'i3' }, { action_digest: 'a4', input: 'i4' }];
const kinds = ['allow', 'deny', 'escalate'];
for (const [i, [ot, nt]] of ([
  [{ i1: 'allow', i2: 'deny', i3: 'escalate', i4: 'allow' }, { i1: 'allow', i2: 'allow', i3: 'deny', i4: 'escalate' }],
  [{ i1: 'deny', i2: 'deny', i3: 'deny', i4: 'deny' }, { i1: 'deny', i2: 'deny', i3: 'deny', i4: 'deny' }],
  [{ i1: 'bogus', i2: 'allow' }, { i1: 'allow', i2: 'bogus' }],
  [{}, { i1: 'allow' }],
] as any[]).entries()) {
  const records = cs.map((c, k) => ({ v: 1, seq: k, prev: '', bundle_revision: 1 + (k % 2), bundle_digest: 'b', action_digest: c.action_digest, decision: kinds[k % 3], at: T0 }));
  const revT: any = {};
  for (const [k, c] of cs.entries()) revT[`${c.input}@${1 + (k % 2)}`] = kinds[(k + i) % 3];
  await o.run('replayScenario', `s${i}`, replayScenario, [{ cases: cs, oldT: ot, newT: nt, records, revT }]);
}
await o.run('replayScenario', 'dupaction', replayScenario, [{ cases: [cs[0], { action_digest: 'a1', input: 'i2' }], oldT: { i1: 'allow', i2: 'deny' }, newT: { i1: 'deny', i2: 'deny' }, records: [{ action_digest: 'a1', bundle_revision: 1, decision: 'deny' }], revT: { 'i2@1': 'deny' } }]);

// ---- fresh_at helpers -----------------------------------------------------------------------------------------------------------
const st = (r: number, l: number, b: number, p: number, d = 'pd') => ({ revocation_epoch: r, ledger_tree_size: l, budget_version: b, policy_revision: p, policy_digest: d });
const states = [st(1, 2, 3, 4), st(5, 1, 3, 2, 'pd2'), st(0, 0, 0, 0, ''), st(1, 2, 3, 4, 'other')];
for (const a of states) for (const b of states) await o.run('mergeFreshAt', `m#${n++}`, (x: any, y: any) => mergeFreshAt(x, y), [a, b]);
for (const d of ['allow', 'deny', 'escalate']) for (const v of [{ decision: 'ok' }, { decision: 'escalate', code: 'stale_state', behind: [] }, { decision: 'deny', code: 'bad_token' }])
  await o.run('gateDecision', `g#${n++}`, (a: any, b: any) => gateDecision(a, b), [d, v]);
function freshScenario(spec: any) {
  const iss = new FreshAtIssuer(sk(spec.label), spec.scope, spec.init);
  const out: any[] = [];
  let last: any;
  for (const s of spec.steps) {
    try {
      if (s.op === 'advance') { last = iss.advance(s.patch, s.now); out.push(last); }
      else if (s.op === 'check') out.push(iss.check(s.token === 'last' ? last : s.token, s.now, s.maxAge ?? undefined));
      else if (s.op === 'current') out.push(iss.current);
      else if (s.op === 'tamper') out.push(iss.check({ ...last, policy_revision: last.policy_revision + 1 }, s.now));
    } catch { out.push({ $err: true }); }
  }
  return out;
}
const fsteps = [
  { op: 'current' }, { op: 'advance', patch: { revocation_epoch: 3 }, now: T0 }, { op: 'check', token: 'last', now: T0 + 1 },
  { op: 'advance', patch: { revocation_epoch: 1, policy_revision: 9, policy_digest: 'new' }, now: T0 + 2 }, { op: 'current' }, { op: 'check', token: 'last', now: T0 + 3, maxAge: 1 },
  { op: 'check', token: 'last', now: T0 + 90_000, maxAge: 5 }, { op: 'check', token: 'last', now: T0 - 200_000 }, { op: 'tamper', now: T0 + 3 },
  { op: 'advance', patch: { budget_version: -1 }, now: T0 }, { op: 'advance', patch: { ledger_tree_size: 1.5 }, now: T0 }, { op: 'check', token: null, now: T0 },
  { op: 'check', token: 'junk', now: T0 }, { op: 'advance', patch: { ledger_tree_size: 50 }, now: -1 }, { op: 'current' },
];
await o.run('freshScenario', 'steps', freshScenario, [{ label: 'iss', scope: 'scope-a', init: st(1, 1, 1, 1), steps: fsteps }]);
await o.run('freshScenario', 'badinit', freshScenario, [{ label: 'iss', scope: 'scope-a', init: { revocation_epoch: 1 }, steps: [{ op: 'advance', patch: {}, now: T0 }] }]);
await o.run('freshScenario', 'badscope', freshScenario, [{ label: 'iss', scope: '', init: st(1, 1, 1, 1), steps: [{ op: 'advance', patch: {}, now: T0 }] }]);

// ---- shadow ---------------------------------------------------------------------------------------------------------------------
function shadowScenario(spec: any) {
  const log = new ShadowLog(sk(spec.label));
  const T = (t: any) => (i: any) => { const d = t[i]; if (d === 'throw') throw new Error('boom'); if (d === 'junk') return 'weird'; return d; };
  const out: any = { runs: [], diffs: {} };
  for (const ob of spec.obs) {
    const run = runShadow(ob.input, T(spec.enforcedT), spec.cands.map((c: any) => ({ digest: c.digest, decide: T(c.T) })));
    out.runs.push({ decision: run.decision, shadow: run.shadow });
    for (const oc of run.shadow) log.observe({ enforced_digest: spec.enforcedDigest, action_digest: ob.action_digest, enforced: run.decision, outcome: oc, at: ob.at });
  }
  out.stats = Object.fromEntries(spec.cands.map((c: any) => [c.digest, log.stats(c.digest)]));
  for (const c of spec.cands) out.diffs[c.digest] = log.diffs(c.digest);
  out.verify = Object.values(out.diffs).flat().map((d: any) => [verifyShadowDiff(d, log.signer), verifyShadowDiff(d), verifyShadowDiff(d, pub('zz')), verifyShadowDiff({ ...d, sig: d.sig.slice(1) + 'A' }, log.signer), verifyShadowDiff({ ...d, at: d.at + 1 })]);
  out.signer = log.signer;
  const g = spec.gate;
  if (g) {
    const principals = (g.principals ?? []).map(pub);
    const explanations = (g.explain ?? []).map((e: any) => signWideningExplanation(sk(e.label), { shadow_digest: e.shadow_digest, action_digest: e.action_digest, reason_digest: e.reason_digest }));
    const approval = g.approval ? signPromotionApproval(sk(g.approval.label), { shadow_digest: g.approval.shadow_digest, enforced_digest: g.approval.enforced_digest, at: g.approval.at }) : undefined;
    out.explanations = explanations;
    out.approval = approval ?? null;
    out.gate = promotionGate(log, { ...g.options, principals: g.options?.principals ?? principals, explanations: g.options?.explanations ?? explanations, ...(approval !== undefined ? { approval } : {}) });
    if (spec.promote) {
      try { out.promoted = promoteShadow(spec.promote.enforced, spec.promote.candidate, spec.promote.useGate === false ? ({ ok: false, code: 'bad_input', reason: 'x' } as any) : out.gate, spec.promote.now); } catch { out.promoted = { $err: true }; }
    }
  }
  return out;
}
const eT = { a: 'allow', b: 'deny', c: 'escalate', d: 'allow', e: 'deny' };
const cands = [
  { digest: 'cand-1', T: { a: 'allow', b: 'allow', c: 'deny', d: 'allow', e: 'deny' } },
  { digest: 'cand-2', T: { a: 'deny', b: 'deny', c: 'allow', d: 'throw', e: 'junk' } },
];
const obs = ['a', 'b', 'c', 'd', 'e', 'a', 'b', 'c'].map((input, i) => ({ input, action_digest: `act-${input}`, at: T0 + i }));
const gateBase = { shadow_digest: 'cand-1', enforced_digest: 'enf-1', minSamples: 3, surface: 'narrower' };
const shBase = { label: 'sh', enforcedDigest: 'enf-1', enforcedT: eT, cands, obs };
const ex = (label: string, shadow_digest: string, action_digest: string) => ({ label, shadow_digest, action_digest, reason_digest: 'rr' });
const sh: any[] = [
  { ...shBase },
  { ...shBase, gate: { options: gateBase, principals: ['pr1'] } },
  { ...shBase, gate: { options: gateBase, principals: ['pr1'], explain: [ex('pr1', 'cand-1', 'act-b')] } },
  { ...shBase, gate: { options: gateBase, principals: ['pr1'], explain: [ex('pr1', 'cand-1', 'act-b'), ex('pr1', 'cand-1', 'act-c')] } },
  { ...shBase, gate: { options: gateBase, principals: ['pr1'], explain: [ex('pr9', 'cand-1', 'act-b'), ex('pr1', 'other', 'act-c')] } },
  { ...shBase, gate: { options: { ...gateBase, minSamples: 99 } } },
  { ...shBase, gate: { options: { ...gateBase, minSamples: 0 } } },
  { ...shBase, gate: { options: { ...gateBase, shadow_digest: 'cand-2' } } },
  { ...shBase, gate: { options: { ...gateBase, enforced_digest: 'enf-other' }, principals: ['pr1'] } },
  { ...shBase, gate: { options: { ...gateBase, surface: 'sideways' } } },
  { ...shBase, gate: { options: { ...gateBase, explanations: 'nope' } } },
  { ...shBase, gate: { options: { ...gateBase, principals: 'nope' } } },
  { ...shBase, gate: { options: { ...gateBase, minSamples: 1.5 } } },
];
const tight = [{ digest: 'cand-1', T: { a: 'deny', b: 'deny', c: 'deny', d: 'deny', e: 'deny' } }];
for (const surface of ['narrower', 'equal', 'wider', 'unknown'])
  for (const ap of [null, { label: 'pr1', shadow_digest: 'cand-1', enforced_digest: 'enf-1', at: T0 }, { label: 'pr9', shadow_digest: 'cand-1', enforced_digest: 'enf-1', at: T0 }, { label: 'pr1', shadow_digest: 'cand-1', enforced_digest: 'enf-x', at: T0 }]) {
    const g = { options: { ...gateBase, surface }, principals: ['pr1'], approval: ap };
    sh.push({ ...shBase, cands: tight, gate: g });
    sh.push({ ...shBase, cands: tight, gate: g, promote: { enforced: { ...bundleBody, revision: 4, shadow: [], issued_at: T0 }, candidate: { ...bundleBody2, revision: 9, shadow: ['zz'], sigs: [{ signer: 's', sig: 'x' }], issued_at: T0 + 1 }, now: T0 + 5 } });
  }
{
  const candBundle = { ...bundleBody2, revision: 2, issued_at: T0 + 1 };
  const dig = bundleDigest(candBundle);
  const enforcedBundle = { ...bundleBody, revision: 1, shadow: [dig] };
  const tightC = [{ digest: dig, T: { a: 'deny', b: 'deny', c: 'deny', d: 'deny', e: 'deny' } }];
  const g = { options: { shadow_digest: dig, enforced_digest: 'enf-1', minSamples: 3, surface: 'narrower' }, principals: ['pr1'] };
  for (const pr of [
    { enforced: enforcedBundle, candidate: candBundle, now: T0 + 7 },
    { enforced: { ...enforcedBundle, shadow: ['other'] }, candidate: candBundle, now: T0 + 7 },
    { enforced: enforcedBundle, candidate: candBundle, now: -1 },
    { enforced: enforcedBundle, candidate: candBundle, now: 1.5 },
    { enforced: enforcedBundle, candidate: { ...candBundle, sigs: [1], shadow: ['x'], prev: 'p' }, now: T0 },
    { enforced: enforcedBundle, candidate: candBundle, now: T0, useGate: false },
  ]) sh.push({ ...shBase, cands: tightC, gate: g, promote: pr });
}
for (const [i, s] of sh.entries()) await o.run('shadowScenario', `s${i}`, shadowScenario, [s]);

// ---- list-authorized ------------------------------------------------------------------------------------------------------------
async function listScenario(spec: any) {
  const acc = new WindowReadAccumulator(spec.cap, spec.windowMs);
  const universe: string[] = spec.universe;
  const pageOf = (list: string[], q: any) => {
    const idx = q.cursor === undefined ? 0 : Number(q.cursor);
    const objects = list.slice(idx, idx + q.limit + (spec.overfetch ? 3 : 0));
    const next = idx + q.limit < list.length ? String(idx + q.limit) : spec.emptyNext ? '' : undefined;
    return { objects, ...(next !== undefined ? { next } : {}) };
  };
  const allowed = new Set<string>(spec.relation?.allowed ?? []);
  const rel: any = { check: async (q: any) => allowed.has(q.object), ...(spec.relation?.useList ? { listObjects: async (q: any) => pageOf(spec.relation.listed ?? universe, q) } : {}) };
  const permitted = spec.permitted ? new Set<string>(spec.permitted) : null;
  const out: any[] = [];
  let cursor: string | undefined;
  for (let p = 0; p < spec.pages; p++) {
    const t = spec.tamper && p === spec.tamper.page ? spec.tamper : null;
    try {
      const candidates = spec.relation?.asCandidates ? candidatesFromRelation(rel, spec.subject, spec.relation.name) : { page: async (q: any) => pageOf(universe, q) };
      const r = await listAuthorized({
        subject: t?.subject ?? spec.subject, resourceType: spec.type, permits: (x: string) => permitted === null || permitted.has(x), candidates,
        ...(spec.relation ? { relation: { source: rel, relation: t?.relation ?? spec.relation.name } } : {}), filterId: t?.filterId ?? spec.filterId, policyDigest: spec.policyDigest, freshAtDigest: spec.freshAt,
        page: { ...(t?.dropCursor || cursor === undefined ? {} : { cursor: t?.cursor ?? cursor }), limit: t?.limit ?? spec.limit }, reads: acc, now: T0 + p * (spec.nowStep ?? 1), signingSecret: sk(t?.label ?? spec.label), ...(spec.maxScan !== undefined ? { maxScan: spec.maxScan } : {}),
      });
      out.push(r);
      cursor = r.next_cursor;
    } catch (e: any) { out.push({ $err: e.code ?? 'x' }); if (!t) break; }
  }
  return out;
}
const uni = Array.from({ length: 23 }, (_, i) => `doc-${i}`);
const lb = { label: 'lst', subject: 'alice', type: 'doc', universe: uni, filterId: 'fid', policyDigest: 'pd', freshAt: 'fa', limit: 5, cap: 1000, windowMs: 60_000, pages: 6 };
const ls: any[] = [
  { ...lb },
  { ...lb, permitted: uni.filter((_, i) => i % 3 === 0) },
  { ...lb, permitted: uni.filter((_, i) => i % 7 === 0), maxScan: 6, pages: 8 },
  { ...lb, permitted: [], pages: 3 },
  { ...lb, limit: 1, pages: 4 }, { ...lb, limit: 500, pages: 2 }, { ...lb, limit: 0 }, { ...lb, limit: 501 }, { ...lb, limit: -1 },
  { ...lb, cap: 6, pages: 5 }, { ...lb, cap: 12, windowMs: 2, nowStep: 3, pages: 5 },
  { ...lb, relation: { name: 'viewer', allowed: uni.filter((_, i) => i % 2 === 0) } },
  { ...lb, permitted: uni.filter((_, i) => i < 12), relation: { name: 'viewer', allowed: uni.filter((_, i) => i % 2 === 1) }, pages: 7 },
  { ...lb, relation: { name: 'viewer', allowed: uni, useList: true, asCandidates: true, listed: uni.slice(4) } },
  { ...lb, relation: { name: 'viewer', allowed: uni, useList: false, asCandidates: true } },
  { ...lb, overfetch: true }, { ...lb, emptyNext: true }, { ...lb, universe: [] }, { ...lb, universe: ['only'], pages: 3 },
  { ...lb, tamper: { page: 1, subject: 'mallory' } }, { ...lb, tamper: { page: 1, filterId: 'other' } }, { ...lb, tamper: { page: 1, limit: 4 } },
  { ...lb, tamper: { page: 1, relation: 'editor' }, relation: { name: 'viewer', allowed: uni } }, { ...lb, tamper: { page: 1, label: 'other-signer' } },
  { ...lb, tamper: { page: 1, cursor: 'garbage' } }, { ...lb, tamper: { page: 1, cursor: 'a.b.c' } }, { ...lb, tamper: { page: 1, dropCursor: true } }, { ...lb, tamper: { page: 1, cursor: '' } },
];
for (const [i, s] of ls.entries()) await o.run('listScenario', `s${i}`, listScenario, [s]);
for (const [i, ops] of ([
  [{ key: 'k', units: 3, now: 0 }, { key: 'k', units: 3, now: 1 }, { key: 'k', units: 5, now: 2 }, { key: 'k', units: 5, now: 10 }, { key: 'j', units: 10, now: 10 }, { key: 'j', units: 1, now: 10 }, { key: 'k', units: 0, now: 11 }],
  [{ key: 'k', units: 11, now: 0 }, { key: 'k', units: 10, now: 0 }, { key: 'k', units: 1, now: 9 }, { key: 'k', units: 1, now: 10 }],
] as any[]).entries()) await o.run('windowAcc', `w${i}`, (cap: number, win: number, os: any[]) => { const a = new WindowReadAccumulator(cap, win); return os.map((x) => a.charge(x.key, x.units, x.now)); }, [10, 10, ops]);

// ---- grant management ----------------------------------------------------------------------------------------------------------
async function grantScenario(spec: any) {
  const store = new MemoryGrantStore();
  const events: any[] = [];
  let gc = 0, nc = 0;
  const svc = new GrantService({
    store, now: () => T0, newId: (k) => (k === 'grant' ? `g_${++gc}` : `n_${++nc}`),
    ...(spec.providers ? { providers: { usage: (g: any) => ({ rev: g.rev }), remainingBudget: () => ({ left: 5 }), residual: (g: any) => ({ id: g.id }) } } : {}),
    ...(spec.stepUp ? { verifyStepUp: (ref: string) => ref === 'ok-step' } : {}),
    onRevoke: (ids, scope, root) => { events.push({ revoked: ids, scope, root: root.id }); },
    onChange: (kind, g) => { events.push({ change: kind, id: g.id, rev: g.rev }); },
    ...(spec.validateNeed ? { validateNeed: (nd: any) => (nd.verb === 'forbidden' ? 'verb not allowed' : null) } : {}),
  });
  const handler = grantResourceHandler(svc, { authenticate: (req: any) => (req.who === undefined ? null : req.who) } as any);
  const sec = (by: string) => ({ principal: sk('$P'), holder: sk('$A'), wrongkey: sk('$X') } as any)[by];
  const out: any[] = [];
  for (const raw of spec.steps) {
    const s = resolve(raw);
    try {
      let r: any;
      switch (s.op) {
        case 'register': r = await svc.register(s.grant); break;
        case 'list': r = await svc.list(s.filter ?? {}); break;
        case 'inspect': r = await svc.inspect(s.id); break;
        case 'amend': {
          const g = await svc.inspect(s.id);
          const req: any = { action: s.action, authority: s.authority };
          if (s.by !== 'none') { req.signed_by = s.signed_by ?? (s.by === 'holder' ? 'holder' : 'principal'); req.sig = signGrantBody(GRANT_AMEND_DOMAIN, amendMessage(g, s.action, s.authority), sec(s.by)); }
          if (s.stepUp) req.step_up_ref = s.stepUp;
          r = await svc.amend(s.id, req); break;
        }
        case 'revoke': {
          const g = await svc.inspect(s.id);
          r = await svc.revoke(s.id, s.scope, s.by === 'admin' ? { admin: true } : s.by === 'noauth' ? ({} as any) : { sig: signGrantBody(GRANT_REVOKE_DOMAIN, grantRevokeMessage(g.id, s.scope), sec(s.by)) }); break;
        }
        case 'needs': r = await svc.requestNeeds(s.id, s.needs); break;
        case 'approve': {
          const nid = await svc.needGrantId(s.needId);
          const g = await svc.inspect(nid);
          r = await svc.approveNeeds(s.needId, s.approved, signGrantBody(NEED_APPROVE_DOMAIN, needApproveMessage({ id: s.needId, grant_id: nid }, g.rev, s.approved), sec(s.by)), s.stepUp); break;
        }
        case 'deny': r = await svc.denyNeeds(s.needId); break;
        case 'http': r = await handler({ method: s.method, path: s.path, query: s.query, body: s.body, who: s.who } as any); break;
        default: throw new Error('bad op');
      }
      out.push(J(r));
    } catch (e) { out.push(errCode(e)); }
  }
  return { steps: out, events, grants: J((await store.list()).sort((a, b) => (a.id < b.id ? -1 : 1))) };
}
const A1 = { verbs: ['read', 'write'], resources: ['doc/*', 'img/1'], limits: { spend: 100 }, expires_at: T0 + 1_000_000 };
const reg = (id: string, extra: any = {}) => ({ op: 'register', grant: { id, principal: '$key:$P', agent: '$key:$A', chain_digest: `cd-${id}`, authority: A1, ...extra } });
const NARROW = { verbs: ['read'], resources: ['doc/*'], limits: { spend: 50 }, expires_at: T0 + 10 };
const MERGE = { verbs: ['delete'], resources: ['db/*'] };
const gs: any[] = [
  { steps: [reg('g0'), reg('g0'), { op: 'inspect', id: 'g0' }, { op: 'inspect', id: 'nope' }, { op: 'list' }, { op: 'list', filter: { status: 'revoked' } }, { op: 'list', filter: { limit: 1 } }] },
  { providers: true, steps: [reg('g0'), { op: 'inspect', id: 'g0' }, { op: 'list' }] },
  { steps: [reg('g0', { authority: { verbs: [], resources: [] } }), reg('g1', { authority: { verbs: ['x'], resources: ['y'], limits: { a: -1 } } }), reg('g2', { authority: { verbs: [1], resources: [] } }), reg('g3', { authority: 'x' }), reg('g4', { authority: { verbs: [], resources: [], expires_at: 1.5 } })] },
  { steps: [reg('g0'),
    { op: 'amend', id: 'g0', action: 'narrow', authority: NARROW, by: 'holder' }, { op: 'amend', id: 'g0', action: 'narrow', authority: NARROW, by: 'principal' },
    { op: 'amend', id: 'g0', action: 'narrow', authority: NARROW, by: 'none' }, { op: 'amend', id: 'g0', action: 'narrow', authority: NARROW, by: 'wrongkey' },
    { op: 'amend', id: 'g0', action: 'narrow', authority: NARROW, by: 'holder' },
    { op: 'amend', id: 'g0', action: 'narrow', authority: { verbs: ['read', 'x'], resources: ['doc/*'] }, by: 'principal' },
    { op: 'amend', id: 'g0', action: 'bogus', authority: A1, by: 'principal' }, { op: 'amend', id: 'g0', action: 'narrow', authority: { verbs: 5 }, by: 'principal' }, { op: 'inspect', id: 'g0' }] },
  { stepUp: true, steps: [reg('g0'),
    { op: 'amend', id: 'g0', action: 'merge', authority: MERGE, by: 'principal' }, { op: 'amend', id: 'g0', action: 'merge', authority: MERGE, by: 'holder' },
    { op: 'amend', id: 'g0', action: 'merge', authority: MERGE, by: 'principal', stepUp: 'bad-step' },
    { op: 'amend', id: 'g0', action: 'merge', authority: { verbs: ['delete'], resources: ['db/*'], limits: { spend: 500 } }, by: 'principal', stepUp: 'ok-step' },
    { op: 'amend', id: 'g0', action: 'merge', authority: { verbs: ['x'], resources: [] }, by: 'principal', stepUp: 'ok-step' },
    { op: 'list' }, { op: 'inspect', id: 'g_1' }, { op: 'amend', id: 'g_1', action: 'replace', authority: { verbs: ['read'], resources: ['doc/*'] }, by: 'principal' },
    { op: 'amend', id: 'g_1', action: 'replace', authority: { verbs: ['read'], resources: ['doc/*'] }, by: 'principal', stepUp: 'ok-step' }, { op: 'list', filter: { status: 'superseded' } }] },
  { steps: [reg('g0'), { op: 'amend', id: 'g0', action: 'merge', authority: MERGE, by: 'principal', stepUp: 'ok-step' }, { op: 'inspect', id: 'g0' }] },
  { steps: [reg('root'), reg('c1', { parent: 'root' }), reg('c2', { parent: 'c1' }), reg('other', { agent: '$key:$X' }), reg('sib', { parent: 'root' }),
    { op: 'revoke', id: 'c1', scope: 'subtree', by: 'principal' }, { op: 'list' }, { op: 'revoke', id: 'root', scope: 'agent', by: 'admin' }, { op: 'revoke', id: 'root', scope: 'grant', by: 'principal' },
    { op: 'revoke', id: 'other', scope: 'grant', by: 'wrongkey' }, { op: 'revoke', id: 'other', scope: 'bogus', by: 'admin' }, { op: 'revoke', id: 'other', scope: 'grant', by: 'noauth' }, { op: 'revoke', id: 'zz', scope: 'grant', by: 'admin' }] },
  { steps: [reg('g0', { adjustable: true }),
    { op: 'needs', id: 'g0', needs: [{ verb: 'write', resource: 'db/1', limits: { rows: 100 }, adjustable: true }, { verb: 'read', resource: 'db/2' }] },
    { op: 'needs', id: 'g0', needs: [] }, { op: 'needs', id: 'g0', needs: 'x' }, { op: 'needs', id: 'g0', needs: [{ verb: '', resource: 'x' }] }, { op: 'needs', id: 'g0', needs: [{ verb: 'v', resource: 'r', limits: { a: -1 } }] },
    { op: 'needs', id: 'nope', needs: [{ verb: 'v', resource: 'r' }] }, { op: 'inspect', id: 'g0' },
    { op: 'approve', needId: 'n_1', approved: [{ verb: 'write', resource: 'db/1', limits: { rows: 50 } }, { verb: 'read', resource: 'db/2' }], by: 'principal' },
    { op: 'approve', needId: 'n_1', approved: [{ verb: 'write', resource: 'db/1', limits: { rows: 50 } }, { verb: 'read', resource: 'db/2' }], by: 'principal', stepUp: 'ok-step' },
    { op: 'approve', needId: 'n_1', approved: [], by: 'principal' }, { op: 'deny', needId: 'n_1' }, { op: 'deny', needId: 'zz' }, { op: 'list' }] },
  { stepUp: true, validateNeed: true, steps: [reg('g0'),
    { op: 'needs', id: 'g0', needs: [{ verb: 'forbidden', resource: 'db/1' }] }, { op: 'needs', id: 'g0', needs: [{ verb: 'write', resource: 'db/1', limits: { rows: 100 }, adjustable: false }] },
    { op: 'approve', needId: 'n_1', approved: [{ verb: 'write', resource: 'db/1', limits: { rows: 50 } }], by: 'principal', stepUp: 'ok-step' },
    { op: 'approve', needId: 'n_1', approved: [{ verb: 'write', resource: 'db/1', limits: { rows: 200 } }], by: 'principal', stepUp: 'ok-step' },
    { op: 'approve', needId: 'n_1', approved: [{ verb: 'write', resource: 'db/1', limits: { rows: 100 } }], by: 'wrongkey', stepUp: 'ok-step' },
    { op: 'approve', needId: 'n_1', approved: [{ verb: 'write', resource: 'db/1', limits: { rows: 100 } }], by: 'principal', stepUp: 'ok-step' },
    { op: 'approve', needId: 'n_1', approved: [{ verb: 'write', resource: 'db/1', limits: { rows: 100 } }], by: 'principal', stepUp: 'ok-step' }, { op: 'list' }] },
];
const P = { principal: '$key:$P' };
const hs = (...steps: any[]) => ({ stepUp: true, steps: [reg('g0'), reg('g1', { principal: '$key:$X' }), ...steps] });
const H = (method: string, path: string, who: any, extra: any = {}) => ({ op: 'http', method, path, who, ...extra });
gs.push(
  hs(H('GET', '/pca/grants', P), H('GET', '/pca/grants', { admin: true }), H('GET', '/pca/grants', null), H('GET', '/pca/grants', {}), H('GET', '/pca/grants', { principal: '' }),
    H('GET', '/pca/grants', { admin: true }, { query: { principal: '$key:$X' } }), H('GET', '/pca/grants', P, { query: { principal: '$key:$X' } }), H('GET', '/pca/grants', { admin: true }, { query: { status: 'weird' } }),
    H('GET', '/pca/grants', { admin: true }, { query: { limit: '1' } }), H('GET', '/pca/grants', { admin: true }, { query: { limit: 'x', agent: '$key:$A', cursor: 'g0' } }), H('GET', '/pca/grants', { admin: true }, { query: { limit: '0' } }),
    H('GET', '/pca/grants', { admin: true }, { query: { limit: ' 2 ' } }), H('GET', '/pca/grants', { admin: true }, { query: { limit: '1e0' } }), H('GET', '/pca/grants', { admin: true }, { query: { limit: '' } })),
  hs(H('GET', '/pca/grants/g0', P), H('GET', '/pca/grants/g1', P), H('GET', '/pca/grants/g1', { admin: true }), H('GET', '/pca/grants/nope', { admin: true }), H('GET', '/pca/grants/', P), H('GET', '/elsewhere', P), H('GET', '/', P), H('PUT', '/pca/grants/g0', P),
    H('GET', '/pca/grants/g0/amend', P), H('GET', '/pca/needs/x/approve', P), H('POST', '/pca/grants', P), H('GET', 'pca//grants//g0/', P)),
  hs(H('DELETE', '/pca/grants/g0', { admin: true }), H('GET', '/pca/grants/g0', { admin: true }), H('DELETE', '/pca/grants/g0', P), H('DELETE', '/pca/grants/g1', P, { body: { sig: 'x' } }), H('DELETE', '/pca/grants/g1', { admin: true }, { query: { scope: 'agent' }, body: { sig: '' } }),
    H('DELETE', '/pca/grants/g1', { admin: true }, { query: { scope: 'bogus' } }), H('DELETE', '/pca/grants/g1', { admin: true }, { query: { scope: 'subtree' } }), H('DELETE', '/pca/grants/g1', { admin: true, principal: '$key:$X' }, { body: { sig: 5 } })),
  hs(H('POST', '/pca/grants/g0/needs', P, { body: { needs: [{ verb: 'v', resource: 'r', limits: { a: 1 }, adjustable: true }] } }), H('POST', '/pca/grants/g0/needs', P, { body: {} }), H('POST', '/pca/grants/g0/needs', P), H('POST', '/pca/grants/g1/needs', P, { body: { needs: [{ verb: 'v', resource: 'r' }] } }),
    H('POST', '/pca/needs/n_1/approve', P, { body: {} }), H('POST', '/pca/needs/n_1/approve', P, { body: { sig: 'x', approved: [] } }), H('POST', '/pca/needs/n_1/approve', { principal: '$key:$X' }, { body: { sig: 'x', approved: [] } }),
    H('POST', '/pca/needs/n_1/approve', P, { body: { sig: 'x', approved: [{ verb: 'v', resource: 'r' }], step_up_ref: 'ok-step' } }), H('POST', '/pca/needs/zz/approve', P, { body: { sig: 'x', approved: [] } }), H('POST', '/pca/needs/n_1/deny', { principal: '$key:$X' }),
    H('POST', '/pca/needs/n_1/deny', P), H('POST', '/pca/needs/n_1/deny', P), H('GET', '/pca/grants/g0', P)),
  hs(H('POST', '/pca/grants/g0/amend', P, { body: { action: 'narrow', authority: { verbs: ['read'], resources: ['doc/*'] }, signed_by: 'principal', sig: 'bad' } }), H('POST', '/pca/grants/g0/amend', P, { body: 'x' }), H('POST', '/pca/grants/g0/amend', P),
    H('POST', '/pca/grants/g0/amend', { principal: '$key:$X' }, { body: {} }), H('POST', '/pca/grants/g0/amend', { admin: true }, { body: { action: 'merge', authority: A1 } })),
);
for (const [i, s] of gs.entries()) await o.run('grantScenario', `s${i}`, grantScenario, [s]);

// ---- leases ---------------------------------------------------------------------------------------------------------------------
const lf = (id: string, over: any = {}) => ({ ...lease, lease_id: id, path: `svc/${id}`, grant_ref: `g-${id}`, ...over });
const SL = (kind: string, fields: any, label = 'auth') => ({ $sign: { kind, label, fields } });
async function leaseScenario(spec: any) {
  const now = T0;
  const reg = new LeaseRegistry({ authorities: [pub('auth')], ...(spec.policy ?? {}) }, memoryLeaseKv(), { shards: spec.shards ?? 4, clock: () => now });
  const handler = leaseResourceHandler(reg, { authenticate: (req: any) => (req.who === undefined ? null : req.who), now: () => now } as any);
  const strip = (x: any): any => { if (x && typeof x === 'object' && !Array.isArray(x)) { const { reason: _r, message: _m, ...rest } = x; return rest; } return x; };
  const out: any[] = [];
  for (const raw of spec.steps) {
    const s = resolve(raw);
    try {
      let r: any;
      switch (s.op) {
        case 'accept': r = strip(await reg.accept(s.lease, s.chain)); break;
        case 'revoke': r = await reg.revoke(s.rev); break;
        case 'get': r = (await reg.get(s.id)) ?? null; break;
        case 'history': r = await reg.history(s.id); break;
        case 'shardRevs': r = await reg.shardRevocations(s.i); break;
        case 'renew': {
          const veto = s.vetoSeq !== undefined ? (c: any) => c.seq >= s.vetoSeq : undefined;
          r = await renewLease(sk(s.label ?? 'auth'), reg, s.id, { now: s.now, increment: s.increment, justification_digest: s.just, ...(s.approvers ? { approvers: s.approvers } : {}), ...(veto ? { veto } : {}), ...(s.chain ? { chain: s.chain } : {}) });
          if (!r.ok) r = { ok: false, code: r.code };
          break;
        }
        case 'check': r = await checkLease(s.lease, reg, s.now); break;
        case 'http': { const res: any = await handler({ method: s.method, path: s.path, query: s.query, body: s.body, who: s.who } as any); r = { status: res.status, body: strip(res.body) }; break; }
        default: throw new Error('bad op');
      }
      out.push(J(r));
    } catch (e) { out.push(errCode(e)); }
  }
  return out;
}
const ADM = { admin: true };
const LH = (method: string, path: string, who: any, body?: any) => ({ op: 'http', method, path, who, ...(body !== undefined ? { body } : {}) });
const ls1 = SL('lease', lf('a')), ls1b = SL('lease', lf('a', { seq: 2, renewed_at: T0 + 10, expires_at: T0 + 800_000, justification_digest: 'j2' }));
const lsc: any[] = [
  { steps: [{ op: 'accept', lease: ls1 }, { op: 'accept', lease: ls1 }, { op: 'accept', lease: ls1b }, { op: 'get', id: 'a' }, { op: 'history', id: 'a' }, { op: 'accept', lease: SL('lease', lf('a', { seq: 2, renewed_at: T0 + 10, expires_at: T0 + 800_001, justification_digest: 'j3' })) }, { op: 'accept', lease: ls1 }, { op: 'accept', lease: 'junk' }, { op: 'accept', lease: SL('lease', lf('z'), 'other') }, { op: 'accept', lease: SL('leaseOver', lf('o', { expires_at: T0 + 4_000_000 })) }] },
  { steps: [{ op: 'accept', lease: ls1 }, { op: 'check', lease: ls1, now: T0 + 1 }, { op: 'check', lease: ls1, now: T0 + 600_000 }, { op: 'check', lease: ls1, now: T0 - 1 }, { op: 'check', lease: ls1, now: -1 }, { op: 'check', lease: 'x', now: 1 }, { op: 'check', lease: SL('lease', lf('nope')), now: T0 }, { op: 'accept', lease: ls1b }, { op: 'check', lease: ls1, now: T0 + 20 }, { op: 'check', lease: ls1b, now: T0 + 20 }, { op: 'revoke', rev: SL('revocation', { target: 'lease', value: 'a', revoked_at: T0 + 30 }) }, { op: 'check', lease: ls1b, now: T0 + 40 }, { op: 'shardRevs', i: 0 }, { op: 'shardRevs', i: 99 }] },
  { steps: [{ op: 'accept', lease: SL('lease', lf('p1', { path: 'db/prod/ro' })) }, { op: 'accept', lease: SL('lease', lf('p2', { path: 'db/prod/rw' })) }, { op: 'accept', lease: SL('lease', lf('p3', { path: 'db/production' })) }, { op: 'revoke', rev: SL('revocation', { target: 'prefix', value: 'db/prod', revoked_at: T0 + 5 }) }, { op: 'revoke', rev: SL('revocation', { target: 'prefix', value: 'db/prod', revoked_at: T0 + 5 }) }, { op: 'revoke', rev: SL('revocation', { target: 'grant', value: 'g-p3', revoked_at: T0 + 5 }) }, { op: 'revoke', rev: SL('revocation', { target: 'lease', value: 'p1', revoked_at: T0 + 5 }, 'other') }, { op: 'revoke', rev: 'x' }, { op: 'accept', lease: SL('lease', lf('p4', { path: 'db/prod/x', issued_at: T0 + 100, renewed_at: T0 + 100, expires_at: T0 + 900_000 })) }, { op: 'accept', lease: SL('lease', lf('p5', { path: 'db/prod/x', issued_at: T0 + 1, renewed_at: T0 + 1, expires_at: T0 + 900_000 })) }] },
  { steps: [{ op: 'accept', lease: ls1 }, { op: 'renew', id: 'a', now: T0 + 100, increment: 300_000, just: 'r1' }, { op: 'renew', id: 'a', now: T0 + 200, increment: 99_999_999, just: 'r2' }, { op: 'renew', id: 'a', now: T0 + 3_700_000, increment: 5, just: 'r3' }, { op: 'renew', id: 'zz', now: T0, increment: 1, just: 'r' }, { op: 'renew', id: 'a', now: T0, increment: 0, just: 'r' }, { op: 'renew', id: 'a', now: -1, increment: 5, just: 'r' }, { op: 'renew', id: 'a', now: T0 + 300, increment: 5, just: 'r4', vetoSeq: 3 }, { op: 'renew', id: 'a', now: T0 + 300, increment: 5, just: 'r5', vetoSeq: 99, approvers: ['carol'] }, { op: 'history', id: 'a' }, { op: 'renew', id: 'a', now: T0 + 400, increment: 5, just: 'r6', approvers: [1] }] },
  { policy: { minApprovals: 2 }, steps: [{ op: 'accept', lease: ls1 }, { op: 'accept', lease: SL('lease', lf('two', { approvers: ['bob', 'carol'] })) }, { op: 'accept', lease: SL('lease', lf('dup', { approvers: ['bob', 'bob'] })) }] },
  { policy: { eligibleApprovers: ['bob'] }, steps: [{ op: 'accept', lease: ls1 }, { op: 'accept', lease: SL('lease', lf('x1', { approvers: ['carol'] })) }] },
  { policy: { maxTtlCeiling: 1_000_000 }, steps: [{ op: 'accept', lease: SL('lease', lf('big', { max_ttl: 1_000_001 })) }, { op: 'accept', lease: SL('lease', lf('ok', { max_ttl: 1_000_000 })) }, { op: 'accept', lease: SL('lease', lf('self', { requester: 'agent' })) }, { op: 'accept', lease: SL('lease', lf('chain', { approvers: ['bob'] })), chain: ['bob'] }, { op: 'accept', lease: SL('lease', lf('chain2')), chain: [1, 2] }] },
  { steps: [LH('POST', '/pca/leases', ADM, { lease: ls1 }), LH('POST', '/pca/leases', ADM, { lease: ls1 }), LH('POST', '/pca/leases', ADM, { lease: ls1b, chain: ['x', 1] }), LH('POST', '/pca/leases', ADM, { lease: ls1b, chain: ['x'] }), LH('POST', '/pca/leases', { principal: 'agent' }, { lease: ls1 }), LH('POST', '/pca/leases', null, { lease: ls1 }), LH('POST', '/pca/leases', {}, { lease: ls1 }), LH('POST', '/pca/leases', ADM, { lease: 'junk' }), LH('POST', '/pca/leases', ADM, { lease: SL('lease', lf('b', { seq: 5, renewed_at: T0 + 3, expires_at: T0 + 9000 })) }),
    LH('GET', '/pca/leases/a', { principal: 'agent' }), LH('GET', '/pca/leases/a', { principal: 'other' }), LH('GET', '/pca/leases/a', ADM), LH('GET', '/pca/leases/zz', ADM), LH('GET', '/pca/leases', ADM), LH('GET', '/pca/leases/', ADM), LH('GET', '/pca/other', ADM), LH('DELETE', '/pca/leases/a', ADM),
    LH('POST', '/pca/leases/a/check', { principal: 'agent' }, { lease: ls1b }), LH('POST', '/pca/leases/a/check', { principal: 'agent' }, { lease: ls1 }), LH('POST', '/pca/leases/a/check', { principal: 'other' }, { lease: ls1b }), LH('POST', '/pca/leases/zz/check', ADM, { lease: ls1b }), LH('POST', '/pca/leases/a/check', ADM, {}),
    LH('POST', '/pca/leases/revoke', { principal: 'agent' }, { revocation: SL('revocation', { target: 'lease', value: 'a', revoked_at: T0 + 30 }) }), LH('POST', '/pca/leases/revoke', ADM, { revocation: SL('revocation', { target: 'lease', value: 'a', revoked_at: T0 + 30 }) }), LH('POST', '/pca/leases/revoke', ADM, { revocation: SL('revocation', { target: 'lease', value: 'a', revoked_at: T0 + 30 }, 'other') }), LH('POST', '/pca/leases/revoke', ADM, { revocation: 5 }), LH('POST', '/pca/leases/revoke', ADM),
    LH('POST', '/pca/leases/a/check', ADM, { lease: ls1b })] },
];
for (const [i, s] of lsc.entries()) await o.run('leaseScenario', `s${i}`, leaseScenario, [s]);

// ---- blueprints -----------------------------------------------------------------------------------------------------------------
async function blueprintScenario(spec: any) {
  const reg = new BlueprintRegistry([pub('op')], new MemoryBlueprintStore());
  const adm = new AdmissionRegistry();
  const revoked: any[] = [];
  const fresh = new FreshAtIssuer(sk('iss'), 'scope', { revocation_epoch: 0, ledger_tree_size: 0, budget_version: 0, policy_revision: 0, policy_digest: 'pd' });
  const out: any[] = [];
  for (const raw of spec.steps) {
    const s = resolve(raw);
    try {
      let r: any;
      switch (s.op) {
        case 'accept': r = await reg.accept(s.bp); break;
        case 'epoch': r = await reg.epoch(); break;
        case 'kill': r = await groupKill(sk(s.label ?? 'op'), reg, s.key, { now: s.now, ...(s.reason ? { reason: s.reason } : {}), ...(s.revoker ? { revocation: { revoke: async (i: any) => { revoked.push(i); } } } : {}), ...(s.fresh ? { freshAt: fresh } : {}) }); break;
        case 'revoked': r = revoked; break;
        case 'admit': adm.admit(s.instance, (await reg.get(s.key)) as any, s.until); r = true; break;
        case 'admitRevoke': r = adm.revoke(s.instance, s.key); break;
        case 'admitCheck': r = adm.checker(s.now)(s.instance, (await reg.get(s.key)) as any); break;
        default: throw new Error('bad op');
      }
      out.push(J(r));
    } catch (e) { out.push(errCode(e)); }
  }
  return out;
}
const B = (fields: any, label = 'op') => SL('blueprint', fields, label);
const bps = { ...bp, key: 'bk1' };
const bsc: any[] = [
  { steps: [{ op: 'epoch' }, { op: 'accept', bp: B(bps) }, { op: 'epoch' }, { op: 'kill', key: 'bk1', now: T0 + 5 }, { op: 'epoch' }, { op: 'kill', key: 'bk1', now: T0 + 6, reason: 'why', revoker: true, fresh: true }, { op: 'revoked' }, { op: 'kill', key: 'nope', now: T0 }, { op: 'accept', bp: B({ ...bps, epoch: 2 }) }, { op: 'kill', key: 'bk1', now: T0 + 7, label: 'other' }, { op: 'kill', key: 'bk1', now: -1 }] },
  { steps: [{ op: 'accept', bp: B({ ...bps, runtime_pins: [{ runtime_measurement: 'm1' }] }) }, { op: 'kill', key: 'bk1', now: T0 + 1, revoker: true, fresh: true }, { op: 'kill', key: 'bk1', now: T0 + 2, fresh: true }, { op: 'revoked' }] },
  { steps: [{ op: 'accept', bp: B({ ...bps, epoch: 3 }) }, { op: 'admit', key: 'bk1', instance: 'i1', until: T0 + 100 }, { op: 'admitCheck', key: 'bk1', instance: 'i1', now: T0 + 99 }, { op: 'admitCheck', key: 'bk1', instance: 'i1', now: T0 + 100 }, { op: 'admitCheck', key: 'bk1', instance: 'i2', now: T0 }, { op: 'accept', bp: B({ ...bps, epoch: 4 }) }, { op: 'admitCheck', key: 'bk1', instance: 'i1', now: T0 }, { op: 'admit', key: 'bk1', instance: 'i1', until: T0 + 100 }, { op: 'admitCheck', key: 'bk1', instance: 'i1', now: T0 }, { op: 'admitRevoke', key: 'bk1', instance: 'i1' }, { op: 'admitRevoke', key: 'bk1', instance: 'i1' }, { op: 'admitCheck', key: 'bk1', instance: 'i1', now: T0 }] },
];
for (const [i, s] of bsc.entries()) await o.run('blueprintScenario', `s${i}`, blueprintScenario, [s]);

const pinned = { ...bps, runtime_pins: [{ runtime_measurement: 'm1', operator: 'op1' }, { spiffe_id: 'spiffe://a/b' }, { model_id: 'x' }] };
for (const [i, e] of ([
  { ok: true, bound: true, identity: { runtime_measurement: 'm1', operator: 'op1' } }, { ok: true, bound: true, identity: { runtime_measurement: 'm1', operator: 'op2' } },
  { ok: true, bound: true, identity: { spiffe_id: 'spiffe://a/b', extra: 'x' } }, { ok: true, bound: true, identity: { model_id: 'x' } }, { ok: true, bound: true, identity: {} }, { ok: true, bound: true, identity: [] }, { ok: true, bound: true, identity: 'str' },
  { ok: true, bound: true, identity: null }, { ok: true, bound: true }, { ok: true, bound: false, identity: { model_id: 'x' } }, { ok: true, bound: 'true', identity: { model_id: 'x' } }, { ok: 1, bound: true, identity: { model_id: 'x' } },
  { ok: false, bound: true, reason: 'bad doc' }, { ok: false, reason: 5 }, {}, null, 'str', 5, { $throw: true }, { ok: true, bound: true, identity: { model_id: true } }, { ok: true, bound: true, identity: { runtime_measurement: 'm1' } },
] as any[]).entries()) await o.run('admitWithEvidence', `e${i}`, (b: any, e: any) => admitWithEvidence(b, () => { if (e && e.$throw) throw new TypeError('boom'); return e; }), [pinned, e]);
for (const [i, b] of [bps, { ...bps, runtime_pins: [] }, { ...pinned, runtime_pins: [{}] }, { ...pinned, runtime_pins: ['x', { model_id: 'x' }] }].entries())
  await o.run('admitWithEvidence', `b${i}`, (b: any, e: any) => admitWithEvidence(b, () => e), [b, { ok: true, bound: true, identity: { model_id: 'x' } }]);

refWrite(o, 'grants');
