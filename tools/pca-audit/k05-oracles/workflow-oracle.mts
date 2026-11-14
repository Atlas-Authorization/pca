// k05 oracle: K5 workflow (DAG) admission (Java Workflow and every native port). TS reference: packages/pca/src/workflow.ts.
// Extends conformance/workflow-vectors.json with generated inputs: every body member deleted / retyped / at its limit and the
// body RE-SIGNED (so the check after the shape is reached), every receipt member mutated (re-signed and not), every request
// member, the clock at every boundary, pinned keys swapped, random DAGs (dagError / ancestors), plan-root authorization, and
// the value / workflow / receipt digests. Keys are the fixed seeds of the shared vectors. Deterministic (Ed25519).
// Writes tools/pca-audit/k05-oracles/out/k05-workflow.json.gz.
// PORTING (fn -> Java):
//   admit(workflow, principal, rsSigner, receipts, now, request)   Workflow.admitStep(...).toMap()       canonical-JSON equality
//   bind(...same)                                                  Workflow.bindPromises(...).toMap()    canonical-JSON equality
//   planRoot(workflow, principal, now, root)                       Workflow.planRootAuthorized(...)      boolean
//   validBody(b)                                                   Workflow.validWorkflowBody(b)         boolean
//   dag(b)  (b is a valid body)                                    Workflow.dagError(b)                  exact string | null
//   ancestors(b) (valid body)                                      Workflow.ancestors(b)                 null | {id: sorted ids}
//   valueDigest(v) / workflowDigest(b) / receiptRef(r)             Workflow.valueDigest / workflowDigest / receiptRef   exact
import * as W from '../../../packages/pca/src/workflow.ts';
import { b64u, hashCanonical } from '../../../packages/pca/src/hash.ts';
import { publicKeyOf } from '../../../packages/pca/src/keys.ts';
import { Oracle, variants, rng } from './lib.mjs';

const wf: any = (W as any).admitStep ? W : (W as any).default;
const o = new Oracle('workflow', 'tools/pca-audit/k05-oracles/workflow-oracle.mts', 'TS-reference oracle for K5 workflow admission: re-signed body variants, receipt and request variants, clock and key boundaries, random DAGs, plan-root authorization, digests.');
const P = new Uint8Array(32).fill(51);
const RS = new Uint8Array(32).fill(52);
const X = new Uint8Array(32).fill(53);
const PK = b64u(publicKeyOf(P));
const RSK = b64u(publicKeyOf(RS));
const XK = b64u(publicKeyOf(X));
const NOW = 1_800_000_000_000;
const D = (s: string) => hashCanonical({ vector: s });
const LOOK_PARAMS = { order: 'ord_42' };
const clone = (x: any) => JSON.parse(JSON.stringify(x));

const step = (id: string, verb: string, resource: string, x: any = {}) => ({ id, verb, resource, params_digest: null, deps: [], sink: null, deny_labels: [], escalate_labels: [], fresh_ms: null, cost: {}, ...x });
const edge = (fs: string, ff: string, ts: string, tp: string, op: string, x: any = {}) => ({ from: { step: fs, field: ff }, to: { step: ts, param: tp }, op, unit: null, deny_labels: [], promise: null, ...x });
const BODY: any = {
  v: 1, id: 'wf-refund-1', principal: PK, goal_digest: D('goal'), plan_root: D('plan-root'), issued_at: NOW - 3_600_000, expires_at: NOW + 3_600_000,
  steps: [
    step('lookup', 'orders.get', 'orders/42', { params_digest: hashCanonical(LOOK_PARAMS), cost: { calls: 1 } }),
    step('refund', 'payments.refund', 'payments/42', { deps: ['lookup'], fresh_ms: 600_000, cost: { calls: 1, money: 5000 } }),
    step('notify', 'mail.send', 'mail/out', { deps: ['lookup', 'refund'], sink: 'external_communication', deny_labels: ['secret'], escalate_labels: ['pii'], cost: { calls: 1 } }),
    step('audit', 'audit.log', 'audit/1', { deps: ['refund'], cost: { calls: 1 } }),
  ],
  edges: [
    edge('lookup', 'refund_cents', 'refund', 'amount', 'le', { unit: 'usd_c' }),
    edge('lookup', 'order', 'refund', 'order', 'eq'),
    edge('refund', 'confirmation', 'notify', 'ref', 'eq', { deny_labels: ['secret'] }),
    edge('refund', 'id', 'audit', 'refund_id', 'eq', { promise: 'refund-id-of-this-order' }),
  ],
  budget: { max_steps: 6, caps: { calls: 6, money: 5000 } },
};
const sign = (body: unknown, key = P, domain = wf.WORKFLOW_DOMAIN) => {
  try { return wf.signBody(key, domain, body); } catch { return 'AA'; }
};
const signed = (body: unknown) => ({ body, sig: sign(body) });

/** A receipt chain for `body` (each receipt signed by RS over the receipt body, chained by prev). */
function chain(body: any, x: { labels?: string[]; cents?: number; outcome?: string; at?: number } = {}) {
  const at = x.at ?? NOW - 30_000;
  const mk = (stepId: string, params: unknown, outputs: unknown, issuedAt: number, prev: any, outcome = 'ok') => {
    let wd: string;
    try { wd = wf.workflowDigest(body); } catch { wd = D('bad'); }
    const base: any = { v: 1, wf: wd, step: stepId, seq: prev ? prev.seq + 1 : 0, prev: prev ? wf.receiptRef(prev) : null, outcome, params_digest: hashCanonical(params), outputs, issued_at: issuedAt, signer: RSK };
    return { ...base, sig: sign(base, RS, wf.WF_RECEIPT_DOMAIN) };
  };
  const lookup = mk('lookup', LOOK_PARAMS, { refund_cents: wf.wfOutput(x.cents ?? 2500, { num: true, unit: 'usd_c' }), order: wf.wfOutput('ord_42'), email: wf.wfOutput('a@example.com', { labels: x.labels ?? ['pii'] }) }, at, null, x.outcome ?? 'ok');
  const refund = mk('refund', { amount: 2500, order: 'ord_42' }, { confirmation: wf.wfOutput('conf_9'), id: wf.wfOutput('rf_7') }, at + 1000, lookup);
  const notify = mk('notify', { ref: 'conf_9' }, {}, at + 2000, refund);
  const audit = mk('audit', { refund_id: 'rf_7' }, {}, at + 3000, notify);
  return { lookup, refund, notify, audit, mk };
}
const REQ: Record<string, [string, string, any, any]> = {
  lookup: ['orders.get', 'orders/42', LOOK_PARAMS, {}],
  refund: ['payments.refund', 'payments/42', { amount: 2500, order: 'ord_42' }, { amount: 'usd_c' }],
  notify: ['mail.send', 'mail/out', { ref: 'conf_9' }, {}],
  audit: ['audit.log', 'audit/1', { refund_id: 'rf_7' }, {}],
};
const req = (s: string, x: any = {}) => {
  const [verb, resource, params, units] = REQ[s] ?? ['x.y', 'z', {}, {}];
  return { step: s, verb, resource, params, units, goal_digest: D('goal'), plan_root: D('plan-root'), ...x };
};
const admitFn = (kind: 'admit' | 'bind') => (w: unknown, principal: unknown, rsSigner: unknown, receipts: unknown, now: unknown, request: unknown) =>
  (kind === 'admit' ? wf.admitStep : wf.bindPromises)({ workflow: w, principal, rsSigner, receipts, now, request });
const run = (kind: 'admit' | 'bind', n: string, w: unknown, receipts: unknown, request: unknown, x: { principal?: unknown; rs?: unknown; now?: unknown } = {}) =>
  o.run(kind, n, admitFn(kind), [w, 'principal' in x ? x.principal : PK, 'rs' in x ? x.rs : RSK, receipts, 'now' in x ? x.now : NOW, request]);

const WF = signed(BODY);
const CH = chain(BODY);
const SCEN: [string, any[], any][] = [
  ['lookup', [], req('lookup')],
  ['refund', [CH.lookup], req('refund')],
  ['refund pipelined', [], req('refund')],
  ['notify', [CH.lookup, CH.refund], req('notify')],
  ['audit pending', [CH.lookup], req('audit')],
  ['audit', [CH.lookup, CH.refund], req('audit')],
];
const BIND: [string, any[], any][] = [
  ['bind refund', [CH.lookup, CH.refund], req('refund')],
  ['bind audit', [CH.lookup, CH.refund, CH.notify, CH.audit], req('audit')],
  ['bind audit before refund', [CH.lookup], req('audit')],
  ['bind notify', [CH.lookup, CH.refund, CH.notify], req('notify')],
];
for (const [n, rc, q] of SCEN) await run('admit', 'base ' + n, WF, rc, q);
for (const [n, rc, q] of BIND) await run('bind', 'base ' + n, WF, rc, q);

// ---- body variants, re-signed, with receipts re-issued for the variant ------------------------------------------------
const r = rng(0x5f);
let i = 0;
for (const [n, body] of variants(BODY, { lens: [0, 1, 16, 17, 64, 65, 128, 129, 512, 513], depth: 5 })) {
  const w = signed(body);
  const ch = (() => { try { return chain(body); } catch { return CH; } })();
  const [sn, rc, q] = [
    ['lookup', [], req('lookup')], ['refund', [ch.lookup], req('refund')], ['refund pipelined', [], req('refund')], ['notify', [ch.lookup, ch.refund], req('notify')],
    ['audit pending', [ch.lookup], req('audit')], ['audit', [ch.lookup, ch.refund], req('audit')],
  ][i++ % 6] as [string, any[], any];
  await run('admit', `body ${n} / ${sn}`, w, rc, q);
  if (r.next() < 0.5) await run('bind', `body ${n} / bind refund`, w, [ch.lookup, ch.refund], req('refund'));
  await o.run('validBody', n, wf.validWorkflowBody, [body]);
}
// unsigned (original signature over a changed body) and the envelope itself
for (const [n, w] of variants(WF, { depth: 1 })) await run('admit', 'envelope ' + n, w, [], req('lookup'));
await run('admit', 'tampered not re-signed', { body: { ...BODY, budget: { max_steps: 60, caps: BODY.budget.caps } }, sig: WF.sig }, [], req('lookup'));
await run('admit', 'attacker signed', { body: { ...BODY, principal: XK }, sig: sign({ ...BODY, principal: XK }, X) }, [], req('lookup'));
await run('admit', 'other domain', { body: BODY, sig: sign(BODY, P, 'atlas-pca/other/v1\0') }, [], req('lookup'));

// ---- the clock, the pinned keys --------------------------------------------------------------------------------------
for (const now of [BODY.issued_at - 1, BODY.issued_at, BODY.expires_at - 1, BODY.expires_at, NOW - 30_000 + 600_000, NOW - 30_000 + 600_001, NOW - 30_001, NOW - 30_000, NOW - 29_000, NOW - 28_999, 0, -1, 1.5, -0, 2 ** 53, '1', null])
  for (const [n, rc, q] of SCEN) await run('admit', `now ${Object.is(now, -0) ? '-0' : JSON.stringify(now)} ${n}`, WF, rc, q, { now });
for (const [kn, x] of [['principal X', { principal: XK }], ['principal RS', { principal: RSK }], ['principal short', { principal: 'AA' }], ['principal number', { principal: 1 }],
  ['rs X', { rs: XK }], ['rs P', { rs: PK }], ['rs short', { rs: 'AA' }], ['rs null', { rs: null }]] as const)
  for (const [n, rc, q] of SCEN) await run('admit', `${kn} ${n}`, WF, rc, q, x as any);
await run('admit', 'receipts not array', WF, {}, req('lookup'));
await run('admit', 'receipts null', WF, null, req('lookup'));

// ---- receipt variants -------------------------------------------------------------------------------------------------
const resign = (rc: any) => { if (rc === null || typeof rc !== 'object' || Array.isArray(rc)) return rc; const { sig: _s, ...b } = rc; void _s; return { ...rc, sig: sign({ v: b.v, wf: b.wf, step: b.step, seq: b.seq, prev: b.prev, outcome: b.outcome, params_digest: b.params_digest, outputs: b.outputs, issued_at: b.issued_at, signer: b.signer }, RS, wf.WF_RECEIPT_DOMAIN) }; };
for (const [idx, base] of [[0, CH.lookup], [1, CH.refund]] as const) {
  for (const [n, v] of variants(base, { lens: [0, 1, 32, 33, 64, 65], depth: 4 })) {
    const rcs = idx === 0 ? [v, CH.refund] : [CH.lookup, v];
    await run('admit', `receipt ${idx} ${n}`, WF, rcs, req(idx === 0 ? 'refund' : 'notify'));
    const rs = resign(v);
    const rcs2 = idx === 0 ? [rs] : [CH.lookup, rs];
    await run('admit', `receipt ${idx} resigned ${n}`, WF, rcs2, req(idx === 0 ? 'refund' : 'notify'));
  }
}
// semantic receipts: labels, amounts, outcomes, timing, order
for (const labels of [[], ['secret'], ['pii'], ['a', 'secret'], ['pii', 'secret']])
  for (const [n, s, k] of [['notify', 'notify', 2], ['audit', 'audit', 2], ['refund', 'refund', 1]] as const) {
    const c = chain(BODY, { labels });
    await run('admit', `labels ${labels.join('+')} ${n}`, WF, [c.lookup, c.refund].slice(0, k), req(s));
  }
for (const cents of [0, 2499, 2500, 2501, 1, -1])
  for (const amount of [2499, 2500, 2501, 0, '2500', true]) {
    const c = chain(BODY, { cents: cents < 0 ? 0 : cents });
    await run('admit', `cents ${cents} amount ${JSON.stringify(amount)}`, WF, [c.lookup], req('refund', { params: { amount, order: 'ord_42' } }));
  }
await run('admit', 'lookup failed', WF, [chain(BODY, { outcome: 'failed' }).lookup], req('refund'));
await run('admit', 'receipt from the future', WF, [chain(BODY, { at: NOW + 1 }).lookup], req('refund'));
await run('admit', 'receipt at now', WF, [chain(BODY, { at: NOW }).lookup], req('refund'));
await run('admit', 'receipts out of order', WF, [CH.refund, CH.lookup], req('notify'));
await run('admit', 'receipt twice', WF, [CH.lookup, CH.lookup], req('refund'));
await run('admit', 'refund receipt first (unpromised)', WF, [CH.mk('refund', { amount: 2500, order: 'ord_42' }, {}, NOW - 30_000, null)], req('lookup'));
await run('admit', 'audit receipt before refund (promised)', WF, [CH.lookup, CH.mk('audit', { refund_id: 'rf_7' }, {}, NOW - 29_000, CH.lookup)], req('refund'));
await run('admit', 'audit receipt first', WF, [CH.mk('audit', { refund_id: 'rf_7' }, {}, NOW - 30_000, null)], req('lookup'));
await run('admit', 'unknown step receipt', WF, [CH.mk('ghost', {}, {}, NOW - 30_000, null)], req('lookup'));
await run('admit', 'all four then lookup', WF, [CH.lookup, CH.refund, CH.notify, CH.audit], req('lookup'));
await run('admit', 'all four then audit', WF, [CH.lookup, CH.refund, CH.notify, CH.audit], req('audit'));

// ---- request variants -------------------------------------------------------------------------------------------------
for (const [n, rc, q] of SCEN.slice(1))
  for (const [vn, v] of variants(q, { lens: [0, 1, 64, 65, 128, 129, 512, 513], depth: 3 })) {
    await run('admit', `request ${n} ${vn}`, WF, rc, v);
    if (n === 'audit') await run('bind', `request bind ${vn}`, WF, [CH.lookup, CH.refund, CH.notify, CH.audit], v);
  }
for (const k of Array.from({ length: 34 }, (_, j) => j)) {
  const params = Object.fromEntries(Array.from({ length: k }, (_, j) => [`p${j}`, j]));
  await run('admit', `request ${k} params`, WF, [], req('lookup', { params }));
}

// ---- budget and freshness bodies (re-signed) -------------------------------------------------------------------------
const bodyWith = (f: (b: any) => void) => { const b = clone(BODY); f(b); return b; };
for (const ms of [0, 1, 2, 3, 4, 5]) for (const [n, rc, q] of SCEN) await run('admit', `max_steps ${ms} ${n}`, signed(bodyWith((b) => { b.budget.max_steps = ms; })), chainRc(rc, bodyWith((b) => { b.budget.max_steps = ms; })), q);
function chainRc(rc: any[], body: any) {
  const c = chain(body);
  return rc.map((x) => (c as any)[x.step]);
}
for (const [cn, caps] of [['calls 1', { calls: 1, money: 5000 }], ['calls 2', { calls: 2, money: 5000 }], ['calls 3', { calls: 3, money: 5000 }], ['money 4999', { calls: 6, money: 4999 }], ['money 0', { calls: 6, money: 0 }], ['extra cap', { calls: 6, money: 5000, other: 0 }]] as const)
  for (const [n, rc, q] of SCEN) { const b = bodyWith((x) => { x.budget.caps = caps; }); await run('admit', `caps ${cn} ${n}`, signed(b), chainRc(rc, b), q); }
for (const fm of [0, 29_999, 30_000, 30_001, null])
  for (const [n, rc, q] of SCEN) { const b = bodyWith((x) => { x.steps[1].fresh_ms = fm; x.steps[2].fresh_ms = fm; }); await run('admit', `fresh ${fm} ${n}`, signed(b), chainRc(rc, b), q); }
for (const [en, ef] of [['ge', (b: any) => { b.edges[0].op = 'ge'; }], ['lt', (b: any) => { b.edges[0].op = 'lt'; }], ['gt', (b: any) => { b.edges[0].op = 'gt'; }], ['eq', (b: any) => { b.edges[0].op = 'eq'; }],
  ['unit null', (b: any) => { b.edges[0].unit = null; }], ['deny pii', (b: any) => { b.edges[1].deny_labels = ['pii']; }], ['deny pii on email', (b: any) => { b.edges.push(edge('lookup', 'email', 'refund', 'order', 'eq', { deny_labels: ['pii'] })); }],
  ['promise on lookup->refund', (b: any) => { b.edges[0].promise = 'p'; b.edges[1].promise = 'p'; }], ['promise on one', (b: any) => { b.edges[0].promise = 'p'; }],
  ['refund deny pii', (b: any) => { b.steps[1].deny_labels = ['pii']; }], ['refund escalate pii', (b: any) => { b.steps[1].escalate_labels = ['pii']; }],
  ['audit escalate pii', (b: any) => { b.steps[3].escalate_labels = ['pii']; }], ['audit deny pii', (b: any) => { b.steps[3].deny_labels = ['pii']; }],
  ['notify no deny', (b: any) => { b.steps[2].deny_labels = []; }], ['no edges', (b: any) => { b.edges = []; }], ['refund params digest', (b: any) => { b.steps[1].params_digest = hashCanonical({ amount: 2500, order: 'ord_42' }); }],
  ['refund params digest other', (b: any) => { b.steps[1].params_digest = D('x'); }], ['missing field', (b: any) => { b.edges[1].from.field = 'nope'; }], ['missing param', (b: any) => { b.edges[1].to.param = 'nope'; }],
  ['goal null', (b: any) => { b.goal_digest = null; }], ['plan null', (b: any) => { b.plan_root = null; }]] as const)
  for (const [n, rc, q] of SCEN) {
    const b = bodyWith(ef as (b: any) => void);
    await run('admit', `edge ${en} ${n}`, signed(b), chainRc(rc, b), q);
    await run('bind', `edge ${en} ${n}`, signed(b), chainRc([...rc, { step: q.step }].filter((x, j, a) => a.findIndex((y) => y.step === x.step) === j), b), q);
  }

// ---- random DAGs: dagError, ancestors, validWorkflowBody --------------------------------------------------------------
const anc = (b: any) => { const m = wf.ancestors(b); return m === null ? null : Object.fromEntries([...m].map(([k, v]: [string, Set<string>]) => [k, [...v].sort()])); };
for (let k = 0; k < 600; k++) {
  const n = r.int(1, 7);
  const ids = Array.from({ length: n }, (_, j) => `s${j}`);
  if (r.next() < 0.1 && n > 1) ids[n - 1] = ids[0];
  const steps = ids.map((id, j) => {
    let deps = ids.filter((_, m) => (r.next() < 0.3 ? true : false) && (r.next() < 0.8 ? m < j : true));
    if (r.next() < 0.05) deps = [...deps, 'ghost'];
    deps = [...new Set(deps)].sort();
    return step(id, 'v', 'r', { deps });
  });
  const edges = Array.from({ length: r.int(0, 4) }, () => edge(r.pick(ids), 'f', r.pick(ids), 'p', 'eq'));
  if (r.next() < 0.05) edges.push(edge('ghost', 'f', ids[0]!, 'p', 'eq'));
  const b = { ...clone(BODY), steps, edges, budget: { max_steps: 9, caps: {} } };
  if (!wf.validWorkflowBody(b)) { await o.run('validBody', `dag ${k}`, wf.validWorkflowBody, [b]); continue; }
  await o.run('dag', `dag ${k}`, wf.dagError, [b]);
  await o.run('ancestors', `dag ${k}`, anc, [b]);
}
await o.run('ancestors', 'base', anc, [BODY]);
await o.run('dag', 'base', wf.dagError, [BODY]);

// ---- plan root ----------------------------------------------------------------------------------------------------------
const pr = (n: string, w: unknown, principal: unknown, now: unknown, root: unknown) => o.run('planRoot', n, wf.planRootAuthorized, [w, principal, now, root]);
for (const now of [BODY.issued_at - 1, BODY.issued_at, BODY.expires_at - 1, BODY.expires_at, NOW])
  for (const root of [D('plan-root'), D('other'), null]) {
    await pr(`now ${now} root ${root === null ? 'null' : root.slice(0, 4)}`, WF, PK, now, root);
    await pr(`X now ${now} root ${root === null ? 'null' : root.slice(0, 4)}`, WF, XK, now, root);
  }
const nullRoot = signed({ ...BODY, plan_root: null });
await pr('null root body, null root', nullRoot, PK, NOW, null);
await pr('null root body, root', nullRoot, PK, NOW, D('plan-root'));
await pr('tampered', { body: { ...BODY, id: 'x' }, sig: WF.sig }, PK, NOW, D('plan-root'));
await pr('cycle', signed({ ...BODY, steps: [step('a', 'v', 'r', { deps: ['b'] }), step('b', 'v', 'r', { deps: ['a'] })], edges: [], budget: { max_steps: 1, caps: {} } }), PK, NOW, D('plan-root'));
await pr('not object', 'x', PK, NOW, D('plan-root'));
await pr('bad body', { body: { ...BODY, v: 2 }, sig: WF.sig }, PK, NOW, D('plan-root'));
await pr('principal number', WF, 7, NOW, D('plan-root'));
for (const [n, w] of variants(WF, { depth: 1 })) await pr('envelope ' + n, w, PK, NOW, D('plan-root'));

// ---- digests ------------------------------------------------------------------------------------------------------------
for (const v of ['ord_42', '', 'é', 0, 1, -1, 2500, 2 ** 53 - 1, true, false]) await o.run('valueDigest', JSON.stringify(v), wf.valueDigest, [v]);
await o.run('workflowDigest', 'base', wf.workflowDigest, [BODY]);
await o.run('receiptRef', 'lookup', wf.receiptRef, [CH.lookup]);
await o.run('receiptRef', 'refund', wf.receiptRef, [CH.refund]);

o.write();
