/** Exact-outcome kill tests for workflow.ts / readside.ts / read-vault.ts: every boundary and every check, one assertion each. */
import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical } from './hash';
import { publicKeyOf } from './keys';
import {
  WORKFLOW_DOMAIN, WORKFLOW_LIMITS, admitStep, bindPromises, dagError, planRootAuthorized, signBody, signStepReceipt, signWorkflow, validWorkflowBody, valueDigest, wfOutput,
  type EdgeOp, type SignedWorkflow, type WfReceipt, type WorkflowBody,
} from './workflow';
import { redactRead, signReadGrant, type ReadGrantBody, type ReadInput } from './readside';

const P = new Uint8Array(32).fill(81);
const RS = new Uint8Array(32).fill(82);
const PK = b64u(publicKeyOf(P));
const RSK = b64u(publicKeyOf(RS));
const NOW = 1_800_000_000_000;
const D = (s: string) => hashCanonical({ v: s });
const step = (id: string, deps: string[] = [], o: Record<string, unknown> = {}) => ({ id, verb: 'v', resource: 'r', params_digest: null, deps, sink: null, deny_labels: [], escalate_labels: [], fresh_ms: null, cost: {}, ...o });
const edge = (f: string, t: string, op: EdgeOp = 'eq', o: Record<string, unknown> = {}) => ({ from: { step: f, field: 'out' }, to: { step: t, param: 'in' }, op, unit: null, deny_labels: [], promise: null, ...o });
const body = (o: Partial<WorkflowBody> = {}): WorkflowBody =>
  ({ v: 1, id: 'w', principal: PK, goal_digest: null, plan_root: null, issued_at: NOW - 10, expires_at: NOW + 10, steps: [step('a'), step('b', ['a'])], edges: [edge('a', 'b')], budget: { max_steps: 5, caps: {} }, ...o }) as WorkflowBody;
const req = (s: string, params: Record<string, string | number | boolean>, o: Record<string, unknown> = {}) => ({ step: s, verb: 'v', resource: 'r', params, units: {}, goal_digest: null, plan_root: null, ...o });
const adm = (w: SignedWorkflow, receipts: unknown[], request: unknown, now = NOW) => admitStep({ workflow: w, principal: PK, rsSigner: RSK, receipts, now, request });
const rcpt = (w: WorkflowBody, s: string, outputs = {}, o: Record<string, unknown> = {}, prev?: WfReceipt) =>
  signStepReceipt(RS, { workflow: w, step: s, outcome: 'ok', paramsDigest: D('p'), outputs, issuedAt: NOW - 1, ...(prev ? { prev } : {}), ...o } as never);

describe('workflow: limits and shape (exact boundaries)', () => {
  const ids = (n: number) => Array.from({ length: n }, (_, i) => step(`s${i}`));
  it('64 steps are valid, 65 are not', () => {
    expect(validWorkflowBody(body({ steps: ids(WORKFLOW_LIMITS.steps), edges: [] }))).toBe(true);
    expect(validWorkflowBody(body({ steps: ids(WORKFLOW_LIMITS.steps + 1), edges: [] }))).toBe(false);
  });
  it('no steps is invalid; 256 edges are valid, 257 are not', () => {
    expect(validWorkflowBody(body({ steps: [], edges: [] }))).toBe(false);
    const es = (n: number) => Array.from({ length: n }, () => edge('a', 'b'));
    expect(validWorkflowBody(body({ edges: es(WORKFLOW_LIMITS.edges) as never }))).toBe(true);
    expect(validWorkflowBody(body({ edges: es(WORKFLOW_LIMITS.edges + 1) as never }))).toBe(false);
  });
  it('ids: 64 characters pass, 65 and the empty string fail, __proto__ fails', () => {
    expect(validWorkflowBody(body({ id: 'x'.repeat(64) }))).toBe(true);
    expect(validWorkflowBody(body({ id: 'x'.repeat(65) }))).toBe(false);
    expect(validWorkflowBody(body({ id: '' }))).toBe(false);
    expect(validWorkflowBody(body({ id: '__proto__' }))).toBe(false);
    expect(validWorkflowBody(body({ id: 'has space' }))).toBe(false);
  });
  it('deps (16) and labels (16) and cost entries (8) have exact caps', () => {
    const deps = (n: number) => Array.from({ length: n }, (_, i) => `d${String(i).padStart(2, '0')}`);
    const withDeps = (n: number) => body({ steps: [...deps(n).map((d) => step(d)), step('z', deps(n))], edges: [] });
    expect(validWorkflowBody(withDeps(16))).toBe(true);
    expect(validWorkflowBody(withDeps(17))).toBe(false);
    const labels = (n: number) => Array.from({ length: n }, (_, i) => `l${String(i).padStart(2, '0')}`);
    expect(validWorkflowBody(body({ steps: [step('a', [], { deny_labels: labels(16) })], edges: [] }))).toBe(true);
    expect(validWorkflowBody(body({ steps: [step('a', [], { deny_labels: labels(17) })], edges: [] }))).toBe(false);
    const cost = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`c${i}`, 1]));
    const caps = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`c${i}`, 5]));
    expect(validWorkflowBody(body({ steps: [step('a', [], { cost: cost(8) })], edges: [], budget: { max_steps: 1, caps: caps(8) } }))).toBe(true);
    expect(validWorkflowBody(body({ steps: [step('a', [], { cost: cost(9) })], edges: [], budget: { max_steps: 1, caps: caps(9) } }))).toBe(false);
  });
  it('label lists must be strictly ascending and lower-case', () => {
    const lab = (l: string[]) => validWorkflowBody(body({ steps: [step('a', [], { deny_labels: l })], edges: [] }));
    expect(lab(['a', 'b'])).toBe(true);
    expect(lab(['b', 'a'])).toBe(false);
    expect(lab(['a', 'a'])).toBe(false);
    expect(lab(['A'])).toBe(false);
  });
  it('version, principal and times are checked', () => {
    expect(validWorkflowBody({ ...body(), v: 2 })).toBe(false);
    expect(validWorkflowBody(body({ principal: 'x' }))).toBe(false);
    expect(validWorkflowBody(body({ issued_at: -1 }))).toBe(false);
    expect(validWorkflowBody(body({ expires_at: 1.5 }))).toBe(false);
    expect(validWorkflowBody(body({ goal_digest: 'x' }))).toBe(false);
    expect(validWorkflowBody(body({ plan_root: D('r') }))).toBe(true);
  });
  it('dagError names the structural faults', () => {
    expect(dagError(body())).toBeNull();
    expect(dagError(body({ steps: [step('a'), step('a')], edges: [] }))).toBe('duplicate step id');
    expect(dagError(body({ steps: [step('a', ['a'])], edges: [] }))).toBe('bad dependency');
    expect(dagError(body({ steps: [step('a', ['x'])], edges: [] }))).toBe('bad dependency');
    expect(dagError(body({ steps: [step('a', ['b']), step('b', ['a'])], edges: [] }))).toBe('cycle');
    expect(dagError(body({ edges: [edge('b', 'a')] as never }))).toBe('edge does not follow a dependency');
    expect(dagError(body({ edges: [edge('a', 'zz')] as never }))).toBe('edge does not follow a dependency');
  });
  it('a transitive ancestor may feed an edge', () => {
    const w = body({ steps: [step('a'), step('b', ['a']), step('c', ['b'])], edges: [edge('a', 'c')] as never });
    expect(dagError(w)).toBeNull();
  });
});

describe('workflow: signing', () => {
  it('signWorkflow refuses a body that is malformed, cyclic, or not signed by its principal', () => {
    expect(() => signWorkflow(P, body({ steps: [] }))).toThrow('malformed workflow');
    expect(() => signWorkflow(P, body({ steps: [step('a', ['b']), step('b', ['a'])], edges: [] }))).toThrow('malformed workflow');
    expect(() => signWorkflow(RS, body())).toThrow('principal is not the signer');
  });
  it('the commitment signature is bound to the workflow domain', () => {
    const b = body();
    expect(adm({ body: b, sig: signBody(P, WORKFLOW_DOMAIN, b) }, [], req('a', {})).decision).toBe('allow');
    expect(adm({ body: b, sig: signBody(P, 'atlas-pca/workflow/v2\0', b) }, [], req('a', {})).code).toBe('bad_signature');
  });
});

describe('workflow: the edge relations are exact at the boundary', () => {
  const rel = (op: EdgeOp, val: number, src: number) => {
    const b = body({ edges: [edge('a', 'b', op)] as never });
    const w = signWorkflow(P, b);
    const a = rcpt(b, 'a', { out: wfOutput(src, { num: true }) });
    return adm(w, [a], req('b', { in: val })).code;
  };
  it.each([
    ['le', 5, 5, null], ['le', 6, 5, 'edge_relation'], ['le', 4, 5, null],
    ['ge', 5, 5, null], ['ge', 4, 5, 'edge_relation'], ['ge', 6, 5, null],
    ['lt', 5, 5, 'edge_relation'], ['lt', 4, 5, null], ['lt', 6, 5, 'edge_relation'],
    ['gt', 5, 5, 'edge_relation'], ['gt', 6, 5, null], ['gt', 4, 5, 'edge_relation'],
  ] as const)('%s: request %i against source %i -> %s', (op, val, src, code) => {
    expect(rel(op, val, src)).toBe(code);
  });
  it('eq compares the value digest; a missing source number is edge_value for an ordering', () => {
    const b = body();
    const w = signWorkflow(P, b);
    const a = rcpt(b, 'a', { out: wfOutput('x') });
    expect(adm(w, [a], req('b', { in: 'x' })).code).toBeNull();
    expect(adm(w, [a], req('b', { in: 'y' })).code).toBe('edge_digest');
    const b2 = body({ edges: [edge('a', 'b', 'le')] as never });
    expect(adm(signWorkflow(P, b2), [rcpt(b2, 'a', { out: wfOutput(5) })], req('b', { in: 5 })).code).toBe('edge_value');
  });
  it('a taint label on the source output named by the edge denies; an unrelated label does not', () => {
    const b = body({ edges: [edge('a', 'b', 'eq', { deny_labels: ['pii'] })] as never });
    const w = signWorkflow(P, b);
    expect(adm(w, [rcpt(b, 'a', { out: wfOutput('x', { labels: ['pii'] }) })], req('b', { in: 'x' })).code).toBe('taint_flow');
    expect(adm(w, [rcpt(b, 'a', { out: wfOutput('x', { labels: ['other'] }) })], req('b', { in: 'x' })).code).toBeNull();
  });
  it('the unit must match on both the receipt and the edge', () => {
    const b = body({ edges: [edge('a', 'b', 'le', { unit: 'usd' })] as never });
    const w = signWorkflow(P, b);
    const ok = rcpt(b, 'a', { out: wfOutput(5, { num: true, unit: 'usd' }) });
    expect(adm(w, [ok], req('b', { in: 5 }, { units: { in: 'usd' } })).code).toBeNull();
    expect(adm(w, [ok], req('b', { in: 5 }, { units: { in: 'eur' } })).code).toBe('edge_unit');
    expect(adm(w, [rcpt(b, 'a', { out: wfOutput(5, { num: true, unit: 'eur' }) })], req('b', { in: 5 }, { units: { in: 'usd' } })).code).toBe('edge_unit');
  });
});

describe('workflow: time, freshness and budget boundaries', () => {
  it('valid on [issued_at, expires_at): both edges', () => {
    const b = body();
    const w = signWorkflow(P, b);
    expect(adm(w, [], req('a', {}), b.issued_at).decision).toBe('allow');
    expect(adm(w, [], req('a', {}), b.issued_at - 1).code).toBe('not_yet');
    expect(adm(w, [], req('a', {}), b.expires_at - 1).decision).toBe('allow');
    expect(adm(w, [], req('a', {}), b.expires_at).code).toBe('expired');
  });
  it('fresh_ms: exactly fresh_ms old is fresh, one ms more is stale', () => {
    const b = body({ steps: [step('a'), step('b', ['a'], { fresh_ms: 100 })] });
    const w = signWorkflow(P, b);
    const a = rcpt(b, 'a', { out: wfOutput('x') }, { issuedAt: NOW - 100 });
    expect(adm(w, [a], req('b', { in: 'x' })).decision).toBe('allow');
    expect(adm(w, [a], req('b', { in: 'x' }), NOW + 1).code).toBe('stale_dep');
  });
  it('a failed dependency denies; max_steps and cost caps are inclusive', () => {
    const b = body();
    const w = signWorkflow(P, b);
    expect(adm(w, [rcpt(b, 'a', { out: wfOutput('x') }, { outcome: 'failed' })], req('b', { in: 'x' })).code).toBe('dep_failed');
    const b1 = body({ steps: [step('a', [], { cost: { c: 3 } }), step('b', ['a'], { cost: { c: 3 } })], edges: [], budget: { max_steps: 2, caps: { c: 6 } } });
    const w1 = signWorkflow(P, b1);
    expect(adm(w1, [rcpt(b1, 'a')], req('b', {})).decision).toBe('allow');
    const b2 = body({ steps: [step('a', [], { cost: { c: 3 } }), step('b', ['a'], { cost: { c: 3 } })], edges: [], budget: { max_steps: 2, caps: { c: 5 } } });
    expect(adm(signWorkflow(P, b2), [rcpt(b2, 'a')], req('b', {})).code).toBe('budget_exceeded');
    const b3 = body({ steps: [step('a'), step('b', ['a'])], edges: [], budget: { max_steps: 1, caps: {} } });
    expect(adm(signWorkflow(P, b3), [rcpt(b3, 'a')], req('b', {})).code).toBe('budget_exceeded');
  });
  it('a step with a committed params digest admits exactly those params', () => {
    const b = body({ steps: [step('a', [], { params_digest: hashCanonical({ x: 1 }) })], edges: [] });
    const w = signWorkflow(P, b);
    expect(adm(w, [], req('a', { x: 1 })).decision).toBe('allow');
    expect(adm(w, [], req('a', { x: 2 })).code).toBe('params_mismatch');
  });
  it('step-level taint: deny and escalate come from labels of any executed ancestor, not only a direct dependency', () => {
    const b = body({ steps: [step('a'), step('b', ['a']), step('c', ['b'], { deny_labels: ['secret'] }), step('d', ['b'], { escalate_labels: ['pii'] })], edges: [] });
    const w = signWorkflow(P, b);
    const a = rcpt(b, 'a', { out: wfOutput('x', { labels: ['secret'] }) });
    const bb = rcpt(b, 'b', {}, {}, a);
    expect(adm(w, [a, bb], req('c', {})).code).toBe('taint_flow');
    const a2 = rcpt(b, 'a', { out: wfOutput('x', { labels: ['pii'] }) });
    const b2 = rcpt(b, 'b', {}, {}, a2);
    const r = adm(w, [a2, b2], req('d', {}));
    expect(r).toEqual({ decision: 'escalate', code: 'taint_escalate', step: 'd', at: null, pending: [] });
  });
});

describe('workflow: promises and binding', () => {
  const b = body({ edges: [edge('a', 'b', 'eq', { promise: 'dom' })] as never });
  const w = signWorkflow(P, b);
  it('an edge with a promise admits ahead of the source and reports it pending', () => {
    expect(adm(w, [], req('b', { in: 'x' }))).toEqual({ decision: 'allow', code: null, step: 'b', at: null, pending: [0] });
  });
  it('bindPromises needs the step receipt, with the same params digest, and every edge satisfied', () => {
    const own = rcpt(b, 'b', {}, { paramsDigest: hashCanonical({ in: 'x' }) });
    const a = rcpt(b, 'a', { out: wfOutput('x') }, {}, own);
    const bind = (rs: unknown[], p: Record<string, string>) => bindPromises({ workflow: w, principal: PK, rsSigner: RSK, receipts: rs, now: NOW, request: req('b', p) });
    expect(bind([own, a], { in: 'x' }).code).toBeNull();
    expect(bind([own, a], { in: 'y' }).code).toBe('params_mismatch');
    expect(bind([own], { in: 'x' }).code).toBe('deps_unmet');
    expect(bind([rcpt(b, 'a', { out: wfOutput('x') })], { in: 'x' }).code).toBe('params_mismatch');
  });
  it('a receipt may precede its dependency only through a declared promise', () => {
    const plain = body();
    const wp = signWorkflow(P, plain);
    const early = rcpt(plain, 'b');
    expect(adm(wp, [early], req('a', {})).code).toBe('bad_receipt');
    const own = rcpt(b, 'b');
    expect(adm(w, [own], req('a', {})).code).toBeNull();
  });
});

describe('workflow: receipts, value digests and the plan root', () => {
  it('a receipt must be from this workflow, in sequence, linked, and not future-dated', () => {
    const b = body();
    const w = signWorkflow(P, b);
    const a = rcpt(b, 'a', { out: wfOutput('x') });
    expect(adm(w, [a], req('b', { in: 'x' })).code).toBeNull();
    expect(adm(w, [{ ...a, seq: 1, prev: D('z') }], req('b', { in: 'x' })).code).toBe('bad_receipt');
    expect(adm(w, [{ ...a, prev: D('z') }], req('b', { in: 'x' })).code).toBe('bad_receipt');
    expect(adm(w, [rcpt(b, 'a', {}, { issuedAt: NOW })], req('b', { in: 'x' })).code).not.toBe('bad_receipt');
    expect(adm(w, [rcpt(b, 'a', {}, { issuedAt: NOW + 1 })], req('b', { in: 'x' })).code).toBe('bad_receipt');
  });
  it('value digests are domain separated from params digests', () => {
    expect(valueDigest('x')).not.toBe(hashCanonical('x'));
    expect(valueDigest(1)).not.toBe(valueDigest('1'));
    expect(valueDigest(true)).not.toBe(valueDigest('true'));
  });
  it('planRootAuthorized needs the exact root, the pinned principal and the time window', () => {
    const b = body({ plan_root: D('root') });
    const w = signWorkflow(P, b);
    expect(planRootAuthorized(w, PK, NOW, D('root'))).toBe(true);
    expect(planRootAuthorized(w, PK, NOW, D('other'))).toBe(false);
    expect(planRootAuthorized(w, RSK, NOW, D('root'))).toBe(false);
    expect(planRootAuthorized(w, PK, b.expires_at, D('root'))).toBe(false);
    expect(planRootAuthorized(w, PK, b.issued_at, D('root'))).toBe(true);
    expect(planRootAuthorized(w, PK, b.issued_at - 1, D('root'))).toBe(false);
    expect(planRootAuthorized(signWorkflow(P, body()), PK, NOW, D('root'))).toBe(false);
  });
});

describe('readside: mask modes and boundaries', () => {
  const g = (modes: Record<string, string>, caps: Record<string, number> = {}, def = 'drop'): ReadGrantBody => ({
    v: 1, id: 'g', principal: PK, issued_at: NOW - 10, expires_at: NOW + 10,
    reads: [{ verb: 'get', resource_prefix: 'r/', purposes: ['p'], modes, default_mode: def }], caps, sinks: {},
  });
  const run = (grant: ReadGrantBody, record: Record<string, string | number | boolean>, o: Partial<ReadInput> = {}) =>
    redactRead({ grant: signReadGrant(P, grant), principal: PK, now: NOW, verb: 'get', resource: 'r/1', purpose: 'p', schema: { fields: Object.fromEntries(Object.keys(record).map((k) => [k, 'c'])), required: [] }, record, tighten: {}, salt: 'x'.repeat(16), counts: {}, ...o });
  it('last4: five characters mask, four drop; an astral character drops', () => {
    expect(run(g({ c: 'last4' }), { f: 'abcde' }).view).toEqual({ f: '****bcde' });
    expect(run(g({ c: 'last4' }), { f: 'abcd' }).view).toEqual({});
    expect(run(g({ c: 'last4' }), { f: 'abc\u{1F600}e' }).view).toEqual({});
    expect(run(g({ c: 'last4' }), { f: 12345 }).view).toEqual({});
  });
  it('bucket: rounds down, zero stays zero, negative drops, bucket:1 is the identity, bucket:0 is not a mode', () => {
    expect(run(g({ c: 'bucket:10' }), { f: 19 }).view).toEqual({ f: 10 });
    expect(run(g({ c: 'bucket:10' }), { f: 0 }).view).toEqual({ f: 0 });
    expect(run(g({ c: 'bucket:10' }), { f: -1 }).view).toEqual({});
    expect(run(g({ c: 'bucket:1' }), { f: 7 }).view).toEqual({ f: 7 });
    expect(run(g({ c: 'bucket:10' }), { f: 'x' }).view).toEqual({});
    expect(() => signReadGrant(P, g({ c: 'bucket:0' }))).toThrow('malformed grant');
    expect(() => signReadGrant(P, g({ c: 'bucket:01' }))).toThrow('malformed grant');
    expect(() => signReadGrant(P, g({ c: 'bucket:1234567890' }))).toThrow('malformed grant');
  });
  it('hash and token are salted; show passes the value through; drop removes it', () => {
    const a = run(g({ c: 'hash' }), { f: 'v' });
    const b = run(g({ c: 'hash' }), { f: 'v' }, { salt: 'y'.repeat(16) });
    expect(a.view.f).not.toBe(b.view.f);
    expect(String(run(g({ c: 'token' }), { f: 'v' }).view.f)).toMatch(/^tok_[A-Za-z0-9_-]{22}$/);
    expect(run(g({ c: 'show' }), { f: 'v' }).view).toEqual({ f: 'v' });
    expect(run(g({ c: 'drop' }, {}, 'show'), { f: 'v' }).view).toEqual({});
    expect(run(g({}, {}, 'show'), { f: 'v' }).view).toEqual({ f: 'v' });
  });
  it('tighten: equal rank is ignored, a stricter rank applies, a weaker one is ignored', () => {
    expect(run(g({ c: 'last4' }), { f: 'abcdef' }, { tighten: { c: 'last4' } }).view).toEqual({ f: '****cdef' });
    expect(run(g({ c: 'last4' }), { f: 'abcdef' }, { tighten: { c: 'show' } }).view).toEqual({ f: '****cdef' });
    expect(run(g({ c: 'last4' }), { f: 'abcdef' }, { tighten: { c: 'drop' } }).view).toEqual({});
    expect(run(g({ c: 'bucket:10' }), { f: 25 }, { tighten: { c: 'last4' } }).view).toEqual({ f: 20 });
    expect(run(g({ c: 'hash' }), { f: 'abcdef' }, { tighten: { c: 'token' } }).view.f).not.toMatch(/^tok_/);
  });
  it('salt: 16 characters pass, 15 deny', () => {
    expect(run(g({ c: 'show' }), { f: 'v' }, { salt: 'x'.repeat(16) }).decision).toBe('allow');
    expect(run(g({ c: 'show' }), { f: 'v' }, { salt: 'x'.repeat(15) })).toMatchObject({ decision: 'deny', code: 'bad_request' });
  });
  it('cap: reaching the cap allows, one over denies and reports the prior counts', () => {
    const grant = g({ c: 'show' }, { c: 2 });
    expect(run(grant, { f: 'a', h: 'b' })).toMatchObject({ decision: 'allow', counts: { c: 2 } });
    expect(run(grant, { f: 'a', h: 'b', i: 'c' })).toMatchObject({ decision: 'deny', code: 'read_cap', counts: {} });
    expect(run(grant, { f: 'a' }, { counts: { c: 1 } })).toMatchObject({ decision: 'allow', counts: { c: 2 } });
    expect(run(grant, { f: 'a' }, { counts: { c: 2 } })).toMatchObject({ decision: 'deny', code: 'read_cap', counts: { c: 2 } });
  });
  it('the grant window is [issued_at, expires_at)', () => {
    const grant = g({ c: 'show' });
    expect(run(grant, { f: 'a' }, { now: grant.issued_at }).decision).toBe('allow');
    expect(run(grant, { f: 'a' }, { now: grant.issued_at - 1 }).code).toBe('not_yet');
    expect(run(grant, { f: 'a' }, { now: grant.expires_at - 1 }).decision).toBe('allow');
    expect(run(grant, { f: 'a' }, { now: grant.expires_at }).code).toBe('expired');
  });
  it('prefix scope: the resource must start with the prefix, not merely contain it', () => {
    expect(run(g({ c: 'show' }), { f: 'a' }, { resource: 'r/' }).decision).toBe('allow');
    expect(run(g({ c: 'show' }), { f: 'a' }, { resource: 'xr/1' }).code).toBe('no_read_scope');
    expect(run(g({ c: 'show' }), { f: 'a' }, { resource: 'r' }).code).toBe('no_read_scope');
  });
});
