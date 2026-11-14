/** Exact-outcome tests for the workflow shape checks, the commitment and receipt-chain helpers, and the admission edge cases. */
import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical } from './hash';
import { publicKeyOf } from './keys';
import {
  LABEL_RE, WF_RECEIPT_DOMAIN, WORKFLOW_DOMAIN, admitStep, ancestors, bindPromises, isScalarMap, isStr, onlyKeys, planRootAuthorized, signBody, signStepReceipt,
  signWorkflow, sortedUnique, validWorkflowBody, valueDigest, verifyBody, wfOutput, workflowCommitmentError, workflowReceiptError,
  type AdmitInput, type EdgeOp, type WfReceipt, type WorkflowBody,
} from './workflow';

const P = new Uint8Array(32).fill(91);
const RS = new Uint8Array(32).fill(92);
const PK = b64u(publicKeyOf(P));
const RSK = b64u(publicKeyOf(RS));
const NOW = 1_800_000_000_000;
const D = (s: string) => hashCanonical({ v: s });
const step = (id: string, deps: string[] = [], o: Record<string, unknown> = {}) => ({ id, verb: 'v', resource: 'r', params_digest: null, deps, sink: null, deny_labels: [], escalate_labels: [], fresh_ms: null, cost: {}, ...o });
const edge = (f: string, t: string, op: EdgeOp = 'eq', o: Record<string, unknown> = {}) => ({ from: { step: f, field: 'out' }, to: { step: t, param: 'in' }, op, unit: null, deny_labels: [], promise: null, ...o });
const body = (o: Partial<WorkflowBody> = {}): WorkflowBody =>
  ({ v: 1, id: 'w', principal: PK, goal_digest: null, plan_root: null, issued_at: NOW - 10, expires_at: NOW + 10, steps: [step('a'), step('b', ['a'])], edges: [edge('a', 'b')], budget: { max_steps: 5, caps: {} }, ...o }) as WorkflowBody;
const req = (s: string, params: Record<string, string | number | boolean>, o: Record<string, unknown> = {}) => ({ step: s, verb: 'v', resource: 'r', params, units: {}, goal_digest: null, plan_root: null, ...o });
const input = (workflow: unknown, receipts: unknown[], request: unknown, o: Partial<AdmitInput> = {}): AdmitInput => ({ workflow, principal: PK, rsSigner: RSK, receipts, now: NOW, request, ...o });
const rcpt = (w: WorkflowBody, s: string, outputs = {}, o: Record<string, unknown> = {}, prev?: WfReceipt) =>
  signStepReceipt(RS, { workflow: w, step: s, outcome: 'ok', paramsDigest: D('p'), outputs, issuedAt: NOW - 1, ...(prev ? { prev } : {}), ...o } as never);
/** A receipt with `o` applied to its body and a fresh, valid resource-server signature over the result. */
const forge = (r: WfReceipt, o: Record<string, unknown>): unknown => {
  const nb: Record<string, unknown> = { ...r, ...o };
  delete nb.sig;
  return { ...nb, sig: signBody(RS, WF_RECEIPT_DOMAIN, nb) };
};
const denyOf = (code: string, s: string | null = null, at: number | null = null) => ({ decision: 'deny', code, step: s, at, pending: [] });

describe('workflow helpers', () => {
  it('isStr needs a real string', () => {
    expect(isStr(['a'], 10)).toBe(false);
    expect(isStr('a', 10)).toBe(true);
  });
  it('sortedUnique rejects non-string members even when their text would match', () => {
    expect(sortedUnique([1], LABEL_RE, 16)).toBe(false);
    expect(sortedUnique([null], LABEL_RE, 16)).toBe(false);
    expect(sortedUnique(['a'], LABEL_RE, 16)).toBe(true);
  });
  it('onlyKeys needs every listed key, not just the count', () => {
    expect(onlyKeys({ a: 1, c: 1 }, ['a', 'b'])).toBe(false);
    expect(onlyKeys({ a: 1, b: 1 }, ['a', 'b'])).toBe(true);
  });
  it('verifyBody is false (not undefined) when the body cannot be canonicalized', () => {
    expect(verifyBody(WORKFLOW_DOMAIN, { x: -0 }, PK, signBody(P, WORKFLOW_DOMAIN, { x: 0 }))).toBe(false);
    expect(verifyBody(WORKFLOW_DOMAIN, { x: 0 }, PK, signBody(P, WORKFLOW_DOMAIN, { x: 0 }))).toBe(true);
  });
  it('isScalarMap: objects only, at most 32 entries', () => {
    expect(isScalarMap('ab')).toBe(false);
    expect(isScalarMap(['a'])).toBe(false);
    const m = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, i]));
    expect(isScalarMap(m(32))).toBe(true);
    expect(isScalarMap(m(33))).toBe(false);
  });
  it('wfOutput carries num only for numbers and sorts labels', () => {
    expect(wfOutput('x', { num: true })).toEqual({ digest: valueDigest('x'), num: null, unit: null, labels: [] });
    expect(wfOutput(5, { num: true, labels: ['b', 'a'] })).toEqual({ digest: valueDigest(5), num: 5, unit: null, labels: ['a', 'b'] });
  });
  it('ancestors visits every step exactly once', () => {
    const reads: Record<string, number> = { a: 0, b: 0, c: 0 };
    const counted = (id: string, deps: string[]) => {
      const s = step(id, deps);
      Object.defineProperty(s, 'deps', { get: () => { reads[id] = (reads[id] ?? 0) + 1; return deps; } });
      return s;
    };
    const anc = ancestors(body({ steps: [counted('a', []), counted('b', ['a']), counted('c', ['a', 'b'])], edges: [] }));
    expect(reads).toEqual({ a: 1, b: 1, c: 1 });
    expect(anc?.get('c')).toEqual(new Set(['a', 'b']));
  });
});

describe('workflow body shape: each check on its own', () => {
  const one = (o: Record<string, unknown>) => validWorkflowBody(body({ steps: [step('a', [], o)], edges: [] }));
  it('a step with an unknown key is refused', () => {
    expect(one({})).toBe(true);
    expect(one({ extra: 1 })).toBe(false);
    expect(validWorkflowBody({ ...body(), id: 123 })).toBe(false);
  });
  it.each([
    ['id', { id: 'bad space' }], ['id', { id: 123 }], ['verb', { verb: '' }], ['verb', { verb: 'v'.repeat(129) }], ['resource', { resource: '' }],
    ['resource', { resource: 'r'.repeat(513) }], ['params_digest', { params_digest: 'x' }], ['deps', { deps: ['b', 'a'] }], ['sink', { sink: 'bad space' }],
    ['deny_labels', { deny_labels: ['B'] }], ['escalate_labels', { escalate_labels: ['B'] }], ['fresh_ms', { fresh_ms: -1 }],
  ] as const)('step %s alone invalid -> refused', (_, o) => {
    expect(one(o)).toBe(false);
  });
  it('verb 128 and resource 512 characters are valid', () => {
    expect(one({ verb: 'v'.repeat(128), resource: 'r'.repeat(512) })).toBe(true);
  });
  it('step cost and budget caps need valid names and non-negative integers', () => {
    expect(validWorkflowBody(body({ steps: [step('a', [], { cost: { c: -1 } })], edges: [], budget: { max_steps: 1, caps: { c: 5 } } }))).toBe(false);
    expect(validWorkflowBody(body({ budget: { max_steps: 1, caps: { 'bad space': 5 } } }))).toBe(false);
    expect(validWorkflowBody(body({ budget: { max_steps: 1, caps: { c: -1 } } }))).toBe(false);
    expect(validWorkflowBody(body({ budget: { max_steps: 1, caps: { c: 5 } } }))).toBe(true);
  });
  it('a budget with an unknown key or not an object is refused', () => {
    expect(validWorkflowBody(body({ budget: { max_steps: 1, caps: {}, extra: 1 } as never }))).toBe(false);
    expect(validWorkflowBody(body({ budget: null as never }))).toBe(false);
  });
  const ed = (o: Record<string, unknown>) => validWorkflowBody(body({ edges: [{ ...edge('a', 'b'), ...o }] as never }));
  it('an edge with an unknown key is refused', () => {
    expect(ed({})).toBe(true);
    expect(ed({ extra: 1 })).toBe(false);
  });
  it.each([
    ['from not an object', { from: Object.assign([], { step: 'a', field: 'out' }) }],
    ['from extra key', { from: { step: 'a', field: 'out', x: 1 } }],
    ['from.step', { from: { step: 'bad space', field: 'out' } }],
    ['from.field text', { from: { step: 'a', field: 'bad space' } }],
    ['from.field number', { from: { step: 'a', field: 123 } }],
    ['to not an object', { to: Object.assign([], { step: 'b', param: 'in' }) }],
    ['to extra key', { to: { step: 'b', param: 'in', x: 1 } }],
    ['to.step', { to: { step: 'bad space', param: 'in' } }],
    ['to.param text', { to: { step: 'b', param: 'bad space' } }],
    ['to.param number', { to: { step: 'b', param: 123 } }],
    ['op', { op: 'ne' }],
    ['unit too long', { unit: 'u'.repeat(17) }],
    ['unit number', { unit: 123 }],
    ['deny_labels', { deny_labels: ['B'] }],
    ['promise', { promise: 'bad space' }],
  ] as const)('edge %s alone invalid -> refused', (_, o) => {
    expect(ed(o)).toBe(false);
  });
});

describe('workflowCommitmentError', () => {
  const b = body();
  const sw = signWorkflow(P, b);
  it('a valid commitment is null on [issued_at, expires_at)', () => {
    expect(workflowCommitmentError(sw, PK, NOW)).toBeNull();
    expect(workflowCommitmentError(sw, PK, b.issued_at)).toBeNull();
    expect(workflowCommitmentError(sw, PK, b.issued_at - 1)).toBe('not_yet');
    expect(workflowCommitmentError(sw, PK, b.expires_at - 1)).toBeNull();
    expect(workflowCommitmentError(sw, PK, b.expires_at)).toBe('expired');
  });
  it('malformed input is bad_workflow, each check on its own', () => {
    expect(workflowCommitmentError(null, PK, NOW)).toBe('bad_workflow');
    expect(workflowCommitmentError({ ...sw, x: 1 }, PK, NOW)).toBe('bad_workflow');
    expect(workflowCommitmentError({ body: b }, PK, NOW)).toBe('bad_workflow');
    expect(workflowCommitmentError({ body: { ...b, v: 2 }, sig: sw.sig }, PK, NOW)).toBe('bad_workflow');
    expect(workflowCommitmentError(sw, 'x', NOW)).toBe('bad_workflow');
    expect(workflowCommitmentError(sw, PK, NOW + 0.5)).toBe('bad_workflow');
    expect(workflowCommitmentError(sw, PK, -1)).toBe('bad_workflow');
  });
  it('a cyclic body is bad_dag', () => {
    const cb = body({ steps: [step('a', ['b']), step('b', ['a'])], edges: [] });
    expect(workflowCommitmentError({ body: cb, sig: signBody(P, WORKFLOW_DOMAIN, cb) }, PK, NOW)).toBe('bad_dag');
  });
  it('the body principal must be the pinned key and the signature must verify', () => {
    const other = { body: b, sig: signBody(RS, WORKFLOW_DOMAIN, b) };
    expect(workflowCommitmentError(other, RSK, NOW)).toBe('bad_signature');
    expect(workflowCommitmentError(other, PK, NOW)).toBe('bad_signature');
    expect(workflowCommitmentError({ body: b, sig: signBody(P, 'atlas-pca/workflow/v2\0', b) }, PK, NOW)).toBe('bad_signature');
  });
});

describe('planRootAuthorized: hostile and mis-pinned input', () => {
  it('non-objects and malformed bodies are false, never a throw', () => {
    expect(planRootAuthorized(null, PK, NOW, D('root'))).toBe(false);
    expect(planRootAuthorized({ body: {}, sig: 'x' }, PK, NOW, D('root'))).toBe(false);
  });
  it('a body naming another principal is false even when the pinned key signed it', () => {
    const b = body({ plan_root: D('root') });
    expect(planRootAuthorized({ body: b, sig: signBody(RS, WORKFLOW_DOMAIN, b) }, RSK, NOW, D('root'))).toBe(false);
  });
});

describe('workflowReceiptError: each receipt check on its own', () => {
  const b = body();
  const a = rcpt(b, 'a', { out: wfOutput('x') });
  const chk = (rs: unknown[]) => workflowReceiptError(b, RSK, rs, NOW);
  it('a valid receipt passes', () => {
    expect(chk([a])).toBeNull();
  });
  it.each([
    ['an unknown key', { ...a, x: 1 }],
    ['version 2', forge(a, { v: 2 })],
    ['an unknown outcome', forge(a, { outcome: 'maybe' })],
    ['a malformed params digest', forge(a, { params_digest: 'x' })],
    ['a non-integer issued_at', forge(a, { issued_at: 'x' })],
    ['a signer field that is not the pinned key', forge(a, { signer: PK })],
    ['an output name that is not a name', forge(a, { outputs: { 'bad space': wfOutput('x') } })],
    ['an output with an unknown key', forge(a, { outputs: { out: { ...wfOutput('x'), x: 1 } } })],
    ['an output digest that is not a digest', forge(a, { outputs: { out: { ...wfOutput('x'), digest: 'x' } } })],
    ['an output num that is not an integer', forge(a, { outputs: { out: { ...wfOutput('x'), num: 'x' } } })],
    ['an output unit that is too long', forge(a, { outputs: { out: { ...wfOutput('x'), unit: 'u'.repeat(17) } } })],
    ['output labels that are not labels', forge(a, { outputs: { out: { ...wfOutput('x'), labels: ['B'] } } })],
  ])('%s -> at 0', (_, r) => {
    expect(chk([r])).toEqual({ at: 0 });
  });
  it('outputs: 32 entries pass, 33 are refused', () => {
    const outs = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`o${i}`, wfOutput(i)]));
    expect(chk([forge(a, { outputs: outs(32) })])).toBeNull();
    expect(chk([forge(a, { outputs: outs(33) })])).toEqual({ at: 0 });
  });
  it('the second receipt must carry seq 1 and link the first', () => {
    const second = rcpt(b, 'b', {}, {}, a);
    expect(chk([a, second])).toBeNull();
    expect(chk([a, forge(second, { seq: 2 })])).toEqual({ at: 1 });
    expect(chk([a, forge(second, { prev: D('z') })])).toEqual({ at: 1 });
  });
  it('a receipt ahead of a dependency with no edge from it is refused', () => {
    const w = body({ edges: [] });
    expect(workflowReceiptError(w, RSK, [rcpt(w, 'b')], NOW)).toEqual({ at: 0 });
  });
  it('a receipt ahead of a dependency needs every edge from it to be a promise', () => {
    const w = body({ edges: [edge('a', 'b', 'eq', { promise: 'dom' }), { ...edge('a', 'b'), from: { step: 'a', field: 'out2' }, to: { step: 'b', param: 'in2' } }] as never });
    expect(workflowReceiptError(w, RSK, [rcpt(w, 'b')], NOW)).toEqual({ at: 0 });
  });
  it('only edges from the missing dependency count', () => {
    const w = body({ steps: [step('a'), step('c'), step('b', ['a', 'c'])], edges: [edge('a', 'b', 'eq', { promise: 'dom' }), edge('c', 'b')] as never });
    const c = rcpt(w, 'c');
    expect(workflowReceiptError(w, RSK, [c, rcpt(w, 'b', {}, {}, c)], NOW)).toBeNull();
  });
});

describe('admitStep / bindPromises: remaining paths, exact results', () => {
  const b = body();
  const sw = signWorkflow(P, b);
  it('a signed workflow with an unknown top-level key is bad_workflow', () => {
    expect(admitStep(input(sw, [], req('a', {})))).toEqual({ decision: 'allow', code: null, step: 'a', at: null, pending: [] });
    expect(admitStep(input({ ...sw, x: 1 }, [], req('a', {})))).toEqual(denyOf('bad_workflow'));
  });
  it('a body naming another principal is bad_signature even when the pinned key signed it', () => {
    expect(admitStep(input({ body: b, sig: signBody(RS, WORKFLOW_DOMAIN, b) }, [], req('a', {}), { principal: RSK }))).toEqual(denyOf('bad_signature', 'a'));
  });
  it('request units need valid names and units', () => {
    expect(admitStep(input(sw, [], req('a', {}, { units: { 'bad space': 'usd' } })))).toEqual(denyOf('bad_workflow'));
    expect(admitStep(input(sw, [], req('a', {}, { units: { u: 'u'.repeat(17) } })))).toEqual(denyOf('bad_workflow'));
  });
  it('a missing source output is edge_missing', () => {
    expect(admitStep(input(sw, [rcpt(b, 'a', {})], req('b', { in: 'x' })))).toEqual(denyOf('edge_missing', 'b', 0));
  });
  it('a unit on the source output with a unitless edge is edge_unit', () => {
    expect(admitStep(input(sw, [rcpt(b, 'a', { out: wfOutput('x', { unit: 'usd' }) })], req('b', { in: 'x' }, { units: { in: 'usd' } })))).toEqual(denyOf('edge_unit', 'b', 0));
  });
  it('one unpromised edge among promised ones escalates', () => {
    const w = body({ edges: [edge('a', 'b', 'eq', { promise: 'dom' }), { ...edge('a', 'b'), from: { step: 'a', field: 'out2' }, to: { step: 'b', param: 'in2' } }] as never });
    expect(admitStep(input(signWorkflow(P, w), [], req('b', { in: 'x', in2: 'y' })))).toEqual({ decision: 'escalate', code: 'pipeline_unconstrained', step: 'b', at: null, pending: [] });
  });
  it('binding with an edge from a transitive ancestor that has no receipt is deps_unmet', () => {
    const w = body({ steps: [step('a'), step('b', ['a']), step('c', ['b'])], edges: [edge('a', 'b', 'eq', { promise: 'dom' }), edge('a', 'c')] as never });
    const rb = rcpt(w, 'b');
    const rc = rcpt(w, 'c', {}, { paramsDigest: hashCanonical({ in: 'x' }) }, rb);
    expect(bindPromises(input(signWorkflow(P, w), [rb, rc], req('c', { in: 'x' })))).toEqual(denyOf('deps_unmet', 'c'));
  });
  it('an input that throws while being read is bad_workflow, never a throw', () => {
    const hostile = { get workflow(): unknown { throw new Error('boom'); }, principal: PK, rsSigner: RSK, receipts: [], now: NOW, request: req('a', {}) } as AdmitInput;
    expect(admitStep(hostile)).toEqual(denyOf('bad_workflow'));
    expect(bindPromises(hostile)).toEqual(denyOf('bad_workflow'));
  });
});
