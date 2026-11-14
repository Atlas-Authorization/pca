/**
 * requirePCA paths pinned to exact outcomes: the atomic / durable state stores (claim, budget comparison, pins), the
 * default header / body readers, construction rules, the guard's context wiring (seed budget, operation fallback, risk
 * merge, revocation staleness, consistency token), the required-check lists, the provenance gate, escalation answers and
 * undo admissions, and the exact result shapes of allow / deny / escalate.
 */
import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { provEnvelopeError } from '../arg-provenance';
import { beaconRef, issueLivenessBeacon } from '../beacons';
import { type Capability } from '../capability';
import { mintGrant } from '../envelope';
import { escalationActionDigest, escalationHistoryHead, escalationPolicyDigest, signEscalationAnswer, type EscalationAnswerBody } from '../escalation';
import { signFreshAt, type FreshAtPolicy, type FreshAtState } from '../fresh-at';
import { b64u } from '../hash';
import { encodeKey, generateKeyPair, publicKeyOf } from '../keys';
import { paramsDigest, type PlanNode } from '../merkle';
import { buildPCActn, type PCActn } from '../pcactn';
import { RevocationSet, signRevocationEpoch } from '../revocation';
import { type RiskPolicy } from '../risk';
import {
  atomicMemoryPcaStore,
  decisionOfResult,
  defaultEscalationAnswer,
  defaultProvenanceBundle,
  durablePcaStateStore,
  isAtomicPcaStateStore,
  memoryPcaStore,
  pcaStateKey,
  presentedK1,
  requirePCA as requirePCA05,
  undoAdmissionError,
  type AtomicKv,
  type AtomicPcaStateStore,
  type PcaGuardResult,
  type PcaStateStore,
} from './require-pca';
import type { PcaOperation } from './verify';
import { AUD, NOW, setup } from './fixture.test-util';

type Opts = Parameters<typeof requirePCA05>[0];
const requirePCA = (o: Opts): ReturnType<typeof requirePCA05> => requirePCA05({ insecureAllowUnboundOperation: true, multiInstance: false, ...o }); // unbound and single-instance on purpose where a test is not about operation binding or store scope
const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
const settle = async <T>(f: () => Promise<T>): Promise<T | string> => {
  try {
    return await f();
  } catch (e) {
    return `THREW: ${(e as Error).message}`;
  }
};

const s = setup();
const revocation = () => ({ enforced: true as const, ok: true });
const base = () => ({
  resolveGrant: async (ref: string) => (ref === s.grant.id ? s.grant : null),
  now: () => NOW,
  audience: AUD,
  context: () => ({ plan: s.plan, planAuthorized: true, risk: s.lowRisk }),
  budgetStore: memoryPcaStore() as PcaStateStore,
  hooks: { revocation },
});
const body = (p: unknown, headers: Record<string, string> = {}) => ({ headers, body: { pcactn: p } });
const LIST: PcaOperation = { verb: 'list_sessions', resource: 'session:*', params: {} };

describe('atomic memory store: claim and the budget comparison', () => {
  const B = (b: number, tau = 1, asOf = 2) => ({ B: b, tau, asOf });
  it('a first claim stores only the counter; a second one with the same counter is a replay naming the stored counter', async () => {
    const st = atomicMemoryPcaStore();
    expect(await st.claim('k', { counter: 1 })).toEqual({ ok: true });
    expect(Object.keys((await st.get('k'))!)).toEqual(['lastCounter']);
    expect(await st.claim('k', { counter: 1 })).toStrictEqual({ ok: false, reason: 'replay', lastCounter: 1 });
  });
  it('stored budget absent and expected budget present is a conflict (never a throw)', async () => {
    const st = atomicMemoryPcaStore();
    expect(await settle(() => st.claim('k', { counter: 1, budgetBefore: B(5) }))).toStrictEqual({ ok: false, reason: 'conflict' });
  });
  it('stored budget present and expected budget absent is a conflict (never a throw)', async () => {
    const st = atomicMemoryPcaStore();
    await st.put('k', { budget: B(5) });
    expect(await settle(() => st.claim('k', { counter: 1 }))).toStrictEqual({ ok: false, reason: 'conflict' });
  });
  it('equal budgets held in distinct objects match; both absent match', async () => {
    const st = atomicMemoryPcaStore();
    await st.put('k', { budget: B(5) });
    expect(await settle(() => st.claim('k', { counter: 1, budgetBefore: B(5) }))).toStrictEqual({ ok: true });
    expect(await st.get('k')).toEqual({ budget: B(5), lastCounter: 1 });
    expect(await settle(() => st.claim('n', { counter: 1 }))).toStrictEqual({ ok: true });
  });
  it('budgets that differ only in B, only in tau or only in asOf are a conflict', async () => {
    for (const other of [B(6), B(5, 9), B(5, 1, 9)]) {
      const st = atomicMemoryPcaStore();
      await st.put('k', { budget: B(5) });
      expect(await settle(() => st.claim('k', { counter: 1, budgetBefore: other }))).toStrictEqual({ ok: false, reason: 'conflict' });
    }
  });
  it('raisePin never rewrites a pin to an equal or lower value, and raises a higher one', async () => {
    const st = atomicMemoryPcaStore();
    await st.put('p', { lastEpoch: 5 });
    const before = await st.get('p');
    await st.raisePin('p', 'lastEpoch', 5);
    expect(await st.get('p')).toBe(before);
    await st.raisePin('p', 'lastEpoch', 4);
    expect(await st.get('p')).toBe(before);
    await st.raisePin('p', 'lastEpoch', 6);
    expect(await st.get('p')).toEqual({ lastEpoch: 6 });
  });
  it('isAtomicPcaStateStore needs claim AND raisePin to be functions', () => {
    const fn = async () => undefined as never;
    expect(isAtomicPcaStateStore({ get: fn, put: fn, claim: 1, raisePin: fn } as never)).toBe(false);
    expect(isAtomicPcaStateStore({ get: fn, put: fn, claim: fn, raisePin: 1 } as never)).toBe(false);
    expect(isAtomicPcaStateStore({ get: fn, put: fn, claim: fn, raisePin: fn } as never)).toBe(true);
    expect(isAtomicPcaStateStore(undefined)).toBe(false);
  });
});

describe('durablePcaStateStore over an atomic key/value store', () => {
  const kv = (callFn = true) => {
    const m = new Map<string, unknown>();
    const store: AtomicKv = {
      get: async (k) => m.get(k),
      set: async (k, v) => void m.set(k, v),
      update: async (k, fn) => {
        if (!callFn) return undefined;
        const n = fn(m.get(k));
        if (n !== undefined) m.set(k, n);
        return n;
      },
    };
    return { m, store };
  };
  it('scope defaults to shared and keeps an explicit one', () => {
    expect(durablePcaStateStore(kv().store).scope).toBe('shared');
    expect(durablePcaStateStore(kv().store, { scope: 'process' }).scope).toBe('process');
  });
  it('put writes under the prefix (default and custom)', async () => {
    const a = kv();
    await durablePcaStateStore(a.store).put('g:h', { lastCounter: 3 });
    expect([...a.m.entries()]).toEqual([['pca-state:g:h', { lastCounter: 3 }]]);
    const b = kv();
    await durablePcaStateStore(b.store, { prefix: 'x/' }).put('g:h', { lastCounter: 4 });
    expect([...b.m.entries()]).toEqual([['x/g:h', { lastCounter: 4 }]]);
  });
  it('get returns only object values: null, a number and a string read as no state', async () => {
    const a = kv();
    const d = durablePcaStateStore(a.store);
    for (const v of [null, 5, 'str', true]) {
      a.m.set('pca-state:k', v);
      expect(await d.get('k')).toBeUndefined();
    }
    const st = { lastCounter: 9 };
    a.m.set('pca-state:k', st);
    expect(await d.get('k')).toBe(st);
  });
  it('a claim whose update never runs the function is a conflict', async () => {
    expect(await durablePcaStateStore(kv(false).store).claim('k', { counter: 1 })).toStrictEqual({ ok: false, reason: 'conflict' });
  });
  it('claim and raisePin go through update under the prefix', async () => {
    const a = kv();
    const d = durablePcaStateStore(a.store);
    expect(await d.claim('k', { counter: 2 })).toStrictEqual({ ok: true });
    expect(await d.claim('k', { counter: 2 })).toStrictEqual({ ok: false, reason: 'replay', lastCounter: 2 });
    await d.raisePin('k', 'lastBeaconSeq', 3);
    expect(a.m.get('pca-state:k')).toEqual({ lastCounter: 2, lastBeaconSeq: 3 });
  });
});

describe('default request readers', () => {
  it('PCA-Discharges that is not a JSON array throws its exact message', () => {
    expect(() => presentedK1({ headers: { 'pca-discharges': enc({ a: 1 }) } })).toThrow('PCA-Discharges must be a JSON array');
    expect(presentedK1({ headers: { 'pca-discharges': enc([1]) } })).toEqual({ discharges: [1] });
  });
  for (const [name, read, field, hdr] of [
    ['escalation answer', defaultEscalationAnswer, 'escalation_answer', 'pca-escalation-answer'],
    ['provenance bundle', defaultProvenanceBundle, 'pca_provenance', 'pca-provenance'],
  ] as const) {
    it(`${name}: header first, an empty header falls back to the body`, () => {
      expect(read({ headers: { [hdr]: enc({ h: 1 }) }, body: { [field]: 'b' } })).toEqual({ h: 1 });
      expect(read({ headers: { [hdr]: '' }, body: { [field]: 'from-body' } })).toBe('from-body');
      expect(read({ headers: {}, body: { [field]: 'from-body' } })).toBe('from-body');
    });
    it(`${name}: an object body is read as is; a string body is parsed strictly; an unparseable one is nothing`, () => {
      expect(read({ headers: {}, body: { [field]: { x: 1 } } })).toEqual({ x: 1 });
      expect(read({ headers: {}, body: JSON.stringify({ [field]: 5 }) })).toBe(5);
      expect(read({ headers: {}, body: '{not json' })).toBeUndefined();
    });
    it(`${name}: a missing or null body is nothing (never a throw)`, () => {
      expect(read({ headers: {} })).toBeUndefined();
      expect(read({ headers: {}, body: null })).toBeUndefined();
    });
  }
  it('decisionOfResult: allow, escalate, and deny for every other refusal', () => {
    expect(decisionOfResult({ ok: true })).toBe('allow');
    expect(decisionOfResult({ ok: false, decision: 'escalate' })).toBe('escalate');
    expect(decisionOfResult({ ok: false, decision: 'deny' })).toBe('deny');
    expect(decisionOfResult({ ok: false })).toBe('deny');
  });
  it('pcaStateKey: an audience-scoped key with no audience uses an empty audience', () => {
    expect(pcaStateKey('g', 'h', 'audience-grant-holder')).toBe('aud::g:h');
    expect(pcaStateKey('g', 'h')).toBe('g:h');
  });
});

describe('undoAdmissionError: each refusal by its exact reason', () => {
  const ok = { id: 'u1', window_end: 10, compensation: { verb: 'v' } };
  it('non-objects', () => {
    for (const a of [5, 'x', true, null, [], undefined]) expect(undoAdmissionError(a)).toBe('an admission must be an object');
  });
  it('id, window_end and compensation.verb', () => {
    expect(undoAdmissionError(ok)).toBeNull();
    for (const id of [5, '', 'i'.repeat(129)]) expect(undoAdmissionError({ ...ok, id })).toBe('admission id must be a non-empty string of at most 128 characters');
    for (const window_end of [-1, 1.5, -0, '3']) expect(undoAdmissionError({ ...ok, window_end })).toBe('admission window_end must be a non-negative safe integer');
    for (const compensation of [null, undefined, 5, [], {}, { verb: 5 }, { verb: '' }]) {
      let got: string | null | undefined;
      try {
        got = undoAdmissionError({ ...ok, compensation });
      } catch {
        got = undefined;
      }
      expect(got).toBe('admission compensation.verb must be a non-empty string');
    }
  });
});

describe('construction', () => {
  it('the intentV2 object is kept by reference (never enumerated at construction)', () => {
    let reads = 0;
    const intentV2 = {
      get probe() {
        reads++;
        return 1;
      },
    };
    requirePCA({ ...base(), intentV2: intentV2 as never });
    expect(reads).toBe(0);
  });
  it('multiInstance with no store at all is accepted (state mode none)', () => {
    const { budgetStore: _b, ...rest } = base();
    const g = requirePCA05({ ...rest, operation: () => LIST, multiInstance: true });
    expect(g.stateMode).toBe('none');
  });
  it('no audience is accepted under insecureAllowUnenforced when no replay scope is named', () => {
    const { audience: _a, ...rest } = base();
    expect(() => requirePCA05({ ...rest, insecureAllowUnenforced: true, multiInstance: false })).not.toThrow();
  });
});

describe('guard context wiring', () => {
  it('the grant-holder scope reads only its own key (no legacy lookup)', async () => {
    const inner = memoryPcaStore();
    const gets: string[] = [];
    const spy: PcaStateStore = { get: (k) => (gets.push(k), inner.get(k)), put: (k, v) => inner.put(k, v), scope: 'process' };
    const r = await requirePCA({ ...base(), budgetStore: spy, replayScope: 'grant-holder' })(body(s.mk(s.plan[0]!)));
    expect(r.ok).toBe(true);
    expect(gets).toEqual([`${s.grant.id}:${s.aPub}`]);
  });
  it('a context budget wins over seedBudget', async () => {
    const risk = { ...s.lowRisk, blastRadius: 0.5 };
    const g = requirePCA({ ...base(), context: () => ({ plan: s.plan, planAuthorized: true, risk, budget: { B: 1, tau: NOW, asOf: NOW } }), seedBudget: () => ({ B: 0, tau: NOW, asOf: NOW }) });
    expect((await g(body(s.mk(s.plan[0]!)))).ok).toBe(true);
  });
  it('an operation mapping that returns null binds the impossible operation {verb, resource} (seen by the risk source)', async () => {
    const seen: unknown[] = [];
    const r = await requirePCA05({ ...base(), multiInstance: false, operation: () => null, risk: (o) => (seen.push(o), undefined) })(body(s.mk(s.plan[0]!)));
    expect(r.ok).toBe(false);
    expect(seen).toHaveLength(1);
    expect(Object.keys(seen[0] as object)).toEqual(['verb', 'resource']);
  });
  it('revocation staleness on a PCActn without an action is a verdict, never a guard error', async () => {
    const { action: _a, ...noAction } = s.mk(s.plan[0]!);
    const r = await requirePCA({ ...base(), revocationStaleness: {}, extract: () => noAction as never })({ headers: {} });
    expect(r.ok).toBe(false);
    expect(!r.ok && r.status).toBe(401);
    expect(r.verdict.reasons.join('|')).not.toMatch(/guard error/);
  });
  it('a context epoch that names its own maxAgeMs keeps it (the class default does not override it)', async () => {
    const G = generateKeyPair();
    const set = new RevocationSet();
    const issued = NOW - 120_000;
    const epoch = signRevocationEpoch(G.secretKey, { instance_id: 'i', grant_ref: s.grant.id, epoch: 0, set_size: set.size, root: set.root, issued_at: issued, not_after: issued + 300_000 });
    const ctx = (maxAgeMs?: number) => () => ({ plan: s.plan, planAuthorized: true, risk: s.lowRisk, revocationEpoch: { epoch, guardianPublic: encodeKey(G.publicKey), ...(maxAgeMs !== undefined ? { maxAgeMs } : {}) } });
    const run = (maxAgeMs?: number) => requirePCA({ ...base(), insecureAllowUnenforced: true, revocationStaleness: { maxRevocationAgeMs: 60_000 }, context: ctx(maxAgeMs) })(body(s.mk(s.plan[0]!)));
    const own = await run(3_600_000);
    expect(own.verdict.checks.freshness).toBe('pass');
    expect(own.ok).toBe(true);
    const capped = await run();
    expect(capped.verdict.checks.freshness).toBe('fail');
  });
  it('without a plan the plan-root check fails with its own default-deny reason', async () => {
    const r = await requirePCA({ ...base(), context: () => ({ risk: s.lowRisk }) })(body(s.mk(s.plan[0]!)));
    expect(r.ok).toBe(false);
    expect(r.verdict.reasons).toContain('plan_root_authorized: default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)');
  });
  it('no assurance report unless asked for', async () => {
    const r = await requirePCA(base())(body(s.mk(s.plan[0]!)));
    expect(r.ok).toBe(true);
    expect(r.verdict.assurance).toBeUndefined();
  });
});

describe('risk merge (riskier of context and server per input)', () => {
  const rOf = async (ctxRisk: Record<string, number>, risk?: Record<string, number>) =>
    (await requirePCA({ ...base(), insecureAllowUnenforced: true, context: () => ({ plan: s.plan, planAuthorized: true, risk: ctxRisk as never }), ...(risk ? { risk: () => risk as never } : {}) })(body(s.mk(s.plan[0]!)))).verdict.r;
  it('the score is sensitive to the inputs used below', async () => {
    expect(await rOf({ ...s.lowRisk, blastRadius: 0.3 })).not.toBe(await rOf(s.lowRisk));
    expect(await rOf({ blastRadius: 0.3 })).not.toBe(await rOf({ ...s.lowRisk, blastRadius: 0.3 }));
  });
  it('context inputs the server does not name are kept', async () => {
    expect(await rOf(s.lowRisk, { blastRadius: 0.3 })).toBe(await rOf({ ...s.lowRisk, blastRadius: 0.3 }));
  });
  it('a non-finite server input is ignored', async () => {
    expect(await rOf(s.lowRisk, { blastRadius: Number.NaN })).toBe(await rOf(s.lowRisk));
  });
  it('a non-finite context input is replaced by the server value', async () => {
    expect(await rOf({ ...s.lowRisk, blastRadius: Number.NaN }, { blastRadius: 0.3 })).toBe(await rOf({ ...s.lowRisk, blastRadius: 0.3 }));
  });
});

describe('consistency token (fresh_at) read beside the PCActn', () => {
  const T = generateKeyPair();
  const S: FreshAtState = { revocation_epoch: 5, ledger_tree_size: 100, budget_version: 7, policy_revision: 3, policy_digest: 'pd3' };
  const token = signFreshAt(T.secretKey, 'inst_A', S, NOW - 1000);
  const policy = (extra: Partial<FreshAtPolicy> = {}): FreshAtPolicy => ({ signer: b64u(publicKeyOf(T.secretKey)), scope: 'inst_A', local: S, ...extra });
  const run = (freshAt: unknown, headers: Record<string, string>) => requirePCA({ ...base(), ...(freshAt !== undefined ? { freshAt: freshAt as never } : {}) })(body(s.mk(s.plan[0]!), headers));
  it('an object policy reads a valid header token: pass', async () => {
    const r = await run(policy(), { 'pca-fresh-at': JSON.stringify(token) });
    expect(r.verdict.checks.fresh_at).toBe('pass');
    expect(r.ok).toBe(true);
  });
  it('a function policy is called per request and reads the header token: pass', async () => {
    const r = await run(async () => policy(), { 'pca-fresh-at': JSON.stringify(token) });
    expect(r.verdict.checks.fresh_at).toBe('pass');
    expect(r.ok).toBe(true);
  });
  it('a policy and no header: no check reported, admitted', async () => {
    const r = await run(policy(), {});
    expect(r.verdict.checks.fresh_at).toBeUndefined();
    expect(r.ok).toBe(true);
  });
  it('an unparseable header token is a bad token (deny), never a missing one', async () => {
    const r = await run(policy(), { 'pca-fresh-at': 'not json' });
    expect(r.ok).toBe(false);
    expect(r.verdict.checks.fresh_at).toBe('fail');
    expect(r.verdict.reasons).toContain('fresh_at: bad_token');
  });
  it('a policy that already carries a token keeps it (the header is not read)', async () => {
    const r = await run(policy({ sideCarried: token }), { 'pca-fresh-at': 'not json' });
    expect(r.verdict.checks.fresh_at).toBe('pass');
    expect(r.ok).toBe(true);
  });
  it('no policy: the header is ignored', async () => {
    const r = await run(undefined, { 'pca-fresh-at': JSON.stringify(token) });
    expect(r.verdict.checks.fresh_at).toBeUndefined();
    expect(r.ok).toBe(true);
  });
});

describe('required-check lists', () => {
  it('a bound operation requires operation and params_digest; requireRiskInputs requires risk_inputs (absent ones fail by name)', async () => {
    const g = requirePCA05({ ...base(), multiInstance: false, operation: () => LIST, requireRiskInputs: ['taint'] });
    const r = await g(body({ ...s.mk(s.plan[0]!), extraneous: 1 }));
    expect(r.ok).toBe(false);
    expect(r.verdict.checks).toMatchObject({ operation: 'fail', params_digest: 'fail', risk_inputs: 'fail' });
    expect(r.verdict.reasons).toContain('risk_inputs: required check is absent (default-deny: not enforced by this resource server)');
    expect(r.verdict.reasons).toContain('params_digest: required check is absent (default-deny: not enforced by this resource server)');
    expect(r.verdict.reasons.filter((x) => x.startsWith(': '))).toEqual([]);
  });
  it('an operation without params leaves params_digest not-enforced, which the bound operation turns into a denial', async () => {
    const r = await requirePCA05({ ...base(), multiInstance: false, require: ['replay'], operation: () => ({ verb: LIST.verb, resource: LIST.resource }) })(body(s.mk(s.plan[0]!)));
    expect(r.ok).toBe(false);
    expect(r.verdict.checks.params_digest).toBe('fail');
    expect(r.verdict.reasons).toContain('params_digest: required check is not-enforced (default-deny: not enforced by this resource server)');
  });
  it('requireRiskInputs that are supplied admit (no unnamed required check)', async () => {
    const r = await requirePCA05({ ...base(), multiInstance: false, operation: () => LIST, requireRiskInputs: ['taint'] })(body(s.mk(s.plan[0]!)));
    expect(r.ok).toBe(true);
    expect(r.verdict.checks.risk_inputs).toBe('pass');
  });
});

describe('result shapes', () => {
  it('a policy denial is decision deny (403); an authentication failure is decision deny (401)', async () => {
    const r = await requirePCA(base())(body(s.mk({ ...s.plan[0]!, verb: 'delete_account' })));
    expect(r).toMatchObject({ ok: false, status: 403, decision: 'deny' });
    const a = await requirePCA(base())(body(s.mk(s.plan[0]!, { extra: { ver: 99 } })));
    expect(a).toMatchObject({ ok: false, status: 401, decision: 'deny' });
  });
  it('an admitted action (bound or not) is decision allow and carries no escalation or undo member', async () => {
    const un = await requirePCA(base())(body(s.mk(s.plan[0]!)));
    expect(un.ok).toBe(true);
    expect(un.ok && un.decision).toBe('allow');
    expect('escalation' in un).toBe(false);
    expect('undo' in un).toBe(false);
    const bound = await requirePCA05({ ...base(), multiInstance: false, operation: () => LIST })(body(s.mk(s.plan[0]!)));
    expect(bound.ok).toBe(true);
    expect(bound.ok && bound.decision).toBe('allow');
    expect(bound.ok && bound.operation?.verb).toBe('list_sessions');
    expect('escalation' in bound).toBe(false);
    expect('undo' in bound).toBe(false);
  });
});

describe('atomic state path', () => {
  const P = generateKeyPair();
  const issuer = encodeKey(P.publicKey);
  it('a passing beacon raises the beacon pin under <grant>:beacon', async () => {
    const st = atomicMemoryPcaStore();
    const b = issueLivenessBeacon({ issuerSecret: P.secretKey, instance: 'ins_1', scope: s.grant.id, seq: 3, issuedAt: NOW });
    const r = await requirePCA({ ...base(), budgetStore: st, beacon: async () => ({ beacon: b, issuers: [issuer], instance: 'ins_1' }) })(body(s.mk(s.plan[0]!, { beaconRef: beaconRef(b) })));
    expect(r.ok).toBe(true);
    expect(await st.get(`${s.grant.id}:beacon`)).toEqual({ lastBeaconSeq: 3 });
  });
  it('a freshness pass from the core gate with no signed epoch raises no epoch pin (and never errors)', async () => {
    const st = atomicMemoryPcaStore();
    const p = s.mk(s.plan[0]!, { extra: { freshness: { beacon_ref: 'anchor', epoch: NOW / 1000, accumulator_witness: '' } } });
    const r = await requirePCA({ ...base(), budgetStore: st, enforce: { freshness: { epochMs: 1000, maxAgeMs: 60_000 } } })(body(p));
    expect(r.verdict.checks.freshness).toBe('pass');
    expect(r.ok).toBe(true);
    expect(await st.get(`${s.grant.id}:epoch`)).toBeUndefined();
  });
  const refusing = (lastCounter?: number): AtomicPcaStateStore => ({
    scope: 'process',
    get: async () => undefined,
    put: async () => {},
    claim: async () => (lastCounter === undefined ? { ok: false, reason: 'replay' } : { ok: false, reason: 'replay', lastCounter }),
    raisePin: async () => {},
  });
  it('a refused claim with no stored counter: deny, allow false, "was already claimed"', async () => {
    const r = await requirePCA({ ...base(), budgetStore: refusing() })(body(s.mk(s.plan[0]!, { counter: 4 })));
    expect(r).toMatchObject({ ok: false, status: 403, decision: 'deny' });
    expect(r.verdict.allow).toBe(false);
    expect(r.verdict.checks.replay).toBe('fail');
    expect(r.verdict.reasons).toContain('replay: 4 was already claimed (replay)');
  });
  it('a refused claim naming the stored counter says so', async () => {
    const r = await requirePCA({ ...base(), budgetStore: refusing(9) })(body(s.mk(s.plan[0]!, { counter: 4 })));
    expect(r.verdict.allow).toBe(false);
    expect(r.verdict.reasons).toContain('replay: 4 is not greater than last seen 9 (replay)');
  });
});

describe('K1 inputs', () => {
  it('the function form of k1 is called and its inputs are used', async () => {
    const id = 'spiffe://acme.test/ns/prod/runtime';
    const w = setup({ taskCaveats: [{ type: 'spiffe_bound', spiffe_id: id }] });
    const g = requirePCA({ ...base(), resolveGrant: async () => w.grant, context: () => ({ plan: w.plan, planAuthorized: true, risk: w.lowRisk }), k1: async () => ({ spiffe_id: id }) });
    expect((await g(body(w.mk(w.plan[0]!)))).ok).toBe(true);
  });
  it('max_uses without a usesStore: deny with allow false', async () => {
    const w = setup({ taskCaveats: [{ type: 'max_uses', id: 'u', n: 2, until: NOW + 100_000 }] });
    const r = await requirePCA({ ...base(), resolveGrant: async () => w.grant, context: () => ({ plan: w.plan, planAuthorized: true, risk: w.lowRisk }), k1: {} })(body(w.mk(w.plan[0]!)));
    expect(r).toMatchObject({ ok: false, status: 403, decision: 'deny' });
    expect(r.verdict.allow).toBe(false);
    expect(r.verdict.checks.max_uses).toBe('fail');
  });
});

describe('provenance gate inside requirePCA', () => {
  const prov = (provenance: object, over: Partial<Opts> = {}) => requirePCA05({ ...base(), multiInstance: false, operation: () => LIST, provenance: provenance as never, ...over });
  const flow = (r: PcaGuardResult) => r.verdict.reasons.filter((x) => x.startsWith('provenance_flow:'));
  it('observed() gets the session named by the first receipt, else undefined', async () => {
    const cases: [unknown, unknown][] = [
      [undefined, undefined],
      [null, undefined],
      [{}, undefined],
      [{ receipts: [] }, undefined],
      [{ receipts: [{ session: 5 }] }, undefined],
      [{ receipts: [{ session: 'sess-1' }] }, 'sess-1'],
    ];
    for (const [bundle, want] of cases) {
      const got: unknown[] = [];
      await prov({ bundle: () => bundle, observed: (_p: unknown, _o: unknown, session: unknown) => (got.push(session), []) })(body(s.mk(s.plan[0]!)));
      expect(got).toEqual([want]);
      expect(got).toHaveLength(1);
    }
  });
  it('a grant whose provenance member is malformed fails the gate with the exact reason', async () => {
    const bad: Capability = { ...s.grant, caveats: s.grant.caveats.map((c) => (c.type === 'envelope' ? { ...c, provenance: { mode: 'bogus' } } : c)) } as Capability;
    const r = await prov({}, { resolveGrant: async () => bad })(body(s.mk(s.plan[0]!)));
    expect(r.verdict.checks.provenance_flow).toBe('fail');
    expect(flow(r)).toEqual([`provenance_flow: the grant's provenance member is malformed: ${provEnvelopeError({ mode: 'bogus' })}`]);
    expect(r.ok).toBe(false);
  });
  it('no bound operation, or one without a string verb or resource, fails closed', async () => {
    const want = ['provenance_flow: no operation is bound to this request (fail closed)'];
    const unbound = await requirePCA({ ...base(), provenance: {} })(body(s.mk(s.plan[0]!)));
    expect(unbound.verdict.checks.provenance_flow).toBe('fail');
    expect(flow(unbound)).toEqual(want);
    for (const op of [null, { verb: 5, resource: 'session:*', params: {} }, { verb: 'list_sessions', resource: 5, params: {} }]) {
      const r = await prov({}, { operation: () => op as never })(body(s.mk(s.plan[0]!)));
      expect(r.verdict.checks.provenance_flow).toBe('fail');
      expect(flow(r)).toEqual(want);
    }
  });
  it('a bundle reader that throws fails closed', async () => {
    const r = await prov({ bundle: () => { throw new Error('x'); } })(body(s.mk(s.plan[0]!)));
    expect(r.verdict.checks.provenance_flow).toBe('fail');
    expect(flow(r)).toEqual(['provenance_flow: the provenance bundle is unreadable (fail closed)']);
  });
  it('a principal plan or control commitment makes the choice trusted (no bundle needed for a call without arguments)', async () => {
    const none = await prov({ bundle: () => undefined })(body(s.mk(s.plan[0]!)));
    expect(none.verdict.checks.provenance_flow).toBe('fail');
    for (const flags of [{ plan: true }, { control: true }]) {
      const r = await prov({ bundle: () => undefined, principal: () => flags })(body(s.mk(s.plan[0]!)));
      expect(r.verdict.checks.provenance_flow).toBe('pass');
      expect(flow(r)).toEqual([]);
    }
  });
});

// ---- escalation and undo -----------------------------------------------------------------------------------------------
const PAY_AUD = 'payments-rs';
const VERB = 'payments.send';
const RES = 'payments';
const SPEND: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 };
const payOp = (amount: number): PcaOperation => ({ verb: VERB, resource: RES, params: { payee: 'acme', amount } });

function payWorld() {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const pPub = encodeKey(principal.publicKey);
  const grant: Capability = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: pPub,
    holder: encodeKey(holder.publicKey),
    goal: 'pay invoices',
    envelope: {
      predicates: [{ verb: [VERB], resource: '*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }],
      caveats: [],
      agent_binding: {},
      risk_policy: SPEND,
      tighten: [{ id: 'big_payment', when: { field: 'action.params.amount', op: 'gt', value: 50 }, signal: 'escalate' }],
    },
  }).grant;
  const node = (amount: number): PlanNode => ({ id: 'n1', verb: VERB, resource: RES, params_digest: paramsDigest(payOp(amount).params!), reversibility_class: 'irreversible' });
  const sign = (amount: number, counter = 1): PCActn => buildPCActn({ grant, chain: [grant], plan: [node(amount)], nodeId: 'n1', params: payOp(amount).params!, counter, signerSecret: holder.secretKey, aud: PAY_AUD, now: NOW });
  const answer = (p: PCActn, over: Partial<EscalationAnswerBody> = {}) =>
    signEscalationAnswer(
      { v: 1, kind: 'pca-escalation-answer', principal: pPub, policy_digest: escalationPolicyDigest(grant), action_digest: escalationActionDigest(p), history_head: escalationHistoryHead(undefined), decision: 'allow', iat: NOW, expires_at: NOW + 600_000, nonce: b64u(randomBytes(16)), ...over },
      principal.secretKey,
    );
  const guard = (amount: number, over: Partial<Opts> = {}) =>
    requirePCA05({
      audience: PAY_AUD,
      resolveGrant: async (ref) => (ref === grant.id ? grant : null),
      budgetStore: memoryPcaStore(),
      multiInstance: false,
      hooks: { revocation },
      now: () => NOW,
      seedBudget: (_g, now) => ({ B: SPEND.bMax, tau: now, asOf: now }),
      operation: () => payOp(amount),
      context: () => ({ plan: [node(amount)], planAuthorized: true, risk: { blastRadius: amount / 100, semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 } }),
      ...over,
    });
  return { grant, pPub, sign, answer, guard };
}
const lifted = (checks: Record<string, string>) => Object.fromEntries(Object.entries(checks).map(([k, v]) => [k, v === 'fail' ? 'pass' : v]));
const escReasons = (r: PcaGuardResult) => r.verdict.reasons.filter((x) => x.startsWith('escalation:'));
const ADM = { id: 'undo-1', window_end: NOW + 60_000, compensation: { verb: 'payments.refund' } };

describe('escalation inside requirePCA', () => {
  it('baseline: above the tighten threshold the decision is escalate, with failing and not-enforced checks', async () => {
    const w = payWorld();
    const r0 = await w.guard(70)(body(w.sign(70)));
    expect(r0).toMatchObject({ ok: false, status: 403, decision: 'escalate' });
    expect(Object.values(r0.verdict.checks)).toContain('fail');
    expect(Object.values(r0.verdict.checks)).toContain('not-enforced');
  });
  it('the request carries the configured TTL', async () => {
    const w = payWorld();
    const r = await w.guard(70, { escalation: { principals: [w.pPub], requestTtlMs: 1000 } })(body(w.sign(70)));
    expect(!r.ok && r.escalation?.expires_at).toBe(NOW + 1000);
    const d = await w.guard(70, { escalation: { principals: [w.pPub] } })(body(w.sign(70)));
    expect(!d.ok && d.escalation?.expires_at).toBe(NOW + 3_600_000);
  });
  it('an allow answer lifts exactly the failing checks to pass, adds escalation pass and names the principal (8 chars)', async () => {
    const w = payWorld();
    const p = w.sign(70);
    const r0 = await w.guard(70)(body(p));
    const r1 = await w.guard(70, { escalation: { principals: [w.pPub], insecureUnboundApproval: true, answer: () => w.answer(p) } })(body(p));
    expect(r1.ok).toBe(true);
    expect(r1.verdict.checks).toEqual({ ...lifted(r0.verdict.checks), escalation: 'pass' });
    expect(escReasons(r1)).toEqual([`escalation: answered allow by principal ${w.pPub.slice(0, 8)}`]);
    expect(r1.ok && r1.escalation).toEqual({ answered_by: w.pPub });
  });
  it('a deny answer stays escalate with the exact reason', async () => {
    const w = payWorld();
    const p = w.sign(70);
    const r = await w.guard(70, { escalation: { principals: [w.pPub], insecureUnboundApproval: true, answer: () => w.answer(p, { decision: 'deny' }) } })(body(p));
    expect(r.ok).toBe(false);
    expect(escReasons(r)).toEqual(['escalation: the principal answered deny']);
  });
  it('no answer (undefined or null), bound or unbound approval: no escalation reason at all', async () => {
    const w = payWorld();
    for (const insecureUnboundApproval of [false, true]) {
      for (const answer of [undefined, () => null, () => undefined]) {
        const r = await w.guard(70, { escalation: { principals: [w.pPub], insecureUnboundApproval, ...(answer ? { answer } : {}) } })(body(w.sign(70)));
        expect(decisionOfResult(r)).toBe('escalate');
        expect(escReasons(r)).toEqual([]);
      }
    }
  });
});

describe('undo admission inside requirePCA', () => {
  it('an unanswered escalation with a valid admission runs under the window: failing checks lifted, undo_window pass', async () => {
    const w = payWorld();
    const p = w.sign(70);
    const r0 = await w.guard(70)(body(p));
    const r = await w.guard(70, { undo: { admit: async () => ADM as never } })(body(p));
    expect(r.ok).toBe(true);
    expect(r.ok && r.undo).toEqual(ADM);
    expect(r.verdict.checks).toEqual({ ...lifted(r0.verdict.checks), undo_window: 'pass' });
  });
  it('an absent (undefined or null) answer counts as no answer: the window still applies', async () => {
    const w = payWorld();
    for (const answer of [undefined, () => null]) {
      const r = await w.guard(70, { undo: { admit: async () => ADM as never }, escalation: { principals: [w.pPub], ...(answer ? { answer } : {}) } })(body(w.sign(70)));
      expect(r.ok).toBe(true);
      expect(r.ok && r.undo).toEqual(ADM);
      expect(escReasons(r)).toEqual([]);
    }
  });
  it('a malformed admission is no admission: the escalation stands', async () => {
    const w = payWorld();
    for (const adm of [{ ...ADM, id: '' }, { ...ADM, compensation: { verb: '' } }]) {
      const r = await w.guard(70, { undo: { admit: async () => adm as never } })(body(w.sign(70)));
      expect(r).toMatchObject({ ok: false, decision: 'escalate' });
      expect(r.verdict.checks.undo_window).toBeUndefined();
    }
  });
});
