import { describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { type Capability } from '../capability';
import { mintGrant } from '../envelope';
import { b64u } from '../hash';
import { encodeKey, generateKeyPair } from '../keys';
import { paramsDigest, type PlanNode } from '../merkle';
import { buildPCActn, pcactnDigest, type PCActn } from '../pcactn';
import { type RiskPolicy } from '../risk';
import { escalationActionDigest, escalationHistoryHead, escalationPolicyDigest, signEscalationAnswer } from '../escalation';
import { pepObligationGate } from '../obligations';
import { MemoryUndoStore, UndoError, decodeUndoToken, encodeUndoToken, undoReceiptChainError, type UndoToken } from '../undo';
import { createAuthorizer, type AuthorizeOptions } from './authorize';
import { memoryPcaStore } from './require-pca';
import { memoryOperationStore, type OperationStore } from './operations';
import { UNDO_RELAY_GRACE_MS, createUndoCoordinator, hostedUndoVetoRelay, missingUndoComponents, reportUndoEffect, undoNotifierFromDispatcher, type UndoAlert, type UndoCompensationCall, type UndoCoordinatorOptions, type UndoEngine, type UndoNotice, type UndoPolicy } from './undo';
import { createApprovalDispatcher, type ApprovalChannel } from '../approval-channels';
import type { PcaOperation } from './verify';

const NOW = Date.UTC(2026, 9, 28, 12, 0, 0);
const AUD = 'drafts-rs';
const VERB = 'drafts.create';
const COMP = 'drafts.delete';
const PUBLISH = 'drafts.publish';
const RES = 'drafts:box1';
const POLICY: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 };
const D1 = 'A'.repeat(43);
const D2 = 'B'.repeat(43);

/** A stub engine: VERB is confirmed reversible (compensated by COMP with the target from the result); PUBLISH is not. */
const engine: UndoEngine = {
  plan: (op) => (op.verb === VERB ? { def_digest: D1, compensation: { verb: COMP, params: { box: op.params?.box }, def_digest: D2, target_param: 'draft' } } : null),
};

function setup(o: { compPermitted?: boolean; extraPred?: unknown[] } = {}) {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const pPub = encodeKey(principal.publicKey);
  const grant: Capability = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: pPub,
    holder: encodeKey(holder.publicKey),
    goal: 'manage drafts',
    envelope: {
      predicates: [
        { verb: [VERB, PUBLISH], resource: '*', where: [{ field: 'action.params.size', op: 'lte', value: 100 }] },
        ...(o.compPermitted === false ? [] : [{ verb: [COMP], resource: '*' }]),
        ...((o.extraPred ?? []) as never[]),
      ],
      caveats: [],
      agent_binding: {},
      risk_policy: POLICY,
      tighten: [{ id: 'big', when: { field: 'action.params.size', op: 'gt', value: 10 }, signal: 'escalate' }],
    },
  }).grant;
  let counter = 0;
  const sign = (verb: string, params: Record<string, unknown>, cls = 'reversible'): PCActn => {
    const node: PlanNode = { id: 'n1', verb, resource: RES, params_digest: paramsDigest(params), reversibility_class: cls as PlanNode['reversibility_class'] };
    return buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params, counter: ++counter, signerSecret: holder.secretKey, aud: AUD, now: NOW });
  };
  return { grant, sign, pPub, principal };
}

const op = (size: number, verb = VERB): PcaOperation => ({ verb, resource: RES, params: { box: 'box1', size } });

function harness(grant: Capability, over: Partial<UndoCoordinatorOptions> & { deliver?: boolean; policy?: UndoCoordinatorOptions['policy']; fail?: () => boolean } = {}) {
  const clock = { t: NOW };
  const notices: UndoNotice[] = [];
  const alerts: UndoAlert[] = [];
  const calls: UndoCompensationCall[] = [];
  const store = new MemoryUndoStore();
  const operations: OperationStore = memoryOperationStore();
  const signer = new Uint8Array(randomBytes(32));
  const opts: UndoCoordinatorOptions = {
    store,
    engine,
    signerSecret: signer,
    audience: AUD,
    resolveGrant: async (ref) => (ref === grant.id ? grant : null),
    compensate: async (c) => {
      calls.push(c);
      if (over.fail?.()) throw new Error('downstream refused');
      return { deleted: c.operation.params?.draft };
    },
    operations,
    notifier: { notify: async (n) => (notices.push(n), over.deliver === false ? { delivered: false, reason: 'channel down' } : { delivered: true }) },
    alert: (a) => void alerts.push(a),
    now: () => clock.t,
    insecureVolatileStore: true,
    ...over,
  };
  const undo = createUndoCoordinator(opts);
  return { undo, clock, notices, alerts, calls, store, operations, signer };
}

const azOpts = (grant: Capability, over: Partial<AuthorizeOptions> = {}): AuthorizeOptions => ({
  audience: AUD,
  resolveGrant: async (ref) => (ref === grant.id ? grant : null),
  budgetStore: memoryPcaStore(),
  hooks: { revocation: () => ({ enforced: true, ok: true }) },
  plan: 'single-step',
  now: () => NOW,
  risk: (o) => ({ blastRadius: Math.min(1, Number(o?.params?.size) / 100), semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }),
  ...over,
});

describe('authorize + undo: an escalation of a confirmed-reversible action runs now under a veto window', () => {
  it('without undo the action escalates; with undo it is allow + undo_window (record durable before the result)', async () => {
    const g = setup();
    expect((await createAuthorizer(azOpts(g.grant))({ pcactn: g.sign(VERB, op(20).params!), operation: op(20) })).decision).toBe('escalate');
    const h = harness(g.grant);
    const az = createAuthorizer(azOpts(g.grant, { undo: h.undo }));
    const p = g.sign(VERB, op(20).params!);
    const r = await az({ pcactn: p, operation: op(20) });
    expect(r.allow).toBe(true);
    expect(r.decision).toBe('allow');
    if (!r.allow) throw new Error('unreachable');
    expect(r.undo?.converted).toBe(true);
    expect(r.undo?.id).toBe(pcactnDigest(p));
    expect(r.undo?.compensation).toEqual({ verb: COMP, resource: RES });
    expect(r.undo?.obligation).toEqual({ kind: 'undo_window', params: { id: r.undo!.id, window_end: r.undo!.window_end }, due: r.undo!.window_end });
    expect(r.undo?.window_end).toBe(NOW + 15 * 60_000);
    expect(r.verdict.checks.undo_window).toBe('pass');
    expect(r.verdict.reasons.some((x) => x.startsWith('undo_window: '))).toBe(true);
    const rec = await h.store.get(r.undo!.id);
    expect(rec?.state).toBe('open');
    expect(rec?.converted).toBe(true);
    expect(undoReceiptChainError(rec!, h.undo.signerPublic)).toBeNull();
    expect(h.notices.map((n) => n.kind)).toEqual(['opened']);
    expect(h.notices[0]!.token).toBe(r.undo!.token);
    // the PEP rule: an enforcement point that does not run undo windows must deny this allow
    expect(pepObligationGate('allow', false, [r.undo!.obligation], ['log']).decision).toBe('deny');
    expect(pepObligationGate('allow', false, [r.undo!.obligation], ['undo_window']).decision).toBe('allow');
  });

  it('an already allowed eligible action gets a window too (mode always); not in mode escalations; off turns it off', async () => {
    const g = setup();
    const h = harness(g.grant);
    const r = await createAuthorizer(azOpts(g.grant, { undo: h.undo }))({ pcactn: g.sign(VERB, op(5).params!), operation: op(5) });
    expect(r.allow && r.undo?.converted).toBe(false);
    for (const mode of ['escalations', 'off'] as const) {
      const h2 = harness(g.grant, { policy: (): UndoPolicy => ({ mode }) });
      const az = createAuthorizer(azOpts(g.grant, { undo: h2.undo }));
      const plain = await az({ pcactn: g.sign(VERB, op(5).params!), operation: op(5) });
      expect(plain.allow && plain.undo).toBeUndefined();
      const esc = await az({ pcactn: g.sign(VERB, op(20).params!), operation: op(20) });
      expect(esc.decision).toBe(mode === 'off' ? 'escalate' : 'allow');
    }
  });

  it('the window length follows the policy, clamped to [30 s, 24 h]', async () => {
    const g = setup();
    for (const [want, got] of [[1, 30_000], [60_000, 60_000], [10 ** 12, 86_400_000]] as const) {
      const h = harness(g.grant, { policy: () => ({ windowMs: want }) });
      const r = await createAuthorizer(azOpts(g.grant, { undo: h.undo }))({ pcactn: g.sign(VERB, op(20).params!), operation: op(20) });
      expect(r.allow && r.undo!.window_end - NOW).toBe(got);
    }
  });

  it('a deny is never touched: over the grant limit stays deny with no record', async () => {
    const g = setup();
    const h = harness(g.grant);
    const r = await createAuthorizer(azOpts(g.grant, { undo: h.undo }))({ pcactn: g.sign(VERB, op(400).params!), operation: op(400) });
    expect(r.decision).toBe('deny');
    expect(await h.store.list({ state: 'open' })).toEqual([]);
  });

  it('adversarial: the agent signs reversible for an action the definition does not confirm -> still escalate', async () => {
    const g = setup();
    const h = harness(g.grant);
    const r = await createAuthorizer(azOpts(g.grant, { undo: h.undo }))({ pcactn: g.sign(PUBLISH, op(20, PUBLISH).params!, 'reversible'), operation: op(20, PUBLISH) });
    expect(r.decision).toBe('escalate');
    expect(h.notices).toEqual([]);
  });

  it('adversarial: an agent that signs irreversible is taken at its word (no window)', async () => {
    const g = setup();
    const h = harness(g.grant);
    for (const cls of ['irreversible', 'rate_limited']) {
      const r = await createAuthorizer(azOpts(g.grant, { undo: h.undo }))({ pcactn: g.sign(VERB, op(20).params!, cls), operation: op(20) });
      expect([cls, r.allow && r.undo !== undefined]).toEqual([cls, false]);
    }
  });

  it('adversarial: a compensating action the grant does not authorize makes the action ineligible', async () => {
    const g = setup({ compPermitted: false });
    const h = harness(g.grant);
    const r = await createAuthorizer(azOpts(g.grant, { undo: h.undo }))({ pcactn: g.sign(VERB, op(20).params!), operation: op(20) });
    expect(r.decision).toBe('escalate');
    expect(await h.undo.admit({ pcactn: g.sign(VERB, op(20).params!), operation: op(20), converted: true })).toEqual({ refused: expect.stringContaining('compensating action is not authorized') });
  });

  it('a presented answer is never overridden: an explicit deny answer keeps the escalation', async () => {
    const g = setup();
    const h = harness(g.grant);
    const az = createAuthorizer(azOpts(g.grant, { undo: h.undo, escalation: { principals: [g.pPub], insecureUnboundApproval: true } }));
    const p = g.sign(VERB, op(20).params!);
    const answer = signEscalationAnswer(
      { v: 1, kind: 'pca-escalation-answer', principal: g.pPub, policy_digest: escalationPolicyDigest(g.grant), action_digest: escalationActionDigest(p), history_head: escalationHistoryHead(undefined), decision: 'deny', iat: NOW, expires_at: NOW + 600_000, nonce: b64u(randomBytes(16)) },
      g.principal.secretKey,
    );
    const r = await az({ pcactn: p, operation: op(20), escalationAnswer: answer });
    expect(r.allow).toBe(false);
    expect(await h.store.list({ state: 'open' })).toEqual([]);
  });

  it('a window nobody hears about is no window: an undelivered notice refuses a converted escalation and aborts the record', async () => {
    const g = setup();
    const h = harness(g.grant, { deliver: false });
    const az = createAuthorizer(azOpts(g.grant, { undo: h.undo }));
    const p = g.sign(VERB, op(20).params!);
    const r = await az({ pcactn: p, operation: op(20) });
    expect(r.allow).toBe(false);
    expect(!r.allow && r.reason).toContain('undo: the veto window could not be opened');
    expect((await h.store.get(pcactnDigest(p)))?.outcome?.status).toBe('aborted');
    expect(h.alerts.map((a) => [a.code, a.level])).toEqual([['notify_failed', 'critical']]);
    // a plain allow stays an allow without a window (never less than without undo)
    const plain = await az({ pcactn: g.sign(VERB, op(5).params!), operation: op(5) });
    expect(plain.allow && plain.undo).toBeUndefined();
    expect(plain.allow).toBe(true);
  });
});

async function opened(over: Parameters<typeof harness>[1] = {}, size = 20) {
  const g = setup();
  const h = harness(g.grant, over);
  const r = await createAuthorizer(azOpts(g.grant, { undo: h.undo }))({ pcactn: g.sign(VERB, op(size).params!), operation: op(size) });
  if (!r.allow || !r.undo) throw new Error('expected an undo window');
  return { ...h, g, info: r.undo };
}

describe('veto and compensation', () => {
  it('veto with the token after the effect: the compensation runs once under the grant, with the target from the result', async () => {
    const h = await opened();
    await h.undo.recordEffect(h.info.id, { id: 'd_1' });
    h.clock.t += 60_000;
    const v = await h.undo.veto(h.info.id, { token: h.info.token });
    expect(v.ok && v.record.state).toBe('compensated');
    expect(v.ok && v.replayed).toBe(false);
    expect(h.calls).toHaveLength(1);
    expect(h.calls[0]!.operation).toEqual({ verb: COMP, resource: RES, params: { box: 'box1', draft: 'd_1' } });
    expect(h.calls[0]!.undoOf).toBe(h.info.id);
    expect(h.calls[0]!.originalResult).toEqual({ id: 'd_1' });
    const rec = (await h.store.get(h.info.id))!;
    expect(rec.receipts.map((r) => r.event)).toEqual(['opened', 'effect', 'vetoed', 'compensated']);
    expect(rec.veto?.via).toBe('token');
    expect(undoReceiptChainError(rec, h.undo.signerPublic)).toBeNull();
    expect(h.notices.map((n) => n.kind)).toEqual(['opened', 'vetoed', 'compensated']);
  });

  it('a veto before the effect report waits; the report then runs the compensation', async () => {
    const h = await opened();
    const v = await h.undo.veto(h.info.id, { token: h.info.token });
    expect(v.ok && v.record.state).toBe('vetoed');
    expect(h.calls).toHaveLength(0);
    const after = await h.undo.recordEffect(h.info.id, { id: 'd_2' });
    expect(after.state).toBe('compensated');
    expect(h.calls.map((c) => c.operation.params?.draft)).toEqual(['d_2']);
  });

  it('double veto is a replay: nothing runs twice', async () => {
    const h = await opened();
    await h.undo.recordEffect(h.info.id, { id: 'd_1' });
    await h.undo.veto(h.info.id, { token: h.info.token });
    const again = await h.undo.veto(h.info.id, { token: h.info.token });
    expect(again.ok && again.replayed).toBe(true);
    const op2 = await h.undo.veto(h.info.id, { operator: 'ops@example' });
    expect(op2.ok && op2.replayed).toBe(true);
    expect(h.calls).toHaveLength(1);
  });

  it('concurrent vetoes (token and operator at once) apply one veto and run the compensation once', async () => {
    const h = await opened();
    await h.undo.recordEffect(h.info.id, { id: 'd_1' });
    const rs = await Promise.all([h.undo.veto(h.info.id, { token: h.info.token }), h.undo.veto(h.info.id, { operator: 'ops' }), h.undo.veto(h.info.id, { token: h.info.token })]);
    expect(rs.every((r) => r.ok)).toBe(true);
    expect(rs.filter((r) => r.ok && !r.replayed)).toHaveLength(1);
    expect(h.calls).toHaveLength(1);
    expect((await h.store.get(h.info.id))?.receipts.filter((r) => r.event === 'vetoed')).toHaveLength(1);
  });

  it('veto after expiry is refused (token: expired; operator: window_closed); exactly at the end is accepted', async () => {
    const h = await opened();
    h.clock.t = h.info.window_end + 1;
    expect(await h.undo.veto(h.info.id, { token: h.info.token })).toMatchObject({ ok: false, code: 'expired' });
    expect(await h.undo.veto(h.info.id, { operator: 'ops' })).toMatchObject({ ok: false, code: 'window_closed' });
    const k = await opened();
    k.clock.t = k.info.window_end;
    expect((await k.undo.veto(k.info.id, { token: k.info.token })).ok).toBe(true);
  });

  it('forged, tampered, cross-record and unknown tokens are refused with their code', async () => {
    const a = await opened();
    const b = await opened();
    const tok = decodeUndoToken(a.info.token) as UndoToken;
    expect(await a.undo.veto(a.info.id, { token: encodeUndoToken({ ...tok, exp: tok.exp + 1 }) })).toMatchObject({ ok: false, code: 'signature' });
    expect(await a.undo.veto(a.info.id, { token: b.info.token })).toMatchObject({ ok: false, code: 'signer' });
    expect(await a.undo.veto(a.info.id, { token: 'not-a-token' })).toMatchObject({ ok: false, code: 'malformed' });
    expect(await a.undo.veto('nope', { token: a.info.token })).toMatchObject({ ok: false, code: 'unknown' });
    expect((await a.store.get(a.info.id))?.state).toBe('open');
  });

  it('a failed compensation is never silent: compensation_failed, critical alert, notice; retry then succeeds once', async () => {
    let failing = true;
    const h = await opened({ fail: () => failing });
    await h.undo.recordEffect(h.info.id, { id: 'd_1' });
    const v = await h.undo.veto(h.info.id, { token: h.info.token });
    expect(v.ok && v.record.state).toBe('compensation_failed');
    expect(h.alerts.map((a) => [a.code, a.level])).toEqual([['compensation_failed', 'critical']]);
    expect(h.notices.map((n) => n.kind)).toContain('compensation_failed');
    failing = false;
    const r = await h.undo.retry(h.info.id);
    expect(r.state).toBe('compensated');
    expect(r.attempt).toBe(1);
    expect(h.calls).toHaveLength(2);
  });

  it('a compensation whose target the effect never named fails loudly (no guessing)', async () => {
    const h = await opened({ effectTimeoutMs: 1_000 });
    await h.undo.recordEffect(h.info.id, { ok: true });
    const v = await h.undo.veto(h.info.id, { token: h.info.token });
    expect(v.ok && v.record.state).toBe('compensation_failed');
    expect(h.calls).toHaveLength(0);
  });

  it('the compensation is re-decided at veto: a grant that is no longer known refuses it (compensation_denied, nothing runs)', async () => {
    let known = true;
    const g = setup();
    const h = harness(g.grant, { resolveGrant: async (ref) => (known && ref === g.grant.id ? g.grant : null) });
    const r = await createAuthorizer(azOpts(g.grant, { undo: h.undo }))({ pcactn: g.sign(VERB, op(20).params!), operation: op(20) });
    if (!r.allow || !r.undo) throw new Error('expected a window');
    await h.undo.recordEffect(r.undo.id, { id: 'd_1' });
    known = false;
    const v = await h.undo.veto(r.undo.id, { token: r.undo.token });
    expect(v.ok && v.record.state).toBe('compensation_failed');
    expect(h.alerts.map((a) => [a.code, a.level])).toEqual([['compensation_denied', 'critical']]);
    expect(h.calls).toHaveLength(0);
  });

  it('crash mid-compensation: an executing attempt becomes uncertain -> compensation_failed + alert, never re-run blind', async () => {
    const g = setup();
    const shared = harness(g.grant, { compensate: () => new Promise(() => {}) });
    const r = await createAuthorizer(azOpts(g.grant, { undo: shared.undo }))({ pcactn: g.sign(VERB, op(20).params!), operation: op(20) });
    if (!r.allow || !r.undo) throw new Error('expected a window');
    await shared.undo.recordEffect(r.undo.id, { id: 'd_9' });
    void shared.undo.veto(r.undo.id, { token: r.undo.token }); // the process "dies" while the compensator hangs
    for (let i = 0; i < 20; i++) await new Promise((res) => setTimeout(res, 0));
    // restart: a new coordinator over the same durable stores
    const calls: unknown[] = [];
    const alerts: UndoAlert[] = [];
    const restarted = createUndoCoordinator({
      store: shared.store, engine, signerSecret: shared.signer, audience: AUD, resolveGrant: async () => g.grant, operations: shared.operations,
      compensate: async (c) => void calls.push(c), notifier: { notify: async () => ({ delivered: true }) }, alert: (a) => void alerts.push(a),
      now: () => NOW + 60 * 60_000, insecureVolatileStore: true,
    });
    await restarted.recover();
    expect((await shared.store.get(r.undo.id))?.state).toBe('compensation_failed');
    expect(calls).toHaveLength(0);
    expect(alerts.map((a) => a.code)).toContain('compensation_failed');
  });

  it('crash before the compensator started: the attempt is aborted and retried under the next attempt, once', async () => {
    const h = await opened();
    await h.undo.recordEffect(h.info.id, { id: 'd_3' });
    // simulate: the veto was written and the attempt record created, then the process died before `executing`
    const rec = (await h.store.get(h.info.id))!;
    const { hashCanonical } = await import('../hash');
    await h.operations.create({ id: hashCanonical({ d: 'atlas-pca/undo-compensation-op/v1', record: rec.id, attempt: 0 }), state: 'pending', verb: COMP, resource: RES, params_digest: 'x', reversibility: 'irreversible', startedAt: NOW });
    await h.store.replace(rec.id, rec.ver, { ...rec, state: 'vetoed', veto: { at: NOW, via: 'operator', by: 'ops' }, ver: rec.ver + 1, receipts: rec.receipts });
    h.clock.t = NOW + 10 * 60_000;
    await h.undo.recover();
    const done = (await h.store.get(h.info.id))!;
    expect(done.state).toBe('compensated');
    expect(done.attempt).toBe(1);
    expect(h.calls).toHaveLength(1);
  });
});

describe('expiry, budgets, revocation, fraud proofs', () => {
  const budgetStub = () => {
    const log: string[] = [];
    const ledger = {
      durable: true,
      commit: async (k: string, id: string) => (log.push(`commit ${k} ${id}`), { outcome: 'settled' as const, version: 1 }),
      release: async (k: string, id: string, e?: { reason: string }) => (log.push(`release ${k} ${id} ${e?.reason ?? ''}`), { outcome: 'settled' as const, version: 1 }),
    };
    return { log, budget: { ledger: ledger as never, evidence: (_r: unknown, reason: string) => ({ reason }) as never } };
  };

  it('finalizeDue closes only ended windows and commits their held budget', async () => {
    const b = budgetStub();
    const h = await opened({ budget: b.budget });
    await h.undo.holdBudget(h.info.id, [{ key: 'principal/p', id: h.info.id }]);
    await h.undo.recordEffect(h.info.id, { id: 'd' });
    h.clock.t = h.info.window_end;
    expect(await h.undo.finalizeDue()).toEqual([]);
    h.clock.t = h.info.window_end + 1;
    expect(await h.undo.finalizeDue()).toEqual([h.info.id]);
    expect((await h.store.get(h.info.id))?.state).toBe('finalized');
    expect(b.log).toEqual([`commit principal/p ${h.info.id}`]);
    expect(await h.undo.veto(h.info.id, { operator: 'ops' })).toMatchObject({ ok: false, code: 'finalized' });
  });

  it('a relayed (hosted) veto made inside the window is applied before the sweep, even when read after the window closed', async () => {
    let pending: { id: string; token: unknown; at: number }[] = [];
    const h = await opened({ relay: { pending: async () => pending } });
    await h.undo.recordEffect(h.info.id, { id: 'd_1' });
    pending = [{ id: h.info.id, token: h.info.token, at: h.info.window_end }];
    h.clock.t = h.info.window_end + 5 * 60_000;
    expect(await h.undo.finalizeDue()).toEqual([]);
    const rec = (await h.store.get(h.info.id))!;
    expect([rec.state, rec.veto?.via, rec.veto?.at]).toEqual(['compensated', 'token', h.info.window_end]);
    expect(undoReceiptChainError(rec, h.undo.signerPublic)).toBeNull(); // receipts stay in time order
    expect(h.calls).toHaveLength(1);
  });

  it('a relayed veto is still checked: a time after the window, in the future or before the opening is refused', async () => {
    const h = await opened({ relay: { pending: async () => [] } });
    h.clock.t = NOW + 60_000;
    expect(await h.undo.veto(h.info.id, { token: h.info.token, at: h.info.window_end + 1 })).toMatchObject({ ok: false });
    expect(await h.undo.veto(h.info.id, { token: h.info.token, at: NOW + 120_000 })).toMatchObject({ ok: false, code: 'malformed' });
    expect(await h.undo.veto(h.info.id, { token: h.info.token, at: NOW - 1 })).toMatchObject({ ok: false, code: 'malformed' });
    expect(await h.undo.veto(h.info.id, { token: h.info.token, at: 1.5 })).toMatchObject({ ok: false, code: 'malformed' });
    expect((await h.store.get(h.info.id))?.state).toBe('open');
  });

  it('a relay that cannot be read finalizes nothing (critical alert); with a relay the sweep waits out the grace period', async () => {
    let broken = true;
    const h = await opened({ relay: { pending: async () => { if (broken) throw new Error('relay down'); return []; } } });
    h.clock.t = h.info.window_end + 10 * 60_000;
    expect(await h.undo.finalizeDue()).toEqual([]);
    expect(h.alerts.map((a) => [a.code, a.level])).toEqual([['veto_relay_failed', 'critical']]);
    expect((await h.store.get(h.info.id))?.state).toBe('open');
    broken = false;
    expect(await h.undo.finalizeDue()).toEqual([h.info.id]);
    const k = await opened({ relay: { pending: async () => [] } });
    k.clock.t = k.info.window_end + UNDO_RELAY_GRACE_MS;
    expect(await k.undo.finalizeDue()).toEqual([]);
    k.clock.t = k.info.window_end + UNDO_RELAY_GRACE_MS + 1;
    expect(await k.undo.finalizeDue()).toEqual([k.info.id]);
  });

  it('hostedUndoVetoRelay maps the hosted veto listing and throws on anything else', async () => {
    const seen: string[] = [];
    const ok = hostedUndoVetoRelay({ baseUrl: 'https://api.example/', secretKey: 'sk_test', fetch: async (url, init) => (seen.push(`${init.method} ${url} ${init.headers.authorization === 'Bearer sk_test'}`), { ok: true, status: 200, json: async () => ({ object: 'list', data: [{ record_id: 'r1', veto: { at: 5, via: 'token', by: 'p', token: 't' } }] }) }) });
    expect(await ok.pending()).toEqual([{ id: 'r1', token: 't', at: 5 }]);
    expect(seen).toEqual(['GET https://api.example/v1/pca/undo/vetoes?limit=200 true']);
    const status = hostedUndoVetoRelay({ baseUrl: 'https://api.example', secretKey: 'sk', fetch: async () => ({ ok: false, status: 503, json: async () => ({}) }) });
    await expect(status.pending()).rejects.toThrow(/503/);
    const shape = hostedUndoVetoRelay({ baseUrl: 'https://api.example', secretKey: 'sk', fetch: async () => ({ ok: true, status: 200, json: async () => ({ data: [{ record_id: 'r1', veto: { at: 5 } }] }) }) });
    await expect(shape.pending()).rejects.toThrow(/malformed/);
  });

  it('a compensated action releases its held budget as a rollback; an aborted one as effect_not_run', async () => {
    const b = budgetStub();
    const h = await opened({ budget: b.budget });
    await h.undo.holdBudget(h.info.id, [{ key: 'org/o', id: h.info.id }]);
    await h.undo.recordEffect(h.info.id, { id: 'd' });
    await h.undo.veto(h.info.id, { token: h.info.token });
    expect(b.log).toEqual([`release org/o ${h.info.id} rollback`]);
    const b2 = budgetStub();
    const k = await opened({ budget: b2.budget });
    await k.undo.holdBudget(k.info.id, [{ key: 'org/o', id: k.info.id }]);
    const rec = await reportUndoEffect(k.undo, k.info.id, { status: 'failed' });
    expect(rec.outcome?.status).toBe('aborted');
    expect(b2.log).toEqual([`release org/o ${k.info.id} effect_not_run`]);
  });

  it('a failed compensation keeps the budget reserved', async () => {
    const b = budgetStub();
    const h = await opened({ budget: b.budget, fail: () => true });
    await h.undo.holdBudget(h.info.id, [{ key: 'org/o', id: h.info.id }]);
    await h.undo.recordEffect(h.info.id, { id: 'd' });
    await h.undo.veto(h.info.id, { token: h.info.token });
    expect(b.log).toEqual([]);
  });

  it('revocation mid-window: keep (default) alerts and notifies; veto compensates', async () => {
    const h = await opened();
    expect(await h.undo.onRevocation(h.g.grant.id)).toEqual([]);
    expect(h.alerts.map((a) => a.code)).toEqual(['revoked_open_window']);
    expect(h.notices.map((n) => n.kind)).toEqual(['opened', 'revoked']);
    expect((await h.store.get(h.info.id))?.state).toBe('open');
    const k = await opened({ policy: () => ({ onRevocation: 'veto' }) });
    await k.undo.recordEffect(k.info.id, { id: 'd' });
    expect(await k.undo.onRevocation(k.g.grant.id)).toEqual([k.info.id]);
    const rec = (await k.store.get(k.info.id))!;
    expect([rec.state, rec.veto?.via]).toEqual(['compensated', 'revocation']);
  });

  it('a slash with a fraud proof rolls the effect back; a refused slash undoes nothing', async () => {
    const h = await opened();
    await h.undo.recordEffect(h.info.id, { id: 'd' });
    await expect(h.undo.rollbackOnSlash({ slashBond: async () => { throw new Error('window_closed'); } }, { claimId: h.info.id })).rejects.toThrow('window_closed');
    expect((await h.store.get(h.info.id))?.state).toBe('open');
    const s = await h.undo.rollbackOnSlash({ slashBond: async () => ({ action: 'slash' }) as never }, { claimId: h.info.id });
    expect(s.veto.ok && s.veto.record.state).toBe('compensated');
    expect((await h.store.get(h.info.id))?.veto?.via).toBe('fraud_proof');
    // after the window closed: the slash stands but nothing can be undone -> a critical alert
    const k = await opened();
    k.clock.t = k.info.window_end + 1;
    await k.undo.finalizeDue();
    const late = await k.undo.rollbackOnSlash({ slashBond: async () => ({ action: 'slash' }) as never }, { claimId: k.info.id });
    expect(late.veto.ok).toBe(false);
    expect(k.alerts.map((a) => a.code)).toContain('slash_after_window');
  });

  it('a record linked to a bond stays open until the challenge window ends', async () => {
    const g = setup();
    const h = harness(g.grant);
    const p = g.sign(VERB, op(20).params!);
    const adm = await h.undo.admit({ pcactn: p, operation: op(20), converted: false });
    if ('refused' in adm) throw new Error(adm.refused);
    const info = await h.undo.open(adm, { bond: { ref: 'bond-1', challengeEndsAt: NOW + 2 * 60 * 60_000 } });
    expect(info.window_end).toBe(NOW + 2 * 60 * 60_000);
    expect((await h.store.list({ state: 'open', bondRef: 'bond-1' })).map((r) => r.id)).toEqual([info.id]);
  });
});

describe('configuration fails closed', () => {
  it('a non-durable store is refused unless a test says otherwise; missing components are named', () => {
    const g = setup();
    const base = harness(g.grant);
    const opts = { store: new MemoryUndoStore(), engine, signerSecret: base.signer, audience: AUD, resolveGrant: async () => g.grant, compensate: async () => 1, operations: memoryOperationStore(), notifier: { notify: async () => ({ delivered: true }) }, alert: () => undefined };
    expect(() => createUndoCoordinator(opts)).toThrow(UndoError);
    try {
      createUndoCoordinator(opts);
    } catch (e) {
      expect((e as UndoError).code).toBe('not_durable');
    }
    expect(missingUndoComponents({})).toEqual(['store', 'engine', 'signerSecret', 'audience', 'resolveGrant', 'compensate', 'operations', 'notifier', 'alert']);
    expect(() => createUndoCoordinator({ ...opts, notifier: undefined as never, insecureVolatileStore: true })).toThrow(/notifier/);
  });

  it('an engine that throws, or a grant that is unknown, admits nothing', async () => {
    const g = setup();
    const h = harness(g.grant, { engine: { plan: () => { throw new Error('boom'); } } });
    expect(await h.undo.admit({ pcactn: g.sign(VERB, op(20).params!), operation: op(20), converted: true })).toEqual({ refused: expect.stringContaining('fail closed') });
    const k = harness(setup().grant);
    expect(await k.undo.admit({ pcactn: g.sign(VERB, op(20).params!), operation: op(20), converted: true })).toEqual({ refused: 'unknown grant' });
  });
});

describe('the approval-channel notifier', () => {
  it('sends the one-click link and the render through the existing dispatcher; no delivery is reported as such', async () => {
    const sent: { link?: string; reason: string }[] = [];
    const ch = (enabled: boolean, ok: boolean): ApprovalChannel => ({
      kind: 'webhook',
      enabled,
      notify: async (req, ctx) => (sent.push({ link: ctx?.inboxUrl, reason: req.reason }), { kind: 'webhook', requestId: req.id, delivered: ok, payload: {} }),
    });
    const n = undoNotifierFromDispatcher(createApprovalDispatcher([ch(true, true)]), { undoUrl: (t, id) => `https://undo.example/${id}?t=${t}` });
    const h = await opened({ notifier: n });
    expect(sent[0]!.link).toBe(`https://undo.example/${h.info.id}?t=${h.info.token}`);
    expect(sent[0]!.reason).toContain('You can undo it until');
    const none = undoNotifierFromDispatcher(createApprovalDispatcher([ch(false, true)]), { undoUrl: () => 'x' });
    expect((await none.notify({ kind: 'opened', record: (await h.store.get(h.info.id))! })).delivered).toBe(false);
  });
});
