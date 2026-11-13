/**
 * The undo-window coordinator, value by value: every refusal with its exact code and reason, every alert with its exact
 * fields, each operand of each guard on its own, and the races the compare-and-swap and the once-per-attempt records exist for.
 */
import { describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { mintRoot, type Capability } from '../capability';
import { mintGrant } from '../envelope';
import { hashCanonical } from '../hash';
import { encodeKey, generateKeyPair } from '../keys';
import { paramsDigest, type PlanNode } from '../merkle';
import { buildPCActn, pcactnDigest, type PCActn } from '../pcactn';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from '../pq';
import type { Predicate } from '../predicates';
import type { RiskPolicy } from '../risk';
import type { ApprovalRender } from '../approval-render';
import type { ApprovalDelivery, ApprovalDispatcher, ApprovalNotifyContext } from '../approval-channels';
import type { StepUpRequest } from '../approvals';
import { MemoryUndoStore, UndoError, decodeUndoToken, type UndoQuery, type UndoRecord, type UndoStore } from '../undo';
import { memoryOperationStore, type OperationRecord, type OperationState, type OperationStore } from './operations';
import {
  createUndoCoordinator,
  hostedUndoVetoRelay,
  missingUndoComponents,
  reportUndoEffect,
  undoNotifierFromDispatcher,
  undoSignerPublic,
  type UndoAdmission,
  type UndoAlert,
  type UndoCompensationCall,
  type UndoCoordinatorOptions,
  type UndoEngine,
  type UndoNotice,
} from './undo';
import type { PcaOperation } from './verify';

const NOW = Date.UTC(2026, 9, 28, 12, 0, 0);
const AUD = 'drafts-rs';
const VERB = 'drafts.create';
const COMP = 'drafts.delete';
const RES = 'drafts:box1';
const POLICY: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 };
/** No risk weight at all: a zero risk costs nothing, so no budget reason is added to a refusal. */
const ZERO_RISK: RiskPolicy = { ...POLICY, weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 } };
const D1 = 'A'.repeat(43);
const D2 = 'B'.repeat(43);
const WINDOW = 15 * 60_000;
const RENDER = { v: 1, kind: 'pca-approval-render', verb: VERB, def_digest: D1, unreviewed: false, fields: [] } as unknown as ApprovalRender;
const ERR = (code: string, msg: string): string => `${code}: ${msg}`;

const engineOf = (o: { target?: boolean; render?: ApprovalRender; renderDigest?: string } = {}): UndoEngine => ({
  plan: (op) =>
    op.verb === VERB
      ? {
          def_digest: D1,
          compensation: { verb: COMP, params: { box: op.params?.box }, def_digest: D2, ...(o.target === false ? {} : { target_param: 'draft' }) },
          ...(o.render !== undefined ? { render: o.render } : {}),
          ...(o.renderDigest !== undefined ? { render_digest: o.renderDigest } : {}),
        }
      : null,
});

/** A memory undo store with seams for the races: forced CAS misses, a hidden record, a stale listing, a failing read. */
class SeamStore implements UndoStore {
  durable = false;
  readonly inner = new MemoryUndoStore();
  failReplaces = 0;
  replaceCalls = 0;
  hide = false;
  getError: unknown = undefined;
  listHook: ((q: UndoQuery) => UndoRecord[] | undefined) | undefined = undefined;
  async get(id: string): Promise<UndoRecord | undefined> {
    if (this.getError !== undefined) throw this.getError;
    return this.hide ? undefined : this.inner.get(id);
  }
  create(rec: UndoRecord) {
    return this.inner.create(rec);
  }
  async replace(id: string, ver: number, next: UndoRecord): Promise<boolean> {
    this.replaceCalls++;
    if (this.failReplaces > 0) {
      this.failReplaces--;
      return false;
    }
    return this.inner.replace(id, ver, next);
  }
  async list(q: UndoQuery): Promise<UndoRecord[]> {
    return this.listHook?.(q) ?? this.inner.list(q);
  }
  /** Change a stored record behind the coordinator's back (another worker, an operator, a crash). */
  async patch(id: string, p: Partial<UndoRecord>): Promise<UndoRecord> {
    const cur = (await this.inner.get(id))!;
    const next = { ...cur, ...p, ver: cur.ver + 1 };
    expect(await this.inner.replace(id, cur.ver, next)).toBe(true);
    return next;
  }
}

interface Hooks {
  onCreate?: (r: OperationRecord) => void | Promise<void>;
  onTransition?: (id: string, from: OperationState, next: OperationRecord) => boolean | undefined | Promise<boolean | undefined>;
}
function seamOps(h: Hooks): OperationStore {
  const base = memoryOperationStore();
  return {
    create: async (r) => {
      const c = await base.create(r);
      await h.onCreate?.(r);
      return c;
    },
    get: (id) => base.get(id),
    transition: async (id, from, next) => ((await h.onTransition?.(id, from, next)) === false ? false : base.transition(id, from, next)),
  };
}

type KitOpts = Partial<UndoCoordinatorOptions> & { preds?: Predicate[]; risk?: RiskPolicy; deliver?: boolean; fail?: () => unknown; hooks?: Hooks; result?: unknown };

function kit(o: KitOpts = {}) {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const pPub = encodeKey(principal.publicKey);
  const grant: Capability = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: pPub,
    holder: encodeKey(holder.publicKey),
    goal: 'manage drafts',
    envelope: { predicates: o.preds ?? [{ verb: [VERB, COMP], resource: '*' }], caveats: [], agent_binding: {}, risk_policy: o.risk ?? POLICY },
  }).grant;
  let counter = 0;
  const sign = (params: Record<string, unknown> = { box: 'box1', size: 20 }, cls = 'reversible', g: Capability = grant): PCActn => {
    const node: PlanNode = { id: 'n1', verb: VERB, resource: RES, params_digest: paramsDigest(params), reversibility_class: cls as PlanNode['reversibility_class'] };
    return buildPCActn({ grant: g, chain: [g], plan: [node], nodeId: 'n1', params, counter: ++counter, signerSecret: holder.secretKey, aud: AUD, now: NOW });
  };
  const clock = { t: NOW };
  const notices: UndoNotice[] = [];
  const alerts: UndoAlert[] = [];
  const calls: UndoCompensationCall[] = [];
  const store = new SeamStore();
  const hooks: Hooks = o.hooks ?? {};
  const operations = seamOps(hooks);
  const signer = new Uint8Array(randomBytes(32));
  const opts: UndoCoordinatorOptions = {
    store,
    engine: engineOf(),
    signerSecret: signer,
    audience: AUD,
    resolveGrant: async (ref) => (ref === grant.id ? grant : null),
    compensate: async (c) => {
      calls.push(c);
      const f = o.fail?.();
      if (f !== undefined && f !== false) throw f === true ? new Error('downstream refused') : f;
      return 'result' in o ? o.result : { deleted: c.operation.params?.draft };
    },
    operations,
    notifier: { notify: async (n) => (notices.push(n), o.deliver === false ? { delivered: false, reason: 'channel down' } : { delivered: true }) },
    alert: (a) => void alerts.push(a),
    now: () => clock.t,
    insecureVolatileStore: true,
    ...o,
  };
  const undo = createUndoCoordinator(opts);
  const op = (params: Record<string, unknown> = { box: 'box1', size: 20 }): PcaOperation => ({ verb: VERB, resource: RES, params });
  const admitted = async (converted = false, params: Record<string, unknown> = { box: 'box1', size: 20 }): Promise<UndoAdmission> => {
    const adm = await undo.admit({ pcactn: sign(params), operation: op(params), converted });
    if ('refused' in adm) throw new Error(`refused: ${adm.refused}`);
    return adm;
  };
  const opened = async (converted = false) => {
    const adm = await admitted(converted);
    const info = await undo.open(adm);
    return { adm, info, id: info.id };
  };
  const opIdOf = (id: string, attempt = 0): string => hashCanonical({ d: 'atlas-pca/undo-compensation-op/v1', record: id, attempt });
  return { grant, principal, holder, pPub, sign, op, clock, notices, alerts, calls, store, operations, signer, opts, undo, admitted, opened, opIdOf, hooks };
}

async function rejection(p: Promise<unknown>): Promise<Error> {
  try {
    await p;
  } catch (e) {
    return e as Error;
  }
  throw new Error('expected a rejection');
}
function thrown(f: () => unknown): Error {
  try {
    f();
  } catch (e) {
    return e as Error;
  }
  throw new Error('expected a throw');
}
const kinds = (ns: UndoNotice[]): string[] => ns.map((n) => n.kind);

describe('configuration', () => {
  it('names exactly the component whose own check fails', () => {
    const k = kit();
    const base = k.opts;
    expect(missingUndoComponents(base)).toEqual([]);
    expect(missingUndoComponents({ ...base, engine: { plan: 'x' } as never })).toEqual(['engine']);
    expect(missingUndoComponents({ ...base, signerSecret: new Uint8Array(31) })).toEqual(['signerSecret']);
    expect(missingUndoComponents({ ...base, signerSecret: new Uint8Array(33) })).toEqual(['signerSecret']);
    expect(missingUndoComponents({ ...base, audience: '' })).toEqual(['audience']);
    const ops = memoryOperationStore();
    expect(missingUndoComponents({ ...base, operations: { get: ops.get, transition: ops.transition } as never })).toEqual(['operations']);
    expect(missingUndoComponents({ ...base, operations: { create: ops.create, transition: ops.transition } as never })).toEqual(['operations']);
    expect(missingUndoComponents({ ...base, operations: { create: ops.create, get: ops.get } as never })).toEqual(['operations']);
    expect(missingUndoComponents({ ...base, notifier: {} as never })).toEqual(['notifier']);
  });

  it('a missing component throws config with every name joined; a volatile store throws not_durable; a durable one is accepted', () => {
    const k = kit();
    const e = thrown(() => createUndoCoordinator({ ...k.opts, engine: undefined as never, notifier: undefined as never }));
    expect(e).toBeInstanceOf(UndoError);
    expect((e as UndoError).code).toBe('config');
    expect(e.message).toBe(ERR('config', 'undo coordinator: missing required component(s): engine, notifier'));
    const v = thrown(() => createUndoCoordinator({ ...k.opts, insecureVolatileStore: false }));
    expect((v as UndoError).code).toBe('not_durable');
    expect(v.message).toBe(ERR('not_durable', 'an undo ledger must be durable: a restart would lose every open window and its compensation'));
    const durable = new SeamStore();
    durable.durable = true;
    const c = createUndoCoordinator({ ...k.opts, store: durable, insecureVolatileStore: false });
    expect(c.signerPublic).toBe(undoSignerPublic(k.signer));
  });

  it('a clock that is not a safe integer refuses the admission (fail closed)', async () => {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, 2 ** 60]) {
      const k = kit({ now: () => bad });
      expect(await k.undo.admit({ pcactn: k.sign(), operation: k.op(), converted: false })).toEqual({ refused: 'undo admission error (fail closed): invalid: the clock returned a non-finite time' });
    }
  });
});

describe('admission', () => {
  it('refuses a missing PCActn, a missing operation, a non-string verb and a non-string resource, each on its own', async () => {
    const k = kit();
    const p = k.sign();
    expect(await k.undo.admit({ pcactn: undefined as never, operation: k.op(), converted: false })).toEqual({ refused: 'no operation' });
    expect(await k.undo.admit({ pcactn: p, operation: undefined as never, converted: false })).toEqual({ refused: 'no operation' });
    expect(await k.undo.admit({ pcactn: p, operation: { verb: 5 as never, resource: RES, params: {} }, converted: false })).toEqual({ refused: 'no operation' });
    expect(await k.undo.admit({ pcactn: p, operation: { verb: VERB, resource: 5 as never, params: { box: 'box1' } }, converted: false })).toEqual({ refused: 'no operation' });
  });

  it('policy off and escalations-only refuse with their exact reasons; escalations admits a converted action', async () => {
    const off = kit({ policy: () => ({ mode: 'off' }) });
    expect(await off.undo.admit({ pcactn: off.sign(), operation: off.op(), converted: true })).toEqual({ refused: 'policy: undo windows are off' });
    const esc = kit({ policy: () => ({ mode: 'escalations' }) });
    expect(await esc.undo.admit({ pcactn: esc.sign(), operation: esc.op(), converted: false })).toEqual({ refused: 'policy: windows only replace approvals' });
    const ok = await esc.undo.admit({ pcactn: esc.sign(), operation: esc.op(), converted: true });
    expect('refused' in ok).toBe(false);
  });

  it('the signed class decides first: irreversible and a missing action are refused by name', async () => {
    const k = kit();
    expect(await k.undo.admit({ pcactn: k.sign(undefined, 'irreversible'), operation: k.op(), converted: false })).toEqual({ refused: 'the signed class is irreversible' });
    const noAction = { ...k.sign(), action: undefined } as unknown as PCActn;
    expect(await k.undo.admit({ pcactn: noAction, operation: k.op(), converted: false })).toEqual({ refused: 'the signed class is undefined' });
  });

  it('the engine is asked with the operation id; no plan is refused by name; an engine that throws a non-error is refused', async () => {
    const seen: { operationId: string }[] = [];
    const k = kit({ engine: { plan: (_op, ctx) => (seen.push(ctx), null) } });
    const p = k.sign();
    expect(await k.undo.admit({ pcactn: p, operation: k.op(), converted: false })).toEqual({ refused: 'not confirmed reversible, or no confirmed compensating action' });
    expect(seen).toEqual([{ operationId: pcactnDigest(p) }]);
    const t = kit({
      engine: {
        plan: () => {
          throw 'not an error';
        },
      },
    });
    expect(await t.undo.admit({ pcactn: t.sign(), operation: t.op(), converted: false })).toEqual({ refused: 'undo admission error (fail closed): unknown' });
  });

  it('the admission carries the exact compensation and a copy of the operation', async () => {
    const k = kit();
    const p = k.sign();
    const adm = await k.undo.admit({ pcactn: p, operation: k.op(), converted: true });
    if ('refused' in adm) throw new Error(adm.refused);
    const id = pcactnDigest(p);
    expect(adm.id).toBe(id);
    expect([adm.opened_at, adm.window_end, adm.converted]).toEqual([NOW, NOW + WINDOW, true]);
    expect(adm.compensation).toStrictEqual({ verb: COMP, resource: RES, params: { box: 'box1' }, undo_of: id, def_digest: D2, target_param: 'draft' });
    expect(adm.operation).toStrictEqual({ verb: VERB, resource: RES, params: { box: 'box1', size: 20 } });
    expect(adm.grant).toBe(k.grant);
    expect(adm.pcactn).toBe(p);
    // without a target parameter the compensation names none (not even an undefined one); an operation without params gets {}
    const n = kit({ engine: { plan: () => ({ def_digest: D1, compensation: { verb: COMP, params: {}, def_digest: D2 } }) } });
    const a2 = await n.undo.admit({ pcactn: n.sign({ box: 'box1' }), operation: { verb: VERB, resource: RES }, converted: false });
    if ('refused' in a2) throw new Error(a2.refused);
    expect(Object.keys(a2.compensation).sort()).toEqual(['def_digest', 'params', 'resource', 'undo_of', 'verb']);
    expect(a2.compensation.params).toStrictEqual({});
    expect(a2.operation).toStrictEqual({ verb: VERB, resource: RES, params: {} });
  });

  it('the compensation is decided over its own params: a where on them admits when they match', async () => {
    const k = kit({ preds: [{ verb: [VERB], resource: '*' }, { verb: [COMP], resource: '*', where: [{ field: 'action.params.box', op: 'eq', value: 'box1' }] }] });
    const adm = await k.undo.admit({ pcactn: k.sign(), operation: k.op(), converted: false });
    expect('refused' in adm).toBe(false);
    const other = await k.undo.admit({ pcactn: k.sign({ box: 'box2', size: 1 }), operation: k.op({ box: 'box2', size: 1 }), converted: false });
    expect(other).toEqual({ refused: 'the compensating action is not authorized under the grant: box == "box1" not satisfied for drafts.delete on drafts:box1' });
  });

  it('a refused compensation names the first reason that is not about missing risk inputs, else a fixed reason', async () => {
    const none = kit({ preds: [{ verb: [VERB], resource: '*' }] });
    expect(await none.undo.admit({ pcactn: none.sign(), operation: none.op(), converted: false })).toEqual({ refused: 'the compensating action is not authorized under the grant: no predicate permits drafts.delete on drafts:box1' });
    // a limit whose name itself reads "risk input": with a budget reason after it, that one is named
    const tricky: Predicate[] = [{ verb: [VERB], resource: '*' }, { verb: [COMP], resource: '*', where: [{ field: 'action.params.risk input', op: 'eq', value: 1 }] }];
    const withBudget = kit({ preds: tricky });
    expect(await withBudget.undo.admit({ pcactn: withBudget.sign(), operation: withBudget.op(), converted: false })).toEqual({ refused: 'the compensating action is not authorized under the grant: trust budget depleted: human recharge required' });
    // with zero risk (and the empty budget the decision is held to) there is no other reason: the fixed one is used
    const zero = kit({ preds: tricky, risk: ZERO_RISK });
    expect(await zero.undo.admit({ pcactn: zero.sign(), operation: zero.op(), converted: false })).toEqual({ refused: 'the compensating action is not authorized under the grant: the grant does not authorize the compensating action' });
  });

  it('the verifier PQ pins reach the compensation decision: a pin that disagrees with a PQ grant refuses it', async () => {
    const principal = generateKeyPair();
    const holder = generateKeyPair();
    const ml = mlDsa65Keygen(new Uint8Array(32).fill(3));
    const env = mintGrant({ principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: encodeKey(holder.publicKey), goal: 'g', envelope: { predicates: [{ verb: [VERB, COMP], resource: '*' }], caveats: [], agent_binding: {}, risk_policy: POLICY } }).grant;
    const grant = mintRoot({ principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: encodeKey(holder.publicKey), caveats: env.caveats, suite: { alg: 'ml-dsa-65', mlDsa: ml } });
    const params = { box: 'box1', size: 20 };
    const pc = buildPCActn({ grant, chain: [grant], plan: [{ id: 'n1', verb: VERB, resource: RES, params_digest: paramsDigest(params), reversibility_class: 'reversible' }], nodeId: 'n1', params, counter: 1, signerSecret: holder.secretKey, aud: AUD, now: NOW });
    const operation: PcaOperation = { verb: VERB, resource: RES, params };
    const plain = kit({ resolveGrant: async () => grant });
    expect('refused' in (await plain.undo.admit({ pcactn: pc, operation, converted: false }))).toBe(false);
    const other = encodeMlDsaPublicKey(mlDsa65Keygen(new Uint8Array(32).fill(4)).publicKey);
    const pinned = kit({ resolveGrant: async () => grant, pqPins: { [grant.issuer]: other } });
    const r = await pinned.undo.admit({ pcactn: pc, operation, converted: false });
    expect('refused' in r && r.refused.startsWith('the compensating action is not authorized under the grant: capability chain unverified: ')).toBe(true);
  });
});

describe('opening a window', () => {
  it('the record holds the action, the render digest when the plan has one, and the converted note on its receipt', async () => {
    const k = kit({ engine: engineOf({ render: RENDER, renderDigest: 'R'.repeat(43) }) });
    const { adm, id } = await k.opened(true);
    const rec = (await k.store.get(id))!;
    expect(rec.action).toStrictEqual({ verb: VERB, resource: RES, params_digest: adm.pcactn.action.params_digest, def_digest: D1 });
    expect(rec.render_digest).toBe('R'.repeat(43));
    expect(rec.receipts.map((r) => [r.event, r.note])).toEqual([['opened', 'converted']]);
    expect(k.notices).toHaveLength(1);
    expect(k.notices[0]!.render).toEqual(RENDER);
    const plain = kit();
    const o2 = await plain.opened(false);
    const r2 = (await plain.store.get(o2.id))!;
    expect('render_digest' in r2).toBe(false);
    expect(r2.receipts.map((r) => [r.event, r.note])).toEqual([['opened', '']]);
    expect('render' in plain.notices[0]!).toBe(false);
  });

  it('opening the same admission again returns the same window without a second notice', async () => {
    const k = kit();
    const adm = await k.admitted();
    const a = await k.undo.open(adm);
    const b = await k.undo.open(adm);
    expect(b).toEqual(a);
    expect(kinds(k.notices)).toEqual(['opened']);
  });

  it('the same id with other terms, or in another state, is refused by name', async () => {
    const k = kit();
    const adm = await k.admitted();
    await k.undo.open(adm);
    const other: UndoAdmission = { ...adm, compensation: { ...adm.compensation, params: { box: 'box9' } } };
    expect((await rejection(k.undo.open(other))).message).toBe(ERR('invalid', `undo record ${adm.id} already exists with other terms or state open`));
    await k.undo.veto(adm.id, { operator: 'ops' });
    expect((await rejection(k.undo.open(adm))).message).toBe(ERR('invalid', `undo record ${adm.id} already exists with other terms or state vetoed`));
  });

  it('a notice that is not delivered aborts the window, alerts with the reason and refuses with it', async () => {
    const mute = new Error();
    Object.defineProperty(mute, 'message', { value: undefined });
    const cases: [UndoCoordinatorOptions['notifier']['notify'], string][] = [
      [async () => ({ delivered: false }), 'no channel delivered the notice'],
      [async () => undefined as never, 'no channel delivered the notice'],
      [async () => ({ delivered: false, reason: 'channel down' }), 'channel down'],
      [
        async () => {
          throw new Error('smtp down');
        },
        'smtp down',
      ],
      [
        async () => {
          throw 'not an error';
        },
        'notifier error',
      ],
      [
        async () => {
          throw mute;
        },
        'not delivered',
      ],
    ];
    for (const [notify, reason] of cases) {
      const k = kit({ notifier: { notify } });
      const adm = await k.admitted();
      expect([reason, (await rejection(k.undo.open(adm))).message]).toEqual([reason, ERR('invalid', `notify_failed: the undo window could not be announced (${reason})`)]);
      expect(k.alerts).toEqual([{ level: 'critical', code: 'notify_failed', record: adm.id, reason: `the principal could not be told about the undo window: ${reason}` }]);
      const rec = (await k.store.get(adm.id))!;
      expect([rec.state, rec.outcome?.status, rec.outcome?.reason]).toEqual(['finalized', 'aborted', 'notify_failed']);
    }
  });

  it('an alert sink that throws is written to the error console instead', async () => {
    const k = kit({
      deliver: false,
      alert: () => {
        throw new Error('pager down');
      },
    });
    const adm = await k.admitted();
    const seen: unknown[][] = [];
    const orig = console.error;
    console.error = (...a: unknown[]) => void seen.push(a);
    try {
      await rejection(k.undo.open(adm));
    } finally {
      console.error = orig;
    }
    expect(seen).toEqual([[`pca undo alert (notify_failed) for ${adm.id}: the principal could not be told about the undo window: channel down`]]);
  });
});

describe('ledger writes', () => {
  it('get returns the stored record', async () => {
    const k = kit();
    const { id } = await k.opened();
    expect(await k.undo.get(id)).toEqual(await k.store.get(id));
    expect((await k.undo.get(id))?.id).toBe(id);
  });

  it('an unknown record and a refused transition are refused by name', async () => {
    const k = kit();
    expect((await rejection(k.undo.recordEffect('nope', { id: 'x' }))).message).toBe(ERR('invalid', 'unknown: no undo record nope'));
    const { id } = await k.opened();
    k.clock.t = NOW + WINDOW + 1;
    expect(await k.undo.finalizeDue()).toEqual([id]);
    expect((await k.undo.recordEffect(id, { id: 'x' }).catch((e: Error) => e.message))).toBe(ERR('invalid', 'finalized: a finalized record takes no effect report'));
  });

  it('a record that keeps changing gives up after exactly 64 compare-and-swap attempts', async () => {
    const k = kit();
    const { id } = await k.opened();
    k.store.replaceCalls = 0;
    k.store.failReplaces = 64;
    expect((await rejection(k.undo.recordEffect(id, { id: 'x' }))).message).toBe(ERR('conflict_exhausted', `undo record ${id} kept changing`));
    expect(k.store.replaceCalls).toBe(64);
    expect((await k.store.get(id))?.effect).toBeUndefined();
    k.store.replaceCalls = 0;
    k.store.failReplaces = 64;
    expect((await rejection(k.undo.holdBudget(id, [{ key: 'k', id }]))).message).toBe(ERR('conflict_exhausted', `undo record ${id} kept changing`));
    expect(k.store.replaceCalls).toBe(64);
    expect((await k.store.get(id))?.budget).toBeUndefined();
  });

  it('holdBudget: unknown and closed records are refused by name; open and vetoed ones take reservations, one version up', async () => {
    const k = kit();
    expect((await rejection(k.undo.holdBudget('nope', []))).message).toBe(ERR('invalid', 'no undo record nope'));
    const { id } = await k.opened();
    const v0 = (await k.store.get(id))!.ver;
    const r1 = await k.undo.holdBudget(id, [{ key: 'a', id: 'r1', extra: 1 } as { key: string; id: string }]);
    expect(r1.budget).toStrictEqual([{ key: 'a', id: 'r1' }]);
    expect(r1.ver).toBe(v0 + 1);
    await k.undo.veto(id, { operator: 'ops' });
    const v1 = (await k.store.get(id))!.ver;
    const r2 = await k.undo.holdBudget(id, [{ key: 'b', id: 'r2' }]);
    expect(r2.budget).toStrictEqual([{ key: 'a', id: 'r1' }, { key: 'b', id: 'r2' }]);
    expect(r2.ver).toBe(v1 + 1);
    expect(await k.store.get(id)).toEqual(r2);
    const f = kit();
    const o = await f.opened();
    f.clock.t = NOW + WINDOW + 1;
    await f.undo.finalizeDue();
    expect((await rejection(f.undo.holdBudget(o.id, []))).message).toBe(ERR('invalid', 'a finalized record holds no budget'));
  });

  it('abort releases the held budget once; a replayed abort releases nothing', async () => {
    const log: string[] = [];
    const ledger = {
      durable: true,
      commit: async (k: string, i: string) => (log.push(`commit ${k} ${i}`), { outcome: 'settled' as const, version: 1 }),
      release: async (k: string, i: string) => (log.push(`release ${k} ${i}`), { outcome: 'settled' as const, version: 1 }),
    };
    const k = kit({ budget: { ledger: ledger as never } });
    const { id } = await k.opened();
    await k.undo.holdBudget(id, [{ key: 'o', id }]);
    const a = await k.undo.abort(id, 'effect_failed');
    const b = await k.undo.abort(id, 'effect_failed');
    expect(b).toEqual(a);
    expect(log).toEqual([`release o ${id}`]);
  });
});

describe('budget settlement', () => {
  const ledgerOf = (outcome: () => { outcome: string; version: number }) => {
    const log: unknown[][] = [];
    const ledger = {
      durable: true,
      commit: async (k: string, i: string) => (log.push(['commit', k, i]), outcome()),
      release: async (k: string, i: string, e?: unknown) => (log.push(['release', k, i, e]), outcome()),
    };
    return { log, ledger: ledger as never };
  };

  it('settled and replayed are quiet; any other outcome raises a warning that names it', async () => {
    for (const o of ['settled', 'replayed']) {
      const b = ledgerOf(() => ({ outcome: o, version: 1 }));
      const k = kit({ budget: { ledger: b.ledger } });
      const { id } = await k.opened();
      await k.undo.recordEffect(id, { id: 'd' });
      await k.undo.holdBudget(id, [{ key: 'p', id }]);
      k.clock.t = NOW + WINDOW + 1;
      expect(await k.undo.finalizeDue()).toEqual([id]);
      expect([o, k.alerts]).toEqual([o, []]);
      expect(b.log).toEqual([['commit', 'p', id]]);
    }
    const b = ledgerOf(() => ({ outcome: 'unknown', version: 1 }));
    const k = kit({ budget: { ledger: b.ledger } });
    const { id } = await k.opened();
    await k.undo.recordEffect(id, { id: 'd' });
    await k.undo.holdBudget(id, [{ key: 'p', id }]);
    k.clock.t = NOW + WINDOW + 1;
    await k.undo.finalizeDue();
    expect(k.alerts).toEqual([{ level: 'warning', code: 'budget_settle_failed', record: id, reason: `commit of p/${id}: unknown` }]);
  });

  it('a ledger that throws raises a warning with its message (or "error"); the evidence hook is optional', async () => {
    for (const [err, text] of [[new Error('db down'), 'db down'], ['not an error', 'error']] as const) {
      const ledger = {
        durable: true,
        commit: async () => ({ outcome: 'settled' as const, version: 1 }),
        release: async () => {
          throw err;
        },
      };
      const k = kit({ budget: { ledger: ledger as never } });
      const { id } = await k.opened();
      await k.undo.holdBudget(id, [{ key: 'p', id }]);
      await k.undo.abort(id, 'effect_failed');
      expect(k.alerts).toEqual([{ level: 'warning', code: 'budget_settle_failed', record: id, reason: `effect_not_run of p/${id}: ${text}` }]);
    }
    const b = ledgerOf(() => ({ outcome: 'settled', version: 1 }));
    const k = kit({ budget: { ledger: b.ledger } });
    const { id } = await k.opened();
    await k.undo.holdBudget(id, [{ key: 'p', id }]);
    await k.undo.abort(id, 'effect_failed');
    expect(b.log).toEqual([['release', 'p', id, undefined]]);
    expect(k.alerts).toEqual([]);
    const seen: unknown[] = [];
    const e = kit({ budget: { ledger: b.ledger, evidence: (r, how) => (seen.push([r, how]), undefined) } });
    const o = await e.opened();
    await e.undo.holdBudget(o.id, [{ key: 'q', id: 'x1' }]);
    await e.undo.abort(o.id, 'effect_failed');
    expect(seen).toEqual([[{ key: 'q', id: 'x1' }, 'effect_not_run']]);
  });

  it('nothing is settled for a record without reservations, or without a budget ledger', async () => {
    const b = ledgerOf(() => ({ outcome: 'settled', version: 1 }));
    const k = kit({ budget: { ledger: b.ledger } });
    const { id } = await k.opened();
    k.clock.t = NOW + WINDOW + 1;
    expect(await k.undo.finalizeDue()).toEqual([id]);
    expect(b.log).toEqual([]);
    const n = kit();
    const o = await n.opened();
    await n.undo.holdBudget(o.id, [{ key: 'p', id: o.id }]);
    n.clock.t = NOW + WINDOW + 1;
    expect(await n.undo.finalizeDue()).toEqual([o.id]);
    expect((await n.store.get(o.id))?.state).toBe('finalized');
  });
});

describe('veto', () => {
  it('an unknown record, a refused token and a malformed operator are refused by name', async () => {
    const k = kit();
    const { id, info } = await k.opened();
    expect(await k.undo.veto('nope', { token: info.token })).toEqual({ ok: false, code: 'unknown', reason: 'no undo record nope' });
    expect(await k.undo.veto(id, { token: 'not-a-token' })).toEqual({ ok: false, code: 'malformed', reason: 'the undo token was refused (malformed)' });
    for (const operator of ['', 5]) expect(await k.undo.veto(id, { operator: operator as never })).toEqual({ ok: false, code: 'malformed', reason: 'an operator veto names the operator' });
    expect((await k.store.get(id))?.state).toBe('open');
  });

  it('an already decoded token object is accepted as is', async () => {
    const k = kit();
    const { id, info } = await k.opened();
    const v = await k.undo.veto(id, { token: decodeUndoToken(info.token) });
    expect(v.ok && v.record.veto?.via).toBe('token');
  });

  it('a relayed veto time is accepted from the opening to now inclusive, and only as a safe integer', async () => {
    const reason = 'a relayed veto time must lie between the opening of the window and now';
    const atNow = kit();
    const a = await atNow.opened();
    atNow.clock.t = NOW + 60_000;
    expect((await atNow.undo.veto(a.id, { token: a.info.token, at: NOW + 60_000 })).ok).toBe(true);
    const atOpen = kit();
    const b = await atOpen.opened();
    atOpen.clock.t = NOW + 60_000;
    const vb = await atOpen.undo.veto(b.id, { token: b.info.token, at: NOW });
    expect(vb.ok && vb.record.veto?.at).toBe(NOW);
    const frac = kit();
    const c = await frac.opened();
    frac.clock.t = NOW + 60_000;
    expect(await frac.undo.veto(c.id, { token: c.info.token, at: NOW + 0.5 })).toEqual({ ok: false, code: 'malformed', reason });
    expect(await frac.undo.veto(c.id, { token: c.info.token, at: NOW + 60_001 })).toEqual({ ok: false, code: 'malformed', reason });
    expect(await frac.undo.veto(c.id, { token: c.info.token, at: NOW - 1 })).toEqual({ ok: false, code: 'malformed', reason });
  });

  it('negative zero is refused even for a window opened at time zero, where zero itself is accepted', async () => {
    const reason = 'a relayed veto time must lie between the opening of the window and now';
    const k = kit({ resolveTarget: () => 't1' });
    const { id, info } = await k.opened();
    await k.store.patch(id, { opened_at: 0 });
    expect(await k.undo.veto(id, { token: info.token, at: -0 })).toEqual({ ok: false, code: 'malformed', reason });
    const v = await k.undo.veto(id, { token: info.token, at: 0 });
    expect(v.ok && v.record.veto?.at).toBe(0);
  });

  it('a replayed veto sends no second notice', async () => {
    const k = kit();
    const { id, info } = await k.opened();
    await k.undo.recordEffect(id, { id: 'd_1' });
    await k.undo.veto(id, { token: info.token });
    const again = await k.undo.veto(id, { operator: 'ops' });
    expect(again.ok && again.replayed).toBe(true);
    expect(kinds(k.notices)).toEqual(['opened', 'vetoed', 'compensated']);
  });

  it('an error inside a veto is a malformed refusal with its message (or "unknown")', async () => {
    for (const [err, text] of [[new Error('db down'), 'db down'], ['not an error', 'unknown']] as const) {
      const k = kit();
      k.store.getError = err;
      expect(await k.undo.veto('any', { operator: 'ops' })).toEqual({ ok: false, code: 'malformed', reason: `veto error (fail closed): ${text}` });
    }
  });
});

describe('compensation', () => {
  it('runs once with the exact call, op record and outcome', async () => {
    const k = kit();
    const { id, info } = await k.opened();
    await k.undo.recordEffect(id, { id: 'd_1' });
    k.clock.t = NOW + 60_000;
    const v = await k.undo.veto(id, { token: info.token });
    expect(v.ok && v.record.state).toBe('compensated');
    const opId = k.opIdOf(id);
    expect(k.calls).toHaveLength(1);
    const c = k.calls[0]!;
    expect(c.operation).toStrictEqual({ verb: COMP, resource: RES, params: { box: 'box1', draft: 'd_1' } });
    expect([c.idempotencyKey, c.undoOf, c.originalResult]).toEqual([opId, id, { id: 'd_1' }]);
    expect('pcactn' in c.record).toBe(false);
    expect([c.record.id, c.record.state, c.record.receipts.map((r) => r.event)]).toEqual([id, 'vetoed', ['opened', 'effect', 'vetoed']]);
    expect(await k.operations.get(opId)).toStrictEqual({ id: opId, state: 'committed', verb: COMP, resource: RES, params_digest: hashCanonical({ box: 'box1', draft: 'd_1' }), reversibility: 'irreversible', startedAt: NOW + 60_000, executingAt: NOW + 60_000, result: { deleted: 'd_1' }, finishedAt: NOW + 60_000 });
    expect((await k.store.get(id))?.outcome?.result).toEqual({ deleted: 'd_1' });
  });

  it('a compensator that returns nothing leaves no result on the outcome', async () => {
    const k = kit({ result: undefined });
    const { id } = await k.opened();
    await k.undo.recordEffect(id, { id: 'd_1' });
    await k.undo.veto(id, { operator: 'ops' });
    const rec = (await k.store.get(id))!;
    expect(rec.state).toBe('compensated');
    expect('result' in rec.outcome!).toBe(false);
  });

  it('a failing compensator: the op record is failed with the error, the outcome names it', async () => {
    for (const [err, text] of [[true, 'downstream refused'], ['plain text', 'plain text']] as const) {
      const k = kit({ fail: () => err });
      const { id } = await k.opened();
      await k.undo.recordEffect(id, { id: 'd_1' });
      await k.undo.veto(id, { operator: 'ops' });
      const rec = (await k.store.get(id))!;
      expect([rec.state, rec.outcome?.reason]).toEqual(['compensation_failed', `the compensating action failed: ${text}`]);
      expect(await k.operations.get(k.opIdOf(id))).toMatchObject({ state: 'failed', error: text, finishedAt: NOW });
      expect(k.alerts).toEqual([{ level: 'critical', code: 'compensation_failed', record: id, reason: `the compensating action failed: ${text}` }]);
    }
  });

  it('the target comes from a non-empty string result id only; without a target parameter none is added', async () => {
    const reason = "the target 'draft' of the compensation is unknown (no effect result names it)";
    for (const result of [{ id: 7 }, { id: '' }, null]) {
      const k = kit();
      const { id } = await k.opened();
      await k.undo.recordEffect(id, result);
      await k.undo.veto(id, { operator: 'ops' });
      const rec = (await k.store.get(id))!;
      expect([JSON.stringify(result), rec.state, rec.outcome?.reason]).toEqual([JSON.stringify(result), 'compensation_failed', reason]);
      expect(k.calls).toHaveLength(0);
    }
    const n = kit({ engine: engineOf({ target: false }) });
    const { id } = await n.opened();
    await n.undo.recordEffect(id, { id: 'd_1' });
    await n.undo.veto(id, { operator: 'ops' });
    expect(n.calls[0]!.operation.params).toStrictEqual({ box: 'box1' });
  });

  it('an effect reported without a result passes no original result', async () => {
    const k = kit({ resolveTarget: () => 't1' });
    const { id } = await k.opened();
    await k.undo.recordEffect(id);
    await k.undo.veto(id, { operator: 'ops' });
    expect(k.calls).toHaveLength(1);
    expect('originalResult' in k.calls[0]!).toBe(false);
    expect(k.calls[0]!.operation.params).toStrictEqual({ box: 'box1', draft: 't1' });
  });

  it('waits for the effect report for the default five minutes exactly, then compensates anyway', async () => {
    const k = kit({ resolveTarget: () => 't1' });
    const { id } = await k.opened();
    await k.undo.veto(id, { operator: 'ops' });
    k.clock.t = NOW + 1;
    expect((await k.undo.compensate(id)).state).toBe('vetoed');
    k.clock.t = NOW + 5 * 60_000 - 1;
    expect((await k.undo.compensate(id)).state).toBe('vetoed');
    expect(k.calls).toHaveLength(0);
    k.clock.t = NOW + 5 * 60_000;
    expect((await k.undo.compensate(id)).state).toBe('compensated');
    expect(k.calls).toHaveLength(1);
    expect('originalResult' in k.calls[0]!).toBe(false);
  });

  it('a vetoed record without a veto entry waits for its effect report', async () => {
    const k = kit();
    const { id } = await k.opened();
    await k.store.patch(id, { state: 'vetoed', veto: undefined });
    k.clock.t = NOW + 60 * 60_000;
    expect((await k.undo.compensate(id)).state).toBe('vetoed');
    expect(k.calls).toHaveLength(0);
  });

  it('compensate: an unknown record is refused; an open record is left alone even with an effect', async () => {
    const k = kit();
    expect((await rejection(k.undo.compensate('nope'))).message).toBe(ERR('invalid', 'no undo record nope'));
    const { id } = await k.opened();
    await k.undo.recordEffect(id, { id: 'd_1' });
    k.clock.t = NOW + 60 * 60_000;
    expect((await k.undo.compensate(id)).state).toBe('open');
    expect(k.calls).toHaveLength(0);
  });

  it('an unknown grant at veto time is denied with the exact reason', async () => {
    let known = true;
    const k = kit({ resolveGrant: async (ref) => (known && ref === k.grant.id ? k.grant : null) });
    const { id } = await k.opened();
    await k.undo.recordEffect(id, { id: 'd_1' });
    known = false;
    await k.undo.veto(id, { operator: 'ops' });
    const reason = 'the grant is no longer known: the compensation cannot be authorized';
    expect((await k.store.get(id))?.outcome?.reason).toBe(reason);
    expect(k.alerts).toEqual([{ level: 'critical', code: 'compensation_denied', record: id, reason }]);
    expect(kinds(k.notices)).toEqual(['opened', 'vetoed', 'compensation_failed']);
  });

  it('the compensation is decided again at veto time: a grant that no longer permits it is denied, nothing runs', async () => {
    let swap: Capability | undefined;
    const k = kit({ resolveGrant: async (ref) => swap ?? (ref === k.grant.id ? k.grant : null) });
    const { id } = await k.opened();
    await k.undo.recordEffect(id, { id: 'd_1' });
    swap = kit({ preds: [{ verb: [VERB], resource: '*' }] }).grant;
    await k.undo.veto(id, { operator: 'ops' });
    const rec = (await k.store.get(id))!;
    expect(rec.state).toBe('compensation_failed');
    expect(rec.outcome?.reason?.startsWith('the compensating action is not authorized under the grant: ')).toBe(true);
    expect(k.alerts.map((a) => [a.level, a.code, a.record, a.reason])).toEqual([['critical', 'compensation_denied', id, rec.outcome?.reason]]);
    expect(k.calls).toHaveLength(0);
  });
});

describe('the once-per-attempt record', () => {
  const pre = async (k: ReturnType<typeof kit>, id: string, r: Partial<OperationRecord>, attempt = 0) =>
    k.operations.create({ id: k.opIdOf(id, attempt), state: 'pending', verb: COMP, resource: RES, params_digest: 'x', reversibility: 'irreversible', startedAt: NOW, ...r });

  it('a committed attempt is adopted: compensated with its result, nothing runs again', async () => {
    const k = kit();
    const { id } = await k.opened();
    await k.undo.recordEffect(id, { id: 'd_1' });
    await pre(k, id, { state: 'committed', result: { r: 1 } });
    const v = await k.undo.veto(id, { operator: 'ops' });
    expect(v.ok && v.record.state).toBe('compensated');
    expect((await k.store.get(id))?.outcome?.result).toEqual({ r: 1 });
    expect(k.calls).toHaveLength(0);
    expect(kinds(k.notices)).toEqual(['opened', 'vetoed', 'compensated']);
  });

  it('a failed or uncertain attempt fails the compensation with its state and error', async () => {
    for (const [state, error, want] of [
      ['failed', 'boom', 'compensation attempt 0 failed: boom'],
      ['failed', undefined, 'compensation attempt 0 failed: '],
      ['uncertain', 'lost', 'compensation attempt 0 uncertain: lost'],
    ] as const) {
      const k = kit();
      const { id } = await k.opened();
      await k.undo.recordEffect(id, { id: 'd_1' });
      await pre(k, id, { state, ...(error !== undefined ? { error } : {}) });
      await k.undo.veto(id, { operator: 'ops' });
      const rec = (await k.store.get(id))!;
      expect([rec.state, rec.outcome?.reason]).toEqual(['compensation_failed', want]);
      expect(k.calls).toHaveLength(0);
    }
  });

  it('an aborted attempt is closed as never started and retried under the next attempt', async () => {
    const k = kit();
    const { id } = await k.opened();
    await k.undo.recordEffect(id, { id: 'd_1' });
    await pre(k, id, { state: 'aborted' });
    await k.undo.veto(id, { operator: 'ops' });
    const rec = (await k.store.get(id))!;
    expect(rec.receipts.map((r) => [r.event, r.note])).toEqual([
      ['opened', ''],
      ['effect', ''],
      ['vetoed', 'operator'],
      ['compensation_failed', 'attempt never started'],
      ['retried', ''],
      ['compensated', ''],
    ]);
    expect([rec.state, rec.attempt, k.calls.length]).toEqual(['compensated', 1, 1]);
  });

  it('an aborted attempt whose retry is refused stays failed', async () => {
    const k = kit();
    const { id } = await k.opened();
    await k.undo.recordEffect(id, { id: 'd_1' });
    await k.store.patch(id, { state: 'vetoed', veto: { at: NOW, via: 'operator', by: 'ops' }, attempt: -1 });
    await pre(k, id, { state: 'aborted' }, -1);
    const out = await k.undo.compensate(id);
    expect([out.state, out.outcome?.reason]).toEqual(['compensation_failed', 'attempt never started']);
    expect(k.calls).toHaveLength(0);
  });

  it('a pending or executing attempt is left to its holder until it is older than the effect timeout', async () => {
    const k = kit({ effectTimeoutMs: 1_000 });
    const { id } = await k.opened();
    await k.undo.recordEffect(id, { id: 'd_1' });
    await pre(k, id, { state: 'pending', startedAt: NOW });
    await k.undo.veto(id, { operator: 'ops' });
    k.clock.t = NOW + 1_000;
    expect((await k.undo.compensate(id)).state).toBe('vetoed');
    expect((await k.operations.get(k.opIdOf(id)))?.state).toBe('pending');
    k.clock.t = NOW + 1_001;
    const done = await k.undo.compensate(id);
    expect([done.state, done.attempt]).toEqual(['compensated', 1]);
    expect(await k.operations.get(k.opIdOf(id))).toMatchObject({ state: 'aborted', error: 'never started', finishedAt: NOW + 1_001 });
    const x = kit({ effectTimeoutMs: 1_000 });
    const o = await x.opened();
    await x.undo.recordEffect(o.id, { id: 'd_1' });
    await pre(x, o.id, { state: 'executing', startedAt: NOW - 10_000, executingAt: NOW });
    x.clock.t = NOW + 1_000;
    await x.undo.veto(o.id, { operator: 'ops' });
    expect((await x.store.get(o.id))?.state).toBe('vetoed');
    x.clock.t = NOW + 1_001;
    const out = await x.undo.compensate(o.id);
    expect([out.state, out.outcome?.reason]).toEqual(['compensation_failed', 'compensation attempt 0 uncertain: no outcome recorded: the compensation may or may not have run']);
    expect(x.calls).toHaveLength(0);
  });

  it('after settling a stale attempt the record is read again', async () => {
    const j = kit({ effectTimeoutMs: 1_000, hooks: {} });
    const o = await j.opened();
    await j.undo.recordEffect(o.id, { id: 'd_1' });
    await pre(j, o.id, { state: 'pending', startedAt: NOW - 5_000 });
    j.hooks.onTransition = async (_id, from, next) => {
      if (from === 'pending' && next.state === 'aborted') await j.store.patch(o.id, { state: 'finalized' });
      return undefined;
    };
    const v = await j.undo.veto(o.id, { operator: 'ops' });
    expect(v.ok && v.record.state).toBe('finalized');
    expect(j.calls).toHaveLength(0);
  });
});

describe('races around the compensation', () => {
  it('the record moved on after the attempt was claimed: the attempt is aborted and the current record returned', async () => {
    const moves: [string, (k: ReturnType<typeof kit>, id: string) => Promise<unknown>, string, number][] = [
      ['state', (k, id) => k.store.patch(id, { state: 'compensation_failed' }), 'compensation_failed', 0],
      ['attempt', (k, id) => k.store.patch(id, { attempt: 1 }), 'vetoed', 1],
      [
        'gone',
        async (k) => {
          k.store.hide = true;
        },
        'vetoed',
        0,
      ],
    ];
    for (const [name, move, state, attempt] of moves) {
      const k = kit({ hooks: {} });
      const { id } = await k.opened();
      await k.undo.recordEffect(id, { id: 'd_1' });
      k.hooks.onCreate = () => move(k, id);
      const v = await k.undo.veto(id, { operator: 'ops' });
      expect([name, v.ok && v.record.state, v.ok && v.record.attempt]).toEqual([name, state, attempt]);
      expect(k.calls).toHaveLength(0);
      expect(await k.operations.get(k.opIdOf(id))).toMatchObject({ id: k.opIdOf(id), state: 'aborted', error: 'the undo record moved on', finishedAt: NOW });
    }
  });

  it('an attempt that cannot be moved to executing returns the current record and runs nothing', async () => {
    const k = kit({ hooks: {} });
    const { id } = await k.opened();
    await k.undo.recordEffect(id, { id: 'd_1' });
    k.hooks.onTransition = async (_i, from, next) => {
      if (from === 'pending' && next.state === 'executing') {
        await k.store.patch(id, { state: 'compensation_failed' });
        return false;
      }
      return undefined;
    };
    const v = await k.undo.veto(id, { operator: 'ops' });
    expect(v.ok && v.record.state).toBe('compensation_failed');
    expect(k.calls).toHaveLength(0);
  });

  it('a record resolved elsewhere while the compensator ran is returned as stored', async () => {
    let k!: ReturnType<typeof kit>;
    k = kit({
      compensate: async (c) => {
        k.calls.push(c);
        await k.store.patch(c.undoOf, { state: 'finalized' });
        return 1;
      },
    });
    const { id } = await k.opened();
    await k.undo.recordEffect(id, { id: 'd_1' });
    const v = await k.undo.veto(id, { operator: 'ops' });
    expect(v.ok && v.record.state).toBe('finalized');
    expect(kinds(k.notices)).toEqual(['opened', 'vetoed']);
  });

  it('a failure that cannot be written returns the stored record and raises nothing', async () => {
    for (const [moved, want] of [['finalized', 'finalized'], ['compensation_failed', 'compensation_failed']] as const) {
      let at = 0;
      let k!: ReturnType<typeof kit>;
      k = kit({
        resolveGrant: async () => {
          if (++at === 2) {
            await k.store.patch(k.notices[0]!.record.id, { state: moved });
            return null;
          }
          return k.grant;
        },
      });
      const { id } = await k.opened();
      await k.undo.recordEffect(id, { id: 'd_1' });
      const v = await k.undo.veto(id, { operator: 'ops' });
      expect([moved, v.ok && v.record.state]).toEqual([moved, want]);
      expect(k.alerts).toEqual([]);
      expect(kinds(k.notices)).toEqual(['opened', 'vetoed']);
    }
  });

  it('a committed attempt whose result cannot be written keeps the record as read: no rollback, no notice', async () => {
    const log: string[] = [];
    const ledger = { durable: true, commit: async () => ({ outcome: 'settled' as const, version: 1 }), release: async (_k: string, i: string) => (log.push(i), { outcome: 'settled' as const, version: 1 }) };
    let at = 0;
    let k!: ReturnType<typeof kit>;
    k = kit({
      budget: { ledger: ledger as never },
      resolveGrant: async () => {
        if (++at === 2) await k.store.patch(k.notices[0]!.record.id, { state: 'finalized' });
        return k.grant;
      },
    });
    const { id } = await k.opened();
    await k.undo.recordEffect(id, { id: 'd_1' });
    await k.undo.holdBudget(id, [{ key: 'o', id }]);
    await k.operations.create({ id: k.opIdOf(id), state: 'committed', verb: COMP, resource: RES, params_digest: 'x', reversibility: 'irreversible', startedAt: NOW, result: 1 });
    const v = await k.undo.veto(id, { operator: 'ops' });
    expect(v.ok && v.record.state).toBe('vetoed');
    expect(log).toEqual([]);
    expect(kinds(k.notices)).toEqual(['opened', 'vetoed']);
  });

  it('an aborted attempt whose failure cannot be written returns the record as read', async () => {
    let at = 0;
    let k!: ReturnType<typeof kit>;
    k = kit({
      resolveGrant: async () => {
        if (++at === 2) await k.store.patch(k.notices[0]!.record.id, { state: 'finalized' });
        return k.grant;
      },
    });
    const { id } = await k.opened();
    await k.undo.recordEffect(id, { id: 'd_1' });
    await k.operations.create({ id: k.opIdOf(id), state: 'aborted', verb: COMP, resource: RES, params_digest: 'x', reversibility: 'irreversible', startedAt: NOW });
    const v = await k.undo.veto(id, { operator: 'ops' });
    expect(v.ok && v.record.state).toBe('vetoed');
    expect(k.calls).toHaveLength(0);
  });
});

describe('relay, sweeps and recovery', () => {
  it('syncRelay: no relay or an empty one gives []; a non-list is refused; entries without a string id are skipped', async () => {
    const k = kit();
    expect(await k.undo.syncRelay()).toEqual([]);
    const empty = kit({ relay: { pending: async () => [] } });
    expect(await empty.undo.syncRelay()).toEqual([]);
    const bad = kit({ relay: { pending: async () => ({}) as never } });
    expect((await rejection(bad.undo.syncRelay())).message).toBe(ERR('invalid', 'the veto relay returned no list'));
    let list: unknown[] = [];
    const r = kit({ relay: { pending: async () => list as never } });
    const { id, info } = await r.opened();
    list = [null, { id: 5, token: info.token, at: NOW }, { id, token: info.token, at: NOW }];
    const out = await r.undo.syncRelay();
    expect(out).toHaveLength(1);
    expect(out[0]!.ok && out[0]!.record.id).toBe(id);
  });

  it('a relay that cannot be read raises one critical alert with its message (or "error")', async () => {
    for (const [err, text] of [[new Error('relay down'), 'relay down'], ['not an error', 'error']] as const) {
      const k = kit({
        relay: {
          pending: async () => {
            throw err;
          },
        },
      });
      expect(await k.undo.finalizeDue()).toEqual([]);
      expect(k.alerts).toEqual([{ level: 'critical', code: 'veto_relay_failed', record: '*', reason: `the veto relay could not be read; no window was finalized: ${text}` }]);
    }
  });

  it('finalizeDue: a window without an effect report raises effect_unknown; one with an effect does not; both are notified', async () => {
    const k = kit();
    const { id } = await k.opened();
    k.clock.t = NOW + WINDOW + 1;
    expect(await k.undo.finalizeDue()).toEqual([id]);
    expect(k.alerts).toEqual([{ level: 'warning', code: 'effect_unknown', record: id, reason: 'the window closed without an effect report: reconcile the original operation' }]);
    expect(kinds(k.notices)).toEqual(['opened', 'finalized']);
    expect(k.notices[1]!.record.state).toBe('finalized');
    expect('pcactn' in k.notices[1]!.record).toBe(false);
    const e = kit();
    const o = await e.opened();
    await e.undo.recordEffect(o.id, { id: 'd' });
    e.clock.t = NOW + WINDOW + 1;
    expect(await e.undo.finalizeDue()).toEqual([o.id]);
    expect(e.alerts).toEqual([]);
  });

  it('finalizeDue skips a listed window that another worker already closed or vetoed', async () => {
    for (const moved of ['finalized', 'vetoed'] as const) {
      const k = kit();
      const { id } = await k.opened();
      k.clock.t = NOW + WINDOW + 1;
      const stale = (await k.store.get(id))!;
      await k.store.patch(id, moved === 'finalized' ? { state: 'finalized', outcome: { at: NOW, status: 'finalized' } } : { state: 'vetoed', veto: { at: NOW, via: 'operator', by: 'ops' } });
      k.store.listHook = (q) => (q.state === 'open' ? [stale] : undefined);
      expect([moved, await k.undo.finalizeDue()]).toEqual([moved, []]);
      expect(k.alerts).toEqual([]);
      expect(kinds(k.notices)).toEqual(['opened']);
    }
  });

  it('recover reports only records it resolved, plus the windows it finalized', async () => {
    const k = kit();
    expect(await k.undo.recover()).toEqual([]);
    const { id } = await k.opened();
    await k.undo.veto(id, { operator: 'ops' });
    expect(await k.undo.recover()).toEqual([]);
    expect((await k.store.get(id))?.state).toBe('vetoed');
    await k.store.patch(id, { effect: { at: NOW, result: { id: 'd_1' } } });
    expect(await k.undo.recover()).toEqual([id]);
    expect((await k.store.get(id))?.state).toBe('compensated');
    const f = kit();
    const o = await f.opened();
    f.clock.t = NOW + WINDOW + 1;
    expect(await f.undo.recover()).toEqual([o.id]);
  });

  it('revocation: the policy is asked about the action; keep alerts by name; a veto that is refused is not reported', async () => {
    const seen: PcaOperation[] = [];
    const k = kit({ policy: (op) => (seen.push(op), undefined) });
    const { id } = await k.opened();
    seen.length = 0;
    expect(await k.undo.onRevocation(k.grant.id)).toEqual([]);
    expect(seen).toStrictEqual([{ verb: VERB, resource: RES }]);
    expect(k.alerts).toEqual([{ level: 'warning', code: 'revoked_open_window', record: id, reason: `grant ${k.grant.id} was revoked while this window is open; the principal can still undo it` }]);
    const v = kit({ policy: () => ({ onRevocation: 'veto' }) });
    const o = await v.opened();
    v.clock.t = NOW + WINDOW + 1;
    expect(await v.undo.onRevocation(v.grant.id)).toEqual([]);
    expect((await v.store.get(o.id))?.state).toBe('open');
  });

  it('a slash: the fraud-proof evidence binds the settlement; a bond reference finds its record; unknown and late slashes', async () => {
    const k = kit();
    const adm = await k.admitted();
    const info = await k.undo.open(adm, { bond: { ref: 'bond-7', challengeEndsAt: NOW + 1_000 } });
    await k.undo.recordEffect(info.id, { id: 'd_1' });
    const settlement = { action: 'slash', n: 1 } as never;
    const s = await k.undo.rollbackOnSlash({ slashBond: async () => settlement }, { claimId: 'bond-7' });
    expect(s.veto.ok && s.veto.record.state).toBe('compensated');
    expect((await k.store.get(info.id))?.veto).toEqual({ at: NOW, via: 'fraud_proof', by: 'bond-7', evidence: hashCanonical({ d: 'atlas-pca/undo-slash-ref/v1', settlement }) });
    expect(k.alerts).toEqual([]);
    expect(await k.undo.rollbackOnSlash({ slashBond: async () => settlement }, { claimId: 'nope' })).toEqual({ settlement, veto: { ok: false, code: 'unknown', reason: 'no undo record for bond nope' } });
    const late = kit();
    const o = await late.opened();
    late.clock.t = NOW + WINDOW + 1;
    await late.undo.finalizeDue();
    late.alerts.length = 0;
    const r = await late.undo.rollbackOnSlash({ slashBond: async () => settlement }, { claimId: o.id });
    expect(r.veto).toEqual({ ok: false, code: 'finalized', reason: 'the window is closed and the action is final' });
    expect(late.alerts).toEqual([{ level: 'critical', code: 'slash_after_window', record: o.id, reason: 'the bond was slashed but the effect could not be rolled back: the window is closed and the action is final' }]);
  });
});

describe('reportUndoEffect', () => {
  it('committed records the effect; failed, aborted and refused abort with the status; anything else leaves the window', async () => {
    const k = kit();
    const a = await k.opened();
    const c = await reportUndoEffect(k.undo, a.id, { status: 'committed', result: { id: 'd' } });
    expect([c.state, c.effect?.result]).toEqual(['open', { id: 'd' }]);
    for (const status of ['failed', 'aborted', 'refused']) {
      const x = kit();
      const o = await x.opened();
      const r = await reportUndoEffect(x.undo, o.id, { status });
      expect([r.state, r.outcome?.status, r.outcome?.reason]).toEqual(['finalized', 'aborted', `effect_${status}`]);
    }
    const p = kit();
    const o = await p.opened();
    const r = await reportUndoEffect(p.undo, o.id, { status: 'pending' });
    expect([r.state, r.effect, r.outcome]).toEqual(['open', undefined, undefined]);
    expect((await rejection(reportUndoEffect(p.undo, 'nope', { status: 'uncertain' }))).message).toBe(ERR('invalid', 'no undo record nope'));
  });
});

describe('the approval-channel notifier', () => {
  const recordOf = async (o: { outcome?: boolean; renderDigest?: string } = {}) => {
    const k = kit({ engine: engineOf(o.renderDigest !== undefined ? { renderDigest: o.renderDigest } : {}) });
    const { id } = await k.opened();
    const rec = (await k.store.get(id))!;
    const { pcactn: _p, receipts: _r, ...rest } = rec;
    return o.outcome ? { ...rest, outcome: { at: NOW, status: 'compensation_failed' as const, reason: 'downstream refused' } } : rest;
  };
  const capture = (deliveries: Partial<ApprovalDelivery>[] = [{ kind: 'webhook', delivered: true }]) => {
    const sent: { req: StepUpRequest; ctx: ApprovalNotifyContext | undefined }[] = [];
    const d: ApprovalDispatcher = {
      channels: [],
      notifyAll: async (req, ctx) => (sent.push({ req, ctx }), deliveries.map((x) => ({ requestId: req.id, payload: {}, kind: 'webhook', delivered: false, ...x }) as ApprovalDelivery)),
    };
    return { d, sent };
  };

  it('each notice kind has its own exact text; the request carries the lineage of the action', async () => {
    const rec = await recordOf();
    const until = new Date(rec.window_end).toISOString();
    const a = `${VERB} on ${RES}`;
    const want: [UndoNotice['kind'], string][] = [
      ['opened', `Already done: ${a}. You can undo it until ${until}.`],
      ['vetoed', `Undo started for ${a}.`],
      ['compensated', `Undone: ${a}.`],
      ['compensation_failed', `UNDO FAILED for ${a}: unknown. An operator has been alerted.`],
      ['revoked', `The agent's grant was revoked. ${a} can still be undone until ${until}.`],
      ['finalized', `Final: ${a} can no longer be undone.`],
    ];
    for (const [kind, reason] of want) {
      const c = capture();
      const n = undoNotifierFromDispatcher(c.d, { undoUrl: (t, id) => `https://undo.example/${id}?t=${t}`, inboxUrl: 'https://inbox.example/' });
      expect(await n.notify({ kind, record: rec, ...(kind === 'opened' ? { token: 'tok' } : {}) })).toEqual({ delivered: true });
      expect(c.sent[0]!.req).toStrictEqual({
        id: `undo:${rec.id}:${kind}`,
        verb: VERB,
        resource: RES,
        tier: 3,
        reason,
        goalCommit: '',
        lineage: { goalCommit: '', goalVerified: false, chain: [{ kind: 'action', label: `${VERB} ${RES}`, detail: `undo: ${COMP}` }], because: reason },
        r: 0,
        requestedAt: NOW,
      });
      expect(c.sent[0]!.ctx).toEqual({ inboxUrl: kind === 'opened' ? `https://undo.example/${rec.id}?t=tok` : 'https://inbox.example/' });
    }
    const failed = await recordOf({ outcome: true });
    const c = capture();
    await undoNotifierFromDispatcher(c.d, { undoUrl: () => 'u' }).notify({ kind: 'compensation_failed', record: failed });
    expect(c.sent[0]!.req.reason).toBe(`UNDO FAILED for ${a}: downstream refused. An operator has been alerted.`);
  });

  it('the render goes along only with the render digest of the record', async () => {
    const withDigest = await recordOf({ renderDigest: 'R'.repeat(43) });
    const without = await recordOf();
    const cases: [typeof without, ApprovalRender | undefined, boolean][] = [
      [withDigest, RENDER, true],
      [without, RENDER, false],
      [withDigest, undefined, false],
      [without, undefined, false],
    ];
    for (const [record, render, carried] of cases) {
      const c = capture();
      await undoNotifierFromDispatcher(c.d, { undoUrl: () => 'u' }).notify({ kind: 'vetoed', record, ...(render !== undefined ? { render } : {}) });
      const req = c.sent[0]!.req;
      expect(['render' in req, 'renderDigest' in req]).toEqual([carried, carried]);
      if (carried) expect([req.render, req.renderDigest]).toEqual([RENDER, 'R'.repeat(43)]);
    }
  });

  it('a notice no channel accepted reports every channel reason', async () => {
    const rec = await recordOf();
    const c = capture([{ kind: 'webhook', delivered: false, reason: 'HTTP 500' }, { kind: 'email', delivered: false }]);
    expect(await undoNotifierFromDispatcher(c.d, { undoUrl: () => 'u' }).notify({ kind: 'vetoed', record: rec })).toEqual({ delivered: false, reason: 'webhook: HTTP 500; email: not delivered' });
  });
});

describe('hostedUndoVetoRelay', () => {
  it('without any fetch it refuses as a configuration error', async () => {
    const saved = Reflect.get(globalThis, 'fetch');
    Reflect.set(globalThis, 'fetch', undefined);
    let relay!: ReturnType<typeof hostedUndoVetoRelay>;
    try {
      relay = hostedUndoVetoRelay({ baseUrl: 'https://api.example', secretKey: 'sk' });
    } finally {
      Reflect.set(globalThis, 'fetch', saved);
    }
    expect((await rejection(relay.pending())).message).toBe(ERR('config', 'no fetch available: pass one to hostedUndoVetoRelay'));
  });

  it('a body without a data list is refused by name', async () => {
    for (const body of [null, {}, { data: 'x' }]) {
      const relay = hostedUndoVetoRelay({ baseUrl: 'https://api.example', secretKey: 'sk', fetch: async () => ({ ok: true, status: 200, json: async () => body }) });
      expect((await rejection(relay.pending())).message).toBe(ERR('invalid', 'the veto relay answered without a data list'));
    }
  });
});

