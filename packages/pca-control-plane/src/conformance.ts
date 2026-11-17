/**
 * Conformance for control-plane stores. A store holds the state the engine's safety rests on: a sequence that never repeats,
 * a replay floor per source, single-use nonces, atomic agent and fleet updates, at most one live freeze per subject, and a
 * lift that only the first caller wins. Each check is one such claim, driven against YOUR store through a `StoreAdapter`.
 */
import assert from 'node:assert/strict';
import { generateKeyPair } from '@atlasauth/pca';
import { INITIAL_IMMUNE_STATE } from '@atlasauth/pca/ext/research';
import { signDirective } from './directive';
import type { ControlPlaneStore } from './store';
import type { AgentRecord, Directive, DirectiveKind, FleetRecord, Lift, Subject } from './types';

export interface StoreHandle {
  store: ControlPlaneStore;
  /** Another client on the SAME backend (the first stays usable). */
  reopen(): Promise<ControlPlaneStore>;
  close?(): Promise<void>;
}
export interface StoreAdapter {
  name: string;
  /** Default true. Declare false ONLY for an in-process store; the durability check is then skipped and reported. */
  durable?: boolean;
  /** Must return a store that shares no state with any earlier one (a fresh instance, schema or database). */
  create(): Promise<StoreHandle>;
}
export interface StoreCheck {
  name: string;
  claim: string;
  needs?: 'durable';
  run(h: StoreHandle): Promise<void>;
}

const key = generateKeyPair();
const NOW = 1_800_000_000_000;
let n = 0;

const agentRec = (agent: string, over: Partial<AgentRecord> = {}): AgentRecord => ({
  agent,
  immune: INITIAL_IMMUNE_STATE,
  first_seen: NOW,
  last_seen: NOW,
  actions: 0,
  autos: 0,
  step_ups: 0,
  denies: 0,
  executed: 0,
  malformed: 0,
  total_risk: 0,
  score: 0,
  level: 'calm',
  signals: [],
  sessions: [],
  grants: [],
  timeline: [],
  ver: 0,
  ...over,
});
const fleetRec = (over: Partial<FleetRecord> = {}): FleetRecord => ({ immune: INITIAL_IMMUNE_STATE, agents: 0, events: 0, malformed: 0, ver: 0, ...over });

const mk = async (store: ControlPlaneStore, kind: DirectiveKind, subject: Subject, o: { iat?: number; exp?: number } = {}): Promise<Directive> => {
  const seq = await store.nextSeq();
  const iat = o.iat ?? NOW;
  return signDirective(key.secretKey, {
    v: 1,
    kind,
    subject,
    params: kind === 'tighten' ? { kappa_mult: 2, theta_mult: 0.5 } : kind === 'shrink_budget' ? { factor: 0.5 } : {},
    cause: 'operator',
    by: 'conformance',
    reason: `check ${++n}`,
    evidence: '',
    iat,
    ...(kind === 'freeze' ? {} : { exp: o.exp ?? iat + 60_000 }),
    seq,
  });
};
const lift = (over: Partial<Lift> = {}): Lift => ({ op: 'unfreeze', at: NOW, human: 'h'.repeat(43), nonce: `n-${++n}-xxxxxxxxxxxxxxxx`, action: 'a', ...over });
const ids = (rows: Array<{ directive: Directive }>) => rows.map((r) => r.directive.id);

export const STORE_CHECKS: readonly StoreCheck[] = [
  {
    name: 'sequence-never-repeats',
    claim: 'nextSeq is strictly increasing and unique across concurrent callers on every client',
    async run({ store, reopen }) {
      const other = await reopen();
      const got = await Promise.all(Array.from({ length: 40 }, (_, i) => (i % 2 ? store : other).nextSeq()));
      assert.equal(new Set(got).size, got.length);
      assert.ok(got.every((s) => Number.isSafeInteger(s) && s >= 1));
      assert.ok((await store.nextSeq()) > Math.max(...got));
    },
  },
  {
    name: 'source-floor-is-monotone',
    claim: 'advanceSourceSeq accepts only a strictly greater value, per source, and racing equal values have one winner',
    async run({ store, reopen }) {
      assert.equal(await store.advanceSourceSeq('s1', 5), true);
      assert.equal(await store.advanceSourceSeq('s1', 5), false);
      assert.equal(await store.advanceSourceSeq('s1', 4), false);
      assert.equal(await store.advanceSourceSeq('s1', 9), true);
      assert.equal(await store.advanceSourceSeq('s2', 1), true);
      const other = await reopen();
      const rs = await Promise.all(Array.from({ length: 12 }, (_, i) => (i % 2 ? store : other).advanceSourceSeq('s3', 7)));
      assert.equal(rs.filter(Boolean).length, 1);
    },
  },
  {
    name: 'nonce-is-single-use',
    claim: 'consumeNonce is true once until it expires, and racing consumers have one winner',
    async run({ store, reopen }) {
      assert.equal(await store.consumeNonce('k1', NOW + 1000, NOW), true);
      assert.equal(await store.consumeNonce('k1', NOW + 1000, NOW + 500), false);
      assert.equal(await store.consumeNonce('k1', NOW + 9000, NOW + 2000), true);
      const other = await reopen();
      const rs = await Promise.all(Array.from({ length: 12 }, (_, i) => (i % 2 ? store : other).consumeNonce('k2', NOW + 1000, NOW)));
      assert.equal(rs.filter(Boolean).length, 1);
    },
  },
  {
    name: 'agent-update-is-atomic',
    claim: 'concurrent updateAgent calls never lose an update, and the version rises on every write',
    async run({ store, reopen }) {
      const other = await reopen();
      await Promise.all(Array.from({ length: 30 }, (_, i) => (i % 2 ? store : other).updateAgent('a1', (p) => ({ ...(p ?? agentRec('a1')), actions: (p?.actions ?? 0) + 1 }))));
      const r = await store.getAgent('a1');
      assert.equal(r?.actions, 30);
      assert.ok((r?.ver ?? 0) >= 30);
      assert.equal(await store.getAgent('nobody'), undefined);
      assert.equal(await store.countAgents(), 1);
    },
  },
  {
    name: 'reads-are-copies',
    claim: 'mutating a returned record does not change the stored one',
    async run({ store }) {
      await store.updateAgent('a2', () => agentRec('a2', { signals: ['x'] }));
      const r = await store.getAgent('a2');
      r!.signals.push('tampered');
      assert.deepEqual((await store.getAgent('a2'))?.signals, ['x']);
    },
  },
  {
    name: 'agents-list-by-threat',
    claim: 'listAgents is highest score first, then most recently seen, and honours the limit',
    async run({ store }) {
      await store.updateAgent('low', () => agentRec('low', { score: 0.1, last_seen: NOW + 5 }));
      await store.updateAgent('high', () => agentRec('high', { score: 0.9, last_seen: NOW }));
      await store.updateAgent('mid', () => agentRec('mid', { score: 0.5 }));
      assert.deepEqual((await store.listAgents(10)).map((a) => a.agent), ['high', 'mid', 'low']);
      assert.equal((await store.listAgents(2)).length, 2);
      assert.equal((await store.listAgents(0)).length, 0);
    },
  },
  {
    name: 'fleet-update-is-atomic',
    claim: 'concurrent updateFleet calls never lose an update',
    async run({ store, reopen }) {
      assert.equal(await store.getFleet(), undefined);
      const other = await reopen();
      await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? store : other).updateFleet((p) => ({ ...(p ?? fleetRec()), events: (p?.events ?? 0) + 1 }))));
      assert.equal((await store.getFleet())?.events, 20);
    },
  },
  {
    name: 'directive-id-is-unique',
    claim: 'putDirective of an id that exists returns the stored one and changes nothing',
    async run({ store }) {
      const d = await mk(store, 'tighten', { kind: 'agent', id: 'x' });
      assert.deepEqual(await store.putDirective(d), { created: true });
      const again = await store.putDirective(d);
      assert.equal(again.created, false);
      assert.deepEqual((await store.getDirective(d.id))?.directive, d);
      assert.equal(await store.getDirective('missing'), undefined);
    },
  },
  {
    name: 'one-live-freeze-per-subject',
    claim: 'of any number of racing freezes on one subject exactly one is created; other subjects are independent',
    async run({ store, reopen }) {
      const other = await reopen();
      const subject: Subject = { kind: 'agent', id: 'frz' };
      const ds = await Promise.all(Array.from({ length: 10 }, () => mk(store, 'freeze', subject)));
      const rs = await Promise.all(ds.map((d, i) => (i % 2 ? store : other).putDirective(d)));
      assert.equal(rs.filter((r) => r.created).length, 1);
      const loser = rs.find((r) => !r.created);
      assert.ok(loser && !loser.created && loser.existing.directive.kind === 'freeze');
      assert.equal((await store.putDirective(await mk(store, 'freeze', { kind: 'agent', id: 'frz2' }))).created, true);
      assert.equal((await store.putDirective(await mk(store, 'freeze', { kind: 'session', id: 'frz' }))).created, true);
    },
  },
  {
    name: 'lift-has-one-winner',
    claim: 'liftDirective is true for the first caller only, never un-lifts, and after a lift a new freeze on the subject is allowed',
    async run({ store, reopen }) {
      const subject: Subject = { kind: 'grant', id: 'g1' };
      const d = await mk(store, 'freeze', subject);
      await store.putDirective(d);
      const other = await reopen();
      const rs = await Promise.all(Array.from({ length: 10 }, (_, i) => (i % 2 ? store : other).liftDirective(d.id, lift())));
      assert.equal(rs.filter(Boolean).length, 1);
      assert.ok((await store.getDirective(d.id))?.lift);
      assert.equal(await store.liftDirective('missing', lift()), false);
      assert.equal((await store.putDirective(await mk(store, 'freeze', subject))).created, true);
    },
  },
  {
    name: 'list-filters',
    claim: 'listDirectives filters by subject, activity, afterSeq, order and limit',
    async run({ store }) {
      const s1: Subject = { kind: 'agent', id: 'l1' };
      const s2: Subject = { kind: 'agent', id: 'l2' };
      const live = await mk(store, 'tighten', s1, { iat: NOW, exp: NOW + 60_000 });
      const dead = await mk(store, 'tighten', s1, { iat: NOW - 120_000, exp: NOW - 60_000 });
      const lifted = await mk(store, 'shrink_budget', s1);
      const other = await mk(store, 'require_step_up', s2);
      for (const d of [live, dead, lifted, other]) await store.putDirective(d);
      await store.liftDirective(lifted.id, lift({ op: 'revoke' }));
      assert.deepEqual(ids(await store.listDirectives({ subjects: [s1], activeAt: NOW, limit: 10 })), [live.id]);
      assert.deepEqual(ids(await store.listDirectives({ subjects: [s1], limit: 10 })), [live.id, dead.id, lifted.id]);
      assert.deepEqual(ids(await store.listDirectives({ subjects: [s1, s2], order: 'desc', limit: 2 })), [other.id, lifted.id]);
      assert.deepEqual(ids(await store.listDirectives({ afterSeq: lifted.seq, subjects: [s1, s2], limit: 10 })), [other.id]);
      assert.equal((await store.listDirectives({ limit: 0 })).length, 0);
    },
  },
  {
    name: 'acknowledged-writes-survive-reopen',
    claim: 'what one client wrote is visible to a new client on the same backend',
    needs: 'durable',
    async run({ store, reopen }) {
      await store.updateAgent('dur', () => agentRec('dur', { actions: 3 }));
      const d = await mk(store, 'freeze', { kind: 'fleet', id: '*' });
      await store.putDirective(d);
      assert.equal(await store.advanceSourceSeq('dur-src', 1), true);
      const again = await reopen();
      assert.equal((await again.getAgent('dur'))?.actions, 3);
      assert.deepEqual((await again.getDirective(d.id))?.directive, d);
      assert.equal(await again.advanceSourceSeq('dur-src', 1), false);
    },
  },
];

export interface StoreCheckResult {
  name: string;
  claim: string;
  status: 'pass' | 'fail' | 'skipped';
  error?: string;
}

/** Run every check, each on a fresh store. Never throws; read the results. */
export async function runStoreConformance(adapter: StoreAdapter): Promise<StoreCheckResult[]> {
  const out: StoreCheckResult[] = [];
  for (const c of STORE_CHECKS) {
    if (c.needs === 'durable' && adapter.durable === false) {
      out.push({ name: c.name, claim: c.claim, status: 'skipped' });
      continue;
    }
    let h: StoreHandle | undefined;
    try {
      h = await adapter.create();
      await c.run(h);
      out.push({ name: c.name, claim: c.claim, status: 'pass' });
    } catch (e) {
      out.push({ name: c.name, claim: c.claim, status: 'fail', error: e instanceof Error ? e.message : String(e) });
    } finally {
      await h?.close?.().catch(() => undefined);
    }
  }
  return out;
}
