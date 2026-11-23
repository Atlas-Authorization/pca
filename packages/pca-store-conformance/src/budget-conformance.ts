/**
 * Conformance for aggregate budget stores (`BudgetLedger`, `@atlasauth/pca/ext/intent`).
 *
 * A budget ledger keeps, per scope key (a principal, an org, a fleet), the reservations of every session and agent of that
 * scope. What it must get right: a reservation counts at once and the cap is enforced in the same atomic step that records it
 * (concurrent clients can never pass it), the same reservation again is a replay, a compare-and-swap on the version has one
 * winner, a release frees budget only for a reservation that exists and was not committed, a commit never revives a release,
 * keys are independent, and acknowledged writes survive a restart or crash. Each check is one such claim, driven against YOUR
 * ledger through a `BudgetLedgerAdapter`.
 */
import assert from 'node:assert/strict';
import { createMemoryDurableKv, openDurableState } from '@atlasauth/pca/durable-state';
import {
  KvBudgetLedger,
  commitInDoc,
  emptyBudgetDoc,
  expireInDoc,
  releaseInDoc,
  reserveInDoc,
  startInDoc,
  type AccumulatorDecl,
  type BudgetDoc,
  type BudgetLedger,
  type ReserveRequest,
} from '@atlasauth/pca/ext/intent';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export interface BudgetLedgerHandle {
  ledger: BudgetLedger;
  /** Another client on the SAME backend (the first stays usable). */
  reopen(): Promise<BudgetLedger>;
  /** Optional: kill the backend abruptly, then return a client on whatever survived. */
  crash?(): Promise<BudgetLedger>;
  close?(): Promise<void>;
  /** Set by the runner: the adapter's declared durability, so a check can compare it with the ledger's own claim. */
  adapterDurable?: boolean;
}
export interface BudgetLedgerAdapter {
  name: string;
  /** Default true. Declare false ONLY for an in-process ledger; its `durable` must then be false too, and the durability checks are skipped and reported. */
  durable?: boolean;
  create(): Promise<BudgetLedgerHandle>;
}
export interface BudgetCheck {
  name: string;
  claim: string;
  needs?: 'durable' | 'crash';
  run(h: BudgetLedgerHandle): Promise<void>;
}

const CAP = 200;
const spend = (over: Partial<AccumulatorDecl> = {}): AccumulatorDecl => ({
  id: 'spend',
  agg: 'sum',
  val: 'action.params.amount',
  sel: { verbs: ['pay'] },
  win: { kind: 'task' },
  key: null,
  domain_max: CAP,
  holder: { kind: 'site_local' },
  scope: 'principal',
  ...over,
});
const ev = (id: string, amount: number, t = 1000) => ({ id, verb: 'pay', resource: 'r', params: { amount }, t });
const req = (id: string, amount: number, extra: Partial<ReserveRequest> = {}): ReserveRequest => ({ event: ev(id, amount), accumulators: [spend()], ...extra });
const K = 'principal/alice';
const K2 = 'principal/bob';
const reservedTotal = async (l: BudgetLedger, key = K): Promise<number> => (await l.snapshot(key)).events.filter((e) => e.status !== 'released').reduce((s, e) => s + (e.params.amount as number), 0);

export const BUDGET_CHECKS: readonly BudgetCheck[] = [
  {
    name: 'empty-key-is-empty',
    claim: 'a key nobody reserved on has version 0 and no events',
    async run({ ledger }) {
      assert.deepEqual(await ledger.snapshot(K), { version: 0, events: [] });
    },
  },
  {
    name: 'reservation-counts-at-once-and-cap-is-inclusive',
    claim: 'a reservation counts as soon as it is made; one that would pass the cap is refused with the post-value, one that reaches it exactly is admitted',
    async run({ ledger }) {
      const a = await ledger.reserve(K, req('a', 150));
      assert.equal(a.outcome, 'reserved');
      assert.deepEqual(a.outcome === 'reserved' ? a.post : null, { spend: 150 });
      const b = await ledger.reserve(K, req('b', 51));
      assert.deepEqual(b.outcome === 'over_cap' ? [b.acc, b.post, b.cap] : b, ['spend', 201, CAP]);
      assert.equal((await ledger.reserve(K, req('c', 50))).outcome, 'reserved');
      assert.equal(await reservedTotal(ledger), CAP);
    },
  },
  {
    name: 'a-refusal-writes-nothing',
    claim: 'an over-cap reservation leaves no event and does not move the version',
    async run({ ledger }) {
      await ledger.reserve(K, req('a', 150));
      const before = await ledger.snapshot(K);
      assert.equal((await ledger.reserve(K, req('b', 60))).outcome, 'over_cap');
      assert.deepEqual(await ledger.snapshot(K), before);
    },
  },
  {
    name: 'reserve-retry-is-a-replay',
    claim: 'the same event again is a replay that changes nothing and does not count twice; another event under the same id conflicts',
    async run({ ledger }) {
      const first = await ledger.reserve(K, req('a', 150));
      assert.deepEqual(await ledger.reserve(K, req('a', 150)), { outcome: 'replayed', version: first.version, status: 'reserved' });
      assert.equal((await ledger.reserve(K, req('a', 10))).outcome, 'id_conflict');
      assert.equal(await reservedTotal(ledger), 150);
      assert.equal((await ledger.reserve(K, req('b', 50))).outcome, 'reserved');
    },
  },
  {
    name: 'expected-version-is-compare-and-swap',
    claim: 'a reservation naming a stale version conflicts and writes nothing; the current version succeeds; a replay wins over a stale version',
    async run({ ledger }) {
      const a = await ledger.reserve(K, req('a', 10, { expectedVersion: 0 }));
      assert.equal(a.outcome, 'reserved');
      assert.deepEqual(await ledger.reserve(K, req('b', 10, { expectedVersion: 0 })), { outcome: 'conflict', version: 1 });
      assert.equal((await ledger.snapshot(K)).events.length, 1);
      assert.equal((await ledger.reserve(K, req('b', 10, { expectedVersion: 1 }))).outcome, 'reserved');
      assert.equal((await ledger.reserve(K, req('a', 10, { expectedVersion: 0 }))).outcome, 'replayed');
    },
  },
  {
    name: 'racing-reserves-never-pass-the-cap',
    claim: 'forty reservations of 30 racing from four clients against a cap of 200: exactly six land, the total is never above the cap, none is lost or counted twice',
    async run(h) {
      const clients = [h.ledger, await h.reopen(), await h.reopen(), await h.reopen()];
      const rs = await Promise.all(Array.from({ length: 40 }, (_, i) => clients[i % 4]!.reserve(K, req(`r${i}`, 30))));
      assert.equal(rs.filter((r) => r.outcome === 'reserved').length, 6);
      assert.equal(rs.filter((r) => r.outcome === 'over_cap').length, 34);
      assert.equal(await reservedTotal(h.ledger), 180);
      assert.equal(new Set((await h.ledger.snapshot(K)).events.map((e) => e.id)).size, 6);
    },
  },
  {
    name: 'racing-reserves-at-one-version-have-one-winner',
    claim: 'clients reserving with the same expected version: exactly one lands, the others conflict',
    async run(h) {
      const clients = [h.ledger, await h.reopen(), await h.reopen()];
      const rs = await Promise.all(Array.from({ length: 9 }, (_, i) => clients[i % 3]!.reserve(K, req(`v${i}`, 1, { expectedVersion: 0 }))));
      assert.equal(rs.filter((r) => r.outcome === 'reserved').length, 1);
      assert.equal(rs.filter((r) => r.outcome === 'conflict').length, 8);
      assert.equal((await h.ledger.snapshot(K)).events.length, 1);
    },
  },
  {
    name: 'racing-writers-with-retry-fill-the-cap-exactly',
    claim: 'twenty writers of 10 each retrying on conflict against a cap of 200: all twenty land, the twenty-first is refused',
    async run(h) {
      const clients = [h.ledger, await h.reopen(), await h.reopen()];
      const one = async (c: BudgetLedger, i: number): Promise<string> => {
        for (;;) {
          const s = await c.snapshot(K);
          const r = await c.reserve(K, req(`w${i}`, 10, { expectedVersion: s.version }));
          if (r.outcome !== 'conflict') return r.outcome;
        }
      };
      const out = await Promise.all(Array.from({ length: 20 }, (_, i) => one(clients[i % 3]!, i)));
      assert.ok(out.every((o) => o === 'reserved'), out.join());
      assert.equal(await reservedTotal(h.ledger), CAP);
      assert.equal((await h.ledger.reserve(K, req('extra', 1))).outcome, 'over_cap');
    },
  },
  {
    name: 'settle-rules',
    claim: 'commit and release settle only a reservation, are idempotent, and refuse the opposite settlement; an unknown id changes nothing',
    async run({ ledger }) {
      await ledger.reserve(K, req('a', 10));
      await ledger.reserve(K, req('b', 10));
      assert.equal((await ledger.commit(K, 'ghost')).outcome, 'unknown');
      assert.equal((await ledger.release(K, 'ghost')).outcome, 'unknown');
      assert.equal((await ledger.commit(K, 'a')).outcome, 'settled');
      assert.equal((await ledger.commit(K, 'a')).outcome, 'replayed');
      const r1 = await ledger.release(K, 'a');
      assert.deepEqual(r1.outcome === 'refused' ? r1.status : r1.outcome, 'committed');
      assert.equal((await ledger.release(K, 'b')).outcome, 'settled');
      assert.equal((await ledger.release(K, 'b')).outcome, 'replayed');
      const c1 = await ledger.commit(K, 'b');
      assert.deepEqual(c1.outcome === 'refused' ? c1.status : c1.outcome, 'released');
      assert.deepEqual((await ledger.snapshot(K)).events.map((e) => e.status), ['committed', 'released']);
    },
  },
  {
    name: 'release-frees-budget-and-commit-keeps-it',
    claim: 'a released reservation no longer counts; a committed one still does; an open one keeps counting until settled',
    async run({ ledger }) {
      await ledger.reserve(K, req('a', 100));
      await ledger.reserve(K, req('b', 100));
      assert.equal((await ledger.reserve(K, req('c', 1))).outcome, 'over_cap');
      await ledger.release(K, 'a');
      await ledger.commit(K, 'b');
      assert.equal((await ledger.reserve(K, req('d', 100))).outcome, 'reserved');
      assert.equal((await ledger.reserve(K, req('e', 1))).outcome, 'over_cap');
    },
  },
  {
    name: 'release-without-reserve-credits-nothing',
    claim: 'releasing an id that was never reserved does not create headroom, now or after the id is reserved later',
    async run({ ledger }) {
      assert.equal((await ledger.release(K, 'ghost')).outcome, 'unknown');
      assert.equal((await ledger.reserve(K, req('a', 201))).outcome, 'over_cap');
      assert.equal((await ledger.reserve(K, req('ghost', 200))).outcome, 'reserved');
      assert.equal((await ledger.reserve(K, req('b', 1))).outcome, 'over_cap');
    },
  },
  {
    name: 'a-late-commit-cannot-overspend',
    claim: 'after a reservation was released and its budget reused, committing it is refused, so the committed total never passes the cap',
    async run({ ledger }) {
      await ledger.reserve(K, req('a', 200));
      await ledger.release(K, 'a');
      await ledger.reserve(K, req('b', 200));
      assert.equal((await ledger.commit(K, 'a')).outcome, 'refused');
      await ledger.commit(K, 'b');
      assert.equal((await ledger.snapshot(K)).events.filter((e) => e.status === 'committed').length, 1);
    },
  },
  {
    name: 'expiry-releases-only-open-reservations-past-their-deadline',
    claim: 'expire frees a reservation at or after its deadline, never an earlier one, never a committed, started or deadline-less one, and a late commit or start of it is refused',
    async run({ ledger }) {
      await ledger.reserve(K, req('a', 40, { expiresAt: 500 }));
      await ledger.reserve(K, req('b', 40, { expiresAt: 500 }));
      await ledger.reserve(K, req('c', 40));
      await ledger.reserve(K, req('d', 40, { expiresAt: 500 }));
      await ledger.commit(K, 'b');
      await ledger.start(K, 'd');
      assert.deepEqual((await ledger.expire(K, 499)).released, []);
      assert.deepEqual((await ledger.expire(K, 500)).released, ['a']);
      assert.deepEqual((await ledger.expire(K, 10_000)).released, []);
      assert.equal(await reservedTotal(ledger), 120);
      assert.equal((await ledger.commit(K, 'a')).outcome, 'refused');
      assert.equal((await ledger.start(K, 'a')).outcome, 'refused');
    },
  },
  {
    name: 'start-rules',
    claim: 'start marks an open reservation non-expirable and is idempotent; an unknown id changes nothing; a started one can still be committed, or released (the effect did not happen); a released one cannot start',
    async run({ ledger }) {
      await ledger.reserve(K, req('a', 10, { expiresAt: 5 }));
      await ledger.reserve(K, req('b', 10));
      await ledger.reserve(K, req('c', 10));
      const v = (await ledger.snapshot(K)).version;
      assert.equal((await ledger.start(K, 'ghost')).outcome, 'unknown');
      assert.equal((await ledger.snapshot(K)).version, v);
      assert.equal((await ledger.start(K, 'a')).outcome, 'settled');
      assert.equal((await ledger.start(K, 'a')).outcome, 'replayed');
      assert.deepEqual((await ledger.expire(K, 100)).released, []);
      assert.equal((await ledger.commit(K, 'a')).outcome, 'settled');
      assert.equal((await ledger.start(K, 'a')).outcome, 'replayed');
      await ledger.start(K, 'b');
      assert.equal((await ledger.release(K, 'b')).outcome, 'settled');
      const s = await ledger.start(K, 'b');
      assert.deepEqual(s.outcome === 'refused' ? s.status : s.outcome, 'released');
      assert.equal((await ledger.snapshot(K)).events.find((e) => e.id === 'c')!.started, undefined);
    },
  },
  {
    name: 'keys-are-independent',
    claim: 'two keys have their own caps, versions and events',
    async run({ ledger }) {
      await ledger.reserve(K, req('a', 200));
      assert.equal((await ledger.reserve(K2, req('a', 200))).outcome, 'reserved');
      assert.equal((await ledger.reserve(K, req('b', 1))).outcome, 'over_cap');
      assert.deepEqual((await ledger.snapshot(K2)).events.map((e) => e.id), ['a']);
      assert.equal((await ledger.snapshot(K2)).version, 1);
    },
  },
  {
    name: 'windows-reset-the-count',
    claim: 'a period window counts only the events of the period of the new event',
    async run({ ledger }) {
      const w = [spend({ win: { kind: 'period', ms: 1000, t0: 0 } })];
      assert.equal((await ledger.reserve(K, { event: ev('a', 200, 100), accumulators: w })).outcome, 'reserved');
      assert.equal((await ledger.reserve(K, { event: ev('b', 1, 900), accumulators: w })).outcome, 'over_cap');
      assert.equal((await ledger.reserve(K, { event: ev('c', 200, 1100), accumulators: w })).outcome, 'reserved');
    },
  },
  {
    name: 'release-evidence-is-stored-and-bound',
    claim: 'evidence for the reservation is kept with the released event; evidence for another reservation is refused and the reservation stays open',
    async run({ ledger }) {
      await ledger.reserve(K, req('a', 10));
      const mk = (id: string) => ({ v: 1 as const, key: K, id, reason: 'effect_failed' as const, at: 5, signer: 's', sig: 'x' });
      await assert.rejects(ledger.release(K, 'a', mk('other')), RangeError);
      assert.equal((await ledger.snapshot(K)).events[0]!.status, 'reserved');
      assert.equal((await ledger.release(K, 'a', mk('a'))).outcome, 'settled');
      assert.deepEqual((await ledger.snapshot(K)).events[0]!.rel, mk('a'));
    },
  },
  {
    name: 'invalid-input-is-refused',
    claim: 'a malformed event or request throws and writes nothing',
    async run({ ledger }) {
      for (const bad of [ev('', 1), { ...ev('x', 1), t: 0.5 }, { ...ev('x', 1), verb: 7 as never }]) await assert.rejects(ledger.reserve(K, { event: bad, accumulators: [spend()] }), RangeError);
      await assert.rejects(ledger.reserve(K, req('x', 1, { expectedVersion: -1 })), RangeError);
      await assert.rejects(ledger.reserve(K, { event: ev('x', 1), accumulators: [spend({ domain_max: undefined })] }), RangeError);
      assert.deepEqual(await ledger.snapshot(K), { version: 0, events: [] });
    },
  },
  {
    name: 'snapshots-are-copies',
    claim: 'mutating what a snapshot returned cannot change the ledger',
    async run({ ledger }) {
      await ledger.reserve(K, req('a', 10));
      const s = await ledger.snapshot(K);
      (s.events as unknown as { status: string }[])[0]!.status = 'released';
      assert.equal((await ledger.snapshot(K)).events[0]!.status, 'reserved');
    },
  },
  {
    name: 'durable-claim-matches-the-adapter',
    claim: 'a ledger says durable: true exactly when its adapter declares durability, so a volatile ledger can never satisfy the non-session refusal',
    async run(h) {
      assert.equal(h.ledger.durable, h.adapterDurable !== false, `ledger.durable=${String(h.ledger.durable)} but the adapter declares durable=${String(h.adapterDurable !== false)}`);
    },
  },
  {
    name: 'state-survives-reopen',
    claim: 'every acknowledged reserve, commit and release is visible to a new client after the backend restarts, and the cap still holds',
    needs: 'durable',
    async run(h) {
      await h.ledger.reserve(K, req('a', 150));
      await h.ledger.reserve(K, req('b', 50));
      await h.ledger.commit(K, 'a');
      await h.ledger.release(K, 'b');
      const back = await h.reopen();
      assert.deepEqual((await back.snapshot(K)).events.map((e) => [e.id, e.status]), [['a', 'committed'], ['b', 'released']]);
      assert.equal((await back.reserve(K, req('c', 51))).outcome, 'over_cap');
      assert.equal((await back.reserve(K, req('c', 50))).outcome, 'reserved');
    },
  },
  {
    name: 'acknowledged-writes-survive-a-crash',
    claim: 'after an abrupt kill every acknowledged reservation still counts, so a crash can only over-restrict, never reset a cap',
    needs: 'crash',
    async run(h) {
      await h.ledger.reserve(K, req('a', 200));
      const inflight = h.ledger.reserve(K, req('b', 0)).catch(() => undefined);
      const back = await h.crash!();
      void inflight;
      assert.equal((await back.reserve(K, req('c', 1))).outcome, 'over_cap');
      assert.equal((await back.snapshot(K)).events[0]!.id, 'a');
    },
  },
];

export interface BudgetCheckResult {
  name: string;
  status: 'pass' | 'fail' | 'skip';
  detail?: string;
}
export interface BudgetConformanceReport {
  adapter: string;
  status: 'pass' | 'fail';
  checks: BudgetCheckResult[];
}

export async function runBudgetLedgerConformance(adapter: BudgetLedgerAdapter, opts: { only?: readonly string[] } = {}): Promise<BudgetConformanceReport> {
  const checks: BudgetCheckResult[] = [];
  for (const c of BUDGET_CHECKS) {
    if (opts.only && !opts.only.includes(c.name)) continue;
    if (c.needs === 'durable' && adapter.durable === false) {
      checks.push({ name: c.name, status: 'skip', detail: 'the adapter declares durable: false' });
      continue;
    }
    const h = await adapter.create();
    h.adapterDurable = adapter.durable;
    try {
      if (c.needs === 'crash' && !h.crash) {
        checks.push({ name: c.name, status: 'skip', detail: 'the adapter has no crash()' });
        continue;
      }
      await c.run(h);
      checks.push({ name: c.name, status: 'pass' });
    } catch (e) {
      checks.push({ name: c.name, status: 'fail', detail: e instanceof Error ? e.message : String(e) });
    } finally {
      await h.close?.();
    }
  }
  return { adapter: adapter.name, status: checks.some((x) => x.status === 'fail') ? 'fail' : 'pass', checks };
}

export function formatBudgetReport(r: BudgetConformanceReport): string {
  return [`pca-store-conformance (budget ledger): ${r.adapter} -> ${r.status.toUpperCase()}`, ...r.checks.map((c) => `  [${c.status.toUpperCase()}] ${c.name}${c.detail ? `: ${c.detail.split('\n')[0]}` : ''}`)].join('\n');
}

type It = (name: string, fn: () => Promise<void>, timeout?: number) => unknown;
type Describe = (name: string, fn: () => void) => unknown;

/** Register one test-runner test per check (vitest / jest globals, or pass `runner`). */
export function describeBudgetLedgerConformance(adapter: BudgetLedgerAdapter | (() => BudgetLedgerAdapter), opts: { runner?: { describe: Describe; it: It }; timeoutMs?: number } = {}): void {
  const g = globalThis as { describe?: Describe; it?: It };
  const describe = opts.runner?.describe ?? g.describe;
  const it = opts.runner?.it ?? g.it;
  if (!describe || !it) throw new Error('describeBudgetLedgerConformance needs describe/it: pass { runner } or enable test globals');
  const a = typeof adapter === 'function' ? adapter() : adapter;
  describe(`PCA budget ledger conformance: ${a.name}`, () => {
    for (const c of BUDGET_CHECKS) {
      it(
        `${c.name}: ${c.claim}`,
        async () => {
          const x = (await runBudgetLedgerConformance(typeof adapter === 'function' ? adapter() : adapter, { only: [c.name] })).checks[0]!;
          if (x.status === 'fail') throw new Error(x.detail);
        },
        opts.timeoutMs ?? 60_000,
      );
    }
  });
}

// ---- reference adapters --------------------------------------------------------------------------------------------------

export function memoryBudgetLedgerAdapter(): BudgetLedgerAdapter {
  return {
    name: 'KvBudgetLedger over an in-memory kv',
    durable: false,
    async create() {
      const kv = createMemoryDurableKv();
      return { ledger: new KvBudgetLedger(kv, false), reopen: async () => new KvBudgetLedger(kv, false) };
    },
  };
}

export function durableBudgetLedgerAdapter(options: { dir?: string } = {}): BudgetLedgerAdapter {
  return {
    name: 'KvBudgetLedger over durable-state files',
    durable: true,
    async create() {
      const dir = options.dir ?? mkdtempSync(join(tmpdir(), 'pca-budgetsc-'));
      const open = async (): Promise<BudgetLedger> => new KvBudgetLedger(await openDurableState({ dir, lockTimeoutMs: 30_000 }), true);
      return { ledger: await open(), reopen: open, crash: open };
    },
  };
}

type Defect = 'expire-started' | 'no-cap' | 'no-cas' | 'lost-update' | 'amnesia' | 'release-unreserved' | 'release-committed' | 'late-commit' | 'no-replay' | 'shared-keys' | 'expire-committed' | 'volatile-claims-durable';

/** A document ledger with a switchable defect, for the positive controls (each reproduces a real mistake). */
function defective(defect: Defect): BudgetLedgerAdapter {
  const names: Record<Defect, string> = {
    'no-cap': 'BAD no cap check (records every reservation)',
    'no-cas': 'BAD no compare-and-swap (ignores expectedVersion)',
    'lost-update': 'BAD lost update (read, await, write)',
    amnesia: 'BAD amnesia (claims durability, forgets on reopen)',
    'release-unreserved': 'BAD release without reserve (credits budget for an unknown id)',
    'release-committed': 'BAD release of a committed event (frees spent budget)',
    'late-commit': 'BAD late commit (a released reservation can be committed again)',
    'no-replay': 'BAD no idempotence (a retried reservation counts twice)',
    'shared-keys': 'BAD one state for every key (keys leak into each other)',
    'expire-committed': 'BAD expiry releases committed events',
    'expire-started': 'BAD expiry releases started reservations (an effect that ran stops counting)',
    'volatile-claims-durable': 'BAD in-process ledger that claims durable: true',
  };
  const durable = defect !== 'volatile-claims-durable';
  return {
    name: names[defect],
    durable,
    async create() {
      let docs = new Map<string, BudgetDoc>();
      const dk = (key: string): string => (defect === 'shared-keys' ? '*' : key);
      const doc = (key: string): BudgetDoc => {
        const k = dk(key);
        let d = docs.get(k);
        if (!d) docs.set(k, (d = emptyBudgetDoc()));
        return d;
      };
      const tick = (): Promise<void> => new Promise((r) => setImmediate(r));
      const client = (): BudgetLedger => ({
        durable: defect === 'volatile-claims-durable' ? true : durable,
        snapshot: async (key) => {
          const d = doc(key);
          return { version: d.ver, events: structuredClone(d.events) };
        },
        reserve: async (key, r) => {
          let d = doc(key);
          if (defect === 'lost-update') {
            d = structuredClone(d);
            await tick();
          }
          let rr = r;
          if (defect === 'no-cas') rr = { ...r, expectedVersion: undefined };
          if (defect === 'no-cap') rr = { ...rr, accumulators: rr.accumulators.map((a) => ({ ...a, domain_max: Number.MAX_SAFE_INTEGER })) };
          if (defect === 'no-replay' && d.events.some((e) => e.id === r.event.id)) {
            d.events.push({ ...structuredClone(d.events.find((e) => e.id === r.event.id)!), id: `${r.event.id}#dup` });
            d.ver += 1;
            return { outcome: 'reserved', version: d.ver, post: {} };
          }
          const out = reserveInDoc(d, rr);
          if (defect === 'lost-update') docs.set(dk(key), d);
          return out;
        },
        start: async (key, id) => startInDoc(doc(key), id),
        commit: async (key, id) => {
          const d = doc(key);
          if (defect === 'late-commit') {
            const e = d.events.find((x) => x.id === id);
            if (e && e.status === 'released') {
              e.status = 'committed';
              d.ver += 1;
              return { outcome: 'settled', version: d.ver };
            }
          }
          return commitInDoc(d, id);
        },
        release: async (key, id, ev0) => {
          const d = doc(key);
          const e = d.events.find((x) => x.id === id);
          if (defect === 'release-unreserved' && !e) {
            d.events.push({ id, verb: 'pay', resource: 'r', params: { amount: -CAP }, t: 0, status: 'committed' });
            d.ver += 1;
            return { outcome: 'settled', version: d.ver };
          }
          if (defect === 'release-committed' && e?.status === 'committed') {
            e.status = 'released';
            d.ver += 1;
            return { outcome: 'settled', version: d.ver };
          }
          return releaseInDoc(d, key, id, ev0);
        },
        expire: async (key, now) => {
          const d = doc(key);
          if (defect === 'expire-committed') {
            const released: string[] = [];
            for (const e of d.events) if (e.exp !== undefined && e.exp <= now && e.status !== 'released') ((e.status = 'released'), released.push(e.id));
            if (released.length) d.ver += 1;
            return { released, version: d.ver };
          }
          if (defect === 'expire-started') {
            const released: string[] = [];
            for (const e of d.events) if (e.status === 'reserved' && e.exp !== undefined && e.exp <= now) ((e.status = 'released'), released.push(e.id));
            if (released.length) d.ver += 1;
            return { released, version: d.ver };
          }
          return expireInDoc(d, now);
        },
      });
      const again = async (): Promise<BudgetLedger> => {
        if (defect === 'amnesia') docs = new Map();
        return client();
      };
      return { ledger: client(), reopen: again, crash: again };
    },
  };
}
const bad = (d: Defect) => (): BudgetLedgerAdapter => defective(d);
export const noCapBudgetLedgerAdapter = bad('no-cap');
export const noCasBudgetLedgerAdapter = bad('no-cas');
export const lostUpdateBudgetLedgerAdapter = bad('lost-update');
export const amnesiaBudgetLedgerAdapter = bad('amnesia');
export const releaseUnreservedBudgetLedgerAdapter = bad('release-unreserved');
export const releaseCommittedBudgetLedgerAdapter = bad('release-committed');
export const lateCommitBudgetLedgerAdapter = bad('late-commit');
export const noReplayBudgetLedgerAdapter = bad('no-replay');
export const sharedKeysBudgetLedgerAdapter = bad('shared-keys');
export const expireCommittedBudgetLedgerAdapter = bad('expire-committed');
export const expireStartedBudgetLedgerAdapter = bad('expire-started');
export const volatileClaimsDurableBudgetLedgerAdapter = bad('volatile-claims-durable');

export const BUDGET_REFERENCE_ADAPTERS: Readonly<Record<string, () => BudgetLedgerAdapter>> = {
  'budget-memory': memoryBudgetLedgerAdapter,
  'budget-durable-file': () => durableBudgetLedgerAdapter(),
  'bad-budget-no-cap': noCapBudgetLedgerAdapter,
  'bad-budget-no-cas': noCasBudgetLedgerAdapter,
  'bad-budget-lost-update': lostUpdateBudgetLedgerAdapter,
  'bad-budget-amnesia': amnesiaBudgetLedgerAdapter,
  'bad-budget-release-unreserved': releaseUnreservedBudgetLedgerAdapter,
  'bad-budget-release-committed': releaseCommittedBudgetLedgerAdapter,
  'bad-budget-late-commit': lateCommitBudgetLedgerAdapter,
  'bad-budget-no-replay': noReplayBudgetLedgerAdapter,
  'bad-budget-shared-keys': sharedKeysBudgetLedgerAdapter,
  'bad-budget-expire-committed': expireCommittedBudgetLedgerAdapter,
  'bad-budget-expire-started': expireStartedBudgetLedgerAdapter,
  'bad-budget-volatile-claims-durable': volatileClaimsDurableBudgetLedgerAdapter,
};
