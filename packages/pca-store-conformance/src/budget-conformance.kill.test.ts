import { describe, expect, it } from 'vitest';
import { createMemoryDurableKv } from '@atlasauth/pca/durable-state';
import { KvBudgetLedger, type BudgetLedger } from '@atlasauth/pca/ext/intent';
import {
  lateCommitBudgetLedgerAdapter,
  memoryBudgetLedgerAdapter,
  noCapBudgetLedgerAdapter,
  releaseCommittedBudgetLedgerAdapter,
  runBudgetLedgerConformance,
  volatileClaimsDurableBudgetLedgerAdapter,
  type BudgetLedgerAdapter,
} from './budget-conformance';
import { traceHandle } from './test-support/trace';

// ---- exact renderings of the calls a check makes (independent of the source constants) ----------------------------------
const KQ = '"principal/alice"';
const K2Q = '"principal/bob"';
const SPEND = (win = '{"kind":"task"}', cap = '200'): string => `{"id":"spend","agg":"sum","val":"action.params.amount","sel":{"verbs":["pay"]},"win":${win},"key":null,"domain_max":${cap},"holder":{"kind":"site_local"},"scope":"principal"}`;
const EVQ = (id: string, amt: number, t = '1000', verb = '"pay"'): string => `{"id":${JSON.stringify(id)},"verb":${verb},"resource":"r","params":{"amount":${amt}},"t":${t}}`;
const RQ = (id: string, amt: number, extra = ''): string => `{"event":${EVQ(id, amt)},"accumulators":[${SPEND()}]${extra}}`;
const rs = (n: number, id: string, amt: number, extra = '', key = KQ): string => `c${n}.reserve(${key},${RQ(id, amt, extra)})`;
const snap = (n = 0, key = KQ): string => `c${n}.snapshot(${key})`;
const cm = (id: string): string => `c0.commit(${KQ},"${id}")`;
const rl = (id: string, ev = ''): string => `c0.release(${KQ},"${id}"${ev})`;
const st = (id: string): string => `c0.start(${KQ},"${id}")`;
const ex = (now: number): string => `c0.expire(${KQ},${now})`;
const EXP = (n: number): string => `,"expiresAt":${n}`;
const EV0 = (n: number): string => `,"expectedVersion":${n}`;
const MK = (id: string): string => `{"v":1,"key":"principal/alice","id":"${id}","reason":"effect_failed","at":5,"signer":"s","sig":"x"}`;

const memDurable = (): BudgetLedgerAdapter => ({
  name: 'memory kv claiming durability',
  durable: true,
  async create() {
    const kv = createMemoryDurableKv();
    const open = async (): Promise<BudgetLedger> => new KvBudgetLedger(kv, true);
    return { ledger: await open(), reopen: open, crash: open };
  },
});

const traced = async (a: BudgetLedgerAdapter, name: string): Promise<string[]> => {
  const log: string[] = [];
  const r = await runBudgetLedgerConformance({ ...a, async create() { return traceHandle(await a.create(), 'ledger', log); } }, { only: [name] });
  expect(r.checks).toEqual([{ name, status: 'pass' }]);
  return log;
};
const one = async (a: BudgetLedgerAdapter, name: string) => (await runBudgetLedgerConformance(a, { only: [name] })).checks[0]!;

type Over = Partial<BudgetLedger>;
const wrapLedger = (l: BudgetLedger, o: Over): BudgetLedger =>
  new Proxy(l, {
    get(t, p) {
      if (p in o) return (o as Record<string | symbol, unknown>)[p];
      const v = (t as unknown as Record<string | symbol, unknown>)[p];
      return typeof v === 'function' ? v.bind(t) : v;
    },
  });
const fake = (base: BudgetLedgerAdapter, mk: (real: BudgetLedger) => Over): BudgetLedgerAdapter => ({
  ...base,
  async create() {
    const h = await base.create();
    return { ...h, ledger: wrapLedger(h.ledger, mk(h.ledger)), reopen: async () => { const r = await h.reopen(); return wrapLedger(r, mk(r)); } };
  },
});

describe('budget checks make exactly the documented calls', () => {
  const T = (name: string, a: () => BudgetLedgerAdapter, golden: () => string[]) => it(name, async () => expect(await traced(a(), name)).toEqual(golden()));

  T('empty-key-is-empty', memoryBudgetLedgerAdapter, () => [snap()]);
  T('reservation-counts-at-once-and-cap-is-inclusive', memoryBudgetLedgerAdapter, () => [rs(0, 'a', 150), rs(0, 'b', 51), rs(0, 'c', 50), snap()]);
  T('a-refusal-writes-nothing', memoryBudgetLedgerAdapter, () => [rs(0, 'a', 150), snap(), rs(0, 'b', 60), snap()]);
  T('reserve-retry-is-a-replay', memoryBudgetLedgerAdapter, () => [rs(0, 'a', 150), rs(0, 'a', 150), rs(0, 'a', 10), snap(), rs(0, 'b', 50)]);
  T('expected-version-is-compare-and-swap', memoryBudgetLedgerAdapter, () => [rs(0, 'a', 10, EV0(0)), rs(0, 'b', 10, EV0(0)), snap(), rs(0, 'b', 10, EV0(1)), rs(0, 'a', 10, EV0(0))]);
  T('racing-reserves-never-pass-the-cap', memoryBudgetLedgerAdapter, () => [
    'h.reopen()', 'h.reopen()', 'h.reopen()',
    ...Array.from({ length: 40 }, (_, i) => rs(i % 4, `r${i}`, 30)),
    snap(), snap(),
  ]);
  T('racing-reserves-at-one-version-have-one-winner', memoryBudgetLedgerAdapter, () => [
    'h.reopen()', 'h.reopen()',
    ...Array.from({ length: 9 }, (_, i) => rs(i % 3, `v${i}`, 1, EV0(0))),
    snap(),
  ]);
  T('settle-rules', memoryBudgetLedgerAdapter, () => [
    rs(0, 'a', 10), rs(0, 'b', 10), cm('ghost'), rl('ghost'), cm('a'), cm('a'), rl('a'), rl('b'), rl('b'), cm('b'), snap(),
  ]);
  T('release-frees-budget-and-commit-keeps-it', memoryBudgetLedgerAdapter, () => [
    rs(0, 'a', 100), rs(0, 'b', 100), rs(0, 'c', 1), rl('a'), cm('b'), rs(0, 'd', 100), rs(0, 'e', 1),
  ]);
  T('release-without-reserve-credits-nothing', memoryBudgetLedgerAdapter, () => [rl('ghost'), rs(0, 'a', 201), rs(0, 'ghost', 200), rs(0, 'b', 1)]);
  T('a-late-commit-cannot-overspend', memoryBudgetLedgerAdapter, () => [rs(0, 'a', 200), rl('a'), rs(0, 'b', 200), cm('a'), cm('b'), snap()]);
  T('expiry-releases-only-open-reservations-past-their-deadline', memoryBudgetLedgerAdapter, () => [
    rs(0, 'a', 40, EXP(500)), rs(0, 'b', 40, EXP(500)), rs(0, 'c', 40), rs(0, 'd', 40, EXP(500)), cm('b'), st('d'), ex(499), ex(500), ex(10000), snap(), cm('a'), st('a'),
  ]);
  T('start-rules', memoryBudgetLedgerAdapter, () => [
    rs(0, 'a', 10, EXP(5)), rs(0, 'b', 10), rs(0, 'c', 10), snap(), st('ghost'), snap(), st('a'), st('a'), ex(100), cm('a'), st('a'), st('b'), rl('b'), st('b'), snap(),
  ]);
  T('keys-are-independent', memoryBudgetLedgerAdapter, () => [rs(0, 'a', 200), rs(0, 'a', 200, '', K2Q), rs(0, 'b', 1), snap(0, K2Q), snap(0, K2Q)]);
  T('windows-reset-the-count', memoryBudgetLedgerAdapter, () => {
    const w = SPEND('{"kind":"period","ms":1000,"t0":0}');
    const q = (id: string, amt: number, t: string): string => `c0.reserve(${KQ},{"event":${EVQ(id, amt, t)},"accumulators":[${w}]})`;
    return [q('a', 200, '100'), q('b', 1, '900'), q('c', 200, '1100')];
  });
  T('release-evidence-is-stored-and-bound', memoryBudgetLedgerAdapter, () => [rs(0, 'a', 10), rl('a', `,${MK('other')}`), snap(), rl('a', `,${MK('a')}`), snap()]);
  T('invalid-input-is-refused', memoryBudgetLedgerAdapter, () => {
    const q = (event: string, spend = SPEND()): string => `c0.reserve(${KQ},{"event":${event},"accumulators":[${spend}]})`;
    return [
      q(EVQ('', 1)),
      q(EVQ('x', 1, '0.5')),
      q(EVQ('x', 1, '1000', '7')),
      rs(0, 'x', 1, ',"expectedVersion":-1'),
      q(EVQ('x', 1), SPEND().replace('"domain_max":200', '"domain_max":"<undefined>"')),
      snap(),
    ];
  });
  T('snapshots-are-copies', memoryBudgetLedgerAdapter, () => [rs(0, 'a', 10), snap(), snap()]);
  T('durable-claim-matches-the-adapter', memoryBudgetLedgerAdapter, () => []);
  T('acknowledged-writes-survive-a-crash', memDurable, () => [rs(0, 'a', 200), rs(0, 'b', 0), 'h.crash()', rs(1, 'c', 1), snap(1)]);

  it('racing-writers-with-retry-fill-the-cap-exactly: every writer sends the version it just read', async () => {
    const log = await traced(memoryBudgetLedgerAdapter(), 'racing-writers-with-retry-fill-the-cap-exactly');
    expect(log.slice(0, 2)).toEqual(['h.reopen()', 'h.reopen()']);
    expect(log.slice(2, 22)).toEqual(Array.from({ length: 20 }, (_, i) => snap(i % 3)));
    expect(log.slice(-2)).toEqual([snap(0), rs(0, 'extra', 1)]);
    const mid = log.slice(22, -2);
    const reserves = mid.filter((l) => l.includes('.reserve('));
    expect(mid.filter((l) => l.includes('.snapshot(')).length + reserves.length).toBe(mid.length);
    const ids = new Set<number>();
    for (const l of reserves) {
      const id = Number(/"id":"w(\d+)"/.exec(l)![1]);
      const v = Number(/"expectedVersion":(\d+)\}\)$/.exec(l)![1]);
      ids.add(id);
      expect(l.replace(/^c[012]\./, 'c0.')).toBe(rs(0, `w${id}`, 10, EV0(v)));
    }
    expect([...ids].sort((a, b) => a - b)).toEqual(Array.from({ length: 20 }, (_, i) => i));
  });
});

describe('budget checks judge the outcomes, not just the calls', () => {
  it('a writer refused for no reason fails the retry check with the outcome list', async () => {
    const a = fake(memoryBudgetLedgerAdapter(), (real) => ({
      reserve: async (k, r) => {
        const out = await real.reserve(k, r);
        return r.event.id === 'w3' ? { outcome: 'over_cap', version: 0, acc: 'spend', post: 210, cap: 200 } : out;
      },
    }));
    const c = await one(a, 'racing-writers-with-retry-fill-the-cap-exactly');
    expect(c.status).toBe('fail');
    expect(c.detail).toBe(Array.from({ length: 20 }, (_, i) => (i === 3 ? 'over_cap' : 'reserved')).join());
  });

  it('only committed events are counted by the late-commit check', async () => {
    const e = (id: string, status: string) => ({ id, verb: 'pay', resource: 'r', params: { amount: 1 }, t: 1, status });
    const a = fake(memoryBudgetLedgerAdapter(), () => ({
      snapshot: async () => ({ version: 3, events: [e('a', 'released'), e('b', 'committed'), e('x', 'reserved')] as never }),
    }));
    expect(await one(a, 'a-late-commit-cannot-overspend')).toEqual({ name: 'a-late-commit-cannot-overspend', status: 'pass' });
  });

  it('a snapshot that aliases the ledger fails the copy check with the aliased value', async () => {
    const a = fake(memoryBudgetLedgerAdapter(), (real) => {
      let cached: Awaited<ReturnType<BudgetLedger['snapshot']>> | undefined;
      return { snapshot: async (k) => (cached ??= await real.snapshot(k)) };
    });
    const c = await one(a, 'snapshots-are-copies');
    expect(c.status).toBe('fail');
    // node:assert appends a version-dependent diff to the message; the two values are in it either way
    expect(c.detail).toMatch(/released/);
    expect(c.detail).toMatch(/reserved/);
  });

  it('a refused start that is reported as settled fails the start check with the outcome', async () => {
    const a = fake(memoryBudgetLedgerAdapter(), (real) => ({
      start: async (k, id) => {
        const r = await real.start(k, id);
        return r.outcome === 'refused' ? { outcome: 'settled', version: 9 } : r;
      },
    }));
    const c = await one(a, 'start-rules');
    expect(c.status).toBe('fail');
    expect(c.detail).toContain("'settled'");
  });

  it('a ledger that admits a reservation past the cap shows the admitted outcome in the failure', async () => {
    const c = await one(noCapBudgetLedgerAdapter(), 'reservation-counts-at-once-and-cap-is-inclusive');
    expect(c.status).toBe('fail');
    expect(c.detail).toContain('reserved');
  });

  it('a release of a committed event that succeeds shows the settled outcome', async () => {
    const c = await one(releaseCommittedBudgetLedgerAdapter(), 'settle-rules');
    expect(c.status).toBe('fail');
    expect(c.detail).toContain("'settled'");
  });

  it('a commit of a released event that succeeds shows the settled outcome', async () => {
    const c = await one(lateCommitBudgetLedgerAdapter(), 'settle-rules');
    expect(c.status).toBe('fail');
    expect(c.detail).toContain("'settled'");
  });
});

describe('the durability claim check', () => {
  const name = 'durable-claim-matches-the-adapter';
  it('names both sides when a volatile ledger claims durability', async () => {
    const c = await one(volatileClaimsDurableBudgetLedgerAdapter(), name);
    expect(c).toMatchObject({ name, status: 'fail' });
    // node:assert may append a diff after the message; the message itself is the first line
    expect(c.detail?.split('\n')[0]).toBe('ledger.durable=true but the adapter declares durable=false');
  });
  it('passes for a volatile ledger that says so', async () => {
    expect(await one(memoryBudgetLedgerAdapter(), name)).toEqual({ name, status: 'pass' });
  });
  it('passes for a durable ledger, whether durability is declared or left to the default', async () => {
    expect(await one(memDurable(), name)).toEqual({ name, status: 'pass' });
    const dflt = memDurable();
    delete dflt.durable;
    expect(await one(dflt, name)).toEqual({ name, status: 'pass' });
  });
  it('fails a durable adapter whose ledger says it is volatile', async () => {
    const c = await one({ ...memoryBudgetLedgerAdapter(), durable: true }, name);
    expect(c).toMatchObject({ name, status: 'fail' });
    expect(c.detail?.split('\n')[0]).toBe('ledger.durable=false but the adapter declares durable=true');
  });
});
