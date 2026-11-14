import { beforeEach, describe, expect, it, vi } from 'vitest';

const kit = vi.hoisted(() => ({
  detectKinds: vi.fn(),
  runBurst: vi.fn(),
  runDurability: vi.fn(),
  checkHistory: vi.fn(),
  formatOps: vi.fn(),
  loadAdapter: vi.fn(),
}));
vi.mock('@atlasauth/pca-store-conformance', () => kit);

import { ATOMICITY_REMEDIATION, DURABILITY_REMEDIATION, checkStore } from './store';

interface H {
  ops: number;
  keys: number;
  outcomes: { true: number; false: number; unknown: number };
  violations: { key: string; counterexample?: number[] }[];
  unresolved: unknown[];
}
const hist = (o: Partial<H> = {}): H => ({ ops: 4, keys: 2, outcomes: { true: 2, false: 2, unknown: 0 }, violations: [], unresolved: [], ...o });
const good = hist();
const spec = 'mod';

/** Wire the kit: kinds, then one history per checkHistory call (atomicity kinds first, then durability kinds). */
function wire(kinds: string[], histories: H[], burst: { ops: { res: string; key: string }[]; errors: number }[] = [], dur: { ops: unknown[]; errors: number }[] = []) {
  kit.detectKinds.mockResolvedValue(kinds);
  kit.runBurst.mockImplementation(async () => burst.shift() ?? { ops: [], errors: 0 });
  kit.runDurability.mockImplementation(async () => dur.shift() ?? { ops: [1, 2, 3, 4], errors: 0 });
  kit.checkHistory.mockImplementation(() => histories.shift() ?? good);
  kit.formatOps.mockImplementation((ops: number[]) => ops.map((o) => `op${o}`));
}
const adapter = (extra: Record<string, unknown> = {}) => ({ name: 'A', ...extra });
const run = async (cfgStore: Record<string, unknown> = {}, a: Record<string, unknown> = adapter()) => {
  kit.loadAdapter.mockResolvedValue(a);
  return checkStore({ store: { adapter: spec, ...cfgStore } as never }, { loadAdapter: kit.loadAdapter });
};

beforeEach(() => {
  for (const f of Object.values(kit)) f.mockReset();
});

describe('checkStore: loading', () => {
  it('skips both checks with the same exact message when no adapter is configured', async () => {
    const detail = 'no store adapter given (--store ./adapter.mjs); the replay store cannot be exercised remotely';
    expect(await checkStore({})).toStrictEqual([
      { id: 'store.atomicity', status: 'skip', detail },
      { id: 'store.durability', status: 'skip', detail },
    ]);
    expect(await checkStore({ store: {} })).toHaveLength(2);
  });

  it('passes the spec and the options (or an empty object) to the loader', async () => {
    wire([], []);
    await run({ options: { a: 'b' } });
    expect(kit.loadAdapter).toHaveBeenLastCalledWith(spec, { a: 'b' });
    await run();
    expect(kit.loadAdapter).toHaveBeenLastCalledWith(spec, {});
  });

  it('a loader failure is a single failed atomicity result', async () => {
    kit.loadAdapter.mockRejectedValue(new Error('no such module'));
    expect(await checkStore({ store: { adapter: spec } }, { loadAdapter: kit.loadAdapter })).toStrictEqual([
      {
        id: 'store.atomicity',
        status: 'fail',
        detail: 'cannot load the store adapter mod: no such module',
        remediation: 'Point --store at a module exporting a store adapter (see the store conformance kit guide).',
      },
    ]);
  });

  it('an adapter that fails while running is a failed atomicity result, and the adapter is still torn down', async () => {
    const teardown = vi.fn(async () => undefined);
    kit.detectKinds.mockRejectedValue(new Error('conn reset'));
    expect(await run({}, adapter({ teardown }))).toStrictEqual([
      { id: 'store.atomicity', status: 'fail', detail: 'the store adapter failed: conn reset', remediation: ATOMICITY_REMEDIATION },
    ]);
    expect(teardown).toHaveBeenCalledTimes(1);
  });

  it('tears the adapter down after a normal run', async () => {
    wire(['consume'], []);
    const teardown = vi.fn(async () => undefined);
    await run({}, adapter({ teardown }));
    expect(teardown).toHaveBeenCalledTimes(1);
  });
});

describe('store.atomicity', () => {
  it('uses 32 clients and 10 rounds by default, and the configured numbers otherwise', async () => {
    wire(['consume'], []);
    await run();
    expect(kit.runBurst).toHaveBeenLastCalledWith(expect.objectContaining({ name: 'A' }), 'consume', { clients: 32, rounds: 10, values: 8 });
    await run({ concurrency: 5, rounds: 3 });
    expect(kit.runBurst).toHaveBeenLastCalledWith(expect.objectContaining({ name: 'A' }), 'consume', { clients: 5, rounds: 3, values: 8 });
  });

  it('pass: exact detail, winners counted per distinct key, observed counters, no remediation', async () => {
    const ops = [
      { res: 'true', key: 'k1' },
      { res: 'true', key: 'k1' },
      { res: 'true', key: 'k2' },
      { res: 'false', key: 'k3' },
    ];
    wire(['consume'], [hist()], [{ ops, errors: 0 }]);
    const [atom] = await run({ concurrency: 5, rounds: 3 });
    expect(atom).toStrictEqual({
      id: 'store.atomicity',
      status: 'pass',
      detail: 'A: consumeOnce: 3 rounds of 5 concurrent conflicting calls linearizable (2 of 3 rounds had exactly one TRUE).',
      observed: { consume: { ops: 4, keys: 2, outcomes: { true: 2, false: 2, unknown: 0 }, violations: 0, unresolved: 0 } },
    });
  });

  it('advance has no winners clause; failed calls are reported; parts are joined by "; "', async () => {
    wire(['consume', 'advance'], [good, good], [{ ops: [], errors: 0 }, { ops: [], errors: 2 }]);
    const [atom] = await run({ concurrency: 4, rounds: 2 });
    expect(atom!.status).toBe('pass');
    expect(atom!.detail).toBe(
      'A: consumeOnce: 2 rounds of 4 concurrent conflicting calls linearizable (0 of 2 rounds had exactly one TRUE); advance: 2 rounds of 4 concurrent conflicting calls linearizable, 2 calls failed closed.',
    );
    expect(Object.keys(atom!.observed!)).toEqual(['consume', 'advance']);
  });

  it('fail: counts violations, quotes the first counterexample only, adds the remediation', async () => {
    wire(['consume', 'advance'], [hist({ violations: [{ key: 'kk', counterexample: [1, 2] }, { key: 'k2' }] }), hist({ violations: [{ key: 'other', counterexample: [9] }] })]);
    const [atom] = await run({ concurrency: 5, rounds: 3 });
    expect(atom).toStrictEqual({
      id: 'store.atomicity',
      status: 'fail',
      detail:
        'A: consumeOnce: 2 of 3 same-key rounds NOT linearizable (5 concurrent clients); advance: 1 of 3 same-key rounds NOT linearizable (5 concurrent clients). First violating key kk: op1 | op2',
      remediation: ATOMICITY_REMEDIATION,
      observed: {
        consume: { ops: 4, keys: 2, outcomes: { true: 2, false: 2, unknown: 0 }, violations: 2, unresolved: 0 },
        advance: { ops: 4, keys: 2, outcomes: { true: 2, false: 2, unknown: 0 }, violations: 1, unresolved: 0 },
      },
    });
  });

  it('a violation without a counterexample quotes an empty one', async () => {
    wire(['consume'], [hist({ violations: [{ key: 'kk' }] })]);
    const [atom] = await run();
    expect(atom!.detail.endsWith(' First violating key kk: ')).toBe(true);
    expect(kit.formatOps).toHaveBeenCalledWith([]);
  });

  it('inconclusive when nothing was decided: warn with the failed-call count and no undecided clause', async () => {
    wire(['consume'], [hist({ outcomes: { true: 0, false: 0, unknown: 4 } })], [{ ops: [], errors: 3 }]);
    const [atom] = await run();
    expect(atom).toMatchObject({
      status: 'warn',
      detail: 'A: consumeOnce: inconclusive (3 of 4 calls failed or timed out).',
      remediation: ATOMICITY_REMEDIATION,
    });
  });

  it('inconclusive when some keys are undecided even though other calls were decided', async () => {
    wire(['consume'], [hist({ unresolved: [{}, {}] })], [{ ops: [], errors: 1 }]);
    const [atom] = await run();
    expect(atom).toMatchObject({ status: 'warn', detail: 'A: consumeOnce: inconclusive (1 of 4 calls failed or timed out, 2 key(s) undecided).' });
    expect(atom!.observed).toMatchObject({ consume: { unresolved: 2 } });
  });

  it('status only ever gets worse: warn then fail is fail, fail then warn stays fail, warn then pass stays warn', async () => {
    const warnH = hist({ outcomes: { true: 0, false: 0, unknown: 4 } });
    const failH = hist({ violations: [{ key: 'k' }] });
    wire(['consume', 'advance'], [warnH, failH]);
    expect((await run())[0]!.status).toBe('fail');
    wire(['consume', 'advance'], [failH, warnH]);
    expect((await run())[0]!.status).toBe('fail');
    wire(['consume', 'advance'], [warnH, good]);
    expect((await run())[0]!.status).toBe('warn');
    wire(['consume', 'advance'], [warnH, warnH]);
    expect((await run())[0]!.status).toBe('warn');
  });
});

describe('store.durability', () => {
  const dur = async (histories: H[], a: Record<string, unknown> = adapter(), kinds = ['consume'], runs: { ops: unknown[]; errors: number }[] = []) => {
    wire(kinds, [good, ...kinds.slice(1).map(() => good), ...histories], [], runs);
    return (await run({}, a))[1]!;
  };

  it('a non-durable adapter is a warn with the exact message, without running the workload', async () => {
    wire(['consume'], []);
    const r = (await run({}, adapter({ capabilities: { durable: false } })))[1];
    expect(r).toStrictEqual({
      id: 'store.durability',
      status: 'warn',
      detail: 'A declares itself non-durable: a restart forgets consumed nonces',
      remediation: DURABILITY_REMEDIATION,
    });
    expect(kit.runDurability).not.toHaveBeenCalled();
  });

  it('works for an adapter without a capabilities object', async () => {
    const r = await dur([good]);
    expect(r.status).toBe('pass');
  });

  it('pass: survived, restart wording depends on the restart hook, no remediation', async () => {
    expect(await dur([good])).toStrictEqual({
      id: 'store.durability',
      status: 'pass',
      detail: 'A (write, close, re-open (no restart() hook: the backend itself was not restarted)): consumeOnce: survived.',
    });
    const withRestart = await dur([good, good], adapter({ restart: async () => undefined, capabilities: {} }), ['consume', 'advance']);
    expect(withRestart).toStrictEqual({
      id: 'store.durability',
      status: 'pass',
      detail: 'A (write, close, restart() the backend, read back): consumeOnce: survived; advance: survived.',
    });
  });

  it('fail: state lost, first counterexample only, remediation', async () => {
    const r = await dur(
      [hist({ violations: [{ key: 'a', counterexample: [1] }] }), hist({ violations: [{ key: 'b', counterexample: [2] }] })],
      adapter(),
      ['consume', 'advance'],
    );
    expect(r).toStrictEqual({
      id: 'store.durability',
      status: 'fail',
      detail: 'A (write, close, re-open (no restart() hook: the backend itself was not restarted)): consumeOnce: state LOST across close/restart; advance: state LOST across close/restart. First violating key a: op1',
      remediation: DURABILITY_REMEDIATION,
    });
  });

  it('inconclusive when fewer calls were decided than made', async () => {
    const r = await dur([hist({ outcomes: { true: 1, false: 2, unknown: 1 } })], adapter(), ['consume'], [{ ops: [1, 2, 3, 4], errors: 1 }]);
    expect(r).toStrictEqual({
      id: 'store.durability',
      status: 'warn',
      detail: 'A (write, close, re-open (no restart() hook: the backend itself was not restarted)): consumeOnce: inconclusive (1 calls failed).',
      remediation: DURABILITY_REMEDIATION,
    });
  });

  it('exactly as many decided calls as made is a pass', async () => {
    const r = await dur([hist({ outcomes: { true: 1, false: 3, unknown: 0 } })]);
    expect(r.status).toBe('pass');
  });

  it('status only ever gets worse across kinds', async () => {
    const warnH = hist({ outcomes: { true: 0, false: 0, unknown: 4 } });
    const failH = hist({ violations: [{ key: 'k' }] });
    expect((await dur([failH, warnH], adapter(), ['consume', 'advance'])).status).toBe('fail');
    expect((await dur([warnH, failH], adapter(), ['consume', 'advance'])).status).toBe('fail');
    expect((await dur([warnH, good], adapter(), ['consume', 'advance'])).status).toBe('warn');
    expect((await dur([good, warnH], adapter(), ['consume', 'advance'])).status).toBe('warn');
  });
});
