// Positive controls: the kit MUST flag every bad reference adapter (with a counterexample), and the good ones must pass.
// A checker that passes everything is worthless; these tests are what make a PASS mean something.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { checkHistory } from './check';
import { runBurst, runConcurrent, runDurability, runRetention } from './harness';
import {
  REFERENCE_ADAPTERS,
  durableFileAdapter,
  evictingAdapter,
  inMemoryAdapter,
  nonStrictCounterAdapter,
  readThenWriteAdapter,
  volatileAdapter,
} from './reference';
import { runConformance } from './runner';

const quick = { clients: 8, durationMs: 300, rounds: 10, revisitKeys: 200 };

describe('good references pass', () => {
  it('InMemoryReplayStore (single process): every in-process test passes; durability skipped as declared', async () => {
    const r = await runConformance(inMemoryAdapter(), quick);
    expect(r.status).toBe('pass');
    expect(r.tests.find((t) => t.test === 'durability')!.status).toBe('skip');
    expect(r.tests.filter((t) => t.status === 'pass').length).toBe(6);
  });
  it('durable-state file store: passes every in-process test including durability', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-good-'));
    const r = await runConformance(durableFileAdapter({ dir }), { clients: 4, durationMs: 300, rounds: 5, revisitKeys: 30, tests: ['burst', 'concurrent', 'retention', 'durability'] });
    expect(r.status).toBe('pass');
    expect(r.tests.filter((t) => t.status === 'pass').length).toBe(8);
    expect(r.tests.every((t) => t.ops > 0)).toBe(true);
  }, 60_000);
  it('the durable file adapter keeps the larger horizon and rejects equal counters', async () => {
    const c = await durableFileAdapter().open();
    expect(await c.consumeOnce!('k', 100, 50)).toBe(true);
    expect(await c.consumeOnce!('k', 200, 100)).toBe(false); // live at 100 (horizon 100 >= now)
    expect(await c.consumeOnce!('k', 300, 101)).toBe(true); // expired: may be consumed again
    expect(await c.consumeOnce!('k', 400, 299)).toBe(false); // horizon is now 300
    await expect(c.consumeOnce!('k2', 5, 6)).rejects.toThrow(RangeError);
    expect(await c.consumeOnce!('k2', 6, 6)).toBe(true);
    expect(await c.advance!('s', 3)).toBe(true);
    expect(await c.advance!('s', 3)).toBe(false);
    expect(await c.advance!('s', 2)).toBe(false);
    expect(await c.advance!('s', 4)).toBe(true);
  });
  it('the in-memory adapter forwards both operations to one shared store', async () => {
    const a = inMemoryAdapter();
    const [x, y] = [await a.open(), await a.open()];
    expect(await x.consumeOnce!('k', 10, 1)).toBe(true);
    expect(await y.consumeOnce!('k', 10, 1)).toBe(false);
    expect(await x.advance!('s', 1)).toBe(true);
    expect(await y.advance!('s', 1)).toBe(false);
    expect(a.capabilities).toEqual({ durable: false });
  });
});

describe('positive controls are flagged', () => {
  it('read-then-write: two clients both read "absent" -> two TRUEs for one key (burst and concurrent)', async () => {
    for (const kind of ['consume', 'advance'] as const) {
      const b = checkHistory((await runBurst(readThenWriteAdapter(), kind, { clients: 8, rounds: 5 })).ops);
      expect(b.violations.length, kind).toBeGreaterThan(0);
      expect(b.violations[0]!.counterexample!.length).toBeLessThanOrEqual(3);
      const c = checkHistory((await runConcurrent(readThenWriteAdapter(), kind, { clients: 8, durationMs: 100 })).ops);
      expect(c.violations.length, kind).toBeGreaterThan(0);
    }
    const r = await runConformance(readThenWriteAdapter(), { ...quick, tests: ['burst'] });
    expect(r.status).toBe('fail');
  });
  it('volatile store: the durability test sees a consumed nonce / counter come back after restart', async () => {
    for (const kind of ['consume', 'advance'] as const) {
      const h = checkHistory((await runDurability(volatileAdapter(), kind)).ops);
      expect(h.violations, kind).toHaveLength(1);
      expect(h.violations[0]!.counterexample!.map((o) => o.client)).toEqual(['before-restart', 'after-restart']);
    }
    // ... while it looks perfect without a restart
    const ok = await runConformance(volatileAdapter(), { ...quick, tests: ['burst', 'concurrent', 'retention'] });
    expect(ok.status).toBe('pass');
    expect((await runConformance(volatileAdapter(), { tests: ['durability'] })).status).toBe('fail');
  });
  it('evicting cache: the retention test sees evicted live records accepted again', async () => {
    for (const kind of ['consume', 'advance'] as const) {
      const h = checkHistory((await runRetention(evictingAdapter({ capacity: 16 }), kind, { clients: 4, revisitKeys: 40 })).ops);
      expect(h.violations.length, kind).toBe(40);
    }
    const within = checkHistory((await runRetention(evictingAdapter({ capacity: 64 }), 'consume', { clients: 4, revisitKeys: 64 })).ops);
    expect(within.ok).toBe(true); // below capacity nothing is evicted: the flag comes from eviction, not from the harness
    const over = checkHistory((await runRetention(evictingAdapter({ capacity: 64 }), 'consume', { clients: 4, revisitKeys: 65 })).ops);
    expect(over.violations.length).toBeGreaterThan(0);
    expect(evictingAdapter().name).toContain('capacity 64');
    expect(evictingAdapter({ capacity: '7' }).name).toContain('capacity 7');
  });
  it('non-strict counter: an equal value is accepted twice (burst, concurrent)', async () => {
    const b = checkHistory((await runBurst(nonStrictCounterAdapter(), 'advance', { clients: 8, rounds: 5, values: 2 })).ops);
    expect(b.violations.length).toBeGreaterThan(0);
    const r = await runConformance(nonStrictCounterAdapter(), { ...quick, tests: ['burst', 'concurrent'] });
    expect(r.status).toBe('fail');
    expect(r.tests.map((t) => t.kind)).toEqual(['advance', 'advance']);
    const c = await nonStrictCounterAdapter().open();
    expect(await c.advance!('s', 5)).toBe(true);
    expect(await c.advance!('s', 4)).toBe(false);
    expect(await c.advance!('s', 5)).toBe(true);
  });
  it('the bad adapters behave as documented in isolation', async () => {
    const r = await readThenWriteAdapter().open();
    expect(await r.consumeOnce!('k', 10, 1)).toBe(true);
    expect(await r.consumeOnce!('k', 10, 2)).toBe(false);
    expect(await r.consumeOnce!('k', 20, 11)).toBe(true);
    expect(await r.advance!('s', 2)).toBe(true);
    expect(await r.advance!('s', 2)).toBe(false);
    expect(await r.advance!('s', 3)).toBe(true);
    const e = await evictingAdapter({ capacity: 1 }).open();
    expect(await e.consumeOnce!('a', 10, 1)).toBe(true);
    expect(await e.consumeOnce!('a', 10, 1)).toBe(false);
    expect(await e.consumeOnce!('a', 20, 11)).toBe(true);
    expect(await e.advance!('s', 1)).toBe(true);
    expect(await e.advance!('s', 1)).toBe(false);
    expect(await e.advance!('t', 1)).toBe(true);
    expect(await e.advance!('s', 1)).toBe(true); // evicted
    const v = volatileAdapter();
    const vc = await v.open();
    expect(await vc.advance!('s', 1)).toBe(true);
    await v.restart!();
    expect(await vc.advance!('s', 1)).toBe(true); // forgotten (even through an old client)
    expect(v.capabilities).toEqual({ durable: true });
  });
});

describe('REFERENCE_ADAPTERS', () => {
  it('names every reference and passes options through', () => {
    expect(Object.keys(REFERENCE_ADAPTERS).sort()).toEqual(['bad-evicting', 'bad-non-strict-counter', 'bad-read-then-write', 'bad-volatile', 'durable-file', 'in-memory']);
    expect(REFERENCE_ADAPTERS['in-memory']!({}).name).toMatch(/in-memory/);
    expect(REFERENCE_ADAPTERS['durable-file']!({ dir: '/tmp/pcasc-x' }).name).toContain('/tmp/pcasc-x');
    expect(REFERENCE_ADAPTERS['bad-read-then-write']!({}).name).toMatch(/read-then-write/);
    expect(REFERENCE_ADAPTERS['bad-volatile']!({}).name).toMatch(/volatile/);
    expect(REFERENCE_ADAPTERS['bad-evicting']!({ capacity: '3' }).name).toContain('capacity 3');
    expect(REFERENCE_ADAPTERS['bad-non-strict-counter']!({}).name).toMatch(/non-strict/);
  });
});
