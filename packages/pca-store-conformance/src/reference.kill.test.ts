import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { openDurableState } from '@atlasauth/pca/durable-state';
import { durableFileAdapter, evictingAdapter, inMemoryAdapter, nonStrictCounterAdapter, readThenWriteAdapter } from './reference';

describe('reference adapters: declared capabilities', () => {
  it('each adapter states exactly what it claims', () => {
    expect(durableFileAdapter({ dir: mkdtempSync(join(tmpdir(), 'pcasc-ref-')) }).capabilities).toEqual({ durable: true });
    expect(readThenWriteAdapter().capabilities).toEqual({ durable: false });
    expect(evictingAdapter().capabilities).toEqual({ durable: false });
    expect(nonStrictCounterAdapter().capabilities).toEqual({ durable: false, consumeOnce: false });
  });
});

describe('inMemoryAdapter capacity', () => {
  it('holds more live keys than the library default', async () => {
    const c = await inMemoryAdapter().open();
    for (let i = 0; i <= 100_000; i++) expect(await c.consumeOnce!(`k${i}`, 1e12, 0)).toBe(true);
  });
});

describe('durableFileAdapter', () => {
  it('refuses a retention horizon before now, with its message', async () => {
    const c = await durableFileAdapter({ dir: mkdtempSync(join(tmpdir(), 'pcasc-ref-')) }).open();
    await expect(c.consumeOnce!('k', 5, 6)).rejects.toThrow('consumeOnce: retainUntilMs is before nowMs');
  });

  it('a stored horizon that is not a number is replaced, not compared', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-ref-'));
    const st = await openDurableState({ dir });
    await st.update('n:k', () => '1000' as never);
    const c = await durableFileAdapter({ dir }).open();
    expect(await c.consumeOnce!('k', 200, 50)).toBe(true);
  });
});

describe('bad adapters keep the exact flaw they are meant to show', () => {
  it('read-then-write and evicting caches treat a horizon equal to now as live', async () => {
    for (const a of [readThenWriteAdapter(), evictingAdapter()]) {
      const c = await a.open();
      expect(await c.consumeOnce!('k', 10, 5)).toBe(true);
      expect(await c.consumeOnce!('k', 20, 10)).toBe(false);
      expect(await c.consumeOnce!('k', 20, 11)).toBe(true);
    }
  });

  it('the evicting cache accepts a larger counter and refuses an equal or smaller one', async () => {
    const c = await evictingAdapter().open();
    expect(await c.advance!('s', 1)).toBe(true);
    expect(await c.advance!('s', 2)).toBe(true);
    expect(await c.advance!('s', 2)).toBe(false);
    expect(await c.advance!('s', 1)).toBe(false);
  });

  it('the non-strict counter accepts an equal value but refuses a smaller one', async () => {
    const c = await nonStrictCounterAdapter().open();
    expect(await c.advance!('s', 2)).toBe(true);
    expect(await c.advance!('s', 2)).toBe(true);
    expect(await c.advance!('s', 1)).toBe(false);
  });
});
