import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { durableFileAdapter, evictingAdapter, readThenWriteAdapter } from './reference';

describe('reference adapters with a non-finite clock never re-admit a live key', () => {
  const adapters = {
    'read-then-write': () => readThenWriteAdapter(),
    evicting: () => evictingAdapter(),
    durable: () => durableFileAdapter({ dir: mkdtempSync(join(tmpdir(), 'pcasc-nan-')) }),
  };
  // pre-fix: `until >= NaN` (and `prev >= NaN`) was false, so the live key read as expired and was consumable again
  it.each(Object.entries(adapters))('%s: a NaN or -Infinity now refuses a live key', async (_n, make) => {
    const c = await make().open();
    expect(await c.consumeOnce!('k', 100, 5)).toBe(true);
    for (const bad of [Number.NaN, Number.NEGATIVE_INFINITY]) {
      const second = await c.consumeOnce!('k', 100, bad).then(
        (v) => v,
        () => false, // a refusal by throwing is also fail-closed
      );
      expect(second).toBe(false);
    }
  });
});
