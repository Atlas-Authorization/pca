import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';

describe('where the binding reads its wasm core from', () => {
  afterEach(() => {
    vi.doUnmock('node:fs');
    vi.resetModules();
  });

  it('reads exactly <package root>/wasm/pca_fndsa_wasm.wasm, once', async () => {
    vi.resetModules();
    const seen: unknown[] = [];
    vi.doMock('node:fs', async (orig) => {
      const actual = await orig<typeof import('node:fs')>();
      return {
        ...actual,
        readFileSync: (...a: Parameters<typeof actual.readFileSync>) => {
          seen.push(a[0]);
          return actual.readFileSync(...a);
        },
      };
    });
    const mod = await import('./index');
    expect(typeof mod.keygen).toBe('function');
    expect(seen).toEqual([join(dirname(__dirname), 'wasm', 'pca_fndsa_wasm.wasm')]);
  });
});
