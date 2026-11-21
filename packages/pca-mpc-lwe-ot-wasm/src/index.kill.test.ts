import { dirname, resolve, join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { LatticeOtError, TVEC_BYTES, ringSub } from './index';

describe('LatticeOtError', () => {
  it('carries its own name', () => {
    const e = new LatticeOtError('x');
    expect(e.name).toBe('LatticeOtError');
    expect(e.message).toBe('x');
  });
});

describe('length labels', () => {
  it('ringSub names the offending operand', () => {
    expect(() => ringSub(new Uint8Array(TVEC_BYTES), new Uint8Array(3))).toThrow('ringSub: b: expected 1152 bytes, got 3');
    expect(() => ringSub(new Uint8Array(3), new Uint8Array(TVEC_BYTES))).toThrow('ringSub: a: expected 1152 bytes, got 3');
  });
});

describe('wasm location', () => {
  it('loads <package root>/wasm/pca_mpc_lwe_ot_wasm.wasm', async () => {
    const paths: string[] = [];
    vi.resetModules();
    vi.doMock('node:fs', async (orig) => {
      const real = await orig<typeof import('node:fs')>();
      return { ...real, readFileSync: (p: string, ...rest: unknown[]) => { paths.push(String(p)); return (real.readFileSync as (...a: unknown[]) => unknown)(p, ...rest); } };
    });
    await import('./index');
    vi.doUnmock('node:fs');
    const root = resolve(__dirname, '..');
    expect(paths.map((p) => resolve(p))).toContain(join(root, 'wasm', 'pca_mpc_lwe_ot_wasm.wasm'));
    expect(dirname(dirname(paths[0]!))).toBe(root);
  });
});
