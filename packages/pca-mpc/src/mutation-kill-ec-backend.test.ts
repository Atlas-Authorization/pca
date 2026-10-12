/**
 * Mutation-kill suite for ec.ts backend selection and dispatch: the lazy, cached WASM loader (candidate
 * order, the surface check, failure handling) and the routing of every group op / the cofactor check
 * through the WASM core when it is loaded. Each scenario re-imports ec.ts with a controlled `createRequire`.
 */
import * as actualModule from 'node:module';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';

type Req = (spec: string) => unknown;
type Ec = typeof import('./ec');

const realRequire = actualModule.createRequire(__filename);
const realWasm = ((): Record<string, (...a: never[]) => unknown> => {
  try {
    return realRequire('@atlasauth/pca-mpc-wasm') as Record<string, (...a: never[]) => unknown>;
  } catch {
    return realRequire(join(__dirname, '..', '..', 'pca-mpc-wasm', 'dist', 'index.js')) as Record<string, (...a: never[]) => unknown>;
  }
})();
const NAMES = ['mulBase', 'mul', 'add', 'sub', 'neg', 'isOnCurve', 'isIdentity', 'isInSubgroup'] as const;
const full = (): Record<string, unknown> => Object.fromEntries(NAMES.map((n) => [n, vi.fn(realWasm[n] as (...a: unknown[]) => unknown)]));

let createRequireCalls = 0;
async function load(req: Req | 'throw'): Promise<Ec> {
  vi.resetModules();
  createRequireCalls = 0;
  vi.doMock('node:module', () => ({
    ...actualModule,
    createRequire: () => {
      createRequireCalls++;
      if (req === 'throw') throw new Error('createRequire unavailable');
      return req;
    },
  }));
  return import('./ec');
}
afterEach(() => {
  vi.doUnmock('node:module');
  vi.resetModules();
});

const SECOND = join(__dirname, '..', '..', 'pca-mpc-wasm', 'dist', 'index.js');

describe('loader', () => {
  it('tries the workspace package, then the sibling dist path, and falls back to pure when both fail', async () => {
    const seen: string[] = [];
    const ec = await load((s) => {
      seen.push(s);
      throw new Error('missing');
    });
    expect(ec.isWasmCurveActive()).toBe(false);
    expect(seen).toEqual(['@atlasauth/pca-mpc-wasm', SECOND]);
    // the negative result is cached: no second probe
    expect(ec.isWasmCurveActive()).toBe(false);
    expect(seen.length).toBe(2);
    expect(createRequireCalls).toBe(1);
  });
  it('stops at the first candidate that exposes the whole surface, and caches it', async () => {
    const seen: string[] = [];
    const ec = await load((s) => {
      seen.push(s);
      return full();
    });
    expect(ec.isWasmCurveActive()).toBe(true);
    expect(ec.isWasmCurveActive()).toBe(true);
    expect(seen).toEqual(['@atlasauth/pca-mpc-wasm']);
  });
  it('falls through to the dist path when the package is missing', async () => {
    const seen: string[] = [];
    const ec = await load((s) => {
      seen.push(s);
      if (s === '@atlasauth/pca-mpc-wasm') throw new Error('missing');
      return full();
    });
    expect(ec.isWasmCurveActive()).toBe(true);
    expect(seen).toEqual(['@atlasauth/pca-mpc-wasm', SECOND]);
  });
  it('an incomplete module is not used and the next candidate is tried', async () => {
    const seen: string[] = [];
    const ec = await load((s) => {
      seen.push(s);
      if (s === '@atlasauth/pca-mpc-wasm') {
        const m = full();
        delete m.isInSubgroup;
        return m;
      }
      return full();
    });
    expect(ec.isWasmCurveActive()).toBe(true);
    expect(seen).toEqual(['@atlasauth/pca-mpc-wasm', SECOND]);
  });
  for (const missing of NAMES) {
    it(`a module without ${missing}() (or with it as a non-function) is refused`, async () => {
      const ec = await load(() => {
        const m = full();
        m[missing] = 42;
        return m;
      });
      expect(ec.isWasmCurveActive()).toBe(false);
    });
  }
  it('a non-object module (a function carrying every method) is refused; a null module is skipped', async () => {
    const ec = await load(() => Object.assign(() => undefined, full()));
    expect(ec.isWasmCurveActive()).toBe(false);
    const ec2 = await load(() => null);
    expect(ec2.isWasmCurveActive()).toBe(false);
    const ec3 = await load(() => 'module');
    expect(ec3.isWasmCurveActive()).toBe(false);
  });
  it('createRequire itself failing pins the pure path', async () => {
    const ec = await load('throw');
    expect(ec.isWasmCurveActive()).toBe(false);
    expect(ec.isWasmCurveActive()).toBe(false);
    expect(createRequireCalls).toBe(1);
    expect(ec.isIdentity(ec.mul(ec.L, ec.BASE))).toBe(true);
  });
});

describe('dispatch through the core', () => {
  type Core = Record<(typeof NAMES)[number], ReturnType<typeof vi.fn>>;
  async function withCore(): Promise<{ ec: Ec; m: Core }> {
    const m = full() as Core;
    const ec = await load(() => m);
    expect(ec.isWasmCurveActive()).toBe(true);
    return { ec, m };
  }
  it('add, sub, neg, mul and mulBase call the core with compressed points and decompress its answer', async () => {
    const { ec, m } = await withCore();
    const p = ec.mulBase(3n);
    expect(m.mulBase).toHaveBeenCalledWith(3n);
    const q = ec.mulBase(5n);
    const hex = (u: Uint8Array): string => Buffer.from(u).toString('hex');
    const r = ec.add(p, q);
    expect(m.add).toHaveBeenCalledTimes(1);
    expect(hex(m.add.mock.calls[0]![0] as Uint8Array)).toBe(hex(ec.compressPoint(p)));
    expect(hex(m.add.mock.calls[0]![1] as Uint8Array)).toBe(hex(ec.compressPoint(q)));
    expect(ec.equal(r, ec.mulBase(8n))).toBe(true);
    expect(ec.equal(ec.sub(q, p), ec.mulBase(2n))).toBe(true);
    expect(m.sub).toHaveBeenCalledTimes(1);
    expect(ec.equal(ec.neg(p), ec.mulBase(ec.L - 3n))).toBe(true);
    expect(m.neg).toHaveBeenCalledTimes(1);
    expect(ec.equal(ec.mul(4n, p), ec.mulBase(12n))).toBe(true);
    expect(m.mul).toHaveBeenCalledTimes(1);
    expect(m.mul.mock.calls[0]![0]).toBe(4n);
  });
  it('hasPrimeOrder on an on-curve point asks the core: subgroup OR identity', async () => {
    const { ec, m } = await withCore();
    expect(ec.hasPrimeOrder(ec.BASE)).toBe(true);
    expect(m.isInSubgroup).toHaveBeenCalledTimes(1);
    // A core whose torsion test says "no" for the identity still yields true via its identity test.
    m.isInSubgroup.mockReturnValue(false);
    expect(ec.hasPrimeOrder(ec.IDENTITY)).toBe(true);
    expect(m.isIdentity).toHaveBeenCalled();
    m.isIdentity.mockReturnValue(false);
    expect(ec.hasPrimeOrder(ec.BASE)).toBe(false);
  });
  it('hasPrimeOrder on an OFF-curve point never reaches the core (compression is only faithful on the curve)', async () => {
    const { ec, m } = await withCore();
    const off = { X: 3n, Y: 4n, Z: 1n, T: 12n };
    m.isInSubgroup.mockReturnValue(true);
    m.isIdentity.mockReturnValue(true);
    expect(ec.hasPrimeOrder(off)).toBe(false);
    expect(m.isInSubgroup).not.toHaveBeenCalled();
    expect(m.isIdentity).not.toHaveBeenCalled();
  });
  it('the real core rejects small-order points', async () => {
    const { ec } = await withCore();
    const t2 = { X: 0n, Y: ec.Q - 1n, Z: 1n, T: 0n };
    expect(ec.hasPrimeOrder(t2)).toBe(false);
    expect(ec.isInSubgroup(t2)).toBe(false);
    expect(ec.isInSubgroup(ec.BASE)).toBe(true);
  });
});
