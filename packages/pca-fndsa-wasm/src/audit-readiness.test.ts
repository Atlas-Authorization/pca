import { afterEach, describe, expect, it, vi } from 'vitest';
import { FnDsaError, MSG_CAP, SEED_BYTES, keygen, sign, sizes, verify } from './index';

// Audit-readiness: the fail-closed table of the README, one exact outcome per row.
const seed = (n: number): Uint8Array => new Uint8Array(SEED_BYTES).fill(n);
const msg = (n = 8): Uint8Array => new Uint8Array(n).fill(7);
const errOf = (f: () => unknown): FnDsaError | undefined => {
  try {
    f();
  } catch (e) {
    return e as FnDsaError;
  }
  return undefined;
};

describe('binding fail-closed table: exact errors', () => {
  it('unknown parameter set -> FnDsaError "unsupported FN-DSA variant" (sizes, keygen, sign, verify)', () => {
    const v = 'fn-dsa-256' as never;
    for (const f of [() => sizes(v), () => keygen(v, seed(1)), () => sign(v, new Uint8Array(1), msg(), seed(1)), () => verify(v, new Uint8Array(1), msg(), new Uint8Array(1))]) {
      const e = errOf(f);
      expect(e).toBeInstanceOf(FnDsaError);
      expect(e!.message).toBe('unsupported FN-DSA variant: fn-dsa-256');
    }
  });

  it('wrong-size inputs name the field and both sizes', () => {
    const s = sizes('fn-dsa-512');
    expect(s).toEqual({ verifyingKey: 897, signingKey: 1345, signature: 666 });
    const k = keygen('fn-dsa-512', seed(2));
    expect(errOf(() => keygen('fn-dsa-512', new Uint8Array(SEED_BYTES + 1)))!.message).toBe(`keygen: seed: expected ${SEED_BYTES} bytes, got ${SEED_BYTES + 1}`);
    expect(errOf(() => sign('fn-dsa-512', k.signingKey.slice(1), msg(), seed(3)))!.message).toBe('sign: signingKey: expected 1345 bytes, got 1344');
    expect(errOf(() => sign('fn-dsa-512', k.signingKey, msg(), seed(3).slice(1)))!.message).toBe(`sign: seed: expected ${SEED_BYTES} bytes, got ${SEED_BYTES - 1}`);
    const sig = sign('fn-dsa-512', k.signingKey, msg(), seed(3));
    expect(errOf(() => verify('fn-dsa-512', k.verifyingKey.slice(1), msg(), sig))!.message).toBe('verify: verifyingKey: expected 897 bytes, got 896');
    expect(errOf(() => verify('fn-dsa-512', k.verifyingKey, msg(), sig.slice(1)))!.message).toBe('verify: signature: expected 666 bytes, got 665');
  });

  it('a message of exactly MSG_CAP signs and verifies; one byte more -> FnDsaError for sign and verify', () => {
    const k = keygen('fn-dsa-512', seed(4));
    const m = msg(MSG_CAP);
    const sig = sign('fn-dsa-512', k.signingKey, m, seed(5));
    expect(verify('fn-dsa-512', k.verifyingKey, m, sig)).toBe(true);
    const big = msg(MSG_CAP + 1);
    expect(errOf(() => sign('fn-dsa-512', k.signingKey, big, seed(5)))!.message).toBe(`message exceeds ${MSG_CAP} bytes (${MSG_CAP + 1})`);
    expect(errOf(() => verify('fn-dsa-512', k.verifyingKey, big, sig))!.message).toBe(`message exceeds ${MSG_CAP} bytes (${MSG_CAP + 1})`);
  });

  it('a well-sized but undecodable key, an all-zero signature and an all-0xFF signature -> false, not an error', () => {
    for (const variant of ['fn-dsa-512', 'fn-dsa-1024'] as const) {
      const s = sizes(variant);
      const k = keygen(variant, seed(6));
      const sig = sign(variant, k.signingKey, msg(), seed(7));
      expect(verify(variant, new Uint8Array(s.verifyingKey).fill(0xff), msg(), sig)).toBe(false);
      expect(verify(variant, k.verifyingKey, msg(), new Uint8Array(s.signature))).toBe(false);
      expect(verify(variant, k.verifyingKey, msg(), new Uint8Array(s.signature).fill(0xff))).toBe(false);
      expect(verify(variant, k.verifyingKey, msg(), sig)).toBe(true);
    }
  });

  it('an undecodable signing key (right size, wrong content) -> FnDsaError from sign', () => {
    const e = errOf(() => sign('fn-dsa-512', new Uint8Array(1345).fill(0xff), msg(), seed(8)));
    expect(e).toBeInstanceOf(FnDsaError);
    expect(e!.message).toBe('sign: wasm sign failed for fn-dsa-512');
  });

  it('verification does not depend on state left by an earlier call (buffers are rewritten each time)', () => {
    const a = keygen('fn-dsa-512', seed(9));
    const b = keygen('fn-dsa-512', seed(10));
    const sa = sign('fn-dsa-512', a.signingKey, msg(), seed(11));
    sign('fn-dsa-512', b.signingKey, msg(), seed(12)); // overwrite the shared sig/msg buffers
    expect(verify('fn-dsa-512', a.verifyingKey, msg(), sa)).toBe(true);
    expect(verify('fn-dsa-512', b.verifyingKey, msg(), sa)).toBe(false);
  });
});

describe('binding fail-closed table: the wasm module is missing or corrupt', () => {
  afterEach(() => {
    vi.doUnmock('node:fs');
    vi.resetModules();
  });

  it('wasm file missing -> importing the binding rejects with the read error (no JavaScript fallback exists)', async () => {
    vi.resetModules();
    vi.doMock('node:fs', async (orig) => ({
      ...(await orig<typeof import('node:fs')>()),
      readFileSync: () => {
        throw Object.assign(new Error('ENOENT: no such file or directory'), { code: 'ENOENT' });
      },
    }));
    await expect(import('./index')).rejects.toThrow(/ENOENT/);
  });

  it('wasm file corrupt (not a module) -> importing the binding rejects with a compile error', async () => {
    vi.resetModules();
    vi.doMock('node:fs', async (orig) => ({
      ...(await orig<typeof import('node:fs')>()),
      readFileSync: () => new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
    }));
    await expect(import('./index')).rejects.toThrow(/WebAssembly|CompileError|magic/i);
  });
});
