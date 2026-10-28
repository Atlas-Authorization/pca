import { afterEach, describe, expect, it, vi } from 'vitest';
import { CT_BYTES, HASHIN_CAP, LatticeOtError, PK_BYTES, SK_BYTES, SYM_BYTES, TVEC_BYTES, hashToRing, kpkeDec, kpkeEnc, kpkeKeygen, ringAdd, ringSub } from './index';

// Audit-readiness: the fail-closed table of the README, one exact outcome per row.
const msgOf = (f: () => unknown): string | undefined => {
  try {
    f();
  } catch (e) {
    expect(e).toBeInstanceOf(LatticeOtError);
    return (e as Error).message;
  }
  return undefined;
};
const z = (n: number): Uint8Array => new Uint8Array(n);

describe('lattice-core fail-closed table: exact error messages', () => {
  it('wrong length -> "<op>: <argument>: expected N bytes, got M"', () => {
    expect(msgOf(() => kpkeKeygen(z(31)))).toBe('kpkeKeygen: seed: expected 32 bytes, got 31');
    expect(msgOf(() => kpkeEnc(z(PK_BYTES - 1), z(SYM_BYTES), z(SYM_BYTES)))).toBe(`kpkeEnc: publicKey: expected ${PK_BYTES} bytes, got ${PK_BYTES - 1}`);
    expect(msgOf(() => kpkeEnc(z(PK_BYTES), z(33), z(SYM_BYTES)))).toBe('kpkeEnc: message: expected 32 bytes, got 33');
    expect(msgOf(() => kpkeEnc(z(PK_BYTES), z(SYM_BYTES), z(0)))).toBe('kpkeEnc: coins: expected 32 bytes, got 0');
    expect(msgOf(() => kpkeDec(z(SK_BYTES + 1), z(CT_BYTES)))).toBe(`kpkeDec: secretKey: expected ${SK_BYTES} bytes, got ${SK_BYTES + 1}`);
    expect(msgOf(() => kpkeDec(z(SK_BYTES), z(CT_BYTES - 1)))).toBe(`kpkeDec: ciphertext: expected ${CT_BYTES} bytes, got ${CT_BYTES - 1}`);
    expect(msgOf(() => ringAdd(z(TVEC_BYTES), z(1)))).toBe(`ringAdd: b: expected ${TVEC_BYTES} bytes, got 1`);
    expect(msgOf(() => ringSub(z(2), z(TVEC_BYTES)))).toBe(`ringSub: a: expected ${TVEC_BYTES} bytes, got 2`);
  });

  it('not bytes -> "<op>: <argument>: expected a Uint8Array"', () => {
    expect(msgOf(() => kpkeKeygen('a'.repeat(32) as never))).toBe('kpkeKeygen: seed: expected a Uint8Array');
    expect(msgOf(() => ringAdd(null as never, z(TVEC_BYTES)))).toBe('ringAdd: a: expected a Uint8Array');
    expect(msgOf(() => hashToRing([1, 2, 3] as never))).toBe('hashToRing: expected a Uint8Array');
  });

  it('hashToRing input: exactly the cap is accepted, one byte more -> "input exceeds N bytes"', () => {
    expect(hashToRing(z(HASHIN_CAP))).toHaveLength(TVEC_BYTES);
    expect(msgOf(() => hashToRing(z(HASHIN_CAP + 1)))).toBe(`hashToRing: input exceeds ${HASHIN_CAP} bytes (${HASHIN_CAP + 1})`);
  });

  it('a refused call leaves no residue: the next valid call returns exactly what it returned before', () => {
    const seed = new Uint8Array(32).fill(5);
    const a = kpkeKeygen(seed);
    expect(msgOf(() => kpkeEnc(z(5), z(SYM_BYTES), z(SYM_BYTES)))).toContain('kpkeEnc: publicKey');
    const b = kpkeKeygen(seed);
    expect(Buffer.from(b.publicKey).equals(Buffer.from(a.publicKey))).toBe(true);
    expect(Buffer.from(b.secretKey).equals(Buffer.from(a.secretKey))).toBe(true);
  });
});

describe('lattice-core fail-closed table: the wasm module is missing or corrupt', () => {
  afterEach(() => {
    vi.doUnmock('node:fs');
    vi.resetModules();
  });

  it('wasm file missing -> importing the binding rejects with the read error', async () => {
    vi.resetModules();
    vi.doMock('node:fs', async (orig) => ({
      ...(await orig<typeof import('node:fs')>()),
      readFileSync: () => {
        throw Object.assign(new Error('ENOENT: no such file or directory'), { code: 'ENOENT' });
      },
    }));
    await expect(import('./index')).rejects.toThrow(/ENOENT/);
  });

  it('wasm file corrupt -> importing the binding rejects with a compile error', async () => {
    vi.resetModules();
    vi.doMock('node:fs', async (orig) => ({
      ...(await orig<typeof import('node:fs')>()),
      readFileSync: () => new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
    }));
    await expect(import('./index')).rejects.toThrow(/WebAssembly|CompileError|magic/i);
  });
});
