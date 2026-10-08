/**
 * KAT / parity tests for the FN-DSA (Falcon, FIPS 206) signature core, exercised through the
 * WebAssembly binding. These mirror the native Rust KATs in `crate/src/lib.rs` but additionally
 * prove the TypeScript <-> wasm linear-memory marshalling is correct. Determinism (SHAKE256-seeded
 * keygen/signing) lets every vector be reproduced exactly.
 */

import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  type FnDsaVariant,
  MSG_CAP,
  SEED_BYTES,
  keygen,
  sign,
  sizes,
  verify,
} from './index';

/** Deterministic byte generator: SHA-256 counter-mode expansion of a label (test-only). */
function gen(label: string, n: number): Uint8Array {
  const out = new Uint8Array(n);
  let produced = 0;
  let ctr = 0;
  while (produced < n) {
    const block = createHash('sha256').update(`${label}:${ctr}`).digest();
    for (let i = 0; i < block.length && produced < n; i++) out[produced++] = block[i]!;
    ctr++;
  }
  return out;
}

const VARIANTS: FnDsaVariant[] = ['fn-dsa-512', 'fn-dsa-1024'];

describe('FN-DSA (FIPS 206) signature core (wasm)', () => {
  it('exposes the standardized byte sizes for both parameter sets', () => {
    expect(SEED_BYTES).toBe(32);
    expect(MSG_CAP).toBeGreaterThanOrEqual(1024);
    expect(sizes('fn-dsa-512')).toEqual({ verifyingKey: 897, signingKey: 1345, signature: 666 });
    expect(sizes('fn-dsa-1024')).toEqual({ verifyingKey: 1793, signingKey: 2369, signature: 1280 });
  });

  for (const variant of VARIANTS) {
    describe(variant, () => {
      // KAT: keygen -> sign -> verify round-trips a genuine signature for several messages.
      it('keygen / sign / verify round-trips a genuine signature', () => {
        for (let t = 0; t < 4; t++) {
          const { verifyingKey, signingKey } = keygen(variant, gen(`${variant}:kg:${t}`, SEED_BYTES));
          const msg = gen(`${variant}:msg:${t}`, 48 + t);
          const sig = sign(variant, signingKey, msg, gen(`${variant}:sig:${t}`, SEED_BYTES));
          expect(sig.length).toBe(sizes(variant).signature);
          expect(verify(variant, verifyingKey, msg, sig)).toBe(true);
        }
      });

      // Tamper the signature -> must NOT verify.
      it('a tampered signature does not verify', () => {
        const { verifyingKey, signingKey } = keygen(variant, gen(`${variant}:tsk`, SEED_BYTES));
        const msg = gen(`${variant}:tmsg`, 64);
        const sig = sign(variant, signingKey, msg, gen(`${variant}:tsig`, SEED_BYTES));
        const bad = Uint8Array.from(sig);
        const i = Math.floor(bad.length / 2);
        bad[i] = (bad[i] ?? 0) ^ 0x01;
        expect(verify(variant, verifyingKey, msg, bad)).toBe(false);
      });

      // Tamper the message -> must NOT verify.
      it('a modified message does not verify under the original signature', () => {
        const { verifyingKey, signingKey } = keygen(variant, gen(`${variant}:msk`, SEED_BYTES));
        const msg = gen(`${variant}:mmsg`, 50);
        const sig = sign(variant, signingKey, msg, gen(`${variant}:msig`, SEED_BYTES));
        const bad = Uint8Array.from(msg);
        bad[0] = (bad[0] ?? 0) ^ 0x01;
        expect(verify(variant, verifyingKey, bad, sig)).toBe(false);
      });

      // A foreign key must NOT verify the signature.
      it('a foreign verifying key does not verify the signature', () => {
        const a = keygen(variant, gen(`${variant}:fa`, SEED_BYTES));
        const b = keygen(variant, gen(`${variant}:fb`, SEED_BYTES));
        const msg = gen(`${variant}:fmsg`, 40);
        const sig = sign(variant, a.signingKey, msg, gen(`${variant}:fsig`, SEED_BYTES));
        expect(verify(variant, a.verifyingKey, msg, sig)).toBe(true);
        expect(verify(variant, b.verifyingKey, msg, sig)).toBe(false);
      });

      // Determinism: identical seeds -> identical key pair and identical signature bytes.
      it('keygen and signing are deterministic in their seeds', () => {
        const seed = gen(`${variant}:det`, SEED_BYTES);
        const k1 = keygen(variant, seed);
        const k2 = keygen(variant, seed);
        expect(Buffer.from(k1.verifyingKey).equals(Buffer.from(k2.verifyingKey))).toBe(true);
        expect(Buffer.from(k1.signingKey).equals(Buffer.from(k2.signingKey))).toBe(true);
        const msg = gen(`${variant}:detmsg`, 32);
        const sigSeed = gen(`${variant}:detsig`, SEED_BYTES);
        const s1 = sign(variant, k1.signingKey, msg, sigSeed);
        const s2 = sign(variant, k1.signingKey, msg, sigSeed);
        expect(Buffer.from(s1).equals(Buffer.from(s2))).toBe(true);
      });

      // Wrongly-sized inputs are rejected (binding-level guards).
      it('rejects wrongly-sized buffers', () => {
        const { verifyingKey, signingKey } = keygen(variant, gen(`${variant}:wsk`, SEED_BYTES));
        const msg = gen(`${variant}:wmsg`, 16);
        const sig = sign(variant, signingKey, msg, gen(`${variant}:wsig`, SEED_BYTES));
        expect(() => verify(variant, verifyingKey.slice(0, -1), msg, sig)).toThrow();
        expect(() => verify(variant, verifyingKey, msg, sig.slice(0, -1))).toThrow();
        expect(() => keygen(variant, new Uint8Array(SEED_BYTES - 1))).toThrow();
      });
    });
  }

  // A signature from one variant must not be accepted under the other (parameter-set separation).
  it('signatures do not cross parameter sets', () => {
    const k512 = keygen('fn-dsa-512', gen('x512', SEED_BYTES));
    const msg = gen('xmsg', 32);
    const sig512 = sign('fn-dsa-512', k512.signingKey, msg, gen('xsig', SEED_BYTES));
    // A 666-byte FN-DSA-512 signature is the wrong size for FN-DSA-1024 (1280) -> thrown.
    const k1024 = keygen('fn-dsa-1024', gen('y1024', SEED_BYTES));
    expect(() => verify('fn-dsa-1024', k1024.verifyingKey, msg, sig512)).toThrow();
  });
});
