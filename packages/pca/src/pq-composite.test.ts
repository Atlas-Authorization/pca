import { sha512 } from '@noble/hashes/sha512';
import { describe, expect, it } from 'vitest';
import { b64u, unb64u, utf8 } from './hash';
import { publicKeyOf, sign } from './keys';
import {
  COMPOSITE_LABEL,
  COMPOSITE_PREFIX,
  COMPOSITE_SIGNATURE_BYTES,
  ED25519_SIGNATURE_BYTES,
  ML_DSA_65_SIGNATURE_BYTES,
  type SuitePublicKeys,
  type SuiteSecretKeys,
  compositeRepresentative,
  compositeSign,
  compositeVerify,
  mlDsa65Keygen,
  mlDsa65Sign,
  resolveSigAlg,
  signWithSuite,
  verifyWithSuite,
} from './pq';

// ---- helpers ----------------------------------------------------------------------------------

const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

const cat = (...arrays: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
};

/** Return a copy of `b` with the byte at `i` flipped. */
const flipByte = (b: Uint8Array, i: number): Uint8Array => {
  const out = b.slice();
  out[i] = (out[i] ?? 0) ^ 0x01;
  return out;
};

/** Fixed Ed25519 key (deterministic: RFC-8032 signing is deterministic). */
const ED_SECRET = new Uint8Array(32).fill(3);
const ED_PUB = publicKeyOf(ED_SECRET);
/** Fixed ML-DSA-65 key pair (deterministic keygen + signing). */
const MLDSA = mlDsa65Keygen(new Uint8Array(32).fill(9));

const MESSAGE = utf8('proof-carrying action — composite interop test');

// ================================================================================================
// (A) COMPOSITE-ML-DSA WIRE FORMAT (draft-ietf-lamps-pq-composite-sigs)
// ================================================================================================

describe('(A) composite constants + representative M′', () => {
  it('exposes the exact registered Prefix and Label strings', () => {
    expect(COMPOSITE_PREFIX).toBe('CompositeAlgorithmSignatures2025');
    expect(COMPOSITE_LABEL).toBe('COMPSIG-MLDSA65-Ed25519-SHA512');
    // Prefix hex per the draft (436F6D...3235).
    expect(toHex(utf8(COMPOSITE_PREFIX))).toBe('436f6d706f73697465416c676f726974686d5369676e61747572657332303235');
    expect(utf8(COMPOSITE_PREFIX).length).toBe(32);
    expect(COMPOSITE_SIGNATURE_BYTES).toBe(ML_DSA_65_SIGNATURE_BYTES + ED25519_SIGNATURE_BYTES);
    expect(COMPOSITE_SIGNATURE_BYTES).toBe(3373);
  });

  it('M′ = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ SHA-512(M) — exact bytes, empty ctx', () => {
    const rep = compositeRepresentative(MESSAGE);
    const expected = cat(utf8(COMPOSITE_PREFIX), utf8(COMPOSITE_LABEL), Uint8Array.of(0), new Uint8Array(0), sha512(MESSAGE));
    expect(rep).toEqual(expected);
    // Structure spot-checks: the representative LEADS with the exact Prefix then Label bytes.
    const prefixBytes = utf8(COMPOSITE_PREFIX);
    const labelBytes = utf8(COMPOSITE_LABEL);
    expect(rep.subarray(0, prefixBytes.length)).toEqual(prefixBytes);
    expect(rep.subarray(prefixBytes.length, prefixBytes.length + labelBytes.length)).toEqual(labelBytes);
    // The len(ctx) byte is 0 and the pre-hash is SHA-512 (64 bytes) at the tail.
    expect(rep[prefixBytes.length + labelBytes.length]).toBe(0);
    expect(rep.subarray(rep.length - 64)).toEqual(sha512(MESSAGE));
  });

  it('M′ encodes len(ctx) as one byte and embeds the ctx bytes', () => {
    const ctx = utf8('tenant-42');
    const rep = compositeRepresentative(MESSAGE, ctx);
    const head = utf8(COMPOSITE_PREFIX).length + utf8(COMPOSITE_LABEL).length;
    expect(rep[head]).toBe(ctx.length); // len(ctx)
    expect(rep.subarray(head + 1, head + 1 + ctx.length)).toEqual(ctx); // ctx
    // A string ctx equals its UTF-8 encoding.
    expect(compositeRepresentative(MESSAGE, 'tenant-42')).toEqual(rep);
  });

  it('rejects a ctx longer than 255 bytes (len must fit one byte)', () => {
    expect(() => compositeRepresentative(MESSAGE, new Uint8Array(256))).toThrow(RangeError);
  });
});

describe('(A) compositeSign / compositeVerify', () => {
  it('round-trips (BOTH component verifications over M′ pass)', () => {
    const sig = compositeSign({ ed25519Secret: ED_SECRET, mlDsa: MLDSA, message: MESSAGE });
    expect(sig.length).toBe(COMPOSITE_SIGNATURE_BYTES);
    expect(compositeVerify({ ed25519Pub: ED_PUB, mlDsaPub: MLDSA.publicKey, message: MESSAGE, signature: sig })).toBe(true);
  });

  it('is mldsaSig ‖ tradSig, split at the ML-DSA offset', () => {
    const sig = compositeSign({ ed25519Secret: ED_SECRET, mlDsa: MLDSA, message: MESSAGE });
    const mPrime = compositeRepresentative(MESSAGE);
    // The two halves are exactly the independent component signatures over M′.
    expect(sig.subarray(0, ML_DSA_65_SIGNATURE_BYTES)).toEqual(mlDsa65Sign(MLDSA.secretKey, mPrime));
    expect(sig.subarray(ML_DSA_65_SIGNATURE_BYTES)).toEqual(sign(ED_SECRET, mPrime));
  });

  it('tampering the ML-DSA half ⇒ fail', () => {
    const sig = compositeSign({ ed25519Secret: ED_SECRET, mlDsa: MLDSA, message: MESSAGE });
    const bad = flipByte(sig, 0); // flip a byte inside the ML-DSA region
    expect(compositeVerify({ ed25519Pub: ED_PUB, mlDsaPub: MLDSA.publicKey, message: MESSAGE, signature: bad })).toBe(false);
  });

  it('tampering the Ed25519 half ⇒ fail', () => {
    const sig = compositeSign({ ed25519Secret: ED_SECRET, mlDsa: MLDSA, message: MESSAGE });
    const bad = flipByte(sig, sig.length - 1); // flip a byte inside the trailing Ed25519 region
    expect(compositeVerify({ ed25519Pub: ED_PUB, mlDsaPub: MLDSA.publicKey, message: MESSAGE, signature: bad })).toBe(false);
  });

  it('wrong total length / wrong message / wrong key ⇒ fail (fail-closed, never throws)', () => {
    const sig = compositeSign({ ed25519Secret: ED_SECRET, mlDsa: MLDSA, message: MESSAGE });
    expect(compositeVerify({ ed25519Pub: ED_PUB, mlDsaPub: MLDSA.publicKey, message: MESSAGE, signature: sig.slice(0, -1) })).toBe(false);
    expect(compositeVerify({ ed25519Pub: ED_PUB, mlDsaPub: MLDSA.publicKey, message: utf8('other'), signature: sig })).toBe(false);
    const other = mlDsa65Keygen(new Uint8Array(32).fill(1));
    expect(compositeVerify({ ed25519Pub: ED_PUB, mlDsaPub: other.publicKey, message: MESSAGE, signature: sig })).toBe(false);
    expect(compositeVerify({ ed25519Pub: publicKeyOf(new Uint8Array(32).fill(4)), mlDsaPub: MLDSA.publicKey, message: MESSAGE, signature: sig })).toBe(false);
  });

  it('ctx binding: a different ctx ⇒ different signature ⇒ cross-verify fails', () => {
    const sigA = compositeSign({ ed25519Secret: ED_SECRET, mlDsa: MLDSA, message: MESSAGE, ctx: 'ctx-A' });
    const sigB = compositeSign({ ed25519Secret: ED_SECRET, mlDsa: MLDSA, message: MESSAGE, ctx: 'ctx-B' });
    expect(toHex(sigA)).not.toBe(toHex(sigB));
    // Each verifies only under its own ctx.
    expect(compositeVerify({ ed25519Pub: ED_PUB, mlDsaPub: MLDSA.publicKey, message: MESSAGE, signature: sigA, ctx: 'ctx-A' })).toBe(true);
    expect(compositeVerify({ ed25519Pub: ED_PUB, mlDsaPub: MLDSA.publicKey, message: MESSAGE, signature: sigA, ctx: 'ctx-B' })).toBe(false);
    // Signed with a ctx, verified with none ⇒ fail.
    expect(compositeVerify({ ed25519Pub: ED_PUB, mlDsaPub: MLDSA.publicKey, message: MESSAGE, signature: sigA })).toBe(false);
    // A ctx over 255 bytes at verify ⇒ false, not a throw.
    expect(compositeVerify({ ed25519Pub: ED_PUB, mlDsaPub: MLDSA.publicKey, message: MESSAGE, signature: sigA, ctx: new Uint8Array(256) })).toBe(false);
  });

  it('compositeSign throws on an oversized ctx', () => {
    expect(() => compositeSign({ ed25519Secret: ED_SECRET, mlDsa: MLDSA, message: MESSAGE, ctx: new Uint8Array(256) })).toThrow(RangeError);
  });
});

// ================================================================================================
// (B) SUF-CMA NESTED HYBRID — hybrid-nested-ed25519-ml-dsa-65 through signWithSuite/verifyWithSuite
// ================================================================================================

const NESTED = 'hybrid-nested-ed25519-ml-dsa-65';
const PLAIN = 'hybrid-ed25519-ml-dsa-65';
const secretKeys: SuiteSecretKeys = { edSecret: ED_SECRET, mlDsa: MLDSA };
const pubKeys: SuitePublicKeys = { edPub: b64u(ED_PUB), mlDsaPub: b64u(MLDSA.publicKey) };

describe('(B) nested SUF-CMA suite registry', () => {
  it('is a known suite with the same wire shape as the plain hybrid', () => {
    const nested = resolveSigAlg(NESTED);
    const plain = resolveSigAlg(PLAIN);
    expect(nested).not.toBeNull();
    // Identical wire-field shape (sig/pq_pk/pq_sig lengths + flags) — only the signed input differs.
    expect({ ...nested, alg: PLAIN }).toEqual(plain);
  });
});

describe('(B) nested suite round-trips through signWithSuite/verifyWithSuite', () => {
  it('signs and verifies', () => {
    const parts = signWithSuite(NESTED, secretKeys, MESSAGE);
    expect(typeof parts.sig).toBe('string');
    expect(typeof parts.pq_sig).toBe('string');
    expect(verifyWithSuite(NESTED, pubKeys, MESSAGE, parts)).toBe(true);
  });

  it('the PQ half signs `message ‖ sig_ed25519` (the nesting), not `message`', () => {
    const parts = signWithSuite(NESTED, secretKeys, MESSAGE);
    // Classical half is byte-identical to a bare Ed25519 signature over the message.
    expect(parts.sig).toBe(b64u(sign(ED_SECRET, MESSAGE)));
    // PQ half equals ML-DSA over message‖sig_ed25519, and is DISTINCT from ML-DSA over message alone.
    const edSigBytes = unb64u(parts.sig);
    expect(parts.pq_sig).toBe(b64u(mlDsa65Sign(MLDSA.secretKey, cat(MESSAGE, edSigBytes))));
    expect(parts.pq_sig).not.toBe(b64u(mlDsa65Sign(MLDSA.secretKey, MESSAGE)));
  });

  it('requires BOTH components (drop pq_sig, wrong edPub, wrong mlDsaPub ⇒ fail)', () => {
    const parts = signWithSuite(NESTED, secretKeys, MESSAGE);
    expect(verifyWithSuite(NESTED, pubKeys, MESSAGE, { sig: parts.sig })).toBe(false); // no pq_sig
    expect(verifyWithSuite(NESTED, pubKeys, MESSAGE, { pq_sig: parts.pq_sig })).toBe(false); // no sig
    expect(verifyWithSuite(NESTED, { edPub: b64u(publicKeyOf(new Uint8Array(32).fill(5))), mlDsaPub: pubKeys.mlDsaPub }, MESSAGE, parts)).toBe(false);
    const other = mlDsa65Keygen(new Uint8Array(32).fill(2));
    expect(verifyWithSuite(NESTED, { edPub: pubKeys.edPub, mlDsaPub: b64u(other.publicKey) }, MESSAGE, parts)).toBe(false);
  });

  it('a swapped/mauled classical half fails — demonstrating the nesting binds the two', () => {
    const nested = signWithSuite(NESTED, secretKeys, MESSAGE);
    const plain = signWithSuite(PLAIN, secretKeys, MESSAGE);
    // Classical `sig` is identical in both constructions (same key, same message)...
    expect(plain.sig).toBe(nested.sig);
    // ...but the plain hybrid's pq_sig signs `message`, so under the NESTED verifier it fails
    // (the nested verifier expects the PQ half over `message ‖ sig`). This is the whole point of nesting.
    expect(verifyWithSuite(NESTED, pubKeys, MESSAGE, plain)).toBe(false);
    // Symmetrically, the nested parts fail under the PLAIN verifier.
    expect(verifyWithSuite(PLAIN, pubKeys, MESSAGE, nested)).toBe(false);
    // Mauling the classical half to a well-formed-but-foreign Ed25519 sig also fails.
    const foreignSig = b64u(sign(new Uint8Array(32).fill(7), MESSAGE));
    expect(verifyWithSuite(NESTED, pubKeys, MESSAGE, { sig: foreignSig, pq_sig: nested.pq_sig })).toBe(false);
  });
});

// ================================================================================================
// NON-REGRESSION — the existing hybrid-ed25519-ml-dsa-65 suite is byte-identical / unaffected
// ================================================================================================

describe('non-regression: existing hybrid-ed25519-ml-dsa-65 is unaffected', () => {
  it('its sig/pq_sig are exactly the independent signatures over the plain message', () => {
    const parts = signWithSuite(PLAIN, secretKeys, MESSAGE);
    expect(parts.sig).toBe(b64u(sign(ED_SECRET, MESSAGE)));
    expect(parts.pq_sig).toBe(b64u(mlDsa65Sign(MLDSA.secretKey, MESSAGE)));
    expect(verifyWithSuite(PLAIN, pubKeys, MESSAGE, parts)).toBe(true);
    // And it is DISTINCT from the nested suite (adding the nested alg changed nothing here).
    const nested = signWithSuite(NESTED, secretKeys, MESSAGE);
    expect(nested.sig).toBe(parts.sig);
    expect(nested.pq_sig).not.toBe(parts.pq_sig);
  });
});
