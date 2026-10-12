/**
 * Standards-based validation of the constant-time WASM curve core.
 *
 * The core exposes group operations (not signatures), so Ed25519 test vectors are exercised through a
 * small verifier assembled from the core's own operations (`mulBase`, `mul`, `add`, `equal`, decode
 * validation) plus SHA-512 from `node:crypto`:
 *   - RFC 8032 section 7.1: public keys are re-derived with the WASM fixed-base multiplication, and the
 *     published signatures verify through the WASM group operations;
 *   - Project Wycheproof `ed25519_test.json`: 151 verification cases (valid, malleable, non-canonical
 *     and malformed encodings, small-order components), run through the same verifier and compared with
 *     `@noble/curves` in strict (non-ZIP-215) mode;
 *   - small-order points, non-canonical encodings and the "negative zero" encoding are checked for
 *     agreement with strict `@noble/curves` decoding.
 * Fixtures and provenance are in `test-vectors/`.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ED25519_TORSION_SUBGROUP, ed25519 } from '@noble/curves/ed25519';
import {
  add,
  decodePoint,
  equal,
  isIdentity,
  isInSubgroup,
  isOnCurve,
  L,
  mul,
  mulBase,
  neg,
  PointValidationError,
  Q,
  type PointBytes,
} from './index';

const ROOT = join(__dirname, '../crate/test-vectors');
const Ext = ed25519.ExtendedPoint;

const hex = (a: Uint8Array): string => Array.from(a, (b) => b.toString(16).padStart(2, '0')).join('');
const unhex = (h: string): Uint8Array => {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const sha512 = (...parts: Uint8Array[]): Uint8Array => {
  const h = createHash('sha512');
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};
const leToBig = (b: Uint8Array): bigint => {
  let v = 0n;
  for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i] ?? 0);
  return v;
};

/** RFC 8032 section 5.1.5: expand a 32-byte seed into the clamped secret scalar. */
function clampedScalar(seed: Uint8Array): bigint {
  const h = sha512(seed).slice(0, 32);
  h[0] = (h[0] as number) & 248;
  h[31] = (h[31] as number) & 127;
  h[31] = (h[31] as number) | 64;
  return leToBig(h);
}

type Verdict = { ok: true } | { ok: false; reason: string };

/**
 * Ed25519 verification (RFC 8032 section 5.1.7, cofactorless equation `[S]B = R + [k]A`) built ONLY from
 * the WASM core's operations. Strictness comes from the core: it must reject undecodable points.
 */
function verifyWithCore(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): Verdict {
  if (pk.length !== 32) return { ok: false, reason: 'bad-pk-length' };
  if (sig.length !== 64) return { ok: false, reason: 'bad-sig-length' };
  const rBytes = sig.slice(0, 32);
  const s = leToBig(sig.slice(32));
  if (s >= L) return { ok: false, reason: 'S-not-canonical' };
  let A: PointBytes;
  let R: PointBytes;
  try {
    A = decodePoint(pk);
  } catch (e) {
    if (e instanceof PointValidationError) return { ok: false, reason: 'A-undecodable' };
    throw e;
  }
  try {
    R = decodePoint(rBytes);
  } catch (e) {
    if (e instanceof PointValidationError) return { ok: false, reason: 'R-undecodable' };
    throw e;
  }
  const k = leToBig(sha512(rBytes, pk, msg)) % L;
  const lhs = mulBase(s);
  const rhs = add(R, mul(k, A));
  return equal(lhs, rhs) ? { ok: true } : { ok: false, reason: 'equation-mismatch' };
}

describe('fixture integrity', () => {
  it('RFC 8032 and Wycheproof fixtures match their recorded hashes', () => {
    const wy = JSON.parse(readFileSync(join(ROOT, 'PROVENANCE.json'), 'utf8')) as { fileSha256: string };
    const bytes = readFileSync(join(ROOT, 'wycheproof-ed25519_test.json'));
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(wy.fileSha256);
    const rfc = JSON.parse(readFileSync(join(ROOT, 'rfc8032-ed25519.json'), 'utf8')) as {
      provenance: { url: string; sourceSha256: string };
      vectors: unknown[];
    };
    expect(rfc.provenance.url).toBe('https://www.rfc-editor.org/rfc/rfc8032.txt');
    expect(rfc.vectors.length).toBe(5);
  });
});

describe('RFC 8032 section 7.1 (Ed25519)', () => {
  const rfc = JSON.parse(readFileSync(join(ROOT, 'rfc8032-ed25519.json'), 'utf8')) as {
    vectors: { name: string; secretKey: string; publicKey: string; message: string; signature: string }[];
  };
  for (const v of rfc.vectors) {
    it(`TEST ${v.name}: WASM fixed-base multiplication derives the published public key`, () => {
      const a = clampedScalar(unhex(v.secretKey));
      // a is up to 2^255, i.e. larger than L: the core reduces mod L, which is exact because B has order L.
      expect(hex(mulBase(a))).toBe(v.publicKey);
    });
    it(`TEST ${v.name}: the published signature verifies through the WASM group operations`, () => {
      expect(verifyWithCore(unhex(v.publicKey), unhex(v.message), unhex(v.signature))).toEqual({ ok: true });
    });
    it(`TEST ${v.name}: tampering with the message, R, S or the key is rejected with the right reason`, () => {
      const pk = unhex(v.publicKey);
      const msg = unhex(v.message);
      const sig = unhex(v.signature);
      expect(verifyWithCore(pk, new Uint8Array([...msg, 0]), sig)).toEqual({ ok: false, reason: 'equation-mismatch' });
      const badS = Uint8Array.from(sig);
      badS[40] = (badS[40] as number) ^ 1;
      expect(verifyWithCore(pk, msg, badS)).toEqual({ ok: false, reason: 'equation-mismatch' });
      // S + L is the classic malleated twin: same equation, non-canonical scalar
      const sPlusL = leToBig(sig.slice(32)) + L;
      const twin = new Uint8Array(64);
      twin.set(sig.slice(0, 32));
      for (let i = 0; i < 32; i++) twin[32 + i] = Number((sPlusL >> BigInt(8 * i)) & 0xffn);
      expect(verifyWithCore(pk, msg, twin)).toEqual({ ok: false, reason: 'S-not-canonical' });
    });
    it(`TEST ${v.name}: strict @noble agrees on the published vector`, () => {
      expect(ed25519.verify(unhex(v.signature), unhex(v.message), unhex(v.publicKey), { zip215: false })).toBe(true);
    });
  }
});

describe('Wycheproof ed25519_test.json (151 cases)', () => {
  interface Test { tcId: number; comment: string; flags: string[]; msg: string; sig: string; result: 'valid' | 'invalid' | 'acceptable' }
  interface Group { publicKey: { pk: string }; tests: Test[] }
  const wy = JSON.parse(readFileSync(join(ROOT, 'wycheproof-ed25519_test.json'), 'utf8')) as {
    numberOfTests: number;
    testGroups: Group[];
  };
  const all = wy.testGroups.flatMap((g) => g.tests.map((t) => ({ pk: g.publicKey.pk, t })));

  it('contains the full 151-case suite', () => {
    expect(all.length).toBe(151);
    expect(wy.numberOfTests).toBe(151);
  });

  it('strict @noble matches every Wycheproof expectation (sanity check of the reference)', () => {
    for (const { pk, t } of all) {
      let nobleOk = false;
      try {
        nobleOk = ed25519.verify(unhex(t.sig), unhex(t.msg), unhex(pk), { zip215: false });
      } catch {
        nobleOk = false;
      }
      expect(nobleOk, `tcId ${t.tcId} ${t.comment}`).toBe(t.result === 'valid');
    }
  });

  it('the WASM-core verifier matches every Wycheproof expectation (valid accepted, invalid rejected)', () => {
    const failures: string[] = [];
    for (const { pk, t } of all) {
      const v = verifyWithCore(unhex(pk), unhex(t.msg), unhex(t.sig));
      const expected = t.result === 'valid';
      if (v.ok !== expected) failures.push(`tcId ${t.tcId} [${t.flags.join(',')}] expected ${t.result}, core ${v.ok ? 'accepted' : 'rejected: ' + v.reason} - ${t.comment}`);
    }
    expect(failures).toEqual([]);
  });

  it('rejection reasons are specific for the malleability and encoding classes', () => {
    const reasons = new Map<string, Set<string>>();
    for (const { pk, t } of all) {
      if (t.result !== 'invalid') continue;
      const v = verifyWithCore(unhex(pk), unhex(t.msg), unhex(t.sig));
      if (v.ok) continue;
      for (const f of t.flags) reasons.set(f, (reasons.get(f) ?? new Set()).add(v.reason));
    }
    expect([...(reasons.get('SignatureMalleability') ?? [])].sort()).toEqual(['S-not-canonical']);
    expect([...(reasons.get('TruncatedSignature') ?? [])]).toEqual(['bad-sig-length']);
  });
});

describe('small-order points, non-canonical and "negative zero" encodings: WASM core vs strict @noble', () => {
  const P = Q;
  const le = (v: bigint, signBit: boolean): Uint8Array => {
    const out = new Uint8Array(32);
    let x = v;
    for (let i = 0; i < 32; i++) {
      out[i] = Number(x & 0xffn);
      x >>= 8n;
    }
    if (signBit) out[31] = (out[31] as number) | 0x80;
    return out;
  };
  const nobleDecodes = (b: Uint8Array): boolean => {
    try {
      Ext.fromHex(b); // strict (zip215 = false): canonical y and no negative zero
      return true;
    } catch {
      return false;
    }
  };

  // y values worth probing: every small y, the field edge y = p-1, and non-canonical y in [p, 2^255).
  const ys: bigint[] = [];
  for (let y = 0n; y < 40n; y++) ys.push(y);
  for (let y = P - 20n; y < P; y++) ys.push(y);
  for (let y = P; y < P + 19n; y++) ys.push(y); // every non-canonical y representable in 255 bits
  const candidates: { label: string; bytes: Uint8Array }[] = [];
  for (const y of ys) for (const s of [false, true]) candidates.push({ label: `y=${y >= P ? 'p+' + (y - P) : y.toString()} sign=${s ? 1 : 0}`, bytes: le(y, s) });

  it('the core accepts exactly the encodings strict @noble accepts (canonical y, no negative zero)', () => {
    const diffs: string[] = [];
    for (const c of candidates) {
      if (isOnCurve(c.bytes) !== nobleDecodes(c.bytes)) {
        diffs.push(`${c.label} (${hex(c.bytes)}): core=${isOnCurve(c.bytes)} noble=${nobleDecodes(c.bytes)}`);
      }
    }
    expect(diffs).toEqual([]);
  });

  it('every one of the 8 canonical small-order encodings: decodes, is not in the prime subgroup, ops stay closed', () => {
    let seen = 0;
    for (const h of ED25519_TORSION_SUBGROUP) {
      const b = unhex(h);
      if (!nobleDecodes(b)) continue; // non-canonical aliases are covered by the previous test
      seen++;
      expect(isOnCurve(b)).toBe(true);
      expect(isInSubgroup(b)).toBe(false);
      // 8 * T = identity for every torsion point
      expect(isIdentity(mul(8n, b))).toBe(true);
      // T - T = identity
      expect(isIdentity(add(b, neg(b)))).toBe(true);
    }
    expect(seen).toBe(8);
  });

  it('negative zero: y = 1 and y = p-1 with the sign bit set are rejected (RFC 8032 section 5.1.3)', () => {
    expect(isOnCurve(le(1n, true))).toBe(false);
    expect(isOnCurve(le(P - 1n, true))).toBe(false);
    expect(isOnCurve(le(1n, false))).toBe(true); // the identity
    expect(isOnCurve(le(P - 1n, false))).toBe(true); // the order-2 point
  });

  it('non-canonical aliases of the identity and of the order-2 point (y = p+1, p-1+p...) are rejected', () => {
    expect(isOnCurve(le(P + 1n, false))).toBe(false); // alias of y = 1
    expect(isOnCurve(le(P + 1n, true))).toBe(false);
    expect(() => decodePoint(le(P + 1n, false))).toThrow(PointValidationError);
  });

  it('operations refuse non-canonical operands instead of silently re-encoding them', () => {
    const alias = le(P + 1n, false);
    expect(() => add(alias, mulBase(1n))).toThrow(PointValidationError);
    expect(() => mul(3n, alias)).toThrow(PointValidationError);
    expect(equal(alias, mulBase(0n))).toBe(false);
  });
});
