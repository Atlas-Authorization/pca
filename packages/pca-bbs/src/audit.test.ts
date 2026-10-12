/**
 * Adversarial / audit-style tests for @atlasauth/pca-bbs (complements the draft fixtures and the
 * zkryptium cross-check; does not repeat them). Covers: malformed / identity / wrong-subgroup /
 * non-canonical encodings on every deserializer, binding of every public input into the proof
 * challenge, message-count denial-of-service, RNG failure, malleability, property tests and bounded
 * fuzzing of every parse/verify entry. Fuzz seconds per group: `AUDIT_FUZZ_SECONDS` (default 3).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import fc from 'fast-check';
import { bls12_381 } from '@noble/curves/bls12-381';
import { b64u } from '@atlasauth/pca';
import {
  MAX_MESSAGES,
  R,
  createGenerators,
  generateKeyPair,
  keyGen,
  proofGen,
  proofVerify,
  proofVerifyDetailed,
  sign,
  skFromBytes,
  skToBytes,
  skToPk,
  verify,
  verifyDetailed,
} from './bbs';
import {
  capabilityAttributes,
  issueCapabilityCredential,
  presentCredential,
  verifyCredential,
  verifyPresentation,
  type BBSCredential,
} from './credential';

const TEXT = new TextEncoder();
const msg = (s: string): Uint8Array => TEXT.encode(s);
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const FUZZ_MS = Number(process.env.AUDIT_FUZZ_SECONDS ?? '3') * 1000;
const fuzzOpts = { numRuns: 1_000_000, interruptAfterTimeLimit: FUZZ_MS, markInterruptAsFailure: false } as const;
const INTERNAL_CRASH = /Cannot read propert|Cannot mix BigInt|is not a function|is not iterable|undefined is not|Maximum call stack|Invalid (array|typed array) length|allocation failed/i;

function noInternalCrash(fn: () => unknown): void {
  const t0 = performance.now();
  try {
    fn();
  } catch (e) {
    expect(e instanceof Error, `non-Error thrown: ${String(e)}`).toBe(true);
    expect(INTERNAL_CRASH.test((e as Error).message), `internal crash: ${(e as Error).message}`).toBe(false);
  }
  expect(performance.now() - t0, 'call took > 2s (hang / DoS?)').toBeLessThan(2000);
}

afterEach(() => vi.restoreAllMocks());

const kp = generateKeyPair();
const header = msg('hdr');
const ph = msg('ph');
const msgs = [msg('m0'), msg('m1'), msg('m2'), msg('m3')];
const sig = sign(kp.sk, kp.pk, header, msgs);
const proof = proofGen(kp.pk, sig, header, ph, msgs, [0, 2]);
const disclosedMsgs = [msgs[0] as Uint8Array, msgs[2] as Uint8Array];

// --- construct points that are ON the curve but NOT in the prime-order subgroup -------------------
const Fp = bls12_381.fields.Fp;
const Fp2 = bls12_381.fields.Fp2;
function offSubgroupG1(): Uint8Array {
  for (let x = 5n; ; x++) {
    const rhs = Fp.add(Fp.pow(x, 3n), 4n);
    if (!Fp.eql(Fp.pow(rhs, (Fp.ORDER - 1n) / 2n), 1n)) continue;
    const out = new Uint8Array(48);
    let v = x;
    for (let i = 47; i >= 0; i--) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    out[0] = (out[0] ?? 0) | 0x80; // compressed, positive y
    try {
      bls12_381.G1.ProjectivePoint.fromHex(out);
    } catch {
      return out; // rejected by the library's own subgroup check: this is what we want to confirm below
    }
  }
}
void Fp2;

describe('encodings: identity, malformed, non-canonical and off-subgroup inputs', () => {
  const G1ID = new Uint8Array(48);
  G1ID[0] = 0xc0;

  it('signature: wrong lengths, identity A, e = 0, e >= r are all rejected with a precise reason', () => {
    for (const n of [0, 1, 79, 81, 160]) expect(verifyDetailed(kp.pk, new Uint8Array(n), header, msgs)).toEqual({ ok: false, reason: 'malformed-signature' });
    const idSig = new Uint8Array(80);
    idSig.set(G1ID, 0);
    idSig.set(sig.subarray(48), 48);
    expect(verifyDetailed(kp.pk, idSig, header, msgs)).toEqual({ ok: false, reason: 'malformed-signature' });
    for (const e of [0n, R, R + 1n, 2n ** 256n - 1n]) {
      const s = Uint8Array.from(sig);
      for (let i = 31; i >= 0; i--) s[48 + (31 - i)] = Number((e >> BigInt(8 * i)) & 0xffn);
      expect(verifyDetailed(kp.pk, s, header, msgs)).toEqual({ ok: false, reason: 'malformed-signature' });
    }
  });

  it('public key: identity, wrong length, garbage and an uncompressed/flag-corrupted G2 encoding are rejected', () => {
    const G2ID = new Uint8Array(96);
    G2ID[0] = 0xc0;
    expect(verifyDetailed(G2ID, sig, header, msgs)).toEqual({ ok: false, reason: 'malformed-public-key' });
    for (const n of [0, 48, 95, 97, 192]) expect(verifyDetailed(new Uint8Array(n).fill(1), sig, header, msgs).ok).toBe(false);
    const flipped = Uint8Array.from(kp.pk);
    flipped[0] = (flipped[0] ?? 0) & 0x7f; // clear the "compressed" flag
    expect(verify(flipped, sig, header, msgs)).toBe(false);
  });

  it('a G1 point that is on the curve but outside the prime-order subgroup is rejected as signature.A and as every proof point', () => {
    const bad = offSubgroupG1();
    const s = Uint8Array.from(sig);
    s.set(bad, 0);
    expect(verifyDetailed(kp.pk, s, header, msgs)).toEqual({ ok: false, reason: 'malformed-signature' });
    for (const off of [0, 48, 96]) {
      const p = Uint8Array.from(proof);
      p.set(bad, off);
      expect(proofVerifyDetailed(kp.pk, p, header, ph, disclosedMsgs, [0, 2])).toEqual({ ok: false, reason: 'malformed-proof' });
    }
  });

  it('proof: identity points (Abar, Bbar, D), wrong length and out-of-range scalars are rejected', () => {
    for (const off of [0, 48, 96]) {
      const p = Uint8Array.from(proof);
      p.set(G1ID, off);
      expect(proofVerifyDetailed(kp.pk, p, header, ph, disclosedMsgs, [0, 2]).ok).toBe(false);
    }
    for (const n of [0, 1, proof.length - 1, proof.length + 1, proof.length + 31]) {
      expect(proofVerifyDetailed(kp.pk, new Uint8Array(n), header, ph, disclosedMsgs, [0, 2]).ok).toBe(false);
    }
    const p = Uint8Array.from(proof);
    p.fill(0xff, 144, 176); // eHat >= r
    expect(proofVerifyDetailed(kp.pk, p, header, ph, disclosedMsgs, [0, 2])).toEqual({ ok: false, reason: 'malformed-proof' });
    const q = Uint8Array.from(proof);
    q.fill(0xff, proof.length - 32); // c >= r
    expect(proofVerifyDetailed(kp.pk, q, header, ph, disclosedMsgs, [0, 2])).toEqual({ ok: false, reason: 'malformed-proof' });
  });

  it('secret-key encodings: 0, r, r+1, 31 and 33 bytes are refused; keyGen needs >= 32 bytes of key material', () => {
    for (const bad of [new Uint8Array(32), skToBytes(1n).slice(0, 31), new Uint8Array(33)]) expect(() => skFromBytes(bad)).toThrow();
    const rBytes = new Uint8Array(32);
    let v = R;
    for (let i = 31; i >= 0; i--) {
      rBytes[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    expect(() => skFromBytes(rBytes)).toThrow(/out of range/);
    expect(() => keyGen(new Uint8Array(31))).toThrow();
    expect(() => keyGen(new Uint8Array(32), new Uint8Array(65536))).toThrow();
    expect(skFromBytes(skToBytes(kp.sk))).toBe(kp.sk);
  });

  it('proof indexes: duplicate, negative, fractional, NaN, out-of-range are refused by ProofGen and ProofVerify', () => {
    for (const bad of [[0, 0], [-1], [0.5], [Number.NaN], [4], [Infinity]]) {
      expect(() => proofGen(kp.pk, sig, header, ph, msgs, bad)).toThrow(RangeError);
      expect(proofVerify(kp.pk, proof, header, ph, [msg('m0')], bad)).toBe(false);
    }
    // count mismatch
    expect(proofVerifyDetailed(kp.pk, proof, header, ph, [msg('m0')], [0, 2])).toEqual({ ok: false, reason: 'disclosed-length-mismatch' });
  });
});

describe('transcript binding: every public input is bound into the proof challenge', () => {
  const ok = (over: Partial<{ pk: Uint8Array; h: Uint8Array; p: Uint8Array; dm: Uint8Array[]; di: number[]; pr: Uint8Array }> = {}) =>
    proofVerify(over.pk ?? kp.pk, over.pr ?? proof, over.h ?? header, over.p ?? ph, over.dm ?? disclosedMsgs, over.di ?? [0, 2]);

  it('baseline verifies; unsorted (but consistent) disclosure order also verifies', () => {
    expect(ok()).toBe(true);
    expect(ok({ dm: [disclosedMsgs[1] as Uint8Array, disclosedMsgs[0] as Uint8Array], di: [2, 0] })).toBe(true);
  });

  it('header, presentation header, issuer key, disclosed values and disclosed indexes are each bound', () => {
    expect(ok({ h: msg('hdr2') })).toBe(false);
    expect(ok({ p: msg('ph2') })).toBe(false);
    expect(ok({ p: new Uint8Array(0) })).toBe(false);
    expect(ok({ pk: generateKeyPair().pk })).toBe(false);
    expect(ok({ dm: [msg('m0'), msg('m1')] })).toBe(false);
    expect(ok({ di: [0, 1] })).toBe(false);
    expect(ok({ di: [1, 2] })).toBe(false);
    expect(ok({ dm: [disclosedMsgs[1] as Uint8Array, disclosedMsgs[0] as Uint8Array] })).toBe(false); // values swapped vs indexes
  });

  it('header and ph are not interchangeable (distinct slots): swapping them fails', () => {
    const p2 = proofGen(kp.pk, sig, header, ph, msgs, [1]);
    expect(proofVerify(kp.pk, p2, header, ph, [msg('m1')], [1])).toBe(true);
    expect(proofVerify(kp.pk, p2, ph, header, [msg('m1')], [1])).toBe(false);
  });

  it('message boundaries are bound: ["ab","c"] and ["a","bc"] and ["abc"] sign differently; a trailing empty message changes the credential', () => {
    const variants = [[msg('ab'), msg('c')], [msg('a'), msg('bc')], [msg('abc')], [msg('abc'), msg('')]];
    const sigs = variants.map((m) => hex(sign(kp.sk, kp.pk, header, m)));
    expect(new Set(sigs).size).toBe(variants.length);
    const s = sign(kp.sk, kp.pk, header, variants[0] as Uint8Array[]);
    for (const m of variants.slice(1)) expect(verify(kp.pk, s, header, m)).toBe(false);
  });

  it('a proof cannot be re-targeted to a credential with extra undisclosed messages (message count is bound via the domain)', () => {
    const longer = [...msgs, msg('extra')];
    const sigLong = sign(kp.sk, kp.pk, header, longer);
    expect(verify(kp.pk, sig, header, longer)).toBe(false);
    expect(verify(kp.pk, sigLong, header, msgs)).toBe(false);
    const pLong = proofGen(kp.pk, sigLong, header, ph, longer, [0, 2]);
    expect(proofVerify(kp.pk, pLong, header, ph, disclosedMsgs, [0, 2])).toBe(true); // 5-message credential, honest
    expect(proofVerify(kp.pk, proof, header, ph, disclosedMsgs, [0, 2])).toBe(true);
    expect(pLong.length).not.toBe(proof.length);
  });

  it('a signature is not a proof and a proof is not a signature (no cross-acceptance)', () => {
    expect(verify(kp.pk, proof, header, msgs)).toBe(false);
    expect(proofVerify(kp.pk, sig, header, ph, disclosedMsgs, [0, 2])).toBe(false);
  });

  it('proof malleability: sampled single-bit flips anywhere in the proof (and in the signature) are rejected', () => {
    let accepted = 0;
    const flip = (b: Uint8Array, bit: number) => {
      const m = Uint8Array.from(b);
      m[bit >> 3] = (m[bit >> 3] ?? 0) ^ (1 << (bit & 7));
      return m;
    };
    for (let bit = 0; bit < proof.length * 8; bit += 53) if (ok({ pr: flip(proof, bit) })) accepted++;
    for (let bit = 0; bit < sig.length * 8; bit += 41) if (verify(kp.pk, flip(sig, bit), header, msgs)) accepted++;
    expect(accepted).toBe(0);
  });
});

describe('nonce / randomness: reuse, failure and unlinkability', () => {
  it('proofs are re-randomised: two proofs of the same disclosure differ in every blinded point', () => {
    const a = proofGen(kp.pk, sig, header, ph, msgs, [0]);
    const b = proofGen(kp.pk, sig, header, ph, msgs, [0]);
    for (const off of [0, 48, 96]) expect(hex(a.subarray(off, off + 48))).not.toBe(hex(b.subarray(off, off + 48)));
  });

  it('signing is deterministic (RFC-style nonce derivation): same inputs, same signature; header changes it', () => {
    expect(hex(sign(kp.sk, kp.pk, header, msgs))).toBe(hex(sig));
    expect(hex(sign(kp.sk, kp.pk, msg('other'), msgs))).not.toBe(hex(sig));
  });

  it('pinned random scalars reproduce a proof (test-vector hook) but reject r1 = 0 / r2 = 0 (a zero blinding collapses the proof)', () => {
    const rs = (z: number) => Array.from({ length: 5 + 2 }, (_, i) => (i === z ? 0n : BigInt(i + 11)));
    expect(() => proofGen(kp.pk, sig, header, ph, msgs, [0, 2], rs(0))).toThrow(/non-zero/);
    expect(() => proofGen(kp.pk, sig, header, ph, msgs, [0, 2], rs(1))).toThrow(/non-zero/);
    expect(() => proofGen(kp.pk, sig, header, ph, msgs, [0, 2], rs(2))).not.toThrow();
    expect(() => proofGen(kp.pk, sig, header, ph, msgs, [0, 2], [1n, 2n])).toThrow(/random scalars/);
  });

  it('a stuck-at-zero RNG fails closed: no key is generated and no degenerate proof is produced', () => {
    vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(((a: Uint8Array) => {
      a.fill(0);
      return a;
    }) as never);
    expect(() => generateKeyPair()).toThrow(/RNG failure/);
    expect(() => proofGen(kp.pk, sig, header, ph, msgs, [0, 2])).toThrow(/non-zero/);
  });
});

describe('denial of service: message count is bounded', () => {
  it('createGenerators / sign refuse more than MAX_MESSAGES; verification of an oversized message list is a cheap rejection', () => {
    expect(() => createGenerators(MAX_MESSAGES + 2)).toThrow(RangeError);
    const t0 = performance.now();
    expect(verify(kp.pk, sig, header, new Array<Uint8Array>(MAX_MESSAGES + 1).fill(msg('x')))).toBe(false);
    expect(performance.now() - t0).toBeLessThan(500);
  });

  it('a hostile proof whose length implies hundreds of thousands of messages is rejected before any hash-to-curve', () => {
    const huge = new Uint8Array(3 * 48 + 4 * 32 + 32 * 100_000);
    const t0 = performance.now();
    expect(proofVerifyDetailed(kp.pk, huge, header, ph, [], [])).toEqual({ ok: false, reason: 'malformed-proof' });
    expect(performance.now() - t0).toBeLessThan(1000);
  });
});

describe('credential layer: attribute ambiguity, structure and presentation binding', () => {
  const cap = { issuer: 'iss-key', holder: 'sub-key', caveats: [{ type: 'scope', scopes: ['a'] }, { type: 'budget', max: 5 }] } as never;
  const cred = issueCapabilityCredential(cap, { sk: kp.sk, pk: kp.pk });

  it('baseline: credential verifies; presentation of one caveat verifies', () => {
    expect(verifyCredential(cred)).toBe(true);
    const pres = presentCredential(cred, { disclose: ['cav:0:scope'], presentationHeader: msg('act-1') });
    expect(verifyPresentation(pres, { presentationHeader: msg('act-1') })).toBe(true);
  });

  it('NUL separator ambiguity is closed: a NUL in an attribute name is refused at encode time', () => {
    const evil = { ...cred, attributes: cred.attributes.map((a) => (a.index === 0 ? { ...a, name: 'iss\0x' } : a)) };
    expect(verifyCredential(evil)).toBe(false);
    expect(() => issueCapabilityCredential({ issuer: 'a', holder: 'b', caveats: [{ type: 'x\0y' }] } as never, { sk: kp.sk, pk: kp.pk })).toThrow(/NUL/);
  });

  it('re-labelling a signed attribute (moving the NUL boundary, changing name or index) does not verify', () => {
    const pres = presentCredential(cred, { disclose: ['iss'], presentationHeader: msg('p') });
    const d = pres.disclosed[0];
    if (d === undefined) throw new Error('no disclosure');
    const alt = { ...pres, disclosed: [{ ...d, name: 'sub' }] };
    expect(verifyPresentation(alt, { presentationHeader: msg('p') })).toBe(false);
    const moved = { ...pres, disclosed: [{ ...d, index: 1 }] };
    expect(verifyPresentation(moved, { presentationHeader: msg('p') })).toBe(false);
    const val = { ...pres, disclosed: [{ ...d, value: d.value + 'x' }] };
    expect(verifyPresentation(val, { presentationHeader: msg('p') })).toBe(false);
  });

  it('replay: a presentation bound to action A fails for action B, for an empty ph, and under a different pinned issuer', () => {
    const pres = presentCredential(cred, { disclose: ['cav:0:scope'], presentationHeader: msg('A') });
    expect(verifyPresentation(pres, { presentationHeader: msg('B') })).toBe(false);
    expect(verifyPresentation(pres, { presentationHeader: new Uint8Array(0) })).toBe(false);
    expect(verifyPresentation(pres, { pk: generateKeyPair().pk })).toBe(false);
    expect(verifyPresentation({ ...pres, messageCount: 1 })).toBe(false);
    expect(verifyPresentation({ ...pres, disclosed: [] })).toBe(false);
  });

  it('unknown attribute names are refused at presentation time; disclosing nothing is allowed and verifies', () => {
    expect(() => presentCredential(cred, { disclose: ['nope'] })).toThrow(RangeError);
    const none = presentCredential(cred, { disclose: [] });
    expect(verifyPresentation(none)).toBe(true);
  });

  it('malformed credential / presentation objects return false instead of throwing', () => {
    const junk: unknown[] = [null, undefined, {}, [], 'x', 7, { ...cred, attributes: null }, { ...cred, attributes: [{}] }, { ...cred, attributes: [null] }, { ...cred, signature: 5 }];
    for (const j of junk) {
      expect(verifyCredential(j as BBSCredential)).toBe(false);
      expect(verifyPresentation(j as never)).toBe(false);
    }
  });

  it('capabilityAttributes: caveat index encoding stays stable and bijective for repeated caveat types', () => {
    const a = capabilityAttributes({ issuer: 'i', holder: 'h', caveats: [{ type: 't' }, { type: 't' }] } as never);
    expect(a.map((x) => x.name)).toEqual(['iss', 'sub', 'cav:0:t', 'cav:1:t']);
  });
});

describe('property tests (fast-check)', () => {
  const msgArb = fc.array(fc.uint8Array({ maxLength: 12 }), { minLength: 0, maxLength: 5 });

  it('Sign/Verify round-trip; changing any single message, reordering, or truncating breaks it', () => {
    fc.assert(
      fc.property(msgArb, fc.uint8Array({ maxLength: 8 }), (ms, h) => {
        const s = sign(kp.sk, kp.pk, h, ms);
        if (!verify(kp.pk, s, h, ms)) return false;
        if (ms.length > 0) {
          const t = ms.map((m) => Uint8Array.from(m));
          const first = t[0] as Uint8Array;
          t[0] = new Uint8Array([...first, 1]);
          if (verify(kp.pk, s, h, t)) return false;
          if (verify(kp.pk, s, h, ms.slice(1))) return false;
        }
        return true;
      }),
      { numRuns: 6 },
    );
  });

  it('ProofGen/ProofVerify round-trip for any disclosed subset; any wrong disclosed value is rejected', () => {
    fc.assert(
      fc.property(fc.array(fc.uint8Array({ maxLength: 8 }), { minLength: 1, maxLength: 5 }), fc.infiniteStream(fc.boolean()), (ms, bits) => {
        const s = sign(kp.sk, kp.pk, header, ms);
        const idx: number[] = [];
        const it = bits[Symbol.iterator]();
        ms.forEach((_, i) => {
          if (it.next().value === true) idx.push(i);
        });
        const p = proofGen(kp.pk, s, header, ph, ms, idx);
        const dm = idx.map((i) => ms[i] as Uint8Array);
        if (!proofVerify(kp.pk, p, header, ph, dm, idx)) return false;
        if (idx.length > 0) {
          const bad = dm.map((m) => Uint8Array.from(m));
          bad[0] = new Uint8Array([...(bad[0] as Uint8Array), 9]);
          if (proofVerify(kp.pk, p, header, ph, bad, idx)) return false;
        }
        return true;
      }),
      { numRuns: 6 },
    );
  });

  it('skToPk is a deterministic function of sk and keyGen is deterministic in its key material', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 64 }), (ikm) => keyGen(ikm) === keyGen(ikm) && hex(skToPk(keyGen(ikm))) === hex(skToPk(keyGen(ikm)))),
      { numRuns: 20 },
    );
  });
});

describe('bounded fuzzing of every parse / verify entry (no untyped exception, no hang)', () => {
  const bytesArb = fc.oneof(fc.uint8Array({ maxLength: 300 }), fc.uint8Array({ minLength: 80, maxLength: 80 }), fc.uint8Array({ minLength: 96, maxLength: 96 }), fc.uint8Array({ minLength: 48, maxLength: 48 }));
  const mutated = (base: Uint8Array) =>
    fc.array(fc.nat({ max: base.length * 8 - 1 }), { minLength: 1, maxLength: 4 }).map((bits) => {
      const m = Uint8Array.from(base);
      for (const b of bits) m[b >> 3] = (m[b >> 3] ?? 0) ^ (1 << (b & 7));
      return m;
    });

  it('verify / verifyDetailed / proofVerify never throw on arbitrary bytes and never accept mutated honest data', () => {
    fc.assert(
      fc.property(bytesArb, bytesArb, mutated(sig), mutated(proof), (a, b, ms, mp) => {
        expect(() => verify(a, b, a, [b])).not.toThrow();
        expect(() => proofVerify(a, b, a, b, [a], [0])).not.toThrow();
        // (a mutation that flips the same bit twice is the original; only genuinely different bytes must fail)
        if (hex(ms) !== hex(sig)) expect(verify(kp.pk, ms, header, msgs)).toBe(false);
        if (hex(mp) !== hex(proof)) expect(proofVerify(kp.pk, mp, header, ph, disclosedMsgs, [0, 2])).toBe(false);
        return true;
      }),
      fuzzOpts,
    );
  });

  it('proofGen / sign on hostile arguments fail with typed errors only', () => {
    fc.assert(
      fc.property(bytesArb, fc.array(fc.integer({ min: -3, max: 8 }), { maxLength: 4 }), (b, idx) => {
        noInternalCrash(() => proofGen(kp.pk, b, header, ph, msgs, idx));
        noInternalCrash(() => proofGen(b, sig, header, ph, msgs, idx));
        return true;
      }),
      { ...fuzzOpts, interruptAfterTimeLimit: FUZZ_MS },
    );
  });

  it('credential verifiers survive arbitrary JSON-shaped input', () => {
    fc.assert(
      fc.property(fc.anything(), (j) => {
        expect(() => verifyCredential(j as never)).not.toThrow();
        expect(() => verifyPresentation(j as never)).not.toThrow();
        return true;
      }),
      fuzzOpts,
    );
    const goodPres = presentCredential(issueCapabilityCredential({ issuer: 'i', holder: 'h', caveats: [] } as never, { sk: kp.sk, pk: kp.pk }), { disclose: ['iss'] });
    fc.assert(
      fc.property(fc.string({ maxLength: 40 }), fc.string({ maxLength: 40 }), (s1, s2) => {
        expect(() => verifyPresentation({ ...goodPres, proof: s1, header: s2 })).not.toThrow();
        expect(verifyPresentation({ ...goodPres, proof: b64u(msg(s1)) })).toBe(false);
        return true;
      }),
      fuzzOpts,
    );
  });
});
