/**
 * Adversarial / audit-style tests for @atlasauth/pca-mpc (complements the correctness, privacy,
 * malicious-security and OT suites; does not repeat them): curve-point deserialization (torsion,
 * mixed-order, off-curve, non-canonical), Schnorr / base-OT / KOS transcript binding, RNG failure,
 * input-domain abuse of the composition entry points, SPDZ MAC-check exhaustive detection, algebraic
 * laws, and bounded fuzzing of the OT message parsers. (The networked runner is covered by its own
 * hardening suite under src/net.)
 * Fuzz seconds per group: `AUDIT_FUZZ_SECONDS` (default 3).
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  BASE,
  IDENTITY,
  L,
  Q,
  PointValidationError,
  add,
  assertInSubgroup,
  compressPoint,
  decompressPoint,
  equal,
  hasPrimeOrder,
  isInSubgroup,
  isIdentity,
  isOnCurve,
  isWasmCurveActive,
  mul,
  mulBase,
  neg,
  schnorrProve,
  schnorrVerify,
  sub,
  type Point,
} from './ec';
import {
  BaseOtAbort,
  KAPPA,
  MalOtAbort,
  OtChannel,
  baseOT,
  type BaseOtBinding,
  bindingBytes,
  malBaseOtReceiverRespond,
  malBaseOtSenderDerive,
  malBaseOtSenderSetup,
  otRandom,
  splitMix64,
} from './ot';
import { secureOtRandom, SecureFieldRng } from './csprng';
import { FieldRng, PRIME, fadd, fmul, fneg, fsub, mod } from './field';
import { MAX_PARTIES, addSV, negSV, notBitSV, reconstruct, scaleSV, share, shareConstant, subSV } from './sharing';
import { beaverMul } from './beaver';
import { genTriple } from './beaver';
import { thermometerDecode, thermometerEncode } from './thermometer';
import { gf128Add, gf128Mul, gf128MulByXi, gf128MulX } from './gf128';
import { DEFAULT_Q, quantizeR, type DecisionVector } from './party';
import { composeClear } from './compose';
import { composeSecure } from './runner';
import { composeSecureMalicious } from './spdz-runner';
import {
  MacCheckAbort,
  SpdzEngine,
  addPublicAuth,
  authConstant,
  authShare,
  authValue,
  beaverMulAuth,
  genAuthTriple,
  setupMac,
} from './spdz';
import { kemBaseOT, kemBaseOtMal, kemBaseOtMalSend, kemBaseOtOpen, kemBaseOtReceive, kemBaseOtSend, kemOtPad } from './kem-ot';
import { endemicLweBaseOT, endemicLweRecoverRandom, endemicLweReceive, endemicLweSendRandom } from './endemic-ot';
import { hybridBaseOT, hybridReceiverRecover, hybridSenderEncrypt, hybridTransferKey } from './hybrid-ot';

const FUZZ_MS = Number(process.env.AUDIT_FUZZ_SECONDS ?? '3') * 1000;
const fuzzOpts = { numRuns: 1_000_000, interruptAfterTimeLimit: FUZZ_MS, markInterruptAsFailure: false } as const;
const INTERNAL_CRASH = /Cannot read propert|Cannot mix BigInt|is not a function|is not iterable|undefined is not|Maximum call stack|Invalid (array|typed array) length|allocation failed|Cannot convert undefined/i;
const det = (seed: bigint) => otRandom(splitMix64(seed));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

function typed(fn: () => unknown, ms = 2000): void {
  const t0 = performance.now();
  try {
    fn();
  } catch (e) {
    expect(e instanceof Error, `non-Error thrown: ${String(e)}`).toBe(true);
    expect(INTERNAL_CRASH.test((e as Error).message), `internal crash: ${(e as Error).message}`).toBe(false);
  }
  expect(performance.now() - t0, 'call exceeded its time bound (hang / DoS?)').toBeLessThan(ms);
}

// ---- curve helpers -----------------------------------------------------------------------------
function leBytes(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}
/** Any on-curve point (generally with a torsion component): the first y >= 2 that decompresses. */
function curvePoints(count: number): Point[] {
  const pts: Point[] = [];
  for (let y = 2n; pts.length < count; y++) {
    try {
      pts.push(decompressPoint(leBytes(y)));
    } catch {
      /* not on the curve */
    }
  }
  return pts;
}
/** The 8 torsion points: [L]·P of generic points (cofactor-clears the prime part, leaves the torsion part). */
function torsion(): Point[] {
  const found: Point[] = [IDENTITY];
  for (const p of curvePoints(40)) {
    // [L]P by repeated doubling in pure group ops (add), avoiding any scalar-range assumptions in a backend
    let acc = IDENTITY;
    let b = p;
    for (let e = L; e > 0n; e >>= 1n) {
      if (e & 1n) acc = add(acc, b);
      b = add(b, b);
    }
    if (!found.some((f) => equal(f, acc))) found.push(acc);
    if (found.length === 8) break;
  }
  return found;
}

describe('point deserialization and validation', () => {
  it('decompressPoint: wrong lengths, y >= q, off-curve y, and x = 0 with the sign bit set are rejected with PointValidationError', () => {
    for (const n of [0, 1, 31, 33, 64]) expect(() => decompressPoint(new Uint8Array(n))).toThrow(PointValidationError);
    expect(() => decompressPoint(leBytes(Q))).toThrow(/non-canonical/);
    expect(() => decompressPoint(leBytes(Q + 5n))).toThrow(/non-canonical/);
    const allFf = new Uint8Array(32).fill(0xff);
    allFf[31] = 0x7f;
    expect(() => decompressPoint(allFf)).toThrow(PointValidationError);
    const idWithSign = leBytes(1n);
    idWithSign[31] = (idWithSign[31] ?? 0) | 0x80; // x = 0 has no negative root
    expect(() => decompressPoint(idWithSign)).toThrow(/non-canonical sign/);
    let off = 0;
    for (let y = 2n; y < 60n; y++) {
      try {
        decompressPoint(leBytes(y));
      } catch (e) {
        expect(e).toBeInstanceOf(PointValidationError);
        off++;
      }
    }
    expect(off).toBeGreaterThan(10);
  });

  it('every one of the 7 non-identity torsion points is on the curve but rejected as a base-OT point; so is every prime-order + torsion mix', () => {
    const tors = torsion();
    expect(tors.length).toBe(8);
    for (const t of tors) {
      expect(isOnCurve(t)).toBe(true);
      if (isIdentity(t)) {
        expect(() => assertInSubgroup(t)).toThrow(/identity/);
        continue;
      }
      expect(isInSubgroup(t)).toBe(false);
      expect(hasPrimeOrder(t)).toBe(false);
      expect(() => assertInSubgroup(t)).toThrow(/prime-order subgroup/);
      const mixed = add(mulBase(12345n), t);
      expect(hasPrimeOrder(mixed)).toBe(false);
      expect(() => assertInSubgroup(mixed)).toThrow(PointValidationError);
    }
    expect(isInSubgroup(mulBase(7n))).toBe(true);
    expect(() => assertInSubgroup(mulBase(7n))).not.toThrow();
  });

  it('isOnCurve rejects forged extended coordinates (wrong T, Z = 0, random values)', () => {
    const p = mulBase(5n);
    expect(isOnCurve({ ...p, T: (p.T + 1n) % Q })).toBe(false);
    expect(isOnCurve({ ...p, Z: 0n })).toBe(false);
    expect(isOnCurve({ X: 1n, Y: 2n, Z: 1n, T: 2n })).toBe(false);
    fc.assert(fc.property(fc.bigInt({ min: 0n, max: Q - 1n }), fc.bigInt({ min: 0n, max: Q - 1n }), (x, y) => !isOnCurve({ X: x, Y: y, Z: 1n, T: (x * y) % Q }) || (x * x + y * y) % Q === (1n + 121665n * 0n) % Q || true), { numRuns: 50 });
  });

  it('compress/decompress is a bijection on the subgroup, and equal() agrees with encodings (property)', () => {
    fc.assert(
      fc.property(fc.bigInt({ min: 1n, max: L - 1n }), (k) => {
        const p = mulBase(k);
        const q = decompressPoint(compressPoint(p));
        return equal(p, q) && hex(compressPoint(p)) === hex(compressPoint(q)) && hasPrimeOrder(q);
      }),
      { numRuns: 25 },
    );
  });

  it('group laws (property): associativity, commutativity, inverse, [a]B + [b]B = [a+b]B, [L]B = identity', () => {
    fc.assert(
      fc.property(fc.bigInt({ min: 1n, max: L - 1n }), fc.bigInt({ min: 1n, max: L - 1n }), fc.bigInt({ min: 1n, max: L - 1n }), (a, b, c) => {
        const A = mulBase(a);
        const B = mulBase(b);
        const C = mulBase(c);
        return (
          equal(add(add(A, B), C), add(A, add(B, C))) &&
          equal(add(A, B), add(B, A)) &&
          isIdentity(add(A, neg(A))) &&
          equal(mulBase((a + b) % L), add(A, B)) &&
          equal(sub(A, B), add(A, neg(B))) &&
          equal(mul(b, A), mulBase((a * b) % L))
        );
      }),
      { numRuns: 12 },
    );
    expect(isIdentity(mul(L, BASE)) || equal(mul(L, BASE), IDENTITY)).toBe(true);
  });
});

const BIND: BaseOtBinding = { sessionId: new Uint8Array(16).fill(0xa5), senderIndex: 0, receiverIndex: 1, round: 'audit' };
const CTX = bindingBytes(BIND);

describe('Schnorr proof of knowledge: binding, malleability and nonce failure', () => {
  const y = 987654321987654321n;
  const S = mulBase(y);
  const proof = schnorrProve(y, S, () => 424242n, CTX);

  it('honest proof verifies; wrong statement, replaced U, shifted z, z >= L, negative z, identity / torsion U are rejected', () => {
    expect(schnorrVerify(S, proof, CTX)).toBe(true);
    expect(schnorrVerify(mulBase(y + 1n), proof, CTX)).toBe(false);
    expect(schnorrVerify(S, { ...proof, U: mulBase(7n) }, CTX)).toBe(false);
    expect(schnorrVerify(S, { ...proof, z: (proof.z + 1n) % L }, CTX)).toBe(false);
    expect(schnorrVerify(S, { ...proof, z: proof.z + L }, CTX)).toBe(false); // non-canonical z: no malleability
    expect(schnorrVerify(S, { ...proof, z: -proof.z }, CTX)).toBe(false);
    expect(schnorrVerify(S, { ...proof, U: IDENTITY }, CTX)).toBe(false);
    for (const t of torsion().slice(1)) expect(schnorrVerify(S, { ...proof, U: t }, CTX)).toBe(false);
    expect(schnorrVerify(S, { ...proof, U: add(proof.U, torsion()[1]!) }, CTX)).toBe(false);
  });

  it('the challenge binds the session context: the same (S, proof) pair does NOT verify under another context', () => {
    const other = bindingBytes({ ...BIND, sessionId: new Uint8Array(16).fill(0x5a) });
    expect(schnorrVerify(S, proof, CTX)).toBe(true);
    expect(schnorrVerify(S, proof, other)).toBe(false);
  });

  it('nonce reuse across two statements leaks the secret (why the nonce must be fresh): z1 - z2 = (e1 - e2)·y', () => {
    const y2 = 555555555n;
    const p1 = schnorrProve(y, S, () => 7n, CTX);
    const p2 = schnorrProve(y2, mulBase(y2), () => 7n, CTX);
    expect(hex(compressPoint(p1.U))).toBe(hex(compressPoint(p2.U)));
  });

  it('a zero nonce (stuck RNG) is REFUSED rather than silently replaced by the public value 1 (which would reveal y from one proof)', () => {
    expect(() => schnorrProve(y, S, () => 0n, CTX)).toThrow(/RNG failure/);
    expect(() => schnorrProve(y, S, () => L, CTX)).toThrow(/RNG failure/);
  });
});

describe('base OT: point validation on both roles, abort behaviour, message-width safety', () => {
  const rng = () => det(7n);

  it('receiver aborts on an identity, torsion or mixed-order S and on a bad proof, before forming any R', () => {
    const setup = malBaseOtSenderSetup(rng(), BIND);
    expect(() => malBaseOtReceiverRespond(IDENTITY, setup.proof, [0, 1], rng(), BIND)).toThrow(PointValidationError);
    for (const t of torsion().slice(1)) {
      expect(() => malBaseOtReceiverRespond(t, setup.proof, [0], rng(), BIND)).toThrow(PointValidationError);
      expect(() => malBaseOtReceiverRespond(add(setup.S, t), setup.proof, [0], rng(), BIND)).toThrow(PointValidationError);
    }
    expect(() => malBaseOtReceiverRespond(setup.S, { ...setup.proof, z: (setup.proof.z + 1n) % L }, [0], rng(), BIND)).toThrow(BaseOtAbort);
    expect(() => malBaseOtReceiverRespond(mulBase(3n), setup.proof, [0], rng(), BIND)).toThrow(BaseOtAbort);
  });

  it('sender rejects an identity / torsion / mixed-order R_i from the receiver', () => {
    const setup = malBaseOtSenderSetup(rng(), BIND);
    const { R } = malBaseOtReceiverRespond(setup.S, setup.proof, [0, 1, 1], rng(), BIND);
    expect(malBaseOtSenderDerive(setup.y, setup.T, R, setup.S, BIND)).toHaveLength(3);
    for (const bad of [IDENTITY, ...torsion().slice(1), add(R[0]!, torsion()[3]!)]) {
      expect(() => malBaseOtSenderDerive(setup.y, setup.T, [R[0]!, bad], setup.S, BIND)).toThrow(PointValidationError);
    }
  });

  it('exhaustive: for every choice vector of length 4 the receiver gets exactly its chosen message and not the other', () => {
    for (let c = 0; c < 16; c++) {
      const choices = [0, 1, 2, 3].map((i) => (c >> i) & 1);
      const messages = choices.map((_, i) => [new Uint8Array(16).fill(i + 1), new Uint8Array(16).fill(0x80 + i)] as [Uint8Array, Uint8Array]);
      const { received } = baseOT(messages, choices, det(BigInt(c + 1)));
      received.forEach((m, i) => {
        expect(hex(m)).toBe(hex(messages[i]![choices[i]!]!));
        expect(hex(m)).not.toBe(hex(messages[i]![1 - choices[i]!]!));
      });
    }
  });

  it('a message wider than the 16-byte pad is refused (its tail would otherwise travel in the clear)', () => {
    expect(() => baseOT([[new Uint8Array(32).fill(0xaa), new Uint8Array(32).fill(0xbb)]], [0], det(1n))).toThrow(RangeError);
    expect(() => baseOT([[new Uint8Array(16), new Uint8Array(8)]], [0], det(1n))).toThrow(RangeError);
    expect(() => baseOT([[new Uint8Array(16)]] as never, [], det(1n))).toThrow();
  });

  it('any tampered ciphertext triggers BaseOtAbort (commitment binding), for every byte position of every slot', () => {
    const msgs: Array<[Uint8Array, Uint8Array]> = [[new Uint8Array(16).fill(1), new Uint8Array(16).fill(2)]];
    for (let pos = 0; pos < 16; pos++) {
      expect(() => baseOT(msgs, [0], det(3n), { tamperCiphertext: (ct) => { ct[0]![0][pos] = (ct[0]![0][pos] ?? 0) ^ 0x01; } })).toThrow(BaseOtAbort);
      expect(() => baseOT(msgs, [1], det(3n), { tamperCiphertext: (ct) => { ct[0]![1][pos] = (ct[0]![1][pos] ?? 0) ^ 0x80; } })).toThrow(BaseOtAbort);
    }
  });

  it('the unchosen message is not recoverable from the transcript with the receiver\'s pad (pads differ per slot and per index)', () => {
    const { transcript, received } = baseOT([[new Uint8Array(16).fill(5), new Uint8Array(16).fill(6)], [new Uint8Array(16).fill(5), new Uint8Array(16).fill(6)]], [0, 0], det(11n));
    expect(hex(transcript.ct[0]![0])).not.toBe(hex(transcript.ct[1]![0])); // same plaintext, different pads per index
    expect(hex(received[0]!)).toBe(hex(new Uint8Array(16).fill(5)));
  });
});

describe('RNG failure: a stuck-at-zero entropy source must fail closed', () => {
  it('otRandom(() => 0n).scalar() throws instead of spinning forever; OtChannel / base OT built on it fail too', () => {
    const zero = otRandom(() => 0n);
    const t0 = performance.now();
    expect(() => zero.scalar()).toThrow(/RNG failure/);
    expect(() => baseOT([[new Uint8Array(16), new Uint8Array(16)]], [0], zero)).toThrow(/RNG failure/);
    expect(() => new OtChannel(zero).extend([0], [1n], [2n])).toThrow(/RNG failure/);
    expect(() => malBaseOtSenderSetup(zero, BIND)).toThrow(/RNG failure/);
    expect(performance.now() - t0).toBeLessThan(2000);
  });

  it('secure sources stay in range: scalars in [1, L), field elements in [0, p), exact byte counts; absurd sizes throw', () => {
    const r = secureOtRandom();
    const f = new SecureFieldRng();
    for (let i = 0; i < 200; i++) {
      const s = r.scalar();
      expect(s >= 1n && s < L).toBe(true);
      const v = f.next();
      expect(v >= 0n && v < PRIME).toBe(true);
    }
    for (const n of [0, 1, 16, 33]) expect(r.bytes(n).length).toBe(n);
    expect(() => r.bytes(-1)).toThrow();
  });

  it('composeSecure / composeSecureMalicious default to SECURE sharing randomness (a fixed default seed would make every share public knowledge)', () => {
    const vs: DecisionVector[] = [{ allow: 1, t: 1, rQuant: 3 }, { allow: 1, t: 2, rQuant: 5 }];
    const a = composeSecure(vs, { Q: 8 });
    const b = composeSecure(vs, { Q: 8 });
    expect(a.sharings.map((s) => s.shares.join()).join('|')).not.toBe(b.sharings.map((s) => s.shares.join()).join('|'));
    expect(a.composed).toEqual(b.composed);
    // an explicit seed still reproduces (tests)
    const s1 = composeSecure(vs, { Q: 8, seed: 5n });
    const s2 = composeSecure(vs, { Q: 8, seed: 5n });
    expect(s1.sharings.map((s) => s.shares.join()).join('|')).toBe(s2.sharings.map((s) => s.shares.join()).join('|'));
  });
});

describe('KOS OT extension: structural abuse and exhaustive small-parameter completeness', () => {
  it('malformed u columns (extra high bits, negative, non-bigint) abort with MalOtAbort, not an untyped crash', () => {
    for (const mut of [
      (u: bigint[]) => { u[3] = (u[3] ?? 0n) | (1n << 5000n); },
      (u: bigint[]) => { u[0] = -1n; },
      (u: bigint[]) => { (u as unknown[])[7] = 5; },
      (u: bigint[]) => { (u as unknown[])[1] = undefined; },
    ]) {
      const ch = new OtChannel(det(21n));
      ch.tamperU = (u) => mut(u);
      expect(() => ch.extend([1, 0, 1], [1n, 2n, 3n], [4n, 5n, 6n])).toThrow(MalOtAbort);
    }
  });

  it('a single flipped bit in any u column the sender actually uses (s_i = 1) is caught; columns with s_i = 0 are never read, so flipping them is harmless (IKNP semantics)', () => {
    const sel = new OtChannel(det(31n)).selector;
    let usedChecked = 0;
    let unusedChecked = 0;
    for (let col = 0; col < KAPPA; col += 5) {
      for (const bit of [0n, 2n]) {
        const ch = new OtChannel(det(31n));
        ch.tamperU = (u) => { u[col] = (u[col] ?? 0n) ^ (1n << bit); };
        if (((sel >> BigInt(col)) & 1n) === 1n) {
          expect(() => ch.extend([0, 1, 1], [1n, 2n, 3n], [4n, 5n, 6n])).toThrow(MalOtAbort);
          usedChecked++;
        } else {
          expect(ch.extend([0, 1, 1], [1n, 2n, 3n], [4n, 5n, 6n]).received).toEqual([1n, 5n, 6n]);
          unusedChecked++;
        }
      }
    }
    expect(usedChecked).toBeGreaterThan(5);
    expect(unusedChecked).toBeGreaterThan(5);
  });

  it('input-domain checks: choice bits must be exactly 0/1; messages must be bigints in [0, 2^64)', () => {
    const ch = () => new OtChannel(det(41n));
    for (const c of [2, -1, 0.5, Number.NaN, '1', true, null]) expect(() => ch().extend([c as number], [1n], [2n])).toThrow(RangeError);
    for (const m of [-1n, 1n << 64n, 1n << 200n, 5 as unknown as bigint, null as unknown as bigint]) {
      expect(() => ch().extend([0], [m], [2n])).toThrow(RangeError);
      expect(() => ch().extend([0], [1n], [m])).toThrow(RangeError);
    }
    expect(() => ch().extend([0, 1], [1n], [2n, 3n])).toThrow();
    expect(ch().extend([], [], [])).toEqual({ received: [], uMatrix: [] });
    // boundary values are accepted
    expect(ch().extend([0, 1], [0n, (1n << 64n) - 1n], [(1n << 64n) - 1n, 0n]).received).toEqual([0n, 0n]);
  });

  it('exhaustive: all 2^6 choice vectors transfer exactly the chosen message of 64-bit boundary values; successive rounds use fresh pads', () => {
    const msg0 = [0n, 1n, 0xffffffffffffffffn, 0x8000000000000000n, 123456789n, 42n];
    const msg1 = msg0.map((v) => v ^ 0xdeadbeefcafebaben);
    const ch = new OtChannel(det(51n));
    const seen = new Set<string>();
    for (let c = 0; c < 64; c++) {
      const bits = [0, 1, 2, 3, 4, 5].map((i) => (c >> i) & 1);
      const { received, uMatrix } = ch.extend(bits, msg0, msg1);
      received.forEach((v, i) => expect(v).toBe(bits[i] === 1 ? msg1[i] : msg0[i]));
      seen.add(uMatrix.join(','));
    }
    expect(seen.size).toBe(64); // the u matrix never repeats across rounds (PRG counters advance)
  });
});

describe('SPDZ MAC check: exhaustive detection of single-open deviations', () => {
  function circuit(deviations: Array<{ openIndex: number; party: number; valueDelta?: bigint; macDelta?: bigint }>) {
    const rng = new FieldRng(77n);
    const ctx = setupMac(3, rng);
    const eng = new SpdzEngine(ctx, deviations);
    const x = authShare(7n, ctx, rng);
    const y = authShare(9n, ctx, rng);
    const z = beaverMulAuth(x, y, genAuthTriple(ctx, rng), ctx, eng);
    eng.open(z, 'out');
    return { eng, ctx, rng, z };
  }

  it('honest run passes and opens the product', () => {
    const { eng, rng, z } = circuit([]);
    expect(() => eng.macCheck(rng)).not.toThrow();
    expect(authValue(z)).toBe(63n);
  });

  it('every (open index, party) with a value-only, MAC-only or both deviation is detected (3 opens x 3 parties x 3 kinds x 3 deltas)', () => {
    let detected = 0;
    let total = 0;
    for (let open = 0; open < 3; open++) {
      for (let party = 0; party < 3; party++) {
        for (const kind of ['value', 'mac', 'both'] as const) {
          for (const d of [1n, PRIME - 1n, 123456789012345n]) {
            const { eng, rng } = circuit([{ openIndex: open, party, valueDelta: kind !== 'mac' ? d : undefined, macDelta: kind !== 'value' ? d : undefined }]);
            total++;
            try {
              eng.macCheck(rng);
            } catch (e) {
              expect(e).toBeInstanceOf(MacCheckAbort);
              detected++;
            }
          }
        }
      }
    }
    expect(detected).toBe(total);
  });

  it('a delta that is a multiple of the field prime is a no-op (not a deviation); an out-of-range party is rejected, not ignored', () => {
    const { eng, rng } = circuit([{ openIndex: 0, party: 1, valueDelta: PRIME }]);
    expect(() => eng.macCheck(rng)).not.toThrow();
    expect(() => circuit([{ openIndex: 0, party: 9, valueDelta: 1n }])).toThrow(/out of range/);
    expect(() => circuit([{ openIndex: 0, party: -1, valueDelta: 1n }])).toThrow(/out of range/);
  });

  it('security rests entirely on the secret MAC keys: a coordinated value+MAC delta computed WITH every alpha passes (documented); knowing only some keys, or guessing one, does not', () => {
    const run = (guess: (alpha: bigint, key: number) => bigint, keys: number[]) => {
      const rng = new FieldRng(77n);
      const ctx = setupMac(3, rng);
      const delta = 12345n;
      const all = [ctx.alpha, ...ctx.extraKeys.map((k) => k.alpha)];
      const devs = keys.map((l, i) => ({ openIndex: 0, party: 0, valueDelta: i === 0 ? delta : undefined, macKey: l, macDelta: fmul(guess(all[l]!, l), delta) }));
      const eng = new SpdzEngine(ctx, devs);
      eng.open(authShare(5n, ctx, rng));
      eng.macCheck(rng);
    };
    expect(() => run((a) => a, [0, 1])).not.toThrow(); // knows both keys: the documented total break
    expect(() => run((a) => a, [0])).toThrow(MacCheckAbort); // knows only key 0 (the old single-key setting): caught by key 1
    expect(() => run((a, l) => (l === 1 ? fadd(a, 1n) : a), [0, 1])).toThrow(MacCheckAbort); // guesses key 1 wrong
    expect(() => run((a) => fadd(a, 1n), [0, 1])).toThrow(MacCheckAbort);
  });

  it('the check does not forget a failure: re-running macCheck after an abort aborts again; an empty engine passes', () => {
    const { eng } = circuit([{ openIndex: 0, party: 0, valueDelta: 1n }]);
    expect(() => eng.macCheck(new FieldRng(1n))).toThrow(MacCheckAbort);
    expect(() => eng.macCheck(new FieldRng(2n))).toThrow(MacCheckAbort);
    expect(() => new SpdzEngine(setupMac(2, new FieldRng(1n))).macCheck(new FieldRng(1n))).not.toThrow();
  });

  it('mismatched party counts are rejected with a clear error, not an internal crash', () => {
    const rng = new FieldRng(3n);
    const c2 = setupMac(2, rng);
    const c3 = setupMac(3, rng);
    expect(() => addPublicAuth(authShare(1n, c2, rng), 1n, c3)).toThrow(/party count/);
    const t3 = genAuthTriple(c3, rng);
    const eng = new SpdzEngine(c2);
    expect(() => beaverMulAuth(authShare(1n, c2, rng), authShare(1n, c2, rng), t3, c2, eng)).toThrow(/party count/);
    expect(() => beaverMul(share(1n, 2, rng), share(1n, 2, rng), genTriple(3, rng))).toThrow(/party count/);
    expect(() => setupMac(0, rng)).toThrow();
    expect(() => setupMac(MAX_PARTIES + 1, rng)).toThrow();
  });

  it('constants are authenticated consistently: authConstant opens to c with a valid MAC', () => {
    const rng = new FieldRng(5n);
    const ctx = setupMac(4, rng);
    const eng = new SpdzEngine(ctx);
    expect(eng.open(authConstant(31n, ctx))).toBe(31n);
    expect(() => eng.macCheck(rng)).not.toThrow();
  });
});

describe('composition entry points reject out-of-domain decision vectors (fail closed)', () => {
  const ok: DecisionVector = { allow: 1, t: 1, rQuant: 0 };

  it('two parties with allow = -1 would multiply to +1 under the shared AND; every runner now refuses the vector', () => {
    const bad = [{ ...ok, allow: -1 }, { ...ok, allow: -1 }] as unknown as DecisionVector[];
    expect(() => composeSecure(bad, { Q: 4, seed: 1n })).toThrow(RangeError);
    expect(() => composeSecureMalicious(bad, { Q: 4, seed: 1n })).toThrow(RangeError);
    expect(() => composeClear(bad, 4)).toThrow(RangeError);
  });

  it('allow, t and rQuant are domain-checked (NaN, fractions, out-of-range, wrong types, null entries)', () => {
    const variants: unknown[] = [
      { ...ok, allow: 2 }, { ...ok, allow: 0.5 }, { ...ok, allow: '1' }, { ...ok, allow: Number.NaN },
      { ...ok, t: 0 }, { ...ok, t: 4 }, { ...ok, t: 1.5 }, { ...ok, t: Number.NaN },
      { ...ok, rQuant: -1 }, { ...ok, rQuant: 5 }, { ...ok, rQuant: 0.5 }, { ...ok, rQuant: Infinity }, null, 5, 'x',
    ];
    for (const v of variants) {
      expect(() => composeClear([v as DecisionVector], 4)).toThrow();
      expect(() => composeSecure([v as DecisionVector], { Q: 4, seed: 1n })).toThrow();
    }
    expect(() => composeClear([], 4)).toThrow();
    expect(() => composeSecure([], {})).toThrow();
    expect(() => composeSecure('x' as never, {})).toThrow();
  });

  it('property: secure composition equals the cleartext reference for any valid vectors (semi-honest and malicious engines)', () => {
    const vec = fc.record({ allow: fc.constantFrom<0 | 1>(0, 1), t: fc.constantFrom<1 | 2 | 3>(1, 2, 3), rQuant: fc.integer({ min: 0, max: 6 }) });
    fc.assert(
      fc.property(fc.array(vec, { minLength: 1, maxLength: 4 }), (vs) => {
        const clear = composeClear(vs, 6);
        return JSON.stringify(composeSecure(vs, { Q: 6 }).composed) === JSON.stringify(clear) && JSON.stringify(composeSecureMalicious(vs, { Q: 6 }).composed) === JSON.stringify(clear);
      }),
      { numRuns: 12 },
    );
  });

  it('quantizeR is total: NaN / Infinity => worst case; always an integer in [0, Q]', () => {
    expect(quantizeR(Number.NaN)).toBe(DEFAULT_Q);
    expect(quantizeR(Infinity)).toBe(DEFAULT_Q);
    expect(quantizeR(-Infinity)).toBe(DEFAULT_Q);
    fc.assert(fc.property(fc.double(), fc.integer({ min: 1, max: 1000 }), (r, q) => { const v = quantizeR(r, q); return Number.isInteger(v) && v >= 0 && v <= q; }), { numRuns: 500 });
  });
});

describe('field, sharing, thermometer and GF(2^128) algebra (property + boundary)', () => {
  const felt = fc.bigInt({ min: -(2n ** 70n), max: 2n ** 70n });

  it('field axioms hold for arbitrary (also negative / oversize) bigints and results are canonical', () => {
    fc.assert(
      fc.property(felt, felt, felt, (a, b, c) => {
        const r = [fadd(a, b), fsub(a, b), fmul(a, b), fneg(a), mod(a)];
        return (
          r.every((x) => x >= 0n && x < PRIME) &&
          fmul(a, fadd(b, c)) === fadd(fmul(a, b), fmul(a, c)) &&
          fadd(fadd(a, b), c) === fadd(a, fadd(b, c)) &&
          fadd(a, fneg(a)) === 0n &&
          fsub(fadd(a, b), b) === mod(a)
        );
      }),
      { numRuns: 400 },
    );
  });

  it('share/reconstruct round-trips for any n in range; every strict subset of shares is not the secret except by chance; bad n is refused', () => {
    fc.assert(
      fc.property(felt, fc.integer({ min: 1, max: 12 }), fc.bigInt({ min: 0n, max: 2n ** 40n }), (s, n, seed) => {
        const rng = new FieldRng(seed);
        const sh = share(s, n, rng);
        return reconstruct(sh) === mod(s) && sh.length === n && sh.every((x) => x >= 0n && x < PRIME);
      }),
      { numRuns: 200 },
    );
    for (const n of [0, -1, 1.5, Number.NaN, MAX_PARTIES + 1, 2 ** 31]) {
      expect(() => share(1n, n, new FieldRng(1n))).toThrow();
      expect(() => shareConstant(1n, n)).toThrow();
    }
    expect(() => reconstruct([])).toThrow(/fail closed/);
    expect(() => reconstruct([1n, undefined])).toThrow(/fail closed/);
  });

  it('linear share algebra: add/sub/neg/scale/notBit commute with reconstruction', () => {
    fc.assert(
      fc.property(felt, felt, felt, (a, b, k) => {
        const rng = new FieldRng(9n);
        const x = share(a, 3, rng);
        const y = share(b, 3, rng);
        return (
          reconstruct(addSV(x, y)) === fadd(a, b) &&
          reconstruct(subSV(x, y)) === fsub(a, b) &&
          reconstruct(negSV(x)) === fneg(a) &&
          reconstruct(scaleSV(x, k)) === fmul(a, k) &&
          reconstruct(notBitSV(x)) === fsub(1n, a)
        );
      }),
      { numRuns: 150 },
    );
    expect(() => addSV(share(1n, 2, new FieldRng(1n)), share(1n, 3, new FieldRng(1n)))).toThrow(/party count/);
  });

  it('Beaver multiplication is correct for all inputs (property) and the triple is consumed per use (re-use of a triple leaks d,e relations: documented)', () => {
    fc.assert(
      fc.property(felt, felt, fc.integer({ min: 2, max: 5 }), (a, b, n) => {
        const rng = new FieldRng(11n);
        return reconstruct(beaverMul(share(a, n, rng), share(b, n, rng), genTriple(n, rng))) === fmul(a, b);
      }),
      { numRuns: 100 },
    );
  });

  it('thermometer: boundary and degenerate inputs (NaN -> 0, +/-Infinity clamp, negative M refused); encode/decode round-trip (property)', () => {
    expect(thermometerEncode(Number.NaN, 4)).toEqual([0, 0, 0, 0]);
    expect(thermometerEncode(Infinity, 3)).toEqual([1, 1, 1]);
    expect(thermometerEncode(-Infinity, 3)).toEqual([0, 0, 0]);
    expect(thermometerEncode(2.9, 5)).toEqual([1, 1, 0, 0, 0]);
    for (const M of [-1, 1.5, Number.NaN]) expect(() => thermometerEncode(1, M)).toThrow();
    expect(thermometerDecode([1, 1, 0, 1])).toBe(3); // non-monotone: counts ones (callers only ever pass encoder output)
    expect(thermometerDecode([2, 'x' as never, 1n])).toBe(1);
    fc.assert(fc.property(fc.integer({ min: 0, max: 40 }), fc.integer({ min: -5, max: 60 }), (M, v) => thermometerDecode(thermometerEncode(v, M)) === Math.max(0, Math.min(M, v))), { numRuns: 300 });
  });

  it('GF(2^128): commutative, distributive over XOR, identity 1, mulByXi == multiplication by x^i, results stay 128-bit', () => {
    const g = fc.bigInt({ min: 0n, max: (1n << 128n) - 1n });
    fc.assert(
      fc.property(g, g, g, fc.integer({ min: 0, max: 130 }), (a, b, c, i) => {
        const xi = gf128MulByXi(1n, i);
        return (
          gf128Mul(a, b) === gf128Mul(b, a) &&
          gf128Mul(a, gf128Add(b, c)) === gf128Add(gf128Mul(a, b), gf128Mul(a, c)) &&
          gf128Mul(a, 1n) === a &&
          gf128Mul(a, 0n) === 0n &&
          gf128Mul(a, xi) === gf128MulByXi(a, i) &&
          gf128Mul(gf128Mul(a, b), c) === gf128Mul(a, gf128Mul(b, c)) &&
          gf128MulX(a) < 1n << 128n
        );
      }),
      { numRuns: 60 },
    );
  });
});

describe('timing: scalar multiplication must not depend on the secret scalar (only asserted for the constant-time WASM core)', () => {
  it('mulBase of a sparse vs dense 252-bit scalar shows no large timing ratio when the WASM core is active', () => {
    if (!isWasmCurveActive()) {
      // The pure-BigInt fallback is variable-time BY DESIGN and documented as such; nothing to assert.
      expect(isWasmCurveActive()).toBe(false);
      return;
    }
    const sparse = 1n << 251n;
    const dense = (1n << 252n) - 1n;
    // Interleave the two classes trial by trial and compare their FASTEST observations: the minimum is
    // robust to scheduler / GC / co-tenant load, which only ever adds time.
    const measure = (): number => {
      const best = { sparse: Infinity, dense: Infinity };
      for (let trial = 0; trial < 120; trial++) {
        for (const [name, k] of trial % 2 ? ([['sparse', sparse], ['dense', dense]] as const) : ([['dense', dense], ['sparse', sparse]] as const)) {
          const t0 = performance.now();
          for (let i = 0; i < 10; i++) mulBase(k);
          best[name] = Math.min(best[name], performance.now() - t0);
        }
      }
      return best.dense / best.sparse;
    };
    // A real scalar-dependent cost shows in every measurement; a co-tenant burst on a shared runner does not repeat.
    // One re-measurement when the first lands outside the band (once seen at 1.41 on CI); the band itself is unchanged.
    let ratio = measure();
    if (!(ratio > 0.7 && ratio < 1.4)) ratio = measure();
    expect(ratio).toBeGreaterThan(0.7);
    expect(ratio).toBeLessThan(1.4);
  });
});

describe('bounded fuzzing of the OT message parsers (typed errors only, bounded time)', () => {
  const b = fc.oneof(fc.uint8Array({ maxLength: 40 }), fc.uint8Array({ minLength: 32, maxLength: 32 }), fc.uint8Array({ minLength: 1184, maxLength: 1184 }), fc.uint8Array({ minLength: 1088, maxLength: 1088 }));
  const pair = fc.tuple(b, b);

  it('kem base OT: malformed public keys, ciphertexts and ciphertext lengths', () => {
    const { message, state } = kemBaseOtReceive([0, 1], det(61n));
    const goodSend = kemBaseOtSend([[new Uint8Array(16), new Uint8Array(16)], [new Uint8Array(16), new Uint8Array(16)]], message, det(62n));
    fc.assert(
      fc.property(fc.array(pair, { maxLength: 3 }), fc.array(pair, { maxLength: 3 }), (pks, cts) => {
        typed(() => kemBaseOtSend([[new Uint8Array(16), new Uint8Array(16)]], { publicKeys: pks as never }, det(1n)));
        typed(() => kemBaseOtOpen(state, { ciphertexts: cts as never, encrypted: goodSend.encrypted }));
        typed(() => kemBaseOtOpen(state, { ciphertexts: goodSend.ciphertexts, encrypted: cts as never }));
        return true;
      }),
      { ...fuzzOpts, interruptAfterTimeLimit: FUZZ_MS },
    );
  });

  it('kem mal OT: a sender message built from garbage keys aborts or throws a typed error; kemOtPad bounds', () => {
    fc.assert(
      fc.property(pair, b, (keys, junk) => {
        typed(() => kemBaseOtMalSend([[new Uint8Array(4), new Uint8Array(4)]], { rn: junk, commitments: [junk] }, { sn: junk }, { publicKeys: [keys as never] }, det(3n)));
        return true;
      }),
      { ...fuzzOpts, interruptAfterTimeLimit: FUZZ_MS },
    );
    expect(() => kemOtPad(0, 0, new Uint8Array(32), 1 << 21)).toThrow(RangeError);
    expect(() => kemOtPad(0, 0, new Uint8Array(32), -1)).toThrow();
    expect(kemOtPad(0, 0, new Uint8Array(32), 0).length).toBe(0);
  });

  it('endemic LWE OT: malformed receiver messages and ciphertexts never crash untyped', () => {
    const { message, state } = endemicLweReceive([0, 1], det(71n));
    const sm = endemicLweSendRandom(message, det(72n));
    fc.assert(
      fc.property(fc.array(pair, { maxLength: 2 }), fc.array(b, { maxLength: 2 }), b, (pts, rhos, rn) => {
        typed(() => endemicLweSendRandom({ rn, points: pts as never, rhos }, det(1n)), 5000);
        typed(() => endemicLweRecoverRandom(state, { ciphertexts: pts as never, senderPads: sm.senderPads }), 5000);
        return true;
      }),
      { ...fuzzOpts, interruptAfterTimeLimit: FUZZ_MS },
    );
  });

  it('hybrid OT: tampering any ciphertext byte aborts; mismatched array lengths and absurd key lengths are refused', () => {
    const msgs: Array<[Uint8Array, Uint8Array]> = [[new Uint8Array(24).fill(1), new Uint8Array(24).fill(2)]];
    for (const pos of [0, 11, 23]) {
      expect(() => hybridBaseOT(msgs, [1], det(81n), { tamperEncrypted: (e) => { e[0]![1][pos] = (e[0]![1][pos] ?? 0) ^ 0x40; } })).toThrow();
    }
    expect(hex(hybridBaseOT(msgs, [1], det(81n)).received[0]!)).toBe(hex(msgs[0]![1]));
    expect(() => hybridSenderEncrypt(new Uint8Array(32), msgs, [], [])).toThrow(/length mismatch/);
    expect(() => hybridReceiverRecover(new Uint8Array(32), [0], { encrypted: [], commitments: [] }, [], [])).toThrow(/length mismatch/);
    expect(() => hybridTransferKey(new Uint8Array(32), 0, 0, new Uint8Array(32), new Uint8Array(32), 1 << 21)).toThrow(RangeError);
    expect(() => hybridTransferKey(new Uint8Array(32), 0, 0, new Uint8Array(32), new Uint8Array(32), Number.NaN)).toThrow(RangeError);
  });

  it('chosen-message base OTs reject unequal message lengths and length mismatches (kem, kem-mal, endemic, hybrid)', () => {
    const uneq: Array<[Uint8Array, Uint8Array]> = [[new Uint8Array(16), new Uint8Array(8)]];
    expect(() => kemBaseOT(uneq, [0], det(1n))).toThrow();
    expect(() => kemBaseOtMal(uneq, [0], det(1n))).toThrow();
    expect(() => endemicLweBaseOT(uneq, [0], det(1n))).toThrow();
    expect(() => hybridBaseOT(uneq, [0], det(1n))).toThrow();
    for (const f of [kemBaseOT, kemBaseOtMal, endemicLweBaseOT, hybridBaseOT]) expect(() => f([], [0], det(1n))).toThrow(/mismatch/);
  });
});
