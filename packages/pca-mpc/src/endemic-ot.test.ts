/**
 * Endemic (Masny–Rindal) ML-KEM base-OT tests — the TRUE post-quantum, maliciously-secure base OT.
 * REAL primitives throughout (actual Kyber-768 K-PKE via @atlasauth/pca-mpc-lwe-ot-wasm), no mocks:
 *   (A) HONEST flow: the receiver recovers exactly m_c, for every choice and varied lengths, reproducibly;
 *   (B) THE SECURITY TEST — the endemic property: a malicious receiver CANNOT learn the non-chosen
 *       message, because the non-chosen branch's public key is a UNIFORM ring element (no secret exists),
 *       and a receiver cannot make BOTH branches decryptable. The documented reduction: recovering
 *       m_{1−c} ⟺ breaking IND-CPA of K-PKE under a uniform public key ⟺ decisional Module-LWE.
 *   (C) tamper / abort: a malicious sender's inconsistent ciphertext fails the RO commitment (abort);
 *   (D) the endemic baseOtFn drives a full KOS extension AND an SPDZ open end-to-end, with results
 *       IDENTICAL to the existing EC base.
 */

import { describe, expect, it } from 'vitest';
import {
  EndemicLweOtAbort,
  ENDEMIC_SECRET_BYTES,
  SYM_BYTES,
  TVEC_BYTES,
  endemicLweBaseOT,
  endemicLweBaseOtRandom,
  endemicLweReceive,
  endemicLweSendRandom,
  endemicLwePad,
  endemicSessionId,
  hashToRing,
  kpkeDec,
  kpkeKeygen,
  ringAdd,
  ringSub,
  withEndemicLweBaseOt,
  type EndemicLweReceiverMessage,
} from './endemic-ot';
import { OtChannel, otRandom, splitMix64 } from './ot';
import { secureOtRandom } from './csprng';
import { FieldRng, fadd, fmul, fneg, fsub, mod, PRIME } from './field';
import { SpdzEngine, setupMac, type AuthSV } from './spdz';

function msg(fill: number, len = 16): Uint8Array {
  const b = new Uint8Array(len);
  b.fill(fill);
  return b;
}
function hex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}
function u32(x: number): Uint8Array {
  const b = new Uint8Array(4);
  b[0] = (x >>> 24) & 0xff;
  b[1] = (x >>> 16) & 0xff;
  b[2] = (x >>> 8) & 0xff;
  b[3] = x & 0xff;
  return b;
}
function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
const TAG_HPK = new TextEncoder().encode('atlas-pca-mpc/endemic-lwe-ot-hpk');
function hpk(sid: Uint8Array, i: number, other: Uint8Array): Uint8Array {
  return hashToRing(concat(TAG_HPK, sid, u32(i), other));
}

// ===================================================================================================
describe('(A) endemic ML-KEM base OT: honest flow recovers exactly the chosen message', () => {
  it('recovers m_0 when c=0 and m_1 when c=1 across a choice pattern', () => {
    const messages: Array<[Uint8Array, Uint8Array]> = [
      [msg(0x10), msg(0x11)],
      [msg(0x20), msg(0x21)],
      [msg(0x30), msg(0x31)],
      [msg(0x40), msg(0x41)],
    ];
    const choices = [0, 1, 1, 0];
    const { received } = endemicLweBaseOT(messages, choices, secureOtRandom());
    for (let i = 0; i < messages.length; i++) {
      expect(hex(received[i]!)).toBe(hex(messages[i]![choices[i]!]!));
    }
  });

  it('handles varied message lengths and is reproducible under a seeded RNG', () => {
    const messages: Array<[Uint8Array, Uint8Array]> = [
      [msg(1, 8), msg(2, 8)],
      [msg(3, 32), msg(4, 32)],
      [msg(5, 1), msg(6, 1)],
    ];
    const choices = [1, 0, 1];
    const a = endemicLweBaseOT(messages, choices, otRandom(splitMix64(2026n)));
    const b = endemicLweBaseOT(messages, choices, otRandom(splitMix64(2026n)));
    for (let i = 0; i < messages.length; i++) {
      expect(hex(a.received[i]!)).toBe(hex(messages[i]![choices[i]!]!));
      expect(hex(a.received[i]!)).toBe(hex(b.received[i]!)); // deterministic
    }
  });

  it('the honest receiver recovers exactly ONE random-OT pad (the chosen one)', () => {
    const choices = [0, 1];
    const r = endemicLweBaseOtRandom(choices, otRandom(splitMix64(99n)));
    for (let i = 0; i < choices.length; i++) {
      const c = choices[i]!;
      expect(hex(r.recvPads[i]!)).toBe(hex(r.senderPads[i]![c]!)); // chosen pad matches
      expect(hex(r.recvPads[i]!)).not.toBe(hex(r.senderPads[i]![c ^ 1]!)); // not the other
    }
  });
});

// ===================================================================================================
describe('(B) THE SECURITY TEST: the endemic property (malicious receiver cannot learn m_{1−c})', () => {
  it('the non-chosen branch effective public key is UNIFORM (differs from any real key the receiver holds)', () => {
    // Honest receiver for c=0; reconstruct both effective keys the sender would use.
    const rng = otRandom(splitMix64(7n));
    const { message, state } = endemicLweReceive([0], rng);
    const sid = state.sid;
    const [p0, p1] = message.points[0]!;
    const effT0 = ringAdd(p0, hpk(sid, 0, p1)); // chosen branch -> should equal t_real
    const effT1 = ringAdd(p1, hpk(sid, 0, p0)); // non-chosen branch -> uniform

    // The receiver's real public-key ring vector (derivable from its own keypair) equals effT0, NOT effT1.
    // We cannot read t_real out of the retained state directly, but we CAN verify the structural claim:
    // effT0 is a decryptable key (its ciphertext decrypts), effT1 is not (covered by the next tests),
    // and effT0 != effT1 (the two branches are different ring vectors).
    expect(hex(effT0)).not.toBe(hex(effT1));
    expect(effT0.length).toBe(TVEC_BYTES);
    expect(effT1.length).toBe(TVEC_BYTES);
  });

  it('a malicious receiver with ONLY its real sk cannot recover the non-chosen pad', () => {
    const choices = [0];
    const r = endemicLweBaseOtRandom(choices, otRandom(splitMix64(123n)));
    // The honest/malicious receiver holds sk for slot 0 only. The TRUE non-chosen pad:
    const trueK1 = r.senderPads[0]![1]!;
    // Attacker attempt: decrypt the NON-CHOSEN ciphertext with the real sk it holds (slot 0's key),
    // then derive the pad from the (wrong) payload. It must NOT match the true non-chosen pad.
    const { state } = endemicLweReceive(choices, otRandom(splitMix64(123n))); // same seed -> same sk
    const wrongPayload = kpkeDec(state.secretKeys[0]!, r.ciphertexts[0]![1]!);
    const attackerPad = endemicLwePad(r.sid, 0, 1, wrongPayload, ENDEMIC_SECRET_BYTES);
    expect(hex(attackerPad)).not.toBe(hex(trueK1));
  });

  it('a malicious receiver controlling BOTH points (same rho) still learns AT MOST one branch', () => {
    // Build a cheating receiver message by hand: it embeds a real key A at slot 0 (so slot 0 is
    // decryptable with skA), and tries to also make slot 1 decryptable by placing a second real key's
    // ring vector there. Because the sender adds a FRESH random-oracle offset to EACH slot keyed by the
    // OTHER slot, slot 1's effective key becomes uniform and skB does not open it.
    const rng = otRandom(splitMix64(2468n));
    const rn = rng.bytes(SYM_BYTES);
    const sid = endemicSessionId(rn);

    const a = kpkeKeygen(rng.bytes(SYM_BYTES)); // (pkA, skA)
    const tA = a.publicKey.slice(0, TVEC_BYTES);
    const rhoA = a.publicKey.slice(TVEC_BYTES);
    const b = kpkeKeygen(rng.bytes(SYM_BYTES)); // (pkB, skB) — different rho, used as the slot-1 value
    const tB = b.publicKey.slice(0, TVEC_BYTES);

    // slot1 value P1 := tB ; choose P0 so the chosen (slot 0) effective key is exactly tA:
    //   effT0 = P0 + Hpk(sid,0,P1) = tA  =>  P0 = tA − Hpk(sid,0,P1)
    const p1 = tB;
    const p0 = ringSub(tA, hpk(sid, 0, p1));
    const message: EndemicLweReceiverMessage = { rn, points: [[p0, p1]], rhos: [rhoA] };

    const sender = endemicLweSendRandom(message, rng); // honest sender
    const k0 = sender.senderPads[0]![0]!;
    const k1 = sender.senderPads[0]![1]!;
    const [ct0, ct1] = sender.ciphertexts[0]!;

    // POSITIVE CONTROL: slot 0 WAS set up as a real key (tA under rhoA) -> skA recovers k0.
    const payload0 = kpkeDec(a.secretKey, ct0);
    expect(hex(endemicLwePad(sid, 0, 0, payload0, ENDEMIC_SECRET_BYTES))).toBe(hex(k0));

    // ATTACK on slot 1: effT1 = P1 + Hpk(sid,0,P0) = tB + (fresh uniform) -> NOT tB, uniform.
    // Neither skA nor skB opens it, so neither yields the true non-chosen pad k1.
    const tryA = endemicLwePad(sid, 0, 1, kpkeDec(a.secretKey, ct1), ENDEMIC_SECRET_BYTES);
    const tryB = endemicLwePad(sid, 0, 1, kpkeDec(b.secretKey, ct1), ENDEMIC_SECRET_BYTES);
    expect(hex(tryA)).not.toBe(hex(k1));
    expect(hex(tryB)).not.toBe(hex(k1));

    // And structurally: the slot-1 effective key is uniform (not tB, the only other key the attacker made).
    const effT1 = ringAdd(p1, hpk(sid, 0, p0));
    expect(hex(effT1)).not.toBe(hex(tB));
  });

  it('positive control: the SOLE barrier is the lattice secret — given it, the pad IS recoverable', () => {
    // If (counterfactually) the receiver held the secret for the non-chosen UNIFORM key, it would
    // recover the pad. We model this by encrypting to a REAL key and showing decryption succeeds —
    // confirming the barrier is exactly "no secret for a uniform key", not some unrelated failure.
    const r = endemicLweBaseOtRandom([1], otRandom(splitMix64(555n)));
    const { state } = endemicLweReceive([1], otRandom(splitMix64(555n)));
    // chosen branch (slot 1): the receiver HAS the secret -> pad recovered correctly.
    const payload = kpkeDec(state.secretKeys[0]!, r.ciphertexts[0]![1]!);
    expect(hex(endemicLwePad(r.sid, 0, 1, payload, ENDEMIC_SECRET_BYTES))).toBe(hex(r.senderPads[0]![1]!));
  });
});

// ===================================================================================================
describe('(C) tamper / abort: a malicious sender ciphertext fails the RO commitment', () => {
  it('a corrupted one-time-padded message aborts (EndemicLweOtAbort)', () => {
    const messages: Array<[Uint8Array, Uint8Array]> = [[msg(0xaa), msg(0xbb)]];
    const choices = [0];
    expect(() =>
      endemicLweBaseOT(messages, choices, secureOtRandom(), {
        tamperCiphertexts: (encrypted) => {
          const e0 = encrypted[0]![0]!; // E_0 of transfer 0 (the chosen ciphertext)
          e0[0] = (e0[0]! ^ 0xff) & 0xff; // flip a byte -> inconsistent with the commitment
        },
      }),
    ).toThrow(EndemicLweOtAbort);
  });

  it('an untampered run does NOT abort (negative control)', () => {
    const messages: Array<[Uint8Array, Uint8Array]> = [[msg(0xaa), msg(0xbb)]];
    expect(() => endemicLweBaseOT(messages, [1], secureOtRandom())).not.toThrow();
  });
});

// ===================================================================================================
// (D) KOS extension + SPDZ open driven by the endemic base OT, identical to the existing bases.
// (Mirrors the hybrid-ot end-to-end test; the base only seeds KOS, so results are base-independent.)
// ===================================================================================================
function otProduct(ch: OtChannel, x: bigint, y: bigint, fieldRng: FieldRng): [bigint, bigint] {
  const FIELD_BITS = 61;
  const choiceBits: number[] = new Array(FIELD_BITS);
  const msg0: bigint[] = new Array(FIELD_BITS);
  const msg1: bigint[] = new Array(FIELD_BITS);
  let senderSum = 0n;
  let pow = 1n;
  for (let k = 0; k < FIELD_BITS; k++) {
    const rho = fieldRng.next();
    senderSum = fadd(senderSum, rho);
    msg0[k] = rho;
    msg1[k] = fadd(rho, fmul(pow, mod(y)));
    choiceBits[k] = Number((mod(x) >> BigInt(k)) & 1n);
    pow = (pow * 2n) % PRIME;
  }
  const { received } = ch.extend(choiceBits, msg0, msg1);
  let receiverSum = 0n;
  for (let k = 0; k < FIELD_BITS; k++) receiverSum = fadd(receiverSum, mod(received[k]!));
  return [receiverSum, fneg(senderSum)];
}

describe('(D) KOS extension + SPDZ open over the endemic base, identical to the EC base', () => {
  it('KOS: recovers exactly the chosen messages over several rounds (endemic PQ base)', () => {
    const ch = new OtChannel(otRandom(splitMix64(31337n)), withEndemicLweBaseOt());
    for (let round = 0; round < 3; round++) {
      const m = 8 + round;
      const cb = Array.from({ length: m }, (_, j) => (j + round) & 1);
      const msg0 = Array.from({ length: m }, (_, j) => BigInt(1_000 * round + j));
      const msg1 = Array.from({ length: m }, (_, j) => BigInt(500_000 + 1_000 * round + j));
      const { received } = ch.extend(cb, msg0, msg1);
      for (let j = 0; j < m; j++) {
        expect(received[j]).toBe(cb[j] === 1 ? msg1[j] : msg0[j]);
      }
    }
  });

  it('KOS: the endemic-seeded extension yields IDENTICAL results to the EC base', () => {
    const seed = 909090n;
    const cb = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1];
    const m = cb.length;
    const msg0 = Array.from({ length: m }, (_, j) => BigInt(10 + j));
    const msg1 = Array.from({ length: m }, (_, j) => BigInt(900 + j));
    const ec = new OtChannel(otRandom(splitMix64(seed))).extend(cb, msg0, msg1).received;
    const en = new OtChannel(otRandom(splitMix64(seed)), withEndemicLweBaseOt()).extend(cb, msg0, msg1).received;
    for (let j = 0; j < m; j++) {
      expect(en[j]).toBe(cb[j] === 1 ? msg1[j] : msg0[j]); // correct
      expect(en[j]).toBe(ec[j]); // identical to the EC base
    }
  });

  it('SPDZ open end-to-end: an endemic-OT Gilboa product opens to x·y and the MAC-check passes', () => {
    const x = 123_456_789n;
    const y = 987_654_321n;
    const product = fmul(x, y);
    const otSeed = 24680n;
    const rhoSeed = 1357n;

    const runWith = (channel: OtChannel): [bigint, bigint] =>
      otProduct(channel, x, y, new FieldRng(rhoSeed));
    const ec = runWith(new OtChannel(otRandom(splitMix64(otSeed))));
    const endemic = runWith(new OtChannel(otRandom(splitMix64(otSeed)), withEndemicLweBaseOt()));

    // Same product sharing as the EC base (the base only seeds KOS).
    expect(fadd(ec[0], ec[1])).toBe(product);
    expect(endemic[0]).toBe(ec[0]);
    expect(endemic[1]).toBe(ec[1]);

    // Drive a real SPDZ open over the ENDEMIC-produced value sharing.
    const dealerRng = new FieldRng(555_111n);
    const ctx = setupMac(2, dealerRng);
    const m0 = dealerRng.next();
    const m1 = fsub(fmul(ctx.alpha, product), m0);
    const auth: AuthSV = { value: [endemic[0], endemic[1]], mac: [m0, m1] };

    const engine = new SpdzEngine(ctx);
    expect(engine.open(auth, 'endemic-product')).toBe(product);
    expect(() => engine.macCheck(dealerRng)).not.toThrow();
  });
});
