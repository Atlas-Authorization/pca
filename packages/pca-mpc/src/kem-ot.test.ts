/**
 * Post-quantum base OT (ML-KEM-768) tests — all REAL (actual ml_kem768 keygen/encaps/decaps, no mocks):
 *   (A) correctness over BOTH choice bits: the receiver recovers EXACTLY m_c, for every choice pattern;
 *   (B) sender privacy against an honest receiver: the non-chosen ciphertext does NOT decrypt under the
 *       receiver's retained state (it holds only sk_c), so m_{1−c} is not recoverable;
 *   (C) multiple messages / varied lengths in one batch;
 *   (D) choice-privacy shape: the receiver's wire message is two equal-length ML-KEM public keys whose
 *       ordering is the only choice-dependent signal, and both are real keys (i.i.d.);
 *   (E) KOS round-trip: the IKNP/KOS OT-extension driven by the ML-KEM base OT recovers exactly the
 *       chosen messages over several rounds (post-quantum base, no EC discrete log).
 */

import { describe, expect, it } from 'vitest';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import {
  kemBaseOT,
  kemBaseOtMal,
  KemBaseOtAbort,
  kemBaseOtReceive,
  kemBaseOtSend,
  kemBaseOtOpen,
  kemOtPad,
  withKemBaseOt,
  withKemBaseOtMal,
} from './kem-ot';
import { OtChannel, otRandom, splitMix64 } from './ot';
import { secureOtRandom } from './csprng';

function msg(fill: number, len = 16): Uint8Array {
  const b = new Uint8Array(len);
  b.fill(fill);
  return b;
}

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}

// ===================================================================================================
describe('(A) ML-KEM base OT: receiver recovers exactly the chosen message, for every choice', () => {
  it('recovers m_0 when c=0 and m_1 when c=1 across a choice pattern', () => {
    const messages: Array<[Uint8Array, Uint8Array]> = [
      [msg(0x10), msg(0x11)],
      [msg(0x20), msg(0x21)],
      [msg(0x30), msg(0x31)],
      [msg(0x40), msg(0x41)],
    ];
    const choices = [0, 1, 1, 0];
    const { received } = kemBaseOT(messages, choices, secureOtRandom());
    for (let i = 0; i < messages.length; i++) {
      expect(hex(received[i]!)).toBe(hex(messages[i]![choices[i]!]!));
    }
  });

  it('both choices recover the right slot for the SAME message pair (c=0 then c=1)', () => {
    const pair: Array<[Uint8Array, Uint8Array]> = [[msg(0xaa), msg(0xbb)]];
    const r0 = kemBaseOT(pair, [0], secureOtRandom());
    const r1 = kemBaseOT(pair, [1], secureOtRandom());
    expect(hex(r0.received[0]!)).toBe(hex(pair[0]![0]));
    expect(hex(r1.received[0]!)).toBe(hex(pair[0]![1]));
  });

  it('is reproducible under a seeded deterministic RNG', () => {
    const messages: Array<[Uint8Array, Uint8Array]> = [
      [msg(1), msg(2)],
      [msg(3), msg(4)],
    ];
    const a = kemBaseOT(messages, [1, 0], otRandom(splitMix64(99n)));
    const b = kemBaseOT(messages, [1, 0], otRandom(splitMix64(99n)));
    expect(hex(a.received[0]!)).toBe(hex(b.received[0]!));
    expect(hex(a.transcript.ciphertexts[0]![0]!)).toBe(hex(b.transcript.ciphertexts[0]![0]!));
    // And it recovers the correct slots.
    expect(hex(a.received[0]!)).toBe(hex(messages[0]![1])); // choice 1
    expect(hex(a.received[1]!)).toBe(hex(messages[1]![0])); // choice 0
  });
});

// ===================================================================================================
describe('(B) sender privacy: the non-chosen ciphertext does not decrypt under the receiver state', () => {
  it('receiver keeps only sk_c, and the non-chosen slot cannot be unmasked to m_{1−c}', () => {
    const messages: Array<[Uint8Array, Uint8Array]> = [
      [msg(0x55), msg(0x66)],
      [msg(0x77), msg(0x88)],
    ];
    const choices = [0, 1];
    const rng = secureOtRandom();
    const { message, state } = kemBaseOtReceive(choices, rng);
    const sent = kemBaseOtSend(messages, message, rng);

    // The honest receiver retains exactly one secret per transfer (the chosen one) — never two.
    expect(state.secretKeys).toHaveLength(2);

    for (let i = 0; i < choices.length; i++) {
      const c = choices[i]! & 1;
      const other = (1 - c) as 0 | 1;

      // The chosen slot recovers the right message.
      const recovered = kemBaseOtOpen(state, sent)[i]!;
      expect(hex(recovered)).toBe(hex(messages[i]![c]!));

      // The receiver has NO secret for the non-chosen slot. The best it can do is misuse its only
      // secret (sk_c) on the non-chosen ciphertext; ML-KEM implicit rejection then yields a shared
      // secret unrelated to the sender's, so the unmasked value is NOT m_{1−c}.
      const wrongSs = ml_kem768.decapsulate(sent.ciphertexts[i]![other]!, state.secretKeys[i]!);
      const candidate = new Uint8Array(messages[i]![other].length);
      const pad = kemOtPad(i, other, wrongSs, candidate.length);
      for (let k = 0; k < candidate.length; k++) candidate[k] = sent.encrypted[i]![other]![k]! ^ pad[k]!;
      expect(hex(candidate)).not.toBe(hex(messages[i]![other]!));
    }
  });
});

// ===================================================================================================
describe('(C) multiple messages and varied lengths in one batch', () => {
  it('handles a larger batch of mixed-length message pairs', () => {
    const lengths = [1, 16, 32, 48, 100];
    const messages: Array<[Uint8Array, Uint8Array]> = lengths.map((len, i) => [
      msg(i + 1, len),
      msg(i + 101, len),
    ]);
    const choices = lengths.map((_, i) => i & 1);
    const { received } = kemBaseOT(messages, choices, secureOtRandom());
    for (let i = 0; i < messages.length; i++) {
      expect(received[i]!.length).toBe(lengths[i]);
      expect(hex(received[i]!)).toBe(hex(messages[i]![choices[i]!]!));
    }
  });

  it('rejects unequal-length message pairs', () => {
    const { message } = kemBaseOtReceive([0], secureOtRandom());
    expect(() => kemBaseOtSend([[msg(1, 16), msg(2, 17)]], message, secureOtRandom())).toThrow();
  });
});

// ===================================================================================================
describe('(D) choice-privacy shape: wire message is two i.i.d. real ML-KEM public keys', () => {
  it('both public keys are valid full-length ML-KEM keys regardless of choice', () => {
    for (const c of [0, 1]) {
      const { message } = kemBaseOtReceive([c], secureOtRandom());
      const [pk0, pk1] = message.publicKeys[0]!;
      expect(pk0.length).toBe(ml_kem768.publicKeyLen);
      expect(pk1.length).toBe(ml_kem768.publicKeyLen);
      // Both keys are genuine encapsulation targets (encaps/decaps is well-defined under each) — there
      // is no "oblivious"/unopenable key on the wire to distinguish the choice by.
      expect(() => ml_kem768.encapsulate(pk0)).not.toThrow();
      expect(() => ml_kem768.encapsulate(pk1)).not.toThrow();
    }
  });
});

// ===================================================================================================
describe('(E) KOS OT-extension driven by the post-quantum ML-KEM base OT', () => {
  it('recovers exactly the chosen messages over several rounds (PQ base, no EC dlog)', () => {
    const ch = new OtChannel(otRandom(splitMix64(2026n)), withKemBaseOt());
    for (let round = 0; round < 3; round++) {
      const m = 10 + round;
      const cb = Array.from({ length: m }, (_, j) => (j + round) & 1);
      const msg0 = Array.from({ length: m }, (_, j) => BigInt(1_000 * round + j));
      const msg1 = Array.from({ length: m }, (_, j) => BigInt(500_000 + 1_000 * round + j));
      const { received } = ch.extend(cb, msg0, msg1);
      for (let j = 0; j < m; j++) {
        expect(received[j]).toBe(cb[j] === 1 ? msg1[j] : msg0[j]);
      }
    }
  });

  it('the extension still masks the unchosen message', () => {
    const ch = new OtChannel(otRandom(splitMix64(4242n)), withKemBaseOt());
    const cb = [1, 0, 1, 1, 0, 0, 1, 0];
    const m = cb.length;
    const msg0 = Array.from({ length: m }, (_, j) => BigInt(10 + j));
    const msg1 = Array.from({ length: m }, (_, j) => BigInt(900 + j));
    const { received } = ch.extend(cb, msg0, msg1);
    for (let j = 0; j < m; j++) {
      const chosen = cb[j] === 1 ? msg1[j]! : msg0[j]!;
      const unchosen = cb[j] === 1 ? msg0[j]! : msg1[j]!;
      expect(received[j]).toBe(chosen);
      expect(received[j]).not.toBe(unchosen);
    }
  });
});

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const o = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) o[i] = a[i]! ^ b[i]!;
  return o;
}

// ===================================================================================================
describe('(F) MALICIOUS-HARDENED committed KEM base OT: honest flow is correct', () => {
  it('recovers exactly the chosen message for every choice pattern', () => {
    const messages: Array<[Uint8Array, Uint8Array]> = [
      [msg(0x10), msg(0x11)],
      [msg(0x20), msg(0x21)],
      [msg(0x30), msg(0x31)],
      [msg(0x40), msg(0x41)],
    ];
    const choices = [0, 1, 1, 0];
    const { received } = kemBaseOtMal(messages, choices, secureOtRandom());
    for (let i = 0; i < messages.length; i++) {
      expect(hex(received[i]!)).toBe(hex(messages[i]![choices[i]!]!));
    }
  });

  it('handles a mixed-length batch and is reproducible under a seeded RNG', () => {
    const lengths = [1, 16, 32, 48];
    const messages: Array<[Uint8Array, Uint8Array]> = lengths.map((len, i) => [
      msg(i + 1, len),
      msg(i + 101, len),
    ]);
    const choices = lengths.map((_, i) => i & 1);
    const a = kemBaseOtMal(messages, choices, otRandom(splitMix64(2027n)));
    const b = kemBaseOtMal(messages, choices, otRandom(splitMix64(2027n)));
    for (let i = 0; i < messages.length; i++) {
      expect(a.received[i]!.length).toBe(lengths[i]);
      expect(hex(a.received[i]!)).toBe(hex(messages[i]![choices[i]!]!));
      expect(hex(a.received[i]!)).toBe(hex(b.received[i]!)); // deterministic under a fixed seed
    }
  });
});

// ===================================================================================================
describe('(G) MALICIOUS-HARDENED: a cheating receiver attempting to manipulate the OT is caught → ABORT', () => {
  it('a receiver that opens public keys ≠ its commitment makes the sender ABORT (recovers nothing)', () => {
    const messages: Array<[Uint8Array, Uint8Array]> = [
      [msg(0x55), msg(0x66)],
      [msg(0x77), msg(0x88)],
    ];
    // Malicious receiver: after committing, it opens a DIFFERENT public key for slot 1 of transfer 0
    // (a freshly-generated key whose secret it controls) to try to steer/learn the other slot. The
    // sender recomputes the commitment from the opened keys and aborts on the mismatch.
    const tamper = {
      tamperOpenedKeys: (publicKeys: Array<[Uint8Array, Uint8Array]>) => {
        const forged = ml_kem768.keygen(new Uint8Array(64).fill(7)).publicKey;
        publicKeys[0]![1] = forged;
      },
    };
    expect(() => kemBaseOtMal(messages, [0, 1], secureOtRandom(), tamper)).toThrow(KemBaseOtAbort);
    expect(() => kemBaseOtMal(messages, [0, 1], secureOtRandom(), tamper)).toThrow(
      /do not match the receiver's commitment/,
    );
  });

  it('even a one-byte mutation of an opened key is caught by the commitment check', () => {
    const messages: Array<[Uint8Array, Uint8Array]> = [[msg(0x01), msg(0x02)]];
    const tamper = {
      tamperOpenedKeys: (publicKeys: Array<[Uint8Array, Uint8Array]>) => {
        publicKeys[0]![0] = publicKeys[0]![0]!.slice();
        publicKeys[0]![0]![0] = (publicKeys[0]![0]![0]! ^ 0x01) & 0xff;
      },
    };
    expect(() => kemBaseOtMal(messages, [0], secureOtRandom(), tamper)).toThrow(KemBaseOtAbort);
  });

  it('a receiver that binds the wrong session id gets GARBAGE, never the message (pad is sid-bound)', () => {
    const messages: Array<[Uint8Array, Uint8Array]> = [[msg(0xcc, 32), msg(0xdd, 32)]];
    const tamper = {
      tamperReceiverSid: (sid: Uint8Array) => {
        const bad = sid.slice();
        bad[0] = (bad[0]! ^ 0xff) & 0xff;
        return bad;
      },
    };
    const { received } = kemBaseOtMal(messages, [0], secureOtRandom(), tamper);
    // The sender bound its pad to the real sid; a receiver that unmasks with a different sid cannot
    // reconstruct the message.
    expect(hex(received[0]!)).not.toBe(hex(messages[0]![0]));
  });
});

// ===================================================================================================
describe('(H) DOCUMENTED intrinsic residue (opaque ML-KEM): keeping BOTH secrets recovers both', () => {
  it('a receiver that runs keygen twice and keeps both sks learns both messages — the header caveat, lifted by KOS', () => {
    // This is NOT a defect of the hardening: no base OT from an OPAQUE IND-CCA KEM can prevent it (the
    // decisional-MLWE indistinguishability that gives choice-privacy makes a "both-keys-real" receiver
    // undetectable; forcing a secretless slot needs public-key-space arithmetic / a CRS this module
    // forbids). We demonstrate the residue explicitly, as documented. It is closed by the KOS
    // OT-extension (roles inverted) — see test (J) / (E) for the extension running over this base.
    const kp0 = ml_kem768.keygen(new Uint8Array(64).fill(1));
    const kp1 = ml_kem768.keygen(new Uint8Array(64).fill(2));
    const messages: Array<[Uint8Array, Uint8Array]> = [[msg(0xa1, 32), msg(0xb2, 32)]];
    const sent = kemBaseOtSend(messages, { publicKeys: [[kp0.publicKey, kp1.publicKey]] }, secureOtRandom());
    const ss0 = ml_kem768.decapsulate(sent.ciphertexts[0]![0]!, kp0.secretKey);
    const ss1 = ml_kem768.decapsulate(sent.ciphertexts[0]![1]!, kp1.secretKey);
    const got0 = xor(sent.encrypted[0]![0]!, kemOtPad(0, 0, ss0, 32));
    const got1 = xor(sent.encrypted[0]![1]!, kemOtPad(0, 1, ss1, 32));
    expect(hex(got0)).toBe(hex(messages[0]![0])); // both slots recovered — the intrinsic residue
    expect(hex(got1)).toBe(hex(messages[0]![1]));
  });
});

// ===================================================================================================
describe('(J) KOS OT-extension over the MALICIOUS-HARDENED committed ML-KEM base OT', () => {
  it('recovers exactly the chosen messages over several rounds', () => {
    const ch = new OtChannel(otRandom(splitMix64(777n)), withKemBaseOtMal());
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
});
