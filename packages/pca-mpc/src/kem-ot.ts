/**
 * Post-quantum base OT from ML-KEM — a 1-of-2 oblivious transfer whose hardness rests on Module-LWE
 * (ML-KEM-768, FIPS 203) instead of the curve25519 discrete log. This is the end-game plan's P3
 * ("KEM-based OT from ML-KEM") so the MPC base OT no longer has a classical, quantum-breakable root.
 *
 * ─── THE CONSTRUCTION (be precise and honest) ──────────────────────────────────────────────────────
 * This is the folklore semi-honest 1-of-2 OT from a key-encapsulation mechanism — the "dual-public-key
 * KEM-OT" (closely related to endemic/Masny–Rindal-style OT, but WITHOUT any oblivious-key derivation):
 *
 *   RECEIVER, choice bit c, per transfer:
 *     • generates TWO *real* ML-KEM keypairs, (pk_c, sk_c) and (pk', sk');
 *     • places pk_c at wire index c and pk' at wire index 1−c, and sends the ordered pair (pk_0, pk_1);
 *     • KEEPS sk_c and DISCARDS the other secret sk' (this discard is the whole semi-honest assumption).
 *   SENDER, messages (m_0, m_1), per transfer:
 *     • encapsulates under each received key: (ct_b, ss_b) ← Encaps(pk_b) for b ∈ {0,1};
 *     • one-time-pads each message under a random-oracle key: E_b = m_b ⊕ H(b ‖ ss_b), and sends
 *       (ct_0, E_0), (ct_1, E_1).
 *   RECEIVER recovers ONLY m_c:  ss_c ← Decaps(ct_c, sk_c); m_c = E_c ⊕ H(c ‖ ss_c).
 *   It cannot recover m_{1−c}: it discarded sk_{1−c}, so ss_{1−c} is hidden by ML-KEM IND-CCA security
 *   and H(1−c ‖ ss_{1−c}) is a pseudorandom pad.
 *
 * ─── WHY *THIS* CONSTRUCTION (soundness) ───────────────────────────────────────────────────────────
 * A tempting alternative is an "oblivious public key": derive pk_{1−c} by HASHING some public value so
 * the receiver provably cannot invert it. That is sound for group-based KEMs where a public key is a
 * group element you can hash-to. It is NOT soundly implementable for ML-KEM with the primitive we have:
 * an ML-KEM public key is a structured Module-LWE object (a matrix seed ρ plus t = A·s + e); a hash
 * output is not a valid encapsulation target, and there is no black-box "hash → valid pk whose secret is
 * unknown-to-everyone" for ML-KEM without a trusted setup or a specialised lattice gadget. Rolling one
 * by hand would be exactly the hand-rolled lattice crypto this module forbids. So we use the two-real-
 * keypairs/discard-one-secret variant, which is sound with `ml_kem768` as an opaque IND-CCA KEM.
 *
 * ─── SECURITY MODEL (exactly what is and is not achieved) ──────────────────────────────────────────
 *   • Receiver-choice privacy — UNCONDITIONAL, and holds even against a *malicious* sender. The wire
 *     message (pk_0, pk_1) is two i.i.d. honest ML-KEM public keys; the choice c only decides which
 *     secret the receiver keeps *locally*. The two orderings are therefore identically distributed, so
 *     the sender's view is independent of c with probability 1 (no assumption, no abort needed).
 *   • Sender privacy (receiver learns nothing about m_{1−c}) — SEMI-HONEST only, under ML-KEM IND-CCA
 *     security + H modelled as a random oracle. An honest-but-curious receiver discards sk_{1−c}; given
 *     only pk_{1−c} and ct_{1−c} it cannot distinguish ss_{1−c} from random (IND-CCA), so the pad hides
 *     m_{1−c}. A MALICIOUS receiver that *keeps both* secrets learns BOTH messages — this base OT does
 *     not stop that by itself.
 *   • POST-QUANTUM: both guarantees are PQ. Choice privacy is information-theoretic; sender privacy
 *     rests on Module-LWE (ML-KEM-768, NIST security level ~3) and a hash in the ROM — no classical
 *     discrete-log anywhere, which is the entire point of P3.
 *
 * ─── LIFTING TOWARD MALICIOUS (how this plugs into the stack) ──────────────────────────────────────
 * These base OTs feed the existing KOS OT-extension (`ot.ts`). KOS runs the base OTs with ROLES
 * INVERTED (the extension *sender* is the base *receiver*, holding the secret selector s) and then adds
 * the KOS correlation check over sacrifice rows, which catches an extension receiver that deviates. The
 * malicious surface a semi-honest base OT leaves open — a base receiver keeping both secrets — maps to
 * the extension *sender* learning the extension *receiver*'s seed pairs; KOS's consistency machinery and
 * the correlation-robust hash are what constrain that, exactly as documented for the IKNP/KOS layer.
 * HONEST CAVEAT: a semi-honest base OT does not give a fully malicious base OT on its own; a
 * deployment wanting malicious base security would add a base-OT consistency/commitment round (as the
 * EC `baseOT` wrapper does with its per-message RO commitment). The KOS layer above raises the overall
 * extension to malicious-with-abort against a cheating *extension receiver*, which is the attack IKNP is
 * vulnerable to; see `ot.ts` for that argument.
 *
 * No hand-rolled lattice crypto: all PQ operations go through `ml_kem768` (keygen/encapsulate/
 * decapsulate) as a black box. Randomness follows the module policy — a CSPRNG (`secureOtRandom`) by
 * default, a seeded deterministic stream ONLY when a test passes one.
 */

import { createHash } from 'node:crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { secureOtRandom } from './csprng';
import { type OtChannel, type OtRandom } from './ot';

/** Bytes of fresh randomness fed to ML-KEM keygen (d ‖ z, FIPS 203). */
const KEYGEN_SEED_BYTES = 64;
/** Bytes of fresh randomness fed to ML-KEM encapsulation (the message m, FIPS 203). */
const ENCAPS_MSG_BYTES = ml_kem768.msgLen; // 32

const TAG_KEMOT = new TextEncoder().encode('atlas-pca-mpc/kem-ot-pad');

function sha256(...chunks: Uint8Array[]): Uint8Array {
  const h = createHash('sha256');
  for (const c of chunks) h.update(c);
  return new Uint8Array(h.digest());
}

function u32(x: number): Uint8Array {
  const b = new Uint8Array(4);
  b[0] = (x >>> 24) & 0xff;
  b[1] = (x >>> 16) & 0xff;
  b[2] = (x >>> 8) & 0xff;
  b[3] = x & 0xff;
  return b;
}

/** XOR two equal-length byte arrays into a fresh array. */
function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) throw new Error('kem-ot: XOR length mismatch');
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

/**
 * The random-oracle pad for one slot: `H(TAG ‖ i ‖ b ‖ sharedSecret)` expanded (SHA-256 counter mode)
 * to exactly `len` bytes. `i` binds the transfer index and `b` the slot, so the two pads of one transfer
 * — and the pads across transfers — are domain-separated.
 */
export function kemOtPad(index: number, slot: number, sharedSecret: Uint8Array, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let produced = 0;
  let ctr = 0;
  while (produced < len) {
    const block = sha256(TAG_KEMOT, u32(index), Uint8Array.of(slot & 1), u32(ctr), sharedSecret);
    for (let k = 0; k < block.length && produced < len; k++) out[produced++] = block[k]!;
    ctr++;
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------
// Round-based API (matching ot.ts's in-process, transcript-returning style).
// ---------------------------------------------------------------------------------------------------

/** Receiver round-1 wire message: the ordered public-key pairs the sender encapsulates under. */
export interface KemOtReceiverMessage {
  /** For each transfer i, [pk_0, pk_1]; the chosen key sits at index `choices[i]`. */
  publicKeys: Array<[Uint8Array, Uint8Array]>;
}

/**
 * The receiver's RETAINED state after round 1. An honest receiver keeps ONLY the chosen secret key per
 * transfer (`secretKeys[i]` is `sk_{choices[i]}`); the other secret has been discarded. This is exactly
 * the state the semi-honest model assumes, and the one the tests assert over ("the non-chosen ciphertext
 * does not decrypt under the receiver's state").
 */
export interface KemOtReceiverState {
  /** The choice bits, one per transfer. */
  choices: number[];
  /** The chosen secret key per transfer (sk for slot `choices[i]`); the non-chosen secret is discarded. */
  secretKeys: Uint8Array[];
}

/** Sender round wire message: the two ciphertexts + two padded messages per transfer. */
export interface KemOtSenderMessage {
  /** For each transfer i, the ML-KEM ciphertexts [ct_0, ct_1] under [pk_0, pk_1]. */
  ciphertexts: Array<[Uint8Array, Uint8Array]>;
  /** For each transfer i, the one-time-padded messages [E_0, E_1] = [m_0 ⊕ H(0‖ss_0), m_1 ⊕ H(1‖ss_1)]. */
  encrypted: Array<[Uint8Array, Uint8Array]>;
}

/** A full KEM base-OT transcript (receiver message + sender message), exposed for inspection/tests. */
export interface KemBaseOtTranscript extends KemOtReceiverMessage, KemOtSenderMessage {}

export interface KemBaseOtResult {
  /** Receiver's recovered messages m_{i, choices[i]}. */
  received: Uint8Array[];
  transcript: KemBaseOtTranscript;
}

/**
 * RECEIVER round 1: for each choice bit, generate two real ML-KEM keypairs, send both public keys
 * (chosen one at wire index `c`), and retain only the chosen secret key. Returns the wire message AND
 * the retained receiver state.
 */
export function kemBaseOtReceive(
  choices: number[],
  rng: OtRandom = secureOtRandom(),
): { message: KemOtReceiverMessage; state: KemOtReceiverState } {
  const publicKeys: Array<[Uint8Array, Uint8Array]> = [];
  const secretKeys: Uint8Array[] = [];
  const retainedChoices: number[] = [];
  for (let i = 0; i < choices.length; i++) {
    const c = choices[i]! & 1;
    const chosen = ml_kem768.keygen(rng.bytes(KEYGEN_SEED_BYTES));
    const other = ml_kem768.keygen(rng.bytes(KEYGEN_SEED_BYTES));
    // Place the chosen public key at wire index c; the other at 1−c. The order is the only thing the
    // sender sees, and both keys are i.i.d. honest keygen outputs, so it reveals nothing about c.
    const pk0 = c === 0 ? chosen.publicKey : other.publicKey;
    const pk1 = c === 0 ? other.publicKey : chosen.publicKey;
    publicKeys.push([pk0, pk1]);
    // Keep only the chosen secret; `other.secretKey` is deliberately dropped (never stored).
    secretKeys.push(chosen.secretKey);
    retainedChoices.push(c);
  }
  return { message: { publicKeys }, state: { choices: retainedChoices, secretKeys } };
}

/**
 * SENDER round: encapsulate under each received public key and one-time-pad each message under
 * `H(slot ‖ sharedSecret)`. `messages[i] = [m_0, m_1]`; the two messages of one transfer must be equal
 * length (padding is derived to that length). Returns the sender wire message.
 */
export function kemBaseOtSend(
  messages: Array<[Uint8Array, Uint8Array]>,
  receiverMessage: KemOtReceiverMessage,
  rng: OtRandom = secureOtRandom(),
): KemOtSenderMessage {
  const { publicKeys } = receiverMessage;
  if (messages.length !== publicKeys.length) {
    throw new Error('kemBaseOtSend: messages/publicKeys length mismatch');
  }
  const ciphertexts: Array<[Uint8Array, Uint8Array]> = [];
  const encrypted: Array<[Uint8Array, Uint8Array]> = [];
  for (let i = 0; i < messages.length; i++) {
    const [m0, m1] = messages[i]!;
    if (m0.length !== m1.length) {
      throw new Error(`kemBaseOtSend (index ${i}): the two messages must be equal length`);
    }
    const [pk0, pk1] = publicKeys[i]!;
    // ml_kem768.encapsulate derandomised with fresh bytes so a seeded test stays reproducible.
    const e0 = ml_kem768.encapsulate(pk0, rng.bytes(ENCAPS_MSG_BYTES));
    const e1 = ml_kem768.encapsulate(pk1, rng.bytes(ENCAPS_MSG_BYTES));
    ciphertexts.push([e0.cipherText, e1.cipherText]);
    encrypted.push([
      xorBytes(m0, kemOtPad(i, 0, e0.sharedSecret, m0.length)),
      xorBytes(m1, kemOtPad(i, 1, e1.sharedSecret, m1.length)),
    ]);
  }
  return { ciphertexts, encrypted };
}

/**
 * RECEIVER recovery: decapsulate ONLY the chosen ciphertext with the retained secret key and unmask the
 * chosen message. The receiver never touches the non-chosen slot (it has no secret for it). Returns
 * `received[i] = m_{i, choices[i]}`.
 */
export function kemBaseOtOpen(
  state: KemOtReceiverState,
  senderMessage: KemOtSenderMessage,
): Uint8Array[] {
  const { choices, secretKeys } = state;
  const { ciphertexts, encrypted } = senderMessage;
  if (ciphertexts.length !== choices.length || encrypted.length !== choices.length) {
    throw new Error('kemBaseOtOpen: transcript/state length mismatch');
  }
  const received: Uint8Array[] = [];
  for (let i = 0; i < choices.length; i++) {
    const c = choices[i]! & 1;
    const ss = ml_kem768.decapsulate(ciphertexts[i]![c]!, secretKeys[i]!);
    const e = encrypted[i]![c]!;
    received.push(xorBytes(e, kemOtPad(i, c, ss, e.length)));
  }
  return received;
}

/**
 * In-process combined simulator (both parties in one call), matching the shape of `baseOT` in `ot.ts`:
 * run `count = choices.length` KEM base OTs and return the receiver's recovered messages plus the full
 * transcript. This is the drop-in the KOS extension consumes (see `OtChannel`'s `baseOtFn` option).
 */
export function kemBaseOT(
  messages: Array<[Uint8Array, Uint8Array]>,
  choices: number[],
  rng: OtRandom = secureOtRandom(),
): KemBaseOtResult {
  if (messages.length !== choices.length) {
    throw new Error('kemBaseOT: messages/choices length mismatch');
  }
  const { message: receiverMessage, state } = kemBaseOtReceive(choices, rng);
  const senderMessage = kemBaseOtSend(messages, receiverMessage, rng);
  const received = kemBaseOtOpen(state, senderMessage);
  return {
    received,
    transcript: {
      publicKeys: receiverMessage.publicKeys,
      ciphertexts: senderMessage.ciphertexts,
      encrypted: senderMessage.encrypted,
    },
  };
}

/**
 * Wire the ML-KEM base OT into the existing KOS OT-extension: returns the constructor option bag for
 * `OtChannel` that makes it run its κ setup base OTs over `kemBaseOT` (post-quantum) instead of the
 * classical EC Chou–Orlandi `baseOT`. Everything above the base OT (the IKNP matrix, the KOS correlation
 * check, the correlation-robust hash) is unchanged.
 *
 *   const ch = new OtChannel(secureOtRandom(), withKemBaseOt());
 */
export function withKemBaseOt(): ConstructorParameters<typeof OtChannel>[1] {
  return { baseOtFn: kemBaseOT };
}
