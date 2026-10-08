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
 * ─── MALICIOUS-RECEIVER HARDENING (`kemBaseOtMal`, below) ──────────────────────────────────────────
 * The semi-honest base OT above leaves two malicious-receiver surfaces. The committed variant
 * `kemBaseOtMal` closes the one that CAN be closed from an opaque KEM, and documents — precisely,
 * rather than faking a defence — the one that cannot:
 *
 *   CLOSED (by an RO-commitment + session binding, mirroring the EC `baseOT`'s commit round):
 *     • ADAPTIVE / MALLEABLE / REPLAYED key material. The receiver first sends only a RO-commitment
 *       `com = H(rn ‖ pk_0 ‖ pk_1)` to its ordered public keys (and a receiver nonce `rn`); the sender
 *       replies with a fresh nonce `sn`; the parties set `sid = H(rn ‖ sn)`; only THEN does the receiver
 *       open `(pk_0, pk_1)` and the sender encapsulate, binding every pad to `(sid, com)`. The sender
 *       recomputes `com` from the opened keys and ABORTS on any mismatch. So the receiver must fix its
 *       keys BEFORE it learns `sn` (no adaptive/precomputed/related-key choice, no cross-session replay),
 *       and cannot open keys other than the ones it committed to — exactly the non-malleability the EC
 *       base OT gets from `R` being a single committed group element.
 *
 *   NOT CLOSABLE from an OPAQUE ML-KEM, and WHY (an impossibility, not a shortcut):
 *     • A receiver that simply runs keygen TWICE and keeps BOTH secret keys learns both messages. To
 *       stop it the protocol would have to force one slot to a public key whose secret NOBODY knows
 *       (the Masny–Rindal "endemic OT" idea: `pk_{1−c}` derived in the public-key space from a random
 *       oracle / a common reference). That needs either (i) sampling / adding in ML-KEM's structured
 *       public-key space — reaching into the Module-LWE internals this module forbids (no hand-rolled
 *       lattice crypto), or (ii) a trusted setup / CRS. Crucially, the SAME decisional-Module-LWE
 *       indistinguishability that makes choice privacy hold (a real `pk` ≈ a uniform one) is what makes
 *       a cheating "both-keys-real" receiver UNDETECTABLE to the sender: it cannot tell a secretless
 *       slot from a real one. So this residue is intrinsic to the opaque primitive.
 *
 * ─── LIFTING THE RESIDUE (how this plugs into the stack) ───────────────────────────────────────────
 * The residue is closed exactly where the EC stack closes its analogue: the KOS OT-extension (`ot.ts`).
 * KOS runs the base OTs with ROLES INVERTED (the extension *sender* is the base *receiver*, holding the
 * secret selector s) and adds the correlation check over sacrifice rows. A base receiver keeping both
 * secrets maps to the extension *sender* learning the extension *receiver*'s seed pairs; the KOS
 * consistency machinery + correlation-robust hash constrain that, raising the overall extension to
 * malicious-with-abort against a cheating extension receiver — the attack IKNP is vulnerable to. So
 * `kemBaseOtMal` is the right base layer: it hardens everything the opaque KEM allows (commitment /
 * binding), and defers only the intrinsic residue to the layer that already handles it.
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

// ===================================================================================================
// MALICIOUS-RECEIVER HARDENING: the committed, session-bound KEM base OT (`kemBaseOtMal`).
//
// See the module header for the exact security model. In one line: an RO-commitment to the ordered
// public keys + a two-nonce session id bind the receiver's key material (commit-BEFORE the sender's
// nonce, open AFTER), and the sender aborts if the opened keys do not match the commitment — closing
// the adaptive / malleable / replay surfaces. The intrinsic "keep both secrets" residue is deferred to
// the KOS extension, as the header and tests document.
// ===================================================================================================

const TAG_KEMOT_COMMIT = new TextEncoder().encode('atlas-pca-mpc/kem-ot-commit');
const TAG_KEMOT_SID = new TextEncoder().encode('atlas-pca-mpc/kem-ot-sid');
const TAG_KEMOT_MALPAD = new TextEncoder().encode('atlas-pca-mpc/kem-ot-mal-pad');

/** Bytes of a protocol nonce (receiver `rn`, sender `sn`). */
const NONCE_BYTES = 32;

/** Raised when the committed KEM base OT aborts: a cheating receiver (opened keys ≠ commitment) is caught. */
export class KemBaseOtAbort extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KemBaseOtAbort';
  }
}

/** The RO-commitment to one transfer's ordered public keys, bound to the receiver nonce `rn`. */
function kemMalCommit(rn: Uint8Array, index: number, pk0: Uint8Array, pk1: Uint8Array): Uint8Array {
  return sha256(TAG_KEMOT_COMMIT, rn, u32(index), pk0, pk1);
}

/** The session id `sid = H(TAG ‖ rn ‖ sn)` — both parties' nonces, so neither alone fixes it. */
function kemMalSid(rn: Uint8Array, sn: Uint8Array): Uint8Array {
  return sha256(TAG_KEMOT_SID, rn, sn);
}

/**
 * The malicious-variant RO pad: `H(TAG ‖ sid ‖ com ‖ i ‖ slot ‖ ss)` expanded to `len` bytes. Binding
 * the pad to `(sid, com)` ties the sender's encryption to the exact committed keys and this session, so
 * a receiver that opens different keys (or replays another session) cannot unmask the message.
 */
function kemOtMalPad(
  sid: Uint8Array,
  com: Uint8Array,
  index: number,
  slot: number,
  sharedSecret: Uint8Array,
  len: number,
): Uint8Array {
  const out = new Uint8Array(len);
  let produced = 0;
  let ctr = 0;
  while (produced < len) {
    const block = sha256(
      TAG_KEMOT_MALPAD,
      sid,
      com,
      u32(index),
      Uint8Array.of(slot & 1),
      u32(ctr),
      sharedSecret,
    );
    for (let k = 0; k < block.length && produced < len; k++) out[produced++] = block[k]!;
    ctr++;
  }
  return out;
}

/** Receiver round-1 message: a nonce + the per-transfer commitments (public keys NOT yet revealed). */
export interface KemMalCommitMessage {
  /** Receiver nonce `rn`, bound into every commitment and into `sid`. */
  rn: Uint8Array;
  /** Per-transfer RO-commitment `com_i = H(rn ‖ i ‖ pk_0 ‖ pk_1)`. */
  commitments: Uint8Array[];
}

/** Receiver round-3 message: the opening of the committed public keys. */
export interface KemMalOpenMessage {
  /** For each transfer i, the ordered public keys `[pk_0, pk_1]` the sender encapsulates under. */
  publicKeys: Array<[Uint8Array, Uint8Array]>;
}

/** Sender round-2 message: the sender nonce `sn` completing the session id. */
export interface KemMalSenderNonce {
  sn: Uint8Array;
}

/** Sender round-4 message: ciphertexts + `(sid, com)`-bound padded messages. */
export interface KemMalSenderMessage {
  ciphertexts: Array<[Uint8Array, Uint8Array]>;
  encrypted: Array<[Uint8Array, Uint8Array]>;
}

/** The receiver's retained state across the committed flow. */
export interface KemMalReceiverState {
  choices: number[];
  /** The chosen secret key per transfer (`sk_{choices[i]}`); the non-chosen secret is discarded. */
  secretKeys: Uint8Array[];
  /** The ordered public keys (opened in round 3). */
  publicKeys: Array<[Uint8Array, Uint8Array]>;
  rn: Uint8Array;
}

/** A full committed KEM base-OT transcript, exposed for inspection/tests. */
export interface KemMalTranscript
  extends KemMalCommitMessage,
    KemMalOpenMessage,
    KemMalSenderNonce,
    KemMalSenderMessage {}

export interface KemBaseOtMalResult {
  received: Uint8Array[];
  transcript: KemMalTranscript;
}

/**
 * TEST-ONLY injection points modelling a malicious RECEIVER in the committed flow. Each hook mutates a
 * value exactly where it crosses the wire, so the honest sender's checks run against the adversarial
 * value.
 */
export interface KemMalTamper {
  /** Malicious receiver: open public keys DIFFERENT from the committed ones (→ sender abort). */
  tamperOpenedKeys?: (publicKeys: Array<[Uint8Array, Uint8Array]>) => void;
  /** Malicious receiver/MITM: tamper the sender nonce the receiver binds `sid` with (→ pad mismatch). */
  tamperReceiverSid?: (sid: Uint8Array) => Uint8Array;
}

/**
 * RECEIVER round 1: generate the keypairs (keeping only the chosen secret), draw a nonce `rn`, and send
 * only the COMMITMENTS to the ordered public keys. Returns the round-1 wire message plus the retained
 * state (which holds the not-yet-revealed public keys for the round-3 opening).
 */
export function kemBaseOtMalCommit(
  choices: number[],
  rng: OtRandom = secureOtRandom(),
): { message: KemMalCommitMessage; state: KemMalReceiverState } {
  const rn = rng.bytes(NONCE_BYTES);
  const publicKeys: Array<[Uint8Array, Uint8Array]> = [];
  const secretKeys: Uint8Array[] = [];
  const retainedChoices: number[] = [];
  const commitments: Uint8Array[] = [];
  for (let i = 0; i < choices.length; i++) {
    const c = choices[i]! & 1;
    const chosen = ml_kem768.keygen(rng.bytes(KEYGEN_SEED_BYTES));
    const other = ml_kem768.keygen(rng.bytes(KEYGEN_SEED_BYTES));
    const pk0 = c === 0 ? chosen.publicKey : other.publicKey;
    const pk1 = c === 0 ? other.publicKey : chosen.publicKey;
    publicKeys.push([pk0, pk1]);
    secretKeys.push(chosen.secretKey);
    retainedChoices.push(c);
    commitments.push(kemMalCommit(rn, i, pk0, pk1));
  }
  return {
    message: { rn, commitments },
    state: { choices: retainedChoices, secretKeys, publicKeys, rn },
  };
}

/** SENDER round 2: draw the sender nonce `sn` completing the session id. */
export function kemBaseOtMalSenderNonce(rng: OtRandom = secureOtRandom()): KemMalSenderNonce {
  return { sn: rng.bytes(NONCE_BYTES) };
}

/** RECEIVER round 3: open the committed public keys (the sender will re-check them against `com`). */
export function kemBaseOtMalOpen(state: KemMalReceiverState): KemMalOpenMessage {
  return { publicKeys: state.publicKeys.map(([a, b]) => [a, b] as [Uint8Array, Uint8Array]) };
}

/**
 * SENDER round 4: VERIFY the opened keys against the round-1 commitments (ABORT on mismatch), then
 * encapsulate under each and one-time-pad each message with a `(sid, com)`-bound pad.
 */
export function kemBaseOtMalSend(
  messages: Array<[Uint8Array, Uint8Array]>,
  commit: KemMalCommitMessage,
  senderNonce: KemMalSenderNonce,
  opening: KemMalOpenMessage,
  rng: OtRandom = secureOtRandom(),
): KemMalSenderMessage {
  const { rn, commitments } = commit;
  const { publicKeys } = opening;
  if (messages.length !== publicKeys.length || commitments.length !== publicKeys.length) {
    throw new Error('kemBaseOtMalSend: messages/commitments/publicKeys length mismatch');
  }
  const sid = kemMalSid(rn, senderNonce.sn);
  const ciphertexts: Array<[Uint8Array, Uint8Array]> = [];
  const encrypted: Array<[Uint8Array, Uint8Array]> = [];
  for (let i = 0; i < messages.length; i++) {
    const [m0, m1] = messages[i]!;
    if (m0.length !== m1.length) {
      throw new Error(`kemBaseOtMalSend (index ${i}): the two messages must be equal length`);
    }
    const [pk0, pk1] = publicKeys[i]!;
    // The binding check: the opened keys MUST reproduce the round-1 commitment, else a cheating
    // receiver swapped/adapted its keys after learning the sender nonce → ABORT.
    const com = kemMalCommit(rn, i, pk0, pk1);
    if (!constTimeEqual(com, commitments[i]!)) {
      throw new KemBaseOtAbort(
        `kem base OT (index ${i}): opened public keys do not match the receiver's commitment; aborting`,
      );
    }
    const e0 = ml_kem768.encapsulate(pk0, rng.bytes(ENCAPS_MSG_BYTES));
    const e1 = ml_kem768.encapsulate(pk1, rng.bytes(ENCAPS_MSG_BYTES));
    ciphertexts.push([e0.cipherText, e1.cipherText]);
    encrypted.push([
      xorBytes(m0, kemOtMalPad(sid, com, i, 0, e0.sharedSecret, m0.length)),
      xorBytes(m1, kemOtMalPad(sid, com, i, 1, e1.sharedSecret, m1.length)),
    ]);
  }
  return { ciphertexts, encrypted };
}

/**
 * RECEIVER round 5: decapsulate ONLY the chosen ciphertext and unmask with the `(sid, com)`-bound pad.
 */
export function kemBaseOtMalRecover(
  state: KemMalReceiverState,
  senderNonce: KemMalSenderNonce,
  senderMessage: KemMalSenderMessage,
  tamper?: KemMalTamper,
): Uint8Array[] {
  const { choices, secretKeys, publicKeys, rn } = state;
  const { ciphertexts, encrypted } = senderMessage;
  if (ciphertexts.length !== choices.length || encrypted.length !== choices.length) {
    throw new Error('kemBaseOtMalRecover: transcript/state length mismatch');
  }
  let sid = kemMalSid(rn, senderNonce.sn);
  if (tamper?.tamperReceiverSid) sid = tamper.tamperReceiverSid(sid);
  const received: Uint8Array[] = [];
  for (let i = 0; i < choices.length; i++) {
    const c = choices[i]! & 1;
    const [pk0, pk1] = publicKeys[i]!;
    const com = kemMalCommit(rn, i, pk0, pk1);
    const ss = ml_kem768.decapsulate(ciphertexts[i]![c]!, secretKeys[i]!);
    const e = encrypted[i]![c]!;
    received.push(xorBytes(e, kemOtMalPad(sid, com, i, c, ss, e.length)));
  }
  return received;
}

/** Constant-time byte-equality (both the commitment check and length check in one place). */
function constTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * In-process combined simulator for the MALICIOUS-HARDENED committed KEM base OT, matching the shape of
 * `kemBaseOT` so it is a drop-in for `OtChannel`'s `baseOtFn` (`withKemBaseOtMal`). Runs all five
 * rounds; a cheating receiver (opened keys ≠ commitment) makes the sender throw `KemBaseOtAbort`. The
 * `tamper` hook injects malicious-receiver behaviour for tests.
 */
export function kemBaseOtMal(
  messages: Array<[Uint8Array, Uint8Array]>,
  choices: number[],
  rng: OtRandom = secureOtRandom(),
  tamper?: KemMalTamper,
): KemBaseOtMalResult {
  if (messages.length !== choices.length) {
    throw new Error('kemBaseOtMal: messages/choices length mismatch');
  }
  const { message: commit, state } = kemBaseOtMalCommit(choices, rng);
  const senderNonce = kemBaseOtMalSenderNonce(rng);
  const opening = kemBaseOtMalOpen(state);
  // A malicious receiver may open keys OTHER than those it committed to (test-injected).
  if (tamper?.tamperOpenedKeys) tamper.tamperOpenedKeys(opening.publicKeys);
  const senderMessage = kemBaseOtMalSend(messages, commit, senderNonce, opening, rng);
  const received = kemBaseOtMalRecover(state, senderNonce, senderMessage, tamper);
  return {
    received,
    transcript: {
      rn: commit.rn,
      commitments: commit.commitments,
      sn: senderNonce.sn,
      publicKeys: opening.publicKeys,
      ciphertexts: senderMessage.ciphertexts,
      encrypted: senderMessage.encrypted,
    },
  };
}

/**
 * Wire the MALICIOUS-HARDENED committed ML-KEM base OT into the KOS OT-extension — the recommended
 * post-quantum base. Like `withKemBaseOt`, but the κ setup base OTs run the committed/session-bound
 * protocol (and abort on a cheating receiver). Everything above the base OT is unchanged.
 *
 *   const ch = new OtChannel(secureOtRandom(), withKemBaseOtMal());
 */
export function withKemBaseOtMal(): ConstructorParameters<typeof OtChannel>[1] {
  return { baseOtFn: (m, c, r) => kemBaseOtMal(m, c, r) };
}

// ===================================================================================================
// COMMITTED KEM *RANDOM* OT (`kemBaseOtMalRandom`) — the random-OT face of the hardened protocol.
//
// The chosen-message `kemBaseOtMal` above one-time-pads the sender's messages internally and never
// surfaces the raw KEM shared secrets. A hybrid OT COMBINER (`hybrid-ot.ts`) needs those per-slot
// shared secrets so it can fold them with a second base OT's secrets. This variant runs the EXACT SAME
// five-round committed/session-bound protocol — same `rn`/`sn`/`sid`, same RO-commitment to the ordered
// public keys, same ABORT on an opened-key / commitment mismatch — but instead of padding messages it
// returns, per transfer, a session-bound shared secret PER SLOT:
//
//     ss_slot = H(TAG ‖ sid ‖ com ‖ i ‖ slot ‖ Decaps/Encaps shared secret).
//
// The SENDER derives BOTH (`senderSecrets[i] = [ss_0, ss_1]`); the honest RECEIVER derives only the
// chosen one (`recvSecrets[i] = ss_{choices[i]}`), because it kept only `sk_{choices[i]}`. Binding each
// secret to `(sid, com)` makes it non-transferable across sessions / across different opened keys —
// identical to how `kemOtMalPad` binds the chosen-message pad. The intrinsic "keep both secrets"
// residue is UNCHANGED from the chosen-message variant (an opaque IND-CCA KEM cannot stop it; see the
// module header) — closing it is exactly the job the hybrid combiner delegates to the EC base OT.
// ===================================================================================================

const TAG_KEMOT_MALSECRET = new TextEncoder().encode('atlas-pca-mpc/kem-ot-mal-secret');

/** Byte length of a derived committed-KEM random-OT shared secret. */
export const KEM_OT_SECRET_BYTES = 32;

/**
 * The session-bound per-slot shared secret `H(TAG ‖ sid ‖ com ‖ i ‖ slot ‖ ss)` (32 bytes). Binding to
 * `(sid, com)` ties it to the committed keys and this exact session — the random-OT analogue of
 * `kemOtMalPad`.
 */
function kemOtMalSecret(
  sid: Uint8Array,
  com: Uint8Array,
  index: number,
  slot: number,
  sharedSecret: Uint8Array,
): Uint8Array {
  return sha256(TAG_KEMOT_MALSECRET, sid, com, u32(index), Uint8Array.of(slot & 1), sharedSecret).slice(
    0,
    KEM_OT_SECRET_BYTES,
  );
}

/** Sender round-4 message of the committed KEM RANDOM OT: ciphertexts (wire) + both per-slot secrets (sender-local). */
export interface KemMalRandomSenderMessage {
  /** For each transfer i, the ML-KEM ciphertexts `[ct_0, ct_1]` (the only part that crosses the wire). */
  ciphertexts: Array<[Uint8Array, Uint8Array]>;
  /** Sender-LOCAL: the two session-bound shared secrets `[ss_0, ss_1]` per transfer (never sent). */
  senderSecrets: Array<[Uint8Array, Uint8Array]>;
}

/** A full committed KEM RANDOM-OT transcript + the two parties' shared-secret outputs. */
export interface KemBaseOtMalRandomResult {
  /** Sender's per-slot shared secrets `[ss_0, ss_1]` per transfer (the sender learns BOTH). */
  senderSecrets: Array<[Uint8Array, Uint8Array]>;
  /** Receiver's chosen shared secret `ss_{choices[i]}` per transfer (the honest receiver learns ONE). */
  recvSecrets: Uint8Array[];
  /** The session id `sid = H(rn ‖ sn)` the secrets are bound to (public; both parties derive it). */
  sid: Uint8Array;
  transcript: {
    rn: Uint8Array;
    commitments: Uint8Array[];
    sn: Uint8Array;
    publicKeys: Array<[Uint8Array, Uint8Array]>;
    ciphertexts: Array<[Uint8Array, Uint8Array]>;
  };
}

/**
 * SENDER round 4 (RANDOM variant): VERIFY the opened keys against the round-1 commitments (ABORT on
 * mismatch), encapsulate under each, and derive BOTH per-slot session-bound shared secrets. No messages
 * are padded — the two secrets per transfer ARE the random output.
 */
export function kemBaseOtMalRandomSend(
  commit: KemMalCommitMessage,
  senderNonce: KemMalSenderNonce,
  opening: KemMalOpenMessage,
  rng: OtRandom = secureOtRandom(),
): KemMalRandomSenderMessage {
  const { rn, commitments } = commit;
  const { publicKeys } = opening;
  if (commitments.length !== publicKeys.length) {
    throw new Error('kemBaseOtMalRandomSend: commitments/publicKeys length mismatch');
  }
  const sid = kemMalSid(rn, senderNonce.sn);
  const ciphertexts: Array<[Uint8Array, Uint8Array]> = [];
  const senderSecrets: Array<[Uint8Array, Uint8Array]> = [];
  for (let i = 0; i < publicKeys.length; i++) {
    const [pk0, pk1] = publicKeys[i]!;
    // Same binding check as the chosen-message variant: opened keys MUST reproduce the commitment.
    const com = kemMalCommit(rn, i, pk0, pk1);
    if (!constTimeEqual(com, commitments[i]!)) {
      throw new KemBaseOtAbort(
        `kem base OT (index ${i}): opened public keys do not match the receiver's commitment; aborting`,
      );
    }
    const e0 = ml_kem768.encapsulate(pk0, rng.bytes(ENCAPS_MSG_BYTES));
    const e1 = ml_kem768.encapsulate(pk1, rng.bytes(ENCAPS_MSG_BYTES));
    ciphertexts.push([e0.cipherText, e1.cipherText]);
    senderSecrets.push([
      kemOtMalSecret(sid, com, i, 0, e0.sharedSecret),
      kemOtMalSecret(sid, com, i, 1, e1.sharedSecret),
    ]);
  }
  return { ciphertexts, senderSecrets };
}

/**
 * RECEIVER round 5 (RANDOM variant): decapsulate ONLY the chosen ciphertext and derive the chosen
 * session-bound shared secret. The receiver never touches the non-chosen slot (it kept no secret for it).
 */
export function kemBaseOtMalRandomRecover(
  state: KemMalReceiverState,
  senderNonce: KemMalSenderNonce,
  senderMessage: KemMalRandomSenderMessage,
  tamper?: KemMalTamper,
): Uint8Array[] {
  const { choices, secretKeys, publicKeys, rn } = state;
  const { ciphertexts } = senderMessage;
  if (ciphertexts.length !== choices.length) {
    throw new Error('kemBaseOtMalRandomRecover: transcript/state length mismatch');
  }
  let sid = kemMalSid(rn, senderNonce.sn);
  if (tamper?.tamperReceiverSid) sid = tamper.tamperReceiverSid(sid);
  const recvSecrets: Uint8Array[] = [];
  for (let i = 0; i < choices.length; i++) {
    const c = choices[i]! & 1;
    const [pk0, pk1] = publicKeys[i]!;
    const com = kemMalCommit(rn, i, pk0, pk1);
    const ss = ml_kem768.decapsulate(ciphertexts[i]![c]!, secretKeys[i]!);
    recvSecrets.push(kemOtMalSecret(sid, com, i, c, ss));
  }
  return recvSecrets;
}

/**
 * In-process combined simulator for the committed KEM RANDOM OT. Runs the same five rounds as
 * `kemBaseOtMal` (commit → sender nonce → open → verify+encapsulate → recover) but outputs per-slot
 * shared secrets instead of padded messages. A cheating receiver (opened keys ≠ commitment) makes the
 * sender throw `KemBaseOtAbort`. The `tamper` hook injects malicious-receiver behaviour for tests.
 */
export function kemBaseOtMalRandom(
  choices: number[],
  rng: OtRandom = secureOtRandom(),
  tamper?: KemMalTamper,
): KemBaseOtMalRandomResult {
  const { message: commit, state } = kemBaseOtMalCommit(choices, rng);
  const senderNonce = kemBaseOtMalSenderNonce(rng);
  const opening = kemBaseOtMalOpen(state);
  // A malicious receiver may open keys OTHER than those it committed to (test-injected).
  if (tamper?.tamperOpenedKeys) tamper.tamperOpenedKeys(opening.publicKeys);
  const senderMessage = kemBaseOtMalRandomSend(commit, senderNonce, opening, rng);
  const recvSecrets = kemBaseOtMalRandomRecover(state, senderNonce, senderMessage, tamper);
  return {
    senderSecrets: senderMessage.senderSecrets,
    recvSecrets,
    sid: kemMalSid(commit.rn, senderNonce.sn),
    transcript: {
      rn: commit.rn,
      commitments: commit.commitments,
      sn: senderNonce.sn,
      publicKeys: opening.publicKeys,
      ciphertexts: senderMessage.ciphertexts,
    },
  };
}
