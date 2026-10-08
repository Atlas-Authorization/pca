/**
 * Hybrid base OT — a SOUND combiner of the malicious-secure EC base OT (`ot.ts`/`ec.ts`) and the
 * post-quantum committed ML-KEM base OT (`kem-ot.ts`), run together so the stack inherits the BEST
 * guarantee of each half instead of the weakest.
 *
 * ─── WHY A COMBINER ────────────────────────────────────────────────────────────────────────────────
 * The two base OTs this package ships have complementary weaknesses:
 *   • The EC base OT (`malBaseRandomOT`) is MALICIOUS-secure against both roles — a Schnorr NIZK proof
 *     of knowledge of `y` on `S = y·B`, full prime-order-subgroup validation of every transmitted
 *     point, and a random-OT core with no sender-chosen ciphertexts — but its hardness is the curve25519
 *     discrete log, which a QUANTUM adversary breaks with Shor.
 *   • The ML-KEM base OT (`kemBaseOtMalRandom`) is POST-QUANTUM (Module-LWE) and has unconditional,
 *     even-against-a-quantum-sender choice privacy, but against an actively-malicious receiver it has an
 *     IRREDUCIBLE residue from the opaque primitive: a receiver that runs keygen twice and keeps BOTH
 *     secret keys learns both messages, and the decisional-MLWE indistinguishability that gives choice
 *     privacy makes that cheat undetectable to the sender (see `kem-ot.ts` header).
 *
 * The combiner runs BOTH base OTs on the SAME choice bit and the SAME session, then derives each
 * transfer key from BOTH halves' shared secrets:
 *
 *     k_b = H( DOMAIN_SEP ‖ sid ‖ i ‖ b ‖ ss_ec_b ‖ ss_kem_b )        for b ∈ {0, 1}
 *
 * where `ss_ec_b` is the EC random-OT pad (`malBaseRandomOT`) and `ss_kem_b` the committed ML-KEM
 * random-OT secret (`kemBaseOtMalRandom`, the hardened variant — never the semi-honest one). The sender
 * one-time-pads `m_b` under `k_b` and commits to it (`com_b`); the honest receiver reconstructs only
 * `k_c` (it holds only `ss_ec_c` and `ss_kem_c`) and checks `com_c`.
 *
 * ─── WHAT THIS ACHIEVES (precise) ───────────────────────────────────────────────────────────────────
 * To recover `m_{1−c}` an adversary needs `k_{1−c}`, hence BOTH `ss_ec_{1−c}` AND `ss_kem_{1−c}` (the
 * hash is a random oracle; missing either input leaves the pad pseudorandom). Therefore:
 *   • vs a CLASSICAL malicious receiver — MALICIOUS-secure. Even a receiver that defeats the KEM half
 *     entirely by keeping both ML-KEM secrets (so it holds `ss_kem_{1−c}`) still cannot obtain
 *     `ss_ec_{1−c}`: the EC base OT is malicious-secure and `ss_ec_{1−c} = H(y·R − T)` is a point the
 *     receiver cannot compute without the discrete log of `S`. No `ss_ec_{1−c}` ⇒ no `k_{1−c}` ⇒ `m_{1−c}`
 *     stays hidden. This is the KILLER property the tests prove.
 *   • SENDER PRIVACY vs a SEMI-HONEST QUANTUM receiver — holds via the KEM half (Module-LWE): a quantum
 *     receiver that follows the protocol (discards the non-chosen material) cannot get `ss_kem_{1−c}`,
 *     so again `k_{1−c}` is unobtainable even though it could break the EC half with Shor.
 *   • CHOICE PRIVACY — POST-QUANTUM. The KEM half's choice privacy is unconditional (two i.i.d. real
 *     ML-KEM public keys on the wire); the EC half's is information-theoretic in its transcript (`R` is a
 *     uniform subgroup element whatever `c` is). Neither leaks `c`, against any adversary.
 *   • SESSION BINDING — both halves are bound to a COMMON `sid` derived from BOTH sub-protocols'
 *     session material (the KEM `(rn, sn)` nonces and the EC point `S`), and `sid` is hashed into every
 *     transfer key and commitment, so secrets from one session/opened-key-set cannot be replayed into
 *     another. The KEM half additionally aborts (`KemBaseOtAbort`) if the receiver opens keys other than
 *     the ones it committed to; the EC half aborts (`BaseOtAbort`/`PointValidationError`) on a bad proof
 *     or an off-/small-order point; and the combiner aborts (`HybridOtAbort`) if a tampered ciphertext
 *     fails its commitment.
 *
 * ─── THE HONEST BOUNDARY (NOT faked) ────────────────────────────────────────────────────────────────
 * The one residue this combiner does NOT close is a receiver that is SIMULTANEOUSLY actively-malicious
 * AND quantum: such a receiver could break the classical EC half with Shor (recovering `ss_ec_{1−c}`
 * from the transcript) WHILE keeping both ML-KEM secrets (recovering `ss_kem_{1−c}`), and so assemble
 * `k_{1−c}`. Closing THAT requires a base OT that is BOTH post-quantum AND malicious-secure in one
 * primitive — i.e. an endemic/UC OT from Module-LWE with a CRS, which needs direct lattice module
 * arithmetic (sampling / adding in ML-KEM's structured public-key space to plant a secretless slot).
 * The opaque `ml_kem768` keygen/encaps/decaps interface this package is restricted to does NOT expose
 * that arithmetic, and hand-rolling it is exactly the lattice crypto the module forbids. So this is the
 * honest limit of what a KEM-opaque + EC combiner can reach; it is stated, not papered over.
 *
 * No hand-rolled crypto: the EC half goes through `malBaseRandomOT` (unchanged), the KEM half through
 * `kemBaseOtMalRandom` (unchanged), and this module only hashes (SHA-256 RO) and XORs their outputs.
 */

import { createHash, timingSafeEqual } from 'node:crypto';
import { encodePoint, type Point } from './ec';
import {
  malBaseRandomOT,
  type BaseOtTamper,
  type OtChannel,
  type OtRandom,
} from './ot';
import {
  kemBaseOtMalRandom,
  type KemMalTamper,
} from './kem-ot';
import { secureOtRandom } from './csprng';

const TAG_HYBRID_SID = new TextEncoder().encode('atlas-pca-mpc/hybrid-ot-sid');
const TAG_HYBRID_KEY = new TextEncoder().encode('atlas-pca-mpc/hybrid-ot-transfer-key');
const TAG_HYBRID_COMMIT = new TextEncoder().encode('atlas-pca-mpc/hybrid-ot-msg-commit');

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

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) throw new Error('hybrid-ot: XOR length mismatch');
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/** Raised when the hybrid combiner aborts: a sender ciphertext inconsistent with its commitment is caught. */
export class HybridOtAbort extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HybridOtAbort';
  }
}

/**
 * The COMMON session id binding both halves: `H(TAG ‖ kemSid ‖ encode(ecS))`. It folds the KEM
 * sub-protocol's two-nonce session id (`rn, sn`) and the EC sub-protocol's point `S`, so neither party
 * alone fixes it and secrets cannot be mixed across sessions. Both parties derive the same value from
 * the public transcript.
 */
export function hybridSessionId(kemSid: Uint8Array, ecS: Point): Uint8Array {
  return sha256(TAG_HYBRID_SID, kemSid, encodePoint(ecS));
}

/**
 * The hybrid transfer key for one slot: `H(TAG ‖ sid ‖ i ‖ slot ‖ ss_ec ‖ ss_kem)` expanded (SHA-256
 * counter mode) to `len` bytes. Modelled as a random oracle: the key is pseudorandom unless BOTH
 * `ss_ec` and `ss_kem` (for that exact slot/index/session) are supplied — the soundness crux of the
 * combiner.
 */
export function hybridTransferKey(
  sid: Uint8Array,
  index: number,
  slot: number,
  ssEc: Uint8Array,
  ssKem: Uint8Array,
  len: number,
): Uint8Array {
  const out = new Uint8Array(len);
  let produced = 0;
  let ctr = 0;
  while (produced < len) {
    const block = sha256(
      TAG_HYBRID_KEY,
      sid,
      u32(index),
      Uint8Array.of(slot & 1),
      u32(ctr),
      ssEc,
      ssKem,
    );
    for (let k = 0; k < block.length && produced < len; k++) out[produced++] = block[k]!;
    ctr++;
  }
  return out;
}

/** Per-message RO commitment `com = H(TAG ‖ sid ‖ i ‖ slot ‖ msg ‖ key)`, bound to the session. */
function hybridCommit(
  sid: Uint8Array,
  index: number,
  slot: number,
  msg: Uint8Array,
  key: Uint8Array,
): Uint8Array {
  return sha256(TAG_HYBRID_COMMIT, sid, u32(index), Uint8Array.of(slot & 1), msg, key);
}

/** The sender's wire message of the hybrid combiner: one-time-padded messages + per-message commitments. */
export interface HybridSenderMessage {
  /** For each transfer i, `[E_0, E_1]` with `E_b = m_b ⊕ k_b`. */
  encrypted: Array<[Uint8Array, Uint8Array]>;
  /** For each transfer i, `[com_0, com_1]` with `com_b = H(sid ‖ i ‖ b ‖ m_b ‖ k_b)`. */
  commitments: Array<[Uint8Array, Uint8Array]>;
}

/**
 * SENDER side of the combiner: given BOTH halves' per-slot shared secrets, derive both transfer keys,
 * one-time-pad each message, and commit to each. `ecSecrets[i] = [ss_ec_0, ss_ec_1]` (the EC random-OT
 * `senderPads`), `kemSecrets[i] = [ss_kem_0, ss_kem_1]` (the committed-KEM `senderSecrets`).
 */
export function hybridSenderEncrypt(
  sid: Uint8Array,
  messages: Array<[Uint8Array, Uint8Array]>,
  ecSecrets: Array<[Uint8Array, Uint8Array]>,
  kemSecrets: Array<[Uint8Array, Uint8Array]>,
): HybridSenderMessage {
  if (messages.length !== ecSecrets.length || messages.length !== kemSecrets.length) {
    throw new Error('hybridSenderEncrypt: messages/ecSecrets/kemSecrets length mismatch');
  }
  const encrypted: Array<[Uint8Array, Uint8Array]> = [];
  const commitments: Array<[Uint8Array, Uint8Array]> = [];
  for (let i = 0; i < messages.length; i++) {
    const [m0, m1] = messages[i]!;
    if (m0.length !== m1.length) {
      throw new Error(`hybridSenderEncrypt (index ${i}): the two messages must be equal length`);
    }
    const k0 = hybridTransferKey(sid, i, 0, ecSecrets[i]![0], kemSecrets[i]![0], m0.length);
    const k1 = hybridTransferKey(sid, i, 1, ecSecrets[i]![1], kemSecrets[i]![1], m1.length);
    encrypted.push([xorBytes(m0, k0), xorBytes(m1, k1)]);
    commitments.push([hybridCommit(sid, i, 0, m0, k0), hybridCommit(sid, i, 1, m1, k1)]);
  }
  return { encrypted, commitments };
}

/**
 * RECEIVER side of the combiner: reconstruct ONLY the chosen transfer key (from the chosen EC and KEM
 * secrets the receiver legitimately holds), unmask the chosen message, and CHECK the commitment.
 * `ecRecv[i] = ss_ec_{choices[i]}` (the EC `recvPads`), `kemRecv[i] = ss_kem_{choices[i]}` (the
 * committed-KEM `recvSecrets`). Aborts (`HybridOtAbort`) if the recovered message fails its commitment.
 */
export function hybridReceiverRecover(
  sid: Uint8Array,
  choices: number[],
  sender: HybridSenderMessage,
  ecRecv: Uint8Array[],
  kemRecv: Uint8Array[],
): Uint8Array[] {
  const { encrypted, commitments } = sender;
  if (
    encrypted.length !== choices.length ||
    commitments.length !== choices.length ||
    ecRecv.length !== choices.length ||
    kemRecv.length !== choices.length
  ) {
    throw new Error('hybridReceiverRecover: length mismatch');
  }
  const received: Uint8Array[] = [];
  for (let i = 0; i < choices.length; i++) {
    const c = choices[i]! & 1;
    const e = encrypted[i]![c]!;
    const key = hybridTransferKey(sid, i, c, ecRecv[i]!, kemRecv[i]!, e.length);
    const m = xorBytes(e, key);
    const check = hybridCommit(sid, i, c, m, key);
    if (!ctEqual(check, commitments[i]![c]!)) {
      throw new HybridOtAbort(
        `hybrid base OT (index ${i}): sender ciphertext inconsistent with its commitment; aborting`,
      );
    }
    received.push(m);
  }
  return received;
}

/**
 * TEST-ONLY injection points modelling malicious behaviour in the hybrid combiner. The `ec` / `kem`
 * bags are forwarded to the respective sub-OTs (so each half's real malicious checks run against the
 * adversarial value); `tamperEncrypted` corrupts the hybrid sender's ciphertexts on the wire (caught by
 * the commitment check).
 */
export interface HybridBaseOtTamper {
  /** Forwarded to the EC half (`malBaseRandomOT`): malicious sender/receiver on the EC sub-OT. */
  ec?: BaseOtTamper;
  /** Forwarded to the KEM half (`kemBaseOtMalRandom`): malicious receiver on the committed KEM sub-OT. */
  kem?: KemMalTamper;
  /** Malicious hybrid SENDER: corrupt the padded messages on the wire (inconsistent with the commitment). */
  tamperEncrypted?: (encrypted: Array<[Uint8Array, Uint8Array]>) => void;
}

/** A full hybrid base-OT transcript, exposed for inspection/tests. */
export interface HybridBaseOtTranscript {
  /** The common session id both halves are bound to. */
  sid: Uint8Array;
  /** The EC sub-OT's public point `S` (with its Schnorr proof available via the EC half). */
  ecS: Point;
  /** The committed-KEM sub-OT session id `H(rn ‖ sn)`. */
  kemSid: Uint8Array;
  encrypted: Array<[Uint8Array, Uint8Array]>;
  commitments: Array<[Uint8Array, Uint8Array]>;
}

export interface HybridBaseOtResult {
  /** Receiver's recovered messages `m_{i, choices[i]}`. */
  received: Uint8Array[];
  transcript: HybridBaseOtTranscript;
}

/**
 * In-process combined simulator (both parties in one call), matching the shape of `baseOT`/`kemBaseOT`
 * so it is a drop-in for `OtChannel`'s `baseOtFn` (`withHybridBaseOt`). Runs the malicious-secure EC
 * base OT and the committed ML-KEM base OT on the SAME choices, binds both to a common `sid`, and
 * combines their per-slot secrets into the transfer keys. A cheating party is caught by whichever
 * half's check applies (EC proof/point validation, KEM commitment, or the hybrid ciphertext
 * commitment). `tamper` injects malicious behaviour for tests.
 */
export function hybridBaseOT(
  messages: Array<[Uint8Array, Uint8Array]>,
  choices: number[],
  rng: OtRandom = secureOtRandom(),
  tamper?: HybridBaseOtTamper,
): HybridBaseOtResult {
  if (messages.length !== choices.length) {
    throw new Error('hybridBaseOT: messages/choices length mismatch');
  }
  // EC half: malicious-secure random OT with ALL checks ON (Schnorr proof + subgroup validation).
  const ec = malBaseRandomOT(choices, rng, tamper?.ec);
  // KEM half: the committed/session-bound random OT (aborts on an opened-key/commitment mismatch).
  const kem = kemBaseOtMalRandom(choices, rng, tamper?.kem);

  const sid = hybridSessionId(kem.sid, ec.S);
  const sender = hybridSenderEncrypt(sid, messages, ec.senderPads, kem.senderSecrets);

  // A malicious hybrid SENDER may corrupt the ciphertexts on the wire (test-injected).
  if (tamper?.tamperEncrypted) tamper.tamperEncrypted(sender.encrypted);

  const received = hybridReceiverRecover(sid, choices, sender, ec.recvPads, kem.recvSecrets);
  return {
    received,
    transcript: {
      sid,
      ecS: ec.S,
      kemSid: kem.sid,
      encrypted: sender.encrypted,
      commitments: sender.commitments,
    },
  };
}

/**
 * Wire the HYBRID base OT into the KOS OT-extension: a drop-in for `withKemBaseOt`/`withKemBaseOtMal`
 * that makes `OtChannel` run its κ setup base OTs over the combiner. The extension inherits the
 * combiner's guarantee — malicious security vs a classical receiver, PQ sender-privacy vs a semi-honest
 * quantum one, and PQ choice privacy — with everything above the base OT (IKNP matrix, KOS correlation
 * check, correlation-robust hash) unchanged.
 *
 *   const ch = new OtChannel(secureOtRandom(), withHybridBaseOt());
 */
export function withHybridBaseOt(): ConstructorParameters<typeof OtChannel>[1] {
  return { baseOtFn: (m, c, r) => ({ received: hybridBaseOT(m, c, r).received }) };
}
