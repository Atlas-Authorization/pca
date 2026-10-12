/**
 * Oblivious transfer — the real cryptographic root of the no-dealer offline phase.
 *
 * A 1-out-of-2 OT lets a RECEIVER with a choice bit `c` obtain exactly message `m_c` from a SENDER's
 * pair `(m_0, m_1)`, such that the sender learns nothing about `c` and the receiver learns nothing
 * about `m_{1−c}`. That single primitive is enough to multiply two parties' secret shares without a
 * dealer (Gilboa's trick, see `mascot.ts`), which is enough to generate Beaver triples and SPDZ MACs
 * with no trusted party. This module provides OT two ways:
 *
 *  1. **Base OT — MALICIOUSLY-secure Chou–Orlandi over the Ed25519 subgroup (`ec.ts`).** The core is
 *     "simplest OT": sender samples `y`, publishes `S = y·B`, holds `T = y·S`; receiver with choice `c`
 *     samples `x`, publishes `R = x·B + c·S`, derives pad `k = H(x·S)`; sender derives `k_b = H(y·R − b·T)`
 *     for `b∈{0,1}`; since `y·R = x·(y·B) + c·T`, `k_c = k` while `k_{1−c}` is `H` of a point the receiver
 *     can't compute (it would need the discrete log). **Receiver-choice privacy is information-theoretic
 *     in the transcript:** `R = x·B + c·S` with `x` uniform is a uniform subgroup element whatever `c` is
 *     — for every observed `R` there is one `x` consistent with `c=0` and one with `c=1` (`x' = x − y`),
 *     so the sender's view is identically distributed for both choices. Two additions upgrade this from
 *     semi-honest to **malicious-secure against both a cheating sender AND a cheating receiver** (docs
 *     §7.1 item a):
 *       • **the sender proves knowledge of `y` with a Schnorr NIZK on `S = y·B`** (`ec.ts`), so a sender
 *         cannot use an `S` it cannot open (e.g. one crafted to leak the receiver's choice) — the
 *         receiver verifies the proof and ABORTS before forming `R`;
 *       • **every received point is validated** (on-curve + prime-order-subgroup cofactor check +
 *         non-identity): the receiver validates `S`, the sender validates every `R_i`, so neither party
 *         can inject an off-curve / small-order / mixed-order point for a small-subgroup attack.
 *     The IKNP setup consumes this as a **random OT** (`malBaseRandomOT`): the two transferred seeds ARE
 *     the RO pads `(H(y·R), H(y·R − T))`, so there are **no sender-chosen ciphertexts** and hence no
 *     selective-failure surface — the only abort (bad `S`/proof/`R_i`) is independent of the receiver's
 *     selector, which is exactly what malicious security of the role-inverted base OTs requires. The
 *     chosen-message `baseOT` wrapper (random OT + one-time-pad + a commit-to-message check) is used by
 *     the direct OT tests; its commitment catches a sender that encrypts inconsistently with its commitment.
 *
 *  2. **OT extension — IKNP + the KOS consistency check (MALICIOUS-secure).** Base OT needs public-key
 *     ops per transfer; the offline phase needs hundreds of thousands of OTs. IKNP turns `κ = 128` base
 *     OTs (done once) into arbitrarily many OTs using only a hash/PRG. Roles invert for the base OTs:
 *     the extension SENDER plays base-receiver with a secret selector `s ∈ {0,1}^κ`; the extension
 *     RECEIVER plays base-sender with `κ` seed pairs. Thereafter each extension round of `m` OTs costs
 *     `κ` PRG expansions plus `~3·m` hashes. Correctness: the receiver recovers exactly `m_{c_j}` for
 *     every `j`; the sender's `s` (hidden by the base OTs) and the correlation-robust hash keep the
 *     unchosen messages hidden.
 *
 *     Plain IKNP is only SEMI-HONEST: a cheating RECEIVER can send an extension matrix `u` that encodes
 *     *different* choice vectors in different columns, which breaks the row correlation `q_j = t_j ⊕
 *     (b_j·s)` and lets the receiver learn bits of the sender's selector `s` (and thus the unchosen
 *     messages). The **KOS correlation check** (Keller–Orsini–Scholl, "Actively Secure OT Extension
 *     with Optimal Overhead") closes exactly this: after `u` is on the wire, the parties draw public
 *     random weights `χ_j ∈ GF(2^κ)` (one per row, bound to `u` by a Fiat–Shamir hash here), the
 *     receiver reveals `x = Σ_j b_j·χ_j` and `t = Σ_j χ_j·t_j`, and the sender checks
 *     `Σ_j χ_j·q_j == t ⊕ x·s` in GF(2^κ). Honestly this always holds (`q_j = t_j ⊕ b_j·s`); a receiver
 *     who deviated in `u` is caught, so a deviation ABORTS. The honest statement of the bound is the KOS
 *     STATISTICAL parameter `s = SSEC = 128`, NOT `2^{-κ}`: a receiver that deviates in a few columns passes by
 *     guessing the matching bits of the selector `s`, and the 2015 proof (ePrint 2015/546) was additionally shown
 *     to rest on an incorrect lemma (Roy, CRYPTO 2022). Roy's attacks give the receiver success
 *     about `2^{-s}` with `s` extra rows, and the KOS proof is still open (Roy leaves a sound proof to future work), so
 *     this module sets `s = SSEC = 128` extra rows (was 64): the best KNOWN attack then succeeds with probability about
 *     `2^{-128}`. That is an argument from the attack analysis, NOT a proof; we did not implement SoftSpokenOT's own
 *     (different, small-field VOLE) consistency check, whose parameters we could not verify from the paper.
 *     The check is run over `m + κ + SSEC` rows — the extra `κ + SSEC` random "sacrifice" OT rows mask
 *     the revealed combination (receiver privacy) and give statistical soundness. This makes the OT
 *     extension **malicious-secure**, not just semi-honest.
 *
 * In-process model: both parties run in one process and the functions take *both* parties' inputs and
 * return the receiver's outputs plus an inspectable transcript (the receiver's wire message `R`, the
 * sender's ciphertexts, the IKNP `u` matrix). That is exactly what the tests assert over: receiver
 * correctness, sender-side choice-hiding from the transcript, and the KOS check aborting on a tampered
 * `u`. See docs §7.1 for the remaining boundary (real async transport, constant-time, CSPRNG).
 */

import { createHash, timingSafeEqual } from 'node:crypto';
import {
  add,
  assertInSubgroup,
  encodePoint,
  L,
  mul,
  mulBase,
  type Point,
  schnorrProve,
  schnorrVerify,
  type SchnorrProof,
  sub,
} from './ec';
import { gf128Mul } from './gf128';
import {
  bigToBytes,
  bytesToBig,
  COLS,
  accumColumn,
  gfFromBig,
  gfToBig,
  gfXorInto,
  kosCombine,
  maskTail,
  prgColumn,
  otTweakDomain,
  tmmoCrh,
  transposeCols,
  word64,
} from './otx';
import { secureOtRandom } from './csprng';

/** IKNP security parameter (number of base OTs / width of the selector s). */
export const KAPPA = 128;

/**
 * KOS statistical-security parameter: the number of EXTRA random check-OT rows (beyond the `κ` that
 * mask the revealed combination) appended to every extension round. Together `κ + SSEC` padding rows
 * give the correlation check its receiver-privacy and statistical soundness margin. Roy (CRYPTO 2022, ePrint
 * 2022/192) shows the KOS proof is flawed and that the attacks succeed with probability about 2^-s for `s` extra
 * rows; `s = 128` (raised from 64, a WIRE CHANGE: the matrix has 64 more rows per round) makes the best known attack
 * about 2^-128. Not a proof.
 */
export const SSEC = 128;

/** Raised when the KOS correlation check fails: a cheating OT-extension receiver is detected → ABORT. */
export class MalOtAbort extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MalOtAbort';
  }
}

/** Seed length in bytes for base-OT messages / IKNP seeds (κ = 128 bits). */
const SEED_BYTES = KAPPA / 8;

/** A deterministic source of scalars/seeds; wraps the module FieldRng-style stream for OT needs. */
export interface OtRandom {
  /** A uniform scalar in [1, L) (for EC blinding) — never 0. */
  scalar(): bigint;
  /** `n` random bytes (for seeds). */
  bytes(n: number): Uint8Array;
}

/** A raw SplitMix64 64-bit stream (deterministic). Production uses a CSPRNG with a secret seed. */
export function splitMix64(seed: bigint): () => bigint {
  const MASK64 = (1n << 64n) - 1n;
  let s = seed & MASK64;
  return () => {
    s = (s + 0x9e3779b97f4a7c15n) & MASK64;
    let z = s;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64;
    z = (z ^ (z >> 31n)) & MASK64;
    return z;
  };
}

/** Build an OtRandom from a SplitMix64-style 64-bit stream (deterministic; CSPRNG in production). */
export function otRandom(next64: () => bigint): OtRandom {
  return {
    scalar(): bigint {
      // Assemble 256 bits then reduce mod L; reject 0. Bounded: a healthy source yields 0 with probability
      // ~2^-252, so a handful of consecutive zeros means a stuck-at-zero stream - fail closed, never spin.
      for (let attempt = 0; attempt < 8; attempt++) {
        let acc = 0n;
        for (let i = 0; i < 4; i++) acc = (acc << 64n) | next64();
        const s = acc % L;
        if (s !== 0n) return s;
      }
      throw new Error('otRandom: entropy stream returned zero scalars repeatedly (RNG failure)');
    },
    bytes(n: number): Uint8Array {
      const out = new Uint8Array(n);
      let have = 0;
      while (have < n) {
        let v = next64();
        for (let i = 0; i < 8 && have < n; i++) {
          out[have++] = Number(v & 0xffn);
          v >>= 8n;
        }
      }
      return out;
    },
  };
}

// --------------------------------------------------------------------------------------------------
// Hash / PRG helpers (SHA-256 based). Deterministic; a production build uses the same constructions
// over a CSPRNG and a formally correlation-robust hash.
// --------------------------------------------------------------------------------------------------

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

/**
 * Session binding of one base OT: who runs it, in which session and round. It is folded into the sender's
 * Schnorr challenge AND into every pad, so neither a proof nor a pad carries over to another session,
 * party pair or round. `senderIndex` is the base-OT SENDER (the party that publishes S).
 */
export interface BaseOtBinding {
  /** 8..64 bytes, unique per session (the network runner uses its session id). */
  sessionId: Uint8Array;
  senderIndex: number;
  receiverIndex: number;
  /** Non-empty label of the protocol round / use, at most 64 bytes. */
  round: string;
}

const TAG_BINDING = new TextEncoder().encode('atlas-pca-mpc/base-ot-binding');
const TAG_TRANSCRIPT = new TextEncoder().encode('atlas-pca-mpc/base-ot-transcript');

/** Canonical, length-prefixed encoding of a binding (the Schnorr context and part of every KDF input). */
export function bindingBytes(b: BaseOtBinding): Uint8Array {
  if (!(b.sessionId instanceof Uint8Array) || b.sessionId.length < 8 || b.sessionId.length > 64) {
    throw new RangeError('base-OT binding: sessionId must be 8..64 bytes');
  }
  for (const [k, v] of [['senderIndex', b.senderIndex], ['receiverIndex', b.receiverIndex]] as const) {
    if (!Number.isInteger(v) || v < 0 || v > 0xffffffff) throw new RangeError(`base-OT binding: ${k} must be a uint32`);
  }
  if (b.senderIndex === b.receiverIndex) throw new RangeError('base-OT binding: sender and receiver must be different parties');
  const round = new TextEncoder().encode(b.round);
  if (round.length === 0 || round.length > 64) throw new RangeError('base-OT binding: round label must be 1..64 bytes');
  const parts = [TAG_BINDING, u32(b.sessionId.length), b.sessionId, u32(b.senderIndex), u32(b.receiverIndex), u32(round.length), round];
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** A fresh binding for an in-process OT (both roles simulated): random session id from `rng`. */
export function randomBinding(rng: OtRandom, round: string, senderIndex = 0, receiverIndex = 1): BaseOtBinding {
  return { sessionId: rng.bytes(16), senderIndex, receiverIndex, round };
}

/**
 * Hash of the WHOLE base-OT transcript: binding, the sender's S and every receiver point R_i, in order.
 * Every pad is derived under this hash, so changing the session, S or ANY R_j changes EVERY key.
 */
export function baseOtTranscriptHash(binding: BaseOtBinding, S: Point, R: readonly Point[]): Uint8Array {
  const h = createHash('sha256');
  h.update(TAG_TRANSCRIPT);
  h.update(bindingBytes(binding));
  h.update(encodePoint(S));
  h.update(u32(R.length));
  for (const r of R) h.update(encodePoint(r));
  return new Uint8Array(h.digest());
}

/**
 * Key derivation from a group point, Chou–Orlandi / Simplest-OT style but over the full transcript:
 * `H("ot-kdf" ‖ H(transcript) ‖ index ‖ R_i ‖ P)` → SEED_BYTES bytes.
 */
export function baseOtKdf(transcriptHash: Uint8Array, index: number, Ri: Point, p: Point): Uint8Array {
  return sha256(TAG_KDF, transcriptHash, u32(index), encodePoint(Ri), encodePoint(p)).slice(0, SEED_BYTES);
}
const TAG_KDF = new TextEncoder().encode('atlas-pca-mpc/ot-kdf');
const TAG_KOS = new TextEncoder().encode('atlas-pca-mpc/ot-kos');
const TAG_COMMIT = new TextEncoder().encode('atlas-pca-mpc/ot-msg-commit');

/** Little-endian fixed-width serialization of a non-negative bigint (callers have range-checked it). */
const leBytes = bigToBytes;

/**
 * Derive the KOS row-weights χ_j ∈ GF(2^128) for one extension round (Fiat–Shamir). The sender and
 * receiver both derive the SAME χ from the FULL `u` matrix on the wire, so a cheating receiver cannot
 * pick `u` after seeing χ. In the real protocol χ comes from a secure coin-flip after the receiver
 * commits to `u`; the transcript hash here models that round.
 *
 * The weights are the output of SHAKE256 (an extendable-output function, `node:crypto`) over
 * `TAG ‖ channel binding ‖ round ‖ mExt ‖ every bit of every column of u`, 16 bytes per row — a vetted
 * XOF seeded by the whole transcript, not a fast non-cryptographic stream. (An earlier version expanded a
 * 128-bit digest with SplitMix64, and hashed only the low 128 bits of each column; both are gone.)
 */
export function kosChallenges(binding: Uint8Array, round: number, u: bigint[], mExt: number): bigint[] {
  const w = kosChiWords(binding, round, u, mExt);
  const chi: bigint[] = new Array(mExt);
  for (let j = 0; j < mExt; j++) chi[j] = gfToBig(w.subarray(4 * j, 4 * j + 4));
  return chi;
}

/** The same weights as little-endian u32 words (4 per row), the form the typed kernels consume. */
export function kosChiWords(binding: Uint8Array, round: number, u: bigint[], mExt: number, colBytesList?: Uint8Array[]): Uint32Array {
  const colBytes = Math.ceil(mExt / 8);
  const xof = createHash('shake256', { outputLength: mExt * 16 });
  xof.update(TAG_KOS);
  xof.update(u32(binding.length));
  xof.update(binding);
  xof.update(u32(round));
  xof.update(u32(mExt));
  xof.update(u32(u.length));
  if (colBytesList) for (const cb of colBytesList) xof.update(cb);
  else for (const col of u) xof.update(leBytes(col, colBytes));
  const out = xof.digest();
  const words = new Uint32Array(mExt * 4);
  for (let i = 0; i < words.length; i++) words[i] = out.readUInt32LE(i * 4);
  return words;
}

/** XOR two equal-length byte arrays. */
function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}


// --------------------------------------------------------------------------------------------------
// Base OT — MALICIOUSLY-secure Chou–Orlandi, batched (docs §7.1 item a).
//
// Two hardening layers upgrade the semi-honest "simplest OT" to malicious security against BOTH roles:
//   • the SENDER proves knowledge of `y` with a Schnorr NIZK on `S = y·B` (`ec.ts`); the receiver
//     verifies it and ABORTS before forming any `R`, so a sender cannot use an `S` it cannot open;
//   • every point crossing the trust boundary is validated (on-curve + prime-order cofactor check +
//     non-identity): the receiver validates `S` (and the proof's `U`), the sender validates every
//     `R_i`, so neither party can inject an off-curve / small-order / mixed-order point.
// The core is run as a RANDOM OT (`malBaseRandomOT`): the two transferred seeds ARE the RO pads, so
// there are no sender-chosen ciphertexts and no selective-failure surface. The chosen-message `baseOT`
// wrapper then one-time-pads the messages under those pads AND sends a per-message RO commitment; the
// receiver recomputes the commitment on the message+pad it recovers and aborts on a mismatch — this is
// what catches a sender that encrypts a message inconsistent with what it committed.
// --------------------------------------------------------------------------------------------------

/** Raised when a base OT aborts: a cheating sender (bad proof / inconsistent ciphertext) is detected. */
export class BaseOtAbort extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BaseOtAbort';
  }
}

/**
 * TEST-ONLY injection points modelling a malicious SENDER or RECEIVER in the base OT. Each hook mutates
 * or replaces a value exactly where it would cross the wire, so the honest party's validation runs
 * against the adversarial value — which is what the malicious-security checks must catch.
 */
export interface BaseOtTamper {
  /** Malicious SENDER: replace `S` on the wire (the receiver still validates it + the proof). */
  tamperS?: (S: Point) => Point;
  /** Malicious SENDER: forge the Schnorr proof on the wire. */
  tamperProof?: (p: SchnorrProof) => SchnorrProof;
  /** Malicious RECEIVER: mutate the `R_i` points on the wire (the sender still validates each). */
  tamperR?: (R: Point[]) => void;
  /** Malicious SENDER: corrupt the ciphertexts on the wire (inconsistent with the commitment). */
  tamperCiphertext?: (ct: Array<[Uint8Array, Uint8Array]>) => void;
}

/** The base-OT transcript: the sender's `S` + proof-of-knowledge, the receiver's `R_i`, and the ciphertexts/commitments. */
export interface BaseOtTranscript {
  /** Sender's public point S = y·B. */
  S: Point;
  /** Schnorr NIZK proving the sender knows `y` with `S = y·B` (malicious-sender hardening). */
  proof: SchnorrProof;
  /** Receiver's points R_i = x_i·B + c_i·S (uniform subgroup elements; independent of c_i). */
  R: Point[];
  /** Sender ciphertexts: for each i, [E_{i,0}, E_{i,1}] = [m_{i,0} ⊕ pad_{i,0}, m_{i,1} ⊕ pad_{i,1}]. */
  ct: Array<[Uint8Array, Uint8Array]>;
  /** Per-message RO commitments com_{i,b} = H(i ‖ b ‖ m_{i,b} ‖ pad_{i,b}); the receiver checks com_{i,c}. */
  com: Array<[Uint8Array, Uint8Array]>;
}

export interface BaseOtResult {
  /** Receiver's recovered messages m_{i, c_i}. */
  received: Uint8Array[];
  transcript: BaseOtTranscript;
}

/**
 * A pluggable chosen-message base OT: `count = choices.length` 1-of-2 OTs returning the receiver's
 * recovered messages. The EC `baseOT` above satisfies it, and so does the post-quantum `kemBaseOT`
 * (`kem-ot.ts`) — letting `OtChannel` run its κ setup OTs over either base without touching the
 * IKNP/KOS layer. Only `received` is required (the EC-specific `transcript` is not part of the contract,
 * since a non-EC base has a different transcript shape).
 */
export type BaseOtFn = (
  messages: Array<[Uint8Array, Uint8Array]>,
  choices: number[],
  rng: OtRandom,
) => { received: Uint8Array[] };

/** The output of the malicious-secure RANDOM base OT: validated points + the two RO pads per index. */
export interface MalRandomOtResult {
  /** Sender's public point (as seen on the wire by the receiver). */
  S: Point;
  /** Sender's proof of knowledge of the discrete log of `S`. */
  proof: SchnorrProof;
  /** Receiver's points (as seen on the wire by the sender). */
  R: Point[];
  /** Sender's pad pairs: senderPads[i] = [H(y·R_i), H(y·R_i − T)]. */
  senderPads: Array<[Uint8Array, Uint8Array]>;
  /** Receiver's recovered pads: recvPads[i] = H(x_i·S) = senderPads[i][c_i] (honest run). */
  recvPads: Uint8Array[];
}

/** Per-message RO commitment com_{i,b} = H(TAG ‖ i ‖ b ‖ msg ‖ pad). */
function otCommit(i: number, b: number, msg: Uint8Array, pad: Uint8Array): Uint8Array {
  return sha256(TAG_COMMIT, u32(i), Uint8Array.of(b & 1), msg, pad);
}

function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/**
 * The MALICIOUS-secure RANDOM base OT: `count = choices.length` 1-of-2 random OTs. The sender publishes
 * `S = y·B` with a Schnorr proof of knowledge of `y`; the receiver validates `S` + the proof and
 * ABORTS on failure, then forms its `R_i`; the sender validates every `R_i` and derives the pad pairs.
 * No messages are transferred — the pads ARE the random output. `tamper` injects malicious behaviour
 * for tests. Both parties are simulated in-process.
 */
export function malBaseRandomOT(
  choices: number[],
  rng: OtRandom = secureOtRandom(),
  tamper?: BaseOtTamper,
  binding: BaseOtBinding = randomBinding(rng, 'base-ot'),
): MalRandomOtResult {
  const setup = malBaseOtSenderSetup(rng, binding);
  // What actually goes on the wire (a malicious sender may tamper either).
  const S = tamper?.tamperS ? tamper.tamperS(setup.S) : setup.S;
  const proof = tamper?.tamperProof ? tamper.tamperProof(setup.proof) : setup.proof;
  const { R, recvPads } = malBaseOtReceiverRespond(S, proof, choices, rng, binding);
  // A malicious receiver may tamper the R it sends on the wire (test-injected).
  if (tamper?.tamperR) tamper.tamperR(R);
  const senderPads = malBaseOtSenderDerive(setup.y, setup.T, R, S, binding);
  return { S, proof, R, senderPads, recvPads };
}

// --- The same protocol as explicit per-party steps, so it can run over a real network (`net/ot-net.ts`). ---

/** SENDER step 1: S = y·B, T = y·S, and a Schnorr proof of knowledge of y. `y`/`T` stay sender-local. */
export function malBaseOtSenderSetup(
  rng: OtRandom,
  binding: BaseOtBinding,
): { y: bigint; T: Point; S: Point; proof: SchnorrProof } {
  const ctx = bindingBytes(binding);
  const y = rng.scalar();
  const S = mulBase(y);
  const T = mul(y, S); // T = y·S = y²·B
  const proof = schnorrProve(y, S, () => rng.scalar(), ctx);
  return { y, T, S, proof };
}

/**
 * RECEIVER step: validate the sender's point + proof BEFORE forming any R (malicious-sender guard), then
 * choose x_i, form R_i = x_i·B (+ S if c_i=1) and derive recvPad_i = H(x_i·S). Throws `BaseOtAbort`/
 * `PointValidationError` on a bad S or proof.
 */
export function malBaseOtReceiverRespond(
  S: Point,
  proof: SchnorrProof,
  choices: number[],
  rng: OtRandom,
  binding: BaseOtBinding,
): { R: Point[]; recvPads: Uint8Array[] } {
  const ctx = bindingBytes(binding);
  assertInSubgroup(S, 'base-OT S (received by receiver)');
  if (!schnorrVerify(S, proof, ctx)) {
    throw new BaseOtAbort('base OT: sender Schnorr proof-of-knowledge of S=y·B failed; aborting');
  }
  const R: Point[] = [];
  const xs: bigint[] = [];
  for (let i = 0; i < choices.length; i++) {
    const x = rng.scalar();
    const ci = choices[i]! & 1;
    R.push(ci === 1 ? add(mulBase(x), S) : mulBase(x));
    xs.push(x);
  }
  // Keys are derived under the hash of the WHOLE transcript (binding, S, every R_i).
  const th = baseOtTranscriptHash(binding, S, R);
  const recvPads = xs.map((x, i) => baseOtKdf(th, i, R[i]!, mul(x, S)));
  return { R, recvPads };
}

/** SENDER step 2: validate every received R_i (malicious-receiver / small-subgroup guard), derive both pads. */
export function malBaseOtSenderDerive(
  y: bigint,
  T: Point,
  R: Point[],
  S: Point,
  binding: BaseOtBinding,
): Array<[Uint8Array, Uint8Array]> {
  const senderPads: Array<[Uint8Array, Uint8Array]> = [];
  for (let i = 0; i < R.length; i++) assertInSubgroup(R[i]!, `base-OT R_${i} (received by sender)`);
  const th = baseOtTranscriptHash(binding, S, R);
  for (let i = 0; i < R.length; i++) {
    const yR = mul(y, R[i]!);
    senderPads.push([baseOtKdf(th, i, R[i]!, yR), baseOtKdf(th, i, R[i]!, sub(yR, T))]);
  }
  return senderPads;
}

/** SENDER step 3 (chosen-message wrapper): one-time-pad each message under its pad and commit to it. */
export function baseOtSenderEncrypt(
  messages: Array<[Uint8Array, Uint8Array]>,
  senderPads: Array<[Uint8Array, Uint8Array]>,
): { ct: Array<[Uint8Array, Uint8Array]>; com: Array<[Uint8Array, Uint8Array]> } {
  if (messages.length !== senderPads.length) throw new Error('baseOT: messages/pads length mismatch');
  for (const [i, [m0, m1]] of messages.entries()) {
    if (m0.length > SEED_BYTES || m1.length > SEED_BYTES || m0.length !== m1.length) {
      throw new RangeError(`baseOT: message pair ${i} must be equal length and at most ${SEED_BYTES} bytes (pad width)`);
    }
  }
  const ct: Array<[Uint8Array, Uint8Array]> = [];
  const com: Array<[Uint8Array, Uint8Array]> = [];
  for (let i = 0; i < messages.length; i++) {
    const [p0, p1] = senderPads[i]!;
    ct.push([xorBytes(messages[i]![0], p0), xorBytes(messages[i]![1], p1)]);
    com.push([otCommit(i, 0, messages[i]![0], p0), otCommit(i, 1, messages[i]![1], p1)]);
  }
  return { ct, com };
}

/**
 * RECEIVER step 3: decrypt the chosen ciphertext with its pad, then CHECK the commitment it can open;
 * `BaseOtAbort` on any inconsistency (a cheating sender). Every ciphertext/commitment must have the shape
 * the receiver expects (equal-length byte strings of at most the pad width).
 */
export function baseOtReceiverDecrypt(
  choices: number[],
  recvPads: Uint8Array[],
  ct: Array<[Uint8Array, Uint8Array]>,
  com: Array<[Uint8Array, Uint8Array]>,
): Uint8Array[] {
  if (ct.length !== choices.length || com.length !== choices.length || recvPads.length !== choices.length) {
    throw new BaseOtAbort('base OT: ciphertext/commitment count does not match the number of choices; aborting');
  }
  const received: Uint8Array[] = [];
  for (let i = 0; i < choices.length; i++) {
    const ci = choices[i]! & 1;
    const c0 = ct[i]![0];
    const c1 = ct[i]![1];
    if (c0.length !== c1.length || c0.length > SEED_BYTES) {
      throw new BaseOtAbort(`base OT (index ${i}): malformed ciphertext shape; aborting`);
    }
    const m = xorBytes(ct[i]![ci]!, recvPads[i]!);
    const check = otCommit(i, ci, m, recvPads[i]!);
    if (!ctEqual(check, com[i]![ci]!)) {
      throw new BaseOtAbort(`base OT (index ${i}): sender ciphertext inconsistent with its commitment; aborting`);
    }
    received.push(m);
  }
  return received;
}

/**
 * Run `count` MALICIOUS-secure base OTs in one batch (chosen-message, over the random OT above).
 * `messages[i] = [m0, m1]` (SEED_BYTES each), the sender's pair; `choices[i] ∈ {0,1}` the receiver's
 * choice. The sender one-time-pads each message under the random-OT pads and commits to each message;
 * the receiver recovers `m_{i,c_i}` and checks the commitment, aborting (`BaseOtAbort`) on any
 * inconsistency. Returns the receiver's recovered messages and the full transcript.
 */
export function baseOT(
  messages: Array<[Uint8Array, Uint8Array]>,
  choices: number[],
  rng: OtRandom = secureOtRandom(),
  tamper?: BaseOtTamper,
  binding: BaseOtBinding = randomBinding(rng, 'base-ot'),
): BaseOtResult {
  if (messages.length !== choices.length) throw new Error('baseOT: messages/choices length mismatch');
  // The one-time pads are SEED_BYTES wide: a longer message would have its tail sent in the clear.
  const ro = malBaseRandomOT(choices, rng, tamper, binding);
  const { ct, com } = baseOtSenderEncrypt(messages, ro.senderPads);
  // A malicious sender may corrupt the ciphertexts on the wire (inconsistent with the commitment).
  if (tamper?.tamperCiphertext) tamper.tamperCiphertext(ct);
  const received = baseOtReceiverDecrypt(choices, ro.recvPads, ct, com);
  return { received, transcript: { S: ro.S, proof: ro.proof, R: ro.R, ct, com } };
}

// --------------------------------------------------------------------------------------------------
// OT extension — IKNP + KOS, split into the two ROLES so it can run over a real network (`net/offline-net.ts`)
// as well as in-process (`OtChannel` below composes both).
// --------------------------------------------------------------------------------------------------

/** One extension round's receiver -> sender message: the u matrix and the KOS-revealed (x, t) pair. */
export interface ExtRoundMsg {
  /** KAPPA columns of `mExt = m + KAPPA + SSEC` bits each. */
  u: bigint[];
  /** x = Σ_j b_j·χ_j in GF(2^128). */
  x: bigint;
  /** t = Σ_i x^i·(Σ_j t_i[j]·χ_j). */
  tComb: bigint;
}

/** The receiver's private state between sending `ExtRoundMsg` and receiving the sender's ciphertexts. */
export interface ExtPending {
  m: number;
  choiceBits: number[];
  /** The receiver's `t` matrix: COLS columns of `W` u32 words, concatenated. */
  t: Uint32Array;
  W: number;
  /** Channel-global index of this round's first row (R4-12 hash tweak). */
  rowOffset: number;
}

function checkExtInputs(choiceBits: number[], msg0: bigint[] | undefined, msg1: bigint[] | undefined): void {
  const m = choiceBits.length;
  const MSG_LIMIT = 1n << 64n;
  for (let j = 0; j < m; j++) {
    const c = choiceBits[j];
    if (c !== 0 && c !== 1) throw new RangeError(`OtChannel.extend: choice bit ${j} must be 0 or 1`);
  }
  if (msg0 && msg1) {
    for (let j = 0; j < m; j++) {
      const a = msg0[j];
      const b = msg1[j];
      if (typeof a !== 'bigint' || typeof b !== 'bigint' || a < 0n || b < 0n || a >= MSG_LIMIT || b >= MSG_LIMIT) {
        throw new RangeError(`OtChannel.extend: message ${j} must be a bigint in [0, 2^64) (the pad is 64 bits wide)`);
      }
    }
  }
}

/**
 * The OT-extension RECEIVER (holds the choice bits). In the base OT it is the SENDER: it draws κ seed pairs
 * and offers them; after the base OT it expands them with the PRG.
 */
export class OtExtReceiver {
  private readonly rng: OtRandom;
  private readonly kosBinding: Uint8Array;
  private seed0: Uint8Array[] = [];
  private seed1: Uint8Array[] = [];
  private blk0: number[] = [];
  private blk1: number[] = [];
  private round = 0;
  /** Rows hashed in earlier rounds (R4-12 global tweak offset); advanced by m per round, in step with the sender. */
  private rowsDone = 0;
  private readonly tweakDomain: Uint32Array;
  ready = false;
  /**
   * TEST-ONLY: called with the honest `u` matrix just before it goes on the wire; may mutate it (a malicious
   * receiver encoding inconsistent choices). The KOS values are computed over the tampered `u`.
   */
  tamperU?: (u: bigint[], round: number) => void;

  constructor(rng: OtRandom, kosBinding: Uint8Array) {
    this.rng = rng;
    this.kosBinding = kosBinding;
    this.tweakDomain = otTweakDomain(kosBinding);
  }

  /** Base-OT messages: the κ seed pairs this party offers as the base-OT sender. */
  makeSeeds(): Array<[Uint8Array, Uint8Array]> {
    const messages: Array<[Uint8Array, Uint8Array]> = [];
    for (let i = 0; i < KAPPA; i++) {
      const k0 = this.rng.bytes(SEED_BYTES);
      const k1 = this.rng.bytes(SEED_BYTES);
      this.seed0.push(k0);
      this.seed1.push(k1);
      this.blk0.push(0);
      this.blk1.push(0);
      messages.push([k0, k1]);
    }
    this.ready = true;
    return messages;
  }

  /** Round start: form u and the KOS pair for `choiceBits` (the real rows); returns the wire message + pending state. */
  begin(choiceBits: number[]): { msg: ExtRoundMsg; pending: ExtPending } {
    if (!this.ready) throw new Error('OtExtReceiver: base OT not done');
    checkExtInputs(choiceBits, undefined, undefined);
    const m = choiceBits.length;
    const roundIdx = this.round++;
    const rowOffset = this.rowsDone;
    this.rowsDone += m;
    const pad = KAPPA + SSEC;
    const mExt = m + pad;
    const W = (mExt + 31) >>> 5;
    const colBytes = Math.ceil(mExt / 8);
    const bvec = new Uint32Array(W);
    for (let j = 0; j < m; j++) if (choiceBits[j]! & 1) bvec[j >>> 5] = (bvec[j >>> 5]! | (1 << (j & 31))) >>> 0;
    const padBytes = this.rng.bytes(pad);
    for (let p = 0; p < pad; p++) {
      if (padBytes[p]! & 1) {
        const j = m + p;
        bvec[j >>> 5] = (bvec[j >>> 5]! | (1 << (j & 31))) >>> 0;
      }
    }
    const blocks = Math.ceil(W / 4); // 16-byte AES blocks consumed per column
    const t = new Uint32Array(COLS * W);
    const u: bigint[] = new Array(COLS);
    const uw = new Uint32Array(W);
    const ubytes: Uint8Array[] = new Array(COLS);
    for (let i = 0; i < KAPPA; i++) {
      const ti = prgColumn(this.seed0[i]!, this.blk0[i]!, W);
      const gi = prgColumn(this.seed1[i]!, this.blk1[i]!, W);
      this.blk0[i]! += blocks;
      this.blk1[i]! += blocks;
      maskTail(ti, mExt);
      maskTail(gi, mExt);
      t.set(ti, i * W);
      for (let w = 0; w < W; w++) uw[w] = (gi[w]! ^ ti[w]! ^ bvec[w]!) >>> 0;
      ubytes[i] = new Uint8Array(uw.buffer.slice(0, colBytes));
      u[i] = bytesToBig(ubytes[i]!);
    }
    if (this.tamperU) this.tamperU(u, roundIdx);
    const pending: ExtPending = { m, choiceBits: choiceBits.slice(), t, W, rowOffset };
    // A (test-injected) malformed matrix cannot be hashed; send it as is with a zero pair - the sender's
    // structural check aborts on it before any arithmetic.
    const limit = 1n << BigInt(mExt);
    if (u.some((c) => typeof c !== 'bigint' || c < 0n || c >= limit)) {
      return { msg: { u, x: 0n, tComb: 0n }, pending };
    }
    const chi = kosChiWords(this.kosBinding, roundIdx, u, mExt, this.tamperU ? undefined : ubytes);
    const x = new Uint32Array(4);
    accumColumn(bvec, chi, x);
    const tComb = kosCombine(t, W, chi);
    return { msg: { u, x: gfToBig(x), tComb: gfToBig(tComb) }, pending };
  }

  /** Round end: recover the chosen messages from the sender's ciphertexts. */
  finish(pending: ExtPending, y0: bigint[], y1: bigint[]): bigint[] {
    const { m, choiceBits, t, W, rowOffset } = pending;
    if (y0.length !== m || y1.length !== m) throw new MalOtAbort('OT extension: ciphertext count does not match the number of rows; aborting');
    const rows = transposeCols(t, W, m);
    const h = tmmoCrh(rows, m, { offset: rowOffset, domain: this.tweakDomain });
    const received: bigint[] = new Array(m);
    for (let j = 0; j < m; j++) received[j] = (choiceBits[j] === 1 ? y1[j]! : y0[j]!) ^ word64(h, j);
    return received;
  }
}

/** The OT-extension SENDER (holds the message pairs). In the base OT it is the RECEIVER with selector `s`. */
export class OtExtSender {
  private readonly rng: OtRandom;
  private readonly kosBinding: Uint8Array;
  private s: number[] = [];
  private sBits = 0n;
  private seeds: Uint8Array[] = [];
  private blk: number[] = [];
  private round = 0;
  private rowsDone = 0;
  private readonly tweakDomain: Uint32Array;
  ready = false;

  constructor(rng: OtRandom, kosBinding: Uint8Array) {
    this.rng = rng;
    this.kosBinding = kosBinding;
    this.tweakDomain = otTweakDomain(kosBinding);
  }

  /** Draw the secret selector s ∈ {0,1}^κ (the base-OT choice bits). */
  makeSelector(): number[] {
    this.s = Array.from({ length: KAPPA }, () => this.rng.bytes(1)[0]! & 1);
    return this.s.slice();
  }

  /** Install the κ seeds learned from the base OT. */
  setSeeds(seeds: Uint8Array[]): void {
    if (seeds.length !== KAPPA || this.s.length !== KAPPA) throw new Error('OtExtSender: wrong base-OT output size');
    this.seeds = seeds;
    this.blk = new Array(KAPPA).fill(0);
    let acc = 0n;
    for (let i = 0; i < KAPPA; i++) acc |= BigInt(this.s[i]!) << BigInt(i);
    this.sBits = acc;
    this.ready = true;
  }

  get selector(): bigint {
    return this.sBits;
  }

  /**
   * Verify the receiver's round message (structure + KOS correlation check) and return the ciphertexts for
   * the `m` real rows. A cheating receiver is caught here: `MalOtAbort`.
   */
  respond(msg: ExtRoundMsg, msg0: bigint[], msg1: bigint[]): { y0: bigint[]; y1: bigint[] } {
    if (!this.ready) throw new Error('OtExtSender: base OT not done');
    const m = msg0.length;
    if (msg1.length !== m) throw new Error('OtChannel.extend: length mismatch');
    checkExtInputs(new Array<number>(m).fill(0), msg0, msg1);
    const roundIdx = this.round++;
    const rowOffset = this.rowsDone;
    this.rowsDone += m;
    const mExt = m + KAPPA + SSEC;
    const u = msg.u;
    if (!Array.isArray(u) || u.length !== KAPPA) {
      throw new MalOtAbort(`KOS check (round ${roundIdx}): wrong number of u columns; a cheating OT-extension receiver was detected; aborting`);
    }
    // Structural check on what arrived: every column must be an mExt-bit non-negative integer. Bits beyond
    // mExt have no challenge weight, and would otherwise crash the correlation check with an untyped error.
    const colLimit = 1n << BigInt(mExt);
    for (let i = 0; i < KAPPA; i++) {
      const ui = u[i];
      if (typeof ui !== 'bigint' || ui < 0n || ui >= colLimit) {
        throw new MalOtAbort(`KOS check (round ${roundIdx}): malformed u column ${i}; a cheating OT-extension receiver was detected; aborting`);
      }
    }
    const lim128 = 1n << 128n;
    if (typeof msg.x !== 'bigint' || typeof msg.tComb !== 'bigint' || msg.x < 0n || msg.x >= lim128 || msg.tComb < 0n || msg.tComb >= lim128) {
      throw new MalOtAbort(`KOS check (round ${roundIdx}): malformed (x, t); a cheating OT-extension receiver was detected; aborting`);
    }
    const W = (mExt + 31) >>> 5;
    const colBytes = Math.ceil(mExt / 8);
    const blocks = Math.ceil(W / 4);
    // q_i = (s_i ? u_i : 0) ⊕ PRG(k_i^{s_i})  =>  q_i = t_i ⊕ (s_i · bvec) if the receiver is honest.
    const q = new Uint32Array(COLS * W);
    const ubytes: Uint8Array[] = new Array(COLS);
    for (let i = 0; i < KAPPA; i++) {
      ubytes[i] = bigToBytes(u[i]!, colBytes);
      const ks = prgColumn(this.seeds[i]!, this.blk[i]!, W);
      this.blk[i]! += blocks;
      maskTail(ks, mExt);
      if (this.s[i]! === 1) {
        const ub = new Uint8Array(4 * W);
        ub.set(ubytes[i]!);
        const uw = new Uint32Array(ub.buffer, 0, W);
        for (let w = 0; w < W; w++) ks[w] = (ks[w]! ^ uw[w]!) >>> 0;
      }
      q.set(ks, i * W);
    }
    // KOS correlation check (GF(2^128)): Σ χ_j·q_j == t ⊕ x·s with χ bound to the whole u on the wire.
    const chi = kosChiWords(this.kosBinding, roundIdx, u, mExt, ubytes);
    const qComb = gfToBig(kosCombine(q, W, chi));
    const expected = msg.tComb ^ gf128Mul(msg.x, this.sBits);
    if (qComb !== expected) {
      throw new MalOtAbort(`KOS correlation check FAILED (round ${roundIdx}): a cheating OT-extension receiver was detected; aborting`);
    }
    const rows = transposeCols(q, W, m);
    const tweak = { offset: rowOffset, domain: this.tweakDomain };
    const h0 = tmmoCrh(rows, m, tweak);
    const sw = gfFromBig(this.sBits);
    for (let j = 0; j < m; j++) gfXorInto(rows.subarray(4 * j, 4 * j + 4), sw, 0);
    const h1 = tmmoCrh(rows, m, tweak);
    const y0: bigint[] = new Array(m);
    const y1: bigint[] = new Array(m);
    for (let j = 0; j < m; j++) {
      y0[j] = msg0[j]! ^ word64(h0, j);
      y1[j] = msg1[j]! ^ word64(h1, j);
    }
    return { y0, y1 };
  }
}

/**
 * An IKNP/KOS OT-extension channel between a fixed RECEIVER (choice bits) and SENDER (message pairs), both
 * simulated in-process. The κ base OTs run lazily on the first `extend`; each later `extend(m)` is a cheap
 * PRG+hash round. The channel is stateful (advances per-seed PRG counters) so many rounds compose into one
 * amortized setup. The two roles are the standalone `OtExtReceiver` / `OtExtSender` (used over the network).
 */
export class OtChannel {
  private readonly rng: OtRandom;
  /** Optional post-quantum (or otherwise custom) base OT for the κ setup OTs; defaults to EC `baseOT`. */
  private readonly baseOtFn?: BaseOtFn;
  private readonly bindingOpt?: Omit<BaseOtBinding, 'round'>;
  private recv?: OtExtReceiver;
  private send?: OtExtSender;
  private ready = false;

  /** The base-OT transcript (available after setup) — exposed for inspection/tests. */
  baseTranscript?: BaseOtTranscript;

  /**
   * TEST-ONLY injection modelling a MALICIOUS extension RECEIVER: if set, it is called with the honest
   * `u` matrix (κ columns, each `mExt` bits) just before it goes "on the wire", and may mutate it (e.g.
   * XOR a delta into one or more columns) to encode inconsistent choices. The KOS check is computed
   * over the tampered `u` (what the sender sees) while the receiver's revealed `(x, t)` stay honest, so
   * a non-trivial tamper is caught — the real malicious-receiver attack that KOS defeats.
   */
  tamperU?: (u: bigint[], round: number) => void;

  /**
   * `rng` defaults to the CSPRNG (`secureOtRandom`, `node:crypto`) — production randomness. Pass a
   * deterministic `otRandom(splitMix64(seed))` ONLY to make a test bit-reproducible (docs §7.1 item c).
   */
  constructor(
    rng: OtRandom = secureOtRandom(),
    opts?: {
      baseOtFn?: BaseOtFn;
      /**
       * Session binding of this channel (both parties must agree on it). `senderIndex` is the EXTENSION
       * RECEIVER (it plays base-OT sender), `receiverIndex` the extension sender. Omitted for an in-process
       * channel: a fresh random session id is drawn from `rng`.
       */
      binding?: Omit<BaseOtBinding, 'round'>;
    },
  ) {
    this.rng = rng;
    this.baseOtFn = opts?.baseOtFn;
    this.bindingOpt = opts?.binding;
  }

  private setup(): void {
    const base = this.bindingOpt ?? randomBinding(this.rng, 'x');
    const binding = { sessionId: base.sessionId, senderIndex: base.senderIndex, receiverIndex: base.receiverIndex };
    const kos = bindingBytes({ ...binding, round: 'iknp-kos' });
    const recv = new OtExtReceiver(this.rng, kos);
    const send = new OtExtSender(this.rng, kos);
    // Extension-RECEIVER is the base-SENDER: it generates κ seed pairs; the extension-SENDER is the
    // base-RECEIVER with selector s: it learns k_i^{s_i}.
    const messages = recv.makeSeeds();
    const s = send.makeSelector();
    if (this.baseOtFn) {
      // Custom (e.g. post-quantum ML-KEM) base OT: its transcript shape differs, so leave the
      // EC-typed `baseTranscript` unset.
      send.setSeeds(this.baseOtFn(messages, s, this.rng).received);
    } else {
      const baseRes = baseOT(messages, s, this.rng, undefined, { ...binding, round: 'iknp-kappa-setup' });
      send.setSeeds(baseRes.received);
      this.baseTranscript = baseRes.transcript;
    }
    this.recv = recv;
    this.send = send;
    this.ready = true;
  }

  /** Selector s as a κ-bit bigint (sender-side secret; exposed only for tests). */
  get selector(): bigint {
    if (!this.ready) this.setup();
    return this.send!.selector;
  }

  /**
   * One MALICIOUS-secure extension round: `choiceBits[j] ∈ {0,1}` (receiver), `msg0[j]/msg1[j]`
   * field-element messages (sender). Returns the receiver's chosen messages `msg_{choiceBits[j]}[j]`
   * for the `m` real rows. The round transparently appends `κ + SSEC` random check-OT rows and runs the
   * **KOS correlation check** over all `m + κ + SSEC` rows; a cheating receiver (tampered `u`) is caught
   * there and the round throws `MalOtAbort`. `uMatrix` (the receiver→sender wire message, now
   * `mExt`-bit) is returned for tests.
   */
  extend(
    choiceBits: number[],
    msg0: bigint[],
    msg1: bigint[],
  ): { received: bigint[]; uMatrix: bigint[] } {
    if (!this.ready) this.setup();
    const m = choiceBits.length;
    if (msg0.length !== m || msg1.length !== m) throw new Error('OtChannel.extend: length mismatch');
    if (m === 0) return { received: [], uMatrix: [] };
    checkExtInputs(choiceBits, msg0, msg1);
    this.recv!.tamperU = this.tamperU;
    const { msg, pending } = this.recv!.begin(choiceBits);
    const { y0, y1 } = this.send!.respond(msg, msg0, msg1);
    return { received: this.recv!.finish(pending, y0, y1), uMatrix: msg.u };
  }
}
