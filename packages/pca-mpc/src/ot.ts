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
 *     who deviated in `u` satisfies it with probability ≤ `2^{-κ} = 2^{-128}`, so a deviation ABORTS.
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
import { gf128Add, gf128Mul, gf128MulByXi } from './gf128';
import { secureOtRandom } from './csprng';

/** IKNP security parameter (number of base OTs / width of the selector s). */
export const KAPPA = 128;

/**
 * KOS statistical-security parameter: the number of EXTRA random check-OT rows (beyond the `κ` that
 * mask the revealed combination) appended to every extension round. Together `κ + SSEC` padding rows
 * give the correlation check its receiver-privacy and statistical soundness margin.
 */
export const SSEC = 64;

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
      // Assemble 256 bits then reduce mod L; reject 0.
      for (;;) {
        let acc = 0n;
        for (let i = 0; i < 4; i++) acc = (acc << 64n) | next64();
        const s = acc % L;
        if (s !== 0n) return s;
      }
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

/** Key-derivation from a group point: H("ot-kdf" ‖ index ‖ encode(P)) → SEED_BYTES bytes. */
function kdfPoint(index: number, p: Point): Uint8Array {
  return sha256(TAG_KDF, u32(index), encodePoint(p)).slice(0, SEED_BYTES);
}
const TAG_KDF = new TextEncoder().encode('atlas-pca-mpc/ot-kdf');
const TAG_PRG = new TextEncoder().encode('atlas-pca-mpc/ot-prg');
const TAG_CRH = new TextEncoder().encode('atlas-pca-mpc/ot-crh');
const TAG_KOS = new TextEncoder().encode('atlas-pca-mpc/ot-kos');
const TAG_COMMIT = new TextEncoder().encode('atlas-pca-mpc/ot-msg-commit');

/**
 * Derive the KOS row-weights χ_j ∈ GF(2^128) for one extension round, bound to the committed `u`
 * matrix (Fiat–Shamir). The sender and receiver both derive the SAME χ from the `u` on the wire, so a
 * cheating receiver cannot pick `u` after seeing χ. In the real protocol χ comes from a secure
 * coin-flip after the receiver commits to `u`; the transcript-hash here models that round and keeps the
 * check deterministic for tests. The seed expands through a fast (non-crypto) stream — fine because χ
 * only needs to be unpredictable-before-commit and uniform, which the hash seed provides.
 */
function kosChallenges(u: bigint[], mExt: number): bigint[] {
  const h = createHash('sha256');
  h.update(TAG_KOS);
  h.update(u32(u.length));
  const buf = new Uint8Array(SEED_BYTES);
  for (const col of u) {
    let v = col;
    for (let i = 0; i < SEED_BYTES; i++) {
      buf[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    h.update(buf);
  }
  const digest = new Uint8Array(h.digest());
  let lo = 0n;
  for (let i = 0; i < 8; i++) lo |= BigInt(digest[i]!) << BigInt(8 * i);
  let hi = 0n;
  for (let i = 8; i < 16; i++) hi |= BigInt(digest[i]!) << BigInt(8 * (i - 8));
  const s0 = splitMix64(lo === 0n ? 1n : lo);
  const s1 = splitMix64(hi === 0n ? 0x9e3779b97f4a7c15n : hi);
  const chi: bigint[] = new Array(mExt);
  for (let j = 0; j < mExt; j++) chi[j] = (s0() << 64n) | s1();
  return chi;
}

/** XOR into `acc` the χ_j for every SET bit `j` of the (≤ mExt-bit) column `col`, fast via 32-bit words. */
function accumSetBits(col: bigint, chi: bigint[], acc: bigint): bigint {
  let v = col;
  let base = 0;
  while (v > 0n) {
    let w = Number(v & 0xffffffffn) >>> 0;
    v >>= 32n;
    while (w !== 0) {
      const b = w & -w; // lowest set bit
      const j = base + (31 - Math.clz32(b));
      acc = gf128Add(acc, chi[j]!);
      w ^= b;
    }
    base += 32;
  }
  return acc;
}

/** XOR two equal-length byte arrays. */
function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

/** PRG: expand a seed to `nbits` bits as a bigint, from block offset `startBlock` (counter mode). */
function prgBits(seed: Uint8Array, startBlock: number, nbits: number): bigint {
  const nBlocks = Math.ceil(nbits / 256);
  let acc = 0n;
  let produced = 0;
  for (let t = 0; t < nBlocks; t++) {
    const block = sha256(TAG_PRG, seed, u32(startBlock + t));
    for (let i = 0; i < 32 && produced < nbits; i++) {
      acc |= BigInt(block[i]!) << BigInt(produced);
      produced += 8;
    }
  }
  // Mask to exactly nbits.
  return acc & ((1n << BigInt(nbits)) - 1n);
}

/** Correlation-robust hash H(j, row) → a 64-bit mask (field messages are < 2^61). */
function crh(j: number, row: bigint): bigint {
  const rowBytes = new Uint8Array(SEED_BYTES);
  let v = row;
  for (let i = 0; i < SEED_BYTES; i++) {
    rowBytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  const d = sha256(TAG_CRH, u32(j), rowBytes);
  let acc = 0n;
  for (let i = 0; i < 8; i++) acc |= BigInt(d[i]!) << BigInt(8 * i);
  return acc;
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
): MalRandomOtResult {
  const count = choices.length;

  // --- Sender setup: S = y·B, T = y·S, and a Schnorr proof of knowledge of y. ---
  const y = rng.scalar();
  const S0 = mulBase(y);
  const Tpt = mul(y, S0); // T = y·S = y²·B
  const proof0 = schnorrProve(y, S0, () => rng.scalar());

  // What actually goes on the wire (a malicious sender may tamper either).
  const S = tamper?.tamperS ? tamper.tamperS(S0) : S0;
  const proof = tamper?.tamperProof ? tamper.tamperProof(proof0) : proof0;

  // --- Receiver: validate the sender's point + proof BEFORE forming any R (malicious-sender guard). ---
  assertInSubgroup(S, 'base-OT S (received by receiver)');
  if (!schnorrVerify(S, proof)) {
    throw new BaseOtAbort('base OT: sender Schnorr proof-of-knowledge of S=y·B failed; aborting');
  }

  // --- Receiver: choose x_i, form R_i = x_i·B (+ S if c_i=1), derive recvPad_i = H(x_i·S). ---
  const R: Point[] = [];
  const recvPads: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    const x = rng.scalar();
    const ci = choices[i]! & 1;
    const Ri = ci === 1 ? add(mulBase(x), S) : mulBase(x);
    R.push(Ri);
    recvPads.push(kdfPoint(i, mul(x, S)));
  }

  // A malicious receiver may tamper the R it sends on the wire (test-injected).
  if (tamper?.tamperR) tamper.tamperR(R);

  // --- Sender: validate every received R_i (malicious-receiver / small-subgroup guard), then derive pads. ---
  const senderPads: Array<[Uint8Array, Uint8Array]> = [];
  for (let i = 0; i < count; i++) {
    assertInSubgroup(R[i]!, `base-OT R_${i} (received by sender)`);
    const yR = mul(y, R[i]!);
    senderPads.push([kdfPoint(i, yR), kdfPoint(i, sub(yR, Tpt))]);
  }

  return { S, proof, R, senderPads, recvPads };
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
): BaseOtResult {
  if (messages.length !== choices.length) throw new Error('baseOT: messages/choices length mismatch');
  const count = messages.length;

  const ro = malBaseRandomOT(choices, rng, tamper);

  // Sender: E_{i,b} = m_{i,b} ⊕ pad_{i,b}, and commit com_{i,b} = H(i ‖ b ‖ m_{i,b} ‖ pad_{i,b}).
  const ct: Array<[Uint8Array, Uint8Array]> = [];
  const com: Array<[Uint8Array, Uint8Array]> = [];
  for (let i = 0; i < count; i++) {
    const [p0, p1] = ro.senderPads[i]!;
    ct.push([xorBytes(messages[i]![0], p0), xorBytes(messages[i]![1], p1)]);
    com.push([otCommit(i, 0, messages[i]![0], p0), otCommit(i, 1, messages[i]![1], p1)]);
  }

  // A malicious sender may corrupt the ciphertexts on the wire (inconsistent with the commitment).
  if (tamper?.tamperCiphertext) tamper.tamperCiphertext(ct);

  // Receiver: decrypt the chosen ciphertext with its pad, then CHECK the commitment it can open.
  const received: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    const ci = choices[i]! & 1;
    const m = xorBytes(ct[i]![ci]!, ro.recvPads[i]!);
    const check = otCommit(i, ci, m, ro.recvPads[i]!);
    if (!ctEqual(check, com[i]![ci]!)) {
      throw new BaseOtAbort(
        `base OT (index ${i}): sender ciphertext inconsistent with its commitment; aborting`,
      );
    }
    received.push(m);
  }

  return { received, transcript: { S: ro.S, proof: ro.proof, R: ro.R, ct, com } };
}

// --------------------------------------------------------------------------------------------------
// OT extension — IKNP (semi-honest), as a stateful in-process channel for one (receiver, sender) pair.
// --------------------------------------------------------------------------------------------------

/**
 * An IKNP OT-extension channel between a fixed RECEIVER (choice bits) and SENDER (message pairs). The
 * κ base OTs run lazily on the first `extend`; each later `extend(m)` is a cheap PRG+hash round. The
 * channel is stateful (advances per-seed PRG counters) so many rounds compose into one amortized setup.
 */
export class OtChannel {
  private readonly rng: OtRandom;
  /** Optional post-quantum (or otherwise custom) base OT for the κ setup OTs; defaults to EC `baseOT`. */
  private readonly baseOtFn?: BaseOtFn;
  private ready = false;

  // Extension-sender state: selector s (κ bits) and the κ seeds it learned (k_i^{s_i}).
  private s: number[] = [];
  private sBits = 0n; // s packed as a κ-bit bigint (cached)
  private senderSeeds: Uint8Array[] = [];
  private senderBlk: number[] = [];

  // Extension-receiver state: κ seed pairs.
  private recvSeed0: Uint8Array[] = [];
  private recvSeed1: Uint8Array[] = [];
  private recvBlk0: number[] = [];
  private recvBlk1: number[] = [];

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
  private round = 0;

  /**
   * `rng` defaults to the CSPRNG (`secureOtRandom`, `node:crypto`) — production randomness. Pass a
   * deterministic `otRandom(splitMix64(seed))` ONLY to make a test bit-reproducible (docs §7.1 item c).
   */
  constructor(rng: OtRandom = secureOtRandom(), opts?: { baseOtFn?: BaseOtFn }) {
    this.rng = rng;
    this.baseOtFn = opts?.baseOtFn;
  }

  private setup(): void {
    // Extension-RECEIVER is the base-SENDER: it generates κ seed pairs.
    const messages: Array<[Uint8Array, Uint8Array]> = [];
    for (let i = 0; i < KAPPA; i++) {
      const k0 = this.rng.bytes(SEED_BYTES);
      const k1 = this.rng.bytes(SEED_BYTES);
      this.recvSeed0.push(k0);
      this.recvSeed1.push(k1);
      this.recvBlk0.push(0);
      this.recvBlk1.push(0);
      messages.push([k0, k1]);
    }
    // Extension-SENDER is the base-RECEIVER with selector s: it learns k_i^{s_i}.
    this.s = Array.from({ length: KAPPA }, () => {
      const b = this.rng.bytes(1);
      return b[0]! & 1;
    });
    if (this.baseOtFn) {
      // Custom (e.g. post-quantum ML-KEM) base OT: its transcript shape differs, so leave the
      // EC-typed `baseTranscript` unset.
      this.senderSeeds = this.baseOtFn(messages, this.s, this.rng).received;
    } else {
      const base = baseOT(messages, this.s, this.rng);
      this.senderSeeds = base.received;
      this.baseTranscript = base.transcript;
    }
    this.senderBlk = new Array(KAPPA).fill(0);
    let acc = 0n;
    for (let i = 0; i < KAPPA; i++) acc |= BigInt(this.s[i]!) << BigInt(i);
    this.sBits = acc;
    this.ready = true;
  }

  /** Selector s as a κ-bit bigint (sender-side secret; exposed only for tests). */
  get selector(): bigint {
    if (!this.ready) this.setup();
    return this.sBits;
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

    const roundIdx = this.round++;

    // --- KOS padding: append κ+SSEC random check-OT rows (no messages are transferred for them). ---
    const pad = KAPPA + SSEC;
    const mExt = m + pad;
    const padChoice: number[] = new Array(pad);
    for (let p = 0; p < pad; p++) padChoice[p] = this.rng.bytes(1)[0]! & 1;

    // Full choice vector (real ‖ padding) as an mExt-bit bigint, and a per-row accessor for the check.
    let bvec = 0n;
    for (let j = 0; j < m; j++) if (choiceBits[j]! & 1) bvec |= 1n << BigInt(j);
    for (let p = 0; p < pad; p++) if (padChoice[p]! & 1) bvec |= 1n << BigInt(m + p);

    const blocks = Math.ceil(mExt / 256);

    // Receiver forms t_i, u_i = PRG(k1) ⊕ t_i ⊕ bvec  (over all mExt rows).
    const t: bigint[] = new Array(KAPPA);
    const u: bigint[] = new Array(KAPPA);
    for (let i = 0; i < KAPPA; i++) {
      const ti = prgBits(this.recvSeed0[i]!, this.recvBlk0[i]!, mExt);
      const gi = prgBits(this.recvSeed1[i]!, this.recvBlk1[i]!, mExt);
      this.recvBlk0[i]! += blocks;
      this.recvBlk1[i]! += blocks;
      t[i] = ti;
      u[i] = gi ^ ti ^ bvec;
    }

    // A malicious receiver may tamper the u it sends on the wire (test-injected).
    if (this.tamperU) this.tamperU(u, roundIdx);

    // Sender computes q_i = (s_i ? u_i : 0) ⊕ PRG(k_i^{s_i}).  => q_i = t_i ⊕ (s_i · bvec) if honest.
    const q: bigint[] = new Array(KAPPA);
    for (let i = 0; i < KAPPA; i++) {
      const ks = prgBits(this.senderSeeds[i]!, this.senderBlk[i]!, mExt);
      this.senderBlk[i]! += blocks;
      q[i] = (this.s[i]! === 1 ? u[i]! : 0n) ^ ks;
    }

    const sBits = this.sBits;

    // --- KOS correlation check (GF(2^128), column-domain fold over all mExt rows). ---
    // χ_j bound to the (possibly tampered) u on the wire. Receiver reveals x = Σ b_j·χ_j and
    // t_comb = Σ χ_j·t_j; sender checks Σ χ_j·q_j == t_comb ⊕ x·s. Honestly q_j = t_j ⊕ b_j·s so it
    // holds; a receiver who tampered u passes with prob ≤ 2^{-128}, else ABORT.
    const chi = kosChallenges(u, mExt);
    // x = Σ_{j: b_j=1} χ_j  (receiver side; over real + padding choices, so real choices stay masked).
    let x = 0n;
    x = accumSetBits(bvec, chi, x);
    // t_comb = Σ_i (Σ_{j: t_i has bit j} χ_j)·x^i ;  q_comb likewise from q_i.
    let tComb = 0n;
    let qComb = 0n;
    for (let i = 0; i < KAPPA; i++) {
      const at = accumSetBits(t[i]!, chi, 0n);
      const aq = accumSetBits(q[i]!, chi, 0n);
      tComb = gf128Add(tComb, gf128MulByXi(at, i));
      qComb = gf128Add(qComb, gf128MulByXi(aq, i));
    }
    const expected = gf128Add(tComb, gf128Mul(x, sBits));
    if (qComb !== expected) {
      throw new MalOtAbort(
        `KOS correlation check FAILED (round ${roundIdx}): a cheating OT-extension receiver was detected; aborting`,
      );
    }

    // --- Only the m real rows carry messages. Sender: y0_j = msg0_j ⊕ H(j,qrow_j), y1 ⊕ H(j,qrow⊕s). ---
    const y0: bigint[] = new Array(m);
    const y1: bigint[] = new Array(m);
    for (let j = 0; j < m; j++) {
      let qrow = 0n;
      for (let i = 0; i < KAPPA; i++) qrow |= ((q[i]! >> BigInt(j)) & 1n) << BigInt(i);
      y0[j] = msg0[j]! ^ crh(j, qrow);
      y1[j] = msg1[j]! ^ crh(j, qrow ^ sBits);
    }

    // Receiver: recovered_j = y_{b_j}[j] ⊕ H(j, trow_j).
    const received: bigint[] = new Array(m);
    for (let j = 0; j < m; j++) {
      let trow = 0n;
      for (let i = 0; i < KAPPA; i++) trow |= ((t[i]! >> BigInt(j)) & 1n) << BigInt(i);
      const bj = choiceBits[j]! & 1;
      received[j] = (bj === 1 ? y1[j]! : y0[j]!) ^ crh(j, trow);
    }

    return { received, uMatrix: u };
  }
}
