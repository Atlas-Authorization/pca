/**
 * TRUE post-quantum, maliciously-secure base OT — the ENDEMIC OT of Masny–Rindal (ePrint 2019/706)
 * instantiated over Module-LWE (Kyber-768 K-PKE), the RECOMMENDED / default PQ base OT for this stack.
 *
 * ─── WHY THIS EXISTS ────────────────────────────────────────────────────────────────────────────────
 * The semi-honest ML-KEM base OT (`kem-ot.ts`) has an INTRINSIC residue against a malicious receiver:
 * a receiver can run KEM keygen twice and keep BOTH secret keys, learning both messages, and the
 * decisional-MLWE indistinguishability that gives it choice privacy makes that cheat undetectable to
 * the sender. `hybrid-ot.ts` masks the residue with a *classical* EC half, but a receiver that is
 * SIMULTANEOUSLY quantum AND malicious defeats the EC half with Shor. This module closes the residue
 * in ONE post-quantum primitive: the receiver provably cannot form two decryptable branches, because
 * one branch's public key is forced to be a UNIFORM ring element through a random oracle.
 *
 * ─── THE CONSTRUCTION (faithful to libOTe's `MasnyRindal`, group → lattice) ──────────────────────────
 * libOTe's battle-tested `MasnyRindal` base OT works in a group `G` with a hash-to-group RO `H`:
 *   • sender publishes `S = s·G`;
 *   • receiver (choice `c`) picks `r` and a random point `N`, sets the CHOICE point `C = r·G − H(N)`,
 *     places `C` at slot `c` and `N` at slot `1−c`, and sends the pair;
 *   • sender derives, per slot `b`, `shared_b = s·(P_b + H(P_{1−b}))`, so `shared_c = s·r·G = r·S`
 *     (which the receiver recomputes) while `shared_{1−c} = s·(N + H(C))` needs the discrete log of a
 *     fresh RO point — a CDH the receiver cannot solve.
 * We keep this EXACT additive structure but replace the group's Diffie–Hellman with Kyber K-PKE, where
 * the "group" is the public-key ring-vector space `R_q^k` (an additive group) and `H` hashes to a
 * UNIFORM ring vector (the standard FIPS-203 `SampleNTT` sampler — the one Kyber uses for its matrix A):
 *
 *   RECEIVER (choice `c`, transfer `i`), with session nonce `rn` and `sid = H(rn)`:
 *     • real K-PKE keygen -> public key `(t̂_real ‖ rho)`, secret key `sk`;
 *     • sample a UNIFORM ring vector `N` (the non-chosen slot's value);
 *     • `C = t̂_real − Hpk(sid, i, N)`   (ring subtraction, `Hpk` = hash-to-uniform-ring);
 *     • place `C` at slot `c`, `N` at slot `1−c`; send the ordered pair `(P_0, P_1)` and `rho`.
 *   SENDER (random payloads `ρ_0, ρ_1 ∈ {0,1}^256`), per transfer:
 *     • effective public key per slot:  `t̂_b = P_b + Hpk(sid, i, P_{1−b})`, `pk_b = (t̂_b ‖ rho)`;
 *       -> `t̂_c = C + Hpk(sid,i,N) = t̂_real` (a REAL key, the receiver holds its `sk`), while
 *          `t̂_{1−c} = N + Hpk(sid,i,C)` is `N +` a FRESH uniform RO value = UNIFORM (no secret exists);
 *     • K-PKE CPA-encrypt `ρ_b` under `pk_b` -> `ct_b`; pad `k_b = Hpad(sid,i,b,ρ_b)`; send `(ct_0,ct_1)`.
 *   RECEIVER recovers ONLY slot `c`:  `ρ_c = Dec(sk, ct_c)`,  `k_c = Hpad(sid,i,c,ρ_c)`.
 * (The chosen-message wrapper one-time-pads `m_b` under `k_b` and adds an RO commitment, exactly like
 * the EC `baseOT`, so a malicious sender's inconsistent ciphertext is caught — `EndemicLweOtAbort`.)
 *
 * ─── SECURITY ACHIEVED (precise, post-quantum, honest) ───────────────────────────────────────────────
 *   • SENDER PRIVACY — the ENDEMIC property: a (even malicious) receiver cannot learn `m_{1−c}`.
 *     Its branch `1−c` has a UNIFORM public key `t̂_{1−c}`; recovering the payload `ρ_{1−c}` from
 *     `ct_{1−c}` is exactly breaking the semantic (IND-CPA) security of K-PKE encryption under a
 *     UNIFORM public key — which is the standard Kyber IND-CPA "hybrid-1" game and REDUCES TO
 *     DECISIONAL MODULE-LWE. Concretely: for a uniform `t̂`, the ciphertext `(u = Aᵀr+e₁, v = t̂ᵀr+e₂+ρ)`
 *     is pseudorandom under dMLWE on the encryption randomness `r` (with the uniform `t̂` supplying the
 *     extra row), so `ρ_{1−c}` — hence `k_{1−c}`, hence `m_{1−c}` — is hidden. And a malicious receiver
 *     CANNOT make BOTH branches decryptable: fixing slot `c` to a real key determines `P_c`, so
 *     `Hpk(sid,i,P_c)` is a FRESH uniform RO value and `t̂_{1−c}=P_{1−c}+Hpk(sid,i,P_c)` is uniform;
 *     finding a low-norm secret for a uniform target is Module-SIS-hard. (This is the residue the
 *     opaque ML-KEM base OT could not close.)
 *   • RECEIVER (CHOICE) PRIVACY — COMPUTATIONAL under decisional Module-LWE, even against a malicious
 *     or QUANTUM sender. The wire carries `(P_0, P_1, rho)`; the sender derives `t̂_0, t̂_1`, exactly ONE
 *     of which is a real MLWE sample `A∘ŝ+ê` (the chosen branch) and the other uniform. Telling which
 *     index is the real key is precisely decisional Module-LWE. (Unlike the group/DDH instantiation,
 *     this is computational, not statistical — a real lattice key is not uniform; we do NOT overclaim.)
 *   • POST-QUANTUM: both guarantees rest only on Module-LWE (ML-KEM-768, NIST category 3) + a random
 *     oracle (SHAKE/SHA3). No discrete log anywhere.
 *
 * ─── COMPOSITION WITH KOS (how this becomes many malicious OTs) ──────────────────────────────────────
 * `OtChannel` consumes this as its `κ = 128` setup base OTs, with ROLES INVERTED: the extension SENDER
 * plays base-RECEIVER holding the secret selector `s`, and the extension RECEIVER plays base-SENDER
 * providing the `κ` seed pairs. The two endemic guarantees are exactly what the KOS layer needs:
 *   • base receiver-privacy (dMLWE) hides the extension sender's selector `s` from a malicious
 *     extension receiver — the property IKNP relies on for the unchosen messages to stay hidden; and
 *   • the endemic "learn ≤ one" property means the extension sender learns exactly one seed per pair.
 * The KOS correlation check over the sacrifice rows then upgrades the whole extension to
 * MALICIOUS-with-abort against a cheating extension receiver (the IKNP attack). So endemic base OTs +
 * the existing KOS check in `ot.ts` = maliciously-secure, post-quantum OT. Endemic security is a
 * (deliberately) weaker notion in which corrupt parties may fix their own outputs; lifting it to
 * standard malicious OT via actively-secure OT extension is precisely the Masny–Rindal result, and the
 * KOS layer here is unchanged — only the base is swapped. The `extend`-level tests prove the composed
 * results are IDENTICAL to the EC and ML-KEM bases.
 *
 * ─── HONEST RESIDUAL ─────────────────────────────────────────────────────────────────────────────────
 * The Kyber core is the vetted `pqc_kyber` reference compiled to WASM (`@atlasauth/pca-mpc-lwe-ot-wasm`);
 * it is a PROTOTYPE and is NOT claimed constant-time (same caveat as `kem-ot.ts`/`ec.ts`, docs §7.1) —
 * a documented side-channel boundary, not a break of the stated MLWE/ROM security. Decryption of K-PKE
 * has a negligible (~2⁻¹³⁹ for Kyber-768) failure probability, inherited from the primitive.
 *
 * No hand-rolled lattice crypto: keygen / CPA-encrypt / CPA-decrypt and the uniform-ring sampler all go
 * through the vetted crate; this module only hashes (SHA-256 RO), XORs, and marshals byte vectors.
 */

import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { secureOtRandom } from './csprng';
import { type BaseOtFn, type OtChannel, type OtRandom } from './ot';

// ===================================================================================================
// The vetted Kyber-768 lattice core (`@atlasauth/pca-mpc-lwe-ot-wasm`): keygen / CPA enc / CPA dec,
// ring add/sub on a serialized `t̂`, and hash-to-uniform-ring. Loaded once; a hard dependency (unlike
// the EC wasm core, there is no pure-JS fallback — the Module-LWE arithmetic MUST be the vetted crate).
// ===================================================================================================

/** The subset of the lattice core's surface consumed here (see `@atlasauth/pca-mpc-lwe-ot-wasm`). */
interface LatticeCore {
  readonly PK_BYTES: number;
  readonly SK_BYTES: number;
  readonly CT_BYTES: number;
  readonly TVEC_BYTES: number;
  readonly SYM_BYTES: number;
  kpkeKeygen(seed: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
  kpkeEnc(publicKey: Uint8Array, message: Uint8Array, coins: Uint8Array): Uint8Array;
  kpkeDec(secretKey: Uint8Array, ciphertext: Uint8Array): Uint8Array;
  ringAdd(a: Uint8Array, b: Uint8Array): Uint8Array;
  ringSub(a: Uint8Array, b: Uint8Array): Uint8Array;
  hashToRing(input: Uint8Array): Uint8Array;
}

/** Narrow an opaque module to the `LatticeCore` surface without `any` — every member must be present. */
function asLatticeCore(mod: unknown): LatticeCore | null {
  if (typeof mod !== 'object' || mod === null) return null;
  const m = mod as Record<string, unknown>;
  const fns = ['kpkeKeygen', 'kpkeEnc', 'kpkeDec', 'ringAdd', 'ringSub', 'hashToRing'];
  for (const name of fns) if (typeof m[name] !== 'function') return null;
  const nums = ['PK_BYTES', 'SK_BYTES', 'CT_BYTES', 'TVEC_BYTES', 'SYM_BYTES'];
  for (const name of nums) if (typeof m[name] !== 'number') return null;
  return mod as LatticeCore;
}

function loadLatticeCore(): LatticeCore {
  const require = createRequire(__filename);
  const candidates = [
    '@atlasauth/pca-mpc-lwe-ot-wasm',
    join(__dirname, '..', '..', 'pca-mpc-lwe-ot-wasm', 'dist', 'index.js'),
  ];
  for (const spec of candidates) {
    try {
      const loaded = asLatticeCore(require(spec));
      if (loaded !== null) return loaded;
    } catch {
      // try the next candidate
    }
  }
  throw new Error(
    'endemic-ot: could not load @atlasauth/pca-mpc-lwe-ot-wasm (the Kyber lattice core is required; ' +
      'build it with `pnpm --filter @atlasauth/pca-mpc-lwe-ot-wasm build:wasm && ... build`)',
  );
}

const core: LatticeCore = loadLatticeCore();

/** Kyber-768 byte sizes, surfaced from the lattice core. */
export const PK_BYTES = core.PK_BYTES;
export const SK_BYTES = core.SK_BYTES;
export const CT_BYTES = core.CT_BYTES;
export const TVEC_BYTES = core.TVEC_BYTES;
export const SYM_BYTES = core.SYM_BYTES;

/** Re-export the vetted lattice primitives (used by the hybrid combiner alternatives and the tests). */
export const kpkeKeygen = core.kpkeKeygen.bind(core);
export const kpkeEnc = core.kpkeEnc.bind(core);
export const kpkeDec = core.kpkeDec.bind(core);
export const ringAdd = core.ringAdd.bind(core);
export const ringSub = core.ringSub.bind(core);
export const hashToRing = core.hashToRing.bind(core);

// ===================================================================================================
// Random-oracle helpers (SHA-256 based, domain-separated). The hash-to-uniform-ring oracle lives in
// the wasm core; here we build its input and the pad / commitment / session-id oracles.
// ===================================================================================================

const TAG_SID = new TextEncoder().encode('atlas-pca-mpc/endemic-lwe-ot-sid');
const TAG_HPK = new TextEncoder().encode('atlas-pca-mpc/endemic-lwe-ot-hpk');
const TAG_N = new TextEncoder().encode('atlas-pca-mpc/endemic-lwe-ot-N');
const TAG_PAD = new TextEncoder().encode('atlas-pca-mpc/endemic-lwe-ot-pad');
const TAG_COMMIT = new TextEncoder().encode('atlas-pca-mpc/endemic-lwe-ot-commit');

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

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) throw new Error('endemic-ot: XOR length mismatch');
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** The session id `sid = H(TAG ‖ rn)` binding every RO query to this OT instance's receiver nonce. */
export function endemicSessionId(rn: Uint8Array): Uint8Array {
  return sha256(TAG_SID, rn);
}

/** `Hpk(sid, i, other)` — the uniform ring vector the branch's effective key is offset by; `other` is
 *  the OTHER slot's value (mirrors libOTe keying `H` by the opposite point). */
function hpk(sid: Uint8Array, i: number, other: Uint8Array): Uint8Array {
  return core.hashToRing(concat(TAG_HPK, sid, u32(i), other));
}

/** The one-time pad / random-OT output for a slot: `H(TAG ‖ sid ‖ i ‖ slot ‖ ctr ‖ ρ)` to `len` bytes. */
function padBytes(sid: Uint8Array, i: number, slot: number, payload: Uint8Array, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let produced = 0;
  let ctr = 0;
  while (produced < len) {
    const block = sha256(TAG_PAD, sid, u32(i), Uint8Array.of(slot & 1), u32(ctr), payload);
    for (let k = 0; k < block.length && produced < len; k++) out[produced++] = block[k]!;
    ctr++;
  }
  return out;
}

/**
 * The endemic random-OT pad oracle, exposed for the hybrid combiner and the security tests:
 * `H(TAG ‖ sid ‖ i ‖ slot ‖ ρ)` expanded to `len` bytes, where `ρ` is the K-PKE payload of that slot.
 */
export function endemicLwePad(
  sid: Uint8Array,
  index: number,
  slot: number,
  payload: Uint8Array,
  len: number,
): Uint8Array {
  return padBytes(sid, index, slot, payload, len);
}

/** Per-message RO commitment `com = H(TAG ‖ sid ‖ i ‖ slot ‖ msg ‖ pad)`. */
function commitBytes(sid: Uint8Array, i: number, slot: number, msg: Uint8Array, pad: Uint8Array): Uint8Array {
  return sha256(TAG_COMMIT, sid, u32(i), Uint8Array.of(slot & 1), msg, pad);
}

// ===================================================================================================
// Protocol, as explicit rounds (matching the in-process, transcript-returning style of kem-ot.ts).
// ===================================================================================================

/** Byte length of a derived endemic random-OT shared secret (= a K-PKE payload). */
export const ENDEMIC_SECRET_BYTES = SYM_BYTES;

/** Raised when the endemic base OT aborts: a malicious sender's ciphertext fails its RO commitment. */
export class EndemicLweOtAbort extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EndemicLweOtAbort';
  }
}

/** Receiver round-1 wire message. */
export interface EndemicLweReceiverMessage {
  /** Receiver session nonce. */
  rn: Uint8Array;
  /** For each transfer i, the ordered ring-vector pair `[P_0, P_1]` (each `TVEC_BYTES`). */
  points: Array<[Uint8Array, Uint8Array]>;
  /** For each transfer i, the shared matrix seed `rho` (32 B) of that transfer's real keypair. */
  rhos: Uint8Array[];
}

/** The receiver's retained state (it keeps only the chosen branch's secret key). */
export interface EndemicLweReceiverState {
  choices: number[];
  /** `secretKeys[i]` is the IND-CPA secret key for the receiver's real key placed at slot `choices[i]`. */
  secretKeys: Uint8Array[];
  rhos: Uint8Array[];
  rn: Uint8Array;
  sid: Uint8Array;
}

/**
 * RECEIVER round 1: for each choice bit, generate a real K-PKE keypair, sample a uniform ring vector
 * `N`, set the choice vector `C = t̂_real − Hpk(sid,i,N)`, place `C` at slot `c` and `N` at slot `1−c`,
 * send the ordered pair + `rho`, and retain only the chosen branch's secret key.
 */
export function endemicLweReceive(
  choices: number[],
  rng: OtRandom = secureOtRandom(),
): { message: EndemicLweReceiverMessage; state: EndemicLweReceiverState } {
  const rn = rng.bytes(SYM_BYTES);
  const sid = endemicSessionId(rn);
  const points: Array<[Uint8Array, Uint8Array]> = [];
  const rhos: Uint8Array[] = [];
  const secretKeys: Uint8Array[] = [];
  const retained: number[] = [];
  for (let i = 0; i < choices.length; i++) {
    const c = choices[i]! & 1;
    const { publicKey, secretKey } = core.kpkeKeygen(rng.bytes(SYM_BYTES));
    const tReal = publicKey.slice(0, TVEC_BYTES);
    const rho = publicKey.slice(TVEC_BYTES);
    // A uniform ring vector for the non-chosen slot (RO of fresh receiver randomness).
    const nSlot = core.hashToRing(concat(TAG_N, sid, u32(i), rng.bytes(SYM_BYTES)));
    const cPoint = core.ringSub(tReal, hpk(sid, i, nSlot));
    points.push(c === 0 ? [cPoint, nSlot] : [nSlot, cPoint]);
    rhos.push(rho);
    secretKeys.push(secretKey);
    retained.push(c);
  }
  return { message: { rn, points, rhos }, state: { choices: retained, secretKeys, rhos, rn, sid } };
}

/** Sender wire message of the RANDOM endemic OT: the two ciphertexts per transfer (sender-local pads). */
export interface EndemicLweRandomSenderMessage {
  ciphertexts: Array<[Uint8Array, Uint8Array]>;
  /** Sender-LOCAL: both per-slot pads `[k_0, k_1]` per transfer (never sent). */
  senderPads: Array<[Uint8Array, Uint8Array]>;
}

/** TEST-ONLY malicious-sender injection (corrupt the ciphertexts on the wire). */
export interface EndemicLweTamper {
  tamperCiphertexts?: (ciphertexts: Array<[Uint8Array, Uint8Array]>) => void;
}

/**
 * SENDER round (RANDOM variant): derive each slot's effective public key `pk_b = (P_b + Hpk(sid,i,P_{1−b}) ‖ rho)`,
 * CPA-encrypt a fresh random payload under each, and output both per-slot pads. No messages are padded
 * — the two pads per transfer ARE the random output (consumed by the hybrid combiner / the chosen-message
 * wrapper below).
 */
export function endemicLweSendRandom(
  message: EndemicLweReceiverMessage,
  rng: OtRandom = secureOtRandom(),
  tamper?: EndemicLweTamper,
): EndemicLweRandomSenderMessage {
  const sid = endemicSessionId(message.rn);
  const { points, rhos } = message;
  const ciphertexts: Array<[Uint8Array, Uint8Array]> = [];
  const senderPads: Array<[Uint8Array, Uint8Array]> = [];
  for (let i = 0; i < points.length; i++) {
    const [p0, p1] = points[i]!;
    const rho = rhos[i]!;
    const effT0 = core.ringAdd(p0, hpk(sid, i, p1));
    const effT1 = core.ringAdd(p1, hpk(sid, i, p0));
    const pk0 = concat(effT0, rho);
    const pk1 = concat(effT1, rho);
    const r0 = rng.bytes(SYM_BYTES);
    const r1 = rng.bytes(SYM_BYTES);
    const ct0 = core.kpkeEnc(pk0, r0, rng.bytes(SYM_BYTES));
    const ct1 = core.kpkeEnc(pk1, r1, rng.bytes(SYM_BYTES));
    ciphertexts.push([ct0, ct1]);
    senderPads.push([
      padBytes(sid, i, 0, r0, ENDEMIC_SECRET_BYTES),
      padBytes(sid, i, 1, r1, ENDEMIC_SECRET_BYTES),
    ]);
  }
  if (tamper?.tamperCiphertexts) tamper.tamperCiphertexts(ciphertexts);
  return { ciphertexts, senderPads };
}

/**
 * RECEIVER recovery (RANDOM variant): decapsulate ONLY the chosen ciphertext (the chosen branch's
 * effective key equals the receiver's real key) and derive the chosen pad. The non-chosen slot's key
 * is uniform, so its ciphertext is unrecoverable (the endemic property).
 */
export function endemicLweRecoverRandom(
  state: EndemicLweReceiverState,
  senderMessage: EndemicLweRandomSenderMessage,
): Uint8Array[] {
  const { choices, secretKeys, sid } = state;
  const { ciphertexts } = senderMessage;
  const recvPads: Uint8Array[] = [];
  for (let i = 0; i < choices.length; i++) {
    const c = choices[i]! & 1;
    const payload = core.kpkeDec(secretKeys[i]!, ciphertexts[i]![c]!);
    recvPads.push(padBytes(sid, i, c, payload, ENDEMIC_SECRET_BYTES));
  }
  return recvPads;
}

/** Full RANDOM endemic base OT (both parties in-process); the random-OT face reused by the combiner. */
export interface EndemicLweRandomResult {
  /** Sender's per-slot pads `[k_0, k_1]` (the sender learns BOTH). */
  senderPads: Array<[Uint8Array, Uint8Array]>;
  /** Receiver's chosen pad `k_{choices[i]}` (the honest receiver learns ONE). */
  recvPads: Uint8Array[];
  sid: Uint8Array;
  message: EndemicLweReceiverMessage;
  ciphertexts: Array<[Uint8Array, Uint8Array]>;
}

/** In-process RANDOM endemic base OT. */
export function endemicLweBaseOtRandom(
  choices: number[],
  rng: OtRandom = secureOtRandom(),
  tamper?: EndemicLweTamper,
): EndemicLweRandomResult {
  const { message, state } = endemicLweReceive(choices, rng);
  const senderMessage = endemicLweSendRandom(message, rng, tamper);
  const recvPads = endemicLweRecoverRandom(state, senderMessage);
  return {
    senderPads: senderMessage.senderPads,
    recvPads,
    sid: state.sid,
    message,
    ciphertexts: senderMessage.ciphertexts,
  };
}

// --- Chosen-message wrapper (the BaseOtFn seam) over the random OT, with a malicious-sender check. ---

/** A full chosen-message endemic base-OT transcript, exposed for inspection/tests. */
export interface EndemicLweTranscript {
  rn: Uint8Array;
  points: Array<[Uint8Array, Uint8Array]>;
  rhos: Uint8Array[];
  ciphertexts: Array<[Uint8Array, Uint8Array]>;
  /** For each transfer i, `[E_0, E_1]` with `E_b = m_b ⊕ k_b`. */
  encrypted: Array<[Uint8Array, Uint8Array]>;
  /** For each transfer i, `[com_0, com_1]`. */
  commitments: Array<[Uint8Array, Uint8Array]>;
}

export interface EndemicLweResult {
  received: Uint8Array[];
  transcript: EndemicLweTranscript;
}

/**
 * In-process CHOSEN-MESSAGE endemic base OT: `messages[i] = [m0, m1]` (the two must be equal length);
 * `choices[i] ∈ {0,1}`. The sender one-time-pads each message under the endemic random-OT pads and
 * commits to each; the receiver recovers `m_{choices[i]}` and checks the commitment, aborting
 * (`EndemicLweOtAbort`) on any inconsistency. A drop-in for `OtChannel`'s `baseOtFn`.
 */
export function endemicLweBaseOT(
  messages: Array<[Uint8Array, Uint8Array]>,
  choices: number[],
  rng: OtRandom = secureOtRandom(),
  tamper?: EndemicLweTamper,
): EndemicLweResult {
  if (messages.length !== choices.length) throw new Error('endemicLweBaseOT: messages/choices length mismatch');

  const { message, state } = endemicLweReceive(choices, rng);
  const sid = state.sid;

  // Sender: derive effective keys, encrypt a random payload per slot, then one-time-pad + commit each
  // message under the pad expanded to the message length.
  const ciphertexts: Array<[Uint8Array, Uint8Array]> = [];
  const encrypted: Array<[Uint8Array, Uint8Array]> = [];
  const commitments: Array<[Uint8Array, Uint8Array]> = [];
  for (let i = 0; i < messages.length; i++) {
    const [m0, m1] = messages[i]!;
    if (m0.length !== m1.length) {
      throw new Error(`endemicLweBaseOT (index ${i}): the two messages must be equal length`);
    }
    const [p0, p1] = message.points[i]!;
    const rho = message.rhos[i]!;
    const effT0 = core.ringAdd(p0, hpk(sid, i, p1));
    const effT1 = core.ringAdd(p1, hpk(sid, i, p0));
    const r0 = rng.bytes(SYM_BYTES);
    const r1 = rng.bytes(SYM_BYTES);
    ciphertexts.push([
      core.kpkeEnc(concat(effT0, rho), r0, rng.bytes(SYM_BYTES)),
      core.kpkeEnc(concat(effT1, rho), r1, rng.bytes(SYM_BYTES)),
    ]);
    const pad0 = padBytes(sid, i, 0, r0, m0.length);
    const pad1 = padBytes(sid, i, 1, r1, m1.length);
    encrypted.push([xorBytes(m0, pad0), xorBytes(m1, pad1)]);
    commitments.push([commitBytes(sid, i, 0, m0, pad0), commitBytes(sid, i, 1, m1, pad1)]);
  }

  if (tamper?.tamperCiphertexts) tamper.tamperCiphertexts(encrypted);

  // Receiver: decrypt the chosen ciphertext, unmask the chosen message, check the commitment.
  const received: Uint8Array[] = [];
  for (let i = 0; i < messages.length; i++) {
    const c = choices[i]! & 1;
    const payload = core.kpkeDec(state.secretKeys[i]!, ciphertexts[i]![c]!);
    const e = encrypted[i]![c]!;
    const pad = padBytes(sid, i, c, payload, e.length);
    const m = xorBytes(e, pad);
    if (!ctEqual(commitBytes(sid, i, c, m, pad), commitments[i]![c]!)) {
      throw new EndemicLweOtAbort(
        `endemic base OT (index ${i}): sender ciphertext inconsistent with its commitment; aborting`,
      );
    }
    received.push(m);
  }

  return {
    received,
    transcript: { rn: message.rn, points: message.points, rhos: message.rhos, ciphertexts, encrypted, commitments },
  };
}

/**
 * The chosen-message endemic base OT as a `BaseOtFn` (only `received` is part of the contract).
 */
export const endemicLweBaseOtFn: BaseOtFn = (messages, choices, rng) => ({
  received: endemicLweBaseOT(messages, choices, rng).received,
});

/**
 * Wire the endemic ML-KEM base OT into the KOS OT-extension — the RECOMMENDED post-quantum,
 * maliciously-secure base. Everything above the base OT (the IKNP matrix, the KOS correlation check,
 * the correlation-robust hash) is unchanged; only the `κ` setup base OTs run the endemic protocol.
 *
 *   const ch = new OtChannel(secureOtRandom(), withEndemicLweBaseOt());
 */
export function withEndemicLweBaseOt(): ConstructorParameters<typeof OtChannel>[1] {
  return { baseOtFn: endemicLweBaseOtFn };
}
