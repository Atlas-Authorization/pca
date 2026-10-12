/**
 * SPDZ-style authenticated secret sharing over F_p — the MALICIOUS-security layer.
 *
 * The semi-honest layer (`sharing.ts` + `beaver.ts`) is correct only if every party follows the
 * protocol: a party that lies in an opening silently corrupts the result and is never caught. SPDZ
 * closes that gap with *information-theoretic MACs*. A global MAC key `α ∈ F_p` is itself additively
 * shared (`α = Σ_i α_i`, no single party knows `α`). Every authenticated value `⟦x⟧` carries, besides
 * its value shares `x_i` (summing to `x`), a vector of MAC shares `γ_i` summing to `α·x`:
 *
 *     ⟦x⟧ = ( x_i , γ_i )   with   Σ x_i = x   and   Σ γ_i = α·x.
 *
 * Linear ops keep the invariant `Σ γ_i = α·(Σ x_i)` with NO interaction (add/sub of sharings,
 * public-scalar multiply, and — the SPDZ trick — adding a PUBLIC constant updates each party's MAC
 * share by `α_i·c`, which the party can do locally because it holds `α_i`). Beaver multiplication
 * produces an authenticated product. Before any value is accepted as output the parties run the
 * SPDZ **MAC-check** (random linear combination + commit-then-open of the residual `Σγ − α·a`); any
 * party that fed an inconsistent value or MAC share into an opening makes the residual non-zero and
 * the protocol ABORTS. The result is therefore *correct, or an abort* — never a silent wrong answer.
 *
 * Security upgrade: semi-honest → **malicious-with-abort, dishonest-majority** (secure against up to
 * N−1 actively-corrupted parties; privacy and MAC-forgery-resistance both hold at the N−1 threshold).
 * The MAC is information-theoretic, independent of the adversary's computing power. ONE key over the 61-bit
 * field is only ≈ 2^−60 sound, so every value carries `MAC_KEYS = 2` MACs under INDEPENDENT global keys, each
 * with its own challenge vector, all checked in the same batched check: the forgery probability is
 * ≤ (2/p)^2 ≈ 2^−120 (proof: docs/pca/security/pca-mpc-spdz-soundness.md; `macSoundnessBits`).
 *
 * OFFLINE-PHASE BOUNDARY (honest, see docs §7): the authenticated triples / input sharings below are
 * produced by a TRUSTED DEALER that honestly knows the MAC keys. That keeps the *online* phase — openings,
 * MAC updates, and the MAC-check — the real, maliciously-secure thing, with the dealer as the one
 * explicit trust assumption. A no-dealer offline phase (MASCOT/Overdrive: OT- or HE-based authenticated
 * triple generation, itself maliciously secure, with a distributed `α` nobody ever reconstructs) is
 * NOT implemented here; its interface is exactly `setupMac` + `genAuthTriple` + `authShare`, so it
 * drops in under the same online protocol. The commitment below is SHA-256 (a real binding commitment,
 * via `node:crypto`), modelling the commit-then-open round that defeats a rushing adversary.
 */

import { createHash } from 'node:crypto';
import { FieldRng, PRIME, fadd, fmul, fneg, fsub, mod } from './field';
import { share } from './sharing';

/** One global SPDZ MAC key, additively shared. */
export interface MacKey {
  /** α_i: party i's share of this key. Σ α_i = α. No single party may learn α. */
  alphaShares: bigint[];
  /** The key α. For dealer preprocessing + test inspection ONLY; never held by one party. */
  alpha: bigint;
}

/**
 * The global SPDZ MAC keys, additively shared. Key 0 is `alphaShares`/`alpha`; `extraKeys` are further
 * INDEPENDENT keys (the statistical-security amplification: each is an independent 2/p test).
 */
export interface MacContext extends MacKey {
  n: number;
  /** Independent keys 1..k-1. Every authenticated value carries one MAC per key. */
  extraKeys: MacKey[];
}

/** An authenticated secret-shared value: value shares summing to x, MAC shares summing to α·x (per key). */
export interface AuthSV {
  /** value shares x_i (Σ = x). */
  value: bigint[];
  /** MAC shares γ_i under key 0 (Σ = α·x). */
  mac: bigint[];
  /** MAC shares under keys 1..k-1 (`extraMac[l-1]` sums to `extraKeys[l-1].alpha · x`). */
  extraMac: bigint[][];
}

/** An authenticated Beaver triple: ⟦a⟧, ⟦b⟧, ⟦c⟧ with c = a·b, every component MAC'd. */
export interface AuthTriple {
  a: AuthSV;
  b: AuthSV;
  c: AuthSV;
}

/** Number of independent MAC keys the trusted-dealer / no-dealer setups create by default. */
export const MAC_KEYS = 2;

/** The statistical security the MAC-check must provide, in bits. `SpdzEngine` refuses a weaker context. */
export const MIN_MAC_SOUNDNESS_BITS = 100;

/** All keys of a context, key 0 first. */
export function macKeys(ctx: MacContext): MacKey[] {
  return [{ alphaShares: ctx.alphaShares, alpha: ctx.alpha }, ...ctx.extraKeys];
}

/**
 * Soundness (as -log2 of the forgery probability) of the batched MAC-check over a field of `fieldBits`
 * bits (default: this field) with `keys` independent keys: per key the failure probability is ≤ 2/p
 * (1/p for guessing the key, 1/p for a random combination hitting a non-zero residual), and the keys and
 * challenge vectors are independent, so the total is ≤ (2/p)^keys. Returns `keys · (log2 p − 1)`.
 */
export function macSoundnessBits(keys: number, p: bigint = PRIME): number {
  return keys * (Math.log2(Number(p)) - 1);
}

/** Raised when the SPDZ MAC-check detects an inconsistent opening/MAC: the protocol ABORTS, no output. */
export class MacCheckAbort extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MacCheckAbort';
  }
}

/** Dealer preprocessing: sample `keys` independent global MAC keys and additively share each across n parties. */
export function setupMac(n: number, rng: FieldRng, keys: number = MAC_KEYS): MacContext {
  if (!Number.isInteger(n) || n < 1) throw new Error('setupMac: n must be a positive integer');
  if (!Number.isInteger(keys) || keys < 1 || keys > 16) throw new Error('setupMac: keys must be an integer in [1, 16]');
  const mk = (): MacKey => {
    const alpha = rng.next();
    return { alpha, alphaShares: share(alpha, n, rng) };
  };
  const first = mk();
  return { n, ...first, extraKeys: Array.from({ length: keys - 1 }, mk) };
}

/** Authenticated sharing of `secret` (dealer-side): value shares sum to x, MAC shares sum to α·x per key. */
export function authShare(secret: bigint, ctx: MacContext, rng: FieldRng): AuthSV {
  const v = mod(secret);
  return {
    value: share(v, ctx.n, rng),
    mac: share(fmul(ctx.alpha, v), ctx.n, rng),
    extraMac: ctx.extraKeys.map((k) => share(fmul(k.alpha, v), ctx.n, rng)),
  };
}

/** Authenticated sharing of a PUBLIC constant c: value = shareConstant(c), MAC = share of α·c (via α_i·c). */
export function authConstant(c: bigint, ctx: MacContext): AuthSV {
  const v = mod(c);
  const value = new Array<bigint>(ctx.n).fill(0n);
  value[0] = v;
  // γ_i = α_i · c so that Σ γ_i = α·c, with no randomness and no interaction.
  const mac = ctx.alphaShares.map((ai) => fmul(ai, v));
  return { value, mac, extraMac: ctx.extraKeys.map((k) => k.alphaShares.map((ai) => fmul(ai, v))) };
}

const zipMac = (x: bigint[][], y: bigint[][], f: (a: bigint, b: bigint) => bigint): bigint[][] =>
  x.map((row, l) => row.map((m, i) => f(m, y[l]![i]!)));

/** ⟦x⟧ + ⟦y⟧ (local; MAC shares add, preserving Σγ = α·(x+y) under every key). */
export function addAuth(x: AuthSV, y: AuthSV): AuthSV {
  requireSame(x, y);
  return {
    value: x.value.map((xi, i) => fadd(xi, y.value[i]!)),
    mac: x.mac.map((mi, i) => fadd(mi, y.mac[i]!)),
    extraMac: zipMac(x.extraMac, y.extraMac, fadd),
  };
}

/** ⟦x⟧ − ⟦y⟧ (local). */
export function subAuth(x: AuthSV, y: AuthSV): AuthSV {
  requireSame(x, y);
  return {
    value: x.value.map((xi, i) => fsub(xi, y.value[i]!)),
    mac: x.mac.map((mi, i) => fsub(mi, y.mac[i]!)),
    extraMac: zipMac(x.extraMac, y.extraMac, fsub),
  };
}

/** −⟦x⟧ (local). */
export function negAuth(x: AuthSV): AuthSV {
  return { value: x.value.map(fneg), mac: x.mac.map(fneg), extraMac: x.extraMac.map((r) => r.map(fneg)) };
}

/** ⟦x⟧ · c for a PUBLIC scalar c (local): value and every MAC share scale by c. */
export function scaleAuth(x: AuthSV, c: bigint): AuthSV {
  const k = mod(c);
  return {
    value: x.value.map((xi) => fmul(xi, k)),
    mac: x.mac.map((mi) => fmul(mi, k)),
    extraMac: x.extraMac.map((r) => r.map((mi) => fmul(mi, k))),
  };
}

/**
 * ⟦x⟧ + c for a PUBLIC constant c (local). The SPDZ public-constant rule: add c to ONE party's value
 * share, and add α_i·c to EVERY party's MAC share under EVERY key (each party holds its α_i), so Σγ becomes
 * α·x + α·c = α·(x+c). This is what lets affine gates stay authenticated without any interaction.
 */
export function addPublicAuth(x: AuthSV, c: bigint, ctx: MacContext): AuthSV {
  if (x.value.length !== ctx.n || x.mac.length !== ctx.n || ctx.alphaShares.length !== ctx.n) {
    throw new Error('addPublicAuth: shared value and MAC context disagree on the party count');
  }
  if (x.extraMac.length !== ctx.extraKeys.length) throw new Error('addPublicAuth: shared value and MAC context disagree on the key count');
  const k = mod(c);
  const value = x.value.slice();
  value[0] = fadd(value[0]!, k);
  const mac = x.mac.map((mi, i) => fadd(mi, fmul(ctx.alphaShares[i]!, k)));
  const extraMac = x.extraMac.map((row, l) => {
    const key = ctx.extraKeys[l]!;
    if (row.length !== ctx.n || key.alphaShares.length !== ctx.n) throw new Error('addPublicAuth: extra MAC party count mismatch');
    return row.map((mi, i) => fadd(mi, fmul(key.alphaShares[i]!, k)));
  });
  return { value, mac, extraMac };
}

/** Logical NOT of an authenticated bit b: ⟦1 − b⟧ (local). */
export function notBitAuth(b: AuthSV, ctx: MacContext): AuthSV {
  return addPublicAuth(negAuth(b), 1n, ctx);
}

/** Dealer preprocessing: one authenticated triple (a, b, c=a·b), every component MAC'd. */
export function genAuthTriple(ctx: MacContext, rng: FieldRng): AuthTriple {
  const a = rng.next();
  const b = rng.next();
  return {
    a: authShare(a, ctx, rng),
    b: authShare(b, ctx, rng),
    c: authShare(fmul(a, b), ctx, rng),
  };
}

/**
 * Number of independent sacrifice partners per delivered triple. The sacrifice of one partner passes a
 * triple with c ≠ a·b with probability ≤ 1/p (the random challenge must hit one value); `r` independent
 * partners (each with its own challenge) give ≤ p^-r, so 2 partners ≈ 2^-122 > the 2^-100 floor.
 */
export const SACRIFICE_PARTNERS = 2;

/** A triple to be delivered plus its sacrifice partners; every partner shares `keep.b` (same sharing). */
export interface TripleWithPartners {
  keep: AuthTriple;
  partners: AuthTriple[];
}

/**
 * TEST-ONLY fault of a LYING trusted dealer: the dealer authenticates a wrong product, so the triple is
 * internally MAC-consistent (the MACs are computed on the wrong c) - exactly the lie MACs alone cannot
 * detect. `keepCDelta` makes the delivered triple's c = a·b + delta; `partnerCDelta[r]` does the same to
 * sacrifice partner r.
 */
export interface DealerFault {
  keepCDelta?: bigint;
  partnerCDelta?: Array<bigint | undefined>;
}

/** Trusted-dealer preprocessing of one triple together with its sacrifice partners (all sharing b). */
export function genTripleWithPartners(
  ctx: MacContext,
  rng: FieldRng,
  partners: number = SACRIFICE_PARTNERS,
  fault?: DealerFault,
): TripleWithPartners {
  if (!Number.isInteger(partners) || partners < 1 || partners > 8) throw new Error('genTripleWithPartners: partners must be in [1, 8]');
  const a = rng.next();
  const b = rng.next();
  const bSV = authShare(b, ctx, rng);
  const keep: AuthTriple = {
    a: authShare(a, ctx, rng),
    b: bSV,
    c: authShare(fadd(fmul(a, b), fault?.keepCDelta ?? 0n), ctx, rng),
  };
  const ps: AuthTriple[] = [];
  for (let r = 0; r < partners; r++) {
    const ah = rng.next();
    ps.push({ a: authShare(ah, ctx, rng), b: bSV, c: authShare(fadd(fmul(ah, b), fault?.partnerCDelta?.[r] ?? 0n), ctx, rng) });
  }
  return { keep, partners: ps };
}

/**
 * The MASCOT/SPDZ **sacrifice** check on a batch. For every kept triple (a,b,c) and each partner (â,b,ĉ)
 * it draws a public random challenge e ≠ 0, opens ρ = e·a − â, forms ⟦τ⟧ = e·⟦c⟧ − ⟦ĉ⟧ − ρ·⟦b⟧ and opens
 * it. If both triples are correct, τ = e·(c − ab) − (ĉ − âb) = 0; if c = ab + δ with δ ≠ 0, τ = e·δ − δ̂ is
 * non-zero except for one value of e (prob 1/p), and independent partners multiply the failure
 * probabilities. A lie in either opening is caught by the single batched MAC-check (all keys). Throws
 * `MacCheckAbort` on any failure and emits NOTHING; otherwise returns the certified kept triples.
 * The partners are consumed and must never be reused.
 */
export function sacrificeVerify(
  batch: ReadonlyArray<TripleWithPartners>,
  ctx: MacContext,
  rng: FieldRng,
  deviations: Deviation[] = [],
): AuthTriple[] {
  const engine = new SpdzEngine(ctx, deviations);
  const taus: bigint[] = [];
  for (const { keep, partners } of batch) {
    if (partners.length < 1) throw new MacCheckAbort('sacrifice: a triple without partners cannot be certified');
    for (const sac of partners) {
      if (sac.b.value.length !== keep.b.value.length || sac.b.value.some((v, i) => v !== keep.b.value[i])) {
        throw new MacCheckAbort('sacrifice: partner does not share b with the triple');
      }
      let e = rng.next();
      if (e === 0n) e = 1n; // public random challenge, non-zero
      const rho = engine.open(subAuth(scaleAuth(keep.a, e), sac.a), 'sacrifice:rho');
      let tau = subAuth(scaleAuth(keep.c, e), sac.c);
      tau = subAuth(tau, scaleAuth(keep.b, rho));
      taus.push(engine.open(tau, 'sacrifice:tau'));
    }
  }
  engine.macCheck(rng); // commit-then-open MAC-check on every ρ and τ; throws on a forged opening
  for (const t of taus) {
    if (t !== 0n) {
      throw new MacCheckAbort(
        `Beaver-triple sacrifice FAILED: residual tau=${t} != 0 - a malformed triple (c != a*b) was delivered; aborting with no triple emitted`,
      );
    }
  }
  return batch.map((x) => x.keep);
}

/** A party's broadcast deviation in the ONLINE phase — the knob that lets tests model an active cheater. */
export interface Deviation {
  /** 0-based index of the `open()` call to corrupt. */
  openIndex: number;
  /** which party's broadcast to corrupt. */
  party: number;
  /** delta added to that party's VALUE share at the open (a lie about the opened value / an inconsistent Beaver opening). */
  valueDelta?: bigint;
  /** delta added to that party's MAC share carried into the MAC-check for that open (a forged MAC). */
  macDelta?: bigint;
  /** which MAC key `macDelta` applies to (0 = key 0, default). */
  macKey?: number;
}

/** One partial opening as it reaches the MAC-check: the public value and the MAC shares per key per party. */
export interface OpenedValue {
  value: bigint;
  /** macShares[key][party] */
  macShares: bigint[][];
  label: string;
}

/**
 * The arithmetic core of the batched SPDZ MAC-check, over an ARBITRARY prime modulus `p` so the very same
 * code can be exercised on a deliberately tiny field (the soundness experiment in the tests). For each key
 * l, with its own challenge vector r^(l): a^(l) = Σ_j r_j^(l)·v_j, and party i's residual share is
 * σ_i^(l) = Σ_j r_j^(l)·γ_ij^(l) − α_i^(l)·a^(l). Returns σ[key][party]; honest data gives Σ_i σ_i^(l) = 0 for every l.
 */
export function macResiduals(
  p: bigint,
  alphaShares: bigint[][],
  opened: ReadonlyArray<Pick<OpenedValue, 'value' | 'macShares'>>,
  challenges: bigint[][],
): bigint[][] {
  const m = (x: bigint): bigint => ((x % p) + p) % p;
  return alphaShares.map((alphas, l) => {
    const r = challenges[l]!;
    let a = 0n;
    for (let j = 0; j < opened.length; j++) a = m(a + r[j]! * opened[j]!.value);
    return alphas.map((alphaI, i) => {
      let gamma = 0n;
      for (let j = 0; j < opened.length; j++) gamma = m(gamma + r[j]! * opened[j]!.macShares[l]![i]!);
      return m(gamma - alphaI * a);
    });
  });
}

/**
 * The SPDZ online engine: performs partial openings (broadcast value shares, sum to the public value,
 * RETAIN the MAC shares for a single batched MAC-check at the end) and the MAC-check itself. A list of
 * `Deviation`s models one or more actively-malicious parties corrupting their broadcasts; the engine
 * records exactly what would reach the honest parties, so the MAC-check sees the tampered transcript.
 */
export class SpdzEngine {
  private readonly ctx: MacContext;
  private readonly deviations: Deviation[];
  /** Each partial-open: the (possibly tampered) public value and the (possibly tampered) MAC shares. */
  private readonly opened: OpenedValue[] = [];
  private counter = 0;

  constructor(ctx: MacContext, deviations: Deviation[] = []) {
    // Fail closed: a context whose MAC-check is statistically weaker than the floor is refused outright.
    const bits = macSoundnessBits(1 + ctx.extraKeys.length);
    if (bits < MIN_MAC_SOUNDNESS_BITS) {
      throw new Error(`SpdzEngine: MAC context gives only ${bits.toFixed(0)} bits of statistical soundness (< ${MIN_MAC_SOUNDNESS_BITS}); use setupMac(n, rng) with the default ${MAC_KEYS} keys`);
    }
    this.ctx = ctx;
    this.deviations = deviations;
  }

  /** How many opens have happened (lets tests target the last/output open by index). */
  get openCount(): number {
    return this.counter;
  }

  /**
   * Partial-open ⟦x⟧: parties broadcast value shares, the public value is their sum, and the MAC
   * shares are retained for the batched MAC-check. Does NOT check the MAC here (that is the whole
   * point of SPDZ: open cheaply during the circuit, verify everything once at the end).
   */
  open(x: AuthSV, label = ''): bigint {
    const idx = this.counter++;
    if (x.extraMac.length !== this.ctx.extraKeys.length) throw new Error('open: value and MAC context disagree on the key count');
    const valueShares = x.value.slice();
    const macShares = [x.mac.slice(), ...x.extraMac.map((r) => r.slice())];
    for (const d of this.deviations) {
      if (d.openIndex !== idx) continue;
      if (d.party < 0 || d.party >= this.ctx.n) throw new Error('Deviation.party out of range');
      if (d.valueDelta !== undefined) valueShares[d.party] = fadd(valueShares[d.party]!, d.valueDelta);
      if (d.macDelta !== undefined) {
        const key = d.macKey ?? 0;
        if (key < 0 || key >= macShares.length) throw new Error('Deviation.macKey out of range');
        macShares[key]![d.party] = fadd(macShares[key]![d.party]!, d.macDelta);
      }
    }
    const value = valueShares.reduce((a, b) => fadd(a, b), 0n);
    this.opened.push({ value, macShares, label });
    return value;
  }

  /**
   * SPDZ MAC-check over every partial-open so far. For EACH key draws an independent public challenge
   * vector (a secure coin-flip in the real protocol; the supplied RNG here), forms the residual shares
   * (`macResiduals`), then runs commit-then-open on every σ and checks Σ σ = 0 for every key. Honest runs
   * give exactly 0; ANY inconsistent opened value or forged MAC makes some key's sum non-zero with
   * probability ≥ 1 − (2/p)^k, and we ABORT.
   *
   * The commit-then-open (SHA-256 binding commitment) models the round that stops a *rushing*
   * adversary from choosing its σ_i after seeing the others — it must commit before any are revealed.
   */
  macCheck(rng: FieldRng): void {
    if (this.opened.length === 0) return;
    const keys = macKeys(this.ctx);
    const challenges = keys.map(() => this.opened.map(() => rng.next()));
    const sigma = macResiduals(
      PRIME,
      keys.map((k) => k.alphaShares),
      this.opened,
      challenges,
    );

    // Commit-then-open: every party commits to every σ_i^(l) (binding) before any σ is revealed.
    for (let l = 0; l < sigma.length; l++) {
      const nonces = sigma[l]!.map(() => rng.next());
      const commitments = sigma[l]!.map((s, i) => commit(s, nonces[i]!));
      for (let i = 0; i < commitments.length; i++) {
        // Opening phase: a σ_i revealed inconsistent with its commitment is itself an abort.
        if (commit(sigma[l]![i]!, nonces[i]!) !== commitments[i]) {
          throw new MacCheckAbort(`MAC-check: commitment from party ${i} did not open consistently`);
        }
      }
    }

    for (let l = 0; l < sigma.length; l++) {
      const residual = sigma[l]!.reduce((x, y) => fadd(x, y), 0n);
      if (residual !== 0n) {
        throw new MacCheckAbort(
          `MAC-check FAILED (key ${l}): residual ${residual} != 0 — an actively-malicious party was detected; aborting with no output`,
        );
      }
    }
  }
}

/**
 * Authenticated Beaver multiplication: returns ⟦x·y⟧, consuming `triple`, via the engine's partial
 * opens of d = x−a and e = y−b. The product sharing is assembled with the authenticated linear ops,
 * so its MAC shares sum to α·(x·y). The two opens are recorded for the batched MAC-check: a party that
 * opens d or e inconsistently is caught there.
 */
export function beaverMulAuth(
  x: AuthSV,
  y: AuthSV,
  triple: AuthTriple,
  ctx: MacContext,
  engine: SpdzEngine,
  label = '',
): AuthSV {
  for (const t of [triple.a, triple.b, triple.c]) requireSame(x, t);
  requireSame(x, y);
  const d = engine.open(subAuth(x, triple.a), `${label}:d`);
  const e = engine.open(subAuth(y, triple.b), `${label}:e`);
  // ⟦z⟧ = ⟦c⟧ + d·⟦b⟧ + e·⟦a⟧ + d·e  (the last term is a public constant, MAC'd via α_i).
  let z = addAuth(triple.c, addAuth(scaleAuth(triple.b, d), scaleAuth(triple.a, e)));
  z = addPublicAuth(z, fmul(d, e), ctx);
  return z;
}

/** Full-reconstruct an authenticated value's cleartext (sum of value shares). Used after MAC-check passes. */
export function authValue(x: AuthSV): bigint {
  return x.value.reduce((a, b) => fadd(a, b), 0n);
}

/** SHA-256 binding commitment to a field element under a nonce. Real (node:crypto); models commit-then-open. */
function commit(value: bigint, nonce: bigint): string {
  return createHash('sha256').update(`${value.toString(16)}:${nonce.toString(16)}`).digest('hex');
}

function requireSame(x: AuthSV, y: AuthSV): void {
  if (x.value.length !== y.value.length || x.mac.length !== y.mac.length) {
    throw new Error('authenticated shared values must have the same party count');
  }
  if (x.extraMac.length !== y.extraMac.length) throw new Error('authenticated shared values must carry the same number of MAC keys');
  for (let l = 0; l < x.extraMac.length; l++) {
    if (x.extraMac[l]!.length !== y.extraMac[l]!.length) throw new Error('authenticated shared values must have the same party count');
  }
}
