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
 * The MAC is information-theoretic: forging a MAC on a wrong value succeeds with probability ≤ 2/p
 * (here ≈ 2^−60), independent of the adversary's computing power.
 *
 * OFFLINE-PHASE BOUNDARY (honest, see docs §7): the authenticated triples / input sharings below are
 * produced by a TRUSTED DEALER that honestly knows `α`. That keeps the *online* phase — openings,
 * MAC updates, and the MAC-check — the real, maliciously-secure thing, with the dealer as the one
 * explicit trust assumption. A no-dealer offline phase (MASCOT/Overdrive: OT- or HE-based authenticated
 * triple generation, itself maliciously secure, with a distributed `α` nobody ever reconstructs) is
 * NOT implemented here; its interface is exactly `setupMac` + `genAuthTriple` + `authShare`, so it
 * drops in under the same online protocol. The commitment below is SHA-256 (a real binding commitment,
 * via `node:crypto`), modelling the commit-then-open round that defeats a rushing adversary.
 */

import { createHash } from 'node:crypto';
import { FieldRng, fadd, fmul, fneg, fsub, mod } from './field';
import { share } from './sharing';

/** The global SPDZ MAC key, additively shared. `alpha` is known to the DEALER only (and to tests). */
export interface MacContext {
  n: number;
  /** α_i: party i's share of the MAC key. Σ α_i = α. No single party may learn α. */
  alphaShares: bigint[];
  /** The global MAC key α. For dealer preprocessing + test inspection ONLY; never held by one party. */
  alpha: bigint;
}

/** An authenticated secret-shared value: value shares summing to x, MAC shares summing to α·x. */
export interface AuthSV {
  /** value shares x_i (Σ = x). */
  value: bigint[];
  /** MAC shares γ_i (Σ = α·x). */
  mac: bigint[];
}

/** An authenticated Beaver triple: ⟦a⟧, ⟦b⟧, ⟦c⟧ with c = a·b, every component MAC'd. */
export interface AuthTriple {
  a: AuthSV;
  b: AuthSV;
  c: AuthSV;
}

/** Raised when the SPDZ MAC-check detects an inconsistent opening/MAC: the protocol ABORTS, no output. */
export class MacCheckAbort extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MacCheckAbort';
  }
}

/** Dealer preprocessing: sample the global MAC key α and additively share it across n parties. */
export function setupMac(n: number, rng: FieldRng): MacContext {
  if (!Number.isInteger(n) || n < 1) throw new Error('setupMac: n must be a positive integer');
  const alpha = rng.next();
  return { n, alpha, alphaShares: share(alpha, n, rng) };
}

/** Authenticated sharing of `secret` (dealer-side): value shares sum to x, MAC shares sum to α·x. */
export function authShare(secret: bigint, ctx: MacContext, rng: FieldRng): AuthSV {
  const v = mod(secret);
  return { value: share(v, ctx.n, rng), mac: share(fmul(ctx.alpha, v), ctx.n, rng) };
}

/** Authenticated sharing of a PUBLIC constant c: value = shareConstant(c), MAC = share of α·c (via α_i·c). */
export function authConstant(c: bigint, ctx: MacContext): AuthSV {
  const v = mod(c);
  const value = new Array<bigint>(ctx.n).fill(0n);
  value[0] = v;
  // γ_i = α_i · c so that Σ γ_i = α·c, with no randomness and no interaction.
  const mac = ctx.alphaShares.map((ai) => fmul(ai, v));
  return { value, mac };
}

/** ⟦x⟧ + ⟦y⟧ (local; MAC shares add, preserving Σγ = α·(x+y)). */
export function addAuth(x: AuthSV, y: AuthSV): AuthSV {
  requireSame(x, y);
  return {
    value: x.value.map((xi, i) => fadd(xi, y.value[i]!)),
    mac: x.mac.map((mi, i) => fadd(mi, y.mac[i]!)),
  };
}

/** ⟦x⟧ − ⟦y⟧ (local). */
export function subAuth(x: AuthSV, y: AuthSV): AuthSV {
  requireSame(x, y);
  return {
    value: x.value.map((xi, i) => fsub(xi, y.value[i]!)),
    mac: x.mac.map((mi, i) => fsub(mi, y.mac[i]!)),
  };
}

/** −⟦x⟧ (local). */
export function negAuth(x: AuthSV): AuthSV {
  return { value: x.value.map(fneg), mac: x.mac.map(fneg) };
}

/** ⟦x⟧ · c for a PUBLIC scalar c (local): both value and MAC shares scale by c. */
export function scaleAuth(x: AuthSV, c: bigint): AuthSV {
  const k = mod(c);
  return { value: x.value.map((xi) => fmul(xi, k)), mac: x.mac.map((mi) => fmul(mi, k)) };
}

/**
 * ⟦x⟧ + c for a PUBLIC constant c (local). The SPDZ public-constant rule: add c to ONE party's value
 * share, and add α_i·c to EVERY party's MAC share (each party holds α_i), so Σγ becomes α·x + α·c =
 * α·(x+c). This is what lets affine gates stay authenticated without any interaction.
 */
export function addPublicAuth(x: AuthSV, c: bigint, ctx: MacContext): AuthSV {
  const k = mod(c);
  const value = x.value.slice();
  value[0] = fadd(value[0]!, k);
  const mac = x.mac.map((mi, i) => fadd(mi, fmul(ctx.alphaShares[i]!, k)));
  return { value, mac };
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
  private readonly opened: { value: bigint; macShares: bigint[]; label: string }[] = [];
  private counter = 0;

  constructor(ctx: MacContext, deviations: Deviation[] = []) {
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
    const valueShares = x.value.slice();
    const macShares = x.mac.slice();
    for (const d of this.deviations) {
      if (d.openIndex !== idx) continue;
      if (d.party < 0 || d.party >= this.ctx.n) throw new Error('Deviation.party out of range');
      if (d.valueDelta !== undefined) valueShares[d.party] = fadd(valueShares[d.party]!, d.valueDelta);
      if (d.macDelta !== undefined) macShares[d.party] = fadd(macShares[d.party]!, d.macDelta);
    }
    const value = valueShares.reduce((a, b) => fadd(a, b), 0n);
    this.opened.push({ value, macShares, label });
    return value;
  }

  /**
   * SPDZ MAC-check over every partial-open so far. Draws public random coefficients r_j (a secure
   * coin-flip in the real protocol; a seeded RNG here, documented), forms the public combination
   * a = Σ r_j·a_j and each party's residual share σ_i = (Σ r_j·γ_i(a_j)) − α_i·a, then runs
   * commit-then-open on the σ_i and checks Σ σ_i = 0. Honest runs give exactly 0; ANY inconsistent
   * opened value or forged MAC makes it non-zero with probability ≥ 1 − 2/p, and we ABORT.
   *
   * The commit-then-open (SHA-256 binding commitment) models the round that stops a *rushing*
   * adversary from choosing its σ_i after seeing the others — it must commit before any are revealed.
   */
  macCheck(rng: FieldRng): void {
    if (this.opened.length === 0) return;
    const r = this.opened.map(() => rng.next());

    let a = 0n;
    for (let j = 0; j < this.opened.length; j++) a = fadd(a, fmul(r[j]!, this.opened[j]!.value));

    const sigma: bigint[] = [];
    for (let i = 0; i < this.ctx.n; i++) {
      let gamma = 0n;
      for (let j = 0; j < this.opened.length; j++) {
        gamma = fadd(gamma, fmul(r[j]!, this.opened[j]!.macShares[i]!));
      }
      sigma.push(fsub(gamma, fmul(this.ctx.alphaShares[i]!, a)));
    }

    // Commit-then-open: every party commits to σ_i (binding) before any σ is revealed.
    const nonces = sigma.map(() => rng.next());
    const commitments = sigma.map((s, i) => commit(s, nonces[i]!));
    for (let i = 0; i < sigma.length; i++) {
      // Opening phase: a σ_i revealed inconsistent with its commitment is itself an abort.
      if (commit(sigma[i]!, nonces[i]!) !== commitments[i]) {
        throw new MacCheckAbort(`MAC-check: commitment from party ${i} did not open consistently`);
      }
    }

    const residual = sigma.reduce((x, y) => fadd(x, y), 0n);
    if (residual !== 0n) {
      throw new MacCheckAbort(
        `MAC-check FAILED: residual ${residual} != 0 — an actively-malicious party was detected; aborting with no output`,
      );
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
}
