import { type PCActn, pcactnDigest, sha256, utf8 } from '@atlasauth/pca';
import { type VdfProof, bytesToBigInt, checkProductionModulus, vdfEval, vdfVerify } from './vdf';

/**
 * ============================================================================
 *  PCA timelock — a mandatory, offline-verifiable cooling-off on irreversible
 *  actions, enforced by a Wesolowski VDF.
 * ============================================================================
 *
 * The problem: some PCA actions are irreversible (a large transfer, a key
 * deletion, a production data wipe). We want a MANDATORY cooling-off: the action
 * must not execute until a provable, unskippable delay has elapsed — and we want
 * to prove the delay WITHOUT trusting any clock, timestamp, or online service,
 * because a compromised agent (or host) can lie about wall-clock time.
 *
 * The VDF solves exactly this. We bind a VDF challenge to THE SPECIFIC action:
 *
 *   x = H( domain ‖ actionDigest )  mod N
 *
 * so the only way to produce a valid proof for this action is to run `steps`
 * sequential squarings on an input nobody can compute early (it depends on the
 * action's own digest). When the proof verifies, a relying party KNOWS the
 * squaring chain ran — a clock-free, offline witness that the cooling-off time
 * passed. A proof computed for action A has a different `x` than action B, so it
 * does not release B (binding).
 *
 *   requireTimelock(action, { steps, N })   -> the requirement (derives x)
 *   proveTimelockElapsed(action, steps, N)  -> run the VDF (the cost IS the wait)
 *   verifyTimelock(action, proof, { steps, N }) -> gate release, cheap + offline
 *
 * CALIBRATION (steps ≈ wall-clock). A VDF measures sequential WORK, not seconds.
 * To turn a desired cooling-off duration into a `steps` count you must calibrate
 * against the FASTEST squaring rate an adversary could achieve on this modulus
 * (optimised hardware is faster than your reference machine — pick `steps`
 * against a conservative upper bound so the real delay can only be LONGER, never
 * shorter): measure squarings-per-second `S_fast`, then `steps ≈ S_fast *
 * desired_seconds`. See {@link calibrateSteps}. Treat the resulting wall-clock as
 * a FLOOR (the honest party may be slower); never as an exact timer.
 */

/** Something a timelock can be bound to: a full PCActn, or any precomputed digest string. */
export type TimelockActionRef = PCActn | string;

/** A derived timelock requirement: the VDF challenge `x`, the step count, and the modulus. */
export interface TimelockRequirement {
  readonly kind: 'vdf-timelock';
  /** The VDF input `x`, deterministically derived from the action (in `[2, N)`). */
  readonly x: bigint;
  /** Number of sequential squarings required (the enforced delay). */
  readonly steps: number;
  /** The RSA modulus (unknown factorisation). */
  readonly N: bigint;
  /** The action digest `x` was derived from (for diagnostics / logging). */
  readonly actionDigest: string;
}

/** A timelock proof: a VDF proof plus the step count it was produced for. */
export interface TimelockProof {
  readonly kind: 'vdf-timelock-proof';
  /** `y = x^(2^steps) mod N`. */
  readonly y: bigint;
  /** The Wesolowski proof. */
  readonly pi: bigint;
  /** The number of squarings this proof attests to (must match the requirement). */
  readonly steps: number;
}

const X_DERIVATION_DOMAIN = 'atlas-pca/vdf/timelock/input/v1\0';

/**
 * The canonical digest a timelock binds to. A `PCActn` uses {@link pcactnDigest}
 * (`base64url(sha256(strictCanonical(pcactn)))`, the same digest the PCA ledger
 * and receipts use), so the delay is bound to the exact signed action. A string
 * is treated as an opaque, already-computed action digest.
 */
export function actionDigest(action: TimelockActionRef): string {
  return typeof action === 'string' ? action : pcactnDigest(action);
}

/**
 * Derive the VDF input `x in [2, N)` from an action, so the delay is bound to
 * THIS action: `x = (bytesToBigInt(sha256(domain ‖ utf8(digest))) mod N)`, nudged
 * into `[2, N)` to avoid the degenerate inputs `0` and `1` (whose squaring chain
 * is constant). Deterministic: the same action + modulus always yield the same
 * `x`, and different actions yield different `x`.
 */
export function deriveTimelockInput(action: TimelockActionRef, N: bigint): bigint {
  if (typeof N !== 'bigint' || N <= 3n) throw new RangeError('deriveTimelockInput: modulus N must be a bigint > 3');
  const digest = actionDigest(action);
  const h = sha256(utf8(X_DERIVATION_DOMAIN + digest));
  const raw = bytesToBigInt(h) % N;
  // Avoid x in {0, 1}: those give a constant chain. N > 3 guarantees room.
  return raw <= 1n ? raw + 2n : raw;
}


/**
 * Options shared by the timelock entry points. `allowInsecureDevModulus` exists ONLY so tests and local
 * experiments can run on a small / self-generated modulus (see `insecureDevSetup`); the name is
 * deliberately loud. Production code never sets it.
 */
export interface TimelockOptions {
  readonly steps: number;
  readonly N: bigint;
  /** DEV/TEST ONLY: skip the production-modulus screen. A timelock on such a modulus delays nobody who knows its factors. */
  readonly allowInsecureDevModulus?: boolean;
}

/** Throw unless `N` passes the production screen (or the caller opted out by name). */
function requireProductionModulus(N: bigint, allowInsecureDevModulus: boolean | undefined): void {
  if (allowInsecureDevModulus === true) return;
  const check = checkProductionModulus(N);
  if (!check.ok) {
    throw new RangeError(
      `timelock: refusing this modulus: ${check.reason}. Use RSA_2048_CHALLENGE_MODULUS or a ceremony modulus; ` +
        'tests may pass allowInsecureDevModulus: true.',
    );
  }
}

/** Normalise and validate a step count. */
function requireSteps(steps: number): number {
  if (!Number.isSafeInteger(steps) || steps < 1) throw new RangeError(`timelock: steps must be a safe integer >= 1, got ${String(steps)}`);
  return steps;
}

/**
 * Build the timelock requirement for an action: derive the VDF input `x` bound to
 * the action, and carry `steps` and `N`. This is the caveat a policy attaches to
 * an irreversible action; the matching proof must be a valid VDF proof for this
 * exact `(x, steps, N)`.
 */
export function requireTimelock(action: TimelockActionRef, opts: TimelockOptions): TimelockRequirement {
  const steps = requireSteps(opts.steps);
  requireProductionModulus(opts.N, opts.allowInsecureDevModulus);
  const x = deriveTimelockInput(action, opts.N);
  return { kind: 'vdf-timelock', x, steps, N: opts.N, actionDigest: actionDigest(action) };
}

/**
 * Run the VDF for an action: the `steps` sequential squarings ARE the enforced
 * cooling-off, so this call is deliberately slow — it cannot finish before the
 * delay has elapsed. Returns the proof a relying party verifies cheaply.
 */
export function proveTimelockElapsed(
  action: TimelockActionRef,
  steps: number,
  N: bigint,
  opts?: { readonly allowInsecureDevModulus?: boolean },
): TimelockProof {
  const s = requireSteps(steps);
  requireProductionModulus(N, opts?.allowInsecureDevModulus);
  const x = deriveTimelockInput(action, N);
  const proof: VdfProof = vdfEval(x, s, N);
  return { kind: 'vdf-timelock-proof', y: proof.y, pi: proof.pi, steps: s };
}

/**
 * Gate release on a valid VDF proof for the RIGHT input and step count.
 *
 * FAIL CLOSED. Re-derives `x` from the action itself (so a proof cannot lie about
 * which action it is for), checks the proof's `steps` equals the REQUIRED `steps`
 * (a shorter delay is rejected), then runs the O(log) VDF verify. A proof built
 * for another action, with the wrong `y`/`pi`, or for a different step count does
 * not verify. Offline — no clock, no network.
 */
export function verifyTimelock(action: TimelockActionRef, proof: TimelockProof, opts: TimelockOptions): boolean {
  try {
    const requiredSteps = requireSteps(opts.steps);
    requireProductionModulus(opts.N, opts.allowInsecureDevModulus); // throws -> caught below -> false
    if (proof === null || typeof proof !== 'object') return false;
    if (proof.kind !== 'vdf-timelock-proof') return false;
    if (!Number.isSafeInteger(proof.steps) || proof.steps !== requiredSteps) return false;
    if (typeof proof.y !== 'bigint' || typeof proof.pi !== 'bigint') return false;
    const x = deriveTimelockInput(action, opts.N);
    return vdfVerify(x, proof.y, proof.pi, requiredSteps, opts.N);
  } catch {
    return false;
  }
}

/**
 * Turn a desired wall-clock cooling-off into a `steps` count by measuring the
 * squaring rate on this machine for this modulus. Because an adversary may square
 * FASTER than the measuring machine, multiply the measured rate by a conservative
 * `adversaryAdvantage` (>= 1) so the resulting real delay is a FLOOR, never less
 * than intended. This is a helper for operators, not part of verification.
 *
 * @param N                 the modulus the timelock will use.
 * @param desiredSeconds    target cooling-off (floor) in seconds.
 * @param sampleSquarings   how many squarings to time (default 50_000).
 * @param adversaryAdvantage assumed speed multiplier of the fastest adversary (default 10).
 * @param now               clock source in ms (default `performance.now`/`Date.now`); for tests.
 */
export function calibrateSteps(opts: {
  N: bigint;
  desiredSeconds: number;
  sampleSquarings?: number;
  adversaryAdvantage?: number;
  now?: () => number;
}): { steps: number; measuredSquaringsPerSecond: number; assumedAdversarySquaringsPerSecond: number } {
  const { N, desiredSeconds } = opts;
  if (typeof N !== 'bigint' || N <= 3n) throw new RangeError('calibrateSteps: modulus N must be a bigint > 3');
  if (!Number.isFinite(desiredSeconds) || desiredSeconds <= 0) throw new RangeError('calibrateSteps: desiredSeconds must be > 0');
  const sample = opts.sampleSquarings ?? 50_000;
  const advantage = opts.adversaryAdvantage ?? 10;
  if (!Number.isSafeInteger(sample) || sample < 1) throw new RangeError('calibrateSteps: sampleSquarings must be a safe integer >= 1');
  if (!Number.isFinite(advantage) || advantage < 1) throw new RangeError('calibrateSteps: adversaryAdvantage must be >= 1');
  const clock = opts.now ?? (typeof performance !== 'undefined' ? () => performance.now() : () => Date.now());

  let y = 2n % N;
  const t0 = clock();
  for (let i = 0; i < sample; i += 1) y = (y * y) % N;
  const elapsedMs = Math.max(clock() - t0, Number.EPSILON);
  // Keep the optimiser from eliminating the loop.
  if (y === -1n) throw new Error('unreachable');

  const measuredPerSecond = (sample / elapsedMs) * 1000;
  const assumedAdversaryPerSecond = measuredPerSecond * advantage;
  const steps = Math.max(1, Math.ceil(assumedAdversaryPerSecond * desiredSeconds));
  return { steps, measuredSquaringsPerSecond: measuredPerSecond, assumedAdversarySquaringsPerSecond: assumedAdversaryPerSecond };
}
