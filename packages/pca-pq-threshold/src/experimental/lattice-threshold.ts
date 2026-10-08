/**
 * ╔══════════════════════════════════════════════════════════════════════════════════════════╗
 * ║  EXPERIMENTAL — NOT PRODUCTION. NO SECURITY PROOF. TIMING-UNSAFE. RESEARCH / INTEROP ONLY.  ║
 * ╚══════════════════════════════════════════════════════════════════════════════════════════╝
 *
 * Raccoon / Ringtail-style LATTICE-THRESHOLD design + a TOY additive-secret-sharing sketch.
 *
 * This file exists to document the trustless-post-quantum-threshold FUTURE and to give a minimal,
 * runnable interop toy — NOT to be shipped. The production, available-TODAY path is the HYBRID in
 * `../index.ts` (a classical FROST threshold + an ML-DSA co-signature quorum). Use that.
 *
 * WHY THIS IS NOT PRODUCTION
 * --------------------------
 *   • No audited, constant-time, interop-stable library exists for Raccoon or Ringtail. The toy below
 *     shares a key by ordinary additive secret sharing over Z_q — it does NOT implement the masked
 *     lattice signing, noise flooding, or the distributed Gaussian sampling those schemes require.
 *   • The arithmetic here uses variable-time bigint. It leaks secrets through timing. Do not sign with it.
 *   • Additive sharing is n-of-n (ALL shares are required to reconstruct). A genuine t-of-n lattice
 *     threshold needs the full Raccoon/Ringtail machinery (see {@link RACCOON_DESIGN}), which is the
 *     whole reason the shippable path is the hybrid and not this.
 *
 * Every function here is gated behind an explicit opt-in flag; calling without it throws the banner.
 */

export const EXPERIMENTAL_BANNER =
  'EXPERIMENTAL — NOT PRODUCTION. No security proof, timing-unsafe, for research/interop only. ' +
  'The shippable post-quantum threshold step-up is the HYBRID (classical FROST threshold + ML-DSA ' +
  'co-signature quorum) in @atlasauth/pca-pq-threshold; do NOT use this lattice-threshold prototype to sign.';

/** The explicit, loud opt-in a caller must pass to run any experimental routine. */
export interface ExperimentalOptIn {
  /**
   * Must be `true` at runtime. Anything else (including `false` or an omitted-then-undefined opt-in)
   * throws {@link EXPERIMENTAL_BANNER}. It is the caller's acknowledgement that this is NOT production.
   */
  readonly iUnderstandThisIsNotProduction: boolean;
}

function assertOptIn(optIn: ExperimentalOptIn | undefined): void {
  if (!optIn || optIn.iUnderstandThisIsNotProduction !== true) {
    throw new Error(`${EXPERIMENTAL_BANNER} Pass { iUnderstandThisIsNotProduction: true } to proceed.`);
  }
}

// ---------------------------------------------------------------------------------------------
// The research design (a typed, frozen spec object — documentation, not executable crypto)
// ---------------------------------------------------------------------------------------------

export interface RaccoonDesignParameterSet {
  readonly name: string;
  readonly nistCategory: number;
  readonly note: string;
}

export interface RaccoonDesign {
  readonly scheme: 'Raccoon/Ringtail-style lattice threshold (RESEARCH)';
  readonly status: 'research-prototype';
  readonly productionReady: false;
  readonly banner: string;
  /** The hard problem the trustless-threshold future rests on. */
  readonly assumption: string;
  /** The high-level construction, step by step. */
  readonly construction: readonly string[];
  /** Why no shippable library exists yet. */
  readonly whyNoLibraryYet: readonly string[];
  /** What the SHIPPABLE path does instead, today. */
  readonly shippableAlternative: string;
  readonly parameterSets: readonly RaccoonDesignParameterSet[];
  readonly references: readonly string[];
}

/**
 * A documented spec of the Raccoon/Ringtail-style lattice-threshold approach. This is DATA describing
 * the research design — it does not perform any cryptography. See the shippable hybrid for the real path.
 */
export const RACCOON_DESIGN: RaccoonDesign = Object.freeze({
  scheme: 'Raccoon/Ringtail-style lattice threshold (RESEARCH)',
  status: 'research-prototype',
  productionReady: false,
  banner: EXPERIMENTAL_BANNER,
  assumption: 'Module-LWE / Module-SIS (the same lattice assumptions as ML-DSA / FIPS-204), believed hard for quantum adversaries.',
  construction: Object.freeze([
    '1. Distributed key generation: the signing key (a short vector / small polynomial) is SECRET-SHARED across n parties — Raccoon uses additive masking; Ringtail layers a one-time additive mask over a replicated/Shamir-style sharing to reach genuine t-of-n.',
    '2. Each party holds a share s_i such that the shares combine (additively, mod q, per coefficient) to the signing key s.',
    '3. Signing is a masked, multi-round protocol: parties jointly sample commitment randomness, each adds Gaussian NOISE FLOODING to its partial response so the partials leak nothing about the individual shares, and the masked partials are summed.',
    '4. The combined response is accepted only if it passes the standard ML-DSA-style rejection-sampling bound; otherwise the round restarts. The output is a single signature verifiable under ONE ordinary ML-DSA-style public key.',
    '5. A quantum break of a CLASSICAL threshold does not help here — forging requires solving the underlying lattice problem.',
  ] as const),
  whyNoLibraryYet: Object.freeze([
    'Distributed discrete Gaussian / noise-flooding sampling with the right parameters is subtle and unimplemented in any audited library.',
    'Parameter selection for the threshold setting is still moving; interop test vectors are not standardised.',
    'No constant-time, side-channel-hardened reference implementation has been published and audited.',
    'The abort/restart rejection-sampling rounds complicate liveness and make a robust networked coordinator non-trivial.',
  ] as const),
  shippableAlternative:
    'Use the HYBRID in @atlasauth/pca-pq-threshold: a classical FROST(Ed25519) t-of-n threshold AND a pqT-of-m ML-DSA-65 co-signature quorum over the same action. It is post-quantum-protected TODAY (a classical threshold break cannot forge the step-up without ALSO forging the ML-DSA quorum) using only audited, available primitives.',
  parameterSets: Object.freeze([
    Object.freeze({ name: 'Raccoon-128 (illustrative)', nistCategory: 1, note: 'Research parameters only; not implemented here.' }),
    Object.freeze({ name: 'Raccoon-192 (illustrative)', nistCategory: 3, note: 'Matches ML-DSA-65 category; not implemented here.' }),
  ] as const),
  references: Object.freeze([
    'Raccoon: a side-channel-resilient lattice signature (NIST additional-signatures submission).',
    'Ringtail: two-round threshold signatures from lattices.',
    'FIPS-204 (ML-DSA) — the single-party base scheme the threshold variants mirror.',
  ] as const),
});

// ---------------------------------------------------------------------------------------------
// The TOY additive secret-sharing sketch (reconstruct works in-toy; NOT a signature scheme)
// ---------------------------------------------------------------------------------------------

/** Toy lattice parameters. Tiny `q` for demonstration — NOT a real ML-DSA modulus. */
export interface ToyLatticeParams {
  /** Prime-ish modulus for coefficient arithmetic (toy; real ML-DSA uses q = 8380417). */
  readonly q: bigint;
  /** Dimension of the toy key vector. */
  readonly dim: number;
}

/** The default illustrative ML-DSA modulus, used purely so the arithmetic looks familiar. */
export const TOY_DEFAULT_PARAMS: ToyLatticeParams = Object.freeze({ q: 8380417n, dim: 4 });

/** One party's additive share of the toy lattice key: a coefficient vector mod q. */
export interface LatticeKeyShare {
  /** 1-based party index. */
  readonly index: number;
  /** The share's coefficient vector (length === params.dim), each in [0, q). */
  readonly coeffs: readonly bigint[];
}

function mod(x: bigint, q: bigint): bigint {
  const r = x % q;
  return r < 0n ? r + q : r;
}

/** A source of a random coefficient in [0, q). Injectable so tests are deterministic. */
export type CoeffSampler = (q: bigint) => bigint;

function defaultCoeffSampler(q: bigint): bigint {
  // TOY ONLY — non-cryptographic PRNG (Math.random). The banner is explicit: timing-unsafe, not for
  // real keys. A caller who wants reproducibility injects its own {@link CoeffSampler}.
  const hi = BigInt(Math.floor(Math.random() * 0x1_0000_0000));
  const lo = BigInt(Math.floor(Math.random() * 0x1_0000_0000));
  return mod((hi << 32n) | lo, q);
}

/**
 * EXPERIMENTAL. Additively secret-share a toy lattice key vector into `n` shares over Z_q, per
 * coefficient: shares 1..n-1 are random, the last absorbs the remainder so Σ shares ≡ key (mod q).
 *
 * This is n-of-n (ALL n shares reconstruct). It is NOT t-of-n and NOT a signature scheme — see
 * {@link RACCOON_DESIGN} for what a real lattice threshold additionally needs. Gated behind the opt-in.
 */
export function additiveShareLatticeKey(
  key: readonly bigint[],
  n: number,
  optIn: ExperimentalOptIn,
  params: ToyLatticeParams = TOY_DEFAULT_PARAMS,
  sampler: CoeffSampler = defaultCoeffSampler,
): LatticeKeyShare[] {
  assertOptIn(optIn);
  if (!Number.isInteger(n) || n < 1) throw new RangeError('additiveShareLatticeKey: n must be a positive integer');
  if (key.length !== params.dim) throw new RangeError(`additiveShareLatticeKey: key must have ${params.dim} coefficients`);

  // Per coefficient, build n shares summing to the key coefficient (mod q).
  const shareCoeffs: bigint[][] = Array.from({ length: n }, () => Array.from({ length: params.dim }, () => 0n));
  for (let c = 0; c < params.dim; c++) {
    const target = mod(key[c] ?? 0n, params.q);
    let running = 0n;
    for (let i = 0; i < n - 1; i++) {
      const r = mod(sampler(params.q), params.q);
      const row = shareCoeffs[i];
      if (row) row[c] = r;
      running = mod(running + r, params.q);
    }
    const lastRow = shareCoeffs[n - 1];
    if (lastRow) lastRow[c] = mod(target - running, params.q);
  }

  return shareCoeffs.map((coeffs, i) => ({ index: i + 1, coeffs }));
}

/**
 * EXPERIMENTAL. Reconstruct the toy lattice key by summing ALL shares' coefficient vectors mod q.
 * Because the sharing is additive (n-of-n), every share must be present. Gated behind the opt-in.
 */
export function reconstructLatticeKey(
  shares: readonly LatticeKeyShare[],
  optIn: ExperimentalOptIn,
  params: ToyLatticeParams = TOY_DEFAULT_PARAMS,
): bigint[] {
  assertOptIn(optIn);
  if (shares.length === 0) throw new RangeError('reconstructLatticeKey: need at least one share');
  const out: bigint[] = Array.from({ length: params.dim }, () => 0n);
  for (const share of shares) {
    if (share.coeffs.length !== params.dim) throw new RangeError(`reconstructLatticeKey: a share has the wrong dimension`);
    for (let c = 0; c < params.dim; c++) {
      out[c] = mod((out[c] ?? 0n) + (share.coeffs[c] ?? 0n), params.q);
    }
  }
  return out;
}
