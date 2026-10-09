/**
 * @atlasauth/pca-invariants
 *
 * Property-based machine-checking of PCA's core SAFETY INVARIANTS. Thousands of randomly-generated
 * capability chains, policies, risk inputs and actions are run through the REAL `@atlasauth/pca`
 * core (nothing is re-implemented) to assert four universal properties:
 *
 *   1. Attenuation monotonicity — a delegate step can only shrink or preserve authority, never widen
 *      it (append-only caveats, monotone budget allocations, leaf authority ⊆ every ancestor's).
 *   2. Budget soundness — auto-admitted cost κ·r is always covered, the cumulative machine-only risk
 *      obeys Σr ≤ bMax/κ, r is clamped to [0,S], and the risk functional is monotone in its inputs.
 *   3. Fail-closed — undecidable predicates/conditions, unknown caveat types and forged/garbage
 *      chains all deny / fail to verify.
 *   4. Determinism — deciding the same input twice yields identical results.
 *
 * The arbitraries and the `checkInvariants()` runner are exported so other packages can reuse the
 * same universal checks.
 */

export * from './arbitraries';
export * from './properties';
