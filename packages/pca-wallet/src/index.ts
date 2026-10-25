/**
 * @atlasauth/pca-wallet: the wallet side of the PCA Intent Layer v2 (docs/specs/pca-intent-layer-v2.md).
 *
 *  - V4  the trusted question channel (§3.4): verifier-selected cells, wallet-rendered cards from fixed templates (no
 *        agent text), friction tiers scaled by harm, per-session and per-hour question caps, attention canaries with
 *        Beta / Clopper–Pearson noise estimates (T16: canaries never change the grant), the approval-fatigue model,
 *        double confirmation of irreversible cells under estimated noise; the signed answer (M6) and the
 *        site-signed `intent_required` body (M5).
 *  - V13 agent-initiated clarifications (§3.14): structured candidates and a closed reason enum, dry-run verdicts,
 *        max-information cell selection; asked through the same channel.
 *  - V16 opt-in population priors (§3.12): one vote per principal per cell per period, central Gaussian DP release or
 *        local randomized response, the mixture prior (β < 1, so neutral at τ = 1: T23) and `priorAdmittedPpm`.
 */
export * from './wire';
export * from './box';
export * from './friction';
export * from './card';
export * from './stats';
export * from './canary';
export * from './fatigue';
export * from './clarify';
export * from './channel';
export * from './population';
export * from './handlers';
export * from './delivery';
