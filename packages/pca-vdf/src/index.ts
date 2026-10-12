/**
 * @atlasauth/pca-vdf — a Verifiable Delay Function timelock for PCA.
 *
 * A mandatory, OFFLINE-verifiable cooling-off on irreversible actions: an action
 * cannot execute until a Wesolowski VDF proof shows that `T` sequential squarings
 * provably elapsed — no trusted clock, cheap verification.
 *
 * - {@link vdf} / {@link vdfEval} / {@link vdfVerify} — the Wesolowski VDF core.
 * - {@link requireTimelock} / {@link proveTimelockElapsed} / {@link verifyTimelock}
 *   — the PCA timelock layer, binding the delay to a specific PCActn/action.
 *
 * See `vdf.ts` for the trusted-setup honesty note (an RSA-group VDF needs a
 * modulus of unknown factorisation; class groups are the trustless alternative).
 */
export * from './vdf';
export * from './timelock';
