/**
 * Small helpers the local multi-process launcher (`launch-local.ts`) shares with the tests: the one timeout-scale knob and
 * distinct free loopback ports.
 */

const parsed = Number(process.env['PCA_MPC_TEST_TIMEOUT_SCALE'] ?? '1');
/** Multiplier for every launcher/test timeout, from `PCA_MPC_TEST_TIMEOUT_SCALE` (default 1; raise it on a slow machine). */
export const TIMEOUT_SCALE = Number.isFinite(parsed) && parsed > 0 ? parsed : 1;

/** Scale a duration (ms) by the one timeout knob. */
export const T = (ms: number): number => Math.ceil(ms * TIMEOUT_SCALE);
