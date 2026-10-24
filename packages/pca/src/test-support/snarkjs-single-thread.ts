/**
 * Run snarkjs single-threaded when the test itself runs inside a worker thread.
 *
 * snarkjs builds its BN254 / BLS12-381 curves through ffjavascript, whose multi-threaded mode spawns workers through
 * the `web-worker` package. That package only works from the MAIN thread: loaded inside a worker thread it exports the
 * worker-side bootstrap instead of the Worker class, so every real prove / verify fails with "Worker is not a
 * constructor". Vitest's default `forks` pool runs tests on a process main thread, but Stryker's vitest runner forces
 * the `threads` pool, so the real-proof tests failed Stryker's initial test run.
 *
 * ffjavascript caches the multi-threaded curve in `globalThis.curve_bn128` / `globalThis.curve_bls12381` and returns
 * that cache to every later `buildBn128()` / `buildBls12381()` call (snarkjs never terminates it). Installing
 * single-threaded curves there makes every snarkjs prove / verify in this thread run on the same wasm curve code without
 * workers. The proofs and verifications are unchanged; only where the arithmetic runs differs.
 */
import { createRequire } from 'node:module';
import { isMainThread } from 'node:worker_threads';

export async function useSingleThreadSnarkCurvesInWorkerThreads(): Promise<void> {
  if (isMainThread) return;
  // Load snarkjs first: its ffjavascript module clears the two globals when it is first evaluated.
  const spec: string = 'snarkjs';
  await import(spec);
  const fromSnarkjs = createRequire(createRequire(import.meta.url).resolve(spec));
  const ff = fromSnarkjs('ffjavascript') as { buildBn128(single: boolean): Promise<unknown>; buildBls12381(single: boolean): Promise<unknown> };
  const g = globalThis as { curve_bn128?: unknown; curve_bls12381?: unknown };
  g.curve_bn128 = await ff.buildBn128(true);
  g.curve_bls12381 = await ff.buildBls12381(true);
}
