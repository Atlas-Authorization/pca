/**
 * Timing helpers for the network tests (test support, not protocol code; excluded from the package build).
 *
 * Rules the net tests follow so a loaded machine cannot flip an outcome:
 *   - every duration comes from `T()`, which multiplies by `PCA_MPC_TEST_TIMEOUT_SCALE` (default 1; raise it on a slow box);
 *   - the test decides by OBSERVED CONDITIONS (`until`), never by sleeping a fixed time and then asserting;
 *   - liveness-critical timeouts are generous (tens of seconds); only the timeouts that are supposed to FIRE are short, and
 *     their outcome (abort) holds however slow the machine is;
 *   - the mesh takes an injectable clock (`ManualClock`) when a test must control time exactly.
 */
import * as net from 'node:net';
import type { MeshClock } from './mesh';

export { T, TIMEOUT_SCALE, reservePorts } from './launch-support';
import { T } from './launch-support';

/** Poll `cond` until it is truthy (resolving its value) or `ms` (scaled) elapse (rejecting with `what`). */
export async function until<V>(cond: () => V | Promise<V>, what: string, ms = 30_000): Promise<NonNullable<V>> {
  const end = Date.now() + T(ms);
  for (;;) {
    const v = await cond();
    if (v) return v as NonNullable<V>;
    if (Date.now() > end) throw new Error(`timed out waiting for: ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

/** Wait until something accepts TCP connections on `port` (a mesh that has finished `listen`). */
export function waitListening(port: number, host = '127.0.0.1', ms = 30_000): Promise<true> {
  return until(
    () =>
      new Promise<boolean>((res) => {
        const s = net.connect({ port, host });
        s.once('connect', () => {
          s.destroy();
          res(true);
        });
        s.once('error', () => res(false));
      }),
    `port ${port} to accept connections`,
    ms,
  ) as Promise<true>;
}

/** A virtual clock: time moves only when the test says so. Timers fire in order of due time during `advance`. */
export class ManualClock implements MeshClock {
  private t = 0;
  private seq = 0;
  private timers = new Map<number, { due: number; fn: () => void }>();
  now(): number {
    return this.t;
  }
  setTimer(fn: () => void, ms: number): unknown {
    const id = ++this.seq;
    this.timers.set(id, { due: this.t + ms, fn });
    return id;
  }
  clearTimer(h: unknown): void {
    this.timers.delete(h as number);
  }
  /** Advance virtual time by `ms`, firing every timer that falls due (earliest first). */
  advance(ms: number): void {
    const target = this.t + ms;
    for (;;) {
      let best: [number, { due: number; fn: () => void }] | null = null;
      for (const e of this.timers) if (e[1].due <= target && (best === null || e[1].due < best[1].due)) best = e;
      if (best === null) break;
      this.timers.delete(best[0]);
      this.t = Math.max(this.t, best[1].due);
      best[1].fn();
    }
    this.t = target;
  }
  get pending(): number {
    return this.timers.size;
  }
}
