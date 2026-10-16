/**
 * History recording. The invocation is recorded BEFORE the request leaves the client and the response after it
 * completes. An operation that errors, times out or whose client dies keeps an open-ended interval (`ret = Infinity`,
 * outcome unknown): it may or may not have taken effect, at any time after its invocation.
 *
 * Two recorders: in memory (one process), and an append-only file (one `write(2)` per event, so a client process killed
 * with SIGKILL leaves its in-flight operations PENDING, exactly like a crash in production; torn lines are skipped).
 */
import { closeSync, openSync, writeSync } from 'node:fs';
import type { Op, OpKind } from './model';

/** Wall-clock milliseconds with sub-millisecond resolution; comparable across processes on one host. */
export const clock = (): number => performance.timeOrigin + performance.now();

export interface Recorder {
  invoke(client: string, kind: OpKind, key: string, lo: number, w: number): Op;
  /** `true` / `false`: the definite answer; `unknown`: the call failed or timed out (stays open-ended). */
  complete(op: Op, result: boolean | 'unknown'): void;
}

export class MemoryRecorder implements Recorder {
  readonly ops: Op[] = [];
  invoke(client: string, kind: OpKind, key: string, lo: number, w: number): Op {
    const op: Op = { client, kind, key, lo, w, call: clock(), ret: Infinity, res: 'unknown' };
    this.ops.push(op);
    return op;
  }
  complete(op: Op, result: boolean | 'unknown'): void {
    if (result === 'unknown') return;
    op.ret = clock();
    op.res = result ? 'true' : 'false';
  }
}

/** Appends `i` / `r` lines to `path`; `proc` must be unique per process incarnation. */
export class FileRecorder implements Recorder {
  private readonly fd: number;
  private seq = 0;
  private readonly ids = new WeakMap<Op, number>();
  constructor(
    path: string,
    private readonly proc: string,
  ) {
    this.fd = openSync(path, 'a');
  }
  invoke(client: string, kind: OpKind, key: string, lo: number, w: number): Op {
    const op: Op = { client, kind, key, lo, w, call: clock(), ret: Infinity, res: 'unknown' };
    const id = ++this.seq;
    this.ids.set(op, id);
    writeSync(this.fd, `${JSON.stringify(['i', this.proc, id, op.call, client, kind, key, lo, w])}\n`);
    return op;
  }
  complete(op: Op, result: boolean | 'unknown'): void {
    const at = clock();
    writeSync(this.fd, `${JSON.stringify(['r', this.proc, this.ids.get(op), at, result === 'unknown' ? 'unknown' : String(result)])}\n`);
  }
  close(): void {
    closeSync(this.fd);
  }
}

/**
 * Rebuild the operations from recorder lines (any number of files concatenated). An invocation without a response is
 * pending (unknown, open-ended); an `unknown` response stays open-ended too. Lines that do not parse are counted as torn.
 */
export function parseHistory(text: string): { ops: Op[]; torn: number; pending: number } {
  const open = new Map<string, Op>();
  const ops: Op[] = [];
  let torn = 0;
  for (const line of text.split('\n')) {
    if (line === '') continue;
    let e: unknown;
    try {
      e = JSON.parse(line);
    } catch {
      torn++;
      continue;
    }
    if (!Array.isArray(e)) {
      torn++;
      continue;
    }
    const id = `${String(e[1])}/${String(e[2])}`;
    if (e[0] === 'i' && e.length === 9) {
      const op: Op = { client: String(e[4]), kind: e[5] as OpKind, key: String(e[6]), lo: Number(e[7]), w: Number(e[8]), call: Number(e[3]), ret: Infinity, res: 'unknown' };
      open.set(id, op);
      ops.push(op);
    } else if (e[0] === 'r' && e.length === 5 && open.has(id)) {
      const op = open.get(id)!;
      open.delete(id);
      if (e[4] !== 'unknown') {
        op.ret = Number(e[3]);
        op.res = e[4] === 'true' ? 'true' : 'false';
      }
    } else {
      torn++;
    }
  }
  return { ops, torn, pending: open.size };
}
