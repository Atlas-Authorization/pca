/**
 * Test-only reference checker: brute force over EVERY order consistent with real time (and both effects of every unknown
 * outcome), against the contract written out per operation (independent of the unified register in model.ts).
 */
import type { Op } from '../model';

type State = number | undefined;

/** The contract, per operation kind, as the store would apply it. Returns the possible successor states. */
export function contractStep(s: State, op: Op): State[] {
  const applies = op.kind === 'consume' ? s === undefined || s < op.lo : s === undefined || op.lo > s;
  const after: State = op.kind === 'consume' ? Math.max(op.w, s ?? op.w) : op.lo;
  if (op.res === 'true') return applies ? [after] : [];
  if (op.res === 'false') return applies ? [] : [s];
  return applies ? [s, after] : [s];
}

export function bruteLinearizable(ops: readonly Op[]): boolean {
  const n = ops.length;
  const done = new Array<boolean>(n).fill(false);
  const rec = (s: State, count: number): boolean => {
    if (count === n) return true;
    for (let i = 0; i < n; i++) {
      if (done[i]) continue;
      const blocked = ops.some((o, j) => !done[j] && j !== i && o.ret < ops[i]!.call);
      if (blocked) continue;
      for (const s2 of contractStep(s, ops[i]!)) {
        done[i] = true;
        const ok = rec(s2, count + 1);
        done[i] = false;
        if (ok) return true;
      }
    }
    return false;
  };
  return rec(undefined, 0);
}

/** Deterministic PRNG for the generators. */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * A random small history of one key. mode 'legal': generated from a real sequential execution (each operation takes
 * effect at a random point inside its interval), so it is linearizable by construction. 'flip': a legal one with one
 * answer changed (often illegal). 'random': arbitrary answers.
 */
export function randomHistory(r: () => number, mode: 'legal' | 'flip' | 'random', kind: Op['kind'] = r() < 0.5 ? 'consume' : 'advance'): Op[] {
  const int = (k: number): number => Math.floor(r() * k);
  const n = 1 + int(6);
  const ops: (Op & { p: number })[] = [];
  for (let i = 0; i < n; i++) {
    const call = int(20);
    const unknown = r() < 0.2;
    const ret = unknown ? Infinity : call + int(8);
    const lo = kind === 'consume' ? int(6) : int(4);
    const w = kind === 'consume' ? lo + int(7) : lo;
    const p = unknown ? call + r() * 30 : call + r() * (ret - call);
    ops.push({ client: `c${i}`, kind, key: 'k', lo, w, call, ret, res: 'unknown', p });
  }
  let s: State;
  for (const o of [...ops].sort((a, b) => a.p - b.p)) {
    const applies = o.kind === 'consume' ? s === undefined || s < o.lo : s === undefined || o.lo > s;
    const ret = o.ret;
    if (ret === Infinity) {
      if (applies && r() < 0.5) s = o.kind === 'consume' ? Math.max(o.w, s ?? o.w) : o.lo;
      continue;
    }
    o.res = applies ? 'true' : 'false';
    if (applies) s = o.kind === 'consume' ? Math.max(o.w, s ?? o.w) : o.lo;
  }
  const out: Op[] = ops.map(({ p: _p, ...o }) => o);
  if (mode === 'flip') {
    const o = out[int(out.length)]!;
    if (o.res !== 'unknown') o.res = o.res === 'true' ? 'false' : 'true';
  } else if (mode === 'random') {
    for (const o of out) if (o.res !== 'unknown') o.res = r() < 0.5 ? 'true' : 'false';
  }
  return out;
}
