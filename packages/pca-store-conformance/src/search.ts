/**
 * Linearizability search (Wing-Gong / Lowe style, as in porcupine) for ONE key's history against the register model of
 * `model.ts`. Depth-first over "which pending operation linearizes next", with memoization of (set of linearized
 * operations, register value). An operation may go next only if no other not-yet-linearized operation returned before it
 * was invoked. The search is exponential in the number of mutually concurrent operations, so it is BUDGETED: a key that
 * exceeds the budget is UNRESOLVED, never a pass.
 */
import { step, type Op } from './model';

export type Verdict = 'ok' | 'violation' | 'unresolved';

/** Default number of distinct search states explored per key before giving up (UNRESOLVED). */
export const DEFAULT_SEARCH_BUDGET = 200_000;

export function searchLinearizable(ops: readonly Op[], budget: number = DEFAULT_SEARCH_BUDGET): Verdict {
  const order = [...ops].sort((a, b) => a.call - b.call);
  const n = order.length;
  const bits = order.map((_, i) => 1n << BigInt(i));
  const all = (1n << BigInt(n)) - 1n;
  const seen = new Set<string>();
  const stack: { done: bigint; s: number }[] = [{ done: 0n, s: -Infinity }];
  while (stack.length > 0) {
    const { done, s } = stack.pop()!;
    if (done === all) return 'ok';
    const id = `${done.toString(36)}|${s}`;
    if (seen.has(id)) continue;
    if (seen.size >= budget) return 'unresolved';
    seen.add(id);
    let minRet = Infinity;
    for (let i = 0; i < n; i++) if ((done & bits[i]!) === 0n) minRet = Math.min(minRet, order[i]!.ret);
    // sorted by invocation: once one starts after the earliest pending return, all later ones do too
    for (let i = 0; i < n && order[i]!.call <= minRet; i++) {
      if ((done & bits[i]!) !== 0n) continue;
      for (const s2 of step(s, order[i]!)) stack.push({ done: done | bits[i]!, s: s2 });
    }
  }
  return 'violation';
}
