/* eslint-disable @typescript-eslint/no-explicit-any */
// runtime.ts - one fix to the Dafny JavaScript RUNTIME that ships inside every generated/pca_*.js (trusted base, not proved code).
//
// The stock runtime concatenates two sequences with `let r = Seq.of(...a); r.push(...b)`. Spreading an array into a call
// passes every element as a stack argument, so a sequence of more than roughly 10^5 elements throws
// "RangeError: Maximum call stack size exceeded" (the exact limit depends on the engine's stack size). The proved parser
// copies a run of plain string characters as ONE slice (StrBodyF), so a single 1 MiB JSON string, which the strict profile
// accepts, crashed the proved strict-JSON gate. This replacement has the same result (a new Seq holding a's elements then
// b's; the string branch is unchanged) and copies with a loop, so its stack use does not depend on the length.

const HARDENED = Symbol.for('atlasauth.pca-verified-core.runtime-hardened');

/** Replace `_dafny.Seq.Concat` of one generated module's runtime by a loop-based copy. Idempotent. Returns the runtime. */
export function hardenDafnyRuntime<T>(dafny: T): T {
  const Seq = (dafny as any)?.Seq;
  if (typeof Seq !== 'function' || Seq[HARDENED] === true) return dafny;
  Seq.Concat = function Concat(a: any, b: any): any {
    if (typeof a === 'string' || typeof b === 'string') {
      // string concatenation (as in the stock runtime): make both operands strings first
      return (typeof a === 'string' ? a : a.join('')) + (typeof b === 'string' ? b : b.join(''));
    }
    const r = Seq.of();
    for (let i = 0; i < a.length; i++) r.push(a[i]);
    for (let i = 0; i < b.length; i++) r.push(b[i]);
    return r;
  };
  Object.defineProperty(Seq, HARDENED, { value: true });
  return dafny;
}
