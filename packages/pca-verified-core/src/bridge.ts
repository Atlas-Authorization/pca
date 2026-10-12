/* eslint-disable @typescript-eslint/no-explicit-any */
// bridge.ts - the ONLY file that touches the Dafny-generated runtime types. Everything exported from the package
// is plain JSON-like data / closures; Dafny datatypes (BigNumber ints, Seq, Option, Res, tuples) never leak.
import BigNumber from 'bignumber.js';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const core = require('../generated/pca_core.js') as {
  _dafny: any;
  Common: any;
  Chain: any;
  Caveats: any;
  Threshold: any;
  Replay: any;
  Verdict: any;
};

export const D = core;
export const Common = core.Common;
export const Chain = core.Chain;
export const Threshold = core.Threshold;
export const Replay = core.Replay;
export const Verdict = core.Verdict;
export const Caveats = core.Caveats;

/** A Dafny `int` from a JS number. Only safe integers are representable; anything else is a caller bug. */
export function bn(n: number): BigNumber {
  if (!Number.isSafeInteger(n)) throw new RangeError(`pca-verified-core: expected a safe integer, got ${String(n)}`);
  return new BigNumber(n);
}
export const num = (b: BigNumber): number => b.toNumber();

export const some = <T>(v: T): any => Common.Option.create_Some(v);
export const none = (): any => Common.Option.create_None();
export const opt = <T>(v: T | undefined): any => (v === undefined ? none() : some(v));
export const fromOpt = <T>(o: any): T | undefined => (o.is_Some ? (o.dtor_v as T) : undefined);

/** Dafny seq from a JS array (no spread: safe for very long arrays). */
export function seq<T>(a: readonly T[]): any {
  const s = core._dafny.Seq.of();
  for (let i = 0; i < a.length; i++) s.push(a[i]);
  return s;
}
export const fromSeq = <T>(s: any): T[] => Array.from(s as ArrayLike<T>);

/** Result of a lazily evaluated primitive: ok, or an opaque diagnostic carried through untouched. */
export type Res<M> = { ok: true } | { ok: false; m: M };
export const resOk = (): any => Common.Res.create_Ok();
export const wrapRes = <M>(f: () => Res<M>) => (): any => {
  const r = f();
  return r.ok ? Common.Res.create_Ok() : Common.Res.create_Err(r.m);
};

export type Status = 'pass' | 'fail' | 'not-enforced';
export function toStatus(s: any): Status {
  if (s.is_Pass) return 'pass';
  if (s.is_Fail) return 'fail';
  return 'not-enforced';
}
export function fromStatus(s: Status): any {
  return s === 'pass' ? Common.Status.create_Pass() : s === 'fail' ? Common.Status.create_Fail() : Common.Status.create_NotEnforced();
}
/** Dafny string (sequence of code points) from a JS string - only the replay-store model needs it. */
/** An empty Dafny `Map` (the fresh state for a verified store). */
export const emptyDafnyMap = (): any => core._dafny.Map.Empty;
export const dstr = (s: string): any => core._dafny.Seq.UnicodeFromString(s);
export const jstr = (d: any): string => (d as { toVerbatimString(a: boolean): string }).toVerbatimString(false);
