// Shared case recorder for the foundation oracles. Case args are JSON-clean; the reference runs on the revived copy:
//   {"$num":"NaN"|"Infinity"|"-Infinity"} -> that double ; {"$bytes": b64u} -> Uint8Array (secret keys are seed(label) bytes, rewritten to
//   {"$bytes":{"$seed":label}} by strip-corpus-keys.py --any) ; null in an optional position is "not given" (the REF wrapper maps it).
import { capture, ser } from '../oracles-base/lib.mjs';
export const NUMV = { NaN: NaN, Infinity: Infinity, '-Infinity': -Infinity };
export const revive = (v) => Array.isArray(v) ? v.map(revive)
  : v && typeof v === 'object' ? (Object.keys(v).length === 1 && '$bytes' in v && typeof v.$bytes === 'string' ? new Uint8Array(Buffer.from(v.$bytes, 'base64url'))
    : Object.keys(v).length === 1 && '$num' in v ? NUMV[v.$num] : Object.keys(v).length === 1 && '$bigint' in v ? BigInt(v.$bigint) : Object.fromEntries(Object.entries(v).map(([k, x]) => [k, revive(x)]))) : v;
export const nul = (x) => (x === null ? undefined : x);
export const NUMS = [0, -0, 1, 0.5, 0.25, 1e-9, -1, 2, 1e21, 5e-324, 2 ** 53, { $num: 'NaN' }, { $num: 'Infinity' }, { $num: '-Infinity' }, '0.5', true, [], {}];
/** adder(o, REF) -> async add(fn, name, args): records {fn, name#n, args, out}; REF[fn](...revivedArgs) may be async. */
export function adder(o, REF) {
  let seq = 0;
  return async (fn, name, args) => {
    const j = JSON.parse(ser(args));
    const out = await capture(REF[fn], revive(j));
    o.add(fn, `${name}#${seq++}`, j, out);
  };
}
export const flip = (s) => s.slice(0, -2) + (s.slice(-2) === 'AA' ? 'BB' : 'AA');
