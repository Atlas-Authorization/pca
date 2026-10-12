/**
 * Pairwise-authenticated shares (BDOZ-style information-theoretic MACs on each party's OWN share).
 *
 * This is what makes an abort IDENTIFIABLE in the trusted-dealer mode. A share `x_i` held by party `i` carries,
 * for every other party `j`, a tag `T_ij` that only `i` holds and a key `K_ij` that only `j` holds, with
 *
 *     T_ij = K_ij + Δ_j · x_i      (Δ_j: party j's secret verification key, one per verifier)
 *
 * When `i` opens `x_i`, it sends the tag `T_ij` to each verifier `j`, who checks the relation locally. A party
 * that lies about its share (or its tag) passes with probability ≤ 1/p per verifier, so an honest verifier that
 * sees the relation fail KNOWS the sender misbehaved (an honest sender's pair is always consistent): first-hand,
 * attributable evidence, with no help from anyone else.
 *
 * Everything is linear, so tags and keys follow the local linear operations of the SPDZ layer for free:
 *   add / sub / neg / scale by a public constant: apply the same operation to x, every tag and every key;
 *   add a PUBLIC constant c to party 0's share: party 0 changes only x; every other party j re-keys
 *   K_0j <- K_0j - Δ_j·c  (it holds Δ_j), which restores T_0j = K_0j + Δ_j·(x_0 + c).
 *
 * Untagged mode (no trusted dealer) uses the same type with empty `tag`/`key` arrays; all operations then
 * reduce to plain share arithmetic.
 */

import { fadd, fmul, fneg, fsub } from '../field';

/** A pairwise-authenticated field share. `tag[j]`: my tag for verifier j; `key[j]`: my key for verifying j's share. */
export interface PA {
  x: bigint;
  tag: bigint[];
  key: bigint[];
}

/** One authenticated value: its value share and one MAC share per global key, each pairwise-authenticated. */
export interface AW {
  v: PA;
  m: PA[];
}

export interface PaEnv {
  id: number;
  n: number;
  /** My verification key Δ_id (0n and unused when untagged). */
  delta: bigint;
  tagged: boolean;
}

const zip = (a: bigint[], b: bigint[], f: (x: bigint, y: bigint) => bigint): bigint[] => a.map((x, i) => f(x, b[i]!));

export const paAdd = (a: PA, b: PA): PA => ({ x: fadd(a.x, b.x), tag: zip(a.tag, b.tag, fadd), key: zip(a.key, b.key, fadd) });
export const paSub = (a: PA, b: PA): PA => ({ x: fsub(a.x, b.x), tag: zip(a.tag, b.tag, fsub), key: zip(a.key, b.key, fsub) });
export const paNeg = (a: PA): PA => ({ x: fneg(a.x), tag: a.tag.map(fneg), key: a.key.map(fneg) });
export const paScale = (a: PA, c: bigint): PA => ({ x: fmul(a.x, c), tag: a.tag.map((t) => fmul(t, c)), key: a.key.map((k) => fmul(k, c)) });

/** Add a PUBLIC constant to party 0's share of `a` (every party applies this same call). */
export function paAddPublic0(env: PaEnv, a: PA, c: bigint): PA {
  if (env.id === 0) return { x: fadd(a.x, c), tag: a.tag, key: a.key };
  if (!env.tagged) return a;
  const key = a.key.slice();
  key[0] = fsub(key[0]!, fmul(env.delta, c));
  return { x: a.x, tag: a.tag, key };
}

export const wAdd = (a: AW, b: AW): AW => ({ v: paAdd(a.v, b.v), m: a.m.map((p, l) => paAdd(p, b.m[l]!)) });
export const wSub = (a: AW, b: AW): AW => ({ v: paSub(a.v, b.v), m: a.m.map((p, l) => paSub(p, b.m[l]!)) });
export const wNeg = (a: AW): AW => ({ v: paNeg(a.v), m: a.m.map(paNeg) });
export const wScale = (a: AW, c: bigint): AW => ({ v: paScale(a.v, c), m: a.m.map((p) => paScale(p, c)) });

/**
 * ⟦x⟧ + c for a PUBLIC c: the value share of party 0 moves by c, and EVERY party's MAC share under key l moves
 * by α_i^(l)·c (computed from its own α share, whose pairwise tags are `alpha[l]`).
 */
export function wAddPublic(env: PaEnv, a: AW, c: bigint, alpha: PA[]): AW {
  return {
    v: paAddPublic0(env, a.v, c),
    m: a.m.map((p, l) => paAdd(p, paScale(alpha[l]!, c))),
  };
}

/** Verify peer `from`'s opened share `x` with tag `tag` against my key for `from`. */
export function paVerify(env: PaEnv, a: PA, from: number, x: bigint, tag: bigint): boolean {
  return fadd(a.key[from]!, fmul(env.delta, x)) === tag;
}

// ---------------------------------------------------------------------------------------------- codec

/** Numbers per pairwise-authenticated share on the wire (x, n-1 tags, n-1 keys; or just x when untagged). */
export const paWidth = (n: number, tagged: boolean): number => (tagged ? 1 + 2 * (n - 1) : 1);

/** Flatten a PA for party `id`: x, then tag[j] for j != id ascending, then key[j] for j != id ascending. */
export function paFlat(a: PA, id: number, n: number, tagged: boolean): bigint[] {
  const out = [a.x];
  if (tagged) {
    for (let j = 0; j < n; j++) if (j !== id) out.push(a.tag[j]!);
    for (let j = 0; j < n; j++) if (j !== id) out.push(a.key[j]!);
  }
  return out;
}

/** Inverse of `paFlat`: read one PA starting at `off`. */
export function paParse(nums: readonly bigint[], off: number, id: number, n: number, tagged: boolean): PA {
  const x = nums[off]!;
  if (!tagged) return { x, tag: [], key: [] };
  const tag = new Array<bigint>(n).fill(0n);
  const key = new Array<bigint>(n).fill(0n);
  let o = off + 1;
  for (let j = 0; j < n; j++) if (j !== id) tag[j] = nums[o++]!;
  for (let j = 0; j < n; j++) if (j !== id) key[j] = nums[o++]!;
  return { x, tag, key };
}

export const awWidth = (n: number, keys: number, tagged: boolean): number => (1 + keys) * paWidth(n, tagged);

export function awFlat(a: AW, id: number, n: number, tagged: boolean): bigint[] {
  return [a.v, ...a.m].flatMap((p) => paFlat(p, id, n, tagged));
}

export function awParse(nums: readonly bigint[], off: number, id: number, n: number, keys: number, tagged: boolean): AW {
  const w = paWidth(n, tagged);
  const v = paParse(nums, off, id, n, tagged);
  const m = Array.from({ length: keys }, (_, l) => paParse(nums, off + (1 + l) * w, id, n, tagged));
  return { v, m };
}
