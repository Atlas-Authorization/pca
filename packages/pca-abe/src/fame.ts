import {
  G1_BASE,
  G2_BASE,
  type G1Point,
  type G2Point,
  type GtElement,
  frAdd,
  frInv,
  frMul,
  frSub,
  g1Mul,
  g1MulZ,
  g2Mul,
  G1_ZERO,
  gtPow,
  hashToG1,
  pairing,
  pairingProduct,
} from './bls';
import { lagrangeAtZero } from './sss';
import type { ThresholdTree } from './policy';
import { bls12_381 } from '@noble/curves/bls12-381';

/**
 * FAME: Fast Attribute-based Message Encryption (Agrawal and Chase, ACM CCS 2017, ePrint 2017/807), the
 * ciphertext-policy scheme in the asymmetric (type-3) pairing setting. It is proven ADAPTIVELY secure in the
 * random-oracle model under the symmetric external Diffie-Hellman assumption (SXDH / DLIN-family matrix
 * assumption in the paper), for unbounded-size attribute universes, with a monotone span program (LSSS)
 * access structure whose row labelling is injective (one row per attribute). This file is only the group
 * arithmetic; the wire format, validation and AEAD live in `abe.ts`.
 *
 * Notation: g = G1 generator, h = G2 generator, e: G1 x G2 -> GT. H(y, l, t) and H0(j, l, t) are random-oracle
 * hashes into G1 (domain-separated, see `hAttr` / `hCol`), l in {0,1,2}, t in {0,1}.
 *
 *   Setup        a1,a2,b1,b2,d1,d2,d3 <- Z_r*
 *                MPK = ( h^a1, h^a2,  e(g,h)^(d1*a1 + d3),  e(g,h)^(d2*a2 + d3) )
 *                MSK = ( a1, a2, b1, b2,  g^d1, g^d2, g^d3 )
 *   KeyGen(S)    r1,r2 <- Z_r; pow = ( b1*r1, b2*r2, r1 + r2 );  sigma_y, sigma' <- Z_r
 *                K0 = ( h^pow0, h^pow1, h^pow2 )
 *                K_y,t = ( H(y,0,t)^pow0 * H(y,1,t)^pow1 * H(y,2,t)^pow2 * g^sigma_y )^(1/a_(t+1))     t = 0,1
 *                K_y,2 = g^(-sigma_y)
 *                K'_t  = ( H0(0,0,t)^pow0 * H0(0,1,t)^pow1 * H0(0,2,t)^pow2 * g^sigma' )^(1/a_(t+1)) * g^d_(t+1)
 *                K'_2  = g^(-sigma') * g^d3
 *   Encrypt(M,rho)  M an LSSS matrix (rows i, columns j), rho(i) the attribute of row i, s1,s2 <- Z_r
 *                C0 = ( (h^a1)^s1, (h^a2)^s2, h^(s1+s2) )
 *                C_i,l = H(rho(i),l,0)^s1 * H(rho(i),l,1)^s2 * prod_j ( H0(j,l,0)^s1 * H0(j,l,1)^s2 )^M[i][j]
 *                KEM key  K = e(g,h)^((d1*a1 + d3)*s1) * e(g,h)^((d2*a2 + d3)*s2) = T1^s1 * T2^s2
 *   Decrypt     reconstruction coefficients w_i with sum_i w_i * M_i = (1, 0, ..., 0) over the rows whose
 *               attribute the key holds; with  ctProd_l = sum_i w_i C_i,l  and  keyProd_l = sum_i w_i K_rho(i),l + K'_l
 *                    K = prod_l e(keyProd_l, C0_l) / e(ctProd_l, K0_l)
 *
 * The span program is derived from the package's threshold tree exactly as a Shamir sharing down the tree
 * (each t-of-n gate adds t-1 columns; child i of a gate receives its parent's row vector plus i^k in the gate's
 * k-th new column, k = 1..t-1). The first column carries the secret, so every row has entry 1 there and the
 * target vector is (1, 0, ..., 0). The reconstruction coefficients come straight from the tree (the product of the
 * Lagrange coefficients along the root-to-leaf path), which is a valid solution of the linear system, so no
 * Gaussian elimination is run on untrusted input.
 *
 * Restriction (inherited from the paper's proof): rho is injective. A policy that names one attribute in two
 * leaves is refused, never approximated.
 */

export type G1x3 = [G1Point, G1Point, G1Point];
export type G2x3 = [G2Point, G2Point, G2Point];

export interface FameMpk {
  h1: G2Point; // h^a1
  h2: G2Point; // h^a2
  t1: GtElement; // e(g,h)^(d1*a1 + d3)
  t2: GtElement; // e(g,h)^(d2*a2 + d3)
}
export interface FameMsk {
  a: [bigint, bigint];
  b: [bigint, bigint];
  g: G1x3; // g^d1, g^d2, g^d3
}
export interface FameKey {
  k0: G2x3;
  kp: G1x3;
  attrs: Map<string, G1x3>;
}
export interface FameCiphertext {
  ct0: G2x3;
  rows: G1x3[];
}

const enc = new TextEncoder();
const u32 = (n: number): Uint8Array => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const cat = (...p: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(p.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of p) {
    out.set(x, o);
    o += x.length;
  }
  return out;
};

/** H(y, l, t): kind byte 1, length-prefixed UTF-8 attribute, l, t (injective encoding, so no two inputs collide). */
export function hAttr(attr: string, l: number, t: number): G1Point {
  const a = enc.encode(attr);
  return hashToG1(cat(new Uint8Array([1]), u32(a.length), a, new Uint8Array([l, t])));
}

/** H0(j, l, t): the column-indexed oracle of the paper (kind byte 2). */
export function hCol(j: number, l: number, t: number): G1Point {
  return hashToG1(cat(new Uint8Array([2]), u32(j), new Uint8Array([l, t])));
}

// ---- setup / keygen -----------------------------------------------------------------------------

export function fameSetup(a: [bigint, bigint], b: [bigint, bigint], d: [bigint, bigint, bigint]): { mpk: FameMpk; msk: FameMsk } {
  const egh = pairing(G1_BASE, G2_BASE);
  return {
    mpk: {
      h1: g2Mul(G2_BASE, a[0]),
      h2: g2Mul(G2_BASE, a[1]),
      t1: gtPow(egh, frAdd(frMul(d[0], a[0]), d[2])),
      t2: gtPow(egh, frAdd(frMul(d[1], a[1]), d[2])),
    },
    msk: { a, b, g: [g1Mul(G1_BASE, d[0]), g1Mul(G1_BASE, d[1]), g1Mul(G1_BASE, d[2])] },
  };
}

/** Sum over l of oracle(l)^pow[l], then add `g^sigma`, then raise to 1/a_(t+1). */
function keyTerm(oracle: (l: number) => G1Point, pow: [bigint, bigint, bigint], sigma: bigint, aInv: bigint): G1Point {
  const sum = g1MulZ(oracle(0), pow[0]).add(g1MulZ(oracle(1), pow[1])).add(g1MulZ(oracle(2), pow[2])).add(g1Mul(G1_BASE, sigma));
  return g1Mul(sum, aInv);
}

export function fameKeygen(
  msk: FameMsk,
  attrs: readonly string[],
  r: [bigint, bigint],
  sigmas: readonly bigint[],
  sigmaPrime: bigint,
): FameKey {
  const pow: [bigint, bigint, bigint] = [frMul(msk.b[0], r[0]), frMul(msk.b[1], r[1]), frAdd(r[0], r[1])];
  const aInv: [bigint, bigint] = [frInv(msk.a[0]), frInv(msk.a[1])];
  const k0: G2x3 = [g2Mul(G2_BASE, pow[0]), g2Mul(G2_BASE, pow[1]), g2Mul(G2_BASE, pow[2])];
  const out = new Map<string, G1x3>();
  attrs.forEach((y, i) => {
    const sg = sigmas[i];
    if (sg === undefined) throw new RangeError('fameKeygen: one sigma per attribute is required');
    out.set(y, [
      keyTerm((l) => hAttr(y, l, 0), pow, sg, aInv[0]),
      keyTerm((l) => hAttr(y, l, 1), pow, sg, aInv[1]),
      g1Mul(G1_BASE, frSub(0n, sg)),
    ]);
  });
  const kp: G1x3 = [
    keyTerm((l) => hCol(0, l, 0), pow, sigmaPrime, aInv[0]).add(msk.g[0]),
    keyTerm((l) => hCol(0, l, 1), pow, sigmaPrime, aInv[1]).add(msk.g[1]),
    g1Mul(G1_BASE, frSub(0n, sigmaPrime)).add(msk.g[2]),
  ];
  return { k0, kp, attrs: out };
}

// ---- span program from the threshold tree -------------------------------------------------------

export interface MspRow {
  attr: string;
  /** Sparse row vector: column -> non-zero coefficient. Column 0 is the secret column and is always 1. */
  vec: Map<number, bigint>;
}

/** Leaves in depth-first order, each with its span-program row. */
export function buildRows(tree: ThresholdTree): MspRow[] {
  const rows: MspRow[] = [];
  let ncols = 1;
  const walk = (node: ThresholdTree, vec: Map<number, bigint>): void => {
    if (node.kind === 'leaf') {
      rows.push({ attr: node.attr, vec });
      return;
    }
    const base = ncols;
    ncols += node.t - 1;
    node.of.forEach((child, idx) => {
      const cv = new Map(vec);
      const x = BigInt(idx + 1);
      let pw = 1n;
      for (let k = 1; k < node.t; k++) {
        pw = frMul(pw, x);
        cv.set(base + k - 1, pw);
      }
      walk(child, cv);
    });
  };
  walk(tree, new Map([[0, 1n]]));
  return rows;
}

export function leafCount(tree: ThresholdTree): number {
  return tree.kind === 'leaf' ? 1 : tree.of.reduce((n, c) => n + leafCount(c), 0);
}

/** First attribute named by two leaves, or null: FAME needs an injective row labelling. */
export function firstRepeatedAttribute(tree: ThresholdTree): string | null {
  const seen = new Set<string>();
  let dup: string | null = null;
  const walk = (n: ThresholdTree): void => {
    if (dup !== null) return;
    if (n.kind === 'leaf') {
      if (seen.has(n.attr)) dup = n.attr;
      seen.add(n.attr);
    } else n.of.forEach(walk);
  };
  walk(tree);
  return dup;
}

// ---- encrypt ------------------------------------------------------------------------------------

export function fameEncrypt(mpk: FameMpk, tree: ThresholdTree, s: [bigint, bigint]): { ct: FameCiphertext; k: GtElement } {
  const rows = buildRows(tree);
  const colMemo = new Map<string, G1Point>();
  const colTerm = (j: number, l: number): G1Point => {
    const key = `${j}:${l}`;
    let v = colMemo.get(key);
    if (v === undefined) {
      v = g1Mul(hCol(j, l, 0), s[0]).add(g1Mul(hCol(j, l, 1), s[1]));
      colMemo.set(key, v);
    }
    return v;
  };
  const out: G1x3[] = rows.map((row) => {
    const per = (l: number): G1Point => {
      let acc = g1Mul(hAttr(row.attr, l, 0), s[0]).add(g1Mul(hAttr(row.attr, l, 1), s[1]));
      for (const [j, m] of row.vec) acc = acc.add(g1MulZ(colTerm(j, l), m));
      return acc;
    };
    return [per(0), per(1), per(2)];
  });
  return {
    ct: {
      ct0: [g2Mul(mpk.h1, s[0]), g2Mul(mpk.h2, s[1]), g2Mul(G2_BASE, frAdd(s[0], s[1]))],
      rows: out,
    },
    k: gtMul(gtPow(mpk.t1, s[0]), gtPow(mpk.t2, s[1])),
  };
}

const Fp12 = bls12_381.fields.Fp12;
function gtMul(a: GtElement, b: GtElement): GtElement {
  return Fp12.mul(a, b);
}

// ---- decrypt ------------------------------------------------------------------------------------

type Plan = { kind: 'leaf'; row: number } | { kind: 'gate'; of: { x: bigint; sub: Plan }[] };

/** Choose, bottom-up, the first `t` satisfiable children of every gate; null when `has` does not satisfy the subtree. */
function plan(node: ThresholdTree, has: (attr: string) => boolean, offset: number): Plan | null {
  if (node.kind === 'leaf') return has(node.attr) ? { kind: 'leaf', row: offset } : null;
  const of: { x: bigint; sub: Plan }[] = [];
  let off = offset;
  for (let i = 0; i < node.of.length; i++) {
    const child = node.of[i] as ThresholdTree;
    const sub = plan(child, has, off);
    if (sub !== null) of.push({ x: BigInt(i + 1), sub });
    if (of.length >= node.t) break;
    off += leafCount(child);
  }
  return of.length < node.t ? null : { kind: 'gate', of };
}

function weights(p: Plan, w: bigint, out: Map<number, bigint>): boolean {
  if (p.kind === 'leaf') {
    out.set(p.row, w);
    return true;
  }
  const lambda = lagrangeAtZero(p.of.map((c) => c.x));
  if (lambda === null) return false;
  for (let i = 0; i < p.of.length; i++) {
    const c = p.of[i] as { x: bigint; sub: Plan };
    if (!weights(c.sub, frMul(w, lambda[i] ?? 0n), out)) return false;
  }
  return true;
}

/**
 * The reconstruction coefficients over the rows the key can use: row index -> w_i with
 * sum_i w_i * M_i = (1, 0, ..., 0). Null when the attribute set does not satisfy the tree.
 */
export function reconstructionWeights(tree: ThresholdTree, has: (attr: string) => boolean): Map<number, bigint> | null {
  const p = plan(tree, has, 0);
  if (p === null) return null;
  const out = new Map<number, bigint>();
  return weights(p, 1n, out) ? out : null;
}

/** Recover the KEM key, or null when the key does not satisfy the tree (or a point is degenerate). */
export function fameDecrypt(key: FameKey, tree: ThresholdTree, ct: FameCiphertext): GtElement | null {
  const rows = buildRowsAttrs(tree);
  if (rows.length !== ct.rows.length) return null;
  const w = reconstructionWeights(tree, (a) => key.attrs.has(a));
  if (w === null) return null;
  const pairs: { g1: G1Point; g2: G2Point }[] = [];
  for (let l = 0; l < 3; l++) {
    let ctProd: G1Point = G1_ZERO;
    let keyProd: G1Point = key.kp[l] as G1Point;
    for (const [i, wi] of w) {
      const comp = key.attrs.get(rows[i] as string);
      const cRow = ct.rows[i];
      if (comp === undefined || cRow === undefined) return null;
      ctProd = ctProd.add(g1MulZ(cRow[l] as G1Point, wi));
      keyProd = keyProd.add(g1MulZ(comp[l] as G1Point, wi));
    }
    pairs.push({ g1: keyProd, g2: ct.ct0[l] as G2Point }, { g1: ctProd.negate(), g2: key.k0[l] as G2Point });
  }
  try {
    return pairingProduct(pairs);
  } catch {
    return null;
  }
}

function buildRowsAttrs(tree: ThresholdTree): string[] {
  const out: string[] = [];
  const walk = (n: ThresholdTree): void => (n.kind === 'leaf' ? void out.push(n.attr) : n.of.forEach(walk));
  walk(tree);
  return out;
}
