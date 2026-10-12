/**
 * The NO-DEALER offline phase over the mutual-TLS mesh (research prototype).
 *
 * Each party is its own process holding only its own shares. Nobody is trusted to know the MAC keys, the
 * triples or the inputs: every party samples its own key shares and its own triple shares, and the products
 * needed for the triples and the MACs are computed by Gilboa OT multiplication between every ordered pair of
 * parties (`mascot.ts` is the in-process model of exactly this computation):
 *
 *   ob-S / ob-R / ob-C   all-to-all  the kappa = 128 base OTs of every ordered pair (malicious-secure, session-bound
 *                                    Chou-Orlandi: Schnorr proof of knowledge, point validation, transcript KDF)
 *   in-share             all-to-all  each owner splits every input bit into additive shares and sends one to each peer
 *   ox<layer>.<chunk>.u  all-to-all  OT-extension receiver messages (u matrix + KOS pair)  -> KOS correlation check
 *   ox<layer>.<chunk>.y  all-to-all  OT-extension sender ciphertexts
 *
 * Two multiplication layers (plus the tag layer 3): layer 1 = the triple products c = a*b and c-hat = a-hat*b, and the MACs of every
 * value that is known before them (a, b, a-hat, the inputs, the input-check mask); layer 2 = the MACs of the
 * products. The triple SACRIFICE and the input-consistency opening run in the online phase (`protocol.ts`),
 * on top of the same batched MAC-check, so a party that feeds wrong OT inputs yields a wrong triple that the
 * sacrifice catches, and an input whose MAC does not match its value fails the check.
 *
 * Statistical/computational parameters: 2 independent MAC keys (>= 2^-120), 2 sacrifice partners per triple
 * (>= 2^-122), KOS check with SSEC = 128 extra rows (best known attack about 2^-128, argued; see ot.ts), Ed25519 base OTs.
 *
 * PAIRWISE TAGS (identifiable abort): after the MACs are known, a third OT layer gives every share a pairwise tag
 * T_ij = K_ij + Δ_j·x_i for every peer j (one OT product of my x with j's secret Δ_j per item), so the online
 * phase can name a party that lies about a share, a MAC share or a residual (`pa.ts`).
 *
 * SELECTIVE FAILURE (RT-04): receivers do not choose with the bits of their share. Each share they multiply with is the gadget
 * sum `<g, b>` of 61 + 3s = 253 uniform choice bits (s = 64, `enc.ts`), so whether a run aborts is statistically independent of
 * the share (about 2^-63); the gadget is a commit-reveal value contributed by all parties. The tag layer splits its derived operands as `e + d` with an encoded `e`.
 *
 * What is NOT here: any security proof, and attribution of a wrong OT operand in the offline triple products
 * (the sacrifice detects the bad triple, but the tags are computed on the already-wrong value): named only for n = 2.
 */

import { createHash } from 'node:crypto';
import { SecureFieldRng, secureOtRandom } from '../csprng';
import { PRIME, fadd, fmul, fsub, mod } from '../field';
import { type EncShare, FIELD_BITS, PLAIN_GADGET, STAT_SEC, makeGadget, plainShare, sampleEnc } from '../enc';
import {
  type BaseOtBinding,
  BaseOtAbort,
  type ExtRoundMsg,
  KAPPA,
  MalOtAbort,
  OtExtReceiver,
  OtExtSender,
  SSEC,
  baseOtReceiverDecrypt,
  baseOtSenderEncrypt,
  bindingBytes,
  malBaseOtReceiverRespond,
  malBaseOtSenderDerive,
  malBaseOtSenderSetup,
} from '../ot';
import { PointValidationError, type Point, type SchnorrProof } from '../ec';
import type { DecisionVector } from '../party';
import { thermometerEncode } from '../thermometer';
import { NetAbort, hx } from './wire';
import { agreeGadgetSeeds } from './gadget';
import type { Mesh } from './mesh';
import { J, b64, jPt, ptJ, unb64, hexBig } from './ot-net';
import type { AW, PA } from './pa';
import { type Prep, sharingsPerTriple } from './prep';
import type { Disclosure } from './forensics';

/** Most OT rows per extension round (bounds frame size and memory). */
const ROWS_PER_ROUND = 128 * FIELD_BITS;
const T_M = 3;

/** Per-row transcript of selected items (for post-abort attribution). */
interface Kept {
  recv: Map<number, Map<number, bigint[]>>;
  rho: Map<number, Map<number, bigint[]>>;
}

/** One OT multiplication item: my choice bits (weights `gad`, public) against my sender operand `y`. */
interface Item {
  bits: readonly number[];
  gad: readonly bigint[];
  y: bigint;
}

/**
 * The public gadget of the privacy-amplified choice-bit encoding (`enc.ts`) from the parties' contributed seeds:
 * `gadget = H(all seeds in party order || session)` expanded by a hash chain. Every party commits to a fresh random seed
 * before any seed is revealed, so no single party (and no coalition that has not seen the honest seed before committing)
 * can steer the gadget.
 */
function gadgetFromSeeds(sessionId: string, seeds: Uint8Array[]): bigint[] {
  const h0 = createHash('sha256').update('atlas-pca-mpc/enc-gadget').update(sessionId);
  for (const sd of seeds) h0.update(sd);
  const seed = h0.digest();
  let ctr = 0;
  return makeGadget(STAT_SEC, () => {
    for (;;) {
      const h = createHash('sha256').update(seed).update(leBytes(BigInt(ctr++), 8)).digest();
      const v = fromLe(h, 0, 8) & ((1n << 61n) - 1n);
      if (v < PRIME) return v;
    }
  });
}

export interface OfflineNetArgs {
  mesh: Mesh;
  id: number;
  n: number;
  C: number;
  keys: number;
  partners: number;
  sessionId: string;
  input: DecisionVector;
  Q: number;
  /** TEST ONLY (gated by the caller): an offline misbehaviour of this party. */
  behavior?: { kind: string };
  /** One un-echoed all-to-all round (errors while parsing a peer's message abort naming that peer). */
  exchange: <T>(rd: string, mine: (peer: number) => unknown, parse: (p: number, raw: unknown) => T) => Promise<Map<number, T>>;
  crashIf: (rd: string) => void;
  bad: (p: number, what: string) => never;
  arr: (p: number, raw: unknown, len: number) => bigint[];
}

/** Hex of a 128-bit value, canonical. */
const hex128 = (s: unknown): bigint => {
  if (typeof s !== 'string' || !/^(0|[1-9a-f][0-9a-f]{0,31})$/.test(s)) throw new Error('bad 128-bit value');
  return BigInt('0x' + s);
};

function leBytes(v: bigint, len: number): Buffer {
  const out = Buffer.alloc(len);
  let x = v;
  for (let i = 0; i < len; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}
function fromLe(b: Uint8Array, off: number, len: number): bigint {
  let v = 0n;
  for (let i = len - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[off + i]!);
  return v;
}

const encodeU = (msg: ExtRoundMsg, mExt: number): unknown => {
  const cb = Math.ceil(mExt / 8);
  return { u: b64(Buffer.concat(msg.u.map((c) => leBytes(c, cb)))), x: msg.x.toString(16), t: msg.tComb.toString(16) };
};
function decodeU(raw: unknown, mExt: number): ExtRoundMsg {
  if (!J(raw)) throw new Error('bad extension message');
  const cb = Math.ceil(mExt / 8);
  const bytes = unb64(raw.u, KAPPA * cb);
  const u: bigint[] = [];
  for (let i = 0; i < KAPPA; i++) u.push(fromLe(bytes, i * cb, cb));
  return { u, x: hex128(raw.x), tComb: hex128(raw.t) };
}
const encodeY = (y0: bigint[], y1: bigint[]): unknown => ({
  y0: b64(Buffer.concat(y0.map((v) => leBytes(v, 8)))),
  y1: b64(Buffer.concat(y1.map((v) => leBytes(v, 8)))),
});
function decodeY(raw: unknown, m: number): { y0: bigint[]; y1: bigint[] } {
  if (!J(raw)) throw new Error('bad ciphertext message');
  const a = unb64(raw.y0, m * 8);
  const b = unb64(raw.y1, m * 8);
  return { y0: Array.from({ length: m }, (_, i) => fromLe(a, i * 8, 8)), y1: Array.from({ length: m }, (_, i) => fromLe(b, i * 8, 8)) };
}

const pairsB64 = (ps: Array<[Uint8Array, Uint8Array]>): string[][] => ps.map(([a, b]) => [b64(a), b64(b)]);
function parsePairs(raw: unknown, count: number, len: number): Array<[Uint8Array, Uint8Array]> {
  if (!Array.isArray(raw) || raw.length !== count) throw new Error('bad pair array');
  return raw.map((p: unknown) => {
    if (!Array.isArray(p) || p.length !== 2) throw new Error('bad pair');
    return [unb64(p[0], len), unb64(p[1], len)] as [Uint8Array, Uint8Array];
  });
}

export async function runOfflineNet(a: OfflineNetArgs): Promise<Prep> {
  const { mesh, id, n, C, keys: K, partners: P, exchange } = a;
  const others: number[] = [];
  for (let i = 0; i < n; i++) if (i !== id) others.push(i);
  const rng = secureOtRandom();
  const frng = new SecureFieldRng();
  /** My pairwise verification key Δ (non-zero, secret): the key that verifies every share the peers open to me. */
  let delta = frng.next();
  while (delta === 0n) delta = frng.next();
  let gadget: bigint[] = []; // set by the commit-reveal below, before the first OT multiplication
  const sid = new Uint8Array(createHash('sha256').update('atlas-pca-mpc/net-session/v2').update(mesh.sessionId).digest());
  /** Binding of the channel whose EXTENSION RECEIVER (= base-OT sender) is `recv` and extension sender is `send`. */
  const chan = (recv: number, send: number, round: string): BaseOtBinding => ({ sessionId: sid, senderIndex: recv, receiverIndex: send, round });

  /** Run a check that may throw an OT error, turning it into an abort that names `peer`. */
  const otGuard = <T>(peer: number, what: string, f: () => T): T => {
    try {
      return f();
    } catch (e) {
      if (e instanceof NetAbort) throw e;
      const kind = e instanceof BaseOtAbort || e instanceof MalOtAbort || e instanceof PointValidationError ? 'ot-check' : 'malformed';
      const ne = new NetAbort(kind, peer, id, `${what}: ${(e as Error).message}`);
      mesh.fail(ne);
      throw ne;
    }
  };

  // ------------------------------------------------------------------ base OTs (kappa per ordered pair, both roles)
  const recvCh = new Map<number, OtExtReceiver>(); // I am the extension receiver (base-OT sender) towards `peer`
  const sendCh = new Map<number, OtExtSender>(); // I am the extension sender (base-OT receiver) towards `peer`
  const seeds = new Map<number, Array<[Uint8Array, Uint8Array]>>();
  const mySetup = new Map<number, ReturnType<typeof malBaseOtSenderSetup>>();
  const selector = new Map<number, number[]>();
  for (const p of others) {
    const r = new OtExtReceiver(rng, bindingBytes(chan(id, p, 'iknp-kos')));
    seeds.set(p, r.makeSeeds());
    recvCh.set(p, r);
    mySetup.set(p, malBaseOtSenderSetup(rng, chan(id, p, 'offline-kappa')));
    const s = new OtExtSender(rng, bindingBytes(chan(p, id, 'iknp-kos')));
    selector.set(p, s.makeSelector());
    sendCh.set(p, s);
  }
  const theirS = await exchange(
    'ob-S',
    (peer) => {
      const st = mySetup.get(peer)!;
      return { S: ptJ(st.S), U: ptJ(st.proof.U), z: hx(a.behavior?.kind === 'ot-proof-lie' ? st.proof.z + 1n : st.proof.z) };
    },
    (p, raw) => {
      if (!J(raw)) a.bad(p, 'bad S message');
      const o = raw as Record<string, unknown>;
      const proof: SchnorrProof = { U: jPt(o.U), z: hexBig(o.z) };
      return { S: jPt(o.S), proof };
    },
  );
  const respond = new Map<number, ReturnType<typeof malBaseOtReceiverRespond>>();
  for (const p of others) {
    const st = theirS.get(p)!;
    respond.set(
      p,
      otGuard(p, 'base OT (receiver)', () => malBaseOtReceiverRespond(st.S, st.proof, selector.get(p)!, rng, chan(p, id, 'offline-kappa'))),
    );
  }
  const theirR = await exchange(
    'ob-R',
    (peer) => respond.get(peer)!.R.map(ptJ),
    (p, raw): Point[] => {
      if (!Array.isArray(raw) || raw.length !== KAPPA) return a.bad(p, 'bad R array');
      return raw.map(jPt);
    },
  );
  const enc = new Map<number, ReturnType<typeof baseOtSenderEncrypt>>();
  for (const p of others) {
    const st = mySetup.get(p)!;
    enc.set(
      p,
      otGuard(p, 'base OT (sender)', () => {
        const pads = malBaseOtSenderDerive(st.y, st.T, theirR.get(p)!, st.S, chan(id, p, 'offline-kappa'));
        return baseOtSenderEncrypt(seeds.get(p)!, pads);
      }),
    );
  }
  const theirCt = await exchange(
    'ob-C',
    (peer) => ({ ct: pairsB64(enc.get(peer)!.ct), com: pairsB64(enc.get(peer)!.com) }),
    (p, raw) => {
      if (!J(raw)) return a.bad(p, 'bad ciphertext message');
      return { ct: parsePairs(raw.ct, KAPPA, 16), com: parsePairs(raw.com, KAPPA, 32) };
    },
  );
  for (const p of others) {
    const m = theirCt.get(p)!;
    const got = otGuard(p, 'base OT (receiver)', () => baseOtReceiverDecrypt(selector.get(p)!, respond.get(p)!.recvPads, m.ct, m.com));
    sendCh.get(p)!.setSeeds(got);
  }

  // ------------------------------------------------------------------ the jointly contributed choice-bit gadget
  {
    // R3-16: signed commit / reveal / echo (gadget.ts): one corrupt party cannot give different honest parties different gadgets.
    const seedsAgreed = await agreeGadgetSeeds(mesh, n, { exchange, bad: a.bad });
    gadget = gadgetFromSeeds(mesh.sessionId, seedsAgreed);
  }

  // ------------------------------------------------------------------ the OT multiplication layer (Gilboa)
  /**
   * The Gilboa OT core. For every peer p: as the OT RECEIVER towards p I choose with the bits of my `xs[t]`
   * and get `recv[p][t] = x_t·y^p_t + Σρ^p_t` (p's operand y^p_t and p's masks ρ); as the OT SENDER towards p I
   * offer `(ρ_k, ρ_k + 2^k·ys[t])` with fresh masks and keep `sendSum[p][t] = Σρ`. So
   * `recv[p][t] − sendSum^{p}[t]` over the pair is an additive sharing of `x_t·y_t`; the tag layer below uses
   * the two halves separately.
   */
  async function otRows(
    layer: string,
    items: Item[],
    keep?: ReadonlySet<number>,
  ): Promise<{ recv: Map<number, bigint[]>; sendSum: Map<number, bigint[]>; kept: Kept }> {
    const T = items.length;
    const recv = new Map<number, bigint[]>();
    const sendSum = new Map<number, bigint[]>();
    const kept: Kept = { recv: new Map(), rho: new Map() };
    for (const p of others) {
      recv.set(p, new Array<bigint>(T).fill(0n));
      sendSum.set(p, new Array<bigint>(T).fill(0n));
      kept.recv.set(p, new Map());
      kept.rho.set(p, new Map());
    }
    if (T === 0 || others.length === 0) return { recv, sendSum, kept };
    let rows = 0;
    for (const it of items) rows += it.bits.length;
    const rowItem = new Int32Array(rows);
    const choice: number[] = new Array(rows);
    const m0 = new Map<number, bigint[]>();
    const m1 = new Map<number, bigint[]>();
    for (const p of others) {
      m0.set(p, new Array<bigint>(rows));
      m1.set(p, new Array<bigint>(rows));
    }
    let off = 0;
    const itemOff = new Int32Array(T);
    for (let t = 0; t < T; t++) {
      const it = items[t]!;
      const len = it.bits.length;
      itemOff[t] = off;
      if (keep?.has(t)) for (const p of others) kept.recv.get(p)!.set(t, new Array<bigint>(len).fill(0n));
      for (let k = 0; k < len; k++) {
        choice[off + k] = it.bits[k]!;
        rowItem[off + k] = t;
      }
      for (const p of others) {
        const a0 = m0.get(p)!;
        const a1 = m1.get(p)!;
        const ss = sendSum.get(p)!;
        let sumRho = 0n;
        for (let k = 0; k < len; k++) {
          const rho = frng.next();
          sumRho = fadd(sumRho, rho);
          a0[off + k] = rho;
          a1[off + k] = fadd(rho, fmul(it.gad[k]!, it.y));
        }
        ss[t] = sumRho;
        if (keep?.has(t)) kept.rho.get(p)!.set(t, a0.slice(off, off + len));
      }
      off += len;
    }
    let chunk = 0;
    for (let start = 0; start < rows; start += ROWS_PER_ROUND, chunk++) {
      const end = Math.min(rows, start + ROWS_PER_ROUND);
      const m = end - start;
      const mExt = m + KAPPA + SSEC;
      const tag = `ox${layer}.${chunk}`;
      const begun = new Map<number, ReturnType<OtExtReceiver['begin']>>();
      if (a.behavior?.kind === 'ot-u-lie') {
        // an inconsistent matrix: flip the first row in 64 of the 128 columns only (not a different choice vector)
        for (const p of others) recvCh.get(p)!.tamperU = (u) => { for (let i = 0; i < 64; i++) u[i] = u[i]! ^ 1n; };
      }
      for (const p of others) begun.set(p, recvCh.get(p)!.begin(choice.slice(start, end)));
      const us = await exchange(
        `${tag}.u`,
        (peer) => encodeU(begun.get(peer)!.msg, mExt),
        (p, raw) => decodeU(raw, mExt),
      );
      const ys2 = new Map<number, { y0: bigint[]; y1: bigint[] }>();
      for (const p of others) {
        ys2.set(
          p,
          otGuard(p, `OT extension (${tag})`, () => sendCh.get(p)!.respond(us.get(p)!, m0.get(p)!.slice(start, end), m1.get(p)!.slice(start, end))),
        );
      }
      const cts = await exchange(
        `${tag}.y`,
        (peer) => encodeY(ys2.get(peer)!.y0, ys2.get(peer)!.y1),
        (p, raw) => decodeY(raw, m),
      );
      for (const p of others) {
        const got = otGuard(p, `OT extension (${tag})`, () => recvCh.get(p)!.finish(begun.get(p)!.pending, cts.get(p)!.y0, cts.get(p)!.y1));
        const rv = recv.get(p)!;
        for (let j = 0; j < m; j++) {
          const t = rowItem[start + j]!;
          rv[t] = fadd(rv[t]!, mod(got[j]!));
          if (keep?.has(t)) kept.recv.get(p)!.get(t)![start + j - itemOff[t]!] = mod(got[j]!);
        }
      }
    }
    return { recv, sendSum, kept };
  }

  /**
   * Given my shares `xs[t]` of X_t and `ys[t]` of Y_t, return my additive share of X_t*Y_t = (sum x)(sum y):
   * the diagonal x_i*y_i locally plus, for every ordered pair, the Gilboa OT product of one party's x with the
   * other's y. Neither party learns the other's operand or share.
   */
  async function mulLayer(layer: string, xs: EncShare[], ys: bigint[], lieAt = -1, keep?: ReadonlySet<number>): Promise<{ z: bigint[]; kept: Kept }> {
    const z = xs.map((x, t) => fmul(x.value, ys[t]!));
    const items: Item[] = xs.map((x, t) => ({ bits: x.bits, gad: gadget, y: t === lieAt ? fadd(ys[t]!, 1n) : ys[t]! }));
    const { recv, sendSum, kept } = await otRows(layer, items, keep);
    for (const p of others) {
      const rv = recv.get(p)!;
      const ss = sendSum.get(p)!;
      for (let t = 0; t < z.length; t++) z[t] = fsub(fadd(z[t]!, rv[t]!), ss[t]!);
    }
    return { z, kept };
  }

  /**
   * Pairwise tags for my shares `xs`: for every peer j, a tag T_ij (mine) and a key K_ji (for verifying j's share
   * of the same item) with T_ij = K_ij + Δ_j·x_i, where Δ_j is j's secret verification key. One OT product of my
   * x with j's Δ per item: I receive T_ij, and j keeps the sum of its masks as K_ij.
   *
   * A tag operand is an arbitrary derived value (a MAC share, a product share), with no uniform choice-bit encoding
   * of its own, so each x is split as x = e + d with a fresh encoded e and d = x - e; both halves are multiplied
   * with Δ and the results added. A sender's selective failure on d reveals bits of d, which is uniform given e.
   */
  async function tagLayer(layer: string, xs: bigint[]): Promise<{ tag: Map<number, bigint[]>; key: Map<number, bigint[]> }> {
    const items: Item[] = [];
    for (const x of xs) {
      const e = sampleEnc(gadget, frng);
      const d = plainShare(fsub(x, e.value));
      items.push({ bits: e.bits, gad: gadget, y: delta }, { bits: d.bits, gad: PLAIN_GADGET, y: delta });
    }
    const { recv, sendSum } = await otRows(layer, items);
    const tag = new Map<number, bigint[]>();
    const key = new Map<number, bigint[]>();
    for (const p of others) {
      const r = recv.get(p)!;
      const k = sendSum.get(p)!;
      tag.set(p, xs.map((_, u) => fadd(r[2 * u]!, r[2 * u + 1]!)));
      key.set(p, xs.map((_, u) => fadd(k[2 * u]!, k[2 * u + 1]!)));
    }
    return { tag, key };
  }

  // ------------------------------------------------------------------ my randomness and the input sharings
  const alphaEnc = Array.from({ length: K }, () => sampleEnc(gadget, frng));
  const alphaShare = alphaEnc.map((e) => e.value);
  const myBits = [a.input.allow, ...thermometerEncode(a.input.t, T_M), ...thermometerEncode(a.input.rQuant, a.Q)];
  if (myBits.length !== C) throw new NetAbort('local', null, id, 'input chain count mismatch');
  // split each of my bits into additive shares: a random share for every peer, the rest is mine
  const outShares = new Map<number, bigint[]>();
  for (const p of others) outShares.set(p, Array.from({ length: C }, () => frng.next()));
  const myOwn = myBits.map((b, c) => {
    let s = BigInt(b);
    for (const p of others) s = fsub(s, outShares.get(p)![c]!);
    return s;
  });
  const gotShares = await exchange(
    'in-share',
    (peer) => outShares.get(peer)!.map(hx),
    (p, raw) => a.arr(p, raw, C),
  );
  const inputValue: bigint[] = []; // my value share of every (owner, chain)
  for (let o = 0; o < n; o++) for (let c = 0; c < C; c++) inputValue.push(o === id ? myOwn[c]! : gotShares.get(o)![c]!);
  const maskShare = frng.next(); // my share of the input-check mask

  const nT = (n - 1) * C;
  const aE: EncShare[] = [];
  const bS: bigint[] = [];
  const ahE: EncShare[][] = [];
  for (let t = 0; t < nT; t++) {
    aE.push(sampleEnc(gadget, frng));
    bS.push(frng.next());
    ahE.push(Array.from({ length: P }, () => sampleEnc(gadget, frng)));
  }
  const aS = aE.map((e) => e.value);
  const ahS = ahE.map((row) => row.map((e) => e.value));

  // ------------------------------------------------------------------ layer 1: products and the MACs of known values
  const xs1: EncShare[] = [];
  const ys1: bigint[] = [];
  const push1 = (x: EncShare, y: bigint): number => {
    xs1.push(x);
    ys1.push(y);
    return xs1.length - 1;
  };
  const iC: number[] = [];
  const iCh: number[][] = [];
  const iMa: number[][] = [];
  const iMb: number[][] = [];
  const iMah: number[][][] = [];
  for (let t = 0; t < nT; t++) {
    iC.push(push1(aE[t]!, bS[t]!));
    iCh.push(Array.from({ length: P }, (_, r) => push1(ahE[t]![r]!, bS[t]!)));
    iMa.push(alphaEnc.map((al) => push1(al, aS[t]!)));
    iMb.push(alphaEnc.map((al) => push1(al, bS[t]!)));
    iMah.push(Array.from({ length: P }, (_, r) => alphaEnc.map((al) => push1(al, ahS[t]![r]!))));
  }
  const iIn: number[][] = inputValue.map((val) => alphaEnc.map((al) => push1(al, val)));
  const iMask: number[] = alphaEnc.map((al) => push1(al, maskShare));
  const keepItems = new Set<number>([...iC, ...iCh.flat()]);
  const { z: z1, kept: kept1 } = await mulLayer('1', xs1, ys1, a.behavior?.kind === 'offline-lie' && iC.length > 0 ? iC[0]! : -1, keepItems);

  // ------------------------------------------------------------------ layer 2: the MACs of the products
  const cS = iC.map((i) => z1[i]!);
  const chS = iCh.map((row) => row.map((i) => z1[i]!));
  const xs2: EncShare[] = [];
  const ys2: bigint[] = [];
  const push2 = (x: EncShare, y: bigint): number => {
    xs2.push(x);
    ys2.push(y);
    return xs2.length - 1;
  };
  const iMc: number[][] = [];
  const iMch: number[][][] = [];
  for (let t = 0; t < nT; t++) {
    iMc.push(alphaEnc.map((al) => push2(al, cS[t]!)));
    iMch.push(chS[t]!.map((chv) => alphaEnc.map((al) => push2(al, chv))));
  }
  const { z: z2 } = await mulLayer('2', xs2, ys2);

  // ------------------------------------------------------------------ assemble, then pairwise-tag every share
  const pa = (x: bigint): PA => ({ x, tag: new Array<bigint>(n).fill(0n), key: new Array<bigint>(n).fill(0n) });
  const aw = (value: bigint, macIdx: number[], z: bigint[]): AW => ({ v: pa(value), m: macIdx.map((i) => pa(z[i]!)) });
  const triples: AW[][] = [];
  for (let t = 0; t < nT; t++) {
    const sh: AW[] = [aw(aS[t]!, iMa[t]!, z1), aw(bS[t]!, iMb[t]!, z1), aw(cS[t]!, iMc[t]!, z2)];
    for (let r = 0; r < P; r++) {
      sh.push(aw(ahS[t]![r]!, iMah[t]![r]!, z1));
      sh.push(aw(chS[t]![r]!, iMch[t]![r]!, z2));
    }
    if (sh.length !== sharingsPerTriple(P)) throw new NetAbort('local', null, id, 'triple assembly mismatch');
    triples.push(sh);
  }
  const inputs: AW[] = inputValue.map((val, q) => aw(val, iIn[q]!, z1));
  const checkMask = aw(maskShare, iMask, z1);
  const alpha: PA[] = alphaShare.map(pa);
  const allPA: PA[] = [...alpha];
  for (const w of [...triples.flat(), ...inputs, checkMask]) allPA.push(w.v, ...w.m);
  const tags = await tagLayer('3', allPA.map((x) => x.x));
  allPA.forEach((x, u) => {
    for (const p of others) {
      x.tag[p] = tags.tag.get(p)![u]!;
      x.key[p] = tags.key.get(p)![u]!;
    }
  });
  return {
    mode: 'no-dealer',
    tagged: true,
    delta,
    alpha,
    triples,
    inputs,
    myPlain: myBits.map((b) => BigInt(b)),
    checkMask,
    forensics: {
      gadget,
      rows: gadget.length,
      slots: 1 + P,
      disclose: (t: number): Disclosure => {
        const slot = (item: number, x: EncShare, z: bigint): Disclosure[number] => ({
          bits: x.bits.slice(),
          y: bS[t]!,
          z,
          recv: new Map(others.map((p) => [p, kept1.recv.get(p)!.get(item)!])),
          rho: new Map(others.map((p) => [p, kept1.rho.get(p)!.get(item)!])),
        });
        return [slot(iC[t]!, aE[t]!, cS[t]!), ...iCh[t]!.map((item, r) => slot(item, ahE[t]![r]!, chS[t]![r]!))];
      },
    },
  };
}
