/** Mutation-kill tests for ledger.ts: consistency proofs, STH / witness verification, domain separation, bounds. */
import { describe, expect, it } from 'vitest';
import { b64u, canonicalBytes, utf8 } from './hash';
import { generateKeyPair, publicKeyOf, verifyB64u } from './keys';
import {
  STH_DOMAIN,
  STH_WITNESS_DOMAIN,
  TransparencyLedger,
  cosignTreeHead,
  detectEquivocation,
  signTreeHead,
  verifyHeadConsistency,
  verifyLedgerConsistency,
  verifyTreeHead,
  verifyWitnessCosignature,
  verifyWitnessCosignatures,
  verifyOpening,
  verifyWitnessedHead,
  type SignedTreeHead,
} from './ledger';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';

const cat = (a: Uint8Array, b: Uint8Array) => {
  const o = new Uint8Array(a.length + b.length);
  o.set(a);
  o.set(b, a.length);
  return o;
};
const mkLedger = (n: number, principal = 'p', tag = 'c') => {
  const l = new TransparencyLedger(principal);
  for (let i = 0; i < n; i++) l.appendCommitment(`${tag}${i}`);
  return l;
};
const G = generateKeyPair();
const gPub = b64u(G.publicKey);

describe('verifyLedgerConsistency', () => {
  const L = mkLedger(20);
  const roots = Array.from({ length: 21 }, (_, i) => L.rootAt(i));
  const flip = (s: string) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
  it('every (old,new) pair verifies, and every single-field corruption fails', () => {
    for (let o = 0; o <= 20; o++) {
      for (let n = o; n <= 20; n++) {
        const proof = L.consistencyProof(o, n);
        expect(verifyLedgerConsistency(roots[o]!, roots[n]!, proof), `${o}->${n}`).toBe(true);
        if (o > 0 && o < n) {
          expect(verifyLedgerConsistency(roots[o]!, roots[n]!, { ...proof, path: proof.path.slice(0, -1) }), `trunc ${o}->${n}`).toBe(false);
          expect(verifyLedgerConsistency(roots[o]!, roots[n]!, { ...proof, path: [...proof.path, proof.path[0]!] }), `ext ${o}->${n}`).toBe(false);
          expect(verifyLedgerConsistency(roots[o]!, roots[n]!, { ...proof, path: [flip(proof.path[0]!), ...proof.path.slice(1)] }), `flip ${o}->${n}`).toBe(false);
          expect(verifyLedgerConsistency(roots[n]!, roots[o]!, proof), `swap ${o}->${n}`).toBe(false);
          expect(verifyLedgerConsistency(flip(roots[o]!), roots[n]!, proof), `oldroot ${o}->${n}`).toBe(false);
          expect(verifyLedgerConsistency(roots[o]!, flip(roots[n]!), proof), `newroot ${o}->${n}`).toBe(false);
        }
      }
    }
  });
  it('size arguments: non-integers, negatives and first > second are refused', () => {
    const p = L.consistencyProof(3, 8);
    const ok = (o: number, n: number) => verifyLedgerConsistency(roots[3]!, roots[8]!, { ...p, oldSize: o, newSize: n });
    expect(ok(3, 8)).toBe(true);
    for (const [o, n] of [[3.5, 8], [3, 8.5], [NaN, 8], [3, Infinity], [-1, 8], [9, 8], [4, 8], [3, 9]] as const) expect(ok(o, n), `${o},${n}`).toBe(false);
    for (const path of [null, undefined, 'x', {}, 5]) expect(verifyLedgerConsistency(roots[3]!, roots[8]!, { ...p, path: path as never })).toBe(false);
  });
  it('the empty log is a prefix of everything, but only with the empty-tree oldRoot and an empty path', () => {
    expect(verifyLedgerConsistency(roots[0]!, roots[5]!, { oldSize: 0, newSize: 5, path: [] })).toBe(true);
    expect(verifyLedgerConsistency(roots[0]!, roots[5]!, { oldSize: 0, newSize: 5, path: ['AA'] })).toBe(false);
    expect(verifyLedgerConsistency('anything', 'whatever', { oldSize: 0, newSize: 5, path: [] })).toBe(false);
    expect(verifyLedgerConsistency('anything', 'whatever', { oldSize: 0, newSize: 0, path: [] })).toBe(false);
    expect(verifyLedgerConsistency(roots[0]!, roots[0]!, { oldSize: 0, newSize: 0, path: [] })).toBe(true);
    expect(verifyLedgerConsistency('x', 'x', { oldSize: 0, newSize: 0, path: ['x'] })).toBe(false);
  });
  it('equal sizes need an empty path AND equal roots', () => {
    expect(verifyLedgerConsistency(roots[4]!, roots[4]!, { oldSize: 4, newSize: 4, path: [] })).toBe(true);
    expect(verifyLedgerConsistency(roots[4]!, roots[5]!, { oldSize: 4, newSize: 4, path: [] })).toBe(false);
    expect(verifyLedgerConsistency(roots[4]!, roots[4]!, { oldSize: 4, newSize: 4, path: [roots[4]!] })).toBe(false);
    expect(verifyLedgerConsistency(roots[4]!, roots[5]!, { oldSize: 4, newSize: 4, path: [roots[4]!] })).toBe(false);
  });
  it('a non-power-of-two old size with an empty path is refused; hostile path entries never throw', () => {
    expect(verifyLedgerConsistency(roots[3]!, roots[8]!, { oldSize: 3, newSize: 8, path: [] })).toBe(false);
    expect(verifyLedgerConsistency(roots[3]!, roots[8]!, { oldSize: 3, newSize: 8, path: ['!!', 5 as never] })).toBe(false);
    expect(verifyLedgerConsistency(roots[3]!, roots[8]!, null as never)).toBe(false);
  });
});

describe('TransparencyLedger API bounds and messages', () => {
  it('default principal is the empty string (constructor and fromEntries)', () => {
    expect(new TransparencyLedger().principal).toBe('');
    expect(TransparencyLedger.fromEntries([]).principal).toBe('');
    expect(TransparencyLedger.fromEntries([], 'z').principal).toBe('z');
    expect(new TransparencyLedger().witnessHead(G.secretKey).principal).toBe('');
  });
  it('appendCommitment refuses non-strings and the empty string with its exact message', () => {
    const l = new TransparencyLedger('p');
    for (const c of ['', 5, null, undefined, {}]) expect(() => l.appendCommitment(c as never)).toThrow('appendCommitment: commit must be a non-empty string');
    expect(l.size).toBe(0);
    expect(l.appendCommitment('a')).toEqual({ index: 0, commit: 'a' });
  });
  it('rootAt: exact range checks and message', () => {
    const l = mkLedger(3);
    for (const s of [-1, 1.5, NaN, 4, Infinity, '2' as never]) expect(() => l.rootAt(s)).toThrow(new RangeError('rootAt: size out of range'));
    expect(l.rootAt(3)).toBe(l.head().root);
    expect(l.rootAt(0)).toBe(new TransparencyLedger().head().root);
    expect(l.rootAt(1)).toBe(mkLedger(1).head().root);
  });
  it('entry / shred: exact range errors, including index == size', () => {
    const l = mkLedger(2);
    for (const i of [-1, 2, 99]) {
      expect(() => l.entry(i)).toThrow(new RangeError('entry: index out of range'));
      expect(() => l.shred(i)).toThrow(new RangeError('shred: index out of range'));
    }
    expect(l.entry(1)).toEqual({ commit: 'c1' });
    expect(l.shred(0)).toBe(false);
  });
  it('consistencyProof: exact size checks and message', () => {
    const l = mkLedger(5);
    for (const [o, n] of [[-1, 3], [1.5, 3], [1, 3.5], [3, 2], [1, 6], [NaN, 3], [1, NaN]] as const) {
      expect(() => l.consistencyProof(o, n), `${o},${n}`).toThrow(new RangeError('consistencyProof: invalid sizes'));
    }
    expect(l.consistencyProof(0, 5)).toEqual({ oldSize: 0, newSize: 5, path: [] });
    expect(l.consistencyProof(5)).toEqual({ oldSize: 5, newSize: 5, path: [] });
    expect(l.consistencyProof(2, 5).path.length).toBeGreaterThan(0);
  });
});

describe('signature domains are fixed (known-answer, independent of the signer)', () => {
  it('witnessHead signs "atlas-pca/ledger-head/v1\\0" || canonical({principal,size,root})', () => {
    const l = mkLedger(3, 'prin');
    const wh = l.witnessHead(G.secretKey);
    const msg = cat(utf8('atlas-pca/ledger-head/v1\0'), canonicalBytes({ principal: 'prin', size: 3, root: l.head().root }));
    expect(verifyB64u(gPub, msg, wh.sig)).toBe(true);
    expect(wh).toMatchObject({ principal: 'prin', size: 3, witness: gPub });
  });
  const head = { instance_id: 'i', principal: 'p', size: 3, root: 'r', prev_root: 'q', timestamp: 9 };
  it('signTreeHead signs STH_DOMAIN || canonical({instance_id,principal,size,root,prev_root,timestamp})', () => {
    expect(STH_DOMAIN).toBe('atlas-pca/sth/v1\0');
    const s = signTreeHead(G.secretKey, head);
    expect(verifyB64u(gPub, cat(utf8(STH_DOMAIN), canonicalBytes(head)), s.sig)).toBe(true);
    expect(s).toEqual({ ...head, guardian: gPub, sig: s.sig });
  });
  it('cosignTreeHead signs STH_WITNESS_DOMAIN || canonical({scope + guardian_epoch (default 0)})', () => {
    expect(STH_WITNESS_DOMAIN).toBe('atlas-pca/sth-witness/v2\0');
    const w = generateKeyPair();
    const c0 = cosignTreeHead(head, w.secretKey);
    const body = (e: number) => canonicalBytes({ instance_id: 'i', principal: 'p', size: 3, root: 'r', prev_root: 'q', guardian_epoch: e });
    expect(verifyB64u(b64u(w.publicKey), cat(utf8(STH_WITNESS_DOMAIN), body(0)), c0.sig)).toBe(true);
    const c2 = cosignTreeHead({ ...head, guardian_epoch: 2 }, w.secretKey);
    expect(verifyB64u(b64u(w.publicKey), cat(utf8(STH_WITNESS_DOMAIN), body(2)), c2.sig)).toBe(true);
    expect(c0.key).toBe(b64u(w.publicKey));
  });
});

describe('verifyWitnessedHead / detectEquivocation', () => {
  const W = generateKeyPair();
  const wPub = b64u(W.publicKey);
  const a = mkLedger(3, 'p', 'a').witnessHead(W.secretKey);
  const b = mkLedger(3, 'p', 'b').witnessHead(W.secretKey);
  it('accepts only the exact witness key and a known suite; never throws', () => {
    expect(verifyWitnessedHead(a, wPub)).toBe(true);
    expect(verifyWitnessedHead({ ...a, witness: gPub }, wPub)).toBe(false); // valid sig, mislabelled witness
    expect(verifyWitnessedHead(a, gPub)).toBe(false);
    expect(verifyWitnessedHead({ ...a, alg: 'bogus' as never }, wPub)).toBe(false);
    expect(verifyWitnessedHead(null as never, wPub)).toBe(false);
    expect(verifyWitnessedHead({ ...a, size: 4 }, wPub)).toBe(false);
    expect(verifyWitnessedHead({ ...a, root: 'x' }, wPub)).toBe(false);
    expect(verifyWitnessedHead({ ...a, principal: 'q' }, wPub)).toBe(false);
    expect(verifyWitnessedHead({ ...a, size: 1n as never }, wPub)).toBe(false);
  });
  it('equivocation needs two VALID heads, same principal, same size, different roots', () => {
    expect(detectEquivocation(a, b, wPub)).toBe(true);
    expect(detectEquivocation(a, a, wPub)).toBe(false); // same root
    expect(detectEquivocation({ ...a, sig: b.sig }, b, wPub)).toBe(false); // first invalid
    expect(detectEquivocation(a, { ...b, sig: a.sig }, wPub)).toBe(false); // second invalid
    const other = mkLedger(3, 'other', 'b').witnessHead(W.secretKey);
    expect(detectEquivocation(a, other, wPub)).toBe(false); // different principal
    const longer = mkLedger(4, 'p', 'b').witnessHead(W.secretKey);
    expect(detectEquivocation(a, longer, wPub)).toBe(false); // different size
    expect(detectEquivocation(a, b, gPub)).toBe(false); // wrong witness key
  });
});

describe('verifyTreeHead / witnesses / head consistency', () => {
  const mkHead = (over: Partial<SignedTreeHead> = {}, key = G): SignedTreeHead =>
    signTreeHead(key.secretKey, { instance_id: 'i', principal: 'p', size: 3, root: 'r', prev_root: 'q', timestamp: 1, ...over });
  const ws = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
  const wk = ws.map((w) => b64u(w.publicKey));
  const withCos = (h: SignedTreeHead, idx: number[]): SignedTreeHead => ({ ...h, witnesses: idx.map((i) => cosignTreeHead(h, ws[i]!.secretKey)) });

  it('guardian key, suite and size are checked', () => {
    const h = mkHead();
    expect(verifyTreeHead(h, gPub)).toBe(true);
    expect(verifyTreeHead({ ...h, guardian: wk[0]! }, gPub)).toBe(false);
    expect(verifyTreeHead(h, wk[0]!)).toBe(false);
    expect(verifyTreeHead({ ...h, alg: 'bogus' as never }, gPub)).toBe(false);
    expect(verifyTreeHead(null as never, gPub)).toBe(false);
    expect(verifyTreeHead(mkHead({ size: 0 }), gPub)).toBe(true);
    for (const size of [-1, 1.5, -0.5]) expect(verifyTreeHead(mkHead({ size }), gPub), String(size)).toBe(false);
  });
  it('k-of-n: exact threshold, duplicates once, unknown witnesses ignored, malformed entries skipped', () => {
    const h = mkHead();
    const pol = (threshold: number, keys = wk) => ({ threshold, witnessKeys: keys });
    expect(verifyWitnessCosignatures(withCos(h, [0, 1]), pol(2))).toBe(true);
    expect(verifyWitnessCosignatures(withCos(h, [0]), pol(2))).toBe(false);
    expect(verifyWitnessCosignatures(withCos(h, [0, 0]), pol(2))).toBe(false); // duplicate key counts once
    expect(verifyWitnessCosignatures(withCos(h, [0, 1]), pol(2, [wk[0]!]))).toBe(false); // second is not trusted
    expect(verifyWitnessCosignatures(withCos(h, [0, 1, 2]), pol(3))).toBe(true);
    expect(verifyWitnessCosignatures(withCos(h, [0, 1, 2]), pol(1))).toBe(true);
    expect(verifyWitnessCosignatures(h, pol(0))).toBe(true); // vacuous
    expect(verifyWitnessCosignatures(h, pol(1))).toBe(false); // none present
    for (const t of [1.5, -1, NaN, undefined, '1']) expect(verifyWitnessCosignatures(withCos(h, [0]), { witnessKeys: wk, threshold: t as never }), String(t)).toBe(false);
    expect(verifyWitnessCosignatures(withCos(h, [0]), pol(1, []))).toBe(false);
    expect(verifyWitnessCosignatures(withCos(h, [0]), { threshold: 1 } as never)).toBe(false);
    expect(verifyWitnessCosignatures({ ...h, witnesses: 'nope' as never }, pol(1))).toBe(false);
    const good = cosignTreeHead(h, ws[0]!.secretKey);
    for (const junk of [null, 5, {}, { key: 5, sig: 'x' }, { key: wk[0], sig: 5 }]) {
      expect(verifyWitnessCosignatures({ ...h, witnesses: [junk as never, good] }, pol(1)), JSON.stringify(junk)).toBe(true);
    }
  });
  it('a cosignature is bound to this head (size/root/scope/epoch) and to its own key', () => {
    const h = mkHead();
    const c = cosignTreeHead(h, ws[0]!.secretKey);
    expect(verifyWitnessCosignature(h, c, wk[0]!)).toBe(true);
    expect(verifyWitnessCosignature(h, c, wk[1]!)).toBe(false);
    expect(verifyWitnessCosignature(h, { ...c, key: wk[1]! }, wk[1]!)).toBe(false);
    expect(verifyWitnessCosignature({ ...h, size: 4 }, c, wk[0]!)).toBe(false);
    expect(verifyWitnessCosignature({ ...h, instance_id: 'j' }, c, wk[0]!)).toBe(false);
    expect(verifyWitnessCosignature({ ...h, principal: 'z' }, c, wk[0]!)).toBe(false);
    expect(verifyWitnessCosignature(h, { ...c, alg: 'bogus' as never }, wk[0]!)).toBe(false);
    expect(verifyWitnessCosignature(h, { ...c, sig: 5 as never }, wk[0]!)).toBe(false);
    expect(verifyWitnessCosignature(h, null as never, wk[0]!)).toBe(false);
  });
  it('verifyTreeHead demands the witness threshold only when asked, and uses the supplied pin for PQ witnesses', () => {
    const h = mkHead();
    expect(verifyTreeHead(h, gPub, { threshold: 1, witnessKeys: wk })).toBe(false);
    expect(verifyTreeHead(withCos(h, [1]), gPub, { threshold: 1, witnessKeys: wk })).toBe(true);
    expect(verifyTreeHead(withCos(h, [1]), gPub)).toBe(true);
    // hybrid witness cosignature: valid only under a pin for that witness
    const ml = mlDsa65Keygen(crypto.getRandomValues(new Uint8Array(32)));
    const pk = encodeMlDsaPublicKey(ml.publicKey);
    const cos = cosignTreeHead(h, ws[0]!.secretKey, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml });
    const hh = { ...h, witnesses: [cos] };
    const pol = { threshold: 1, witnessKeys: wk };
    expect(verifyTreeHead(hh, gPub, pol)).toBe(false); // policy carries no pin
    expect(verifyTreeHead(hh, gPub, pol, { pqPins: { [wk[0]!]: pk } })).toBe(true); // explicit pin is used for the cosignature
    expect(verifyTreeHead(hh, gPub, { ...pol, pqPins: { [wk[0]!]: pk } })).toBe(true); // policy doubling as the pin
    expect(verifyTreeHead(hh, gPub, { ...pol, allowUnboundPq: true })).toBe(true);
  });
  it('verifyHeadConsistency: valid chain, then each binding broken in turn', () => {
    const L = mkLedger(6, 'p');
    const mk = (size: number, prev: string, over: Partial<SignedTreeHead> = {}) =>
      mkHead({ instance_id: 'i', principal: 'p', size, root: L.rootAt(size), prev_root: prev, ...over });
    const older = mk(3, 'x');
    const newer = mk(6, 'y');
    const proof = L.consistencyProof(3, 6);
    expect(verifyHeadConsistency(older, newer, proof, gPub)).toBe(true);
    expect(verifyHeadConsistency(mk(3, 'x', { instance_id: 'other' }), newer, proof, gPub)).toBe(false);
    expect(verifyHeadConsistency(older, mk(6, 'y', { instance_id: 'other' }), proof, gPub)).toBe(false);
    expect(verifyHeadConsistency(mk(3, 'x', { principal: 'q' }), newer, proof, gPub)).toBe(false);
    expect(verifyHeadConsistency(older, mk(6, 'y', { principal: 'q' }), proof, gPub)).toBe(false);
    expect(verifyHeadConsistency(older, newer, { ...proof, oldSize: 2 }, gPub)).toBe(false);
    expect(verifyHeadConsistency(older, newer, { ...proof, newSize: 5 }, gPub)).toBe(false);
    expect(verifyHeadConsistency({ ...older, sig: newer.sig }, newer, proof, gPub)).toBe(false);
    expect(verifyHeadConsistency(older, { ...newer, sig: older.sig }, proof, gPub)).toBe(false);
    expect(verifyHeadConsistency(older, newer, proof, wk[0]!)).toBe(false);
    // adjacent heads: prev_root must equal older.root
    const a5 = mk(5, 'x');
    const a6bad = mk(6, 'not-a5-root');
    const a6ok = mk(6, a5.root);
    const p56 = L.consistencyProof(5, 6);
    expect(verifyHeadConsistency(a5, a6ok, p56, gPub)).toBe(true);
    expect(verifyHeadConsistency(a5, a6bad, p56, gPub)).toBe(false);
    // non-adjacent: prev_root is not checked
    expect(verifyHeadConsistency(older, mk(6, 'whatever'), proof, gPub)).toBe(true);
    // witness policy is enforced on BOTH heads
    const pol = { threshold: 1, witnessKeys: wk };
    expect(verifyHeadConsistency(withCos(older, [0]), withCos(newer, [0]), proof, gPub, pol)).toBe(true);
    expect(verifyHeadConsistency(older, withCos(newer, [0]), proof, gPub, pol)).toBe(false);
    expect(verifyHeadConsistency(withCos(older, [0]), newer, proof, gPub, pol)).toBe(false);
    void publicKeyOf;
  });
});

describe('cosignature label and shape guards are independent of the signature check', () => {
  const g = generateKeyPair();
  const w = generateKeyPair();
  const wPub = b64u(w.publicKey);
  const h = signTreeHead(g.secretKey, { instance_id: 'i', principal: 'p', size: 3, root: 'r', prev_root: 'q', timestamp: 1 });
  const c = cosignTreeHead(h, w.secretKey);
  it('a validly signed cosignature whose key LABEL names someone else is refused', () => {
    expect(verifyWitnessCosignature(h, c, wPub)).toBe(true);
    expect(verifyWitnessCosignature(h, { ...c, key: b64u(generateKeyPair().publicKey) }, wPub)).toBe(false);
  });
  it('a cosignature with an unknown suite label is refused even though its signature is valid', () => {
    expect(verifyWitnessCosignature(h, { ...c, alg: 'ed25519' }, wPub)).toBe(true); // explicit default == absent
    expect(verifyWitnessCosignature(h, { ...c, alg: 'nope' as never }, wPub)).toBe(false);
  });
  it('a witnessed head with an unknown suite label is refused', () => {
    const wh = new TransparencyLedger('p').witnessHead(w.secretKey);
    expect(verifyWitnessedHead({ ...wh, alg: 'nope' as never }, wPub)).toBe(false);
  });
});

describe('fail-closed catch blocks and degenerate sizes (residual mutants)', () => {
  const g = generateKeyPair();
  const w = generateKeyPair();
  const wPub = b64u(w.publicKey);
  const h = signTreeHead(g.secretKey, { instance_id: 'i', principal: 'p', size: 3, root: 'r', prev_root: 'q', timestamp: 1 });
  it('verifyOpening returns false (not undefined, not a throw) for an opening that cannot be canonicalised', async () => {
    const { verifyOpening } = await import('./ledger');
    const r = verifyOpening('c', { salt: 's', pcactn: { x: undefined } as never });
    expect(r).toBe(false);
  });
  it('verifyWitnessedHead / Cosignature / Cosignatures / TreeHead / HeadConsistency return exactly false on hostile input', () => {
    const wh = new TransparencyLedger('p').witnessHead(w.secretKey);
    expect(verifyWitnessedHead({ ...wh, size: NaN }, wPub)).toBe(false);
    const c = cosignTreeHead(h, w.secretKey);
    expect(verifyWitnessCosignature({ ...h, timestamp: 1, size: NaN }, c, wPub)).toBe(false);
    expect(verifyWitnessCosignatures({ ...h, witnesses: [c] }, { threshold: 1, witnessKeys: 5 as never })).toBe(false);
    expect(verifyTreeHead({ ...h, timestamp: NaN }, b64u(g.publicKey))).toBe(false);
    expect(verifyHeadConsistency(h, h, null as never, b64u(g.publicKey))).toBe(false);
  });
  it('negative or inverted sizes never verify, even with a degenerate self-consistent path', () => {
    expect(verifyLedgerConsistency('R', 'R', { oldSize: -1, newSize: 1, path: ['R'] })).toBe(false);
    expect(verifyLedgerConsistency('R', 'R', { oldSize: 2, newSize: 1, path: [] })).toBe(false);
    const L = mkLedger(1);
    const r = L.head().root;
    expect(verifyLedgerConsistency(r, r, { oldSize: 2, newSize: 1, path: [] })).toBe(false);
    expect(verifyLedgerConsistency(r, r, { oldSize: -1, newSize: 1, path: [r] })).toBe(false);
  });
  it('witnesses must be an array: an iterable of valid cosignatures is not accepted', () => {
    const c = cosignTreeHead(h, w.secretKey);
    expect(verifyWitnessCosignatures({ ...h, witnesses: [c] }, { threshold: 1, witnessKeys: [wPub] })).toBe(true);
    expect(verifyWitnessCosignatures({ ...h, witnesses: new Set([c]) as never }, { threshold: 1, witnessKeys: [wPub] })).toBe(false);
  });
  it('the proof sizes must equal the heads sizes: a size-0 proof does not vouch for a non-empty older head', () => {
    const L = mkLedger(6, 'p');
    const mk = (size: number, prev: string) => signTreeHead(g.secretKey, { instance_id: 'i', principal: 'p', size, root: L.rootAt(size), prev_root: prev, timestamp: 1 });
    expect(verifyHeadConsistency(mk(3, 'x'), mk(6, 'y'), { oldSize: 0, newSize: 6, path: [] }, b64u(g.publicKey))).toBe(false);
  });
});

describe('hostile inputs are verdicts, never exceptions (catch arms)', () => {
  const g = generateKeyPair();
  const w = generateKeyPair();
  const wPub = b64u(w.publicKey);
  const h = signTreeHead(g.secretKey, { instance_id: 'i', principal: 'p', size: 3, root: 'r', prev_root: 'q', timestamp: 1 });
  const hostile = { ...h, size: 1n } as never;
  it('verifyOpening on an un-canonicalizable opening is false', () => {
    expect(verifyOpening('c', { salt: 's', pcactn: { x: 1n } as never })).toBe(false);
    expect(verifyOpening('c', null as never)).toBe(false);
  });
  it('cosignature / witness-set / tree-head / head-consistency verification never throw', () => {
    const c = cosignTreeHead(h, w.secretKey);
    expect(verifyWitnessCosignature(hostile, c, wPub)).toBe(false);
    expect(verifyWitnessCosignatures(hostile, { threshold: 1, witnessKeys: [wPub] })).toBe(false);
    expect(verifyTreeHead(hostile, b64u(g.publicKey))).toBe(false);
    const L = mkLedger(3);
    expect(verifyHeadConsistency(hostile, h, L.consistencyProof(3, 3), b64u(g.publicKey))).toBe(false);
    expect(verifyHeadConsistency(h, h, null as never, b64u(g.publicKey))).toBe(false);
  });
});
