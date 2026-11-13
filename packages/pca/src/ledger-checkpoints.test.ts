import { describe, expect, it } from 'vitest';
import { TransparencyLedger, cosignTreeHead, detectTreeHeadEquivocation, signTreeHead, verifyCheckpointChain, type Checkpoint, type SignedTreeHead } from './ledger';
import { b64u } from './hash';
import { encodeKey, generateKeyPair } from './keys';

const G = generateKeyPair();
const O = generateKeyPair();
const W = generateKeyPair();
const gpk = encodeKey(G.publicKey);
const log = new TransparencyLedger('p');
for (let i = 0; i < 30; i++) log.appendCommitment(b64u(new TextEncoder().encode(`leaf-${i}-padding-padding-padding`)).slice(0, 43));
const sth = (size: number, prev?: number, o: { root?: string; secret?: Uint8Array; instance?: string; principal?: string } = {}): SignedTreeHead =>
  signTreeHead(o.secret ?? G.secretKey, { instance_id: o.instance ?? 'i', principal: o.principal ?? 'p', size, root: o.root ?? log.rootAt(size), prev_root: prev === undefined ? '' : log.rootAt(prev), timestamp: 1000 + size });
const cp = (size: number, prev?: number, from?: number): Checkpoint => ({ sth: sth(size, prev), ...(from === undefined ? {} : { proof: log.consistencyProof(from, size) }) });
const flip = (s: string) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1);

describe('verifyCheckpointChain: the first failing boundary is named', () => {
  it('accepts an honest chain and returns its last head', () => {
    const chain = [cp(1), cp(4, 3, 1), cp(9, 8, 4), cp(30, 29, 9)];
    expect(verifyCheckpointChain(chain, gpk)).toEqual({ ok: true, head: chain[3]!.sth });
    expect(verifyCheckpointChain([chain[0]!], gpk)).toEqual({ ok: true, head: chain[0]!.sth });
  });
  it('empty and non-array chains fail closed', () => {
    expect(verifyCheckpointChain([], gpk)).toEqual({ ok: false, at: 0, reason: 'empty' });
    expect(verifyCheckpointChain('x' as never, gpk)).toEqual({ ok: false, at: 0, reason: 'empty' });
    expect(verifyCheckpointChain(null as never, gpk)).toEqual({ ok: false, at: 0, reason: 'empty' });
  });
  it('a forged or foreign head fails at its own index with reason head', () => {
    const chain = [cp(1), cp(4, 3, 1), cp(9, 8, 4)];
    expect(verifyCheckpointChain([{ sth: { ...chain[0]!.sth, sig: flip(chain[0]!.sth.sig) } }, chain[1]!], gpk)).toEqual({ ok: false, at: 0, reason: 'head' });
    expect(verifyCheckpointChain([chain[0]!, chain[1]!, { sth: { ...chain[2]!.sth, root: flip(chain[2]!.sth.root) }, proof: chain[2]!.proof }], gpk)).toEqual({ ok: false, at: 2, reason: 'head' });
    expect(verifyCheckpointChain(chain, encodeKey(O.publicKey))).toEqual({ ok: false, at: 0, reason: 'head' });
    expect(verifyCheckpointChain([chain[0]!, null as never], gpk)).toEqual({ ok: false, at: 1, reason: 'head' });
  });
  it('a missing proof is proof_missing, a proof that does not connect the pair is inconsistent', () => {
    const chain = [cp(1), cp(4, 3, 1), cp(9, 8, 4)];
    expect(verifyCheckpointChain([chain[0]!, { sth: chain[1]!.sth }], gpk)).toEqual({ ok: false, at: 1, reason: 'proof_missing' });
    expect(verifyCheckpointChain([chain[0]!, chain[1]!, { sth: chain[2]!.sth, proof: log.consistencyProof(1, 9) }], gpk)).toEqual({ ok: false, at: 2, reason: 'inconsistent' });
    expect(verifyCheckpointChain([chain[0]!, { sth: chain[1]!.sth, proof: { ...chain[1]!.proof!, path: [] } }], gpk)).toEqual({ ok: false, at: 1, reason: 'inconsistent' });
  });
  it('rewritten history between checkpoints, a shrinking log and a broken prev_root link are all inconsistent', () => {
    const rewritten = { sth: sth(9, 8, { root: new TransparencyLedger('x').head().root }), proof: log.consistencyProof(4, 9) };
    expect(verifyCheckpointChain([cp(1), cp(4, 3, 1), rewritten], gpk)).toEqual({ ok: false, at: 2, reason: 'inconsistent' });
    expect(verifyCheckpointChain([cp(9, 8), { sth: sth(4, 3), proof: { oldSize: 9, newSize: 4, path: [] } }], gpk)).toEqual({ ok: false, at: 1, reason: 'inconsistent' });
    expect(verifyCheckpointChain([cp(1), { sth: sth(2, 1, {}), proof: log.consistencyProof(1, 2) }], gpk)).toEqual({ ok: true, head: sth(2, 1) });
    const badLink = signTreeHead(G.secretKey, { instance_id: 'i', principal: 'p', size: 2, root: log.rootAt(2), prev_root: log.rootAt(5), timestamp: 1 });
    expect(verifyCheckpointChain([cp(1), { sth: badLink, proof: log.consistencyProof(1, 2) }], gpk)).toEqual({ ok: false, at: 1, reason: 'inconsistent' });
  });
  it('a witness threshold applies to every head of the chain', () => {
    const w = { witnessKeys: [encodeKey(W.publicKey)], threshold: 1 };
    const withW = (s: SignedTreeHead): SignedTreeHead => ({ ...s, witnesses: [cosignTreeHead(s, W.secretKey)] });
    const a = cp(4, 3);
    const b = cp(9, 8, 4);
    expect(verifyCheckpointChain([{ sth: withW(a.sth) }, { sth: withW(b.sth), proof: b.proof }], gpk, w)).toMatchObject({ ok: true });
    expect(verifyCheckpointChain([{ sth: withW(a.sth) }, b], gpk, w)).toEqual({ ok: false, at: 1, reason: 'head' });
    expect(verifyCheckpointChain([a, b], gpk, w)).toEqual({ ok: false, at: 0, reason: 'head' });
  });
});

describe('detectTreeHeadEquivocation', () => {
  const forked = new TransparencyLedger('p');
  for (let i = 0; i < 8; i++) forked.appendCommitment(i === 7 ? 'different' : b64u(new TextEncoder().encode(`leaf-${i}-padding-padding-padding`)).slice(0, 43));
  const a = sth(8, 7);
  const b = sth(8, 7, { root: forked.head().root });
  it('two genuine heads, one log, one size, two roots', () => {
    expect(detectTreeHeadEquivocation(a, b, gpk)).toBe(true);
    expect(detectTreeHeadEquivocation(b, a, gpk)).toBe(true);
  });
  it('every other combination is not evidence', () => {
    expect(detectTreeHeadEquivocation(a, a, gpk)).toBe(false); // same root
    expect(detectTreeHeadEquivocation(a, sth(9, 8), gpk)).toBe(false); // other size
    expect(detectTreeHeadEquivocation(a, sth(8, 7, { root: forked.head().root, principal: 'q' }), gpk)).toBe(false);
    expect(detectTreeHeadEquivocation(a, sth(8, 7, { root: forked.head().root, instance: 'j' }), gpk)).toBe(false);
    expect(detectTreeHeadEquivocation(a, { ...b, sig: flip(b.sig) }, gpk)).toBe(false); // one forged
    expect(detectTreeHeadEquivocation(a, sth(8, 7, { root: forked.head().root, secret: O.secretKey }), gpk)).toBe(false);
    expect(detectTreeHeadEquivocation(a, b, encodeKey(O.publicKey))).toBe(false);
    expect(detectTreeHeadEquivocation(null as never, b, gpk)).toBe(false);
    expect(detectTreeHeadEquivocation(a, 'x' as never, gpk)).toBe(false);
  });
});
