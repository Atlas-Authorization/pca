/** Mutation-kill tests for verifyChainCheap (the cheap pre-authentication chain gate): each refusal asserted as the exact result. */
import { describe, expect, it } from 'vitest';
import {
  CAVEAT_LIMIT_REASON, MAX_CAVEATS_PER_HOP, MAX_CHAIN_DEPTH, attenuate, delegate, holderPqCommitment, verifyChain, verifyChainCheap,
  type Capability,
} from './capability';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';
import { DEFAULT_RISK_POLICY } from './risk';

const P = generateKeyPair();
const A = generateKeyPair();
const B = generateKeyPair();
const pPub = encodeKey(P.publicKey);
const aPub = encodeKey(A.publicKey);
const bPub = encodeKey(B.publicKey);
const grant = (): Capability =>
  mintGrant({ principalSecret: P.secretKey, principalPublic: pPub, holder: aPub, goal: 'g', envelope: { predicates: [{ verb: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } }).grant;
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const flip = (s: string) => s.slice(0, 10) + (s[10] === 'A' ? 'B' : 'A') + s.slice(11);

describe('verifyChainCheap', () => {
  it('accepts a good chain with the exact result {ok, pqHops:0}, with and without the expected root issuer', () => {
    const g = grant();
    const hop = delegate(g, bPub, [{ type: 'task' }], A.secretKey);
    expect(verifyChainCheap([g], undefined)).toEqual({ ok: true, pqHops: 0 });
    expect(verifyChainCheap([g, hop], pPub)).toEqual({ ok: true, pqHops: 0 });
    expect(verifyChain([g, hop], pPub)).toEqual({ ok: true });
  });
  it('empty / non-array chain', () => {
    for (const c of [[], undefined, null, 'x', {}] as never[]) expect(verifyChainCheap(c)).toEqual({ ok: false, reason: 'empty chain' });
  });
  it('depth bound is inclusive at MAX_CHAIN_DEPTH', () => {
    expect(verifyChainCheap(new Array(MAX_CHAIN_DEPTH + 1).fill({}) as never)).toEqual({ ok: false, reason: `chain too long (max ${MAX_CHAIN_DEPTH} hops)` });
    expect(verifyChainCheap(new Array(MAX_CHAIN_DEPTH).fill({}) as never)).toEqual({ ok: false, reason: 'hop 0: malformed capability' });
  });
  it('caveat limit is reported before any per-hop check', () => {
    const g = grant();
    const big = { ...g, caveats: Array.from({ length: MAX_CAVEATS_PER_HOP + 1 }, () => ({ type: 'task' })) };
    expect(verifyChainCheap([big])).toEqual({ ok: false, reason: CAVEAT_LIMIT_REASON });
  });
  it('caveat caps: 256 per hop is allowed, 257 refused; 1024 per chain allowed, 1025 refused', () => {
    const g = grant();
    const mk = (n: number) => ({ ...g, caveats: Array.from({ length: n }, () => ({ type: 'task' })) });
    expect(verifyChainCheap([mk(MAX_CAVEATS_PER_HOP)])).toEqual({ ok: false, reason: 'hop 0: body digest mismatch' });
    expect(verifyChainCheap([mk(MAX_CAVEATS_PER_HOP + 1)])).toEqual({ ok: false, reason: CAVEAT_LIMIT_REASON });
    expect(verifyChainCheap([mk(256), mk(256), mk(256), mk(256)])).toEqual({ ok: false, reason: 'hop 0: body digest mismatch' });
    expect(verifyChainCheap([mk(256), mk(256), mk(256), mk(256), mk(1)])).toEqual({ ok: false, reason: CAVEAT_LIMIT_REASON });
  });
  it('malformed hops name their index', () => {
    const g = grant();
    expect(verifyChainCheap([{}] as never)).toEqual({ ok: false, reason: 'hop 0: malformed capability' });
    expect(verifyChainCheap([g, {}] as never)).toEqual({ ok: false, reason: 'hop 1: malformed capability' });
    expect(verifyChainCheap([g, null] as never)).toEqual({ ok: false, reason: 'hop 1: malformed capability' });
  });
  it('unknown signature alg names the alg and hop', () => {
    const g = { ...grant(), alg: 'bogus' };
    expect(verifyChainCheap([g] as never)).toEqual({ ok: false, reason: "hop 0: unknown signature alg 'bogus'" });
  });
  it('suite policy refusal carries the hop label', () => {
    const g = grant();
    const r = verifyChainCheap([g], undefined, { allowedSuites: ['hybrid-ed25519-ml-dsa-65'] });
    expect(r.ok).toBe(false);
    expect((r as { reason: string }).reason.startsWith('hop 0: ')).toBe(true);
    expect(verifyChainCheap([g], undefined, { allowedSuites: ['ed25519'] })).toEqual({ ok: true, pqHops: 0 });
  });
  it('root must not have a parent; root issuer must match when expected', () => {
    const g = grant();
    expect(verifyChainCheap([{ ...g, parent: 'x' }])).toEqual({ ok: false, reason: 'hop 0: root must not have a parent' });
    expect(verifyChainCheap([g], bPub)).toEqual({ ok: false, reason: 'hop 0: root issuer is not the expected principal' });
  });
  it('broken parent link and issuer-not-holder at hop 1', () => {
    const g = grant();
    const hop = delegate(g, bPub, [{ type: 'task' }], A.secretKey);
    expect(verifyChainCheap([g, { ...hop, parent: 'zz' }])).toEqual({ ok: false, reason: 'hop 1: broken parent link' });
    expect(verifyChainCheap([g, { ...hop, issuer: bPub }])).toEqual({ ok: false, reason: "hop 1: issuer is not the parent's bound holder" });
  });
  it('body digest mismatch (body or id altered)', () => {
    const g = grant();
    const hop = delegate(g, bPub, [{ type: 'task' }], A.secretKey);
    expect(verifyChainCheap([{ ...g, caveats: [{ type: 'tampered' }] } as never])).toEqual({ ok: false, reason: 'hop 0: body digest mismatch' });
    const alt = clone(hop);
    alt.caveats = [{ type: 'other' }];
    expect(verifyChainCheap([g, alt])).toEqual({ ok: false, reason: 'hop 1: body digest mismatch' });
    expect(verifyChainCheap([g, { ...hop, id: g.id }])).toEqual({ ok: false, reason: 'hop 1: body digest mismatch' });
  });
  it('bad Ed25519 signature on any hop', () => {
    const g = grant();
    const hop = delegate(g, bPub, [{ type: 'task' }], A.secretKey);
    expect(verifyChainCheap([{ ...g, sig: flip(g.sig) }])).toEqual({ ok: false, reason: 'hop 0: bad signature (not signed by expected key)' });
    expect(verifyChainCheap([g, { ...hop, sig: flip(hop.sig) }])).toEqual({ ok: false, reason: 'hop 1: bad signature (not signed by expected key)' });
    // hop 1 signed by the wrong key
    const wrong = delegate(g, bPub, [{ type: 'task' }], B.secretKey);
    expect(verifyChainCheap([g, wrong])).toEqual({ ok: false, reason: 'hop 1: bad signature (not signed by expected key)' });
  });
  it('a non-canonicalisable caveat is a "malformed body" verdict, not a throw', () => {
    const g = grant();
    const bad = { ...g, caveats: [{ type: 'n', v: Number.NaN }] };
    expect(verifyChainCheap([bad] as never)).toEqual({ ok: false, reason: 'hop 0: malformed body' });
  });
  it('a hybrid hop counts as a PQ hop but its PQ half is NOT verified here', () => {
    const g = grant();
    const pq = mlDsa65Keygen(crypto.getRandomValues(new Uint8Array(32)));
    const other = mlDsa65Keygen(crypto.getRandomValues(new Uint8Array(32)));
    const ok = delegate(g, aPub, [{ type: 'task' }], A.secretKey, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: other });
    expect(verifyChainCheap([g, ok])).toEqual({ ok: true, pqHops: 1 });
    expect(verifyChain([g, ok]).ok).toBe(false); // the full verifier refuses the unbound PQ key (F-2)
    void pq; void holderPqCommitment; void encodeMlDsaPublicKey; void attenuate;
  });
  it('a throwing chain object is a verdict', () => {
    const hostile = new Proxy([], { get() { throw new Error('boom'); } });
    expect(verifyChainCheap(hostile as never)).toEqual({ ok: false, reason: 'malformed capability chain: boom' });
  });
});
