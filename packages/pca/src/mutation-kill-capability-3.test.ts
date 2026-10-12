/** Capability residual mutants: holder_pq is body-bound; verifyChainCheap on a pure-PQ hop; non-Error throws are verdicts. */
import { describe, expect, it } from 'vitest';
import { delegate, holderPqCommitment, verifyChain, verifyChainCheap, type Capability } from './capability';
import { mintGrant } from './envelope';
import { b64u } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import { mlDsa65Keygen } from './pq';
import { DEFAULT_RISK_POLICY } from './risk';

const P = generateKeyPair();
const A = generateKeyPair();
const B = generateKeyPair();
const pPub = encodeKey(P.publicKey);
const aPub = encodeKey(A.publicKey);
const bPub = encodeKey(B.publicKey);
const grant = (): Capability =>
  mintGrant({ principalSecret: P.secretKey, principalPublic: pPub, holder: aPub, goal: 'g', envelope: { predicates: [{ verb: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } }).grant;
const pq1 = b64u(mlDsa65Keygen(new Uint8Array(32).fill(1)).publicKey);
const pq2 = b64u(mlDsa65Keygen(new Uint8Array(32).fill(2)).publicKey);

describe('holder_pq is covered by the body digest', () => {
  it('a hop that commits holder_pq carries it, and swapping it for another commitment breaks the digest', () => {
    const g = grant();
    const hop = delegate(g, bPub, [{ type: 'task' }], A.secretKey, undefined, pq1);
    expect(hop.holder_pq).toBe(holderPqCommitment(pq1));
    expect(verifyChain([g, hop], pPub)).toEqual({ ok: true });
    expect(verifyChainCheap([g, hop], pPub)).toEqual({ ok: true, pqHops: 0 });
    const swapped = { ...hop, holder_pq: holderPqCommitment(pq2) };
    expect(verifyChain([g, swapped], pPub)).toEqual({ ok: false, reason: 'hop 1: body digest mismatch' });
    expect(verifyChainCheap([g, swapped], pPub)).toEqual({ ok: false, reason: 'hop 1: body digest mismatch' });
    const { holder_pq: _drop, ...stripped } = hop;
    expect(verifyChainCheap([g, stripped as Capability], pPub)).toEqual({ ok: false, reason: 'hop 1: body digest mismatch' });
  });
});

describe('verifyChainCheap residuals', () => {
  it('a pure-PQ hop has no Ed25519 half: it passes on structure alone and counts as a PQ hop', () => {
    const g = grant();
    const ml = mlDsa65Keygen(new Uint8Array(32).fill(3));
    const hop = delegate(g, bPub, [{ type: 'task' }], A.secretKey, { alg: 'ml-dsa-65', mlDsa: ml });
    expect(hop.alg).toBe('ml-dsa-65');
    expect(verifyChainCheap([g, hop], pPub)).toEqual({ ok: true, pqHops: 1 });
  });
  it('a non-Error throw from the chain object is reported as unverifiable (cheap and full)', () => {
    const hostile = new Proxy([], {
      get() {
        throw 'not an Error';
      },
    });
    expect(verifyChainCheap(hostile as never)).toEqual({ ok: false, reason: 'malformed capability chain: unverifiable' });
    expect(verifyChain(hostile as never)).toEqual({ ok: false, reason: 'malformed capability chain: unverifiable' });
  });
});
