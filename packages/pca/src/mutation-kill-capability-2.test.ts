/** Round-2 mutation-kill tests for capability.ts: PQ binding, caveat limits, exact reasons, delegate holder_pq. */
import { describe, expect, it } from 'vitest';
import {
  CAVEAT_LIMIT_REASON,
  MAX_CAVEATS_PER_CHAIN,
  MAX_CAVEATS_PER_HOP,
  MAX_CHAIN_DEPTH,
  delegate,
  holderPqCommitment,
  holderPqKey,
  mintRoot,
  pqBindingError,
  verifyChain,
  type Capability,
} from './capability';
import { encodeKey, generateKeyPair } from './keys';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';

const rnd = () => crypto.getRandomValues(new Uint8Array(32));
const ALG = 'hybrid-ed25519-ml-dsa-65' as const;
const P = generateKeyPair();
const A = generateKeyPair();
const B = generateKeyPair();
const pPub = encodeKey(P.publicKey);
const aPub = encodeKey(A.publicKey);
const bPub = encodeKey(B.publicKey);
const aPq = mlDsa65Keygen(rnd());
const evil = mlDsa65Keygen(rnd());
const aPqPk = encodeMlDsaPublicKey(aPq.publicKey);
const evilPk = encodeMlDsaPublicKey(evil.publicKey);
const commit = holderPqCommitment(aPqPk);

describe('pqBindingError (F-2): exact verdicts', () => {
  const NOCOMMIT = `L: suite '${ALG}' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)`;
  const MISMATCH = "L: pq_pk does not match the signer's committed holder_pq (F-2)";
  it('ed25519, absent and unknown suites are not subject to binding', () => {
    for (const alg of ['ed25519', undefined, 'bogus', 7]) {
      expect(pqBindingError(alg, aPqPk, undefined, 'L', undefined)).toBeUndefined();
      expect(pqBindingError(alg, evilPk, commit, 'L', undefined)).toBeUndefined();
    }
  });
  it('a PQ suite with no commitment is refused with the no-commitment reason, whatever pq_pk is', () => {
    for (const pk of [aPqPk, undefined, 5]) expect(pqBindingError(ALG, pk, undefined, 'L', undefined)).toBe(NOCOMMIT);
    expect(pqBindingError(ALG, aPqPk, undefined, 'L', { allowUnboundPq: false })).toBe(NOCOMMIT);
  });
  it('a matching commitment passes; a wrong, missing or non-string pq_pk is a mismatch', () => {
    expect(pqBindingError(ALG, aPqPk, commit, 'L', undefined)).toBeUndefined();
    expect(pqBindingError(ALG, evilPk, commit, 'L', undefined)).toBe(MISMATCH);
    for (const pk of [undefined, null, 5, {}, '']) expect(pqBindingError(ALG, pk, commit, 'L', undefined)).toBe(MISMATCH);
  });
  it('allowUnboundPq skips the rule entirely (with or without a commitment, right or wrong key); only === true counts', () => {
    expect(pqBindingError(ALG, evilPk, commit, 'L', { allowUnboundPq: true })).toBeUndefined();
    expect(pqBindingError(ALG, evilPk, undefined, 'L', { allowUnboundPq: true })).toBeUndefined();
    expect(pqBindingError(ALG, evilPk, commit, 'L', { allowUnboundPq: 1 as never })).toBe(MISMATCH);
  });
  it('a pure-PQ suite is bound the same way', () => {
    expect(pqBindingError('ml-dsa-65', aPqPk, commit, 'L', undefined)).toBeUndefined();
    expect(pqBindingError('ml-dsa-65', evilPk, commit, 'L', undefined)).toBe(MISMATCH);
  });
});

describe('holderPqKey', () => {
  it('is {} for ed25519, absent and unknown suites', () => {
    for (const alg of ['ed25519', undefined, 'bogus']) expect(holderPqKey(alg, aPub, aPqPk, commit)).toEqual({});
  });
  it('mints a key only for the committed pq_pk (or when unbound is allowed)', () => {
    expect(Object.keys(holderPqKey(ALG, aPub, aPqPk, commit))).toEqual(['pq']);
    expect(holderPqKey(ALG, aPub, evilPk, commit)).toEqual({});
    expect(holderPqKey(ALG, aPub, aPqPk, undefined)).toEqual({});
    expect(Object.keys(holderPqKey(ALG, aPub, evilPk, undefined, true))).toEqual(['pq']);
    expect(holderPqKey(ALG, aPub, evilPk, commit, false)).toEqual({});
  });
});

describe('verifyChain: hybrid hops, exact reasons', () => {
  const mk = () => mintRoot({ principalSecret: P.secretKey, principalPublic: pPub, holder: aPub, holderPq: aPqPk, caveats: [{ type: 'ttl', secs: 1 }] });
  const hop = (root: Capability, pq = aPq) => delegate(root, bPub, [{ type: 'x' }], A.secretKey, { alg: ALG, mlDsa: pq });
  it('accepts a hop signed under the committed key', () => {
    const r = mk();
    expect(verifyChain([r, hop(r)], pPub)).toEqual({ ok: true });
  });
  it('rejects a hop signed under another PQ key with the mismatch reason', () => {
    const r = mk();
    expect(verifyChain([r, hop(r, evil)], pPub)).toEqual({ ok: false, reason: "hop 1: pq_pk does not match the signer's committed holder_pq (F-2)" });
  });
  it('rejects a hybrid hop whose parent carries no commitment with the no-commitment reason', () => {
    const r = mintRoot({ principalSecret: P.secretKey, principalPublic: pPub, holder: aPub, caveats: [{ type: 'ttl', secs: 1 }] });
    const v = verifyChain([r, hop(r)], pPub);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe(`hop 1: suite '${ALG}' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)`);
    expect(verifyChain([r, hop(r)], pPub, { allowUnboundPq: true })).toEqual({ ok: true });
  });
  it('suite policy refusal is reported verbatim', () => {
    const r = mk();
    expect(verifyChain([r, hop(r)], pPub, { allowedSuites: ['ed25519'] })).toEqual({
      ok: false,
      reason: `hop 1: signature suite '${ALG}' is not allowed by this verifier's suite policy`,
    });
    expect(verifyChain([r, hop(r)], pPub, { allowedSuites: ['ed25519', ALG] })).toEqual({ ok: true });
  });
  it('an unknown suite on a later hop is a clean verdict, not a thrown error', () => {
    const r = mk();
    const h = { ...hop(r), alg: 'bogus' } as unknown as Capability;
    expect(verifyChain([r, h], pPub)).toEqual({ ok: false, reason: "hop 1: unknown signature alg 'bogus'" });
  });
  it('a tampered PQ signature is a bad signature', () => {
    const r = mk();
    const h = hop(r);
    const bad = { ...h, pq_sig: h.pq_sig!.slice(0, -4) + (h.pq_sig!.endsWith('AAAA') ? 'BBBB' : 'AAAA') };
    expect(verifyChain([r, bad], pPub)).toEqual({ ok: false, reason: 'hop 1: bad signature (not signed by expected key)' });
  });
});

describe('verifyChain: hybrid ROOT needs a verifier-side pin (R3-01)', () => {
  const root = mintRoot({ principalSecret: P.secretKey, principalPublic: pPub, holder: aPub, caveats: [{ type: 'ttl', secs: 1 }], suite: { alg: ALG, mlDsa: aPq } });
  const REFUSED = `hop 0: root suite '${ALG}' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)`;
  it('refuses with no pin, a wrong pin and a pin for another issuer', () => {
    expect(verifyChain([root], pPub)).toEqual({ ok: false, reason: REFUSED });
    expect(verifyChain([root], pPub, { pqPins: { [pPub]: evilPk } })).toEqual({ ok: false, reason: REFUSED });
    expect(verifyChain([root], pPub, { pqPins: { [aPub]: aPqPk } })).toEqual({ ok: false, reason: REFUSED });
  });
  it('accepts the exact pin, a byte-identical trustedRoot, or allowUnboundPq', () => {
    expect(verifyChain([root], pPub, { pqPins: { [pPub]: root.pq_pk! } })).toEqual({ ok: true });
    expect(verifyChain([root], pPub, { trustedRoot: root })).toEqual({ ok: true });
    expect(verifyChain([root], pPub, { allowUnboundPq: true })).toEqual({ ok: true });
  });
  it('a trustedRoot that differs from the presented root does not vouch for it', () => {
    const other = mintRoot({ principalSecret: P.secretKey, principalPublic: pPub, holder: bPub, caveats: [{ type: 'ttl', secs: 1 }], suite: { alg: ALG, mlDsa: aPq } });
    expect(verifyChain([root], pPub, { trustedRoot: other })).toEqual({ ok: false, reason: REFUSED });
  });
});

describe('verifyChain: caveat limits are exact and checked before any crypto', () => {
  const fake = (n: number) => ({ caveats: new Array(n).fill({ type: 'x' }) }) as unknown as Capability;
  it('exports the documented limits', () => {
    expect([MAX_CAVEATS_PER_HOP, MAX_CAVEATS_PER_CHAIN, MAX_CHAIN_DEPTH]).toEqual([256, 1024, 16]);
  });
  it('exactly 256 caveats on a hop passes the limit (fails later), 257 trips it', () => {
    expect(verifyChain([fake(256)]).reason).not.toBe(CAVEAT_LIMIT_REASON);
    expect(verifyChain([fake(257)])).toEqual({ ok: false, reason: CAVEAT_LIMIT_REASON });
    expect(verifyChain([fake(1), fake(257)])).toEqual({ ok: false, reason: CAVEAT_LIMIT_REASON });
  });
  it('the chain total is exactly 1024 allowed, 1025 refused', () => {
    expect(verifyChain([fake(256), fake(256), fake(256), fake(256)]).reason).not.toBe(CAVEAT_LIMIT_REASON);
    expect(verifyChain([fake(256), fake(256), fake(256), fake(256), fake(1)])).toEqual({ ok: false, reason: CAVEAT_LIMIT_REASON });
    expect(verifyChain([fake(256), fake(256), fake(256), fake(257)])).toEqual({ ok: false, reason: CAVEAT_LIMIT_REASON });
  });
  it('non-object hops contribute nothing and do not throw; the limit still applies to the objects around them', () => {
    expect(verifyChain([null, fake(257)] as never)).toEqual({ ok: false, reason: CAVEAT_LIMIT_REASON });
    expect(verifyChain([5, 'x', fake(2)] as never).reason).not.toBe(CAVEAT_LIMIT_REASON);
  });
  it('a non-array caveats field counts as zero', () => {
    expect(verifyChain([{ caveats: 'x'.repeat(5000) }] as never).reason).not.toBe(CAVEAT_LIMIT_REASON);
  });
});

describe('delegate: holder_pq inheritance', () => {
  const r = mintRoot({ principalSecret: P.secretKey, principalPublic: pPub, holder: aPub, holderPq: aPqPk, caveats: [] });
  it('an explicit holderPq is committed', () => {
    expect(delegate(r, bPub, [], A.secretKey, undefined, evilPk).holder_pq).toBe(holderPqCommitment(evilPk));
  });
  it('the same holder keeps the commitment; a new holder without one gets none', () => {
    expect(delegate(r, aPub, [], A.secretKey).holder_pq).toBe(commit);
    expect(delegate(r, bPub, [], A.secretKey).holder_pq).toBeUndefined();
    expect('holder_pq' in delegate(r, bPub, [], A.secretKey)).toBe(false);
  });
});

describe('wellTyped: holder_pq must be a string when present', () => {
  it('a non-string holder_pq makes the hop malformed', () => {
    const r = mintRoot({ principalSecret: P.secretKey, principalPublic: pPub, holder: aPub, caveats: [] });
    expect(verifyChain([{ ...r, holder_pq: 5 } as never], pPub)).toEqual({ ok: false, reason: 'hop 0: malformed capability' });
    expect(verifyChain([{ ...r, holder_pq: undefined } as never], pPub)).toEqual({ ok: true });
  });
});

describe('verifyChain: depth bound beats the caveat bound', () => {
  const fake = (n: number) => ({ caveats: new Array(n).fill({ type: 'x' }) }) as unknown as Capability;
  it('a chain of MAX_CHAIN_DEPTH hops is still subject to the caveat limit; MAX+1 is reported as too long first', () => {
    expect(verifyChain(Array.from({ length: MAX_CHAIN_DEPTH }, () => fake(257)))).toEqual({ ok: false, reason: CAVEAT_LIMIT_REASON });
    expect(verifyChain(Array.from({ length: MAX_CHAIN_DEPTH + 1 }, () => fake(257)))).toEqual({ ok: false, reason: `chain too long (max ${MAX_CHAIN_DEPTH} hops)` });
  });
});
