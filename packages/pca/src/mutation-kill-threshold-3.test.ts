/** Threshold R6-02 (a role that registers a pq_pk needs a PQ/hybrid share) and R6-03 (conflicting duplicate (role,key) pq_pk). */
import { describe, expect, it } from 'vitest';
import { b64u, utf8 } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import { mlDsa65Keygen } from './pq';
import { signShare, verifyThreshold, type Signer } from './threshold';

const MSG = utf8('mk3');
const ml1 = mlDsa65Keygen(new Uint8Array(32).fill(7));
const ml2 = mlDsa65Keygen(new Uint8Array(32).fill(8));
const pk1 = b64u(ml1.publicKey);
const pk2 = b64u(ml2.publicKey);
const A = generateKeyPair();
const aPub = encodeKey(A.publicKey);
const HY = { alg: 'hybrid-ed25519-ml-dsa-65' as const, mlDsa: ml1 };

describe('R6-03: duplicate (role, key) signer entries', () => {
  it('identical duplicates (same pq_pk, or none on both) are harmless', () => {
    const withPq: Signer[] = [{ role: 'agent', publicKey: aPub, pq_pk: pk1 }, { role: 'agent', publicKey: aPub, pq_pk: pk1 }];
    const share = signShare('agent', A.secretKey, MSG, { signerSet: withPq, t: 1 }, HY);
    expect(verifyThreshold({ shares: [share] }, MSG, withPq, 1)).toEqual({ ok: true, count: 1, roles: ['agent'] });
    const none: Signer[] = [{ role: 'agent', publicKey: aPub }, { role: 'agent', publicKey: aPub }];
    const s2 = signShare('agent', A.secretKey, MSG, { signerSet: none, t: 1 });
    expect(verifyThreshold({ shares: [s2] }, MSG, none, 1)).toEqual({ ok: true, count: 1, roles: ['agent'] });
  });
  it.each([
    ['different pq_pk', { pq_pk: pk1 }, { pq_pk: pk2 }],
    ['pq_pk then none', { pq_pk: pk1 }, {}],
    ['none then pq_pk', {}, { pq_pk: pk1 }],
  ])('conflicting duplicate (%s) refuses the whole signer set, even with a valid share', (_n, a, b) => {
    const set: Signer[] = [{ role: 'agent', publicKey: aPub, ...a }, { role: 'agent', publicKey: aPub, ...b }];
    const good = signShare('agent', A.secretKey, MSG, { signerSet: [{ role: 'agent', publicKey: aPub }], t: 1 });
    expect(verifyThreshold({ shares: [good] }, MSG, set, 1)).toEqual({ ok: false, count: 0, roles: [], reason: 'malformed signer set (pq_pk)' });
  });
  it('a conflict is judged per (role, key): the same pq_pk under another role is not a duplicate', () => {
    const B = generateKeyPair();
    const set: Signer[] = [{ role: 'agent', publicKey: aPub, pq_pk: pk1 }, { role: 'guardian', publicKey: encodeKey(B.publicKey), pq_pk: pk1 }];
    const share = signShare('agent', A.secretKey, MSG, { signerSet: set, t: 1 }, HY);
    expect(verifyThreshold({ shares: [share] }, MSG, set, 1)).toEqual({ ok: true, count: 1, roles: ['agent'] });
  });
});

describe('R6-02: a role that registers a pq_pk must be satisfied by a PQ share', () => {
  const set: Signer[] = [{ role: 'agent', publicKey: aPub, pq_pk: pk1 }];
  it('hybrid share counts; an Ed25519-only share (even validly signed) does not', () => {
    const hy = signShare('agent', A.secretKey, MSG, { signerSet: set, t: 1 }, HY);
    expect(verifyThreshold({ shares: [hy] }, MSG, set, 1)).toEqual({ ok: true, count: 1, roles: ['agent'] });
    const ed = signShare('agent', A.secretKey, MSG, { signerSet: set, t: 1 });
    expect(verifyThreshold({ shares: [ed] }, MSG, set, 1)).toEqual({ ok: false, count: 0, roles: [], reason: 'invalid signature for role agent' });
  });
  it('a role with no registered pq_pk still accepts an Ed25519 share', () => {
    const plain: Signer[] = [{ role: 'agent', publicKey: aPub }];
    const ed = signShare('agent', A.secretKey, MSG, { signerSet: plain, t: 1 });
    expect(verifyThreshold({ shares: [ed] }, MSG, plain, 1)).toEqual({ ok: true, count: 1, roles: ['agent'] });
  });
});
