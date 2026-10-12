/**
 * A threshold share that names its own `pq_pk` must name exactly the key its role registers. A mismatch (even with a
 * signature valid under the registered key), a `pq_pk` on a share for a role that registers none, or a non-string value is a
 * typed refusal. Python, Go and Rust already refused the mismatch; TS ignored the field.
 */
import { describe, expect, it } from 'vitest';
import { b64u, utf8 } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';
import { signShare, verifyThreshold, type Signer } from './threshold';

const MSG = utf8('share-pq-pk');
const aMl = mlDsa65Keygen(new Uint8Array(32).fill(21));
const xMl = mlDsa65Keygen(new Uint8Array(32).fill(22));
const pqA = encodeMlDsaPublicKey(aMl.publicKey);
const pqX = encodeMlDsaPublicKey(xMl.publicKey);
const A = generateKeyPair(), G = generateKeyPair();
const aPub = encodeKey(A.publicKey), gPub = encodeKey(G.publicKey);
const SET: Signer[] = [{ role: 'agent', publicKey: aPub, pq_pk: pqA }, { role: 'guardian', publicKey: gPub }];
const HY = { alg: 'hybrid-ed25519-ml-dsa-65' as const, mlDsa: aMl };
const MISMATCH = (role: string) => ({ ok: false, count: 0, roles: [], reason: `share for role ${role} names a pq_pk that is not the key its role registers` });

describe('share pq_pk', () => {
  it('absent or equal to the registered key: counted', () => {
    const s = signShare('agent', A.secretKey, MSG, { signerSet: SET, t: 1 }, HY);
    expect(verifyThreshold({ shares: [s] }, MSG, SET, 1)).toEqual({ ok: true, count: 1, roles: ['agent'] });
    expect(verifyThreshold({ shares: [{ ...s, pq_pk: pqA }] }, MSG, SET, 1)).toEqual({ ok: true, count: 1, roles: ['agent'] });
  });
  it('a different pq_pk is refused even though the signatures verify under the registered key', () => {
    const s = signShare('agent', A.secretKey, MSG, { signerSet: SET, t: 1 }, HY);
    expect(verifyThreshold({ shares: [{ ...s, pq_pk: pqX }] }, MSG, SET, 1)).toEqual(MISMATCH('agent'));
    const pure = signShare('agent', A.secretKey, MSG, { signerSet: SET, t: 1 }, { alg: 'ml-dsa-65', mlDsa: aMl });
    expect(verifyThreshold({ shares: [{ ...pure, pq_pk: pqX }] }, MSG, SET, 1)).toEqual(MISMATCH('agent'));
  });
  it('a pq_pk on a share for a role that registers none, or a non-string pq_pk, is refused', () => {
    const g = signShare('guardian', G.secretKey, MSG, { signerSet: SET, t: 1 });
    expect(verifyThreshold({ shares: [g] }, MSG, SET, 1)).toEqual({ ok: true, count: 1, roles: ['guardian'] });
    expect(verifyThreshold({ shares: [{ ...g, pq_pk: pqA }] }, MSG, SET, 1)).toEqual(MISMATCH('guardian'));
    const s = signShare('agent', A.secretKey, MSG, { signerSet: SET, t: 1 }, HY);
    for (const v of [null, 5, '', b64u(new Uint8Array(3))]) expect(verifyThreshold({ shares: [{ ...s, pq_pk: v } as never] }, MSG, SET, 1)).toEqual(MISMATCH('agent'));
  });
  it('the refusal is reported for the first offending share; a later good share still counts', () => {
    const bad = { ...signShare('agent', A.secretKey, MSG, { signerSet: SET, t: 2 }, HY), pq_pk: pqX };
    const g = signShare('guardian', G.secretKey, MSG, { signerSet: SET, t: 2 });
    expect(verifyThreshold({ shares: [bad, g] }, MSG, SET, 2)).toEqual({ ok: false, count: 1, roles: ['guardian'], reason: 'share for role agent names a pq_pk that is not the key its role registers' });
  });
});
