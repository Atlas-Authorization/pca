/** Threshold residual mutants: suiteHasPq is total on an unknown suite (the leaf baseline reaches it with an unchecked alg). */
import { describe, expect, it } from 'vitest';
import { b64u, utf8 } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import { mlDsa65Keygen } from './pq';
import { verifyThreshold, type Signer } from './threshold';

const MSG = utf8('mk4');
const pk1 = b64u(mlDsa65Keygen(new Uint8Array(32).fill(9)).publicKey);
const A = generateKeyPair();
const aPub = encodeKey(A.publicKey);

describe('R6-02 baseline with an unknown leaf suite', () => {
  it('an agent registered with pq_pk and a leaf baseline naming an unknown alg fails closed without throwing', () => {
    const set: Signer[] = [{ role: 'agent', publicKey: aPub, pq_pk: pk1 }];
    for (const alg of ['no-such-suite', 42, null]) {
      const run = () => verifyThreshold({ shares: [] }, MSG, set, 1, { holder: aPub, sig: 'AAAA', alg });
      expect(run).not.toThrow();
      expect(run()).toEqual({ ok: false, count: 0, roles: [], reason: 'only 0 distinct valid key(s), need 1' });
    }
  });
});

describe('invalid t is rendered without stringifying containers', () => {
  it('null, an object and an array t name their kind exactly', () => {
    const set: Signer[] = [{ role: 'agent', publicKey: aPub }];
    expect(verifyThreshold({ shares: [] }, MSG, set, null as never).reason).toBe('invalid threshold t=null (must be 1, 2 or 3)');
    expect(verifyThreshold({ shares: [] }, MSG, set, {} as never).reason).toBe('invalid threshold t=<object> (must be 1, 2 or 3)');
    expect(verifyThreshold({ shares: [] }, MSG, set, [[2]] as never).reason).toBe('invalid threshold t=<array> (must be 1, 2 or 3)');
  });
});
