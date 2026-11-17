import { SignJWT, generateKeyPair as joseGen } from 'jose';
import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { spiffeAdmissionEvidence } from './index';

const ID = 'spiffe://example.org/workload/db';
const throwing = (v: unknown) => ({ kind: 'x509' as const, get chain(): string { throw v; }, verify: {} }) as never;

describe('spiffeAdmissionEvidence', () => {
  it('admits a verified JWT-SVID bound by cnf.jwk to the instance key', async () => {
    const { privateKey, publicKey } = await joseGen('ES256');
    const key = b64u(generateKeyPair().publicKey);
    const sign = (cnf?: object) =>
      new SignJWT(cnf ? { cnf } : {}).setProtectedHeader({ alg: 'ES256' }).setSubject(ID).setAudience('a').setExpirationTime('1h').sign(privateKey);
    const verify = { trustDomain: 'example.org', audience: 'a', key: publicKey };
    const token = await sign({ jwk: { kty: 'OKP', crv: 'Ed25519', x: key } });
    expect(await spiffeAdmissionEvidence({ kind: 'jwt', token, verify }, key)).toEqual({ ok: true, bound: true, identity: { spiffe_id: ID } });
    const other = b64u(generateKeyPair().publicKey);
    expect(await spiffeAdmissionEvidence({ kind: 'jwt', token, verify }, other)).toEqual({ ok: false, bound: false, reason: 'holder_binding_failed' });
  });

  it('reports a thrown value by its string code, else the error name, else "error"', async () => {
    const key = b64u(generateKeyPair().publicKey);
    const reason = async (v: unknown) => spiffeAdmissionEvidence(throwing(v), key);
    expect(await reason({ code: 'c1' })).toEqual({ ok: false, bound: false, reason: 'c1' });
    expect(await reason(new TypeError('x'))).toEqual({ ok: false, bound: false, reason: 'TypeError' });
    expect(await reason(Object.assign(new Error('x'), { code: 5 }))).toEqual({ ok: false, bound: false, reason: 'Error' });
    expect(await reason({ code: 5 })).toEqual({ ok: false, bound: false, reason: 'error' });
    expect(await reason('str')).toEqual({ ok: false, bound: false, reason: 'error' });
    expect(await reason(null)).toEqual({ ok: false, bound: false, reason: 'error' });
  });
});
