import { describe, expect, it } from 'vitest';
import { SignJWT, importJWK } from 'jose';
import { agent, b64u, generateKeyPair } from '@atlasauth/pca';
import { fromTransactionToken, toTransactionToken } from './index';

const TD = 'trust-domain.example';
const ACTION = { verb: 'stripe.refund', resource: 'charge:ch_1', aud: TD };
const tts = generateKeyPair();
const chain = () => agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['refund'] }, limits: { refund: '$5' }, aud: TD }).subAgent().chain;

async function settle(p: Promise<unknown>): Promise<{ ok: true } | { ok: false; message: string }> {
  try {
    await p;
    return { ok: true };
  } catch (e) {
    return { ok: false, message: (e as Error).message };
  }
}

describe('toTransactionToken draft-11 argument guards', () => {
  const base = { chain: chain(), action: ACTION, issuerKey: tts.secretKey, issuer: 'i', profile: 'draft-11' as const, scope: 's', reqWl: 'w' };
  it('an empty reqWl is refused', async () => {
    expect(await settle(toTransactionToken({ ...base, reqWl: '' }))).toEqual({ ok: false, message: 'toTransactionToken: draft-11 requires `reqWl`' });
  });
  it('a non-string trust domain is refused', async () => {
    expect(await settle(toTransactionToken({ ...base, trustDomain: 5 as never }))).toEqual({
      ok: false,
      message: 'toTransactionToken: draft-11 requires a non-empty trust domain (aud)',
    });
  });
});

describe('fromTransactionToken guards', () => {
  it('an empty audience is refused for draft-11', async () => {
    const jwt = await toTransactionToken({ chain: chain(), action: ACTION, issuerKey: tts.secretKey, issuer: 'i', profile: 'draft-11', scope: 's', reqWl: 'w' });
    expect(await settle(fromTransactionToken(jwt, tts.publicKey, { profile: 'draft-11', audience: '', replayCheck: 'unchecked' }))).toEqual({
      ok: false,
      message: 'fromTransactionToken: draft-11 requires opts.audience (the trust domain this verifier serves)',
    });
  });
  it('a non-string token is refused by the canonical-spelling gate', async () => {
    for (const bad of [undefined, null]) {
      expect(await settle(fromTransactionToken(bad as never, tts.publicKey, { profile: 'legacy', replayCheck: 'unchecked' }))).toEqual({
        ok: false,
        message: 'non-canonical compact JWS: not-a-string',
      });
    }
  });
  it('an empty transaction identifier is refused before the replay store is asked', async () => {
    const key = await importJWK({ kty: 'OKP', crv: 'Ed25519', x: b64u(tts.publicKey), d: b64u(tts.secretKey) }, 'EdDSA');
    const jwt = await new SignJWT({ sub: 'P', jti: '', tctx: { verb: 'v', resource: 'r', aud: 'a' } })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'txn_token+jwt' })
      .setExpirationTime(Math.floor(Date.now() / 1000) + 60)
      .sign(key);
    let asked = 0;
    const seenTxn = () => {
      asked += 1;
      return false;
    };
    expect(await settle(fromTransactionToken(jwt, tts.publicKey, { profile: 'legacy', seenTxn }))).toEqual({
      ok: false,
      message: 'transaction token: no transaction identifier to check for replay',
    });
    expect(asked).toBe(0);
  });
});
