import { describe, expect, it } from 'vitest';
import { importJWK } from 'jose';
import { agent, generateKeyPair, type Agent } from '@atlasauth/pca';
import {
  actDepth,
  fromTransactionToken,
  subActChain,
  toTransactionToken,
  type TxnAction,
} from './index';

/** A 3-hop chain: principal -> holder0 (root grant) -> holder1 (sub) -> holder2 (sub). */
function threeHopAgent(): Agent {
  const principal = generateKeyPair();
  const root = agent({
    principal,
    goal: 'reconcile refunds for October',
    permissions: { stripe: ['refund'], gmail: ['send'] },
    limits: { refund: '$500/day' },
    aud: 'https://api.acme.com',
  });
  return root.subAgent().subAgent();
}

const ACTION: TxnAction = { verb: 'stripe.refund', resource: 'charge:ch_123', aud: 'https://api.acme.com' };

describe('subActChain (RFC 8693 §4.1 nested act)', () => {
  it('sub is the root principal; act descends one level per delegation hop', () => {
    const a = threeHopAgent();
    const claim = subActChain(a.chain);

    // sub = root principal (chain[0].issuer)
    expect(claim.sub).toBe(a.chain[0]!.issuer);
    // act.sub = chain[0].holder, act.act.sub = chain[1].holder, act.act.act.sub = chain[2].holder
    expect(claim.act?.sub).toBe(a.chain[0]!.holder);
    expect(claim.act?.act?.sub).toBe(a.chain[1]!.holder);
    expect(claim.act?.act?.act?.sub).toBe(a.chain[2]!.holder);
    expect(claim.act?.act?.act?.act).toBeUndefined();
  });

  it('nesting depth == delegation depth (chain length)', () => {
    const two = agent({
      principal: generateKeyPair(),
      goal: 'g',
      permissions: { stripe: ['refund'] },
      aud: 'https://api.acme.com',
    }).subAgent();
    const three = threeHopAgent();

    expect(two.chain.length).toBe(2);
    expect(actDepth(subActChain(two.chain))).toBe(2);
    expect(three.chain.length).toBe(3);
    expect(actDepth(subActChain(three.chain))).toBe(3);
  });

  it('a single-hop (root only) chain has act depth 1', () => {
    const one = agent({
      principal: generateKeyPair(),
      goal: 'g',
      permissions: { stripe: ['refund'] },
      aud: 'https://api.acme.com',
    });
    expect(one.chain.length).toBe(1);
    const claim = subActChain(one.chain);
    expect(claim.sub).toBe(one.chain[0]!.issuer);
    expect(claim.act?.sub).toBe(one.chain[0]!.holder);
    expect(actDepth(claim)).toBe(1);
  });

  it('throws on an empty chain', () => {
    expect(() => subActChain([])).toThrow(/non-empty/);
  });
});

describe('toTransactionToken / fromTransactionToken round-trip', () => {
  it('recovers the chain of custody and the tctx with a valid signature (raw Ed25519 keys)', async () => {
    const a = threeHopAgent();
    const tts = generateKeyPair(); // Transaction Token Service signing key

    const jwt = await toTransactionToken({
      chain: a.chain,
      action: ACTION,
      issuerKey: tts.secretKey,
      issuer: 'https://tts.acme.com',
    });
    expect(jwt.split('.')).toHaveLength(3);

    const { chain, action, claims } = await fromTransactionToken(jwt, tts.publicKey);

    // chain of custody round-trips byte-for-byte with subActChain
    expect(chain).toEqual(subActChain(a.chain));
    expect(actDepth(chain)).toBe(a.chain.length);
    // transaction context recovered
    expect(action).toEqual(ACTION);
    // standard claims present
    expect(claims.iss).toBe('https://tts.acme.com');
    expect(claims.sub).toBe(a.chain[0]!.issuer);
    expect(claims.aud).toBe(ACTION.aud);
    expect(typeof claims.jti).toBe('string');
    expect(typeof claims.iat).toBe('number');
    expect(typeof claims.exp).toBe('number');
    expect(claims.exp! - claims.iat!).toBe(120); // default ttl
  });

  it('honors a custom ttlSec', async () => {
    const a = threeHopAgent();
    const tts = generateKeyPair();
    const jwt = await toTransactionToken({
      chain: a.chain,
      action: ACTION,
      issuerKey: tts.secretKey,
      issuer: 'iss',
      ttlSec: 30,
    });
    const { claims } = await fromTransactionToken(jwt, tts.publicKey);
    expect(claims.exp! - claims.iat!).toBe(30);
  });

  it('rejects a token verified with the WRONG key', async () => {
    const a = threeHopAgent();
    const tts = generateKeyPair();
    const attacker = generateKeyPair();
    const jwt = await toTransactionToken({
      chain: a.chain,
      action: ACTION,
      issuerKey: tts.secretKey,
      issuer: 'iss',
    });
    await expect(fromTransactionToken(jwt, attacker.publicKey)).rejects.toThrow();
  });

  it('rejects a TAMPERED token (payload edited)', async () => {
    const a = threeHopAgent();
    const tts = generateKeyPair();
    const jwt = await toTransactionToken({
      chain: a.chain,
      action: ACTION,
      issuerKey: tts.secretKey,
      issuer: 'iss',
    });
    const [h, p, s] = jwt.split('.');
    const decoded = JSON.parse(Buffer.from(p!, 'base64url').toString('utf8')) as Record<string, unknown>;
    (decoded.tctx as TxnAction).resource = 'charge:ch_EVIL';
    const forgedPayload = Buffer.from(JSON.stringify(decoded), 'utf8').toString('base64url');
    const tampered = `${h}.${forgedPayload}.${s}`;
    await expect(fromTransactionToken(tampered, tts.publicKey)).rejects.toThrow();
  });

  it('round-trips with a pre-imported jose key as well', async () => {
    const a = threeHopAgent();
    const tts = generateKeyPair();
    const priv = await importJWK(
      {
        kty: 'OKP',
        crv: 'Ed25519',
        x: Buffer.from(tts.publicKey).toString('base64url'),
        d: Buffer.from(tts.secretKey).toString('base64url'),
      },
      'EdDSA',
    );
    const pub = await importJWK(
      { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(tts.publicKey).toString('base64url') },
      'EdDSA',
    );
    const jwt = await toTransactionToken({ chain: a.chain, action: ACTION, issuerKey: priv, issuer: 'iss' });
    const { action } = await fromTransactionToken(jwt, pub);
    expect(action).toEqual(ACTION);
  });

  it('rejects a bad raw key length', async () => {
    const a = threeHopAgent();
    await expect(
      toTransactionToken({ chain: a.chain, action: ACTION, issuerKey: new Uint8Array(16), issuer: 'iss' }),
    ).rejects.toThrow(/32 bytes/);
  });
});
