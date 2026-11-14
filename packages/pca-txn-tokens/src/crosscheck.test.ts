import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { agent, b64u, generateKeyPair } from '@atlasauth/pca';
import { fromTransactionToken, toTransactionToken } from './index';

// Independent cross-check. fixtures/python-vectors.json is produced by crosscheck/crosscheck.py (a hand-assembled JWS,
// no JOSE library, deterministic Ed25519). The same script verifies the tokens this test writes when
// PCA_CROSSCHECK_OUT is set. See the package README (Cross-check) for the commands.

interface Vector {
  name: string;
  token: string;
  expect: 'ok' | 'refuse';
  tctx?: unknown;
  action?: unknown;
  chain?: unknown;
}
const fixture = JSON.parse(readFileSync(resolve(__dirname, '..', 'fixtures', 'python-vectors.json'), 'utf8')) as {
  now: number;
  trustDomain: string;
  publicKey: string;
  vectors: Vector[];
};
const publicKey = new Uint8Array(Buffer.from(fixture.publicKey, 'base64url'));
const opts = { audience: fixture.trustDomain, now: new Date(fixture.now * 1000), replayCheck: 'unchecked' as const };

describe('python-signed Transaction Tokens (independent producer)', () => {
  it('the fixture covers every outcome class', () => {
    expect(fixture.vectors.length).toBe(12);
    expect(fixture.vectors.filter((v) => v.expect === 'ok').length).toBe(2);
    expect(publicKey.length).toBe(32);
  });
  for (const v of fixture.vectors) {
    it(`python vector: ${v.name}`, async () => {
      const r = await fromTransactionToken(v.token, publicKey, opts).then(
        (ok) => ({ outcome: 'ok' as const, tctx: ok.tctx, action: ok.action ?? null, chain: ok.chain }),
        () => ({ outcome: 'refuse' as const }),
      );
      if (v.expect === 'refuse') {
        expect(r).toEqual({ outcome: 'refuse' });
      } else {
        expect(r).toEqual({ outcome: 'ok', tctx: v.tctx, action: v.action, chain: v.chain });
      }
    });
  }
});

describe('package-minted Transaction Tokens for the python verifier', () => {
  it('mints draft-11 tokens, verifies them, and writes them for crosscheck.py when PCA_CROSSCHECK_OUT is set', async () => {
    const tts = generateKeyPair();
    const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['refund'] }, aud: fixture.trustDomain });
    const tokens: string[] = [];
    for (const chain of [a.chain, a.subAgent().chain, a.subAgent().subAgent().chain]) {
      const jwt = await toTransactionToken({
        chain, action: { verb: 'stripe.refund', resource: 'charge:1', aud: fixture.trustDomain }, issuerKey: tts.secretKey,
        issuer: 'https://tts.example', scope: 'refund', reqWl: 'gw.example',
      });
      const back = await fromTransactionToken(jwt, tts.publicKey, { audience: fixture.trustDomain, replayCheck: 'unchecked' });
      expect(back.action).toEqual({ verb: 'stripe.refund', resource: 'charge:1', aud: fixture.trustDomain });
      tokens.push(jwt);
    }
    expect(tokens.length).toBe(3);
    const out = process.env.PCA_CROSSCHECK_OUT;
    if (out) {
      mkdirSync(dirname(out), { recursive: true });
      writeFileSync(out, JSON.stringify({ publicKey: b64u(tts.publicKey), tokens }));
    }
  });
});
