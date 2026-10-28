import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { verifyIdJag, IdJagVerificationError } from './index';

// Independent cross-check. fixtures/python-vectors.json is produced by crosscheck/crosscheck.py (hand-assembled JWS,
// no JOSE library, deterministic Ed25519). The same script verifies the tokens this test writes when PCA_CROSSCHECK_OUT is set.

interface Vector {
  name: string;
  token: string;
  expect: 'ok' | 'refuse';
  code?: string;
  grant?: Record<string, unknown>;
}
const fixture = JSON.parse(readFileSync(resolve(__dirname, '..', 'fixtures', 'python-vectors.json'), 'utf8')) as {
  issuer: string;
  audience: string;
  clientId: string;
  publicKey: string;
  vectors: Vector[];
};
const jwk = { kty: 'OKP', crv: 'Ed25519', x: fixture.publicKey };
const opts = () => ({
  issuer: fixture.issuer,
  audience: fixture.audience,
  clientId: fixture.clientId,
  key: jwk as never,
  consumeJti: () => true,
});

describe('python-signed ID-JAGs (independent producer), strict draft mode', () => {
  it('the fixture covers every outcome class', () => {
    expect(fixture.vectors.length).toBe(15);
    expect(fixture.vectors.filter((v) => v.expect === 'ok').length).toBe(1);
  });
  for (const v of fixture.vectors) {
    it(`python vector: ${v.name}`, async () => {
      const r = await verifyIdJag(v.token, opts()).then(
        (g) => ({ outcome: 'ok' as const, g }),
        (e: unknown) => ({ outcome: 'refuse' as const, code: e instanceof IdJagVerificationError ? e.code : 'other' }),
      );
      if (v.expect === 'refuse') {
        expect(r.outcome).toBe('refuse');
        if (v.code !== undefined) expect(r).toEqual({ outcome: 'refuse', code: v.code });
      } else {
        expect(r.outcome).toBe('ok');
        const g = (r as { g: Record<string, unknown> }).g;
        expect({ iss: g.iss, sub: g.sub, agent: g.agent, audience: g.audience, scopes: g.scopes, iat: g.iat, exp: g.exp, jti: g.jti }).toEqual(v.grant);
      }
    });
  }
});

describe('package-minted ID-JAGs for the python verifier', () => {
  it('mints strict-shape grants, verifies them, and writes them when PCA_CROSSCHECK_OUT is set', async () => {
    const kp = await generateKeyPair('EdDSA', { extractable: true });
    const pubJwk = await exportJWK(kp.publicKey);
    const now = Math.floor(Date.now() / 1000);
    const tokens: string[] = [];
    for (const scope of ['a', 'a b c']) {
      const jwt = await new SignJWT({ iss: fixture.issuer, sub: 'user-1', aud: fixture.audience, iat: now, exp: now + 300, jti: `j-${scope.length}`, client_id: fixture.clientId, act: { sub: 'agent-1' }, scope })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'oauth-id-jag+jwt' }).sign(kp.privateKey);
      const g = await verifyIdJag(jwt, { ...opts(), key: kp.publicKey });
      expect(g.scopes).toEqual(scope.split(' '));
      tokens.push(jwt);
    }
    const out = process.env.PCA_CROSSCHECK_OUT;
    if (out) {
      mkdirSync(dirname(out), { recursive: true });
      writeFileSync(out, JSON.stringify({ publicKey: pubJwk.x, tokens }));
    }
  });
});
