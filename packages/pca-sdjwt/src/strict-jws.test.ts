import { compactJwsAliases } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { SignJWT, generateKeyPair, compactVerify } from 'jose';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { importJWK } from 'jose';
import { verifyPcaSdJwt } from './index';

describe('canonical-spelling gate (re-encoded token strings are rejected)', () => {
  it('rejects every re-encoding of the issuer JWT, the KB-JWT and the disclosures', async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA');
    const jwt = await new SignJWT({ iss: 'i', sub: 's' }).setProtectedHeader({ alg: 'EdDSA' }).setIssuedAt().sign(privateKey);
    const good = `${jwt}~`;
    expect((await verifyPcaSdJwt(good, { issuerKey: publicKey })).ok).toBe(true);
    const aliases = compactJwsAliases(jwt);
    // Sanity: jose alone accepts at least one alias (the very problem the gate fixes).
    const joseAccepts = await Promise.all(
      aliases.map((a) => compactVerify(a.token, publicKey).then(() => a.name, () => null)),
    );
    expect(joseAccepts.filter(Boolean).length).toBeGreaterThan(0);
    for (const a of aliases) {
      const res = await verifyPcaSdJwt(`${a.token}~`, { issuerKey: publicKey });
      expect(res.ok, a.name).toBe(false);
      if (!res.ok) expect(res.reason, a.name).toMatch(/non-canonical compact JWS/);
    }
    // empty disclosure segment alias
    const res = await verifyPcaSdJwt(`${jwt}~~`, { issuerKey: publicKey });
    expect(res.ok).toBe(false);
  });

  it('RFC 9901 presentation: KB-JWT and disclosure aliases are rejected, original passes', async () => {
    const fx = JSON.parse(readFileSync(resolve(__dirname, '..', 'fixtures', 'rfc9901.json'), 'utf8'));
    const v = fx.vectors[1];
    const issuerKey = await importJWK(fx.issuer_public_jwk, 'ES256');
    const opts = { issuerKey, algorithms: ['ES256'], kbAlgorithms: ['ES256'], now: 1748537250 * 1000, expectedKbAudience: v.kb.aud, expectedNonce: v.kb.nonce, requireKeyBinding: true };
    expect((await verifyPcaSdJwt(v.sd_jwt, opts)).ok).toBe(true);
    const segs = (v.sd_jwt as string).split('~');
    const kb = segs[segs.length - 1] as string;
    for (const a of compactJwsAliases(kb)) {
      const t = [...segs.slice(0, -1), a.token].join('~');
      expect((await verifyPcaSdJwt(t, opts)).ok, `kb ${a.name}`).toBe(false);
    }
    const withDisc = (d: string) => [segs[0], d, ...segs.slice(2)].join('~');
    for (const alias of [`${segs[1]}=`, ` ${segs[1]}`, `${segs[1]}\n`]) {
      expect((await verifyPcaSdJwt(withDisc(alias), opts)).ok, `disclosure ${JSON.stringify(alias.slice(-2))}`).toBe(false);
    }
    // malformed (4-element) disclosure
    const dup = Buffer.from('["salt","a",1,"a"]').toString('base64url');
    expect((await verifyPcaSdJwt(withDisc(dup), opts)).ok).toBe(false);
  });
});
