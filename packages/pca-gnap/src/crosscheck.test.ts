import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { generateKeyPair, b64u } from '@atlasauth/pca';
import { signGnapRequest, verifyGnapRequest } from './index';

// Independent cross-check: fixtures/python-vectors.json is produced by crosscheck/crosscheck.py (hand-assembled detached
// JWS, no JOSE library). The script also verifies the requests this test signs when PCA_CROSSCHECK_OUT is set.

interface Vector {
  name: string;
  detachedJws: string;
  body: unknown;
  expect: 'ok' | 'refuse';
  accessTokenValue?: string;
}
const fixture = JSON.parse(readFileSync(resolve(__dirname, '..', 'fixtures', 'python-vectors.json'), 'utf8')) as {
  now: number;
  uri: string;
  htm: string;
  publicKey: string;
  vectors: Vector[];
};

describe('python-signed jwsd requests (independent producer)', () => {
  it('the fixture covers both outcome classes', () => {
    expect(fixture.vectors.length).toBe(18);
    expect(fixture.vectors.filter((v) => v.expect === 'ok').length).toBe(5);
  });
  for (const v of fixture.vectors) {
    it(`python vector: ${v.name}`, async () => {
      const r = await verifyGnapRequest({
        detachedJws: v.detachedJws, body: v.body, holder: fixture.publicKey, htm: fixture.htm, uri: fixture.uri,
        now: fixture.now * 1000, replayCheck: 'unchecked',
        ...(v.accessTokenValue !== undefined ? { accessTokenValue: v.accessTokenValue } : {}),
      });
      expect(r.ok).toBe(v.expect === 'ok');
      if (r.ok) expect(r.holder).toBe(fixture.publicKey);
    });
  }
});

describe('package-signed jwsd requests for the python verifier', () => {
  it('signs, verifies, and writes them when PCA_CROSSCHECK_OUT is set', async () => {
    const k = generateKeyPair();
    const items: Array<{ detachedJws: string; body: unknown }> = [];
    const bodies = [{ a: 1 }, { z: ['x', 2, { k: 'v' }], a: 'b' }, { access_token: { access: [{ type: 'repo', actions: ['read'] }] } }];
    for (const body of bodies) {
      const s = await signGnapRequest({ body, key: k, htm: 'post', uri: fixture.uri, created: fixture.now });
      const r = await verifyGnapRequest({ detachedJws: s.detachedJws, body, holder: s.holder, htm: 'POST', uri: fixture.uri, now: fixture.now * 1000, replayCheck: 'unchecked' });
      expect(r.ok).toBe(true);
      items.push({ detachedJws: s.detachedJws, body });
    }
    const out = process.env.PCA_CROSSCHECK_OUT;
    if (out) {
      mkdirSync(dirname(out), { recursive: true });
      writeFileSync(out, JSON.stringify({ publicKey: b64u(k.publicKey), items }));
    }
  });
});
