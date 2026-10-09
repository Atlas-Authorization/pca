/**
 * Official RFC 9449 (DPoP) example vectors, loaded from fixtures/rfc9449.json (provenance recorded in
 * that file). The RFC publishes no private key, so these are VERIFY-only vectors: they prove that an
 * independently produced ES256 proof is accepted, and that every tamper is rejected for a named reason.
 */
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { decodeProtectedHeader } from 'jose';
import type { JWK } from 'jose';
import { describe, expect, it } from 'vitest';
import { athFor, jwkThumbprint, verifyDpopProof } from './index';

interface Fixture {
  sha256_of_source: string;
  proofs: { fig2_token_request: string; fig7_refresh_request: string; fig13_resource_request: string };
  access_token_fig13: string;
  ath_fig14: string;
  jkt_section6: string;
  nonce_examples: string[];
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null;
}
function loadFixture(): Fixture {
  const raw: unknown = JSON.parse(readFileSync(resolve(__dirname, '..', 'fixtures', 'rfc9449.json'), 'utf8'));
  if (!isRecord(raw) || !isRecord(raw.proofs)) throw new Error('bad fixture');
  const { proofs } = raw;
  const str = (v: unknown): string => {
    if (typeof v !== 'string') throw new Error('bad fixture field');
    return v;
  };
  return {
    sha256_of_source: str(raw.sha256_of_source),
    proofs: {
      fig2_token_request: str(proofs.fig2_token_request),
      fig7_refresh_request: str(proofs.fig7_refresh_request),
      fig13_resource_request: str(proofs.fig13_resource_request),
    },
    access_token_fig13: str(raw.access_token_fig13),
    ath_fig14: str(raw.ath_fig14),
    jkt_section6: str(raw.jkt_section6),
    nonce_examples: Array.isArray(raw.nonce_examples) ? raw.nonce_examples.map(str) : [],
  };
}

const fx = loadFixture();
// The RFC examples carry iat in July 2019; pin "now" to the example time (RFC 9449 Fig. 2 iat = 1562262616).
const AT = 1562262616;

describe('RFC 9449 official proofs', () => {
  it('records the source digest', () => {
    expect(fx.sha256_of_source).toMatch(/^[0-9a-f]{64}$/);
  });

  it('accepts the Figure 2 / Figure 5 token-request proof and yields the §6 jkt', async () => {
    const r = await verifyDpopProof(fx.proofs.fig2_token_request, {
      method: 'POST',
      url: 'https://server.example.com/token',
      maxAgeSec: 300,
      nowSec: AT,
      expectedJkt: fx.jkt_section6,
    });
    expect(r.jkt).toBe(fx.jkt_section6);
    expect(r.claims.jti).toBe('-BwC3ESc6acc2lTc');
    expect(r.claims.htm).toBe('POST');
  });

  it('accepts the Figure 7 refresh-token proof', async () => {
    const r = await verifyDpopProof(fx.proofs.fig7_refresh_request, {
      method: 'POST',
      url: 'https://server.example.com/token',
      maxAgeSec: 300,
      nowSec: 1562265296,
    });
    expect(r.jkt).toBe(fx.jkt_section6);
  });

  it('accepts the Figure 13/14 resource proof with its access-token hash', async () => {
    const r = await verifyDpopProof(fx.proofs.fig13_resource_request, {
      method: 'GET',
      url: 'https://resource.example.org/protectedresource?x=1#f',
      maxAgeSec: 300,
      nowSec: 1562262618,
      accessToken: fx.access_token_fig13,
    });
    expect(r.claims.ath).toBe(fx.ath_fig14);
  });

  it('athFor reproduces the RFC Figure 14 ath digest', () => {
    expect(athFor(fx.access_token_fig13)).toBe(fx.ath_fig14);
  });

  it('jwkThumbprint reproduces the RFC §6 jkt for the example key', async () => {
    const h = decodeProtectedHeader(fx.proofs.fig2_token_request);
    expect(await jwkThumbprint(h.jwk as JWK)).toBe(fx.jkt_section6);
  });

  it('agrees with an independent verifier (node:crypto, no jose) on the RFC signatures', () => {
    for (const proof of Object.values(fx.proofs)) {
      const [h, p, s] = proof.split('.');
      const jwk = decodeProtectedHeader(proof).jwk as JWK;
      const key = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' });
      const ok = nodeVerify('sha256', Buffer.from(`${h}.${p}`), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(s ?? '', 'base64url'));
      expect(ok).toBe(true);
    }
  });
});

describe('RFC 9449 vectors, negative cases (reason asserted)', () => {
  const base = { method: 'POST', url: 'https://server.example.com/token', maxAgeSec: 300, nowSec: AT } as const;

  it('wrong method -> htm', async () => {
    await expect(verifyDpopProof(fx.proofs.fig2_token_request, { ...base, method: 'GET' })).rejects.toMatchObject({ code: 'htm' });
  });
  it('wrong URL -> htu', async () => {
    await expect(verifyDpopProof(fx.proofs.fig2_token_request, { ...base, url: 'https://evil.example.com/token' })).rejects.toMatchObject({ code: 'htu' });
  });
  it('stale -> iat_stale', async () => {
    await expect(verifyDpopProof(fx.proofs.fig2_token_request, { ...base, nowSec: AT + 301 })).rejects.toMatchObject({ code: 'iat_stale' });
  });
  it('future iat -> iat_future', async () => {
    await expect(verifyDpopProof(fx.proofs.fig2_token_request, { ...base, nowSec: AT - 60 })).rejects.toMatchObject({ code: 'iat_future' });
  });
  it('other key -> jkt', async () => {
    await expect(verifyDpopProof(fx.proofs.fig2_token_request, { ...base, expectedJkt: 'x'.repeat(43) })).rejects.toMatchObject({ code: 'jkt' });
  });
  it('flipped payload byte -> signature', async () => {
    const [h, p, s] = fx.proofs.fig2_token_request.split('.');
    const payload = JSON.parse(Buffer.from(p ?? '', 'base64url').toString('utf8')) as Record<string, unknown>;
    payload.htu = 'https://server.example.com/other';
    const forged = `${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${s}`;
    await expect(
      verifyDpopProof(forged, { ...base, url: 'https://server.example.com/other' }),
    ).rejects.toMatchObject({ code: 'signature' });
  });
  it('flipped signature byte -> signature', async () => {
    const parts = fx.proofs.fig2_token_request.split('.');
    const sig = Buffer.from(parts[2] ?? '', 'base64url');
    sig[0] = (sig[0] ?? 0) ^ 1;
    await expect(verifyDpopProof(`${parts[0]}.${parts[1]}.${sig.toString('base64url')}`, base)).rejects.toMatchObject({ code: 'signature' });
  });
  it('replayed jti -> jti_replay', async () => {
    const seen = new Set<string>();
    await verifyDpopProof(fx.proofs.fig2_token_request, { ...base, seenJti: seen });
    await expect(verifyDpopProof(fx.proofs.fig2_token_request, { ...base, seenJti: seen })).rejects.toMatchObject({ code: 'jti_replay' });
  });
  it('proof without the required nonce -> nonce (RFC 9449 §8)', async () => {
    await expect(verifyDpopProof(fx.proofs.fig2_token_request, { ...base, expectedNonce: fx.nonce_examples[0] ?? 'n' })).rejects.toMatchObject({ code: 'nonce' });
  });
  it('a different access token than the one hashed in ath -> ath (RFC 9449 §7.1)', async () => {
    await expect(
      verifyDpopProof(fx.proofs.fig13_resource_request, {
        method: 'GET',
        url: 'https://resource.example.org/protectedresource',
        maxAgeSec: 300,
        nowSec: 1562262618,
        accessToken: 'a-different-token',
      }),
    ).rejects.toMatchObject({ code: 'ath' });
  });
  it('proof with no ath but an access token presented -> ath', async () => {
    await expect(verifyDpopProof(fx.proofs.fig2_token_request, { ...base, accessToken: fx.access_token_fig13 })).rejects.toMatchObject({ code: 'ath' });
  });
});

describe('cross-implementation: PyJWT 2.10.1 (independent)', () => {
  function readProofs(name: string): Record<string, unknown> {
    const raw: unknown = JSON.parse(readFileSync(resolve(__dirname, '..', 'fixtures', name), 'utf8'));
    if (!isRecord(raw)) throw new Error('bad fixture');
    return raw;
  }
  const py = readProofs('pyjwt.json');

  it('accepts an Ed25519 proof produced by PyJWT', async () => {
    const r = await verifyDpopProof(String(py.ed25519), { method: 'GET', url: 'https://api.example.com/r', maxAgeSec: 60, nowSec: 1700000010 });
    expect(r.claims.jti).toBe('pyjwt-ed-1');
  });
  it('accepts an ES256 proof produced by PyJWT, with its nonce enforced', async () => {
    const opts = { method: 'POST', url: 'https://api.example.com/r', maxAgeSec: 60, nowSec: 1700000010 } as const;
    const r = await verifyDpopProof(String(py.es256), { ...opts, expectedNonce: 'srv-n' });
    expect(r.claims.nonce).toBe('srv-n');
    await expect(verifyDpopProof(String(py.es256), { ...opts, expectedNonce: 'other' })).rejects.toMatchObject({ code: 'nonce' });
  });
  it('the proof pca-dpop produced (verified by PyJWT in crosscheck/) still verifies, nonce and ath included', async () => {
    const ours = String(readProofs('ours.json').proof);
    const r = await verifyDpopProof(ours, { method: 'POST', url: 'https://server.example.com/token', maxAgeSec: 60, nowSec: 1700000001, expectedNonce: 'n-1' });
    expect(r.claims.ath).toBe('abc');
  });
});
