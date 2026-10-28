/**
 * Round-2: the ledger claimed "jose only verifies an Ed25519 OKP key under alg EdDSA". jose 5.10 also accepts the
 * fully-specified alg identifier "Ed25519" (RFC 9864), so a detached JWS whose header says alg "Ed25519" verifies in
 * jose; the explicit `header.alg !== 'EdDSA'` check is what refuses it.
 */
import { FlattenedSign, importJWK } from 'jose';
import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import { gnapContentDigest, grantRequestToCapability, resolveHolder, signGnapRequest, verifyGnapRequest as verifyGnapRequestReal } from './index';

// verifyGnapRequest requires a replay store by default; these older tests are about the other checks, so the explicit
// opt-out is pinned once here. draft-replay.test.ts covers the replay requirement itself.
const verifyGnapRequest = (a: Parameters<typeof verifyGnapRequestReal>[0]) => verifyGnapRequestReal({ replayCheck: 'unchecked', ...a });


const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');

describe('r2: jwsd alg must be exactly EdDSA', () => {
  it('a detached JWS with alg "Ed25519" (same key, valid signature) is refused', async () => {
    const key = generateKeyPair();
    const body = { a: 1 };
    const now = 1_700_000_000_000;
    const created = Math.floor(now / 1000);
    const good = await signGnapRequest({ body, key, htm: 'POST', uri: 'https://as/x', created });
    const base = { body, holder: good.holder, htm: 'POST', uri: 'https://as/x', now };
    expect((await verifyGnapRequest({ ...base, detachedJws: good.detachedJws })).ok).toBe(true);
    const sk = await importJWK({ kty: 'OKP', crv: 'Ed25519', x: good.holder, d: b64u(key.secretKey) }, 'EdDSA');
    const payload = gnapContentDigest(body);
    let jws;
    try {
      jws = await new FlattenedSign(payload).setProtectedHeader({ alg: 'Ed25519', typ: 'gnap-binding-jwsd', htm: 'POST', uri: 'https://as/x', created }).sign(sk);
    } catch {
      return; // this jose build does not know "Ed25519": nothing to refuse
    }
    const r = await verifyGnapRequest({ ...base, detachedJws: `${jws.protected}..${jws.signature}` });
    expect(r.ok).toBe(false);
  });
});

describe('supported subset: only the jwsd client key proof method', () => {
  const kp = generateKeyPair();
  const x = b64u(kp.publicKey);
  const mk = (proof: unknown) => ({ access_token: { access: [{ type: 'repo' }] }, client: { key: { ...(proof === undefined ? {} : { proof }), jwk: { kty: 'OKP', crv: 'Ed25519', x } } } }) as never;
  const settle = (f: () => unknown): string => { try { f(); return 'ok'; } catch (e) { return (e as Error).message; } };
  it('accepts jwsd (string or {method})', () => {
    expect(settle(() => resolveHolder(mk('jwsd')))).toBe('ok');
    expect(settle(() => resolveHolder(mk({ method: 'jwsd' })))).toBe('ok');
  });
  it('refuses httpsig, mtls, jwsd-vc, unknown, missing and malformed methods, even with a holder override', () => {
    const msg = (m: string) => `unsupported client key proof method: ${m} (only jwsd is supported)`;
    for (const [p, m] of [['httpsig', 'httpsig'], ['mtls', 'mtls'], ['jwsd-vc', 'jwsd-vc'], ['JWSD', 'JWSD'], [undefined, 'none'], [5, 'none'], [{ method: 'httpsig' }, 'httpsig'], [{}, 'none']] as const) {
      expect(settle(() => resolveHolder(mk(p)))).toBe(msg(m));
      expect(settle(() => resolveHolder(mk(p), x))).toBe(msg(m));
    }
  });
  it('grantRequestToCapability refuses an httpsig-declared client', () => {
    const p = generateKeyPair();
    expect(settle(() => grantRequestToCapability(mk('httpsig'), { issuerSecret: p.secretKey, issuerPublic: b64u(p.publicKey) }))).toBe('unsupported client key proof method: httpsig (only jwsd is supported)');
  });
});
