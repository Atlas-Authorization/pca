/**
 * Official RFC 9901 (SD-JWT) example vectors from fixtures/rfc9901.json (provenance in that file).
 * Every SD-JWT / SD-JWT+KB printed in the RFC is verified under the RFC's own Appendix A.5 issuer key,
 * and tamper cases assert the failure reason.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { SignJWT, generateKeyPair, importJWK } from 'jose';
import type { JWK, KeyLike } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { present, verifyPcaSdJwt } from './index';

interface Vec {
  id: string;
  context_line_in_rfc: string;
  sd_jwt: string;
  kb: { aud: string; nonce: string; iat: number } | null;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
const rawFx: unknown = JSON.parse(readFileSync(resolve(__dirname, '..', 'fixtures', 'rfc9901.json'), 'utf8'));
if (!isRecord(rawFx) || !Array.isArray(rawFx.vectors)) throw new Error('bad fixture');
const vectors: Vec[] = rawFx.vectors.map((v: unknown) => {
  if (!isRecord(v) || typeof v.sd_jwt !== 'string' || typeof v.id !== 'string') throw new Error('bad vector');
  const kb = isRecord(v.kb) ? { aud: String(v.kb.aud), nonce: String(v.kb.nonce), iat: Number(v.kb.iat) } : null;
  return { id: v.id, context_line_in_rfc: String(v.context_line_in_rfc), sd_jwt: v.sd_jwt, kb };
});
const issuerJwk = rawFx.issuer_public_jwk as JWK;
const expected52 = rawFx.section_5_2_processed_payload_expected;

// 5.2 presentation is vector 1; its KB-JWT iat is 1748537244.
const NOW_MS = 1748537250 * 1000;
let issuerKey: KeyLike;
beforeAll(async () => {
  issuerKey = (await importJWK(issuerJwk, 'ES256')) as KeyLike;
});

const common = () => ({ issuerKey, algorithms: ['ES256'], kbAlgorithms: ['ES256'], now: NOW_MS });

describe('RFC 9901: every example SD-JWT in the document', () => {
  it('has the expected number of vectors', () => {
    expect(vectors.length).toBe(8);
  });

  for (const idx of [0, 1, 2, 3, 4, 5, 6, 7]) {
    it(`verifies vector v${idx}`, async () => {
      const v = vectors[idx];
      if (v === undefined) throw new Error('missing vector');
      const res = await verifyPcaSdJwt(v.sd_jwt, {
        ...common(),
        ...(v.kb ? { expectedKbAudience: v.kb.aud, expectedNonce: v.kb.nonce, requireKeyBinding: true, kbMaxAgeSec: 60 } : {}),
      });
      if (!res.ok) throw new Error(`${v.id} (${v.context_line_in_rfc}): ${res.reason}`);
      expect(res.keyBinding.verified).toBe(v.kb !== null);
    });
  }

  it('reproduces the RFC 5.2 Processed SD-JWT Payload exactly', async () => {
    const v = vectors[1];
    if (v === undefined || v.kb === null) throw new Error('missing vector');
    const res = await verifyPcaSdJwt(v.sd_jwt, { ...common(), expectedKbAudience: v.kb.aud, expectedNonce: v.kb.nonce, requireKeyBinding: true });
    if (!res.ok) throw new Error(res.reason);
    expect(res.processed).toEqual(expected52);
  });

  it('recovers nested object and array-element disclosures from the full issuance (5.1)', async () => {
    const v = vectors[0];
    if (v === undefined) throw new Error('missing vector');
    const res = await verifyPcaSdJwt(v.sd_jwt, common());
    if (!res.ok) throw new Error(res.reason);
    expect(res.processed.nationalities).toEqual(['US', 'DE']);
    expect(res.processed.address).toEqual({ street_address: '123 Main St', locality: 'Anytown', region: 'Anystate', country: 'US' });
    expect(res.processed.given_name).toBe('John');
  });

  it('present() on the full RFC issuance yields an SD-JWT the verifier accepts', async () => {
    const v = vectors[0];
    if (v === undefined) throw new Error('missing vector');
    const pres = await present(v.sd_jwt, ['given_name']);
    const res = await verifyPcaSdJwt(pres, common());
    if (!res.ok) throw new Error(res.reason);
    expect(res.disclosed).toEqual({ given_name: 'John' });
  });
});

describe('RFC 9901 vectors: tamper cases assert the reason', () => {
  const v1 = (): Vec => {
    const v = vectors[1];
    if (v === undefined || v.kb === null) throw new Error('missing vector');
    return v;
  };
  const kbOpts = () => ({ ...common(), expectedKbAudience: v1().kb?.aud ?? '', expectedNonce: v1().kb?.nonce ?? '', requireKeyBinding: true });

  it('wrong issuer key -> signature failure', async () => {
    const other = (await importJWK({ ...issuerJwk, x: 'TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc', y: 'ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ' }, 'ES256')) as KeyLike;
    const res = await verifyPcaSdJwt(v1().sd_jwt, { ...kbOpts(), issuerKey: other });
    expect(res).toMatchObject({ ok: false });
    expect(!res.ok && res.reason).toMatch(/signature/i);
  });

  it('wrong KB nonce -> nonce mismatch', async () => {
    const res = await verifyPcaSdJwt(v1().sd_jwt, { ...kbOpts(), expectedNonce: 'other' });
    expect(res).toEqual({ ok: false, reason: 'KB-JWT nonce does not match' });
  });

  it('wrong KB audience -> claim failure naming aud', async () => {
    const res = await verifyPcaSdJwt(v1().sd_jwt, { ...kbOpts(), expectedKbAudience: 'https://evil.example' });
    expect(!res.ok && res.reason).toMatch(/aud/);
  });

  it('KB-JWT too old -> window failure', async () => {
    const res = await verifyPcaSdJwt(v1().sd_jwt, { ...kbOpts(), kbMaxAgeSec: 1, now: (1748537244 + 100) * 1000 });
    expect(res).toEqual({ ok: false, reason: 'KB-JWT is older than the accepted window' });
  });

  it('splicing a not-yet-presented disclosure into the presentation -> sd_hash mismatch', async () => {
    const full = (vectors[0]?.sd_jwt ?? '').split('~');
    const email = full[3] ?? ''; // "email" disclosure, not in the 5.2 presentation
    const kbJwt = v1().sd_jwt.split('~').pop() ?? '';
    const head = v1().sd_jwt.slice(0, v1().sd_jwt.length - kbJwt.length);
    const res = await verifyPcaSdJwt(`${head}${email}~${kbJwt}`, kbOpts());
    expect(res).toEqual({ ok: false, reason: 'KB-JWT sd_hash does not cover this presentation' });
  });

  it('dropping the KB-JWT when binding is required -> required', async () => {
    const parts = v1().sd_jwt.split('~');
    parts.pop();
    const res = await verifyPcaSdJwt(`${parts.join('~')}~`, kbOpts());
    expect(res).toEqual({ ok: false, reason: 'key binding required but no KB-JWT was presented' });
  });

  it('a disclosure from a different credential -> not matched', async () => {
    const other = (vectors[4]?.sd_jwt ?? '').split('~')[1] ?? '';
    const parts = (vectors[0]?.sd_jwt ?? '').split('~');
    const res = await verifyPcaSdJwt(`${parts[0]}~${other}~`, common());
    expect(res).toEqual({ ok: false, reason: 'a presented disclosure does not match any _sd digest (tampered)' });
  });

  it('the same disclosure presented twice -> duplicate', async () => {
    const parts = (vectors[0]?.sd_jwt ?? '').split('~');
    const res = await verifyPcaSdJwt(`${parts[0]}~${parts[1]}~${parts[1]}~`, common());
    expect(res).toEqual({ ok: false, reason: 'duplicate disclosure' });
  });

  it('a flipped byte in the issuer payload -> signature failure', async () => {
    const parts = (vectors[0]?.sd_jwt ?? '').split('~');
    const jwt = (parts[0] ?? '').split('.');
    const body = Buffer.from(jwt[1] ?? '', 'base64url').toString('utf8').replace('user_42', 'user_43');
    const forged = `${jwt[0]}.${Buffer.from(body).toString('base64url')}.${jwt[2]}`;
    const res = await verifyPcaSdJwt([forged, ...parts.slice(1)].join('~'), common());
    expect(!res.ok && res.reason).toMatch(/signature/i);
  });

  it('expired credential -> exp failure', async () => {
    const res = await verifyPcaSdJwt(vectors[0]?.sd_jwt ?? '', { ...common(), now: 1990000000 * 1000 });
    expect(!res.ok && res.reason).toMatch(/exp/);
  });

  it('refuses an algorithm outside the allow-list', async () => {
    const res = await verifyPcaSdJwt(vectors[0]?.sd_jwt ?? '', { ...common(), algorithms: ['EdDSA'] });
    expect(!res.ok && res.reason).toMatch(/alg/i);
  });
});

describe('present() over RFC nested structures', () => {
  it('selecting an array claim discloses its elements; selecting address discloses the object', async () => {
    const full = vectors[0]?.sd_jwt ?? '';
    const pres = await present(full, ['nationalities', 'address']);
    const res = await verifyPcaSdJwt(pres, common());
    if (!res.ok) throw new Error(res.reason);
    expect(res.processed.nationalities).toEqual(['US', 'DE']);
    expect(res.processed.address).toEqual({ street_address: '123 Main St', locality: 'Anytown', region: 'Anystate', country: 'US' });
    expect(res.processed.given_name).toBeUndefined();
  });
});

// ---- processing rules (RFC 9901 section 7.1) exercised with credentials built by this test, NOT RFC vectors ----
describe('RFC 9901 section 7.1 processing rules (locally built credentials)', () => {
  const dig = (e: string): string => createHash('sha256').update(e, 'ascii').digest().toString('base64url');
  const disc = (...parts: unknown[]): string => Buffer.from(JSON.stringify(parts)).toString('base64url');
  async function build(payload: Record<string, unknown>, disclosures: string[]): Promise<{ sd: string; key: KeyLike }> {
    const { privateKey, publicKey } = await generateKeyPair('EdDSA', { extractable: true });
    const jwt = await new SignJWT({ iss: 'https://i.example', ...payload }).setProtectedHeader({ alg: 'EdDSA', typ: 'dc+sd-jwt' }).sign(privateKey);
    return { sd: `${jwt}~${disclosures.map((d) => `${d}~`).join('')}`, key: publicKey };
  }

  it('resolves recursive disclosures (a digest inside another disclosure)', async () => {
    const inner = disc('s2', 'zip', '12345');
    const outer = disc('s1', 'address', { _sd: [dig(inner)], city: 'X' });
    const { sd, key } = await build({ _sd: [dig(outer)], _sd_alg: 'sha-256' }, [outer, inner]);
    const res = await verifyPcaSdJwt(sd, { issuerKey: key });
    if (!res.ok) throw new Error(res.reason);
    expect(res.processed.address).toEqual({ city: 'X', zip: '12345' });
  });

  it('treats a missing _sd_alg as sha-256 (RFC default)', async () => {
    const d = disc('s', 'a', 1);
    const { sd, key } = await build({ _sd: [dig(d)] }, [d]);
    expect((await verifyPcaSdJwt(sd, { issuerKey: key })).ok).toBe(true);
  });

  it('rejects an unsupported _sd_alg', async () => {
    const d = disc('s', 'a', 1);
    const { sd, key } = await build({ _sd: [dig(d)], _sd_alg: 'sha-512' }, [d]);
    expect(await verifyPcaSdJwt(sd, { issuerKey: key })).toEqual({ ok: false, reason: 'unsupported _sd_alg (require "sha-256")' });
  });

  it('rejects a disclosure whose name collides with a clear claim', async () => {
    const d = disc('s', 'role', 'admin');
    const { sd, key } = await build({ role: 'user', _sd: [dig(d)] }, [d]);
    const res = await verifyPcaSdJwt(sd, { issuerKey: key });
    expect(!res.ok && res.reason).toMatch(/collides/);
  });

  it('rejects reserved disclosure names _sd and ...', async () => {
    for (const name of ['_sd', '...']) {
      const d = disc('s', name, 'x');
      const { sd, key } = await build({ _sd: [dig(d)] }, [d]);
      const res = await verifyPcaSdJwt(sd, { issuerKey: key });
      expect(!res.ok && res.reason).toMatch(/reserved/);
    }
  });

  it('rejects a security-critical claim (exp) behind a disclosure', async () => {
    const d = disc('s', 'exp', 99999999999);
    const { sd, key } = await build({ _sd: [dig(d)] }, [d]);
    const res = await verifyPcaSdJwt(sd, { issuerKey: key });
    expect(!res.ok && res.reason).toMatch(/security-critical/);
  });

  it('rejects the same digest listed twice in the payload', async () => {
    const d = disc('s', 'a', 1);
    const { sd, key } = await build({ _sd: [dig(d), dig(d)] }, [d]);
    expect(await verifyPcaSdJwt(sd, { issuerKey: key })).toEqual({ ok: false, reason: 'a digest appears more than once in the payload' });
  });

  it('rejects an array-entry disclosure with three elements, and an object disclosure with two', async () => {
    const three = disc('s', 'n', 'v');
    const a = await build({ list: [{ '...': dig(three) }] }, [three]);
    expect((await verifyPcaSdJwt(a.sd, { issuerKey: a.key })).ok).toBe(false);
    const two = disc('s', 'v');
    const b = await build({ _sd: [dig(two)] }, [two]);
    expect((await verifyPcaSdJwt(b.sd, { issuerKey: b.key })).ok).toBe(false);
  });

  it('accepts decoy digests and removes undisclosed array elements', async () => {
    const e = disc('s', 'DE');
    const { sd, key } = await build({ _sd: ['decoy-digest-not-a-disclosure'], list: [{ '...': dig(e) }, { '...': 'another-decoy' }, 'US'] }, [e]);
    const res = await verifyPcaSdJwt(sd, { issuerKey: key });
    if (!res.ok) throw new Error(res.reason);
    expect(res.processed.list).toEqual(['DE', 'US']);
  });
});

describe('cross-implementation: credentials issued by @sd-jwt/core (independent library)', () => {
  const raw: unknown = JSON.parse(readFileSync(resolve(__dirname, '..', 'fixtures', 'sd-jwt-js.json'), 'utf8'));
  if (!isRecord(raw)) throw new Error('bad fixture');
  const kbInfo = raw.presentation_kb as { aud: string; nonce: string; iat: number };

  it('verifies a nested/array SD-JWT and an SD-JWT+KB presentation issued by @sd-jwt/core', async () => {
    const key = (await importJWK(raw.issuer_public_jwk as JWK, 'ES256')) as KeyLike;
    const opts = { issuerKey: key, algorithms: ['ES256'], kbAlgorithms: ['ES256'], now: (kbInfo.iat + 10) * 1000 };
    const full = await verifyPcaSdJwt(String(raw.issued), opts);
    if (!full.ok) throw new Error(full.reason);
    expect(full.processed.nationalities).toEqual(['GB', 'FR', 'US']);
    const res = await verifyPcaSdJwt(String(raw.presentation), { ...opts, expectedKbAudience: kbInfo.aud, expectedNonce: kbInfo.nonce, requireKeyBinding: true });
    if (!res.ok) throw new Error(res.reason);
    expect(res.processed.given_name).toBe('Ada');
    expect(res.processed.family_name).toBeUndefined();
    expect(res.processed.address).toEqual({ city: 'London', zip: 'N1' });
    expect(res.processed.nationalities).toEqual(['GB', 'FR']); // index 1 is in the clear, index 2 withheld
    expect(res.keyBinding.verified).toBe(true);
  });
});
