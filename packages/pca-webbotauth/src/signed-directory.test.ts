import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import { DIRECTORY_CONTENT_TYPE, DIRECTORY_SIGNATURE_TAG, buildKeyDirectory, fetchKeyDirectory, jwkThumbprint, parseKeyDirectory, signDirectoryResponse, verifyDirectoryResponse } from './index';

const NOW = 1_800_000_000;
const AUTH = 'bots.example';
const k1 = generateKeyPair();
const k2 = generateKeyPair();
const dir = buildKeyDirectory([{ publicKey: k1.publicKey }, { publicKey: k2.publicKey }]);
const signed = (over: Record<string, unknown> = {}) => signDirectoryResponse({ keys: [k1, k2], directory: dir, authority: AUTH, created: NOW, ...over });
const verify = (s: ReturnType<typeof signed>, over: Record<string, unknown> = {}) =>
  verifyDirectoryResponse({ authority: AUTH, headers: s.headers, body: s.body, now: NOW + 10, ...over });

describe('signed key directory (draft section 5.2)', () => {
  it('sign then verify: both keys come back, the signature covers @authority;req with the directory tag', () => {
    const s = signed();
    expect(s.headers['signature-input']).toContain('("@authority";req);created=1800000000;expires=1800086400;keyid="');
    expect(s.headers['signature-input']).toContain(`tag="${DIRECTORY_SIGNATURE_TAG}"`);
    const r = verify(s);
    expect(r.valid).toBe(true);
    expect(r.keys.map((k) => k.kid).sort()).toEqual(dir.keys.map((k) => k.kid).sort());
    expect(s.headers['content-type']).toBe(DIRECTORY_CONTENT_TYPE);
    expect(jwkThumbprint(k1.publicKey)).toBeTruthy();
  });
  it('only keys with a valid signature are returned (an unsigned key is ignored)', () => {
    const s = signDirectoryResponse({ keys: [k1], directory: dir, authority: AUTH, created: NOW });
    const r = verify(s);
    expect(r.valid && r.keys).toHaveLength(1);
    expect(r.valid && r.keys[0]!.x).toBe(dir.keys[0]!.x);
  });
  it('a different authority (replay at another host) is refused', () => {
    expect(verify(signed(), { authority: 'evil.example' })).toEqual({ valid: false, reason: 'signature does not verify', keys: [] });
  });
  it('a changed body (a swapped key) does not change what the signature vouches for: the extra key is dropped', () => {
    const s = signed();
    const evil = generateKeyPair();
    const swapped = JSON.stringify({ keys: [...dir.keys, ...buildKeyDirectory([{ publicKey: evil.publicKey }]).keys] });
    const r = verify({ ...s, body: swapped });
    expect(r.valid && r.keys.map((k) => k.x)).not.toContain(Buffer.from(evil.publicKey).toString('base64url'));
  });
  it.each([
    ['expired', { now: NOW + 86_401 }, 'signature has expired'],
    ['from the future', { now: NOW - 5 }, 'signature created-time is in the future'],
  ])('%s', (_n, over, reason) => {
    expect(verify(signed(), over)).toEqual({ valid: false, reason, keys: [] });
  });
  it('a lifetime above maxLifetimeSec is refused', () => {
    expect(verify(signed({ expiresInSec: 200_000 }), { maxLifetimeSec: 86_400, now: NOW + 5 })).toEqual({ valid: false, reason: 'signature lifetime exceeds maxLifetimeSec', keys: [] });
  });
  it('missing headers, garbage headers, a wrong tag, a missing expires and a foreign keyid are refused with exact reasons', () => {
    const s = signed();
    expect(verify({ ...s, headers: {} })).toEqual({ valid: false, reason: 'missing signature-input or signature header', keys: [] });
    expect(verify({ ...s, headers: { ...s.headers, signature: 'garbage' } })).toEqual({ valid: false, reason: 'malformed signature header', keys: [] });
    expect(verify({ ...s, headers: { ...s.headers, 'signature-input': s.headers['signature-input']!.replaceAll(DIRECTORY_SIGNATURE_TAG, 'web-bot-auth') } }).valid).toBe(false);
    expect(verify({ ...s, headers: { ...s.headers, 'signature-input': s.headers['signature-input']!.replaceAll(/;expires=\d+/g, '') } })).toEqual({ valid: false, reason: 'created and expires are required', keys: [] });
    const foreign = signDirectoryResponse({ keys: [k1], directory: dir, authority: AUTH, created: NOW });
    const fi = foreign.headers['signature-input']!.replace(/keyid="[^"]+"/, 'keyid="nope"');
    expect(verify({ ...foreign, headers: { ...foreign.headers, 'signature-input': fi } })).toEqual({ valid: false, reason: 'keyid is not the thumbprint of any directory key', keys: [] });
  });
  it('a signature that covers anything other than @authority;req is refused', () => {
    const s = signed();
    const si = s.headers['signature-input']!.replaceAll('("@authority";req)', '("@authority")');
    expect(verify({ ...s, headers: { ...s.headers, 'signature-input': si } }).valid).toBe(false);
  });
  it('a key outside its nbf/exp window is dropped', () => {
    const windowed = buildKeyDirectory([{ publicKey: k1.publicKey, exp: NOW + 5 }]);
    const s = signDirectoryResponse({ keys: [k1], directory: windowed, authority: AUTH, created: NOW });
    expect(verify(s, { now: NOW + 10 })).toEqual({ valid: false, reason: 'directory key is outside its validity window', keys: [] });
  });
  it('an invalid directory body is refused', () => {
    const s = signed();
    expect(verify({ ...s, body: '{"keys":[]}' })).toEqual({ valid: false, reason: 'verification failed (fail closed): directory has no keys', keys: [] });
  });
  it('signing refuses no keys, a key not in the directory, and a malformed authority', () => {
    expect(() => signDirectoryResponse({ keys: [], directory: dir, authority: AUTH })).toThrow(/at least one/);
    expect(() => signDirectoryResponse({ keys: [generateKeyPair()], directory: dir, authority: AUTH })).toThrow(/not in the directory/);
    expect(() => signDirectoryResponse({ keys: [k1], directory: dir, authority: 'Bots.Example' })).toThrow(/lower-case/);
  });
  it('parseKeyDirectory is the strict parser fetchKeyDirectory uses', () => {
    expect(parseKeyDirectory(JSON.stringify(dir))).toEqual(dir);
    expect(() => parseKeyDirectory('{"keys":[{"kty":"RSA"}]}')).toThrow('directory contains a malformed key');
  });
});

describe('fetchKeyDirectory({ requireSignature })', () => {
  const URL_ = `https://${AUTH}/.well-known/http-message-signatures-directory`;
  const respond = (s: ReturnType<typeof signed>, extra: Record<string, string> = {}) => async () => ({
    status: 200,
    headers: { get: (n: string) => ({ 'content-type': DIRECTORY_CONTENT_TYPE, ...s.headers, ...extra } as Record<string, string>)[n.toLowerCase()] ?? null },
    text: async () => s.body,
  });
  it('returns only the verified keys', async () => {
    const s = signDirectoryResponse({ keys: [k2], directory: dir, authority: AUTH, created: NOW });
    const d = await fetchKeyDirectory(URL_, { fetch: respond(s), requireSignature: true, now: NOW + 1 });
    expect(d.keys.map((k) => k.x)).toEqual([dir.keys[1]!.x]);
  });
  it('throws when the response is unsigned, or signed for another host', async () => {
    const s = signed();
    await expect(fetchKeyDirectory(URL_, { fetch: respond({ ...s, headers: {} as never }, { 'signature-input': '', signature: '' }), requireSignature: true, now: NOW + 1 })).rejects.toThrow('directory signature: missing signature-input or signature header');
    const other = signDirectoryResponse({ keys: [k1], directory: dir, authority: 'other.example', created: NOW });
    await expect(fetchKeyDirectory(URL_, { fetch: respond(other), requireSignature: true, now: NOW + 1 })).rejects.toThrow('directory signature: signature does not verify');
  });
  it('without requireSignature the signature is not consulted (unchanged behaviour)', async () => {
    const s = signed();
    expect((await fetchKeyDirectory(URL_, { fetch: respond(s) })).keys).toHaveLength(2);
  });
});
