import { createPrivateKey, sign as nodeSign } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import { DIRECTORY_CONTENT_TYPE, DIRECTORY_SIGNATURE_TAG, buildKeyDirectory, fetchKeyDirectory, parseKeyDirectory, signDirectoryResponse, verifyDirectoryResponse, type KeyDirectory } from './index';

const NOW = 1_800_000_000;
const AUTH = 'bots.example';
const k1 = generateKeyPair();
const k2 = generateKeyPair();
const dir = buildKeyDirectory([{ publicKey: k1.publicKey }, { publicKey: k2.publicKey }]);
const b64url = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const keyidOf = (s: { headers: Record<string, string> }) => /keyid="([^"]+)"/.exec(s.headers['signature-input']!)![1]!;
const signed1 = (over: Record<string, unknown> = {}) => signDirectoryResponse({ keys: [k1], directory: dir, authority: AUTH, created: NOW, ...over });
const verify = (s: { headers: Record<string, string>; body: string }, over: Record<string, unknown> = {}) => verifyDirectoryResponse({ authority: AUTH, headers: s.headers, body: s.body, now: NOW + 10, ...over });
const KID = keyidOf(signed1());

/** Hand-built signed response: an arbitrary parameter list signed over the draft's base string with k1. */
function forge(params: string, over: { label?: string; sigLabel?: string; sigBytes?: Buffer; body?: string } = {}) {
  const label = over.label ?? 'sig1';
  const base = `"@authority";req: ${AUTH}\n"@signature-params": ${params}`;
  const priv = createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', x: b64url(k1.publicKey), d: b64url(k1.secretKey) }, format: 'jwk' });
  const sig = over.sigBytes ?? nodeSign(null, Buffer.from(base), priv);
  return {
    body: over.body ?? JSON.stringify(dir),
    headers: { 'signature-input': `${label}=${params}`, signature: `${over.sigLabel ?? label}=:${sig.toString('base64')}:` },
  };
}
const P = (o: { created?: string; expires?: string; keyid?: string; alg?: string; tag?: string; extra?: string } = {}) => {
  const parts = ['("@authority";req)'];
  const add = (k: string, v: string | undefined, dflt: string | undefined) => {
    const val = v === undefined ? dflt : v;
    if (val !== '' && val !== undefined) parts.push(`${k}=${val}`);
  };
  add('created', o.created, String(NOW));
  add('expires', o.expires, String(NOW + 100));
  add('keyid', o.keyid, `"${KID}"`);
  add('alg', o.alg, '"ed25519"');
  add('tag', o.tag, `"${DIRECTORY_SIGNATURE_TAG}"`);
  return parts.join(';') + (o.extra ?? '');
};
const bad = (reason: string) => ({ valid: false, reason, keys: [] });

describe('signing output shape', () => {
  it('labels are sig1, sig2 in key order and nothing else is in the header', () => {
    const s = signDirectoryResponse({ keys: [k1, k2], directory: dir, authority: AUTH, created: NOW });
    expect(s.headers['signature-input']!.split(', ').map((e) => e.split('=')[0])).toEqual(['sig1', 'sig2']);
    expect(s.headers.signature!.split(', ').map((e) => e.split('=')[0])).toEqual(['sig1', 'sig2']);
  });
  it('an authority with a trailing or embedded foreign character is refused', () => {
    for (const a of ['bots.example/x', 'bots.example ', 'bots.example?x', 'bots.example!']) {
      expect(() => signDirectoryResponse({ keys: [k1], directory: dir, authority: a })).toThrow(/lower-case/);
    }
    expect(() => signDirectoryResponse({ keys: [k1], directory: dir, authority: '[::1]:8443' })).not.toThrow();
  });
  it('default created is the current time: sign with defaults, verify with defaults', () => {
    const s = signDirectoryResponse({ keys: [k1], directory: dir, authority: AUTH });
    const r = verifyDirectoryResponse({ authority: AUTH, headers: s.headers, body: s.body });
    expect(r.valid).toBe(true);
  });
});

describe('parseKeyDirectory strictness', () => {
  const x = b64url(k1.publicKey);
  const doc = (k: unknown) => JSON.stringify({ keys: [k] });
  const key = (o: Record<string, unknown> = {}) => ({ kty: 'OKP', crv: 'Ed25519', kid: 'a', x, ...o });
  const MSG = 'directory contains a malformed key';
  it('a null document has no keys', () => {
    expect(() => parseKeyDirectory('null')).toThrow(new Error('directory has no keys'));
  });
  it('a well-formed key passes', () => {
    expect(parseKeyDirectory(doc(key())).keys).toHaveLength(1);
  });
  it('null and scalar entries, and a non-string kid, are malformed', () => {
    for (const k of [null, 5, 'x', key({ kid: 5 }), key({ kid: '' }), key({ kty: 'EC' }), key({ crv: 'X25519' })]) expect(() => parseKeyDirectory(doc(k))).toThrow(new Error(MSG));
  });
  it('x must be exactly 43 base64url characters, anchored at both ends', () => {
    const missing = { kty: 'OKP', crv: 'Ed25519', kid: 'a' };
    for (const bx of [undefined, 5, ' ' + x, x + ' ', x + '=', x + '!', x.slice(1), x + 'A', 'AAAA']) {
      expect(() => parseKeyDirectory(doc(bx === undefined ? missing : key({ x: bx })))).toThrow(new Error(MSG));
    }
  });
  it('nbf and exp must be finite numbers when present', () => {
    expect(() => parseKeyDirectory(doc(key({ nbf: 'x' })))).toThrow(new Error(MSG));
    expect(() => parseKeyDirectory(doc(key({ exp: null })))).toThrow(new Error(MSG));
    expect(parseKeyDirectory(doc(key({ nbf: 1, exp: 2 }))).keys).toHaveLength(1);
  });
});

describe('verifyDirectoryResponse: header handling', () => {
  it('either header missing is refused with the same reason', () => {
    const s = signed1();
    const r = bad('missing signature-input or signature header');
    expect(verify({ ...s, headers: { signature: s.headers.signature! } })).toEqual(r);
    expect(verify({ ...s, headers: { 'signature-input': s.headers['signature-input']! } })).toEqual(r);
  });
  it('signature header entries are anchored at both ends', () => {
    const s = signed1();
    const sig = s.headers.signature!;
    expect(verify({ ...s, headers: { ...s.headers, signature: sig + 'junk' } })).toEqual(bad('malformed signature header'));
    expect(verify({ ...s, headers: { ...s.headers, signature: 'X' + sig } })).toEqual(bad('malformed signature header'));
    expect(verify({ ...s, headers: { ...s.headers, signature: 'garbage' } })).toEqual(bad('malformed signature header'));
  });
  it('a malformed signature-input entry has its own reason', () => {
    const s = signed1();
    expect(verify({ ...s, headers: { ...s.headers, 'signature-input': 'nonsense' } })).toEqual(bad('malformed signature-input entry (must cover exactly "@authority";req)'));
  });
  it('the signature is checked against the real default lifetime and an explicit one', () => {
    const long = signed1({ expiresInSec: 86_401 });
    expect(verify(long)).toEqual(bad('signature lifetime exceeds maxLifetimeSec'));
    expect(verify(signed1({ expiresInSec: 86_400 })).valid).toBe(true);
    const mid = signed1({ expiresInSec: 200 });
    expect(verify(mid, { maxLifetimeSec: 100 })).toEqual(bad('signature lifetime exceeds maxLifetimeSec'));
    expect(verify(mid, { maxLifetimeSec: 200 }).valid).toBe(true);
  });
});

describe('verifyDirectoryResponse: signature parameters', () => {
  it('the hand-built baseline verifies', () => {
    expect(verify(forge(P())).valid).toBe(true);
  });
  it('a repeated parameter is refused as a duplicate', () => {
    expect(verify(forge(P({ extra: `;created=${NOW}` })))).toEqual(bad('duplicate signature parameter'));
    expect(verify(forge(P({ extra: `;tag="${DIRECTORY_SIGNATURE_TAG}"` })))).toEqual(bad('duplicate signature parameter'));
  });
  it('a wrong tag, even a numeric one, is refused', () => {
    expect(verify(forge(P({ tag: '"web-bot-auth"' })))).toEqual(bad('wrong tag'));
    expect(verify(forge(P({ tag: '5' })))).toEqual(bad('wrong tag'));
    expect(verify(forge(P({ tag: '' })))).toEqual(bad('wrong tag'));
  });
  it('alg: absent is accepted, ed25519 is accepted, anything else is unsupported', () => {
    expect(verify(forge(P({ alg: '' }))).valid).toBe(true);
    expect(verify(forge(P({ alg: '"rsa-pss-sha512"' })))).toEqual(bad('unsupported alg'));
    expect(verify(forge(P({ alg: '5' })))).toEqual(bad('unsupported alg'));
  });
  it('created and expires are both required and must be bare integers', () => {
    const r = bad('created and expires are required');
    expect(verify(forge(P({ created: '' })))).toEqual(r);
    expect(verify(forge(P({ expires: '' })))).toEqual(r);
    expect(verify(forge(P({ created: '"5"' })))).toEqual(r);
    expect(verify(forge(P({ expires: `"${NOW + 100}"` })))).toEqual(r);
  });
  it('keyid must be a quoted string, present, and a directory key thumbprint', () => {
    expect(verify(forge(P({ keyid: '' })))).toEqual(bad('missing keyid'));
    expect(verify(forge(P({ keyid: '5' })))).toEqual(bad('missing keyid'));
    expect(verify(forge(P({ keyid: '"nope"' })))).toEqual(bad('keyid is not the thumbprint of any directory key'));
  });
  it('created may be at most now + skew; expires must be at least now - skew', () => {
    const at = (created: number, expires: number, over: Record<string, unknown>) => verify(forge(P({ created: String(created), expires: String(expires) })), { now: NOW, ...over });
    const future = bad('signature created-time is in the future');
    expect(at(NOW, NOW + 50, { clockSkewSec: 0 }).valid).toBe(true);
    expect(at(NOW + 1, NOW + 50, { clockSkewSec: 0 })).toEqual(future);
    expect(at(NOW + 5, NOW + 50, { clockSkewSec: 5 }).valid).toBe(true);
    expect(at(NOW + 1, NOW + 50, { clockSkewSec: 5 }).valid).toBe(true);
    expect(at(NOW + 6, NOW + 50, { clockSkewSec: 5 })).toEqual(future);

    const expired = bad('signature has expired');
    expect(at(NOW - 50, NOW, { clockSkewSec: 0 }).valid).toBe(true);
    expect(at(NOW - 50, NOW - 1, { clockSkewSec: 0 })).toEqual(expired);
    expect(at(NOW - 50, NOW - 5, { clockSkewSec: 5 }).valid).toBe(true);
    expect(at(NOW - 50, NOW - 1, { clockSkewSec: 5 }).valid).toBe(true);
    expect(at(NOW - 50, NOW - 6, { clockSkewSec: 5 })).toEqual(expired);
  });
  it('a signature entry without bytes for its label, or with the wrong length, is refused', () => {
    const none = bad('no valid signature bytes for the label');
    expect(verify(forge(P(), { sigLabel: 'sig2' }))).toEqual(none);
    expect(verify(forge(P(), { sigBytes: Buffer.alloc(63, 1) }))).toEqual(none);
    expect(verify(forge(P(), { sigBytes: Buffer.alloc(65, 1) }))).toEqual(none);
    expect(verify(forge(P(), { sigBytes: Buffer.alloc(64, 1) }))).toEqual(bad('signature does not verify'));
  });
});

describe('verifyDirectoryResponse: key validity window', () => {
  const NOWV = NOW + 100;
  const check = (win: { nbf?: number; exp?: number }, skew: number) => {
    const d: KeyDirectory = buildKeyDirectory([{ publicKey: k1.publicKey, ...win }]);
    const s = signDirectoryResponse({ keys: [k1], directory: d, authority: AUTH, created: NOW });
    return verify(s, { now: NOWV, clockSkewSec: skew });
  };
  const outside = bad('directory key is outside its validity window');
  it('nbf: a past nbf is fine, now + skew is the last accepted instant', () => {
    expect(check({ nbf: NOWV - 1000 }, 0).valid).toBe(true);
    expect(check({ nbf: NOWV }, 0).valid).toBe(true);
    expect(check({ nbf: NOWV + 1 }, 0)).toEqual(outside);
    expect(check({ nbf: NOWV + 5 }, 5).valid).toBe(true);
    expect(check({ nbf: NOWV + 6 }, 5)).toEqual(outside);
  });
  it('exp: a future exp is fine, now - skew is the last accepted instant', () => {
    expect(check({ exp: NOWV + 1000 }, 0).valid).toBe(true);
    expect(check({ exp: NOWV }, 0).valid).toBe(true);
    expect(check({ exp: NOWV - 1 }, 0)).toEqual(outside);
    expect(check({ exp: NOWV - 5 }, 5).valid).toBe(true);
    expect(check({ exp: NOWV - 6 }, 5)).toEqual(outside);
  });
  it('both nbf and exp in range pass', () => {
    expect(check({ nbf: NOWV - 10, exp: NOWV + 10 }, 0).valid).toBe(true);
  });
});

describe('fetchKeyDirectory', () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });
  const URL_ = `https://${AUTH}/.well-known/http-message-signatures-directory`;
  const body = JSON.stringify(dir);
  type Init = { redirect: 'error'; signal: AbortSignal; headers: Record<string, string> };
  const reply = (h: Record<string, string>, text = body, status = 200) => ({ status, headers: { get: (n: string) => h[n.toLowerCase()] ?? null }, text: async () => text });
  const okHeaders = { 'content-type': DIRECTORY_CONTENT_TYPE };

  it('https only; http needs the explicit flag and ftp is never allowed', async () => {
    const f = async () => reply(okHeaders);
    await expect(fetchKeyDirectory('http://bots.example/d', { fetch: f })).rejects.toThrow('directory URL must be https');
    await expect(fetchKeyDirectory('http://bots.example/d', { fetch: f, allowInsecureHttp: false })).rejects.toThrow('directory URL must be https');
    await expect(fetchKeyDirectory('ftp://bots.example/d', { fetch: f, allowInsecureHttp: true })).rejects.toThrow('directory URL must be https');
    expect((await fetchKeyDirectory('http://bots.example/d', { fetch: f, allowInsecureHttp: true })).keys).toHaveLength(2);
    expect((await fetchKeyDirectory(URL_, { fetch: f })).keys).toHaveLength(2);
  });
  it('sends no redirects and asks for the directory media type', async () => {
    let seen: { url: string; init: Init } | undefined;
    await fetchKeyDirectory(URL_, { fetch: async (url, init) => ((seen = { url, init }), reply(okHeaders)) });
    expect(seen!.url).toBe(URL_);
    expect(seen!.init.redirect).toBe('error');
    expect(seen!.init.headers).toEqual({ accept: 'application/http-message-signatures-directory+json' });
    expect(seen!.init.signal.aborted).toBe(false);
  });
  it('uses the global fetch by default', async () => {
    const g = vi.fn(async (_u: string, _i: Init) => reply(okHeaders));
    vi.stubGlobal('fetch', g);
    expect((await fetchKeyDirectory(URL_)).keys).toHaveLength(2);
    expect(g).toHaveBeenCalledTimes(1);
    expect(g.mock.calls[0]![0]).toBe(URL_);
    expect(g.mock.calls[0]![1].redirect).toBe('error');
  });
  it('a non-200 status is refused with the status in the message', async () => {
    await expect(fetchKeyDirectory(URL_, { fetch: async () => reply(okHeaders, body, 404) })).rejects.toThrow('directory fetch returned status 404');
  });
  it('content type: parameters and surrounding spaces are tolerated, anything else is refused', async () => {
    const ct = (v: string | undefined) => fetchKeyDirectory(URL_, { fetch: async () => reply(v === undefined ? {} : { 'content-type': v }) });
    expect((await ct(`${DIRECTORY_CONTENT_TYPE} ; charset=utf-8`)).keys).toHaveLength(2);
    expect((await ct(DIRECTORY_CONTENT_TYPE.toUpperCase())).keys).toHaveLength(2);
    await expect(ct('application/json')).rejects.toThrow('directory has the wrong content type');
    await expect(ct(undefined)).rejects.toThrow('directory has the wrong content type');
  });
  it('maxBytes is inclusive; the default limit is 65536 characters', async () => {
    const pad = (n: number) => body + ' '.repeat(n - body.length);
    const get = (text: string, maxBytes?: number) => fetchKeyDirectory(URL_, { fetch: async () => reply(okHeaders, text), ...(maxBytes !== undefined ? { maxBytes } : {}) });
    expect((await get(body, body.length)).keys).toHaveLength(2);
    await expect(get(body, body.length - 1)).rejects.toThrow('directory response is too large');
    expect((await get(pad(65536))).keys).toHaveLength(2);
    await expect(get(pad(65537))).rejects.toThrow('directory response is too large');
  });
  it('requireSignature with absent headers reports the missing headers (not a parse error)', async () => {
    const s = signed1();
    const only = (h: Record<string, string>) => fetchKeyDirectory(URL_, { fetch: async () => reply({ ...okHeaders, ...h }, s.body), requireSignature: true, now: NOW + 1 });
    const missing = 'directory signature: missing signature-input or signature header';
    await expect(only({})).rejects.toThrow(missing);
    await expect(only({ 'signature-input': s.headers['signature-input']! })).rejects.toThrow(missing);
    await expect(only({ signature: s.headers.signature! })).rejects.toThrow(missing);
    expect((await only(s.headers)).keys).toHaveLength(1);
  });
  it('requireSignature uses the real clock when no now is given', async () => {
    const s = signDirectoryResponse({ keys: [k1], directory: dir, authority: AUTH });
    const d = await fetchKeyDirectory(URL_, { fetch: async () => reply({ ...okHeaders, ...s.headers }, s.body), requireSignature: true });
    expect(d.keys).toHaveLength(1);
  });
  it('the timeout aborts the request (default 5000 ms, configurable)', async () => {
    vi.useFakeTimers();
    let signal!: AbortSignal;
    const hang = (_u: string, init: Init) =>
      new Promise<never>((_res, rej) => {
        signal = init.signal;
        init.signal.addEventListener('abort', () => rej(new Error('aborted')));
      });
    const a = expect(fetchKeyDirectory(URL_, { fetch: hang })).rejects.toThrow('aborted');
    await vi.advanceTimersByTimeAsync(4999);
    expect(signal.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(signal.aborted).toBe(true);
    await a;

    const b = expect(fetchKeyDirectory(URL_, { fetch: hang, timeoutMs: 100 })).rejects.toThrow('aborted');
    await vi.advanceTimersByTimeAsync(99);
    expect(signal.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(signal.aborted).toBe(true);
    await b;
  });
  it('the timer is cleared after success and after failure', async () => {
    vi.useFakeTimers();
    await fetchKeyDirectory(URL_, { fetch: async () => reply(okHeaders) });
    expect(vi.getTimerCount()).toBe(0);
    await expect(fetchKeyDirectory(URL_, { fetch: async () => reply(okHeaders, body, 500) })).rejects.toThrow();
    expect(vi.getTimerCount()).toBe(0);
  });
});
