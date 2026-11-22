import { createPrivateKey, sign as nodeSign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import { buildKeyDirectory, memoryReplayCache, signDirectoryResponse, verifyDirectoryResponse, verifySignedRequest, type VerifyOptions } from './index';

const BAD = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY];
const kp = generateKeyPair();
const KID = 'k1';
const NOW = 1_800_000_000;
const URL1 = 'https://example.com/a/b';
const STD = ['"@authority": example.com', '"@method": GET', '"@path": /a/b'];
const STD_LIST = '("@authority" "@method" "@path")';
const b64url = (u: Uint8Array) => Buffer.from(u).toString('base64url');
function forge(params: string) {
  const jwk = { kty: 'OKP', crv: 'Ed25519', x: b64url(kp.publicKey), d: b64url(kp.secretKey) };
  const sig = nodeSign(null, Buffer.from([...STD, `"@signature-params": ${params}`].join('\n')), createPrivateKey({ key: jwk, format: 'jwk' })).toString('base64');
  return { 'signature-input': `sig1=${params}`, signature: `sig1=:${sig}:` };
}
const vr = (headers: Record<string, string>, opts: Partial<VerifyOptions> = {}) =>
  verifySignedRequest({ method: 'GET', url: URL1, headers }, { resolveKey: (id) => (id === KID ? kp.publicKey : null), now: NOW, ...opts });
const withExpires = forge(`${STD_LIST};created=${NOW};keyid="${KID}";alg="ed25519";expires=${NOW + 100};tag="web-bot-auth"`);
const noExpires = forge(`${STD_LIST};created=${NOW};keyid="${KID}";alg="ed25519";tag="web-bot-auth"`);

describe('memoryReplayCache with a non-finite clock never re-admits a live claim', () => {
  // pre-fix: `existing >= NaN` was false, so the live claim read as expired and was claimable again
  it.each(BAD)('nowSec of %s', (bad) => {
    const c = memoryReplayCache();
    expect(c.claim('a', 10, 5)).toBe(true);
    expect(c.claim('a', 10, bad)).toBe(false);
  });
});

describe('verifySignedRequest with a non-finite clock or skew never admits', () => {
  it('a finite clock admits both signatures', async () => {
    expect((await vr(withExpires)).valid).toBe(true);
    expect((await vr(noExpires, { requireExpires: false })).valid).toBe(true);
  });
  // pre-fix: `now > expires + skew` was false for a NaN clock
  it.each(BAD)('with expires, now of %s', async (now) => {
    expect((await vr(withExpires, { now })).valid).toBe(false);
  });
  // `created > now + skew` and the maxAgeSec comparison were also false for NaN (fixed in the same batch)
  it('without expires, now of NaN is refused as a future created-time', async () => {
    expect(await vr(noExpires, { requireExpires: false, now: Number.NaN })).toMatchObject({ valid: false, reason: 'signature created-time is in the future' });
  });
  it('without expires, clockSkewSec of NaN is refused', async () => {
    expect((await vr(noExpires, { requireExpires: false, clockSkewSec: Number.NaN })).valid).toBe(false);
  });
  it('maxAgeSec check with a NaN clock is refused', async () => {
    expect((await vr(noExpires, { requireExpires: false, maxAgeSec: 100, now: Number.NaN })).valid).toBe(false);
  });
});

describe('verifyDirectoryResponse with a non-finite clock or skew never admits', () => {
  const k1 = generateKeyPair();
  const dir = buildKeyDirectory([{ publicKey: k1.publicKey }]);
  const s = signDirectoryResponse({ keys: [k1], directory: dir, authority: 'bots.example', created: NOW });
  const verify = (over: Record<string, unknown>) => verifyDirectoryResponse({ authority: 'bots.example', headers: s.headers, body: s.body, now: NOW + 10, ...over });
  it('a finite clock admits', () => {
    expect(verify({}).valid).toBe(true);
  });
  // pre-fix: `created > now + skew` and `now > expires + skew` were false for a NaN operand
  it.each(BAD)('now of %s', (now) => {
    expect(verify({ now }).valid).toBe(false);
  });
  it('clockSkewSec of NaN', () => {
    expect(verify({ clockSkewSec: Number.NaN }).valid).toBe(false);
  });
});

describe('an infinite skew or expiry never admits (webbotauth)', () => {
  // old code: `now <= expires + Infinity` and `created <= now + Infinity` were true for any clock
  it.each([Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('clockSkewSec of %s refuses an expired signature', async (clockSkewSec) => {
    expect((await vr(withExpires, { now: NOW + 100_000, clockSkewSec })).valid).toBe(false);
    expect((await vr(noExpires, { requireExpires: false, now: NOW - 100_000, clockSkewSec })).valid).toBe(false);
    expect((await vr(noExpires, { requireExpires: false, maxAgeSec: 10, now: NOW + 100_000, clockSkewSec })).valid).toBe(false);
  });
  it('directory: clockSkewSec of an infinity refuses an expired response', () => {
    const k1 = generateKeyPair();
    const s = signDirectoryResponse({ keys: [k1], directory: buildKeyDirectory([{ publicKey: k1.publicKey }]), authority: 'bots.example', created: NOW });
    for (const clockSkewSec of [Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expect(verifyDirectoryResponse({ authority: 'bots.example', headers: s.headers, body: s.body, now: NOW + 1_000_000, clockSkewSec }).valid).toBe(false);
    }
  });
  it('a replay cache refuses an infinite expiry or clock', () => {
    const c = memoryReplayCache();
    expect(c.claim('a', Number.POSITIVE_INFINITY, 5)).toBe(false);
    expect(c.claim('b', 10, 5)).toBe(true);
    expect(c.claim('b', 10, Number.POSITIVE_INFINITY)).toBe(false); // old code: `10 < Infinity` re-admitted the live claim
  });
});
