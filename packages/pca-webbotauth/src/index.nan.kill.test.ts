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
  it.each(BAD.slice(0, 1).concat(BAD[2]!))('nowSec of %s', (bad) => {
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
  // an unbounded skew or window admits any time, so neither ever admits
  it('with expires, clockSkewSec of +Infinity', async () => {
    expect((await vr(withExpires, { now: NOW + 10_000, clockSkewSec: Number.POSITIVE_INFINITY })).valid).toBe(false);
  });
  it('without expires, clockSkewSec of +Infinity', async () => {
    expect((await vr(noExpires, { requireExpires: false, clockSkewSec: Number.POSITIVE_INFINITY })).valid).toBe(false);
  });
  it('maxAgeSec of +Infinity', async () => {
    expect((await vr(noExpires, { requireExpires: false, maxAgeSec: Number.POSITIVE_INFINITY, now: NOW + 10_000 })).valid).toBe(false);
  });
  // no created and no expires: the freshness checks are skipped, and only a maxLifetimeSec of Infinity lets the request on; the maxAgeSec
  // check does not apply to an absent created (it must not read it as a number)
  const noTimes = forge(`${STD_LIST};keyid="${KID}";alg="ed25519";tag="web-bot-auth"`);
  it('an absent created is not aged against maxAgeSec', async () => {
    expect((await vr(noTimes, { requireExpires: false, maxLifetimeSec: Number.POSITIVE_INFINITY, maxAgeSec: 100 })).valid).toBe(true);
  });
  describe('a key validity window is enforced against a non-finite clock or skew even when the freshness checks were skipped', () => {
    const vj = (win: { nbf?: number; exp?: number }, over: Partial<VerifyOptions> = {}) =>
      verifySignedRequest({ method: 'GET', url: URL1, headers: noTimes }, { jwks: buildKeyDirectory([{ publicKey: kp.publicKey, keyid: KID, ...win }]), now: NOW, requireExpires: false, maxLifetimeSec: Number.POSITIVE_INFINITY, ...over });
    it('a key without a window is admitted', async () => {
      expect((await vj({})).valid).toBe(true);
    });
    it('clockSkewSec of +Infinity refuses an expired key and a not-yet-valid key', async () => {
      expect((await vj({ exp: NOW - 1000 }, { clockSkewSec: Number.POSITIVE_INFINITY })).valid).toBe(false);
      expect((await vj({ nbf: NOW + 1000 }, { clockSkewSec: Number.POSITIVE_INFINITY })).valid).toBe(false);
    });
    it('a clock of -Infinity refuses an expired key and +Infinity a not-yet-valid key', async () => {
      expect((await vj({ exp: NOW - 1000 }, { now: Number.NEGATIVE_INFINITY })).valid).toBe(false);
      expect((await vj({ nbf: NOW + 1000 }, { now: Number.POSITIVE_INFINITY })).valid).toBe(false);
    });
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
  it('clockSkewSec of +Infinity', () => {
    expect(verify({ now: NOW + 100_000, clockSkewSec: Number.POSITIVE_INFINITY }).valid).toBe(false);
  });
});
