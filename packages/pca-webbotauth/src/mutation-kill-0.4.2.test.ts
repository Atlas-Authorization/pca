/** 0.4.2 mutation kills: Content-Digest parser / verifier reasons and boundaries; the derived @path of a path-less URL. */
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import { contentDigestHeader, parseContentDigest, signRequest, verifyContentDigest } from './index';

const BODY = '{"hello": "world"}';
const D256 = createHash('sha256').update(BODY).digest();
const B256 = D256.toString('base64');
const B512 = createHash('sha512').update(BODY).digest('base64');

describe('contentDigestHeader / parseContentDigest: exact refusals', () => {
  it('no algorithm named', () => {
    expect(() => contentDigestHeader(BODY, [])).toThrow('contentDigestHeader: name at least one algorithm');
  });
  it('an empty member (a trailing or doubled comma) is refused as such', () => {
    expect(() => parseContentDigest(`sha-256=:${B256}:,`)).toThrow('empty dictionary member');
    expect(() => parseContentDigest(`sha-256=:${B256}:, ,sha-512=:${B512}:`)).toThrow('empty dictionary member');
  });
  it('a member must match the whole grammar (anchored at the start; the message quotes the member)', () => {
    expect(() => parseContentDigest(`Ysha-256=:${B256}:`)).toThrow(`malformed Content-Digest member "Ysha-256=:${B256}:"`);
    expect(() => parseContentDigest('sha-256=AAAA')).toThrow('malformed Content-Digest member "sha-256=AAAA"');
    expect(() => parseContentDigest(`sha-256=:${B256}:;x=1`)).toThrow('malformed Content-Digest member');
  });
  it('base64 must be canonical: a length that is not a multiple of 4, and non-zero padding bits', () => {
    expect(() => parseContentDigest('sha-256=:AAA:')).toThrow('member "sha-256" is not canonical base64');
    expect(() => parseContentDigest('sha-256=:AB==:')).toThrow('member "sha-256" is not canonical base64');
    expect(parseContentDigest('sha-256=:AA==:').get('sha-256')).toEqual(new Uint8Array([0]));
  });
  it('one algorithm twice is ambiguous', () => {
    expect(() => parseContentDigest(`sha-256=:${B256}:, sha-256=:${B256}:`)).toThrow('member "sha-256" appears twice');
  });
});

describe('verifyContentDigest: reasons and comparison', () => {
  it('a missing, empty or blank field is "missing Content-Digest"', () => {
    for (const h of [undefined, '', '   ', '\t']) expect(verifyContentDigest(h, BODY)).toEqual({ valid: false, reason: 'missing Content-Digest' });
  });
  it('a mismatch names the algorithm', () => {
    expect(verifyContentDigest(`sha-256=:${Buffer.alloc(32).toString('base64')}:`, BODY)).toEqual({ valid: false, reason: 'sha-256 digest does not match the content' });
    expect(verifyContentDigest(`sha-512=:${Buffer.alloc(64).toString('base64')}:`, BODY)).toEqual({ valid: false, reason: 'sha-512 digest does not match the content' });
  });
  it('a digest that is a strict PREFIX of the real one does not match (length is compared)', () => {
    const prefix = D256.subarray(0, 24).toString('base64');
    expect(verifyContentDigest(`sha-256=:${prefix}:`, BODY)).toEqual({ valid: false, reason: 'sha-256 digest does not match the content' });
    const longer = Buffer.concat([D256, Buffer.alloc(3)]).toString('base64');
    expect(verifyContentDigest(`sha-256=:${longer}:`, BODY).valid).toBe(false);
  });
  it('a malformed field carries the parser message', () => {
    expect(verifyContentDigest('sha-256=AAAA', BODY)).toEqual({ valid: false, reason: 'malformed Content-Digest: malformed Content-Digest member "sha-256=AAAA"' });
  });
  it('required algorithms: present passes, absent is refused with its name', () => {
    const h = `sha-256=:${B256}:`;
    expect(verifyContentDigest(h, BODY, { require: ['sha-256'] })).toEqual({ valid: true, matched: ['sha-256'] });
    expect(verifyContentDigest(h, BODY, { require: ['sha-512'] })).toEqual({ valid: false, reason: 'required sha-512 digest is absent' });
    expect(verifyContentDigest(h, BODY, { require: [] })).toEqual({ valid: true, matched: ['sha-256'] });
  });
  it('only unsupported members: no supported algorithm', () => {
    expect(verifyContentDigest('md5=:AAAA:', BODY)).toEqual({ valid: false, reason: 'no supported digest algorithm (sha-256 or sha-512)' });
  });
});

describe('derived components of a URL with an empty path', () => {
  it('@path of "foo://host" is "/", so it signs exactly like "foo://host/"', () => {
    const key = generateKeyPair();
    const s = (url: string) => signRequest({ method: 'GET', url, key, keyid: 'k1', created: 1_800_000_000 });
    expect(s('foo://host').signature).toBe(s('foo://host/').signature);
  });
});

describe('@request-target of a URL with an empty path', () => {
  it('is "/" (so it signs exactly like "foo://host/")', () => {
    const key = generateKeyPair();
    const s = (url: string) => signRequest({ method: 'GET', url, key, keyid: 'k1', created: 1_800_000_000, components: ['@authority', '@method', '@request-target'] });
    expect(s('foo://host').signature).toBe(s('foo://host/').signature);
  });
});
