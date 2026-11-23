import { describe, expect, it } from 'vitest';
import { checkPcaGrantPresentation, isHttpsUrl, parsePcaGrantDetails, pcaChainDigest, validatePcaGrantDetail, type PcaGrantDetail } from './pca-grant-details';

const mk = (over: Record<string, unknown> = {}) => ({ type: 'pca_grant', chain_digest: pcaChainDigest(['a']), chain_len: 1, ...over });

describe('isHttpsUrl edges', () => {
  it('rejects non-strings without reading string methods', () => {
    expect(isHttpsUrl(5)).toBe(false);
    expect(isHttpsUrl(null)).toBe(false);
    expect(isHttpsUrl({ length: 20, startsWith: () => true, charCodeAt: () => 0x41, slice: () => 'host' })).toBe(false);
  });
  it('bounds the length at exactly 2048', () => {
    const pad = (n: number) => `https://a.example/${'p'.repeat(n - 'https://a.example/'.length)}`;
    expect(isHttpsUrl(pad(2048))).toBe(true);
    expect(isHttpsUrl(pad(2049))).toBe(false);
  });
  it('accepts the first and last printable ASCII characters and refuses the ones just outside', () => {
    expect(isHttpsUrl('https://a.example/!')).toBe(true);
    expect(isHttpsUrl('https://a.example/~')).toBe(true);
    expect(isHttpsUrl('https://a.example/ ')).toBe(false);
    expect(isHttpsUrl('https://a.example/\x7f')).toBe(false);
    expect(isHttpsUrl('https://a.example/#f')).toBe(false);
    expect(isHttpsUrl('https://a.example/\\')).toBe(false);
  });
  it('reads the authority up to the first slash or question mark', () => {
    expect(isHttpsUrl('https://a')).toBe(true);
    expect(isHttpsUrl('https://')).toBe(false);
    expect(isHttpsUrl('https:///x')).toBe(false);
    expect(isHttpsUrl('https://a/x@y')).toBe(true);
    expect(isHttpsUrl('https://a?x@y')).toBe(true);
    expect(isHttpsUrl('https://u@a/x')).toBe(false);
    expect(isHttpsUrl('https://a@')).toBe(false);
  });
});

describe('pca_grant detail validation edges', () => {
  it('refuses a null entry without throwing', () => {
    expect(validatePcaGrantDetail(null)).toEqual({ ok: false, code: 'bad_entry' });
    expect(parsePcaGrantDetails([null])).toEqual({ ok: false, code: 'bad_entry' });
  });
  it('requires every locations entry to be an https URL', () => {
    const good = 'https://api.example';
    expect(validatePcaGrantDetail(mk({ locations: [good, 'http://x.example'] }))).toEqual({ ok: false, code: 'bad_locations' });
    expect(validatePcaGrantDetail(mk({ locations: ['http://x.example', good] }))).toEqual({ ok: false, code: 'bad_locations' });
    expect(validatePcaGrantDetail(mk({ locations: [good, good] }))).toMatchObject({ ok: true });
  });
});

describe('presentation check edges', () => {
  it('does not match a detail longer than the presented chain', () => {
    const d = mk({ chain_len: 3, chain_digest: pcaChainDigest(['a', 'b']) }) as unknown as PcaGrantDetail;
    expect(checkPcaGrantPresentation([d], { resource: 'r', chainIds: ['a', 'b'], proofVerified: true })).toEqual({ allow: false, code: 'chain_mismatch' });
    const ok = mk({ chain_len: 2, chain_digest: pcaChainDigest(['a', 'b']) }) as unknown as PcaGrantDetail;
    expect(checkPcaGrantPresentation([ok], { resource: 'r', chainIds: ['a', 'b'], proofVerified: true })).toEqual({ allow: true, detail: ok });
  });
});
