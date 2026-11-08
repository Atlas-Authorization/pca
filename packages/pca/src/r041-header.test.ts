// 0.4.1: the PCA-Action header is decoded as STRICT unpadded base64url (the profile's base64url rule). Before, the server
// extractor used Buffer's lenient base64 decoder: padding, the standard alphabet, whitespace and junk characters were accepted.
import { describe, expect, it } from 'vitest';
import { PcaHeaderError, decodePcaHeader, pcaHeaders, PCA_HEADER } from './adapters';
import { encodePCActn } from './pcactn';
import { defaultExtract, memoryPcaStore, requirePCA as requirePCA05 } from './server/require-pca';
import { AUD, NOW, setup } from './server/fixture.test-util';
const requirePCA = (o: Parameters<typeof requirePCA05>[0]): ReturnType<typeof requirePCA05> => requirePCA05({ insecureAllowUnboundOperation: true, multiInstance: false, ...o }); // unbound and single-instance on purpose: these tests are not about operation binding or store scope (see breaking-05.test.ts)


const s = setup();
const a = s.mk(s.plan[0]!);
const text = encodePCActn(a);
const good = pcaHeaders(text)[PCA_HEADER]!;
const std = (t: string) => Buffer.from(t).toString('base64'); // padded, standard alphabet
const guard = () =>
  requirePCA({
    resolveGrant: async (ref: string) => (ref === s.grant.id ? s.grant : null),
    now: () => NOW,
    audience: AUD,
    budgetStore: memoryPcaStore(),
    hooks: { revocation: () => ({ enforced: true, ok: true }) },
    context: () => ({ plan: s.plan, planAuthorized: true, risk: s.lowRisk }),
  });

/** header values that are NOT the one strict spelling of some bytes */
const bad: [string, string][] = [
  ['padding', good + (good.length % 4 === 2 ? '==' : good.length % 4 === 3 ? '=' : '====')],
  ['standard alphabet', std('{"a":"???"}').replace(/=+$/, '')], // "...Pz8/..." carries a '/'
  ['padded base64', Buffer.from('{"a":1}').toString('base64url') + '=='],
  ['padded standard base64', std('{"a":1}')],
  ['leading space', ' ' + good],
  ['trailing space', good + ' '],
  ['inner newline', good.slice(0, 10) + '\n' + good.slice(10)],
  ['invalid character', good.slice(0, 10) + '*' + good.slice(10)],
  ['length mod 4 == 1', good + 'A'.repeat(((1 - good.length) % 4 + 4) % 4 || 4)],
  ['non-canonical trailing bits', 'QR'],
  ['empty', ''],
];

describe('0.4.1 strict PCA-Action header', () => {
  it('round-trips the canonical encoding', () => {
    expect(decodePcaHeader(good)).toBe(text);
  });

  it.each(bad)('refuses %s', (_name, v) => {
    expect(() => decodePcaHeader(v)).toThrow(PcaHeaderError);
  });

  it('refuses bytes that are not UTF-8, and keeps a BOM for the strict JSON parser to refuse', () => {
    expect(() => decodePcaHeader(Buffer.from([0xff, 0xfe, 0x7b]).toString('base64url'))).toThrow(/UTF-8/);
    expect(decodePcaHeader(Buffer.from('\ufeff{}').toString('base64url'))).toBe('\ufeff{}');
  });

  it('defaultExtract throws on a lenient spelling, and requirePCA answers 401', async () => {
    // a padded standard-base64 spelling of a valid PCActn text (trailing spaces are JSON whitespace, so the text stays valid):
    // Buffer's lenient decoder used to accept it
    let t2 = text;
    while (Buffer.byteLength(t2) % 3 === 0) t2 += ' ';
    const lenient = std(t2);
    expect(lenient.endsWith('=')).toBe(true);
    expect(() => defaultExtract({ headers: { 'pca-action': lenient } })).toThrow(PcaHeaderError);
    const r = await guard()({ headers: { 'pca-action': lenient } });
    expect(r.ok).toBe(false);
    expect(!r.ok && r.status).toBe(401);
    const ok = await guard()({ headers: { 'pca-action': good } });
    expect(ok.ok).toBe(true);
  });
});
