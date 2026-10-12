/** derValidityMs / parseDerTime (x509-validity.ts): DER structure and RFC 5280 Time on hand-built bytes, every refusal NaN. */
import { describe, expect, it } from 'vitest';
import { derValidityMs, parseDerTime, x509ValidityMs } from './x509-validity';

const b = (...x: (number | number[] | Uint8Array)[]): number[] => x.flatMap((v) => (typeof v === 'number' ? [v] : [...v]));
const tlv = (tag: number, c: number[]) => b(tag, c.length, c); // short-form length (all test contents < 128)
const ascii = (s: string) => [...Buffer.from(s, 'ascii')];
const NB = '300101000000Z';
const NA = '310101000000Z';
const FROM = Date.UTC(2030, 0, 1);
const TO = Date.UTC(2031, 0, 1);
const validity = (nb = tlv(0x17, ascii(NB)), na = tlv(0x17, ascii(NA)), extra: number[] = []) => tlv(0x30, b(nb, na, extra));
const tbsBody = (opts: { version?: boolean; serialTag?: number; sigTag?: number; issuerTag?: number; validityTag?: number; tail?: number[] } = {}) =>
  b(opts.version === false ? [] : tlv(0xa0, tlv(0x02, [2])), tlv(opts.serialTag ?? 0x02, [7]), tlv(opts.sigTag ?? 0x30, []), tlv(opts.issuerTag ?? 0x30, []), opts.validityTag === undefined ? validity() : tlv(opts.validityTag, validity().slice(2)), opts.tail ?? []);
const cert = (tbs: number[], certTag = 0x30, tbsTag = 0x30) => new Uint8Array(tlv(certTag, tlv(tbsTag, tbs)));
const NANS = { from: NaN, to: NaN };
const ok = { from: FROM, to: TO };

describe('derValidityMs structure', () => {
  it('with and without the [0] version; validity may be the last element of the TBS', () => {
    expect(derValidityMs(cert(tbsBody()))).toEqual(ok);
    expect(derValidityMs(cert(tbsBody({ version: false })))).toEqual(ok);
    expect(derValidityMs(cert(tbsBody({ tail: tlv(0x30, []) })))).toEqual(ok);
  });
  it('every structural tag is checked', () => {
    expect(derValidityMs(cert(tbsBody(), 0x31))).toEqual(NANS);
    expect(derValidityMs(cert(tbsBody(), 0x30, 0x31))).toEqual(NANS);
    expect(derValidityMs(cert(tbsBody({ serialTag: 0x04 })))).toEqual(NANS);
    expect(derValidityMs(cert(tbsBody({ sigTag: 0x31 })))).toEqual(NANS);
    expect(derValidityMs(cert(tbsBody({ issuerTag: 0x31 })))).toEqual(NANS);
    expect(derValidityMs(cert(tbsBody({ validityTag: 0x31 })))).toEqual(NANS);
  });
  it('validity must lie inside the TBS and hold exactly two times', () => {
    // TBS declared to end before the validity (which still lies inside the certificate)
    const body = tbsBody({ version: false });
    const vLen = validity().length;
    const short = new Uint8Array(tlv(0x30, b(0x30, body.length - vLen, body)));
    expect(derValidityMs(short)).toEqual(NANS);
    const three = cert(b(tlv(0x02, [7]), tlv(0x30, []), tlv(0x30, []), validity(undefined, undefined, tlv(0x17, ascii(NA)))));
    expect(derValidityMs(three)).toEqual(NANS);
  });
  it('lengths: long form up to 4 bytes is fine; indefinite, 5-byte and overrunning lengths are refused', () => {
    const tbs = tlv(0x30, tbsBody());
    expect(derValidityMs(new Uint8Array(b(0x30, 0x81, tbs.length, tbs)))).toEqual(ok);
    expect(derValidityMs(new Uint8Array(b(0x30, 0x84, 0, 0, 0, tbs.length, tbs)))).toEqual(ok);
    expect(derValidityMs(new Uint8Array(b(0x30, 0x85, 0, 0, 0, 0, tbs.length, tbs)))).toEqual(NANS);
    expect(derValidityMs(new Uint8Array(b(0x30, 0x80, tbs, 0, 0)))).toEqual(NANS);
    expect(derValidityMs(new Uint8Array(b(0x30, 0x7f, tbs)))).toEqual(NANS); // declared length past the end
    expect(derValidityMs(new Uint8Array([0x30]))).toEqual(NANS);
    expect(derValidityMs(new Uint8Array([]))).toEqual(NANS);
  });
});

describe('parseDerTime', () => {
  it('UTCTime only with tag 0x17 and 13 chars; GeneralizedTime only with tag 0x18 and 15 chars', () => {
    expect(parseDerTime(0x17, '300101000000Z')).toBe(FROM);
    expect(parseDerTime(0x18, '20300101000000Z')).toBe(FROM);
    for (const [tag, t] of [[0x17, '20300101000000Z'], [0x04, '20300101000000Z'], [0x04, '300101000000Z'], [0x18, '300101000000Z']] as const) {
      expect(parseDerTime(tag, t), `${tag} ${t}`).toBeNaN();
    }
  });
  it('the trailing Z and all-digit fields are required', () => {
    for (const t of ['3001010000000', '3a0101000000Z', '300101000000z', '30010100000+Z']) expect(parseDerTime(0x17, t), t).toBeNaN();
  });
});

describe('x509ValidityMs without raw DER', () => {
  it('a shim with Date members uses them, not its rendered strings', () => {
    expect(x509ValidityMs({ validFrom: 'garbage', validTo: 'garbage', validFromDate: new Date(FROM), validToDate: new Date(TO) })).toEqual(ok);
    expect(x509ValidityMs({ validFrom: 'garbage', validTo: 'garbage', validFromDate: new Date(Number.NaN), validToDate: new Date(TO) }).from).toBeNaN();
  });
});
