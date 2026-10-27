/**
 * 0.4.3 hardware-attestation strictness: evidence with a second encoding is refused, not ignored.
 * SEV-SNP exact report length and zero reserved bytes, DCAP bytes after the signature data, MAA / Confidential Space
 * non-canonical base64url. (X.509 / DER cases are pinned in x509-differential.test.ts and mutation-kill-x509-strict.test.ts.)
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { verifyGenuineSevSnpReport } from './hardware-sevsnp';
import { parseDcapQuote } from './attest-intel-tdx';
import { parseMaaJwt } from './attest-azure-maa';
import { parseGcpCsJwt } from './attest-gcp-confidential-space';
import { serializeSevSnpReport } from './test-support/sevsnp-report';

const fx = (...p: string[]) => new Uint8Array(readFileSync(resolve(__dirname, '..', 'fixtures', ...p)));
const snp = async (report: Uint8Array) => (await verifyGenuineSevSnpReport({ report, vcekDer: new Uint8Array(), askArkPem: '', nowMs: 0 })).reason;
const fields = { version: 2, vmpl: 0, reported_tcb: 1n, report_data: new Uint8Array(64), measurement: new Uint8Array(48), chip_id: new Uint8Array(64) };

describe('SEV-SNP report is exactly 1184 bytes with zero reserved signature bytes', () => {
  const base = serializeSevSnpReport(fields);
  it('canonical length reaches the chain check; a short or long report is refused first', async () => {
    expect(base.length).toBe(1184);
    expect(await snp(base)).not.toMatch(/canonical|reserved/);
    expect(await snp(base.subarray(0, 1183))).toMatch(/report parse failed|is not the canonical 1184/);
    expect(await snp(new Uint8Array([...base, 0]))).toBe('report length 1185 is not the canonical 1184');
  });
  it('a non-zero byte in any reserved part of the signature block is refused', async () => {
    for (const at of [0x2a0 + 48, 0x2a0 + 71, 0x2e8 + 48, 0x2e8 + 71, 0x2e8 + 72, 1183]) {
      const r = new Uint8Array(base);
      r[at] = 1;
      expect(await snp(r), String(at)).toBe('report signature block has non-zero reserved bytes');
    }
  });
});

describe('DCAP quote: only zero padding may follow the declared signature data', () => {
  const quote = fx('real-tdx', 'azure-intel-tdx-dcap-quote.bin');
  it('the real quote and zero padding parse; a non-zero trailing byte does not', () => {
    expect(() => parseDcapQuote(quote)).not.toThrow();
    expect(() => parseDcapQuote(new Uint8Array([...quote, 0, 0]))).not.toThrow();
    expect(() => parseDcapQuote(new Uint8Array([...quote, 0, 1]))).toThrow('non-zero bytes after the signature data');
  });
});

describe('MAA and Confidential Space JWS segments must be canonical base64url', () => {
  const b = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const sig = Buffer.from([1, 2, 3]).toString('base64url'); // 'AQID'
  it('padding, stray characters and non-zero trailing bits are refused in every segment', () => {
    const h = b({ alg: 'ES256' });
    for (const [parse, name] of [[parseMaaJwt, 'parseMaaJwt'], [parseGcpCsJwt, 'parseGcpCsJwt']] as const) {
      expect(() => parse(`${h}.${b({})}.${sig}`), name).not.toThrow();
      expect(() => parse(`${h}.${b({})}.${sig}=`), name).toThrow();
      expect(() => parse(`${h}.${b({})}.AR`), name).toThrow('malformed signature segment'); // 'AR' and 'AQ' both decode to 0x01: trailing bits
      expect(() => parse(`${h}.${b({})}.A*QID`), name).toThrow('malformed signature segment');
      expect(() => parse(`${h}=.${b({})}.${sig}`), name).toThrow('malformed JSON segment');
      expect(() => parse(`${h}.${b({})}=.${sig}`), name).toThrow('malformed JSON segment');
    }
  });
});
