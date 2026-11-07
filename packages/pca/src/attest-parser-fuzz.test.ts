/**
 * Deterministic parser fuzz corpus for the vendor evidence formats (SEV-SNP report, DCAP quote, MAA token, SPDM report),
 * driven through the real verifiers over the recorded evidence. For every mutation (bit flip, truncation, extension,
 * deletion, insertion) the verifier must RESOLVE (never throw) and must DENY, except where the mutation leaves every
 * verified byte unchanged: the listed survivors, which are asserted exactly.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildCanary, type CanaryCase, type CanaryManifest } from './attest-canary.test-util';

const MANIFEST = resolve(__dirname, '..', 'fixtures', 'attest-canary', 'manifest.json');
const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8')) as CanaryManifest;
const DIR = resolve(MANIFEST, '..');

function prng(seed: number) {
  let s = seed >>> 0 || 1;
  return (n: number) => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s % n; };
}
type Kind = 'flip' | 'truncate' | 'extend' | 'delete' | 'insert';
const KINDS: Kind[] = ['flip', 'truncate', 'extend', 'delete', 'insert'];
function mutation(kind: Kind, rnd: (n: number) => number): (b: Uint8Array) => Uint8Array {
  return (b) => {
    const at = rnd(b.length);
    switch (kind) {
      case 'flip': { const c = new Uint8Array(b); c[at] = c[at]! ^ (1 << rnd(8)); return c; }
      case 'truncate': return b.slice(0, at);
      case 'extend': return Uint8Array.from([...b, ...new Array(1 + rnd(16)).fill(0)]);
      case 'delete': return Uint8Array.from([...b.slice(0, at), ...b.slice(at + 1)]);
      case 'insert': return Uint8Array.from([...b.slice(0, at), rnd(256), ...b.slice(at)]);
    }
  };
}

/**
 * The primary evidence blob of a case (what the mutations are applied to). Only the DCAP quote has slack: its trailing
 * zero padding, and its PEM certificate chain, whose text the PEM decoder reads through (whitespace and stray bytes between
 * and inside blocks do not change the certificates that get verified). Everything else may be accepted only if byte-identical.
 */
function primaryOf(c: CanaryCase): { bytes: Uint8Array; padStart?: number; pemStart?: number } {
  const f = (p: string) => new Uint8Array(readFileSync(resolve(DIR, p)));
  if (c.vendor === 'tdx') {
    const bytes = f(c.quoteFile);
    return { bytes, padStart: 48 + 584 + 4 + new DataView(bytes.buffer, bytes.byteOffset).getUint32(48 + 584, true), pemStart: Buffer.from(bytes).indexOf('-----BEGIN CERTIFICATE-----') };
  }
  if (c.vendor === 'sev-snp') return { bytes: f(c.reportFile).slice(c.reportOffset ?? 0, (c.reportOffset ?? 0) + 1184) };
  if (c.vendor === 'azure-maa') return { bytes: f(c.tokenFile) };
  return { bytes: f(c.reportFile) };
}
/** The certificates a PEM block list decodes to (PEM decoding ignores whitespace and stray bytes, so this is what is verified). */
const certsOfPem = (b: Uint8Array): string[] => (Buffer.from(b).toString('latin1').match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? []).map((p) => Buffer.from(p.replace(/-----[A-Z ]+-----/g, ''), 'base64').toString('hex'));
const equalBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);

const COUNT = 100;
describe.each(manifest.cases.map((c, i) => [c.vendor, c, i] as const))('evidence fuzz: %s', (_v, c: CanaryCase, idx) => {
  it(`${COUNT} mutations per kind: never throws, and never accepts changed evidence`, async () => {
    const b = buildCanary(c, DIR, c.now === 'now' ? Date.now() : c.now);
    const { bytes: orig, padStart, pemStart } = primaryOf(c);
    const origCerts = certsOfPem(orig);
    const rnd = prng(0x5eed + idx);
    const wrong: string[] = [];
    const acceptedByKind: Record<string, number> = {};
    for (const kind of KINDS) {
      for (let i = 0; i < COUNT; i++) {
        const m = mutation(kind, rnd);
        let seen: Uint8Array | undefined;
        const r = await b.verify({ mutate: (x) => (seen = m(x)) }); // a rejected promise here fails the test: the verifier must not throw
        const unchanged = seen !== undefined && (equalBytes(seen, orig) || (padStart !== undefined && pemStart !== undefined && seen.length >= padStart && seen.subarray(padStart).every((v) => v === 0) && equalBytes(seen.subarray(0, pemStart), orig.subarray(0, pemStart)) && JSON.stringify(certsOfPem(seen.subarray(pemStart))) === JSON.stringify(origCerts)));
        if (r.ok === true && !unchanged) wrong.push(`${kind}#${i} ACCEPTED a changed input`); // safety: never accept bytes that differ from the verified ones
        if (r.ok === true) acceptedByKind[kind] = (acceptedByKind[kind] ?? 0) + 1;
      }
    }
    expect(wrong).toEqual([]);
    // only the DCAP quote has slack (zero padding, PEM text); every other recorded format accepts nothing but itself
    if (c.vendor !== 'tdx') expect(acceptedByKind).toEqual({});
    else expect(acceptedByKind['extend']).toBe(COUNT); // appended zero padding is tolerated, by design
  });
});

describe('targeted strictness rules (each fails without its check)', () => {
  const caseOf = (v: string) => manifest.cases.find((c) => c.vendor === v)!;
  const reasonOf = async (v: string, mutate: (b: Uint8Array) => Uint8Array) => {
    const c = caseOf(v);
    const r = await buildCanary(c, DIR, c.now === 'now' ? Date.now() : c.now).verify({ mutate });
    return [r.ok, r.reason];
  };
  const setByte = (at: number, v: number) => (b: Uint8Array) => { const c = new Uint8Array(b); c[at] = v; return c; };
  const append = (...x: number[]) => (b: Uint8Array) => Uint8Array.from([...b, ...x]);
  const textOf = (f: (s: string) => string) => (b: Uint8Array) => new Uint8Array(Buffer.from(f(Buffer.from(b).toString('latin1')), 'latin1'));

  it('SEV-SNP: the report is exactly 1184 bytes', async () => {
    expect(await reasonOf('sev-snp', append(0))).toEqual([false, 'SEV-SNP report invalid: report length 1185 is not the canonical 1184']);
    expect(await reasonOf('sev-snp', (b) => b.slice(0, 1183))).toEqual([false, 'SEV-SNP report invalid: report length 1183 is not the canonical 1184']);
  });
  it('SEV-SNP: reserved bytes of the signature block must be zero (a second encoding of the same signed report is refused)', async () => {
    for (const at of [0x4a0 - 1, 0x2e8 + 72, 0x2a0 + 48, 0x2a0 + 71, 0x2e8 + 48, 0x2e8 + 71]) {
      expect(await reasonOf('sev-snp', setByte(at, 1)), `byte ${at.toString(16)}`).toEqual([false, 'SEV-SNP report invalid: report signature block has non-zero reserved bytes']);
    }
  });
  it('TDX: zero padding after the signature data is tolerated, anything non-zero is refused', async () => {
    expect((await reasonOf('tdx', append(0, 0, 0)))[0]).toBe(true);
    expect(await reasonOf('tdx', append(1))).toEqual([false, 'DCAP quote invalid: quote parse failed: parseDcapQuote: non-zero bytes after the signature data']);
  });
  it('MAA: a non-canonical base64url JWS segment is refused (no ignored characters, no trailing bits)', async () => {
    const B = 'non-canonical compact JWS: bad-character';
    const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const forms: Array<[string, (s: string) => string, string]> = [
      ['a stray character in the signature', (s) => s.slice(0, -4) + '*' + s.slice(-4), `MAA token parse failed: parseMaaJwt: malformed signature segment: ${B}`],
      ['padding', (s) => s + '=', `MAA token parse failed: parseMaaJwt: malformed signature segment: ${B}`],
      ['a newline in the signature', (s) => s.slice(0, -4) + '\n' + s.slice(-4), `MAA token parse failed: parseMaaJwt: malformed signature segment: ${B}`],
      ['non-zero unused trailing bits in the signature', (s) => s.slice(0, -1) + ALPHA[ALPHA.indexOf(s.slice(-1)) ^ 1], 'MAA token parse failed: parseMaaJwt: malformed signature segment: non-canonical compact JWS: non-canonical-base64url'],
      ['a stray character in the payload', (s) => { const [h, p, g] = s.split('.'); return `${h}.${p!.slice(0, 8)}*${p!.slice(8)}.${g}`; }, `MAA token parse failed: parseMaaJwt: malformed JSON segment: ${B}`],
    ];
    for (const [name, f, want] of forms) expect([name, ...(await reasonOf('azure-maa', textOf(f)))]).toEqual([name, false, want]);
  });
});
