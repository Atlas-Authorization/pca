import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseTrustedRoot, verifySigstoreBundleCore } from './sigstore';
import { ctxPrim, extension, tlv } from './test-support/forge-x509';
import { IDENTITY, OID, mint, type MintOpts } from './test-support/forge-sigstore';

const V = JSON.parse(readFileSync(join(__dirname, '..', '..', 'pca', 'conformance', 'sigstore-vectors.json'), 'utf8'));
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const w = (o?: MintOpts): string => {
  const m = mint(o);
  const r = verifySigstoreBundleCore(m.bundle, { roots: m.roots });
  return r.ok ? 'ok' : `${r.code}: ${r.detail}`;
};

describe('trusted-root validFor spelling', () => {
  it('an extended (signed, six-digit) year is not an RFC 3339 date-time', () => {
    const c = V.cases.find((x: { name: string }) => x.name === 'npm/sigstore-5.0.0');
    const root = (start: string) => {
      const r = clone(V.roots[c.roots]);
      r.tlogs[0].publicKey.validFor = { start };
      return () => parseTrustedRoot(r);
    };
    expect(root('2021-01-12T11:53:27Z')).not.toThrow();
    for (const s of ['-122021-01-12T11:53:27Z', '+012021-01-12T11:53:27Z']) expect(root(s), s).toThrow(/validFor.start/);
  });
});

describe('entry body and key type', () => {
  const BODY = 'tlog_body: the entry body is not the kind the bundle names';
  it('a one-element array is not a string kind or version', () => {
    expect(w({ body: (b) => { b.kind = [b.kind]; } })).toBe(BODY);
    expect(w({ body: (b) => { b.apiVersion = [b.apiVersion]; } })).toBe(BODY);
    expect(w({ body: (b) => { b.kind = [b.kind]; b.apiVersion = [b.apiVersion]; } })).toBe(BODY);
  });
  it('a digest algorithm other than the one named for the signing key is refused for a P-384 key', () => {
    const ALG = "tlog_body: the entry digest algorithm is not the signing key's";
    for (const a of ['SHA2_512', 'MD5']) expect(w({ rekor: 'v2', leaf: { curve: 'P-384' }, body: (b) => { b.spec.hashedRekordV002.data.algorithm = a; } }), a).toBe(ALG);
  });
  it('an EC leaf key on a curve other than P-256 or P-384 is unsupported', () => {
    const k = generateKeyPairSync('ec', { namedCurve: 'secp256k1' }).publicKey.export({ type: 'spki', format: 'der' });
    expect(w({ leaf: { spki: new Uint8Array(k) } })).toBe('signature: unsupported leaf key type');
  });
  it('a subjectAltName that is not a SEQUENCE is refused even when it holds one name (the chain check rejects it first)', () => {
    const wrapped = (base: Parameters<NonNullable<NonNullable<MintOpts['leaf']>['exts']>>[0]) => [...base, extension(OID.san, false, tlv(0x31, ctxPrim(6, new TextEncoder().encode(IDENTITY))))];
    expect(w({ leaf: { noSan: true, exts: wrapped } })).toBe('cert_chain: no pinned CA issued the certificate, valid at every signing time');
  });
});
