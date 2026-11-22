// Two spots of the Sigstore verifier that only a hostile input reaches: a subjectAltName that is not a SEQUENCE, and
// RFC 3339 validity strings with trailing text.
import { describe, expect, it } from 'vitest';
import type { KeyObject } from 'node:crypto';
import { parseTrustedRoot, verifySigstoreBundleCore } from './sigstore';
import { ctxPrim, extension, tlv } from './test-support/forge-x509';
import { IDENTITY, OID, b64, mint, mintCa, mintLog } from './test-support/forge-sigstore';

describe('subjectAltName shape', () => {
  it('a value that is not a SEQUENCE of exactly one name is never accepted as an identity', () => {
    const san = (tag: number) => extension(OID.san, false, tlv(tag, ctxPrim(6, new TextEncoder().encode(IDENTITY))));
    // the same single URI name under a SEQUENCE is the control: it verifies
    const control = mint({ leaf: { noSan: true, exts: (base) => [...base, san(0x30)] } });
    expect(verifySigstoreBundleCore(control.bundle, { roots: control.roots }).ok).toBe(true);
    // under a SET it must be refused, whichever stage refuses it
    const m = mint({ leaf: { noSan: true, exts: (base) => [...base, san(0x31)] } });
    const r = verifySigstoreBundleCore(m.bundle, { roots: m.roots });
    expect(r.ok).toBe(false);
  });
});

describe('RFC 3339 validity strings are anchored at the end', () => {
  const MEDIA = 'application/vnd.dev.sigstore.trustedroot+json;version=0.1';
  const ec = mintLog('ec');
  const ca = mintCa('anchor-root');
  const spki = (k: KeyObject): Buffer => k.export({ type: 'spki', format: 'der' }) as Buffer;
  const root = (start: string) => ({
    mediaType: MEDIA,
    tlogs: [{ baseUrl: 'https://rekor.test', hashAlgorithm: 'SHA2_256', publicKey: { rawBytes: b64(spki(ec.pub)), keyDetails: 'PKIX_ECDSA_P256_SHA_256', validFor: { start } }, logId: { keyId: b64(ec.keyId) } }],
    ctlogs: [],
    certificateAuthorities: [{ subject: {}, uri: '', certChain: { certificates: [{ rawBytes: b64(ca.der) }] }, validFor: { start: '2021-01-12T11:53:27Z' } }],
    timestampAuthorities: [],
  });
  it('the control parses and trailing text of any kind is refused', () => {
    expect(() => parseTrustedRoot(root('2021-01-12T11:53:27Z'))).not.toThrow();
    expect(() => parseTrustedRoot(root('2021-01-12T11:53:27+01:00'))).not.toThrow();
    for (const tail of ['\n', '\t', ' (x)', ' GMT', ' UTC', ' PST', ' 2021', 'Z', 'z', '.', ',', ' ', ' Jan', ' 12:00']) {
      for (const head of ['2021-01-12T11:53:27Z', '2021-01-12T11:53:27+01:00', '2021-01-12T11:53:27.5Z']) {
        expect(() => parseTrustedRoot(root(`${head}${tail}`)), JSON.stringify(`${head}${tail}`)).toThrow(/^validFor\.start missing$/);
      }
    }
  });
});
