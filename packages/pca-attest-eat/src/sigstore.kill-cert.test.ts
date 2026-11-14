// Embedded SCT (RFC 6962), the trusted-root parser and the RSA key rule, over minted logs and certificates.
import { createHash, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseTrustedRoot, rsaKeyOk, verifySigstoreBundleCore, type PinnedRoots } from './sigstore';
import { cat, derLen, ext, extension, oid, tlv } from './test-support/forge-x509';
import { OID, T0, b64, mint, mintCa, mintCtLog, mintLog, type LeafOpts, type MintOpts, type SctSpec } from './test-support/forge-sigstore';

const why = (o: MintOpts): string => {
  const m = mint(o);
  const r = verifySigstoreBundleCore(m.bundle, { roots: m.roots });
  return r.ok ? 'ok' : `${r.code}: ${r.detail}`;
};
const ct = mintCtLog();
const ID = Uint8Array.from(ct.pinned.keyId);
const sct = (scts: SctSpec[], leaf: LeafOpts = {}, o: MintOpts = {}): string => why({ ...o, leaf: { scts, ctLog: ct, ...leaf } });
const be64 = (n: bigint): Uint8Array => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(n);
  return b;
};
const relen = (l: Uint8Array): Uint8Array => {
  const c = Uint8Array.from(l);
  c[0] = ((c.length - 2) >> 8) & 0xff;
  c[1] = (c.length - 2) & 0xff;
  return c;
};
const head = (logId: Uint8Array = ID): Uint8Array => cat(Uint8Array.of(0), logId, be64(BigInt(T0)));
const OK_AFTER_SCT = 'identity: fail closed: no subjectAltName';

describe('embedded SCT', () => {
  it('a valid SCT from a pinned CT log, with and without SCT extensions', () => {
    expect(sct([{}])).toBe('ok');
    expect(sct([{ ext: Uint8Array.of(1, 2, 3) }])).toBe('ok');
  });
  it('no SCT in the certificate', () => {
    expect(why({ ctlogs: true })).toBe('sct: no embedded SCT');
  });
  it('the extension holds an OCTET STRING with a length-prefixed list', () => {
    expect(sct([{}], { sctValue: (l) => tlv(0x30, l) })).toBe('sct: SCT list is not an OCTET STRING');
    expect(sct([{}], { sctList: (l) => l.subarray(0, l.length - 1) })).toBe('sct: SCT list length');
    expect(sct([{}], { sctList: (l) => cat(l, Uint8Array.of(0)) })).toBe('sct: SCT list length');
    expect(sct([{}], { sctList: () => Uint8Array.of(0) })).toBe('sct: SCT list length');
    expect(sct([{}], { sctList: () => Uint8Array.of() })).toBe('sct: SCT list length');
  });
  it('an extension with no value is read at the SCT stage', () => {
    expect(sct([{}], { sctValue: () => Uint8Array.of() })).toBe('sct: fail closed: DER truncated');
  });
  it('an empty list names no SCT from a pinned log', () => {
    expect(sct([{}], { sctList: () => Uint8Array.of(0, 0) })).toBe('sct: no SCT from a pinned CT log');
  });
  it('an SCT from a log that is not pinned, or of another version, is passed over', () => {
    const none = 'sct: no SCT from a pinned CT log';
    expect(sct([{ logId: new Uint8Array(32) }])).toBe(none);
    expect(sct([{ version: 1 }])).toBe(none);
    expect(sct([{ logId: new Uint8Array(32) }, {}])).toBe('ok');
    expect(sct([{ version: 1 }, {}])).toBe('ok');
  });
  it('bytes after the last SCT are a truncated SCT', () => {
    const stray = (...b: number[]) => (l: Uint8Array) => relen(cat(l, Uint8Array.of(...b)));
    expect(sct([{ logId: new Uint8Array(32) }], { sctList: stray(7) })).toBe('sct: SCT truncated');
    expect(sct([{ logId: new Uint8Array(32) }], { sctList: stray(0, 0) })).toBe('sct: SCT truncated');
    expect(sct([{ logId: new Uint8Array(32) }], { sctList: stray(0, 3, 1) })).toBe('sct: SCT truncated');
    // a pinned valid SCT first ends the search before the stray bytes
    expect(sct([{}], { sctList: stray(7) })).toBe('ok');
  });
  it('an SCT shorter than its fixed fields, or shorter than it says', () => {
    const t = 'sct: SCT truncated';
    const f = (raw: Uint8Array) => sct([{ raw }]);
    // 47 bytes is the least a well-formed SCT has (empty extensions, empty signature): it parses and its empty signature is invalid
    expect(f(cat(head(), Uint8Array.of(0, 0, 4, 3, 0, 0)))).toBe('sct: SCT signature invalid');
    expect(f(cat(head(), Uint8Array.of(0, 0, 4, 3, 0)))).toBe(t);
    expect(f(Uint8Array.of(0))).toBe(t);
    // extensions that run past the end
    expect(f(cat(head(), Uint8Array.of(0, 5, 1, 2, 3, 4)))).toBe(t);
    // the entry says it is longer than the list holds
    expect(sct([{}], { sctList: (l) => { const c = Uint8Array.from(l); c[2] = 0; c[3] = 200; return c; } })).toBe(t);
  });
  it('bytes after the signature, or a signature length that overruns, are malformed', () => {
    expect(sct([{ trailing: Uint8Array.of(1) }])).toBe('sct: SCT malformed');
    expect(sct([{ raw: cat(head(), Uint8Array.of(0, 0, 4, 3, 0, 5)) }])).toBe('sct: SCT malformed');
  });
  it('only SHA-256 with ECDSA or RSA', () => {
    const alg = 'sct: SCT is not SHA-256 with ECDSA or RSA';
    expect(sct([{ hashAlg: 2 }])).toBe(alg);
    expect(sct([{ hashAlg: 5 }])).toBe(alg);
    expect(sct([{ sigAlg: 2 }])).toBe(alg);
    expect(sct([{ sigAlg: 0 }])).toBe(alg);
    expect(sct([{ sigAlg: 1 }])).toBe('ok');
    expect(sct([{ hashAlg: 2 }, {}])).toBe('ok');
  });
  it('the timestamp is read as an exact 64-bit value and must fit a safe integer', () => {
    expect(sct([{ ts: 2n ** 53n }])).toBe('sct: SCT timestamp out of range');
    expect(sct([{ ts: 2n ** 63n }])).toBe('sct: SCT timestamp out of range');
    expect(sct([{ ts: 2n ** 64n - 1n }])).toBe('sct: SCT timestamp out of range');
    expect(sct([{ ts: BigInt(Number.MAX_SAFE_INTEGER) }])).toBe('ok');
  });
  it('the CT log key must have been valid at the SCT timestamp, inclusive at both ends', () => {
    const win = (start: number, end: number) => (r: PinnedRoots) => ({ ...r, ctlogs: [{ ...r.ctlogs[0]!, valid: { start, end } }] });
    const msg = 'sct: SCT log key not valid at its timestamp';
    expect(sct([{}], {}, { roots: win(T0, T0) })).toBe('ok');
    expect(sct([{}], {}, { roots: win(T0 + 1, T0 + 5) })).toBe(msg);
    expect(sct([{}], {}, { roots: win(T0 - 5, T0 - 1) })).toBe(msg);
  });
  it('a signature that does not verify, or one by another key', () => {
    expect(sct([{ sig: Uint8Array.of(1, 2, 3) }])).toBe('sct: SCT signature invalid');
    expect(sct([{ signKey: mintCtLog().priv }])).toBe('sct: SCT signature invalid');
    expect(sct([{ sig: Uint8Array.of(1, 2, 3) }, {}])).toBe('ok');
  });
  it('the precertificate is rebuilt with the exact DER length forms, whatever the extension block size', () => {
    const PAD = '1.3.6.1.4.1.99999.1';
    const padLen = (s: number): number => {
      const inner = oid(PAD).length + 1 + derLen(s).length + s;
      return 1 + derLen(inner).length + inner;
    };
    const eku = ext.extKeyUsage([OID.codeSigning], true);
    const padded = (total: number) => () => {
      const need = total - eku.length;
      for (let s = need; s >= 0; s--) {
        if (padLen(s) === need) return [eku, extension(PAD, false, new Uint8Array(s))];
      }
      throw new Error(`cannot pad to ${total}`);
    };
    for (const total of [60, 127, 128, 129, 200, 255, 256, 257, 1000, 65535, 65536, 65537, 70000]) {
      expect(sct([{}], { exts: padded(total) }), String(total)).toBe(OK_AFTER_SCT);
    }
  });
});

// ------------------------------------------------------------------------------------------------ trusted root
const START = '2021-01-12T11:53:27.000Z';
const MEDIA = 'application/vnd.dev.sigstore.trustedroot+json;version=0.1';
const spki = (k: KeyObject): Buffer => k.export({ type: 'spki', format: 'der' }) as Buffer;
const ec = mintLog('ec');
const ca = mintCa('root-under-test');
const tlogJson = (log: { pub: KeyObject; keyId: Buffer }, over: Record<string, unknown> = {}, details = 'PKIX_ECDSA_P256_SHA_256', raw?: Uint8Array) => ({
  baseUrl: 'https://rekor.test',
  hashAlgorithm: 'SHA2_256',
  publicKey: { rawBytes: b64(raw ?? spki(log.pub)), keyDetails: details, validFor: { start: START } },
  logId: { keyId: b64(log.keyId) },
  ...over,
});
const caJson = (der: Uint8Array, over: Record<string, unknown> = {}) => ({ subject: {}, uri: '', certChain: { certificates: [{ rawBytes: b64(der) }] }, validFor: { start: START }, ...over });
const rootJson = (over: Record<string, unknown> = {}) => ({ mediaType: MEDIA, tlogs: [tlogJson(ec)], ctlogs: [], certificateAuthorities: [caJson(ca.der)], timestampAuthorities: [], ...over });

describe('parseTrustedRoot', () => {
  it('a root of each part', () => {
    const r = parseTrustedRoot(rootJson({ ctlogs: [tlogJson({ pub: ct.pinned.key, keyId: Buffer.from(ct.pinned.keyId) })], timestampAuthorities: [caJson(ca.der)] }));
    expect(r.tlogs.length).toBe(1);
    expect(r.ctlogs.length).toBe(1);
    expect(r.tlogs[0]!.valid).toEqual({ start: Date.parse(START), end: Infinity });
    expect(Buffer.from(r.tlogs[0]!.keyId).equals(ec.keyId)).toBe(true);
    expect(r.cas.length).toBe(1);
    expect(r.cas[0]!.valid).toEqual({ start: Date.parse(START), end: Infinity });
    expect(r.tsas.length).toBe(1);
  });
  it('a validity end is kept', () => {
    const r = parseTrustedRoot(rootJson({ tlogs: [tlogJson(ec, { publicKey: { rawBytes: b64(spki(ec.pub)), keyDetails: 'PKIX_ECDSA_P256_SHA_256', validFor: { start: START, end: '2030-01-01T00:00:00Z' } } })] }));
    expect(r.tlogs[0]!.valid).toEqual({ start: Date.parse(START), end: Date.parse('2030-01-01T00:00:00Z') });
  });
  it('absent CT logs and timestamp authorities are empty lists', () => {
    const j = rootJson();
    delete (j as Record<string, unknown>).ctlogs;
    delete (j as Record<string, unknown>).timestampAuthorities;
    const r = parseTrustedRoot(j);
    expect(r.ctlogs).toEqual([]);
    expect(r.tsas).toEqual([]);
  });
  it('not a trusted root', () => {
    for (const j of [null, 5, 'x', [], {}, { ...rootJson(), mediaType: 'x' }]) expect(() => parseTrustedRoot(j)).toThrow(/^not a trusted root v0\.1$/);
  });
  it('a root needs a transparency log and a CA', () => {
    const need = /^a trusted root needs a transparency log and a CA$/;
    expect(() => parseTrustedRoot(rootJson({ tlogs: [] }))).toThrow(need);
    expect(() => parseTrustedRoot(rootJson({ tlogs: undefined }))).toThrow(need);
    expect(() => parseTrustedRoot(rootJson({ certificateAuthorities: [] }))).toThrow(need);
    expect(() => parseTrustedRoot(rootJson({ certificateAuthorities: undefined }))).toThrow(need);
    expect(() => parseTrustedRoot(rootJson({ tlogs: [tlogJson(ec, {}, 'PKIX_RSA_PKCS1V15_2048_SHA256')] }))).toThrow(need);
  });
  it('malformed log entries', () => {
    const bad = /^log entry malformed$/;
    for (const t of [null, 5, 'x', [], tlogJson(ec, { publicKey: undefined }), tlogJson(ec, { publicKey: [] }), tlogJson(ec, { logId: undefined }), tlogJson(ec, { logId: 'x' })]) {
      expect(() => parseTrustedRoot(rootJson({ tlogs: [t] })), JSON.stringify(t)).toThrow(bad);
      expect(() => parseTrustedRoot(rootJson({ ctlogs: [t] })), JSON.stringify(t)).toThrow(bad);
    }
  });
  it('malformed certificate authority entries', () => {
    const bad = /^certificate authority entry malformed$/;
    for (const c of [null, 5, {}, { certChain: [] }, { certChain: {} }, { certChain: { certificates: 'x' } }, { certChain: { certificates: [] } }, { validFor: { start: START } }]) {
      expect(() => parseTrustedRoot(rootJson({ certificateAuthorities: [c] })), JSON.stringify(c)).toThrow(bad);
      expect(() => parseTrustedRoot(rootJson({ timestampAuthorities: [c] })), JSON.stringify(c)).toThrow(bad);
    }
  });
  it('a log id must be the SHA-256 of the key', () => {
    expect(() => parseTrustedRoot(rootJson({ tlogs: [tlogJson({ pub: ec.pub, keyId: Buffer.alloc(32) })] }))).toThrow(/^log id is not the SHA-256 of its key$/);
  });
  it('validity: start is required and an RFC 3339 string', () => {
    const start = (validFor: unknown) => () => parseTrustedRoot(rootJson({ tlogs: [tlogJson(ec, { publicKey: { rawBytes: b64(spki(ec.pub)), keyDetails: 'PKIX_ECDSA_P256_SHA_256', validFor } })] }));
    const missing = /^validFor\.start missing$/;
    expect(start(undefined)).toThrow(missing);
    expect(start(null)).toThrow(missing);
    expect(start(5)).toThrow(missing);
    expect(start({})).toThrow(missing);
    expect(start({ start: 5 })).toThrow(missing);
    expect(start({ start: { toString: () => '2021-01-12T11:53:27Z' } })).toThrow(missing);
    expect(start({ start: ' 2021-01-12T11:53:27Z' })).toThrow(missing);
    expect(start({ start: '2021-01-12T11:53:27Z ' })).toThrow(missing);
    expect(start({ start: '2021-01-12T11:53:27Z', end: '2030-01-01T00:00:00Z ' })).toThrow(/^validFor\.end malformed$/);
    expect(start({ start: '2021-01-12T11:53:27.123456789Z' })).not.toThrow();
    expect(start({ start: '2021-01-12T11:53:27.1234567890Z' })).toThrow(missing);
  });
});

describe('log key forms', () => {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 });
  const pkcs1 = rsa.publicKey.export({ type: 'pkcs1', format: 'der' });
  const rsaId = createHash('sha256').update(spki(rsa.publicKey)).digest();
  const rsaJson = (keyId: Buffer = rsaId) => tlogJson({ pub: rsa.publicKey, keyId }, {}, 'PKCS1_RSA_PKCS1V5', pkcs1);
  it('an RSA key is a CT log key; as a transparency log it is not used', () => {
    const r = parseTrustedRoot(rootJson({ ctlogs: [rsaJson()] }));
    expect(r.ctlogs.length).toBe(1);
    expect(Buffer.from(r.ctlogs[0]!.keyId).equals(rsaId)).toBe(true);
    expect(r.ctlogs[0]!.key.asymmetricKeyType).toBe('rsa');
    expect(parseTrustedRoot(rootJson({ tlogs: [tlogJson(ec), rsaJson()] })).tlogs.length).toBe(1);
  });
  it('an RSA CT log id must be the SHA-256 of the SPKI form', () => {
    expect(() => parseTrustedRoot(rootJson({ ctlogs: [rsaJson(Buffer.alloc(32))] }))).toThrow(/^log id is not the SHA-256 of its key$/);
  });
  it('unsupported key types are left out of both lists', () => {
    const odd = tlogJson(ec, {}, 'PKIX_RSA_PKCS1V15_2048_SHA256');
    const r = parseTrustedRoot(rootJson({ tlogs: [odd, tlogJson(ec)], ctlogs: [odd, tlogJson(ec)] }));
    expect(r.tlogs.length).toBe(1);
    expect(r.ctlogs.length).toBe(1);
  });
  const v2 = mintLog('v2', 'rekor2.test');
  const edJson = (over: Record<string, unknown> = {}, keyId: Buffer = v2.keyId) => tlogJson({ pub: v2.pub, keyId }, { baseUrl: 'https://rekor2.test:8443/api', ...over }, 'PKIX_ED25519');
  it('an Ed25519 key is a transparency log whose id is the signed-note key hash under the host of its base URL', () => {
    const r = parseTrustedRoot(rootJson({ tlogs: [edJson()] }));
    expect(r.tlogs[0]!.v2).toEqual({ name: 'rekor2.test' });
    expect(r.tlogs[0]!.key.asymmetricKeyType).toBe('ed25519');
    expect(Buffer.from(r.tlogs[0]!.keyId).equals(v2.keyId)).toBe(true);
    expect(parseTrustedRoot(rootJson({ tlogs: [tlogJson(ec)] })).tlogs[0]!.v2).toBeUndefined();
  });
  it('as a CT log it is not used', () => {
    expect(parseTrustedRoot(rootJson({ ctlogs: [edJson()] })).ctlogs).toEqual([]);
  });
  it('an Ed25519 log without a usable base URL has no name to hash under', () => {
    const msg = /^log id is not the signed-note key hash of its key$/;
    expect(() => parseTrustedRoot(rootJson({ tlogs: [edJson({ baseUrl: undefined })] }))).toThrow(msg);
    expect(() => parseTrustedRoot(rootJson({ tlogs: [edJson({ baseUrl: 5 })] }))).toThrow(msg);
    // an id computed under some other name does not make a nameless log valid
    const der = spki(v2.pub);
    const other = createHash('sha256').update('Stryker was here!\n').update(Uint8Array.of(1)).update(der.subarray(der.length - 32)).digest();
    expect(() => parseTrustedRoot(rootJson({ tlogs: [edJson({ baseUrl: undefined }, other)] }))).toThrow(msg);
    // the hash under another host is not this log's id
    expect(() => parseTrustedRoot(rootJson({ tlogs: [edJson({ baseUrl: 'https://elsewhere.test' })] }))).toThrow(msg);
  });
});

describe('rsaKeyOk with partial key details', () => {
  const key = (details: Record<string, unknown> | undefined, type = 'rsa'): KeyObject => ({ asymmetricKeyType: type, asymmetricKeyDetails: details }) as unknown as KeyObject;
  it('both the modulus size and the exponent must be known', () => {
    expect(rsaKeyOk(key({ publicExponent: 65537n }))).toBe(false);
    expect(rsaKeyOk(key({ modulusLength: 2048 }))).toBe(false);
    expect(rsaKeyOk(key({ modulusLength: 2048, publicExponent: 65537n }))).toBe(true);
    expect(rsaKeyOk(key({ publicExponent: 65537n }, 'rsa-pss'))).toBe(false);
    expect(rsaKeyOk(key({ modulusLength: 2048 }, 'rsa-pss'))).toBe(false);
  });
  it('the exponent is below 2^32', () => {
    expect(rsaKeyOk(key({ modulusLength: 2048, publicExponent: 2n ** 32n }))).toBe(false);
    expect(rsaKeyOk(key({ modulusLength: 2048, publicExponent: 2n ** 32n - 1n }))).toBe(true);
  });
});
