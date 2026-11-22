// Sigstore bundle verification, end to end over minted bundles (private PKI and logs, every signature re-made around each
// change): every refusal carries its exact code and detail, every accepting boundary is tested on both sides.
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifySigstoreBundle, verifySigstoreBundleCore, type PinnedRoots } from './sigstore';
import { cat, ctxPrim, extension, forgeKey, oid, seq, tlv, utf8 } from './test-support/forge-x509';
import {
  HOUR,
  IDENTITY,
  ISSUER_URL,
  MEDIA_V02,
  MEDIA_V03,
  MEDIA_V03B,
  OID,
  T0,
  b64,
  mint,
  mintCa,
  type LeafOpts,
  type MintOpts,
  type Minted,
} from './test-support/forge-sigstore';

const SLSA = 'https://slsa.dev/provenance/v1';
const why = (m: Minted): string => {
  const r = verifySigstoreBundleCore(m.bundle, { roots: m.roots });
  return r.ok ? 'ok' : `${r.code}: ${r.detail}`;
};
const w = (o?: MintOpts): string => why(mint(o));
const coreOf = (o?: MintOpts) => {
  const m = mint(o);
  const r = verifySigstoreBundleCore(m.bundle, { roots: m.roots });
  if (!r.ok) throw new Error(`${r.code}: ${r.detail}`);
  return r.core;
};
const oneTlog = (f: (l: PinnedRoots['tlogs'][number]) => PinnedRoots['tlogs'][number]) => (r: PinnedRoots) => ({ ...r, tlogs: [f(r.tlogs[0]!)] });
const oneCa = (f: (c: PinnedRoots['cas'][number]) => PinnedRoots['cas'][number]) => (r: PinnedRoots) => ({ ...r, cas: [f(r.cas[0]!)] });

describe('minted bundles: accepted forms', () => {
  const base = {
    identity: IDENTITY,
    oidc_issuer: ISSUER_URL,
    source_repo: 'https://example.test/org/repo',
    source_ref: 'refs/heads/main',
    source_digest: 'd'.repeat(40),
    predicate_type: SLSA,
    subjects: [{ alg: 'sha256', digest: 'ab'.repeat(32) }],
    signed_time: T0 / 1000,
    rekor_log_index: 12345,
    rekor: 'v1',
    timestamps: { tsa: 0, set: true },
  };
  it('Rekor v1 dsse with a signed entry timestamp', () => {
    expect(coreOf()).toStrictEqual(base);
  });
  it('Rekor v1 intoto', () => {
    expect(coreOf({ rekor: 'intoto' })).toStrictEqual(base);
  });
  it('Rekor v2 hashedrekord with an RFC 3161 time: the verified inclusion index is reported', () => {
    expect(coreOf({ rekor: 'v2' })).toStrictEqual({ ...base, rekor: 'v2', rekor_log_index: 0, timestamps: { tsa: 1, set: false } });
  });
  it('Rekor v1 with an RFC 3161 time only, and with both time sources (the earliest is reported)', () => {
    expect(coreOf({ set: false, tsa: [{}] })).toStrictEqual({ ...base, rekor_log_index: 0, timestamps: { tsa: 1, set: false } });
    expect(coreOf({ tsa: [{ genTime: new Date(T0 - 5000) }] })).toStrictEqual({ ...base, signed_time: T0 / 1000 - 5, timestamps: { tsa: 1, set: true } });
  });
  it('the other accepted media types, and the v0.2 certificate chain form', () => {
    expect(w({ media: MEDIA_V03B })).toBe('ok');
    expect(w({ media: MEDIA_V02 })).toBe('ok');
  });
  it('optional certificate facts are absent, not undefined, when the certificate lacks them', () => {
    const c = coreOf({ leaf: { repo: null, digest: null, ref: null } });
    expect(Object.keys(c).sort()).toEqual(['identity', 'oidc_issuer', 'predicate_type', 'rekor', 'rekor_log_index', 'signed_time', 'subjects', 'timestamps']);
    for (const leaf of [{ repo: null }, { digest: null }, { ref: null }] as LeafOpts[]) {
      expect(Object.keys(coreOf({ leaf })).length).toBe(Object.keys(base).length - 1);
    }
  });
  it('an email SAN is an identity; a URI SAN is an identity', () => {
    expect(coreOf({ leaf: { san: [ctxPrim(1, new TextEncoder().encode('dev@example.test'))] } }).identity).toBe('dev@example.test');
  });
  it('either issuer extension alone, or both when equal', () => {
    expect(coreOf({ leaf: { issuerV2: null, issuerV1: 'https://one.test' } }).oidc_issuer).toBe('https://one.test');
    expect(coreOf({ leaf: { issuerV1: null, issuerV2: 'https://two.test' } }).oidc_issuer).toBe('https://two.test');
    expect(coreOf({ leaf: { issuerV1: 'https://same.test', issuerV2: 'https://same.test' } }).oidc_issuer).toBe('https://same.test');
  });
  it('a P-384 leaf is verified under SHA-384 (Rekor v1 and v2)', () => {
    expect(w({ leaf: { curve: 'P-384' } })).toBe('ok');
    expect(w({ rekor: 'v2', leaf: { curve: 'P-384' } })).toBe('ok');
  });
  it('subject digests: sha256 and sha512 are kept, others and non-strings are dropped; 64 subjects pass', () => {
    const c = coreOf({
      statement: (s) => {
        s.subject = [{ digest: { sha256: 'aa', sha512: 'bb', md5: 'cc' } }, { digest: { sha256: 5 } }, 'x', null, { name: 'no digest' }];
      },
    });
    expect(c.subjects).toEqual([{ alg: 'sha256', digest: 'aa' }, { alg: 'sha512', digest: 'bb' }]);
    expect(w({ statement: (s) => { s.subject = Array.from({ length: 64 }, () => ({ digest: { sha256: 'aa' } })); } })).toBe('ok');
  });
});

describe('bundle shape', () => {
  it('not a bundle', () => {
    const roots = mint().roots;
    for (const b of [null, undefined, 5, 'x', [], {}, { mediaType: MEDIA_V03 }, { verificationMaterial: [] }, { verificationMaterial: null }]) {
      expect(verifySigstoreBundleCore(b, { roots })).toEqual({ ok: false, code: 'malformed', detail: 'not a bundle' });
    }
  });
  it('media type', () => {
    expect(w({ bundle: (b) => { b.mediaType = 'x'; } })).toBe('media_type: unsupported media type x');
    expect(w({ bundle: (b) => { delete b.mediaType; } })).toBe('media_type: unsupported media type undefined');
    expect(w({ bundle: (b) => { b.mediaType = 'application/vnd.dev.sigstore.bundle+json;version=0.1'; } })).toMatch(/^media_type: unsupported media type /);
  });
  it('a bundle without a Fulcio certificate is not keyless', () => {
    const msg = 'not_keyless: no Fulcio certificate (public-key bundles are not supported)';
    expect(w({ bundle: (b) => { delete b.verificationMaterial.certificate; } })).toBe(msg);
    expect(w({ bundle: (b) => { b.verificationMaterial.certificate = 'x'; } })).toBe(msg);
    expect(w({ bundle: (b) => { b.verificationMaterial.certificate = {}; } })).toBe(msg);
    expect(w({ media: MEDIA_V02, bundle: (b) => { delete b.verificationMaterial.x509CertificateChain; } })).toBe(msg);
    expect(w({ media: MEDIA_V02, bundle: (b) => { b.verificationMaterial.x509CertificateChain = { certificates: [] }; } })).toBe(msg);
    expect(w({ media: MEDIA_V02, bundle: (b) => { b.verificationMaterial.x509CertificateChain = { certificates: ['x'] }; } })).toBe(msg);
    expect(w({ media: MEDIA_V02, bundle: (b) => { b.verificationMaterial.x509CertificateChain = { certificates: {} }; } })).toBe(msg);
    // a v0.3 bundle does not take the v0.2 form and the other way round
    expect(w({ bundle: (b) => { b.verificationMaterial.x509CertificateChain = { certificates: [b.verificationMaterial.certificate] }; delete b.verificationMaterial.certificate; } })).toBe(msg);
  });
  it('the envelope: a DSSE envelope with one signature and the in-toto payload type', () => {
    expect(w({ bundle: (b) => { delete b.dsseEnvelope; } })).toBe('envelope: not a DSSE bundle');
    expect(w({ bundle: (b) => { b.dsseEnvelope = 'x'; } })).toBe('envelope: not a DSSE bundle');
    expect(w({ bundle: (b) => { b.messageSignature = {}; } })).toBe('envelope: not a DSSE bundle');
    expect(w({ bundle: (b) => { b.dsseEnvelope.payloadType = 'application/json'; } })).toBe('envelope: payloadType is not application/vnd.in-toto+json');
    const one = 'envelope: a DSSE envelope must carry exactly one signature';
    expect(w({ bundle: (b) => { b.dsseEnvelope.signatures = {}; } })).toBe(one);
    expect(w({ bundle: (b) => { b.dsseEnvelope.signatures = []; } })).toBe(one);
    expect(w({ bundle: (b) => { b.dsseEnvelope.signatures.push(b.dsseEnvelope.signatures[0]); } })).toBe(one);
    expect(w({ bundle: (b) => { b.dsseEnvelope.signatures = ['x']; } })).toBe(one);
  });
  it('base64 is strict: alphabet, padding position, length', () => {
    const bad = 'malformed: fail closed: not base64';
    for (const s of ['!!!!', 'AAA', 'AA=A', '!AAA', 'AAA!', 'AAAA===', 'A A A']) {
      expect(w({ bundle: (b) => { b.dsseEnvelope.payload = s; } }), s).toBe(bad);
      expect(w({ bundle: (b) => { b.dsseEnvelope.signatures[0].sig = s; } }), s).toBe(bad);
    }
    // a non-string that stringifies like base64 is still not a string
    expect(w({ bundle: (b) => { b.dsseEnvelope.payload = { toString: () => 'AAAA', length: 4 }; } })).toBe(bad);
    expect(w({ bundle: (b) => { b.dsseEnvelope.payload = 5; } })).toBe(bad);
    expect(w({ bundle: (b) => { b.dsseEnvelope.payload = ['AAAA']; } })).toBe(bad);
  });
  it('a thrown non-Error is reported as a plain failure', () => {
    const roots = mint().roots;
    const b = { mediaType: MEDIA_V03, verificationMaterial: { certificate: { rawBytes: 'AAAA' } }, dsseEnvelope: { payloadType: 'application/vnd.in-toto+json', signatures: [{ sig: 'AAAA' }], get payload(): string { throw 'boom'; } } };
    expect(verifySigstoreBundleCore(b, { roots })).toEqual({ ok: false, code: 'malformed', detail: 'fail closed: error' });
  });
});

describe('the certificate as parsed', () => {
  it('bytes that are not a certificate', () => {
    expect(w({ bundle: (b) => { b.verificationMaterial.certificate.rawBytes = b64('this is not a certificate'); } })).toMatch(/^cert_parse: /);
  });
  it('a certificate with bytes after it is not one SEQUENCE', () => {
    expect(w({ bundle: (b) => { b.verificationMaterial.certificate.rawBytes = b64(cat(Buffer.from(b.verificationMaterial.certificate.rawBytes, 'base64'), Uint8Array.of(0))); } })).toBe('cert_parse: fail closed: certificate is not one SEQUENCE');
  });
  it('a certificate without extensions', () => {
    expect(w({ leaf: { exts: () => [] } })).toBe('cert_parse: fail closed: no extensions');
  });
  it('a repeated extension', () => {
    expect(w({ leaf: { exts: (base) => [...base, base[base.length - 1]!] } })).toBe(`cert_parse: fail closed: duplicate extension ${OID.fulcio}14`);
  });
});

describe('the log entry', () => {
  it('exactly one entry', () => {
    const msg = 'tlog_count: exactly one transparency log entry is required';
    expect(w({ bundle: (b) => { b.verificationMaterial.tlogEntries = 'x'; } })).toBe(msg);
    expect(w({ bundle: (b) => { b.verificationMaterial.tlogEntries = []; } })).toBe(msg);
    expect(w({ bundle: (b) => { b.verificationMaterial.tlogEntries.push(b.verificationMaterial.tlogEntries[0]); } })).toBe(msg);
    expect(w({ bundle: (b) => { b.verificationMaterial.tlogEntries = ['x']; } })).toBe(msg);
  });
  it('the entry kind and version', () => {
    expect(w({ entry: (e) => { delete e.kindVersion; } })).toBe('tlog_kind: unsupported entry ');
    expect(w({ entry: (e) => { e.kindVersion = { kind: 'dsse', version: '0.0.2' }; } })).toBe('tlog_kind: unsupported entry dsse/0.0.2');
    expect(w({ entry: (e) => { e.kindVersion = { kind: 5, version: '0.0.1' }; } })).toBe('tlog_kind: unsupported entry ');
    expect(w({ entry: (e) => { e.kindVersion = { kind: 'dsse', version: 1 }; } })).toBe('tlog_kind: unsupported entry ');
  });
  it('the log must be pinned, and of the version the entry type needs', () => {
    expect(w({ entry: (e) => { e.logId = { keyId: b64(new Uint8Array(32)) }; } })).toBe('tlog_key: the entry names a log the verifier did not pin');
    expect(w({ rekor: 'v2', roots: oneTlog((l) => ({ ...l, v2: undefined })) })).toBe('tlog_key: the entry type does not match the log version');
    expect(w({ roots: oneTlog((l) => ({ ...l, v2: { name: 'rekor.test' } })) })).toBe('tlog_key: the entry type does not match the log version');
  });
  it('unreadable log id, log index or body fail closed at the log-key stage', () => {
    expect(w({ entry: (e) => { delete e.logId; } })).toBe('tlog_key: fail closed: not base64');
    expect(w({ entry: (e) => { e.canonicalizedBody = '!!!!'; } })).toBe('tlog_key: fail closed: not base64');
    for (const v of ['01', '-1', 'x12', '12x', '', ' 12', '12 ', 12]) {
      expect(w({ entry: (e) => { e.logIndex = v; } }), String(v)).toBe('tlog_key: fail closed: not a decimal integer string');
    }
    expect(w({ entry: (e) => { e.logIndex = '9007199254740993'; } })).toBe('tlog_key: fail closed: integer out of range');
    expect(w({ entry: (e) => { e.logIndex = '1234567890123456789'; } })).toBe('tlog_key: fail closed: not a decimal integer string');
  });
});

describe('signing time', () => {
  it('a Rekor v1 entry with no signed entry timestamp and no RFC 3161 timestamp has no verified time', () => {
    expect(w({ set: false })).toBe('no_verified_time: no verified time: no RFC 3161 timestamp and no Rekor v1 signed entry timestamp');
  });
  it('a timestamp entry that is not an object', () => {
    expect(w({ bundle: (b) => { b.verificationMaterial.timestampVerificationData = { rfc3161Timestamps: ['x'] }; } })).toBe('tsa: fail closed: not base64');
  });
  it('the signed entry timestamp: integrated time and signature', () => {
    expect(w({ entry: (e) => { e.integratedTime = 'x'; } })).toBe('tlog_set: fail closed: not a decimal integer string');
    expect(w({ entry: (e) => { e.inclusionPromise.signedEntryTimestamp = '!!!!'; } })).toBe('tlog_set: fail closed: not base64');
    expect(w({ entry: (e) => { e.integratedTime = String(Number(e.integratedTime) + 1); } })).toBe('tlog_set: signed entry timestamp invalid');
    expect(w({ entry: (e) => { e.logIndex = '12346'; } })).toBe('tlog_set: signed entry timestamp invalid');
  });
  it('the log key must have been valid at every signing time, inclusive at both ends', () => {
    const msg = 'tlog_key: the log key was not valid at a signing time';
    const win = (start: number, end: number) => oneTlog((l) => ({ ...l, valid: { start, end } }));
    expect(w({ roots: win(T0, T0) })).toBe('ok');
    expect(w({ roots: win(T0 + 1, T0 + HOUR) })).toBe(msg);
    expect(w({ roots: win(T0 - HOUR, T0 - 1) })).toBe(msg);
    expect(w({ roots: win(T0 - HOUR, T0 + HOUR) })).toBe('ok');
  });
});

describe('the inclusion proof and the checkpoint', () => {
  it('a missing proof', () => {
    const msg = 'tlog_inclusion: no inclusion proof';
    expect(w({ entry: (e) => { delete e.inclusionProof; } })).toBe(msg);
    expect(w({ entry: (e) => { e.inclusionProof = []; } })).toBe(msg);
    expect(w({ entry: (e) => { delete e.inclusionProof.hashes; } })).toBe(msg);
    expect(w({ entry: (e) => { delete e.inclusionProof.checkpoint; } })).toBe(msg);
    expect(w({ entry: (e) => { e.inclusionProof.checkpoint = 'x'; } })).toBe(msg);
  });
  it('an unreadable or wrong proof', () => {
    expect(w({ entry: (e) => { e.inclusionProof.rootHash = '!!!!'; } })).toBe('tlog_inclusion: fail closed: not base64');
    expect(w({ entry: (e) => { e.inclusionProof.treeSize = 'x'; } })).toBe('tlog_inclusion: fail closed: not a decimal integer string');
    expect(w({ entry: (e) => { e.inclusionProof.logIndex = 'x'; } })).toBe('tlog_inclusion: fail closed: not a decimal integer string');
    expect(w({ entry: (e) => { e.inclusionProof.rootHash = b64(new Uint8Array(32)); } })).toBe('tlog_inclusion: the inclusion proof does not lead to the root');
  });
  it('the checkpoint envelope is a string', () => {
    expect(w({ entry: (e) => { e.inclusionProof.checkpoint.envelope = 5; } })).toBe('tlog_checkpoint: the checkpoint envelope is not a string');
    expect(w({ entry: (e) => { e.inclusionProof.checkpoint.envelope = ['x']; } })).toBe('tlog_checkpoint: the checkpoint envelope is not a string');
  });
  const cp = (f: (c: { origin: string; rootB64: string; text: string; sigLine: string; body: string }) => string) => (c: Parameters<NonNullable<MintOpts['checkpoint']>>[0]) => {
    const body = `${c.origin}\n1\n${c.rootB64}\n`;
    const sigLine = c.text.slice(body.length + 1);
    return f({ origin: c.origin, rootB64: c.rootB64, text: c.text, sigLine, body });
  };
  it('the signature block, the body, the size and the root', () => {
    const t = (checkpoint: MintOpts['checkpoint'], rekor: MintOpts['rekor'] = 'dsse') => w({ rekor, checkpoint });
    expect(t(cp((c) => c.body))).toBe('tlog_checkpoint: checkpoint has no signature block');
    expect(t(cp((c) => `\n\n${c.sigLine}`))).toBe('tlog_checkpoint: checkpoint body too short or without an origin');
    expect(t(cp((c) => `${c.origin}\n1\n\n${c.sigLine}`))).toBe('tlog_checkpoint: checkpoint body too short or without an origin');
    expect(t(cp((c) => `\n1\n${c.rootB64}\n\n${c.sigLine}`))).toBe('tlog_checkpoint: checkpoint body too short or without an origin');
    for (const size of ['2', '0', '01', '1 ', ' 1', 'x', '1x']) {
      expect(t(cp((c) => `${c.origin}\n${size}\n${c.rootB64}\n\n${c.sigLine}`)), JSON.stringify(size)).toBe('tlog_checkpoint: checkpoint size differs from the proof');
    }
    expect(t(cp((c) => `${c.origin}\n1\n${b64(new Uint8Array(32))}\n\n${c.sigLine}`))).toBe('tlog_checkpoint: checkpoint root differs from the proof');
    expect(t(cp((c) => `${c.origin}\n1\n!!!!\n\n${c.sigLine}`))).toBe('tlog_checkpoint: fail closed: not base64');
  });
  it('only signature lines of the block are read, and only whole lines', () => {
    const good = (c: { sigLine: string }) => c.sigLine;
    // a body line shaped like a signature line is part of the signed body, not a signature line
    expect(
      w({
        checkpoint: (c) => {
          const body = `\u2014 ${c.name} AA=A\n1\n${c.rootB64}\n`;
          return `${body}\n\u2014 ${c.name} ${b64(Buffer.concat([c.keyId.subarray(0, 4), c.sign(body)]))}\n`;
        },
      }),
    ).toBe('ok');
    // a witness line before the log's own is skipped, not parsed
    expect(w({ checkpoint: cp((c) => `${c.body}\nsome other line\n${good(c)}`) })).toBe('ok');
    // junk before or after the signature line makes it a different line
    expect(w({ checkpoint: cp((c) => `${c.body}\njunk ${good(c)}`) })).toBe('tlog_checkpoint: no checkpoint signature by the pinned log key');
    expect(w({ checkpoint: cp((c) => `${c.body}\n${good(c).trimEnd()}!\n`) })).toBe('tlog_checkpoint: no checkpoint signature by the pinned log key');
    expect(w({ checkpoint: cp((c) => `${c.body}\n${good(c).trimEnd()} trailing\n`) })).toBe('tlog_checkpoint: no checkpoint signature by the pinned log key');
  });
  it('the key hint and the note name must match the pinned log', () => {
    const none = 'tlog_checkpoint: no checkpoint signature by the pinned log key';
    const line = (c: Parameters<NonNullable<MintOpts['checkpoint']>>[0], hint: Buffer, name: string, sig: Buffer = c.sign(`${c.origin}\n1\n${c.rootB64}\n`)) =>
      `${c.origin}\n1\n${c.rootB64}\n\n— ${name} ${b64(Buffer.concat([hint, sig]))}\n`;
    // a valid signature under a wrong hint is not the pinned log's line
    expect(w({ checkpoint: (c) => line(c, Buffer.alloc(4), c.name) })).toBe(none);
    expect(w({ checkpoint: (c) => line(c, c.keyId.subarray(0, 4), c.name) })).toBe('ok');
    // too short to hold a signature (a hint alone, a hint and one byte)
    expect(w({ checkpoint: (c) => line(c, c.keyId.subarray(0, 4), c.name, Buffer.alloc(0)) })).toBe(none);
    expect(w({ checkpoint: (c) => line(c, c.keyId.subarray(0, 4), c.name, Buffer.alloc(1)) })).toBe(none);
    expect(w({ checkpoint: (c) => line(c, c.keyId.subarray(0, 3), c.name, Buffer.alloc(0)) })).toBe(none);
    // Rekor v2: the note name is part of the key
    expect(w({ rekor: 'v2', checkpoint: (c) => line(c, c.keyId.subarray(0, 4), 'other.test') })).toBe(none);
    expect(w({ rekor: 'v2', checkpoint: (c) => line(c, c.keyId.subarray(0, 4), c.name) })).toBe('ok');
    // Rekor v1 does not look at the name
    expect(w({ checkpoint: (c) => line(c, c.keyId.subarray(0, 4), 'any.name') })).toBe('ok');
  });
  it('a checkpoint signed by another key is refused', () => {
    const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
    expect(w({ checkpoint: (c) => c.text.replace(/— (\S+) (\S+)/, (_m, n: string) => `— ${n} ${b64(Buffer.concat([c.keyId.subarray(0, 4), nodeSign('sha256', Buffer.from(`${c.origin}\n1\n${c.rootB64}\n`), other)]))}`) })).toBe('tlog_checkpoint: no checkpoint signature by the pinned log key');
  });
});

describe('the certificate path', () => {
  const NO_CA = 'cert_chain: no pinned CA issued the certificate, valid at every signing time';
  it('no pinned CA issued the certificate', () => {
    expect(w({ roots: (r) => ({ ...r, cas: [{ chain: [mintCa('someone-else').x509], valid: r.cas[0]!.valid }] }) })).toBe(NO_CA);
  });
  it('the pinned validity of a CA is inclusive and holds at every signing time', () => {
    const win = (start: number, end: number) => oneCa((c) => ({ ...c, valid: { start, end } }));
    expect(w({ roots: win(T0, T0) })).toBe('ok');
    expect(w({ roots: win(T0 + 1, T0 + HOUR) })).toBe(NO_CA);
    expect(w({ roots: win(T0 - HOUR, T0 - 1) })).toBe(NO_CA);
    // two signing times, one outside the pin
    const two = { tsa: [{ genTime: new Date(T0) }], integratedOffsetSec: 7200, leaf: { to: new Date(T0 + 3 * HOUR) } };
    expect(w({ ...two, roots: win(T0 - HOUR, T0 + HOUR) })).toBe(NO_CA);
    expect(w({ ...two, roots: win(T0 - HOUR, T0 + 3 * HOUR) })).toBe('ok');
  });
  it('the CA certificate itself must be valid at every signing time', () => {
    const two = { tsa: [{ genTime: new Date(T0) }], integratedOffsetSec: 7200, leaf: { to: new Date(T0 + 3 * HOUR) } };
    expect(w({ ...two, caOpts: { to: new Date(T0 + HOUR) } })).toBe(NO_CA);
    expect(w({ ...two, caOpts: { to: new Date(T0 + 3 * HOUR) } })).toBe('ok');
    expect(w({ caOpts: { to: new Date(T0 - HOUR) } })).toBe(NO_CA);
    expect(w({ caOpts: { from: new Date(T0 + HOUR) } })).toBe(NO_CA);
  });
  it('every link of the pinned chain must be issued by the next, signed by it, and in date', () => {
    // issuer name differs from the subject, signature and dates are right
    expect(w({ caOpts: { issuerName: [['O', 'elsewhere'], ['CN', 'nobody']] } })).toBe(NO_CA);
    // names match, but another key signed it
    expect(w({ caOpts: { signer: forgeKey('another-signer', 'P-256') } })).toBe(NO_CA);
  });
  it('a chain through an intermediate is accepted; a non-CA link anywhere in it is not', () => {
    const root = mintCa('root');
    const viaMid = (m: ReturnType<typeof mint>) => ({ ...m.roots, cas: [{ ...m.roots.cas[0]!, chain: [m.roots.cas[0]!.chain[0]!, root.x509] }] });
    const m = mint({ caOpts: { parent: root } });
    expect(why({ ...m, roots: viaMid(m) })).toBe('ok');
    const bad = mint({ caOpts: { parent: root, isCa: false } });
    expect(why({ ...bad, roots: viaMid(bad) })).toBe(NO_CA);
  });
  it('a CA certificate as the leaf, by basicConstraints or by the CA flag', () => {
    expect(w({ leaf: { bc: 'ca' } })).toBe('cert_chain: the leaf is a CA certificate');
    expect(w({ leaf: { bc: 'false' } })).toBe('ok');
  });
  it('a basicConstraints extension that does not make the leaf a CA is read as such', () => {
    for (const bc of ['empty', 'pathlen'] as const) expect(w({ leaf: { bc } }), bc).toBe('ok');
    // a value that is not a SEQUENCE, or a two-byte BOOLEAN, never gets that far: OpenSSL cannot parse the extension, so no pinned CA is found to have issued it
    for (const bc of ['octet', 'bool2'] as const) expect(w({ leaf: { bc } }), bc).toBe(NO_CA);
  });
  it('basicConstraints is read with the strict DER reader once the leaf is known to be issued by the pinned CA', () => {
    expect(w({ leaf: { bc: 'ber' } })).toBe('cert_chain: fail closed: DER length');
  });
  it('an extension value written as a constructed OCTET STRING is refused', () => {
    const constructed = seq(oid(`${OID.fulcio}14`), tlv(0x24, tlv(0x04, new TextEncoder().encode('refs/heads/x'))));
    expect(w({ leaf: { ref: null, exts: (base) => [...base, constructed] } })).toBe('cert_parse: fail closed: extension value is not an OCTET STRING');
  });
  it('the leaf must be valid at every signing time, up to and including its last second', () => {
    expect(w({ leaf: { to: new Date(T0) } })).toBe('ok');
    expect(w({ leaf: { to: new Date(T0 - 1000) } })).toBe('cert_time: the certificate was not valid at a signing time');
    expect(w({ leaf: { from: new Date(T0 + 1000) } })).toBe('cert_time: the certificate was not valid at a signing time');
  });
  it('the code-signing extended key usage', () => {
    const msg = 'cert_eku: the certificate lacks the code-signing EKU';
    expect(w({ leaf: { eku: ['1.3.6.1.5.5.7.3.1'] } })).toBe(msg);
    expect(w({ leaf: { eku: null } })).toBe(msg);
    expect(w({ leaf: { eku: ['1.3.6.1.5.5.7.3.1', OID.codeSigning] } })).toBe('ok');
  });
});

describe('the entry body names this envelope', () => {
  const BODY = 'tlog_body: the entry body is not the kind the bundle names';
  it('kind and version', () => {
    expect(w({ body: (b) => { delete b.kind; } })).toBe(BODY);
    expect(w({ body: (b) => { b.kind = 5; } })).toBe(BODY);
    expect(w({ body: (b) => { delete b.apiVersion; } })).toBe(BODY);
    expect(w({ body: (b) => { b.apiVersion = 1; } })).toBe(BODY);
    expect(w({ body: (b) => { b.kind = 'intoto'; } })).toBe(BODY);
    expect(w({ body: (b) => { b.apiVersion = '0.0.9'; } })).toBe(BODY);
  });
  const PAYLOAD = 'tlog_body: the entry names another payload';
  const ONE = 'tlog_body: the entry must name exactly one signature';
  const SIG = 'tlog_body: the entry names another signature';
  const CERT = 'tlog_body: the entry names another certificate';
  const pemOfLeaf = (m: Minted, f: (pem: string) => string) => b64(f(`-----BEGIN CERTIFICATE-----\n${Buffer.from(m.leafDer).toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----\n`));
  it('Rekor v1 dsse', () => {
    expect(w({ body: (b) => { b.spec.payloadHash.algorithm = 'sha512'; } })).toBe(PAYLOAD);
    expect(w({ body: (b) => { b.spec.payloadHash.value = 'ab'.repeat(32); } })).toBe(PAYLOAD);
    expect(w({ body: (b) => { delete b.spec.payloadHash; } })).toBe(PAYLOAD);
    expect(w({ body: (b) => { delete b.spec.signatures; } })).toBe(ONE);
    expect(w({ body: (b) => { b.spec.signatures.push(b.spec.signatures[0]); } })).toBe(ONE);
    expect(w({ body: (b) => { b.spec.signatures = ['x']; } })).toBe(ONE);
    expect(w({ body: (b) => { b.spec.signatures[0].signature = b64('another'); } })).toBe(SIG);
    expect(w({ body: (b) => { b.spec.signatures[0].verifier = b64('not a pem'); } })).toBe(CERT);
    expect(w({ body: (b) => { b.spec.signatures[0].verifier = b64('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n'); } })).toBe(CERT);
  });
  it('the PEM of the logged certificate is read whole', () => {
    // the leaf is deterministic, so a second mint carries the very same certificate
    const m = mint();
    const run = (f: (p: string) => string) => w({ body: (b) => { b.spec.signatures[0].verifier = pemOfLeaf(m, f); } });
    expect(run((p) => p)).toBe('ok');
    expect(run((p) => p.trimEnd())).toBe('ok');
    expect(run((p) => `junk${p}`)).toBe(CERT);
    expect(run((p) => `${p}junk`)).toBe(CERT);
    expect(run((p) => `${p}\n`)).toBe(CERT);
    expect(run((p) => ` ${p}`)).toBe(CERT);
    expect(run((p) => p.replace('-----BEGIN CERTIFICATE-----\n', '-----BEGIN CERTIFICATE-----'))).toBe(CERT);
    expect(run((p) => p.replace('\n-----END', '!-----END'))).toBe(CERT);
  });
  it('Rekor v1 intoto', () => {
    const o = (body: (b: any) => void) => w({ rekor: 'intoto', body });
    expect(o((b) => { b.spec.content.payloadHash.algorithm = 'sha512'; })).toBe(PAYLOAD);
    expect(o((b) => { b.spec.content.payloadHash.value = 'ab'.repeat(32); })).toBe(PAYLOAD);
    expect(o((b) => { delete b.spec.content; })).toBe(PAYLOAD);
    expect(o((b) => { delete b.spec.content.envelope; })).toBe(ONE);
    expect(o((b) => { b.spec.content.envelope.signatures.push(b.spec.content.envelope.signatures[0]); })).toBe(ONE);
    expect(o((b) => { b.spec.content.envelope.signatures = ['x']; })).toBe(ONE);
    expect(o((b) => { b.spec.content.envelope.signatures[0].sig = b64(b64('another')); })).toBe(SIG);
    expect(o((b) => { b.spec.content.envelope.signatures[0].sig = b64('plain'); })).toMatch(/^tlog_body: /);
    expect(o((b) => { b.spec.content.envelope.signatures[0].publicKey = b64('not a pem'); })).toBe(CERT);
  });
  it('Rekor v2 hashedrekord', () => {
    const o = (body: (b: any) => void) => w({ rekor: 'v2', body });
    const ALG = "tlog_body: the entry digest algorithm is not the signing key's";
    expect(o((b) => { b.spec.hashedRekordV002.data.algorithm = 'SHA2_384'; })).toBe(ALG);
    expect(o((b) => { b.spec.hashedRekordV002.data.algorithm = 'SHA2_512'; })).toBe(ALG);
    expect(o((b) => { b.spec.hashedRekordV002.data.algorithm = 'MD5'; })).toBe(ALG);
    expect(o((b) => { delete b.spec.hashedRekordV002.data; })).toBe(ALG);
    expect(o((b) => { delete b.spec.hashedRekordV002; })).toBe(ALG);
    expect(w({ rekor: 'v2', leaf: { curve: 'P-384' }, body: (b) => { b.spec.hashedRekordV002.data.algorithm = 'SHA2_256'; } })).toBe(ALG);
    expect(o((b) => { b.spec.hashedRekordV002.data.digest = b64(new Uint8Array(32)); })).toBe('tlog_body: the entry names another envelope');
    expect(w({ rekor: 'v2', leaf: { curve: 'P-384' }, body: (b) => { b.spec.hashedRekordV002.data.digest = b64(new Uint8Array(48)); } })).toBe('tlog_body: the entry names another envelope');
    expect(o((b) => { b.spec.hashedRekordV002.signature.content = b64('another'); })).toBe(SIG);
    expect(o((b) => { delete b.spec.hashedRekordV002.signature; })).toBe('tlog_body: fail closed: not base64');
    expect(o((b) => { b.spec.hashedRekordV002.signature.verifier.x509Certificate.rawBytes = b64('another'); })).toBe(CERT);
    expect(o((b) => { b.spec.hashedRekordV002.signature.verifier = { x509Certificate: 'x' }; })).toBe('tlog_body: fail closed: not base64');
    expect(o((b) => { b.spec.hashedRekordV002.signature.verifier = 'x'; })).toBe('tlog_body: fail closed: not base64');
    expect(o((b) => { b.spec.hashedRekordV002.signature.verifier = {}; })).toBe('tlog_body: fail closed: not base64');
  });
});

describe('the DSSE signature, the identity and the statement', () => {
  it('the envelope signature must verify under the leaf key', () => {
    expect(w({ dsseKey: forgeKey('not-the-leaf', 'P-256') })).toBe('signature: DSSE signature invalid');
  });
  it('a leaf key of a type the verifier does not use', () => {
    const ed = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' });
    expect(w({ leaf: { spki: new Uint8Array(ed) } })).toBe('signature: unsupported leaf key type');
    expect(w({ rekor: 'v2', leaf: { spki: new Uint8Array(ed) } })).toBe("tlog_body: the entry digest algorithm is not the signing key's");
  });
  it('subject alternative name', () => {
    expect(w({ leaf: { noSan: true } })).toBe('identity: fail closed: no subjectAltName');
    const two = [ctxPrim(6, new TextEncoder().encode('https://a.test')), ctxPrim(6, new TextEncoder().encode('https://b.test'))];
    expect(w({ leaf: { san: two } })).toBe('identity: fail closed: subjectAltName must hold exactly one name');
    expect(w({ leaf: { san: [ctxPrim(2, new TextEncoder().encode('host.test'))] } })).toBe('identity: fail closed: subjectAltName must be a URI or an email');
  });
  it('issuer extensions', () => {
    expect(w({ leaf: { issuerV1: 'https://a.test', issuerV2: 'https://b.test' } })).toBe('identity: the two issuer extensions disagree');
    expect(w({ leaf: { issuerV1: null, issuerV2: null } })).toBe('identity: no OIDC issuer extension');
    expect(w({ leaf: { issuerV1: '', issuerV2: null } })).toBe('identity: no OIDC issuer extension');
  });
  it('the newer issuer extension is a DER UTF8String, exactly', () => {
    const bad = (v: Uint8Array) => w({ leaf: { issuerV1: null, issuerV2: null, exts: (base) => [...base, extension(`${OID.fulcio}8`, false, v)] } });
    const msg = 'identity: fail closed: extension .1.8 is not a DER UTF8String';
    expect(bad(tlv(0x13, new TextEncoder().encode('https://a.test')))).toBe(msg);
    expect(bad(cat(utf8('https://a.test'), Uint8Array.of(0)))).toBe(msg);
    expect(bad(utf8('https://a.test'))).toBe('ok');
  });
  it('certificate text must be valid UTF-8', () => {
    expect(w({ leaf: { issuerV1: null, issuerV2: null, exts: (base) => [...base, extension(`${OID.fulcio}1`, false, Uint8Array.of(0xff, 0xfe))] } })).toMatch(/^identity: fail closed: .*utf-8/i);
  });
  it('the statement', () => {
    const st = (f: (s: Record<string, unknown>) => void) => w({ statement: (s) => { f(s); } });
    expect(st((s) => { s._type = 'https://in-toto.io/Statement/v0.1'; })).toBe('statement: not an in-toto Statement v1');
    expect(st((s) => { delete s.subject; })).toBe('statement: no subject');
    expect(st((s) => { s.subject = []; })).toBe('statement: no subject');
    expect(st((s) => { s.subject = 'x'; })).toBe('statement: no subject');
    const none = 'statement: no sha256/sha512 subject digest (or more than 64)';
    expect(st((s) => { s.subject = [{ digest: { md5: 'aa' } }]; })).toBe(none);
    expect(st((s) => { s.subject = [{ name: 'x' }]; })).toBe(none);
    expect(st((s) => { s.subject = Array.from({ length: 65 }, () => ({ digest: { sha256: 'aa' } })); })).toBe(none);
    expect(st((s) => { delete s.predicateType; })).toBe('statement: no predicateType');
    expect(st((s) => { s.predicateType = 5; })).toBe('statement: no predicateType');
  });
  it('a payload that is not UTF-8 or not JSON', () => {
    expect(w({ rawPayload: Uint8Array.of(0x7b, 0xff, 0x7d) })).toMatch(/^statement: fail closed: .*utf-8/i);
    expect(w({ rawPayload: '{' })).toMatch(/^statement: fail closed: /);
  });
});

describe('verifySigstoreBundle: the SLSA v1 facts', () => {
  const facts = (o?: MintOpts) => {
    const m = mint(o);
    return verifySigstoreBundle(m.bundle, { roots: m.roots });
  };
  it('the facts of a good bundle', () => {
    expect(facts()).toStrictEqual({
      ok: true,
      facts: {
        v: 1,
        predicate_type: SLSA,
        build_type: 'https://example.test/build/v1',
        builder_id: 'https://example.test/builder',
        subjects: [{ alg: 'sha256', digest: 'ab'.repeat(32) }],
        identity: IDENTITY,
        oidc_issuer: ISSUER_URL,
        source_repo: 'https://example.test/org/repo',
        source_ref: 'refs/heads/main',
        source_digest: 'd'.repeat(40),
        provenance_source: { uri: 'git+https://example.test/org/repo@refs/heads/main', git_commit: 'c'.repeat(40) },
        integrated_time: T0 / 1000,
        rekor_log_index: 12345,
      },
    });
  });
  it('a verified bundle that is not SLSA v1 provenance', () => {
    expect(facts({ statement: (s) => { s.predicateType = 'https://slsa.dev/provenance/v0.2'; } })).toEqual({ ok: false, code: 'predicate', detail: 'predicate https://slsa.dev/provenance/v0.2 is not SLSA provenance v1' });
  });
  it('a failed core verification is returned as it is', () => {
    expect(facts({ set: false })).toEqual({ ok: false, code: 'no_verified_time', detail: 'no verified time: no RFC 3161 timestamp and no Rekor v1 signed entry timestamp' });
  });
  const need = { ok: false, code: 'predicate', detail: 'buildType, externalParameters and builder.id are required (SLSA Build L1)' };
  it('buildType, externalParameters and builder.id are required', () => {
    const f = (g: (p: any) => void) => facts({ statement: (s) => { g(s.predicate); } });
    expect(f((p) => { delete p.buildDefinition.buildType; })).toEqual(need);
    expect(f((p) => { p.buildDefinition.buildType = 5; })).toEqual(need);
    expect(f((p) => { delete p.runDetails.builder.id; })).toEqual(need);
    expect(f((p) => { p.runDetails.builder.id = 5; })).toEqual(need);
    expect(f((p) => { delete p.runDetails.builder; })).toEqual(need);
    expect(f((p) => { delete p.buildDefinition.externalParameters; })).toEqual(need);
    expect(f((p) => { p.buildDefinition.externalParameters = []; })).toEqual(need);
    expect(f((p) => { delete p.buildDefinition; })).toEqual(need);
    expect(f((p) => { delete p.runDetails; })).toEqual(need);
  });
  it('the build source comes from the first resolved dependency, and only what it carries', () => {
    const src = (g: (bd: any) => void) => {
      const r = facts({ statement: (s) => { g((s.predicate as any).buildDefinition); } });
      if (!r.ok) throw new Error(r.detail);
      return r.facts;
    };
    expect('provenance_source' in src((bd) => { delete bd.resolvedDependencies; })).toBe(false);
    expect('provenance_source' in src((bd) => { bd.resolvedDependencies = []; })).toBe(false);
    expect('provenance_source' in src((bd) => { bd.resolvedDependencies = { 0: { uri: 'git+x', digest: {} } }; })).toBe(false);
    expect('provenance_source' in src((bd) => { bd.resolvedDependencies = [5]; })).toBe(false);
    expect('provenance_source' in src((bd) => { bd.resolvedDependencies = [{ uri: 5, digest: { gitCommit: 'c'.repeat(40) } }]; })).toBe(false);
    expect('provenance_source' in src((bd) => { bd.resolvedDependencies = [{ digest: { gitCommit: 'c'.repeat(40) } }]; })).toBe(false);
    expect(src((bd) => { bd.resolvedDependencies = [{ uri: 'git+x' }]; }).provenance_source).toStrictEqual({ uri: 'git+x' });
    expect(src((bd) => { bd.resolvedDependencies = [{ uri: 'git+x', digest: 'x' }]; }).provenance_source).toStrictEqual({ uri: 'git+x' });
    expect(src((bd) => { bd.resolvedDependencies = [{ uri: 'git+x', digest: { gitCommit: 5 } }]; }).provenance_source).toStrictEqual({ uri: 'git+x' });
    expect(src((bd) => { bd.resolvedDependencies = [{ uri: 'git+x', digest: { gitCommit: 'abc' } }, { uri: 'git+y' }]; }).provenance_source).toStrictEqual({ uri: 'git+x', git_commit: 'abc' });
  });
  it('certificate facts are carried only when the certificate has them', () => {
    const cases: [LeafOpts, string][] = [[{ repo: null }, 'source_repo'], [{ ref: null }, 'source_ref'], [{ digest: null }, 'source_digest']];
    for (const [leaf, key] of cases) {
      const r = facts({ leaf });
      if (!r.ok) throw new Error(r.detail);
      expect(key in r.facts).toBe(false);
      expect(Object.keys(r.facts).length).toBe(12);
    }
  });
});
