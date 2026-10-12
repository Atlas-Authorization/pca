/** Mutation-kill tests for pca-spiffe: exact error codes AND messages, certificate-chain structure (runtime OpenSSL PKI), JWT-SVID options, holder binding by key type. */
import { execFileSync } from 'node:child_process';
import { createPrivateKey, sign as nodeSign } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { SignJWT, generateKeyPair as joseGen, type KeyLike } from 'jose';
import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import {
  SpiffeError,
  holderBindingMessage,
  holderToSpiffeId,
  parseSpiffeId,
  parseX509Svid,
  svidToHolder,
  verifyJwtSvid,
  verifyX509Svid,
  type SpiffeErrorCode,
} from './index';

function thrown(fn: () => unknown): SpiffeError {
  try {
    fn();
  } catch (e) {
    if (e instanceof SpiffeError) return e;
    throw e;
  }
  throw new Error('expected a SpiffeError');
}
async function athrown(fn: () => Promise<unknown>): Promise<SpiffeError> {
  try {
    await fn();
  } catch (e) {
    if (e instanceof SpiffeError) return e;
    throw e;
  }
  throw new Error('expected a SpiffeError');
}
const is = (e: SpiffeError, code: SpiffeErrorCode, message: string): void => expect([e.code, e.message]).toEqual([code, message]);

describe('SpiffeError', () => {
  it('carries a name, a code and a message', () => {
    const e = new SpiffeError('invalid_path', 'm');
    expect([e.name, e.code, e.message, e instanceof Error]).toEqual(['SpiffeError', 'invalid_path', 'm', true]);
  });
});

describe('parseSpiffeId messages and bounds', () => {
  it('non-strings, empty strings and the scheme', () => {
    is(thrown(() => parseSpiffeId('')), 'malformed_spiffe_id', 'SPIFFE ID must be a non-empty string');
    is(thrown(() => parseSpiffeId(5 as never)), 'malformed_spiffe_id', 'SPIFFE ID must be a non-empty string');
    is(thrown(() => parseSpiffeId('https://a.org/x')), 'malformed_spiffe_id', 'SPIFFE ID must begin with "spiffe://"');
  });
  it('total length limit is exactly 2048', () => {
    const base = 'spiffe://example.org/';
    const ok = base + 'a'.repeat(2048 - base.length);
    expect(ok.length).toBe(2048);
    expect(parseSpiffeId(ok).id).toBe(ok);
    is(thrown(() => parseSpiffeId(ok + 'a')), 'id_too_long', 'SPIFFE ID exceeds 2048 bytes');
  });
  it('trust domain', () => {
    is(thrown(() => parseSpiffeId('spiffe:///x')), 'empty_trust_domain', 'SPIFFE ID has an empty trust domain');
    is(thrown(() => parseSpiffeId('spiffe://')), 'empty_trust_domain', 'SPIFFE ID has an empty trust domain');
    expect(parseSpiffeId(`spiffe://${'a'.repeat(255)}`).trustDomain).toHaveLength(255);
    is(thrown(() => parseSpiffeId(`spiffe://${'a'.repeat(256)}/x`)), 'trust_domain_too_long', 'trust domain exceeds 255 bytes');
    is(thrown(() => parseSpiffeId('spiffe://Example.org/x')), 'invalid_trust_domain', 'trust domain "Example.org" must be lowercase and contain only [a-z0-9._-]');
  });
  it('path rules', () => {
    is(thrown(() => parseSpiffeId('spiffe://example.org/')), 'invalid_path', 'SPIFFE ID path must not end with a trailing slash');
    is(thrown(() => parseSpiffeId('spiffe://example.org/a/')), 'invalid_path', 'SPIFFE ID path must not end with a trailing slash');
    is(thrown(() => parseSpiffeId('spiffe://example.org//a')), 'invalid_path', 'SPIFFE ID path must not contain an empty segment');
    is(thrown(() => parseSpiffeId('spiffe://example.org/a//b')), 'invalid_path', 'SPIFFE ID path must not contain an empty segment');
    is(thrown(() => parseSpiffeId('spiffe://example.org/.')), 'invalid_path', 'SPIFFE ID path must not contain a "." or ".." segment');
    is(thrown(() => parseSpiffeId('spiffe://example.org/a/..')), 'invalid_path', 'SPIFFE ID path must not contain a "." or ".." segment');
    is(thrown(() => parseSpiffeId('spiffe://example.org/a b')), 'invalid_path', 'SPIFFE ID path segment "a b" contains an invalid character');
    expect(parseSpiffeId('spiffe://example.org')).toEqual({ id: 'spiffe://example.org', trustDomain: 'example.org', path: '' });
    expect(parseSpiffeId('spiffe://example.org/a/B_c.d-e')).toEqual({ id: 'spiffe://example.org/a/B_c.d-e', trustDomain: 'example.org', path: '/a/B_c.d-e' });
    expect(parseSpiffeId('spiffe://example.org/...').path).toBe('/...');
  });
});

// ---------------------------------------------------------------------------------------------------------------
// JWT-SVID
// ---------------------------------------------------------------------------------------------------------------
describe('verifyJwtSvid options, claims and messages', () => {
  const SUB = 'spiffe://example.org/workload/db';
  const base = { trustDomain: 'example.org', audience: 'aud1' };
  async function mint(claims: Record<string, unknown>, header: Record<string, unknown> = { alg: 'ES256' }): Promise<{ token: string; publicKey: KeyLike }> {
    const { privateKey, publicKey } = await joseGen('ES256');
    const token = await new SignJWT(claims).setProtectedHeader(header as never).sign(privateKey);
    return { token, publicKey };
  }
  const exp = () => Math.floor(Date.now() / 1000) + 600;

  it('requires a non-empty trust domain pin', async () => {
    const { token, publicKey } = await mint({ sub: SUB, aud: 'aud1', exp: exp() });
    const msg = 'verifyJwtSvid requires `trustDomain` (an unpinned JWT-SVID would accept any trust domain the key signs for)';
    is(await athrown(() => verifyJwtSvid(token, { audience: 'aud1', key: publicKey } as never)), 'missing_trust_domain', msg);
    is(await athrown(() => verifyJwtSvid(token, { audience: 'aud1', key: publicKey, trustDomain: '' })), 'missing_trust_domain', msg);
    is(await athrown(() => verifyJwtSvid(token, { audience: 'aud1', key: publicKey, trustDomain: 5 as never })), 'missing_trust_domain', msg);
  });
  it('requires a non-empty audience list without empty entries', async () => {
    const { token, publicKey } = await mint({ sub: SUB, aud: 'aud1', exp: exp() });
    const msg = 'verifyJwtSvid requires a non-empty audience (JWT-SVID aud is mandatory)';
    for (const audience of ['', [], [''], ['aud1', '']]) {
      is(await athrown(() => verifyJwtSvid(token, { ...base, audience, key: publicKey })), 'missing_audience', msg);
    }
  });
  it('refuses none, HMAC (any case) and an empty algorithm list', async () => {
    const { token, publicKey } = await mint({ sub: SUB, aud: 'aud1', exp: exp() });
    for (const alg of ['none', 'HS256', 'hs512', 'Hs384']) {
      is(await athrown(() => verifyJwtSvid(token, { ...base, key: publicKey, algorithms: ['ES256', alg] })), 'forbidden_algorithm', `JWT-SVIDs must not use ${alg}`);
    }
    is(await athrown(() => verifyJwtSvid(token, { ...base, key: publicKey, algorithms: [] })), 'forbidden_algorithm', 'JWT-SVIDs must not use an empty algorithm list');
  });
  it('honours clockTolerance and currentDate', async () => {
    const t = Math.floor(Date.now() / 1000);
    const { token, publicKey } = await mint({ sub: SUB, aud: 'aud1', exp: t - 10 });
    await expect(verifyJwtSvid(token, { ...base, key: publicKey })).rejects.toThrow();
    await expect(verifyJwtSvid(token, { ...base, key: publicKey, clockTolerance: 5 })).rejects.toThrow();
    expect((await verifyJwtSvid(token, { ...base, key: publicKey, clockTolerance: 60 })).expiresAt).toBe(t - 10);
    expect((await verifyJwtSvid(token, { ...base, key: publicKey, clockTolerance: '1m' })).expiresAt).toBe(t - 10);
    expect((await verifyJwtSvid(token, { ...base, key: publicKey, currentDate: new Date((t - 100) * 1000) })).expiresAt).toBe(t - 10);
    await expect(verifyJwtSvid(token, { ...base, key: publicKey, currentDate: new Date((t + 100) * 1000) })).rejects.toThrow();
  });
  it('accepts a key resolver function', async () => {
    const { token, publicKey } = await mint({ sub: SUB, aud: 'aud1', exp: exp() });
    expect((await verifyJwtSvid(token, { ...base, key: async () => publicKey })).spiffeId.id).toBe(SUB);
  });
  it('typ: JWT, JOSE or absent only', async () => {
    for (const typ of ['JWT', 'JOSE']) {
      const { token, publicKey } = await mint({ sub: SUB, aud: 'aud1', exp: exp() }, { alg: 'ES256', typ });
      expect((await verifyJwtSvid(token, { ...base, key: publicKey })).spiffeId.id).toBe(SUB);
    }
    const { token: t0, publicKey: k0 } = await mint({ sub: SUB, aud: 'aud1', exp: exp() }, { alg: 'ES256' });
    expect((await verifyJwtSvid(t0, { ...base, key: k0 })).spiffeId.id).toBe(SUB);
    const { token, publicKey } = await mint({ sub: SUB, aud: 'aud1', exp: exp() }, { alg: 'ES256', typ: 'at+jwt' });
    is(await athrown(() => verifyJwtSvid(token, { ...base, key: publicKey })), 'invalid_typ', "JWT-SVID header typ must be JWT or JOSE, got 'at+jwt'");
  });
  it('claim errors carry exact messages', async () => {
    const noExp = await mint({ sub: SUB, aud: 'aud1' });
    is(await athrown(() => verifyJwtSvid(noExp.token, { ...base, key: noExp.publicKey })), 'missing_exp', 'JWT-SVID is missing the required "exp" claim');
    const numSub = await mint({ sub: 123, aud: 'aud1', exp: exp() });
    is(await athrown(() => verifyJwtSvid(numSub.token, { ...base, key: numSub.publicKey })), 'invalid_subject', 'JWT-SVID "sub" must be a string SPIFFE ID');
    const noSub = await mint({ aud: 'aud1', exp: exp() });
    is(await athrown(() => verifyJwtSvid(noSub.token, { ...base, key: noSub.publicKey })), 'invalid_subject', 'JWT-SVID "sub" must be a string SPIFFE ID');
    const badSub = await mint({ sub: 'x', aud: 'aud1', exp: exp() });
    is(
      await athrown(() => verifyJwtSvid(badSub.token, { ...base, key: badSub.publicKey })),
      'invalid_subject',
      'JWT-SVID "sub" is not a valid SPIFFE ID: SPIFFE ID must begin with "spiffe://"',
    );
    const good = await mint({ sub: SUB, aud: 'aud1', exp: exp() });
    is(
      await athrown(() => verifyJwtSvid(good.token, { ...base, trustDomain: 'other.org', key: good.publicKey })),
      'trust_domain_mismatch',
      'JWT-SVID trust domain "example.org" does not match expected "other.org"',
    );
  });
  it('reports the verified claims, audience (string or list) and expiry', async () => {
    const e = exp();
    const one = await mint({ sub: SUB, aud: 'aud1', exp: e });
    const r1 = await verifyJwtSvid(one.token, { ...base, key: one.publicKey });
    expect(r1.audience).toEqual(['aud1']);
    expect(r1.expiresAt).toBe(e);
    expect(r1.spiffeId).toEqual({ id: SUB, trustDomain: 'example.org', path: '/workload/db' });
    expect(r1.claims).toMatchObject({ sub: SUB, aud: 'aud1', exp: e });
    const many = await mint({ sub: SUB, aud: ['aud1', 'aud2'], exp: e });
    expect((await verifyJwtSvid(many.token, { ...base, key: many.publicKey })).audience).toEqual(['aud1', 'aud2']);
    expect((await verifyJwtSvid(many.token, { ...base, audience: ['aud2', 'zzz'], key: many.publicKey })).audience).toEqual(['aud1', 'aud2']);
  });
});

// ---------------------------------------------------------------------------------------------------------------
// X.509-SVID against the committed OpenSSL fixtures: messages
// ---------------------------------------------------------------------------------------------------------------
const gen = (n: string): string => readFileSync(resolve(__dirname, '..', 'fixtures', 'generated', `${n}.pem`), 'utf8');
const der = (pem: string): Uint8Array => new Uint8Array(Buffer.from(pem.replace(/-----[A-Z ]+-----|\s/g, ''), 'base64'));

describe('X.509-SVID leaf rule messages (fixtures)', () => {
  const leaf = (n: string) => thrown(() => parseX509Svid(gen(n)));
  it('each rule reports its own message', () => {
    is(leaf('leaf-two-uri'), 'multiple_uri_san', 'X.509-SVID certificate must have exactly one URI SAN, found 2');
    is(leaf('leaf-dns-only'), 'no_uri_san', 'X.509-SVID certificate has no URI SAN');
    is(leaf('leaf-root-path'), 'leaf_root_path', 'X.509-SVID leaf SPIFFE ID must have a non-root path');
    is(leaf('leaf-is-ca'), 'leaf_is_ca', 'leaf certificate must not have the CA flag set to true');
    is(leaf('leaf-no-digital-signature'), 'leaf_no_digital_signature', "leaf certificate must have 'digitalSignature' set as key usage");
    is(leaf('leaf-no-key-usage'), 'leaf_no_digital_signature', "leaf certificate must have 'digitalSignature' set as key usage");
    is(leaf('leaf-cert-sign'), 'leaf_cert_sign', "leaf certificate must not have 'keyCertSign' set as key usage");
    is(leaf('leaf-crl-sign'), 'leaf_crl_sign', "leaf certificate must not have 'cRLSign' set as key usage");
    is(leaf('leaf-unknown-critical'), 'unsupported_critical_extension', 'certificate has an unsupported critical extension (2a0304)');
  });
  it('unparseable input is a malformed certificate', () => {
    const e = thrown(() => parseX509Svid(new Uint8Array([1, 2, 3])));
    expect(e.code).toBe('malformed_certificate');
    expect(e.message.startsWith('cannot parse certificate: ')).toBe(true);
    expect(e.message.length).toBeGreaterThan('cannot parse certificate: '.length);
    expect(thrown(() => parseX509Svid('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----')).code).toBe('malformed_certificate');
  });
  it('a certificate whose extensions cannot be read is rejected with the reason', () => {
    const d = Buffer.from(der(gen('leaf')));
    // make the subjectAltName OID (55 1d 11) a second keyUsage OID (55 1d 0f): same length, so the DER stays well-formed
    const at = d.indexOf(Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x11]));
    expect(at).toBeGreaterThan(0);
    d[at + 4] = 0x0f;
    const e = thrown(() => parseX509Svid(new Uint8Array(d)));
    is(e, 'malformed_certificate', 'cannot read certificate extensions: der: duplicate extension');
  });
  it('the SPIFFE ID and key are exposed', () => {
    const s = parseX509Svid(gen('leaf'));
    expect(s.spiffeId).toEqual({ id: 'spiffe://example.org/workload/db', trustDomain: 'example.org', path: '/workload/db' });
    expect(s.publicKeyDer).toBe(Buffer.from(s.certificate.publicKey.export({ type: 'spki', format: 'der' })).toString('base64url'));
  });
});

describe('verifyX509Svid messages and validity boundaries (fixtures)', () => {
  const NOW = new Date('2027-06-01T00:00:00Z');
  const opts = { trustDomain: 'example.org', roots: [gen('root')], now: NOW };
  it('chain shape', () => {
    is(thrown(() => verifyX509Svid([], opts)), 'chain_empty', 'certificate chain is empty');
    is(thrown(() => verifyX509Svid([gen('leaf'), gen('inter0')], { ...opts, maxChainLength: 1 })), 'chain_too_long', 'certificate chain is too long');
    expect(verifyX509Svid([gen('leaf'), gen('inter0')], { ...opts, maxChainLength: 2 }).spiffeId.path).toBe('/workload/db');
    expect(verifyX509Svid([gen('leaf-direct')], { ...opts, maxChainLength: 1 }).spiffeId.path).toBe('/workload/db');
    is(thrown(() => verifyX509Svid([gen('leaf'), gen('inter0')], { ...opts, roots: [] })), 'chain_untrusted_root', 'trust bundle has no X.509 authorities');
    is(thrown(() => verifyX509Svid('garbage', opts)), 'malformed_certificate', 'no PEM certificate found');
    is(thrown(() => verifyX509Svid([gen('leaf')], { ...opts, roots: ['garbage'] })), 'malformed_certificate', 'no PEM certificate found');
    is(thrown(() => verifyX509Svid([gen('leaf-other-td'), gen('inter0')], opts)), 'chain_trust_domain_mismatch', "SPIFFE ID trust domain 'other.org' is not 'example.org'");
  });
  it('anchoring', () => {
    is(thrown(() => verifyX509Svid([gen('leaf')], { ...opts, roots: [gen('leaf')] })), 'chain_untrusted_root', 'a leaf certificate cannot be its own trust anchor');
    is(thrown(() => verifyX509Svid([gen('leaf')], { ...opts, roots: [gen('leaf'), gen('root')] })), 'chain_untrusted_root', 'a leaf certificate cannot be its own trust anchor');
    is(thrown(() => verifyX509Svid([gen('leaf'), gen('inter0')], { ...opts, roots: [gen('other-root')] })), 'chain_untrusted_root', 'the chain does not lead to an authority in the trust bundle');
    is(thrown(() => verifyX509Svid([gen('leaf')], opts)), 'chain_untrusted_root', 'the chain does not lead to an authority in the trust bundle');
    // a leaf listed in the bundle does not anchor a longer chain
    is(thrown(() => verifyX509Svid([gen('leaf'), gen('inter0')], { ...opts, roots: [gen('leaf')] })), 'chain_untrusted_root', 'the chain does not lead to an authority in the trust bundle');
    // the presented top may BE one of several authorities
    expect(verifyX509Svid([gen('leaf'), gen('inter0')], { ...opts, roots: [gen('other-root'), gen('inter0')] }).spiffeId.path).toBe('/workload/db');
    expect(verifyX509Svid([gen('leaf'), gen('inter0')], { ...opts, roots: [gen('inter0'), gen('other-root')] }).spiffeId.path).toBe('/workload/db');
    // a single PEM block holding several authorities
    expect(verifyX509Svid([gen('leaf'), gen('inter0')], { ...opts, roots: [gen('other-root') + gen('root')] }).spiffeId.path).toBe('/workload/db');
  });
  it('signature and structure messages', () => {
    const d = Buffer.from(der(gen('leaf')));
    d[d.length - 1] = d[d.length - 1]! ^ 1;
    is(thrown(() => verifyX509Svid([new Uint8Array(d), gen('inter0')], opts)), 'chain_signature', 'certificate #0 is not signed by certificate #1');
    is(thrown(() => verifyX509Svid([gen('leaf-via-chain'), gen('inter-under-inter0'), gen('inter0')], opts)), 'chain_path_len', 'signing certificate #2 pathLenConstraint exceeded');
    is(thrown(() => verifyX509Svid([gen('leaf-notca'), gen('inter-notca')], opts)), 'chain_not_ca', 'signing certificate #1 must have the CA flag set to true');
    is(thrown(() => verifyX509Svid([gen('leaf-noks'), gen('inter-noks')], opts)), 'chain_no_key_cert_sign', "signing certificate #1 must have 'keyCertSign' set as key usage");
    is(thrown(() => verifyX509Svid([gen('leaf-expired'), gen('inter0')], opts)), 'chain_expired', 'a certificate in the chain is not within its validity period');
  });
  it('validity window is inclusive at both ends', () => {
    const at = (iso: string) => verifyX509Svid([gen('leaf-direct')], { ...opts, now: new Date(iso) });
    expect(at('2026-10-01T00:00:00.000Z').spiffeId.path).toBe('/workload/db');
    expect(at('2036-10-01T00:00:00.000Z').spiffeId.path).toBe('/workload/db');
    is(thrown(() => at('2026-09-30T23:59:59.999Z')), 'chain_expired', 'a certificate in the chain is not within its validity period');
    is(thrown(() => at('2036-10-01T00:00:00.001Z')), 'chain_expired', 'a certificate in the chain is not within its validity period');
  });
  it('the default clock is the real time', () => {
    expect(() => verifyX509Svid([gen('leaf-direct')], { trustDomain: 'example.org', roots: [gen('root')] })).not.toThrow(SpiffeError);
  });
});

// ---------------------------------------------------------------------------------------------------------------
// Runtime OpenSSL PKI: path-length at the authority, signer rules, expired/foreign authorities, key types
// ---------------------------------------------------------------------------------------------------------------
const dir = mkdtempSync(join(tmpdir(), 'spiffe-mk-'));
const sh = (...a: string[]): void => void execFileSync('openssl', a, { cwd: dir, stdio: 'ignore' });
type Kind = 'ec' | 'ec384' | 'rsa' | 'ed' | 'pss';
const NB = '20270101000000Z';
const NA = '20280101000000Z';
const ca = (pathlen?: number, usage = 'keyCertSign,cRLSign'): string[] => [`basicConstraints=critical,CA:TRUE${pathlen === undefined ? '' : `,pathlen:${pathlen}`}`, `keyUsage=critical,${usage}`];
const leafExt = (uri = 'spiffe://example.org/workload/db', extra: string[] = []): string[] => ['basicConstraints=critical,CA:FALSE', 'keyUsage=critical,digitalSignature', `subjectAltName=URI:${uri}`, ...extra];
function issue(name: string, ext: string[], o: { kind?: Kind; signer?: string; nb?: string; na?: string; subj?: string; ids?: boolean } = {}): void {
  const kind = o.kind ?? 'ec';
  if (kind === 'ec') sh('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', `${name}.key`);
  else if (kind === 'ec384') sh('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-384', '-out', `${name}.key`);
  else if (kind === 'rsa') sh('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', `${name}.key`);
  else if (kind === 'pss') sh('genpkey', '-algorithm', 'RSA-PSS', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', `${name}.key`);
  else sh('genpkey', '-algorithm', 'ed25519', '-out', `${name}.key`);
  const lines = [...ext, ...(o.ids === false ? [] : ['subjectKeyIdentifier=hash', ...(o.signer !== undefined ? ['authorityKeyIdentifier=keyid'] : [])])];
  writeFileSync(join(dir, `${name}.ext`), `[ext]\n${lines.join('\n')}\n`);
  sh('req', '-new', '-key', `${name}.key`, '-subj', o.subj ?? `/O=MK/CN=${name}`, '-out', `${name}.csr`);
  const who = o.signer !== undefined ? ['-cert', `${o.signer}.pem`, '-keyfile', `${o.signer}.key`] : ['-selfsign', '-keyfile', `${name}.key`];
  sh('ca', '-batch', '-notext', '-config', 'ca.cnf', '-in', `${name}.csr`, ...who, '-startdate', o.nb ?? NB, '-enddate', o.na ?? NA, '-extfile', `${name}.ext`, '-extensions', 'ext', '-out', `${name}.pem`);
}
writeFileSync(join(dir, 'ca.cnf'), '[ca]\ndefault_ca=CA_default\n[CA_default]\ndir=.\ndatabase=index.txt\nnew_certs_dir=.\nserial=serial\ndefault_md=sha256\npolicy=pol\nunique_subject=no\n[pol]\norganizationName=optional\ncommonName=optional\n');
writeFileSync(join(dir, 'index.txt'), '');
writeFileSync(join(dir, 'serial'), '1000\n');
let have = true;
try {
  issue('R', ca());
  issue('R0', ca(0));
  issue('R1', ca(1));
  issue('RX', ca(), { nb: '20260101000000Z', na: '20270101000000Z' });
  issue('RNOCA', ['basicConstraints=critical,CA:FALSE', 'keyUsage=critical,keyCertSign']);
  issue('RNOKU', ['basicConstraints=critical,CA:TRUE']);
  issue('RNOKS', ['basicConstraints=critical,CA:TRUE', 'keyUsage=critical,digitalSignature']);
  issue('RCRIT', [...ca(), '1.2.3.4=critical,ASN1:UTF8String:x', '1.2.3.5=critical,ASN1:UTF8String:y']);
  issue('EVIL', ca(), { subj: '/O=MK/CN=R', ids: false, nb: '20260101000000Z', na: '20270101000000Z' });
  issue('A', ca(), { signer: 'R' });
  issue('B', ca(), { signer: 'A' });
  issue('I0', ca(), { signer: 'R0' });
  issue('I1', ca(), { signer: 'R1' });
  issue('IBAD', ['basicConstraints=critical,CA:FALSE', 'keyUsage=critical,keyCertSign'], { signer: 'R' });
  issue('INOKU', ['basicConstraints=critical,CA:TRUE'], { signer: 'R' });
  issue('ICRIT', [...ca(), '1.2.3.4=critical,ASN1:UTF8String:x', '1.2.3.5=critical,ASN1:UTF8String:y'], { signer: 'R' });
  for (const [leaf, signer] of [['L_R', 'R'], ['L_A', 'A'], ['L_B', 'B'], ['L_R0', 'R0'], ['L_I0', 'I0'], ['L_R1', 'R1'], ['L_I1', 'I1'], ['L_RX', 'RX'], ['L_RNOCA', 'RNOCA'], ['L_RNOKU', 'RNOKU'], ['L_RNOKS', 'RNOKS'], ['L_RCRIT', 'RCRIT'], ['L_IBAD', 'IBAD'], ['L_INOKU', 'INOKU'], ['L_ICRIT', 'ICRIT']] as const) {
    issue(leaf, leafExt(), { signer });
  }
  issue('L_CRIT2', leafExt('spiffe://example.org/workload/db', ['1.2.3.4=critical,ASN1:UTF8String:x', '1.2.3.5=critical,ASN1:UTF8String:y']), { signer: 'R' });
  issue('K_EC', leafExt(), { signer: 'R', kind: 'ec' });
  issue('K_EC384', leafExt(), { signer: 'R', kind: 'ec384' });
  issue('K_RSA', leafExt(), { signer: 'R', kind: 'rsa' });
  issue('K_ED', leafExt(), { signer: 'R', kind: 'ed' });
  issue('K_PSS', leafExt(), { signer: 'R', kind: 'pss' });
} catch {
  have = false;
}
const rd = (f: string): string => readFileSync(join(dir, f), 'utf8');
const NOW = new Date('2027-06-01T00:00:00Z');
const v = (chain: string[], roots: string[], extra: Record<string, unknown> = {}) => verifyX509Svid(chain.map((n) => rd(`${n}.pem`)), { trustDomain: 'example.org', roots: roots.map((n) => rd(`${n}.pem`)), now: NOW, ...extra });

describe.runIf(have)('verifyX509Svid structure (runtime PKI)', () => {
  it('unconstrained chains and signers pass', () => {
    expect(v(['L_B', 'B', 'A'], ['R']).spiffeId.path).toBe('/workload/db');
    expect(v(['L_A', 'A'], ['R']).spiffeId.path).toBe('/workload/db');
    expect(v(['L_R'], ['R']).spiffeId.path).toBe('/workload/db');
  });
  it('authority path-length constraint counts the signing certificates below it', () => {
    expect(v(['L_R0'], ['R0']).spiffeId.path).toBe('/workload/db'); // 0 below, pathlen 0
    is(thrown(() => v(['L_I0', 'I0'], ['R0'])), 'chain_path_len', 'trust bundle authority pathLenConstraint exceeded'); // 1 below, pathlen 0
    expect(v(['L_I1', 'I1'], ['R1']).spiffeId.path).toBe('/workload/db'); // 1 below, pathlen 1
    expect(v(['L_I1', 'I1'], ['R1', 'R0']).spiffeId.path).toBe('/workload/db');
  });
  it('signing certificates must be CAs with keyCertSign and no unknown critical extensions', () => {
    is(thrown(() => v(['L_IBAD', 'IBAD'], ['R'])), 'chain_not_ca', 'signing certificate #1 must have the CA flag set to true');
    is(thrown(() => v(['L_INOKU', 'INOKU'], ['R'])), 'chain_no_key_cert_sign', "signing certificate #1 must have 'keyCertSign' set as key usage");
    is(thrown(() => v(['L_ICRIT', 'ICRIT'], ['R'])), 'unsupported_critical_extension', 'signing certificate #1 has an unsupported critical extension (2a0304, 2a0305)');
  });
  it('the trust bundle authority is held to the same rules, with its own label', () => {
    is(thrown(() => v(['L_RNOCA'], ['RNOCA'])), 'chain_not_ca', 'trust bundle authority must have the CA flag set to true');
    is(thrown(() => v(['L_RNOKU'], ['RNOKU'])), 'chain_no_key_cert_sign', "trust bundle authority must have 'keyCertSign' set as key usage");
    // an authority whose keyUsage lacks keyCertSign is not even considered an issuer (X509 checkIssued refuses it)
    is(thrown(() => v(['L_RNOKS'], ['RNOKS'])), 'chain_untrusted_root', 'the chain does not lead to an authority in the trust bundle');
    is(thrown(() => v(['L_RCRIT'], ['RCRIT'])), 'unsupported_critical_extension', 'trust bundle authority has an unsupported critical extension (2a0304, 2a0305)');
    is(thrown(() => v(['L_RX'], ['RX'])), 'chain_expired', 'the trust bundle authority is not within its validity period');
  });
  it('a lookalike authority that did not sign the chain is never chosen', () => {
    expect(v(['L_R'], ['EVIL', 'R']).spiffeId.path).toBe('/workload/db');
    expect(v(['L_R'], ['R', 'EVIL']).spiffeId.path).toBe('/workload/db');
  });
  it('a tampered signing certificate is attributed to the right link', () => {
    const d = Buffer.from(der(rd('B.pem')));
    d[d.length - 1] = d[d.length - 1]! ^ 1;
    is(thrown(() => verifyX509Svid([rd('L_B.pem'), new Uint8Array(d), rd('A.pem')], { trustDomain: 'example.org', roots: [rd('R.pem')], now: NOW })), 'chain_signature', 'certificate #1 is not signed by certificate #2');
  });
  it('several unknown critical extensions on a leaf are all listed', () => {
    is(thrown(() => parseX509Svid(rd('L_CRIT2.pem'))), 'unsupported_critical_extension', 'certificate has an unsupported critical extension (2a0304, 2a0305)');
  });
});

describe.runIf(have)('svidToHolder by key type (runtime PKI)', () => {
  const ID = 'spiffe://example.org/workload/db';
  const hk = generateKeyPair();
  const holder = b64u(hk.publicKey);
  const msg = holderBindingMessage(ID, holder);
  const proofFor = (kind: Kind, sigOf: (k: ReturnType<typeof createPrivateKey>) => Buffer): string => b64u(sigOf(createPrivateKey(rd(`${{ ec: 'K_EC', ec384: 'K_EC384', rsa: 'K_RSA', ed: 'K_ED', pss: 'K_PSS' }[kind]}.key`))));
  const svid = (kind: Kind) => v([{ ec: 'K_EC', ec384: 'K_EC384', rsa: 'K_RSA', ed: 'K_ED', pss: 'K_PSS' }[kind]], ['R']);

  it('P-384 uses SHA-384; P-256 uses SHA-256; the hash must match the curve', () => {
    const p384 = proofFor('ec384', (k) => nodeSign('sha384', msg, { key: k, dsaEncoding: 'ieee-p1363' }));
    expect(svidToHolder(svid('ec384'), hk.publicKey, { proof: p384 }).holder).toBe(holder);
    const wrongHash = proofFor('ec384', (k) => nodeSign('sha256', msg, { key: k, dsaEncoding: 'ieee-p1363' }));
    is(thrown(() => svidToHolder(svid('ec384'), hk.publicKey, { proof: wrongHash })), 'holder_binding_failed', 'opts.proof does not verify under the X.509-SVID key');
    const p256 = proofFor('ec', (k) => nodeSign('sha256', msg, { key: k, dsaEncoding: 'ieee-p1363' }));
    expect(svidToHolder(svid('ec'), hk.publicKey, { proof: p256 }).holder).toBe(holder);
    const p256wrong = proofFor('ec', (k) => nodeSign('sha384', msg, { key: k, dsaEncoding: 'ieee-p1363' }));
    is(thrown(() => svidToHolder(svid('ec'), hk.publicKey, { proof: p256wrong })), 'holder_binding_failed', 'opts.proof does not verify under the X.509-SVID key');
  });
  it('only Ed25519, EC and RSA keys can vouch for a holder (RSA-PSS is not accepted)', () => {
    const proof = proofFor('pss', (k) => nodeSign('sha256', msg, k));
    is(thrown(() => svidToHolder(svid('pss'), hk.publicKey, { proof })), 'holder_binding_failed', 'opts.proof does not verify under the X.509-SVID key');
  });
  it('RSA uses PKCS#1 v1.5 with SHA-256', () => {
    const good = proofFor('rsa', (k) => nodeSign('sha256', msg, k));
    expect(svidToHolder(svid('rsa'), hk.publicKey, { proof: good }).holder).toBe(holder);
    const bad = proofFor('rsa', (k) => nodeSign('sha384', msg, k));
    is(thrown(() => svidToHolder(svid('rsa'), hk.publicKey, { proof: bad })), 'holder_binding_failed', 'opts.proof does not verify under the X.509-SVID key');
    is(thrown(() => svidToHolder(svid('rsa'))), 'invalid_holder_key', 'the X.509-SVID key is not Ed25519, so the holder cannot be derived from it: pass holderKey and opts.proof');
  });
  it('a missing, undecodable or wrong proof is refused with the right message', () => {
    for (const kind of ['ec', 'ec384', 'rsa', 'ed'] as const) {
      is(thrown(() => svidToHolder(svid(kind), generateKeyPair().publicKey)), 'holder_binding_failed', 'the holder key is not the SVID key: opts.proof (a signature by the SVID key over holderBindingMessage) is required');
      for (const proof of ['***', '', 'AAAA', 'x']) {
        is(thrown(() => svidToHolder(svid(kind), hk.publicKey, { proof })), 'holder_binding_failed', 'opts.proof does not verify under the X.509-SVID key');
      }
    }
    is(thrown(() => svidToHolder(svid('ec'), hk.publicKey, { proof: 5 as never })), 'holder_binding_failed', 'the holder key is not the SVID key: opts.proof (a signature by the SVID key over holderBindingMessage) is required');
  });
  it('an Ed25519 SVID binds its own key without a proof and any other key with one', () => {
    const own = svidToHolder(svid('ed'));
    expect(own).toMatchObject({ spiffeId: ID, trustDomain: 'example.org', path: '/workload/db' });
    expect(holderToSpiffeId(own)).toBe(ID);
    expect(svidToHolder(svid('ed'), own.holder).holder).toBe(own.holder);
    const proof = proofFor('ed', (k) => nodeSign(null, msg, k));
    expect(svidToHolder(svid('ed'), hk.publicKey, { proof }).holder).toBe(holder);
  });
  it('holder keys are validated', () => {
    is(thrown(() => svidToHolder(svid('ed'), new Uint8Array(31))), 'invalid_holder_key', 'holder key must be a 32-byte Ed25519 public key');
    is(thrown(() => svidToHolder(svid('ed'), new Uint8Array(33))), 'invalid_holder_key', 'holder key must be a 32-byte Ed25519 public key');
    is(thrown(() => svidToHolder(svid('ed'), '***')), 'invalid_holder_key', 'holder key must be a 32-byte Ed25519 public key encoded as base64url');
    expect(svidToHolder(svid('ec384'), new Uint8Array(32).fill(1), { proof: b64u(nodeSign('sha384', holderBindingMessage(ID, b64u(new Uint8Array(32).fill(1))), { key: createPrivateKey(rd('K_EC384.key')), dsaEncoding: 'ieee-p1363' })) }).holder).toBe(b64u(new Uint8Array(32).fill(1)));
  });
});

describe('svidToHolder: unverified inputs and JWT-SVIDs', () => {
  it('rejects anything that is not a verified SVID, with the exact message', async () => {
    const msg = 'svidToHolder needs the result of verifyJwtSvid / verifyX509Svid (a string, a parsed-only SVID or a hand-built object is not accepted)';
    for (const bad of ['spiffe://example.org/x', null, undefined, 5, {}, parseX509Svid(gen('leaf'))]) is(thrown(() => svidToHolder(bad as never, generateKeyPair().publicKey)), 'unverified_svid', msg);
  });
  async function jwtSvid(claims: Record<string, unknown>) {
    const { privateKey, publicKey } = await joseGen('ES256');
    const token = await new SignJWT({ ...claims }).setProtectedHeader({ alg: 'ES256' }).setSubject('spiffe://example.org/workload/db').setAudience('a').setExpirationTime('1h').sign(privateKey);
    return verifyJwtSvid(token, { trustDomain: 'example.org', audience: 'a', key: publicKey });
  }
  it('needs a holder key, and a cnf.jwk that is an Ed25519 OKP equal to it', async () => {
    const hk = generateKeyPair();
    const x = b64u(hk.publicKey);
    is(thrown(() => svidToHolder(null as never)), 'unverified_svid', 'svidToHolder needs the result of verifyJwtSvid / verifyX509Svid (a string, a parsed-only SVID or a hand-built object is not accepted)');
    is(thrown(() => svidToHolder(null as never, hk.publicKey)), 'unverified_svid', 'svidToHolder needs the result of verifyJwtSvid / verifyX509Svid (a string, a parsed-only SVID or a hand-built object is not accepted)');
    const bound = await jwtSvid({ cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x } } });
    is(thrown(() => svidToHolder(bound)), 'invalid_holder_key', 'a JWT-SVID has no key of its own: pass holderKey');
    expect(svidToHolder(bound, hk.publicKey).holder).toBe(x);
    const bindMsg = 'the JWT-SVID carries no cnf.jwk equal to the holder key (set acceptUnboundJwtHolder only if the key is authenticated by other means)';
    for (const cnf of [undefined, {}, { jwk: {} }, { jwk: { kty: 'EC', crv: 'Ed25519', x } }, { jwk: { kty: 'OKP', crv: 'X25519', x } }, { jwk: { kty: 'OKP', crv: 'Ed25519', x: 5 } }, { jwk: { kty: 'OKP', crv: 'Ed25519', x: b64u(generateKeyPair().publicKey) } }]) {
      const s = await jwtSvid(cnf === undefined ? {} : { cnf });
      is(thrown(() => svidToHolder(s, hk.publicKey)), 'holder_binding_failed', bindMsg);
    }
    const unbound = await jwtSvid({});
    expect(svidToHolder(unbound, hk.publicKey, { acceptUnboundJwtHolder: true }).holder).toBe(x);
    is(thrown(() => svidToHolder(unbound, hk.publicKey, { acceptUnboundJwtHolder: false })), 'holder_binding_failed', bindMsg);
  });
});
