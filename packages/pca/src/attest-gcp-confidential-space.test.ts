/**
 * HONEST VALIDATION of the GCP Confidential Space attestation-token VERIFIER
 * (`attest-gcp-confidential-space.ts`).
 *
 * There is no live Google Confidential Space VM in CI to mint a genuine attestation token, so these tests
 * synthesize a REAL, cryptographically-sound Confidential Space JWT: they generate a fresh RS256
 * (RSA-2048) / ES256 (EC P-256) signing key, publish it as a REAL JWKS (RSA `n`/`e`, EC `x`/`y`, and an
 * `x5c` chain), and sign a realistic claim set modelling the true Confidential Space token shape
 * (`submods.confidential_space`, `submods.container.image_digest`, `hwmodel`, `swname`, `swversion`,
 * `dbgstat`, `eat_nonce`) for BOTH `GCP_AMD_SEV_SNP` (AMD) and `GCP_INTEL_TDX` (Intel). The decisive tests
 * assert the full path verifies and binds; the negatives exercise every fail-closed branch. The user will
 * separately validate this against a REAL Confidential Space token captured from a GCP Confidential VM.
 */
import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import {
  GCP_CS_DEFAULT_ISSUER,
  GCP_CS_SUITE,
  GCP_CS_SUITES,
  createGcpConfidentialSpaceVerifier,
  fetchGcpConfidentialSpaceJwks,
  parseGcpCsJwt,
  teeTypeOfHwModel,
  toHex,
  type GcpConfidentialSpaceVerifierOptions,
  type GcpCsEvidence,
  type GcpJwks,
} from './attest-gcp-confidential-space';
import { attestationBinding, createMultiRootVerifier, type ExpectedAttestationBinding, type HardwareAttestationResult, type HardwareAttestationVerifier } from './attestation';
import { encodeKey, generateKeyPair } from './keys';

// ── minimal DER + X.509 certificate minter (test-only; the adapter only ever PARSES real certs) ──────

function cat(...a: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of a) {
    out.set(x, o);
    o += x.length;
  }
  return out;
}
function derLen(n: number): Uint8Array {
  if (n < 0x80) return Uint8Array.from([n]);
  const bytes: number[] = [];
  let x = n;
  while (x > 0) {
    bytes.unshift(x & 0xff);
    x = Math.floor(x / 256);
  }
  return Uint8Array.from([0x80 | bytes.length, ...bytes]);
}
function tlv(tag: number, content: Uint8Array): Uint8Array {
  return cat(Uint8Array.from([tag]), derLen(content.length), content);
}
const derSeq = (...items: Uint8Array[]): Uint8Array => tlv(0x30, cat(...items));
const derSet = (...items: Uint8Array[]): Uint8Array => tlv(0x31, cat(...items));
const derInt = (v: number): Uint8Array => tlv(0x02, Uint8Array.from([v]));
const derUtf8 = (s: string): Uint8Array => tlv(0x0c, new Uint8Array(Buffer.from(s, 'utf8')));
const derUtcTime = (s: string): Uint8Array => tlv(0x17, new Uint8Array(Buffer.from(s, 'ascii')));
const derExplicit0 = (content: Uint8Array): Uint8Array => tlv(0xa0, content);
const derBitString = (bytes: Uint8Array): Uint8Array => tlv(0x03, cat(Uint8Array.from([0x00]), bytes));
const derNull = (): Uint8Array => Uint8Array.from([0x05, 0x00]);
function derOid(dotted: string): Uint8Array {
  const arcs = dotted.split('.').map((x) => Number(x));
  const body: number[] = [arcs[0]! * 40 + arcs[1]!];
  for (const a of arcs.slice(2)) {
    const stack = [a & 0x7f];
    let v = Math.floor(a / 128);
    while (v > 0) {
      stack.unshift((v & 0x7f) | 0x80);
      v = Math.floor(v / 128);
    }
    body.push(...stack);
  }
  return tlv(0x06, Uint8Array.from(body));
}
const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const OID_RSA_SHA256 = '1.2.840.113549.1.1.11';
const OID_CN = '2.5.4.3';

function name(cn: string): Uint8Array {
  return derSeq(derSet(derSeq(derOid(OID_CN), derUtf8(cn))));
}
function sigAlgId(alg: 'ec' | 'rsa'): Uint8Array {
  return alg === 'ec' ? derSeq(derOid(OID_ECDSA_SHA256)) : derSeq(derOid(OID_RSA_SHA256), derNull());
}

interface KP {
  pub: crypto.KeyObject;
  priv: crypto.KeyObject;
  spkiDer: Uint8Array;
  spkiSha256: string;
}
function genEc(): KP {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const spkiDer = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }));
  return { pub: publicKey, priv: privateKey, spkiDer, spkiSha256: crypto.createHash('sha256').update(Buffer.from(spkiDer)).digest('hex') };
}
function genRsa(): KP {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const spkiDer = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }));
  return { pub: publicKey, priv: privateKey, spkiSha256: crypto.createHash('sha256').update(Buffer.from(spkiDer)).digest('hex'), spkiDer };
}

interface CertOpts {
  subjectSpkiDer: Uint8Array;
  subjectCn: string;
  issuerCn: string;
  issuerPriv: crypto.KeyObject;
  issuerAlg: 'ec' | 'rsa';
  notBefore?: string;
  notAfter?: string;
  serial?: number;
}
/** Mint a real X.509 DER certificate signed by `issuerPriv`. Returns the DER bytes. */
function makeCert(o: CertOpts): Uint8Array {
  const alg = sigAlgId(o.issuerAlg);
  const tbs = derSeq(
    derExplicit0(derInt(2)),
    derInt(o.serial ?? 0x2a),
    alg,
    name(o.issuerCn),
    derSeq(derUtcTime(o.notBefore ?? '230101000000Z'), derUtcTime(o.notAfter ?? '350101000000Z')),
    name(o.subjectCn),
    o.subjectSpkiDer,
  );
  const sig = crypto.sign('sha256', Buffer.from(tbs), o.issuerPriv);
  return derSeq(tbs, alg, derBitString(new Uint8Array(sig)));
}
function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

// ── JWK helpers (publish the real signing key the way Google does: RSA n/e; EC x/y) ─────────────────

function rsaJwk(kp: KP, kid: string): GcpJwks {
  const jwk = kp.pub.export({ format: 'jwk' });
  return { keys: [{ kid, kty: 'RSA', alg: 'RS256', use: 'sig', n: String(jwk.n), e: String(jwk.e) }] };
}
function ecJwk(kp: KP, kid: string): GcpJwks {
  const jwk = kp.pub.export({ format: 'jwk' });
  return { keys: [{ kid, kty: 'EC', crv: 'P-256', x: String(jwk.x), y: String(jwk.y) }] };
}

// ── JWT minting ──────────────────────────────────────────────────────────────────────────────────

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}
function b64urlJson(obj: unknown): string {
  return b64url(new Uint8Array(Buffer.from(JSON.stringify(obj), 'utf8')));
}
function signJwt(header: Record<string, unknown>, payload: Record<string, unknown>, priv: crypto.KeyObject, alg: 'ES256' | 'RS256', tamper = false): string {
  const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
  const sig =
    alg === 'ES256'
      ? crypto.sign('sha256', Buffer.from(signingInput, 'ascii'), { key: priv, dsaEncoding: 'ieee-p1363' })
      : crypto.sign('sha256', Buffer.from(signingInput, 'ascii'), priv);
  const s = new Uint8Array(sig);
  if (tamper) s[0] = (s[0]! ^ 0xff) & 0xff;
  return `${signingInput}.${b64url(s)}`;
}

// ── fixtures ─────────────────────────────────────────────────────────────────────────────────────

const ISS = GCP_CS_DEFAULT_ISSUER;
const T = 1_700_000_000_000; // ms — within the 2023..2035 cert window
const SEC = Math.floor(T / 1000);

const A = generateKeyPair();
const EXPECTED: ExpectedAttestationBinding = {
  holderPub: encodeKey(A.publicKey),
  grantRef: 'grant-gcp-1',
  epoch: 1,
  nonce: 'nonce-gcp-1',
  nonceIssuedAt: T - 1000,
};
const BOUND = attestationBinding(EXPECTED);
const IMAGE_DIGEST = 'sha256:' + 'ab'.repeat(32);
const IMAGE_REF = 'us-docker.pkg.dev/proj/repo/workload:latest';

// RS256 signing key (the real Confidential Space signature suite).
const RSA = genRsa();
const RSA_JWKS = rsaJwk(RSA, 'gcp-kid-rsa');

// ES256 signing key (defensive — the adapter also accepts ES256).
const EC = genEc();
const EC_JWKS = ecJwk(EC, 'gcp-kid-ec');

// An x5c-published RSA signing cert chained leaf←root (root pinned by SPKI).
const CA = genRsa();
const RSA_LEAF = genRsa();
const CERT_ROOT = makeCert({ subjectSpkiDer: CA.spkiDer, subjectCn: 'gcp-attest-root', issuerCn: 'gcp-attest-root', issuerPriv: CA.priv, issuerAlg: 'rsa' });
const CERT_LEAF = makeCert({ subjectSpkiDer: RSA_LEAF.spkiDer, subjectCn: 'gcp-attest-signer', issuerCn: 'gcp-attest-root', issuerPriv: CA.priv, issuerAlg: 'rsa' });
const ROOT_PEM = new crypto.X509Certificate(Buffer.from(CERT_ROOT)).toString();
const X5C_JWKS: GcpJwks = { keys: [{ kid: 'gcp-kid-x5c', kty: 'RSA', x5c: [b64(CERT_LEAF), b64(CERT_ROOT)] }] };

// A rogue RSA signer whose key is in NO anchor set.
const ROGUE = genRsa();
const ROGUE_JWKS = rsaJwk(ROGUE, 'gcp-kid-rsa'); // same kid, different key material

// Default trust: pin Google's published RSA JWKS directly.
const TRUST: GcpConfidentialSpaceVerifierOptions['trustAnchors'] = { trustedJwks: RSA_JWKS };
const POLICY = { imageDigests: [IMAGE_DIGEST] };

interface TokenOpts {
  alg?: 'ES256' | 'RS256';
  hwmodel?: string;
  iss?: string;
  exp?: number;
  iat?: number;
  nbf?: number;
  swname?: string;
  swversion?: string[];
  dbgstat?: string;
  eatNonce?: string | string[];
  nonceHash?: 'none' | 'sha256' | 'sha512';
  imageDigest?: string;
  omitNonce?: boolean;
  omitConfidentialSpace?: boolean;
  omitImageDigest?: boolean;
  kid?: string;
  signPriv?: crypto.KeyObject;
  x5c?: string[];
  tamper?: boolean;
}
function nonceFor(opts: TokenOpts): string {
  if (opts.eatNonce !== undefined) return Array.isArray(opts.eatNonce) ? opts.eatNonce[0]! : opts.eatNonce;
  if (opts.nonceHash === 'sha256') return b64(crypto.createHash('sha256').update(Buffer.from(BOUND)).digest());
  if (opts.nonceHash === 'sha512') return b64(crypto.createHash('sha512').update(Buffer.from(BOUND)).digest());
  return b64(Buffer.from(BOUND)); // standard-base64 of the raw 64-byte binding (as a guest would echo it)
}
function mkToken(opts: TokenOpts = {}): string {
  const alg = opts.alg ?? 'RS256';
  const hwmodel = opts.hwmodel ?? 'GCP_INTEL_TDX';
  const signPriv = opts.signPriv ?? (alg === 'ES256' ? EC.priv : RSA.priv);
  const kid = opts.kid ?? (alg === 'ES256' ? 'gcp-kid-ec' : 'gcp-kid-rsa');
  const header: Record<string, unknown> = {
    alg,
    typ: 'JWT',
    kid,
    jku: `${ISS}/jwks`,
    ...(opts.x5c ? { x5c: opts.x5c } : {}),
  };
  const container: Record<string, unknown> = { image_reference: IMAGE_REF, restart_policy: 'Never' };
  if (!opts.omitImageDigest) container.image_digest = opts.imageDigest ?? IMAGE_DIGEST;
  const submods: Record<string, unknown> = { container };
  if (!opts.omitConfidentialSpace) {
    submods.confidential_space = { support_attributes: ['LATEST', 'STABLE', 'USABLE'] };
  }
  const nonce = opts.omitNonce ? undefined : (opts.eatNonce ?? nonceFor(opts));
  const payload: Record<string, unknown> = {
    iss: opts.iss ?? ISS,
    aud: 'https://sts.googleapis.com',
    iat: opts.iat ?? SEC - 60,
    nbf: opts.nbf ?? SEC - 60,
    exp: opts.exp ?? SEC + 3600,
    sub: 'https://www.googleapis.com/compute/v1/projects/proj/zones/us-central1-a/instances/wl',
    secboot: true,
    oemid: 11129,
    hwmodel,
    swname: opts.swname ?? 'CONFIDENTIAL_SPACE',
    swversion: opts.swversion ?? ['1'],
    dbgstat: opts.dbgstat ?? 'disabled-since-boot',
    submods,
  };
  if (nonce !== undefined) payload.eat_nonce = nonce;
  return signJwt(header, payload, signPriv, alg, opts.tamper);
}

function verifier(over: Partial<GcpConfidentialSpaceVerifierOptions> = {}, evidence?: GcpCsEvidence) {
  const ev = evidence ?? { token: mkToken() };
  return createGcpConfidentialSpaceVerifier({
    trustedIssuers: [ISS],
    trustAnchors: TRUST,
    policy: { ...POLICY },
    resolveEvidence: () => ev,
    ...over,
  });
}
function run(v: HardwareAttestationVerifier): Promise<HardwareAttestationResult> {
  return Promise.resolve(v.verify({ document: {} as never, ctx: {} as never, nowMs: T, expected: EXPECTED }));
}

// ── tests ───────────────────────────────────────────────────────────────────────────────────────

describe('attest-gcp-confidential-space: suite labels + parse', () => {
  it('declares the classical RS256 / ES256 suites and the audit label', () => {
    expect([...GCP_CS_SUITES]).toEqual(['RS256', 'ES256']);
    expect(GCP_CS_SUITE).toBe('gcp-confidential-space-jwt');
    expect(GCP_CS_DEFAULT_ISSUER).toBe('https://confidentialcomputing.googleapis.com');
  });
  it('maps hwmodel to the isolation family', () => {
    expect(teeTypeOfHwModel('GCP_AMD_SEV_SNP')).toBe('sev-snp');
    expect(teeTypeOfHwModel('GCP_AMD_SEV')).toBe('sev-snp');
    expect(teeTypeOfHwModel('GCP_INTEL_TDX')).toBe('tdx');
    expect(teeTypeOfHwModel('GCP_NITRO')).toBeUndefined();
  });
  it('parses a compact JWS into header/payload/signature', () => {
    const p = parseGcpCsJwt(mkToken());
    expect(p.header.alg).toBe('RS256');
    expect(p.payload.iss).toBe(ISS);
    expect(p.header.kid).toBe('gcp-kid-rsa');
  });
  it('rejects a non-three-part token', () => {
    expect(() => parseGcpCsJwt('a.b')).toThrow(/three dot-separated/);
  });
});

describe('attest-gcp-confidential-space: decisive end-to-end path', () => {
  it('ACCEPTS a well-formed Intel TDX (tdxvm) RS256 token (bound + measured)', async () => {
    const r = await run(verifier());
    expect(r.ok).toBe(true);
    expect(r.bound).toBe(true);
    expect(r.measured?.runtime_measurement).toBe(IMAGE_DIGEST);
    expect(r.hostAsserted?.attestation_type).toBe('tdx');
    expect(r.hostAsserted?.hwmodel).toBe('GCP_INTEL_TDX');
    expect(r.hostAsserted?.image_reference).toBe(IMAGE_REF);
  });

  it('ACCEPTS a well-formed AMD SEV-SNP token', async () => {
    const r = await run(verifier({}, { token: mkToken({ hwmodel: 'GCP_AMD_SEV_SNP' }) }));
    expect(r.ok).toBe(true);
    expect(r.measured?.runtime_measurement).toBe(IMAGE_DIGEST);
    expect(r.hostAsserted?.attestation_type).toBe('sev-snp');
  });

  it('ACCEPTS an ES256 token (defensive suite)', async () => {
    const v = verifier({ trustAnchors: { trustedJwks: EC_JWKS } }, { token: mkToken({ alg: 'ES256' }) });
    const r = await run(v);
    expect(r.ok).toBe(true);
    expect(r.measured?.runtime_measurement).toBe(IMAGE_DIGEST);
  });

  it('ACCEPTS a key resolved from the evidence JWKS, anchored by a pinned SPKI fingerprint', async () => {
    const v = verifier({ trustAnchors: { trustedKeySpki: [RSA.spkiSha256] } }, { token: mkToken(), jwks: RSA_JWKS });
    const r = await run(v);
    expect(r.ok).toBe(true);
  });

  it('ACCEPTS an x5c-published key chained to a pinned root SPKI', async () => {
    const token = mkToken({ kid: 'gcp-kid-x5c', signPriv: RSA_LEAF.priv });
    const v = verifier({ trustAnchors: { trustedKeySpki: [CA.spkiSha256] } }, { token, jwks: X5C_JWKS });
    const r = await run(v);
    expect(r.ok).toBe(true);
  });

  it('ACCEPTS an x5c-published key chained to a configured root-CA PEM', async () => {
    const token = mkToken({ kid: 'gcp-kid-x5c', signPriv: RSA_LEAF.priv });
    const v = verifier({ trustAnchors: { rootCertsPem: [ROOT_PEM] } }, { token, jwks: X5C_JWKS });
    const r = await run(v);
    expect(r.ok).toBe(true);
  });

  it('ACCEPTS nonceHash:sha256 binding (guest echoes a hash of the binding)', async () => {
    const token = mkToken({ nonceHash: 'sha256' });
    const v = verifier({ policy: { ...POLICY, nonceHash: 'sha256' } }, { token });
    const r = await run(v);
    expect(r.ok).toBe(true);
  });

  it('ACCEPTS an eat_nonce ARRAY when one entry binds', async () => {
    const token = mkToken({ eatNonce: ['ZmlsbGVy', b64(Buffer.from(BOUND))] });
    const r = await run(verifier({}, { token }));
    expect(r.ok).toBe(true);
  });

  it('ACCEPTS a hex-encoded eat_nonce (decode robustness)', async () => {
    const token = mkToken({ eatNonce: toHex(BOUND) });
    const r = await run(verifier({}, { token }));
    expect(r.ok).toBe(true);
  });
});

describe('attest-gcp-confidential-space: construction fail-closed', () => {
  it('rejects empty trustedIssuers', () => {
    expect(() => createGcpConfidentialSpaceVerifier({ trustedIssuers: [], trustAnchors: TRUST, policy: { ...POLICY } })).toThrow(/trustedIssuers/);
  });
  it('rejects missing trust anchors (accept-all)', () => {
    expect(() => createGcpConfidentialSpaceVerifier({ trustedIssuers: [ISS], trustAnchors: {}, policy: { ...POLICY } })).toThrow(/trustAnchors/);
  });
  it('rejects an empty image-digest allowlist (accept-all)', () => {
    expect(() => createGcpConfidentialSpaceVerifier({ trustedIssuers: [ISS], trustAnchors: TRUST, policy: { imageDigests: [] } })).toThrow(/accept-all is not permitted/);
  });
  it('rejects an empty allowedTeeTypes pin', () => {
    expect(() => createGcpConfidentialSpaceVerifier({ trustedIssuers: [ISS], trustAnchors: TRUST, policy: { ...POLICY, allowedTeeTypes: [] } })).toThrow(/allowedTeeTypes/);
  });
});

describe('attest-gcp-confidential-space: verification fail-closed', () => {
  it('tampered signature denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ tamper: true }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/signature does not verify/);
  });

  it('untrusted signer (same kid, rogue key) denied', async () => {
    // The evidence JWKS presents a rogue key under the expected kid; anchored only by a pinned SPKI it must fail.
    const v = verifier({ trustAnchors: { trustedKeySpki: [RSA.spkiSha256] } }, { token: mkToken({ signPriv: ROGUE.priv }), jwks: ROGUE_JWKS });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/signing key is not anchored|not trusted/);
  });

  it('untrusted issuer denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ iss: 'https://evil.googleapis.com' }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/trusted Google attestation issuer/);
  });

  it('expired token denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ exp: SEC - 10 }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/expired/);
  });

  it('not-yet-valid (nbf in the future) denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ nbf: SEC + 600 }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/not yet valid/);
  });

  it('wrong eat_nonce binding denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ eatNonce: b64(Buffer.from('f'.repeat(64))) }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/does not bind/);
  });

  it('missing eat_nonce claim denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ omitNonce: true }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/no eat_nonce claim/);
  });

  it('missing submods.confidential_space denied (not a CS token)', async () => {
    const r = await run(verifier({}, { token: mkToken({ omitConfidentialSpace: true }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/not a Confidential Space token/);
  });

  it('unrecognized hwmodel denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ hwmodel: 'GCP_NITRO' }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/unrecognized hwmodel/);
  });

  it('wrong attestation type (allowedTeeTypes pin) denied', async () => {
    // Policy accepts only TDX; an AMD SEV-SNP token must fail closed.
    const v = verifier({ policy: { ...POLICY, allowedTeeTypes: ['tdx'] } }, { token: mkToken({ hwmodel: 'GCP_AMD_SEV_SNP' }) });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/not in the policy allowlist/);
  });

  it('debug-mode (dbgstat enabled) denied unless allowDebug', async () => {
    const r = await run(verifier({}, { token: mkToken({ dbgstat: 'enabled' }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/debug build/);
    const ok = await run(verifier({ policy: { ...POLICY, allowDebug: true } }, { token: mkToken({ dbgstat: 'enabled' }) }));
    expect(ok.ok).toBe(true);
  });

  it('workload image_digest not in allowlist denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ imageDigest: 'sha256:' + '00'.repeat(32) }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/image_digest not in policy allowlist/);
  });

  it('missing image_digest denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ omitImageDigest: true }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/no submods.container.image_digest/);
  });

  it('unexpected swname denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ swname: 'SOMETHING_ELSE' }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/unexpected swname/);
  });

  it('swversion not in allowlist denied', async () => {
    const v = verifier({ policy: { ...POLICY, allowedSwVersions: ['2'] } }, { token: mkToken({ swversion: ['1'] }) });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/swversion not in policy allowlist/);
  });

  it('kid not present in any JWKS denied', async () => {
    const v = verifier({ trustAnchors: { trustedJwks: RSA_JWKS } }, { token: mkToken({ kid: 'gcp-kid-nope' }) });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/no JWKS key matches/);
  });

  it('absent evidence (no resolver) denied', async () => {
    const v = createGcpConfidentialSpaceVerifier({ trustedIssuers: [ISS], trustAnchors: TRUST, policy: { ...POLICY } });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/no GCP Confidential Space evidence resolver/);
  });

  it('unsupported alg denied', async () => {
    const forged = mkToken().replace(/^[^.]+/, Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: 'gcp-kid-rsa' }), 'utf8').toString('base64url'));
    const r = await run(verifier({}, { token: forged }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/unsupported JWS alg/);
  });
});

describe('attest-gcp-confidential-space: multi-root integration', () => {
  it('composes as one GCP-native root alongside a second root in an N-of-M policy', async () => {
    // A trivial second root that corroborates the same measured identity, to exercise reconciliation.
    const secondRoot: HardwareAttestationVerifier = {
      verify: () => ({ ok: true, bound: true, measured: { model_id: '', weights_digest: '', runtime_measurement: IMAGE_DIGEST, operator: '' } }),
    };
    const mv = createMultiRootVerifier({
      roots: [
        { id: 'gcp-confidential-space', verifier: verifier(), required: true, suite: GCP_CS_SUITE },
        { id: 'corroborating-root', verifier: secondRoot, suite: 'test-root' },
      ],
      threshold: 2,
    });
    const r = await mv.verify({ document: {} as never, ctx: {} as never, nowMs: T, expected: EXPECTED });
    expect(r.ok).toBe(true);
    expect(r.bound).toBe(true);
    expect(r.measured?.runtime_measurement).toBe(IMAGE_DIGEST);
  });

  it('denies the N-of-M policy when the required GCP root fails', async () => {
    const mv = createMultiRootVerifier({
      roots: [{ id: 'gcp-confidential-space', verifier: verifier({}, { token: mkToken({ tamper: true }) }), required: true, suite: GCP_CS_SUITE }],
      threshold: 1,
    });
    const r = await mv.verify({ document: {} as never, ctx: {} as never, nowMs: T, expected: EXPECTED });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/required attestation root 'gcp-confidential-space' failed/);
  });
});

describe('attest-gcp-confidential-space: fetchGcpConfidentialSpaceJwks helper', () => {
  it('resolves the OpenID config then fetches the JWKS', async () => {
    const calls: string[] = [];
    const fakeFetch = (async (url: string) => {
      calls.push(url);
      if (url.endsWith('/.well-known/openid-configuration')) {
        return { ok: true, status: 200, json: async () => ({ jwks_uri: `${ISS}/jwks` }) } as unknown as Response;
      }
      return { ok: true, status: 200, json: async () => ({ keys: [{ kid: 'k1', kty: 'RSA', n: 'AQAB', e: 'AQAB' }] }) } as unknown as Response;
    }) as unknown as typeof fetch;
    const jwks = await fetchGcpConfidentialSpaceJwks(ISS, { fetch: fakeFetch });
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]!.kid).toBe('k1');
    expect(calls[0]).toContain('/.well-known/openid-configuration');
  });
  it('accepts a direct jwksUri (skips the OpenID config)', async () => {
    const fakeFetch = (async () => ({ ok: true, status: 200, json: async () => ({ keys: [{ kid: 'k2', kty: 'RSA', n: 'AQAB', e: 'AQAB' }] }) }) as unknown as Response) as unknown as typeof fetch;
    const jwks = await fetchGcpConfidentialSpaceJwks(ISS, { fetch: fakeFetch, jwksUri: `${ISS}/jwks` });
    expect(jwks.keys[0]!.kid).toBe('k2');
  });
  it('throws on a non-2xx JWKS response', async () => {
    const fakeFetch = (async () => ({ ok: false, status: 503, json: async () => ({}) }) as unknown as Response) as unknown as typeof fetch;
    await expect(fetchGcpConfidentialSpaceJwks(ISS, { fetch: fakeFetch, jwksUri: `${ISS}/jwks` })).rejects.toThrow(/HTTP 503/);
  });
});
