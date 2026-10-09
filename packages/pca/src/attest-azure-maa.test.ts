/**
 * HONEST VALIDATION of the Azure MAA (Microsoft Azure Attestation) JWT VERIFIER (`attest-azure-maa.ts`).
 *
 * There is no live Azure Confidential VM in CI to mint a genuine MAA token, so these tests synthesize a
 * REAL, cryptographically-sound MAA JWT: they generate a fresh ES256 (EC P-256) / RS256 (RSA-2048) signing
 * key, mint a REAL X.509 certificate chain for it (a self-signed `x5c` self-chain, and a 3-cert
 * leaf←intermediate←root chain), and sign a realistic `tdxvm` / `sevsnpvm` claim set exactly as MAA does
 * (JWS compact serialization, `x5c`/`kid` in the header or the JWKS). The decisive tests assert the full
 * path verifies and binds; the negatives exercise every fail-closed branch. The user will separately
 * validate this against a REAL MAA JWT captured from an Azure CVM.
 */
import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import {
  AZURE_MAA_SUITE,
  AZURE_MAA_SUITES,
  createAzureMaaVerifier,
  fetchMaaJwks,
  parseMaaJwt,
  toHex,
  verifyX5cChain,
  type AzureMaaVerifierOptions,
  type MaaEvidence,
  type MaaJwks,
} from './attest-azure-maa';
import { attestationBinding, createMultiRootVerifier, type ExpectedAttestationBinding } from './attestation';
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
    derExplicit0(derInt(2)), // version v3
    derInt(o.serial ?? 0x2a),
    alg,
    name(o.issuerCn),
    derSeq(derUtcTime(o.notBefore ?? '230101000000Z'), derUtcTime(o.notAfter ?? '350101000000Z')),
    name(o.subjectCn),
    o.subjectSpkiDer,
  );
  const sig = crypto.sign('sha256', Buffer.from(tbs), o.issuerPriv); // ec => DER ECDSA; rsa => PKCS1
  return derSeq(tbs, alg, derBitString(new Uint8Array(sig)));
}
function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
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

const ISS = 'https://sharedeus.eus.attest.azure.net';
const T = 1_700_000_000_000; // ms — within the 2023..2035 cert window
const SEC = Math.floor(T / 1000);

const A = generateKeyPair();
const EXPECTED: ExpectedAttestationBinding = {
  holderPub: encodeKey(A.publicKey),
  grantRef: 'grant-maa-1',
  epoch: 1,
  nonce: 'nonce-maa-1',
  nonceIssuedAt: T - 1000,
};
const BOUND = attestationBinding(EXPECTED);
const MRTD = 'ab'.repeat(48);
const MEAS = 'cd'.repeat(48); // SEV-SNP launch measurement
const HOSTDATA = 'ee'.repeat(32);

// ES256 self-signed signing cert (x5c self-chain).
const EC = genEc();
const CERT_EC = makeCert({ subjectSpkiDer: EC.spkiDer, subjectCn: 'maa-signer-ec', issuerCn: 'maa-signer-ec', issuerPriv: EC.priv, issuerAlg: 'ec' });
const X5C_EC = [b64(CERT_EC)];

// RS256 self-signed signing cert.
const RSA = genRsa();
const CERT_RSA = makeCert({ subjectSpkiDer: RSA.spkiDer, subjectCn: 'maa-signer-rsa', issuerCn: 'maa-signer-rsa', issuerPriv: RSA.priv, issuerAlg: 'rsa' });
const X5C_RSA = [b64(CERT_RSA)];

// A 3-cert chain: leaf (EC) ← intermediate (EC) ← root (EC, self-signed).
const ROOT = genEc();
const INT = genEc();
const LEAF = genEc();
const CERT_ROOT = makeCert({ subjectSpkiDer: ROOT.spkiDer, subjectCn: 'maa-root', issuerCn: 'maa-root', issuerPriv: ROOT.priv, issuerAlg: 'ec' });
const CERT_INT = makeCert({ subjectSpkiDer: INT.spkiDer, subjectCn: 'maa-int', issuerCn: 'maa-root', issuerPriv: ROOT.priv, issuerAlg: 'ec' });
const CERT_LEAF = makeCert({ subjectSpkiDer: LEAF.spkiDer, subjectCn: 'maa-leaf', issuerCn: 'maa-int', issuerPriv: INT.priv, issuerAlg: 'ec' });
const ROOT_PEM = new crypto.X509Certificate(Buffer.from(CERT_ROOT)).toString();

// An untrusted ES256 signer (fingerprint NOT in the anchor set).
const ROGUE = genEc();
const CERT_ROGUE = makeCert({ subjectSpkiDer: ROGUE.spkiDer, subjectCn: 'rogue', issuerCn: 'rogue', issuerPriv: ROGUE.priv, issuerAlg: 'ec' });
const X5C_ROGUE = [b64(CERT_ROGUE)];

const TRUST_ANCHORS = { rootSpkiSha256: [EC.spkiSha256, RSA.spkiSha256, ROOT.spkiSha256] };
const POLICY: { sevSnpMeasurements: string[]; tdxMrtds: string[] } = { sevSnpMeasurements: [MEAS], tdxMrtds: [MRTD] };

const JWKS: MaaJwks = {
  keys: [
    { kid: 'kid-ec', kty: 'EC', x5c: X5C_EC },
    { kid: 'kid-rsa', kty: 'RSA', x5c: X5C_RSA },
  ],
};

interface TokenOpts {
  alg?: 'ES256' | 'RS256';
  isolationType?: string;
  iss?: string;
  exp?: number;
  iat?: number;
  nbf?: number;
  reportDataHex?: string;
  reportDataHash?: 'none' | 'sha256' | 'sha512';
  measurement?: string;
  hostData?: string;
  debuggable?: boolean;
  /** SEV-SNP reported-TCB claims to set (value `null` omits the claim; a string simulates a non-integer). */
  svns?: Partial<Record<'bootloader' | 'snpfw' | 'microcode' | 'tee', number | string | null>>;
  rtmr0?: string;
  omitReportData?: boolean;
  x5cInHeader?: boolean;
  kid?: string;
  signPriv?: crypto.KeyObject;
  tamper?: boolean;
  x5cHeaderValue?: string[];
  tdxDebug?: boolean;
  dbgstat?: string;
  tcbStatus?: string;
  /** x-ms-runtime.user-data (hex); `null` omits the x-ms-runtime claim. */
  runtimeUserData?: string | null;
}
function reportDataFor(opts: TokenOpts): string {
  if (opts.reportDataHex) return opts.reportDataHex;
  if (opts.reportDataHash === 'sha256') return toHex(crypto.createHash('sha256').update(Buffer.from(BOUND)).digest());
  if (opts.reportDataHash === 'sha512') return toHex(crypto.createHash('sha512').update(Buffer.from(BOUND)).digest());
  return toHex(BOUND);
}
function mkToken(opts: TokenOpts = {}): string {
  const alg = opts.alg ?? 'ES256';
  const isolationType = opts.isolationType ?? 'tdxvm';
  const x5cInHeader = opts.x5cInHeader ?? true;
  const signPriv = opts.signPriv ?? (alg === 'ES256' ? EC.priv : RSA.priv);
  const headerX5c = opts.x5cHeaderValue ?? (alg === 'ES256' ? X5C_EC : X5C_RSA);
  const header: Record<string, unknown> = {
    alg,
    typ: 'JWT',
    jku: `${ISS}/certs`,
    ...(opts.kid ? { kid: opts.kid } : {}),
    ...(x5cInHeader ? { x5c: headerX5c } : {}),
  };
  const rd = reportDataFor(opts);
  const meas = opts.measurement ?? (isolationType === 'tdxvm' ? MRTD : MEAS);
  const tee: Record<string, unknown> = { 'x-ms-attestation-type': isolationType };
  if (isolationType === 'tdxvm') {
    tee['x-ms-tdx-mrtd'] = meas;
    if (!opts.omitReportData) tee['x-ms-tdx-report-data'] = rd;
    if (opts.rtmr0) tee['x-ms-tdx-rtmr0'] = opts.rtmr0;
    if (opts.tdxDebug !== undefined) tee['tdx_td_attributes_debug'] = opts.tdxDebug;
    if (opts.dbgstat) tee['dbgstat'] = opts.dbgstat;
    if (opts.tcbStatus) tee['attester_tcb_status'] = opts.tcbStatus;
  } else if (isolationType === 'sevsnpvm') {
    tee['x-ms-sevsnpvm-launchmeasurement'] = meas;
    if (!opts.omitReportData) tee['x-ms-sevsnpvm-reportdata'] = rd;
    tee['x-ms-sevsnpvm-is-debuggable'] = opts.debuggable ?? false;
    if (opts.hostData) tee['x-ms-sevsnpvm-hostdata'] = opts.hostData;
    for (const [k, v] of Object.entries(opts.svns ?? {})) if (v !== null && v !== undefined) tee[`x-ms-sevsnpvm-${k}-svn`] = v;
  } else {
    if (!opts.omitReportData) tee['x-ms-tdx-report-data'] = rd;
  }
  const payload: Record<string, unknown> = {
    iss: opts.iss ?? ISS,
    iat: opts.iat ?? SEC - 60,
    nbf: opts.nbf ?? SEC - 60,
    exp: opts.exp ?? SEC + 3600,
    'x-ms-ver': '1.0',
    'x-ms-attestation-type': 'azurevm',
    'x-ms-isolation-tee': tee,
    ...(typeof opts.runtimeUserData === 'string' ? { 'x-ms-runtime': { 'user-data': opts.runtimeUserData, keys: [] } } : {}),
  };
  return signJwt(header, payload, signPriv, alg, opts.tamper);
}

function verifier(over: Partial<AzureMaaVerifierOptions> = {}, evidence?: MaaEvidence) {
  const ev = evidence ?? { token: mkToken() };
  return createAzureMaaVerifier({
    trustedIssuers: [ISS],
    trustAnchors: TRUST_ANCHORS,
    policy: { ...POLICY },
    resolveEvidence: () => ev,
    ...over,
  });
}
function run(v: ReturnType<typeof createAzureMaaVerifier>) {
  return v.verify({ document: {} as never, ctx: {} as never, nowMs: T, expected: EXPECTED });
}

// ── tests ───────────────────────────────────────────────────────────────────────────────────────

describe('attest-azure-maa: suite labels + parse', () => {
  it('declares the classical ES256 / RS256 suites', () => {
    expect([...AZURE_MAA_SUITES]).toEqual(['ES256', 'RS256']);
    expect(AZURE_MAA_SUITE).toBe('azure-maa-jwt');
  });
  it('parses a compact JWS into header/payload/signature', () => {
    const p = parseMaaJwt(mkToken());
    expect(p.header.alg).toBe('ES256');
    expect(p.payload.iss).toBe(ISS);
    expect(p.signature.length).toBe(64);
  });
  it('rejects a non-three-part token', () => {
    expect(() => parseMaaJwt('a.b')).toThrow(/three dot-separated/);
  });
});

describe('attest-azure-maa: decisive end-to-end path', () => {
  it('ACCEPTS a well-formed tdxvm ES256 token (bound + measured)', async () => {
    const r = await run(verifier());
    expect(r.ok).toBe(true);
    expect(r.bound).toBe(true);
    expect(r.measured?.runtime_measurement).toBe(MRTD);
    expect(r.hostAsserted?.attestation_type).toBe('tdxvm');
  });

  it('ACCEPTS a well-formed sevsnpvm ES256 token', async () => {
    const r = await run(verifier({}, { token: mkToken({ isolationType: 'sevsnpvm', hostData: HOSTDATA }) }));
    expect(r.ok).toBe(true);
    expect(r.measured?.runtime_measurement).toBe(MEAS);
    expect(r.hostAsserted?.attestation_type).toBe('sevsnpvm');
    expect(r.hostAsserted?.host_data).toBe(HOSTDATA);
  });

  it('ACCEPTS an RS256 token', async () => {
    const r = await run(verifier({}, { token: mkToken({ alg: 'RS256' }) }));
    expect(r.ok).toBe(true);
    expect(r.measured?.runtime_measurement).toBe(MRTD);
  });

  it('ACCEPTS a token whose signing x5c is resolved from the JWKS by kid (not the header)', async () => {
    const r = await run(verifier({}, { token: mkToken({ x5cInHeader: false, kid: 'kid-ec' }), jwks: JWKS }));
    expect(r.ok).toBe(true);
  });

  it('ACCEPTS a real 3-cert chain anchored by the root SPKI fingerprint', async () => {
    const token = mkToken({ signPriv: LEAF.priv, x5cHeaderValue: [b64(CERT_LEAF), b64(CERT_INT), b64(CERT_ROOT)] });
    const r = await run(verifier({}, { token }));
    expect(r.ok).toBe(true);
  });

  it('ACCEPTS a chain anchored by an external root CA PEM (root not in x5c)', async () => {
    const token = mkToken({ signPriv: LEAF.priv, x5cHeaderValue: [b64(CERT_LEAF), b64(CERT_INT)] });
    const v = verifier({ trustAnchors: { rootCertsPem: [ROOT_PEM] } }, { token });
    const r = await run(v);
    expect(r.ok).toBe(true);
  });

  it('ACCEPTS reportDataHash:sha256 binding (indirect Azure report-data)', async () => {
    const token = mkToken({ reportDataHash: 'sha256' });
    const v = verifier({ policy: { ...POLICY, reportDataHash: 'sha256' } }, { token });
    const r = await run(v);
    expect(r.ok).toBe(true);
  });
});

describe('attest-azure-maa: construction fail-closed', () => {
  it('rejects empty trustedIssuers', () => {
    expect(() => createAzureMaaVerifier({ trustedIssuers: [], trustAnchors: TRUST_ANCHORS, policy: { ...POLICY } })).toThrow(/trustedIssuers/);
  });
  it('rejects missing trust anchors (accept-all)', () => {
    expect(() => createAzureMaaVerifier({ trustedIssuers: [ISS], trustAnchors: {}, policy: { ...POLICY } })).toThrow(/trustAnchors/);
  });
  it('rejects an empty measurement policy (accept-all)', () => {
    expect(() => createAzureMaaVerifier({ trustedIssuers: [ISS], trustAnchors: TRUST_ANCHORS, policy: {} })).toThrow(/accept-all is not permitted/);
  });
});

describe('attest-azure-maa: verification fail-closed', () => {
  it('tampered signature denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ tamper: true }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/signature does not verify/);
  });

  it('untrusted issuer denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ iss: 'https://evil.attest.azure.net' }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/trusted MAA instance/);
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

  it('wrong report-data binding denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ reportDataHex: 'ff'.repeat(64) }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/does not bind/);
  });

  it('missing report-data claim denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ omitReportData: true }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/no report-data claim/);
  });

  it('wrong attestation-type denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ isolationType: 'nitro' }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/unexpected x-ms-attestation-type/);
  });

  it('untrusted signing chain denied (anchor mismatch)', async () => {
    const token = mkToken({ signPriv: ROGUE.priv, x5cHeaderValue: X5C_ROGUE });
    const r = await run(verifier({}, { token }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/signing chain invalid/);
  });

  it('kid not present in the JWKS denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ x5cInHeader: false, kid: 'kid-nope' }), jwks: JWKS }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/no JWKS key matches/);
  });

  it('tdx MRTD not in allowlist denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ measurement: '00'.repeat(48) }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/MRTD not in policy allowlist/);
  });

  it('sev-snp measurement not in allowlist denied', async () => {
    const r = await run(verifier({}, { token: mkToken({ isolationType: 'sevsnpvm', measurement: '11'.repeat(48) }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/launch measurement not in policy allowlist/);
  });

  it('isolation type present but policy has no allowlist for it denied', async () => {
    // Policy only has TDX; a sevsnpvm token must fail closed.
    const v = createAzureMaaVerifier({
      trustedIssuers: [ISS],
      trustAnchors: TRUST_ANCHORS,
      policy: { tdxMrtds: [MRTD] },
      resolveEvidence: () => ({ token: mkToken({ isolationType: 'sevsnpvm' }) }),
    });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/no SEV-SNP measurement allowlist/);
  });

  it('debuggable SEV-SNP guest denied unless allowDebug', async () => {
    const r = await run(verifier({}, { token: mkToken({ isolationType: 'sevsnpvm', debuggable: true }) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/debuggable/);
    const ok = await run(verifier({ policy: { ...POLICY, allowDebug: true } }, { token: mkToken({ isolationType: 'sevsnpvm', debuggable: true }) }));
    expect(ok.ok).toBe(true);
  });

  it('SEV-SNP host-data not in allowlist denied', async () => {
    const v = verifier({ policy: { ...POLICY, sevSnpHostData: ['aa'.repeat(32)] } }, { token: mkToken({ isolationType: 'sevsnpvm', hostData: HOSTDATA }) });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/host-data not in policy allowlist/);
  });

  it('absent evidence (no resolver) denied', async () => {
    const v = createAzureMaaVerifier({ trustedIssuers: [ISS], trustAnchors: TRUST_ANCHORS, policy: { ...POLICY } });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/no Azure MAA evidence resolver/);
  });

  it('expired signing certificate denied', async () => {
    const past = genEc();
    const expiredCert = makeCert({
      subjectSpkiDer: past.spkiDer,
      subjectCn: 'past',
      issuerCn: 'past',
      issuerPriv: past.priv,
      issuerAlg: 'ec',
      notBefore: '000101000000Z',
      notAfter: '010101000000Z', // 2001 — long expired
    });
    const token = mkToken({ signPriv: past.priv, x5cHeaderValue: [b64(expiredCert)] });
    const v = verifier({ trustAnchors: { rootSpkiSha256: [past.spkiSha256] } }, { token });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/validity window/);
  });

  it('unsupported alg denied', async () => {
    // Forge a header claiming HS256 (unsupported) over an otherwise valid body.
    const r = await run(verifier({}, { token: mkToken({ alg: 'ES256' }).replace(/^[^.]+/, Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' }), 'utf8').toString('base64url')) }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/unsupported JWS alg/);
  });
});

describe('attest-azure-maa: verifyX5cChain unit', () => {
  it('rejects an empty chain', async () => {
    const r = await verifyX5cChain([], TRUST_ANCHORS, { nowMs: T });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/empty x5c/);
  });
  it('verifies a self-chain anchored by fingerprint', async () => {
    const r = await verifyX5cChain(X5C_EC, { rootSpkiSha256: [EC.spkiSha256] }, { nowMs: T });
    expect(r.ok).toBe(true);
    expect(r.leafSpkiSha256).toBe(EC.spkiSha256);
  });
});

describe('attest-azure-maa: multi-root integration', () => {
  it('composes as one AttestationRoot in an N-of-M policy', async () => {
    const mv = createMultiRootVerifier({
      roots: [{ id: 'azure-maa', verifier: verifier(), suite: AZURE_MAA_SUITE }],
      threshold: 1,
    });
    const r = await mv.verify({ document: {} as never, ctx: {} as never, nowMs: T, expected: EXPECTED });
    expect(r.ok).toBe(true);
    expect(r.bound).toBe(true);
    expect(r.measured?.runtime_measurement).toBe(MRTD);
  });
});

describe('attest-azure-maa: fetchMaaJwks helper', () => {
  it('parses a mocked /certs JWKS response', async () => {
    const fakeFetch = (async () =>
      ({ ok: true, status: 200, json: async () => ({ keys: [{ kid: 'k1', kty: 'EC', x5c: X5C_EC }] }) }) as unknown as Response) as unknown as typeof fetch;
    const jwks = await fetchMaaJwks(ISS, { fetch: fakeFetch });
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]!.kid).toBe('k1');
    expect(jwks.keys[0]!.x5c).toEqual(X5C_EC);
  });
  it('throws on a non-2xx response', async () => {
    const fakeFetch = (async () => ({ ok: false, status: 503, json: async () => ({}) }) as unknown as Response) as unknown as typeof fetch;
    await expect(fetchMaaJwks(ISS, { fetch: fakeFetch })).rejects.toThrow(/HTTP 503/);
  });
});

describe('attest-azure-maa: TDX debug, TCB status and runtime user-data binding (gates exercised by synthetic tokens)', () => {
  it('REJECTS a debug TD (tdx_td_attributes_debug) unless allowDebug', async () => {
    const t = mkToken({ tdxDebug: true });
    expect((await run(verifier({}, { token: t }))).ok).toBe(false);
    expect((await run(verifier({ policy: { ...POLICY, allowDebug: true } }, { token: t }))).ok).toBe(true);
  });
  it('REJECTS dbgstat != disabled, ACCEPTS dbgstat disabled', async () => {
    expect((await run(verifier({}, { token: mkToken({ dbgstat: 'enabled' }) }))).ok).toBe(false);
    expect((await run(verifier({}, { token: mkToken({ dbgstat: 'disabled' }) }))).ok).toBe(true);
  });
  it('gates attester_tcb_status: default accepts UpToDate/SWHardeningNeeded, rejects OutOfDate/Revoked, honours a custom allowlist', async () => {
    for (const ok of ['UpToDate', 'SWHardeningNeeded']) {
      const r = await run(verifier({}, { token: mkToken({ tcbStatus: ok }) }));
      expect(r.ok).toBe(true);
      expect(r.hostAsserted?.tcb_status).toBe(ok);
    }
    for (const bad of ['OutOfDate', 'Revoked', 'ConfigurationNeeded']) {
      expect((await run(verifier({}, { token: mkToken({ tcbStatus: bad }) }))).ok).toBe(false);
    }
    const custom = verifier({ policy: { ...POLICY, tdxAllowedTcbStatuses: ['ConfigurationNeeded'] } }, { token: mkToken({ tcbStatus: 'ConfigurationNeeded' }) });
    expect((await run(custom)).ok).toBe(true);
  });
  it('runtimeUserDataBinding: ACCEPTS user-data == binding, REJECTS wrong / missing runtime claim', async () => {
    const pol = { ...POLICY, runtimeUserDataBinding: true };
    const good = verifier({ policy: pol }, { token: mkToken({ runtimeUserData: toHex(BOUND), omitReportData: true }) });
    expect((await run(good)).ok).toBe(true);
    const wrong = verifier({ policy: pol }, { token: mkToken({ runtimeUserData: toHex(new Uint8Array(64)), omitReportData: true }) });
    expect((await run(wrong)).ok).toBe(false);
    const absent = verifier({ policy: pol }, { token: mkToken({ runtimeUserData: null, omitReportData: true }) });
    const r = await run(absent);
    expect(r.ok).toBe(false);
  });
  it('runtimeUserDataBinding does NOT fall back to report_data equality', async () => {
    const pol = { ...POLICY, runtimeUserDataBinding: true };
    const r = await run(verifier({ policy: pol }, { token: mkToken({ runtimeUserData: null }) })); // report_data bound, no runtime
    expect(r.ok).toBe(false);
  });
});

describe('attest-azure-maa: SEV-SNP minimum reported TCB (sevSnpMinTcb)', () => {
  const SVNS = { bootloader: 10, snpfw: 27, microcode: 88, tee: 0 } as const;
  const snp = (svns: TokenOpts['svns'], minTcb?: NonNullable<AzureMaaVerifierOptions['policy']['sevSnpMinTcb']>) =>
    run(verifier({ policy: { ...POLICY, ...(minTcb ? { sevSnpMinTcb: minTcb } : {}) } }, { token: mkToken({ isolationType: 'sevsnpvm', svns }) }));

  it('surfaces the reported SVNs in hostAsserted even with no floor configured', async () => {
    const r = await snp(SVNS);
    expect(r.ok).toBe(true);
    expect(r.hostAsserted).toMatchObject({ bootloader_svn: '10', snpfw_svn: '27', microcode_svn: '88', tee_svn: '0' });
  });
  it('accepts values exactly at, and above, every floor', async () => {
    expect((await snp(SVNS, { bootloader: 10, snp: 27, microcode: 88, tee: 0 })).ok).toBe(true);
    expect((await snp(SVNS, { bootloader: 3, snp: 20, microcode: 50 })).ok).toBe(true);
  });
  it('rejects each field one below its floor with the specific reason', async () => {
    expect((await snp(SVNS, { bootloader: 11 })).reason).toBe('SEV-SNP bootloader SVN 10 is below the policy minimum 11');
    expect((await snp(SVNS, { snp: 28 })).reason).toBe('SEV-SNP snp SVN 27 is below the policy minimum 28');
    expect((await snp(SVNS, { microcode: 89 })).reason).toBe('SEV-SNP microcode SVN 88 is below the policy minimum 89');
    expect((await snp(SVNS, { tee: 1 })).reason).toBe('SEV-SNP tee SVN 0 is below the policy minimum 1');
  });
  it('fails closed on a missing or non-integer claim when a floor is configured, but not when none is', async () => {
    expect((await snp({ ...SVNS, microcode: null }, { microcode: 1 })).reason).toBe("SEV-SNP microcode SVN claim 'x-ms-sevsnpvm-microcode-svn' is missing or not a non-negative integer (policy requires a minimum)");
    expect((await snp({ ...SVNS, bootloader: '99' }, { bootloader: 1 })).reason).toBe("SEV-SNP bootloader SVN claim 'x-ms-sevsnpvm-bootloader-svn' is missing or not a non-negative integer (policy requires a minimum)");
    expect((await snp({ ...SVNS, microcode: null })).ok).toBe(true);
  });
  it('does not apply to TDX tokens', async () => {
    expect((await run(verifier({ policy: { ...POLICY, sevSnpMinTcb: { bootloader: 99 } } }))).ok).toBe(true);
  });
  it('validates the policy at construction', () => {
    const mk = (m: unknown) => () => verifier({ policy: { ...POLICY, sevSnpMinTcb: m as never } });
    expect(mk({ bootloader: -1 })).toThrow('policy.sevSnpMinTcb.bootloader must be a non-negative integer');
    expect(mk({ snp: 1.5 })).toThrow('policy.sevSnpMinTcb.snp must be a non-negative integer');
    expect(mk({ firmware: 1 })).toThrow('policy.sevSnpMinTcb.firmware is not a known field');
    expect(mk(null)).toThrow('policy.sevSnpMinTcb must be an object');
  });
});
