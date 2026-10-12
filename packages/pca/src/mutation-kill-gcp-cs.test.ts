/**
 * Mutation-kill suite for attest-gcp-confidential-space.ts: a configurable JWT / JWKS / x5c minter drives every
 * parse, anchor-resolution, signature, claim and policy branch with its exact refusal text.
 */
import * as crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  GCP_CS_DEFAULT_ISSUER,
  createGcpConfidentialSpaceVerifier,
  fetchGcpConfidentialSpaceJwks,
  parseGcpCsJwt,
  teeTypeOfHwModel,
  toHex,
  type GcpConfidentialSpaceVerifierOptions,
  type GcpCsEvidence,
  type GcpCsPolicy,
  type GcpJwks,
} from './attest-gcp-confidential-space';
import { attestationBinding, type ExpectedAttestationBinding } from './attestation';

// ── DER / X.509 mini minter (test-only) ──────────────────────────────────────────────────────────
const cat = (...a: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of a) {
    out.set(x, o);
    o += x.length;
  }
  return out;
};
const derLen = (n: number): Uint8Array => {
  if (n < 0x80) return Uint8Array.from([n]);
  const b: number[] = [];
  for (let x = n; x > 0; x = Math.floor(x / 256)) b.unshift(x & 0xff);
  return Uint8Array.from([0x80 | b.length, ...b]);
};
const tlv = (tag: number, c: Uint8Array): Uint8Array => cat(Uint8Array.from([tag]), derLen(c.length), c);
const seq = (...i: Uint8Array[]) => tlv(0x30, cat(...i));
const set = (...i: Uint8Array[]) => tlv(0x31, cat(...i));
const int = (v: number) => tlv(0x02, Uint8Array.from([v]));
const utf8 = (s: string) => tlv(0x0c, new Uint8Array(Buffer.from(s)));
const utc = (s: string) => tlv(0x17, new Uint8Array(Buffer.from(s, 'ascii')));
const oidOf = (d: string) => {
  const a = d.split('.').map(Number);
  const body: number[] = [a[0]! * 40 + a[1]!];
  for (const x of a.slice(2)) {
    const st = [x & 0x7f];
    for (let v = Math.floor(x / 128); v > 0; v = Math.floor(v / 128)) st.unshift((v & 0x7f) | 0x80);
    body.push(...st);
  }
  return tlv(0x06, Uint8Array.from(body));
};
const nm = (cn: string) => seq(set(seq(oidOf('2.5.4.3'), utf8(cn))));
function mkCert(o: { spki: Uint8Array; cn: string; issuerCn: string; issuerPriv: crypto.KeyObject; notBefore?: string; notAfter?: string; ec?: boolean }): Uint8Array {
  const alg = o.ec ? seq(oidOf('1.2.840.10045.4.3.2')) : seq(oidOf('1.2.840.113549.1.1.11'), Uint8Array.from([5, 0]));
  const tbs = seq(tlv(0xa0, int(2)), int(0x2a), alg, nm(o.issuerCn), seq(utc(o.notBefore ?? '230101000000Z'), utc(o.notAfter ?? '350101000000Z')), nm(o.cn), o.spki);
  const sig = crypto.sign('sha256', Buffer.from(tbs), o.issuerPriv);
  return seq(tbs, alg, tlv(0x03, cat(Uint8Array.from([0]), new Uint8Array(sig))));
}
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
const b64u = (b: Uint8Array | Buffer) => Buffer.from(b).toString('base64url');
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

interface KP {
  pub: crypto.KeyObject;
  priv: crypto.KeyObject;
  spki: Uint8Array;
  spkiSha: string;
}
const wrap = (publicKey: crypto.KeyObject, privateKey: crypto.KeyObject): KP => {
  const spki = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }));
  return { pub: publicKey, priv: privateKey, spki, spkiSha: crypto.createHash('sha256').update(Buffer.from(spki)).digest('hex') };
};
const rsa = () => {
  const k = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  return wrap(k.publicKey, k.privateKey);
};
const ec = (curve = 'P-256') => {
  const k = crypto.generateKeyPairSync('ec', { namedCurve: curve });
  return wrap(k.publicKey, k.privateKey);
};
const rsaJwk = (kp: KP, kid?: string) => {
  const j = kp.pub.export({ format: 'jwk' });
  return { ...(kid ? { kid } : {}), kty: 'RSA', n: String(j.n), e: String(j.e) };
};
const ecJwk = (kp: KP, kid?: string) => {
  const j = kp.pub.export({ format: 'jwk' });
  return { ...(kid ? { kid } : {}), kty: 'EC', crv: String(j.crv), x: String(j.x), y: String(j.y) };
};

// ── fixtures ─────────────────────────────────────────────────────────────────────────────────────
const ISS = GCP_CS_DEFAULT_ISSUER;
const T = 1_700_000_000_000;
const SEC = Math.floor(T / 1000);
const EXPECTED: ExpectedAttestationBinding = { holderPub: 'holder-1', grantRef: 'grant-1', epoch: 1, nonce: 'nonce-1', nonceIssuedAt: T - 1000 };
const BOUND = attestationBinding(EXPECTED);
const IMG = `sha256:${'ab'.repeat(32)}`;
const REF = 'us-docker.pkg.dev/p/r/w:latest';
const RSA = rsa();
const EC = ec();
const KID = 'kid-rsa';
const RSA_JWKS: GcpJwks = { keys: [rsaJwk(RSA, KID)] };

interface Tok {
  alg?: string;
  header?: Record<string, unknown>;
  payload?: Record<string, unknown>;
  priv?: crypto.KeyObject;
  sig?: Uint8Array;
  nonce?: unknown;
  container?: Record<string, unknown> | null;
  submods?: unknown;
}
const basePayload = (nonce: unknown, container: Record<string, unknown> | null | undefined, submods: unknown): Record<string, unknown> => ({
  iss: ISS,
  iat: SEC - 60,
  nbf: SEC - 60,
  exp: SEC + 3600,
  hwmodel: 'GCP_INTEL_TDX',
  swname: 'CONFIDENTIAL_SPACE',
  swversion: ['1'],
  dbgstat: 'disabled-since-boot',
  eat_nonce: nonce,
  submods: submods !== undefined ? submods : { container: container === null ? undefined : (container ?? { image_reference: REF, image_digest: IMG }), confidential_space: { support_attributes: ['STABLE'] } },
});
function token(t: Tok = {}): string {
  const alg = t.alg ?? 'RS256';
  const header = { alg, typ: 'JWT', kid: KID, ...(t.header ?? {}) };
  const payload = { ...basePayload(t.nonce !== undefined ? t.nonce : b64(BOUND), t.container, t.submods), ...(t.payload ?? {}) };
  const input = `${b64u(Buffer.from(JSON.stringify(header)))}.${b64u(Buffer.from(JSON.stringify(payload)))}`;
  let sig = t.sig;
  if (!sig) {
    const priv = t.priv ?? (alg === 'ES256' ? EC.priv : RSA.priv);
    sig = new Uint8Array(alg === 'ES256' ? crypto.sign('sha256', Buffer.from(input), { key: priv, dsaEncoding: 'ieee-p1363' }) : crypto.sign('sha256', Buffer.from(input), priv));
  }
  return `${input}.${b64u(sig)}`;
}
type Over = Partial<GcpConfidentialSpaceVerifierOptions>;
const mk = (over: Over = {}, ev?: GcpCsEvidence | (() => GcpCsEvidence | undefined)) =>
  createGcpConfidentialSpaceVerifier({
    trustedIssuers: [ISS],
    trustAnchors: { trustedJwks: RSA_JWKS },
    policy: { imageDigests: [IMG] },
    resolveEvidence: typeof ev === 'function' ? ev : () => ev ?? { token: token() },
    ...over,
  });
const run = (v: ReturnType<typeof mk>, o: { nowMs?: number; expected?: ExpectedAttestationBinding | undefined } = {}) =>
  Promise.resolve(v.verify({ document: {} as never, ctx: {} as never, nowMs: o.nowMs ?? T, expected: 'expected' in o ? (o.expected as ExpectedAttestationBinding) : EXPECTED }));
const reasonOf = async (v: ReturnType<typeof mk>, o: Parameters<typeof run>[1] = {}) => {
  const r = await run(v, o);
  return r.ok ? 'OK' : r.reason;
};
const withTok = (t: Tok, over: Over = {}, jwks?: GcpJwks) => mk(over, { token: token(t), ...(jwks ? { jwks } : {}) });
const tokReason = (t: Tok, over: Over = {}, o: Parameters<typeof run>[1] = {}, jwks?: GcpJwks) => reasonOf(withTok(t, over, jwks), o);
const policy = (p: Partial<GcpCsPolicy> = {}): Over => ({ policy: { imageDigests: [IMG], ...p } });
const throwsMsg = (f: () => unknown): string => {
  try {
    f();
  } catch (e) {
    return (e as Error).message;
  }
  return 'NO THROW';
};

describe('toHex / teeTypeOfHwModel', () => {
  it('toHex pads and lowercases', () => {
    expect(toHex(Uint8Array.from([0, 1, 15, 16, 171, 255]))).toBe('00010f10abff');
    expect(toHex(new Uint8Array(0))).toBe('');
  });
  it('hwmodel mapping: exact names, case-insensitive prefixes, nothing else', () => {
    for (const m of ['GCP_AMD_SEV', 'GCP_AMD_SEV_SNP', 'GCP_AMD_SEV_ES']) expect(teeTypeOfHwModel(m)).toBe('sev-snp');
    expect(teeTypeOfHwModel('GCP_INTEL_TDX')).toBe('tdx');
    expect(teeTypeOfHwModel('gcp_amd_sev_future')).toBe('sev-snp');
    expect(teeTypeOfHwModel('GCP_AMD_SEV_V9')).toBe('sev-snp');
    expect(teeTypeOfHwModel('gcp_intel_tdx_2')).toBe('tdx');
    expect(teeTypeOfHwModel('GCP_INTEL_TDX_V2')).toBe('tdx');
    for (const m of ['', 'GCP_NITRO', 'XGCP_AMD_SEV', 'FOO_GCP_AMD_SEV', 'FOO_GCP_INTEL_TDX', 'GCP_AMD', 'GCP_INTEL']) expect(teeTypeOfHwModel(m), m).toBeUndefined();
  });
});

describe('parseGcpCsJwt', () => {
  const seg = (o: unknown) => b64u(Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)));
  const fake = (h: unknown, p: unknown, s = 'AAAA') => `${seg(h)}.${seg(p)}.${s}`;
  const err = (t: unknown) => throwsMsg(() => parseGcpCsJwt(t as string));
  it('token framing', () => {
    expect(err('')).toBe('parseGcpCsJwt: empty token');
    expect(err(5)).toBe('parseGcpCsJwt: empty token');
    expect(err(undefined)).toBe('parseGcpCsJwt: empty token');
    expect(err('a.b')).toBe('parseGcpCsJwt: a compact JWS has exactly three dot-separated parts');
    expect(err('a.b.c.d')).toBe('parseGcpCsJwt: a compact JWS has exactly three dot-separated parts');
    const e = 'parseGcpCsJwt: empty JWS segment';
    expect(err('.b.c')).toBe(e);
    expect(err('a..c')).toBe(e);
    expect(err('a.b.')).toBe(e);
  });
  it('JSON segments', () => {
    expect(err(`${seg('{nope')}.${seg({})}.AAAA`)).toMatch(/^parseGcpCsJwt: malformed JSON segment: /);
    expect(err(`${seg({ alg: 'RS256' })}.${seg('}{')}.AAAA`)).toMatch(/^parseGcpCsJwt: malformed JSON segment: /);
    for (const h of ['[1]', '"x"', 'null', '5']) expect(err(fake(h, {})), h).toBe('parseGcpCsJwt: header is not a JSON object');
    for (const p of ['[1]', '"x"', 'null', '5']) expect(err(fake({ alg: 'RS256' }, p)), p).toBe('parseGcpCsJwt: payload is not a JSON object');
    for (const h of [{}, { alg: '' }, { alg: 5 }, { alg: null }]) expect(err(fake(h, {})), JSON.stringify(h)).toBe('parseGcpCsJwt: header has no alg');
    expect(err(fake({ alg: 'RS256' }, {}, '!'))).toBe('parseGcpCsJwt: empty signature');
  });
  it('header fields are kept only with the right types; signing input and signature are exact', () => {
    const t = fake({ alg: 'RS256', kid: 'k', jku: 'u', x5c: ['a', 'b'], typ: 'JWT', extra: 1 }, { a: 1 }, b64u(Buffer.from([1, 2, 3])));
    const p = parseGcpCsJwt(t);
    expect(p.header).toStrictEqual({ alg: 'RS256', kid: 'k', jku: 'u', x5c: ['a', 'b'], typ: 'JWT' });
    expect(p.payload).toEqual({ a: 1 });
    expect(Array.from(p.signature)).toEqual([1, 2, 3]);
    expect(Buffer.from(p.signingInput).toString('ascii')).toBe(t.split('.').slice(0, 2).join('.'));
    expect(parseGcpCsJwt(fake({ alg: 'ES256' }, {})).header).toStrictEqual({ alg: 'ES256' });
    expect(parseGcpCsJwt(fake({ alg: 'ES256', kid: 5, jku: 5, typ: 5, x5c: 'a' }, {})).header).toStrictEqual({ alg: 'ES256' });
    expect(parseGcpCsJwt(fake({ alg: 'ES256', x5c: ['a', 5] }, {})).header).toStrictEqual({ alg: 'ES256' });
    expect(parseGcpCsJwt(fake({ alg: 'ES256', x5c: [] }, {})).header).toStrictEqual({ alg: 'ES256', x5c: [] });
    expect(parseGcpCsJwt(fake({ alg: 'ES256', kid: '' }, {})).header).toStrictEqual({ alg: 'ES256', kid: '' });
  });
});

describe('createGcpConfidentialSpaceVerifier: construction guards', () => {
  const base = (): GcpConfidentialSpaceVerifierOptions => ({ trustedIssuers: [ISS], trustAnchors: { trustedJwks: RSA_JWKS }, policy: { imageDigests: [IMG] } });
  const m = (o: unknown) => throwsMsg(() => createGcpConfidentialSpaceVerifier(o as never));
  it('issuers, anchors, policy', () => {
    const iss = 'createGcpConfidentialSpaceVerifier: trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs';
    expect(m(undefined)).toBe(iss);
    expect(m(null)).toBe(iss);
    expect(m({ ...base(), trustedIssuers: undefined })).toBe(iss);
    expect(m({ ...base(), trustedIssuers: 'x' })).toBe(iss);
    expect(m({ ...base(), trustedIssuers: [] })).toBe(iss);
    const each = 'createGcpConfidentialSpaceVerifier: every trusted issuer must be a non-empty URL string';
    expect(m({ ...base(), trustedIssuers: [''] })).toBe(each);
    expect(m({ ...base(), trustedIssuers: [ISS, ''] })).toBe(each);
    expect(m({ ...base(), trustedIssuers: [5] })).toBe(each);
    const anc = 'createGcpConfidentialSpaceVerifier: trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted';
    for (const trustAnchors of [undefined, {}, { trustedJwks: { keys: [] } }, { trustedJwks: {} }, { trustedKeySpki: [] }, { rootCertsPem: [] }, { trustedJwks: { keys: [] }, trustedKeySpki: [], rootCertsPem: [] }]) expect(m({ ...base(), trustAnchors })).toBe(anc);
    expect(m({ ...base(), trustAnchors: { trustedKeySpki: ['aa'] } })).toBe('NO THROW');
    expect(m({ ...base(), trustAnchors: { rootCertsPem: ['x'] } })).toBe('NO THROW');
    expect(m({ ...base(), trustAnchors: { trustedJwks: RSA_JWKS, trustedKeySpki: ['aa'] } })).toBe('NO THROW'); // 1 + 1 is not 0
    expect(m({ ...base(), trustAnchors: { trustedJwks: RSA_JWKS, trustedKeySpki: ['aa'], rootCertsPem: ['x'] } })).toBe('NO THROW');
    expect(m({ ...base(), trustAnchors: { trustedKeySpki: ['aa'], rootCertsPem: ['x'] } })).toBe('NO THROW');
    expect(m({ ...base(), trustAnchors: { trustedJwks: RSA_JWKS, rootCertsPem: ['x'] } })).toBe('NO THROW');
    expect(m({ ...base(), trustAnchors: { trustedJwks: { keys: [rsaJwk(RSA, 'a'), rsaJwk(RSA, 'b')] }, trustedKeySpki: ['aa'] } })).toBe('NO THROW');
    expect(m({ ...base(), trustAnchors: { trustedKeySpki: ['aa', 'bb'], rootCertsPem: ['x'] } })).toBe('NO THROW');
    const pol = 'createGcpConfidentialSpaceVerifier: policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)';
    for (const p of [undefined, null, {}, { imageDigests: [] }, { imageDigests: 'x' }]) expect(m({ ...base(), policy: p })).toBe(pol);
    expect(m({ ...base(), policy: { imageDigests: [IMG], allowedTeeTypes: [] } })).toBe('createGcpConfidentialSpaceVerifier: policy.allowedTeeTypes, when present, must be non-empty');
    expect(m({ ...base(), policy: { imageDigests: [IMG], allowedTeeTypes: ['tdx'] } })).toBe('NO THROW');
  });
});

describe('verify: evidence and token shape', () => {
  it('missing resolver / evidence', async () => {
    expect(await reasonOf(createGcpConfidentialSpaceVerifier({ trustedIssuers: [ISS], trustAnchors: { trustedJwks: RSA_JWKS }, policy: { imageDigests: [IMG] } }))).toBe('no GCP Confidential Space evidence resolver configured (fail closed)');
    const m = 'no GCP Confidential Space token for this action';
    for (const ev of [undefined, null, {}, { token: '' }, { token: 5 }, { token: undefined }] as unknown[]) expect(await reasonOf(mk({}, () => ev as GcpCsEvidence | undefined)), JSON.stringify(ev)).toBe(m);
  });
  it('async resolvers are awaited and receive (document, ctx)', async () => {
    const seen: unknown[][] = [];
    const doc = { d: 1 } as never;
    const ctx = { c: 1 } as never;
    const v = createGcpConfidentialSpaceVerifier({ trustedIssuers: [ISS], trustAnchors: { trustedJwks: RSA_JWKS }, policy: { imageDigests: [IMG] }, resolveEvidence: async (...a: unknown[]) => (seen.push(a), { token: token() }) });
    expect((await v.verify({ document: doc, ctx, nowMs: T, expected: EXPECTED })).ok).toBe(true);
    expect(seen).toEqual([[doc, ctx]]);
  });
  it('parse failure and unsupported algorithms', async () => {
    expect(await reasonOf(mk({}, { token: 'a.b' }))).toBe('Confidential Space token parse failed: parseGcpCsJwt: a compact JWS has exactly three dot-separated parts');
    for (const alg of ['HS256', 'none', 'RS384', 'rs256', 'PS256']) expect(await tokReason({ alg, sig: Uint8Array.of(1) }), alg).toBe(`unsupported JWS alg '${alg}' (Confidential Space uses RS256)`);
  });
  it('exceptions inside verification are fail-closed refusals', async () => {
    const v = mk({}, () => {
      throw new Error('resolver exploded');
    });
    expect(await reasonOf(v)).toBe('gcp-confidential-space verification error (fail closed): resolver exploded');
    const w = mk({}, () => {
      throw 'str';
    });
    expect(await reasonOf(w)).toBe('gcp-confidential-space verification error (fail closed): unknown');
  });
});

describe('verify: signing key resolution and anchoring', () => {
  const ANY = (over: Over['trustAnchors']): Over => ({ trustAnchors: over });
  it('the happy path with the pinned JWKS, with or without a kid', async () => {
    expect(await tokReason({})).toBe('OK');
    expect(await tokReason({ header: { kid: undefined } })).toBe('OK'); // a sole trusted key needs no kid
    const two: GcpJwks = { keys: [rsaJwk(RSA, 'a'), rsaJwk(rsa(), 'b')] };
    expect(await tokReason({ header: { kid: undefined } }, ANY({ trustedJwks: two }))).toBe('Confidential Space signing key invalid: no kid on the token and no unambiguous single signing key available');
    expect(await tokReason({ header: { kid: '' } }, ANY({ trustedJwks: two }))).toBe('Confidential Space signing key invalid: no kid on the token and no unambiguous single signing key available');
    expect(await tokReason({ header: { kid: 'a' } }, ANY({ trustedJwks: two }))).toBe('OK');
    expect(await tokReason({ header: { kid: 'zzz' } })).toBe("Confidential Space signing key invalid: no JWKS key matches the token kid 'zzz' (untrusted signer)");
    expect(await tokReason({ header: { kid: undefined } }, ANY({ trustedJwks: { keys: [] }, trustedKeySpki: [RSA.spkiSha] }))).toBe('Confidential Space signing key invalid: no kid on the token and no unambiguous single signing key available');
  });
  it('an empty kid is treated as no kid (a sole key is used)', async () => {
    expect(await tokReason({ header: { kid: '' } })).toBe('OK');
    expect(await tokReason({ header: { kid: '' } }, ANY({ trustedKeySpki: [RSA.spkiSha] }), {}, { keys: [rsaJwk(RSA, 'only')] })).toBe('OK');
  });
  it('a header x5c never overrides a key that the JWKS already provides', async () => {
    const junkChain = ['bm90IGEgY2VydA=='];
    expect(await tokReason({ header: { x5c: junkChain } })).toBe('OK'); // kid present, pinned key found
    expect(await tokReason({ header: { kid: undefined, x5c: junkChain } })).toBe('OK'); // no kid, sole pinned key
    expect(await tokReason({ header: { kid: '', x5c: junkChain } })).toBe('OK');
  });
  it('an unsupported JWS algorithm is reported before any key resolution', async () => {
    expect(await tokReason({ alg: 'HS256', header: { kid: 'nowhere' }, sig: Uint8Array.of(1) })).toBe("unsupported JWS alg 'HS256' (Confidential Space uses RS256)");
    expect(await tokReason({ alg: 'none', header: { kid: 'nowhere' }, sig: Uint8Array.of(1) })).toBe("unsupported JWS alg 'none' (Confidential Space uses RS256)");
  });
  it('a key published only in the evidence JWKS must corroborate a configured anchor', async () => {
    const ev: GcpJwks = { keys: [rsaJwk(RSA, 'ev')] };
    const t = { header: { kid: 'ev' } };
    const none = 'Confidential Space signing key invalid: signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)';
    expect(await tokReason(t, ANY({ trustedJwks: { keys: [rsaJwk(rsa(), 'other')] } }), {}, ev)).toBe(none);
    expect(await tokReason(t, ANY({ trustedKeySpki: ['00'.repeat(32)] }), {}, ev)).toBe(none);
    expect(await tokReason(t, ANY({ trustedKeySpki: [RSA.spkiSha] }), {}, ev)).toBe('OK');
    expect(await tokReason(t, ANY({ trustedKeySpki: [RSA.spkiSha.toUpperCase()] }), {}, ev)).toBe('OK');
    expect(await tokReason(t, ANY({ trustedJwks: { keys: [rsaJwk(RSA, 'renamed')] } }), {}, ev)).toBe('OK'); // same material, any kid
    // an unusable pinned key is skipped, a later matching one is found
    expect(await tokReason(t, ANY({ trustedJwks: { keys: [{ kid: 'junk', kty: 'RSA' }, rsaJwk(RSA, 'p')] } }), {}, ev)).toBe('OK');
    expect(await tokReason(t, ANY({ trustedJwks: { keys: [{ kid: 'junk', kty: 'RSA' }] } }), {}, ev)).toBe(none);
    // a rogue evidence key under the pinned kid is not trusted
    const rogue: GcpJwks = { keys: [rsaJwk(rsa(), KID)] };
    expect(await tokReason({ priv: undefined }, {}, {}, rogue)).toMatch(/^Confidential Space signing key invalid: signing key is not anchored/);
    // the evidence key wins over the pinned one only if it matches an anchor; a different pinned key by kid is NOT consulted afterwards
    expect(await tokReason({ priv: RSA.priv }, {}, {}, { keys: [rsaJwk(RSA, KID)] })).toBe('OK');
  });
  it('unusable JWKs', async () => {
    const t = { header: { kid: 'u' } };
    const run1 = (jwk: Record<string, unknown>) => tokReason(t, ANY({ trustedJwks: { keys: [jwk as never] } }));
    expect(await run1({ kid: 'u', kty: 'RSA' })).toBe('Confidential Space signing key invalid: JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate');
    expect(await run1({ kid: 'u', kty: 'RSA', n: String(rsaJwk(RSA).n) })).toBe('Confidential Space signing key invalid: JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate');
    expect(await run1({ kid: 'u', kty: 'RSA', e: 'AQAB' })).toBe('Confidential Space signing key invalid: JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate');
    expect(await run1({ kid: 'u', kty: 'EC', crv: 'P-256', x: 'a' })).toBe('Confidential Space signing key invalid: JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate');
    expect(await run1({ kid: 'u', kty: 'EC', crv: 'P-256', y: 'a' })).toBe('Confidential Space signing key invalid: JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate');
    expect(await run1({ kid: 'u', kty: 'EC', x: 'a', y: 'b' })).toBe('Confidential Space signing key invalid: JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate');
    expect(await run1({ kid: 'u', kty: 'OKP', crv: 'P-256', x: 'a', y: 'b' })).toBe('Confidential Space signing key invalid: JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate');
    expect(await run1({ kid: 'u', x5c: [] })).toBe('Confidential Space signing key invalid: JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate');
    expect(await run1({ kid: 'u', x5c: [5] })).toBe('Confidential Space signing key invalid: JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate');
    expect(await run1({ kid: 'u', kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' })).toMatch(/^Confidential Space signing key invalid: JWKS key is not a usable public key: /);
    expect(await run1({ kid: 'u', x5c: ['bm90IGEgY2VydA=='] })).toMatch(/^Confidential Space signing key invalid: JWKS key is not a usable public key: /);
  });
  it('EC JWKs and RSA n/e take precedence over x5c', async () => {
    const e = ec();
    const jwks: GcpJwks = { keys: [ecJwk(e, 'ecj')] };
    expect(await tokReason({ alg: 'ES256', priv: e.priv, header: { kid: 'ecj' } }, ANY({ trustedJwks: jwks }))).toBe('OK');
    const both = { ...ecJwk(e, 'ecj'), n: String(rsaJwk(RSA).n), e: 'AQAB' };
    // n/e present => the RSA branch is taken even though x/y exist
    expect(await tokReason({ alg: 'ES256', priv: e.priv, header: { kid: 'ecj' } }, ANY({ trustedJwks: { keys: [both] } }))).toMatch(/^ES256 token but signing key is RSA/);
  });
});

describe('verify: x5c anchoring', () => {
  const CA = rsa();
  const LEAF = rsa();
  const mkChain = (o: { leafNotAfter?: string; leafNotBefore?: string; caNotAfter?: string; caNotBefore?: string; signer?: crypto.KeyObject } = {}) => {
    const root = mkCert({ spki: CA.spki, cn: 'root', issuerCn: 'root', issuerPriv: CA.priv, notBefore: o.caNotBefore, notAfter: o.caNotAfter });
    const leaf = mkCert({ spki: LEAF.spki, cn: 'leaf', issuerCn: 'root', issuerPriv: o.signer ?? CA.priv, notBefore: o.leafNotBefore, notAfter: o.leafNotAfter });
    return { root, leaf, rootPem: new crypto.X509Certificate(Buffer.from(root)).toString() };
  };
  const GOOD = mkChain();
  const x5c = (...c: Uint8Array[]) => c.map(b64);
  const tk = (over: Tok = {}): Tok => ({ ...over, priv: over.priv ?? LEAF.priv, header: { kid: 'x', ...(over.header ?? {}) } });
  const anchor = (a: NonNullable<Over['trustAnchors']>, ev: GcpJwks) => (t: Tok = {}, o: Parameters<typeof run>[1] = {}, over: Over = {}) => tokReason(tk(t), { trustAnchors: a, ...over }, o, ev);
  const ev = (chain: string[], extra: Record<string, unknown> = {}): GcpJwks => ({ keys: [{ kid: 'x', kty: 'RSA', x5c: chain, ...extra }] });
  const PREFIX = 'Confidential Space signing key invalid: signing key not trusted: ';
  it('a chain to a configured root, to a pinned key in the chain, and via a bare public-key PEM', async () => {
    const run = anchor({ rootCertsPem: [GOOD.rootPem] }, ev(x5c(GOOD.leaf, GOOD.root)));
    expect(await run()).toBe('OK');
    expect(await anchor({ rootCertsPem: [GOOD.rootPem] }, ev(x5c(GOOD.leaf)))()).toBe('OK'); // top cert signed by the root
    expect(await anchor({ trustedKeySpki: [LEAF.spkiSha] }, ev(x5c(GOOD.leaf, GOOD.root)))()).toBe('OK');
    expect(await anchor({ trustedKeySpki: [CA.spkiSha.toUpperCase()] }, ev(x5c(GOOD.leaf, GOOD.root)))()).toBe('OK');
    const pubPem = CA.pub.export({ type: 'spki', format: 'pem' }) as string;
    expect(await anchor({ rootCertsPem: [pubPem] }, ev(x5c(GOOD.leaf)))()).toBe('OK');
    expect(await anchor({ rootCertsPem: ['junk', GOOD.rootPem] }, ev(x5c(GOOD.leaf)))()).toBe('OK'); // an unparseable root entry is skipped
    expect(await anchor({ rootCertsPem: ['-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----', pubPem] }, ev(x5c(GOOD.leaf)))()).toBe('OK');
    expect(await anchor({ rootCertsPem: ['junk'] }, ev(x5c(GOOD.leaf)))()).toBe(`${PREFIX}x5c chain does not anchor in a configured GCP trust root`);
    // a well-formed root that did NOT sign the chain is not an anchor
    const strangerRoot = mkChain();
    const strangerCa = rsa();
    const strangerPem = new crypto.X509Certificate(Buffer.from(mkCert({ spki: strangerCa.spki, cn: 'stranger', issuerCn: 'stranger', issuerPriv: strangerCa.priv }))).toString();
    expect(await anchor({ rootCertsPem: [strangerPem] }, ev(x5c(GOOD.leaf)))()).toBe(`${PREFIX}x5c chain does not anchor in a configured GCP trust root`);
    expect(await anchor({ rootCertsPem: [strangerPem, strangerRoot.rootPem] }, ev(x5c(GOOD.leaf)))()).toBe('OK');
    expect(await anchor({ rootCertsPem: [strangerCa.pub.export({ type: 'spki', format: 'pem' }) as string] }, ev(x5c(GOOD.leaf)))()).toBe(`${PREFIX}x5c chain does not anchor in a configured GCP trust root`);
  });
  it('the header x5c is used when no JWKS lists the key (with and without a kid)', async () => {
    const t = (header: Record<string, unknown>) => tk({ header });
    const a: NonNullable<Over['trustAnchors']> = { rootCertsPem: [GOOD.rootPem] };
    expect(await tokReason(t({ x5c: x5c(GOOD.leaf, GOOD.root) }), { trustAnchors: a }, {}, { keys: [] })).toBe('OK');
    expect(await tokReason(t({ kid: undefined, x5c: x5c(GOOD.leaf, GOOD.root) }), { trustAnchors: a }, {}, { keys: [] })).toBe('OK');
    expect(await tokReason(t({ kid: '', x5c: x5c(GOOD.leaf, GOOD.root) }), { trustAnchors: a }, {}, { keys: [] })).toBe('OK');
    expect(await tokReason(t({ x5c: [] }), { trustAnchors: a }, {}, { keys: [] })).toBe("Confidential Space signing key invalid: no JWKS key matches the token kid 'x' (untrusted signer)");
    expect(await tokReason(t({ kid: undefined, x5c: [] }), { trustAnchors: a }, {}, { keys: [] })).toBe('Confidential Space signing key invalid: no kid on the token and no unambiguous single signing key available');
    // an unanchored header chain is refused
    expect(await tokReason(t({ x5c: x5c(GOOD.leaf, GOOD.root) }), { trustAnchors: { rootCertsPem: [mkChain().rootPem.replace(/A/g, 'B')] } }, {}, { keys: [] })).toMatch(/^Confidential Space signing key invalid: /);
  });
  it('x5c is only consulted when there is something to anchor it to', async () => {
    const e = ev(x5c(GOOD.leaf, GOOD.root));
    // only a pinned JWKS (which does not hold this key): no root / SPKI anchors -> not anchored
    expect(await anchor({ trustedJwks: { keys: [rsaJwk(rsa(), 'zz')] } }, e)()).toBe('Confidential Space signing key invalid: signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)');
    // an x5c key matching the pinned JWKS by material is trusted without chain checks
    expect(await anchor({ trustedJwks: { keys: [rsaJwk(LEAF, 'p')] } }, e)()).toBe('OK');
    expect(await anchor({ trustedKeySpki: ['00'.repeat(32)] }, e)()).toBe(`${PREFIX}x5c chain does not anchor in a configured GCP trust root`);
    expect(await anchor({ rootCertsPem: [GOOD.rootPem] }, { keys: [{ kid: 'x', kty: 'RSA', x5c: [] }] })()).toMatch(/not anchored|neither/);
  });
  it('chain defects', async () => {
    const a = { rootCertsPem: [GOOD.rootPem] };
    const bad = (chain: string[], at: Parameters<typeof run>[1] = {}) => anchor(a, ev(chain))({}, at);
    expect(await bad([''])).toMatch(/^Confidential Space signing key invalid: JWKS key is not a usable public key: /);
    expect(await bad([b64(GOOD.leaf), ''])).toBe(`${PREFIX}empty x5c entry at index 1`);
    expect(await bad([b64(GOOD.leaf), 5 as never])).toBe(`${PREFIX}empty x5c entry at index 1`);
    expect(await bad([b64(GOOD.leaf), 'bm90IGEgY2VydA=='])).toMatch(new RegExp(`^${PREFIX}malformed x5c certificate at index 1: .+`));
    // validity windows: certificate times are whole seconds
    const win = mkChain({ leafNotBefore: '231114221320Z', leafNotAfter: '231114221340Z' }); // 2023-11-14T22:13:20Z .. 22:13:40Z
    const from = Date.parse('2023-11-14T22:13:20Z');
    const to = Date.parse('2023-11-14T22:13:40Z');
    const runWin = (nowMs: number, over: Over = {}) => tokReason({ ...tk(), payload: { iat: Math.floor(nowMs / 1000) - 10, nbf: Math.floor(nowMs / 1000) - 10, exp: Math.floor(nowMs / 1000) + 100 } }, { trustAnchors: a, ...over }, { nowMs }, ev(x5c(win.leaf, win.root)));
    // (leaf signed by CA; root cert is the same CA)
    expect(await runWin(from)).toBe('OK');
    expect(await runWin(to)).toBe('OK');
    expect(await runWin(from - 1)).toBe(`${PREFIX}x5c certificate at index 0 is outside its validity window`);
    expect(await runWin(to + 1)).toBe(`${PREFIX}x5c certificate at index 0 is outside its validity window`);
    expect(await runWin(from - 1000, { clockSkewMs: 1000 })).toBe('OK');
    expect(await runWin(to + 1000, { clockSkewMs: 1000 })).toBe('OK');
    expect(await runWin(from - 1001, { clockSkewMs: 1000 })).toBe(`${PREFIX}x5c certificate at index 0 is outside its validity window`);
    expect(await runWin(to + 1001, { clockSkewMs: 1000 })).toBe(`${PREFIX}x5c certificate at index 0 is outside its validity window`);
    const rootExpired = mkChain({ caNotAfter: '231114221300Z' });
    expect(await anchor(a, ev(x5c(rootExpired.leaf, rootExpired.root)))({}, { nowMs: T })).toBe(`${PREFIX}x5c certificate at index 1 is outside its validity window`);
    // each link is signed by the one above it
    const other = rsa();
    const wrongLink = mkChain({ signer: other.priv });
    expect(await anchor(a, ev(x5c(wrongLink.leaf, wrongLink.root)))()).toBe(`${PREFIX}x5c link 0 is not signed by the certificate above it`);
    // three certificates: both links are checked
    const mid = rsa();
    const midCert = mkCert({ spki: mid.spki, cn: 'mid', issuerCn: 'root', issuerPriv: CA.priv });
    const leaf3 = mkCert({ spki: LEAF.spki, cn: 'leaf', issuerCn: 'mid', issuerPriv: mid.priv });
    expect(await anchor(a, ev(x5c(leaf3, midCert, GOOD.root)))()).toBe('OK');
    const leaf3bad = mkCert({ spki: LEAF.spki, cn: 'leaf', issuerCn: 'mid', issuerPriv: other.priv });
    expect(await anchor(a, ev(x5c(leaf3bad, midCert, GOOD.root)))()).toBe(`${PREFIX}x5c link 0 is not signed by the certificate above it`);
    const midBad = mkCert({ spki: mid.spki, cn: 'mid', issuerCn: 'root', issuerPriv: other.priv });
    expect(await anchor(a, ev(x5c(leaf3, midBad, GOOD.root)))()).toBe(`${PREFIX}x5c link 1 is not signed by the certificate above it`);
  });
});

describe('verify: JWS signature', () => {
  it('RS256 / ES256 against the right and the wrong key family', async () => {
    const e = ec();
    const e384 = ec('P-384');
    const ecJwks = (kp: KP): Over => ({ trustAnchors: { trustedJwks: { keys: [ecJwk(kp, KID)] } } });
    expect(await tokReason({ alg: 'ES256', priv: e.priv }, ecJwks(e))).toBe('OK');
    expect(await tokReason({ alg: 'RS256', priv: RSA.priv, sig: undefined }, ecJwks(e))).toBe('RS256 token but signing key is EC (not RSA)');
    expect(await tokReason({ alg: 'ES256', priv: RSA.priv, sig: Uint8Array.from({ length: 64 }, () => 1) })).toBe('ES256 token but signing key is RSA/undefined (not EC P-256)');
    expect(await tokReason({ alg: 'ES256', priv: e384.priv, sig: Uint8Array.from({ length: 64 }, () => 1) }, ecJwks(e384))).toBe('ES256 token but signing key is EC/P-384 (not EC P-256)');
    expect(await tokReason({ alg: 'ES256', sig: Uint8Array.from({ length: 63 }, () => 1) }, ecJwks(e))).toBe('ES256 signature is 63 bytes (expected 64: r‖s)');
    expect(await tokReason({ alg: 'ES256', sig: Uint8Array.from({ length: 65 }, () => 1) }, ecJwks(e))).toBe('ES256 signature is 65 bytes (expected 64: r‖s)');
    expect(await tokReason({ alg: 'ES256', sig: new Uint8Array(64) }, ecJwks(e))).toBe('JWS ES256 signature does not verify under the Confidential Space signing key');
    expect(await tokReason({ alg: 'ES256', priv: ec().priv }, ecJwks(e))).toBe('JWS ES256 signature does not verify under the Confidential Space signing key');
    expect(await tokReason({ sig: Uint8Array.from({ length: 256 }, () => 7) })).toBe('JWS RS256 signature does not verify under the Confidential Space signing key');
    expect(await tokReason({ sig: Uint8Array.of(1) })).toBe('JWS RS256 signature does not verify under the Confidential Space signing key');
    expect(await tokReason({ priv: rsa().priv })).toBe('JWS RS256 signature does not verify under the Confidential Space signing key');
  });
  it('an ES256 (raw r||s) signature is not a DER signature and a tampered payload fails', async () => {
    const e = ec();
    const good = token({ alg: 'ES256', priv: e.priv });
    const [h, p, s] = good.split('.');
    const tampered = `${h}.${b64u(Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p!, 'base64url').toString()), hwmodel: 'GCP_AMD_SEV' })))}.${s}`;
    const v = mk({ trustAnchors: { trustedJwks: { keys: [ecJwk(e, KID)] } } }, { token: tampered });
    expect(await reasonOf(v)).toBe('JWS ES256 signature does not verify under the Confidential Space signing key');
  });
});

describe('verify: standard claims', () => {
  it('issuer', async () => {
    const m = (v: string) => `token iss '${v}' is not a configured trusted Google attestation issuer`;
    expect(await tokReason({ payload: { iss: 'https://evil.example' } })).toBe(m('https://evil.example'));
    expect(await tokReason({ payload: { iss: undefined } })).toBe(m('undefined'));
    expect(await tokReason({ payload: { iss: '' } })).toBe(m(''));
    expect(await tokReason({ payload: { iss: 5 } })).toBe(m('undefined'));
    expect(await tokReason({ payload: { iss: `${ISS}/` } })).toBe(m(`${ISS}/`));
    expect(await tokReason({ payload: { iss: 'https://other.example' } }, { trustedIssuers: [ISS, 'https://other.example'] })).toBe('OK');
  });
  it('exp / nbf / iat, with skew rounded up to whole seconds', async () => {
    const at = (nowMs: number, payload: Record<string, unknown>, over: Over = {}) => tokReason({ payload }, over, { nowMs });
    expect(await at(T, { exp: undefined })).toBe('token has no exp (cannot bound validity — fail closed)');
    expect(await at(T, { exp: 'soon' })).toBe('token has no exp (cannot bound validity — fail closed)');
    expect(await at(T, { exp: null })).toBe('token has no exp (cannot bound validity — fail closed)');
    expect(await at(T, { exp: SEC })).toBe('OK');
    expect(await at(T + 1000, { exp: SEC })).toBe('Confidential Space token expired');
    expect(await at(T, { exp: SEC - 1 })).toBe('Confidential Space token expired');
    expect(await at(T + 999, { exp: SEC })).toBe('OK'); // same second
    // skew 1500 ms => 2 s
    expect(await at(T + 2000, { exp: SEC }, { clockSkewMs: 1500 })).toBe('OK');
    expect(await at(T + 3000, { exp: SEC }, { clockSkewMs: 1500 })).toBe('Confidential Space token expired');
    expect(await at(T + 1000, { exp: SEC }, { clockSkewMs: 1 })).toBe('OK'); // ceil(1ms) = 1 s
    expect(await at(T + 2000, { exp: SEC }, { clockSkewMs: 1 })).toBe('Confidential Space token expired');
    // nbf
    expect(await at(T, { nbf: SEC })).toBe('OK');
    expect(await at(T, { nbf: SEC + 1 })).toBe('Confidential Space token not yet valid (nbf)');
    expect(await at(T, { nbf: SEC + 2 }, { clockSkewMs: 1500 })).toBe('OK');
    expect(await at(T, { nbf: SEC + 3 }, { clockSkewMs: 1500 })).toBe('Confidential Space token not yet valid (nbf)');
    expect(await at(T, { nbf: undefined })).toBe('OK');
    expect(await at(T, { nbf: 'x' })).toBe('OK');
    // iat
    expect(await at(T, { iat: SEC })).toBe('OK');
    expect(await at(T, { iat: SEC + 1 })).toBe('Confidential Space token issued in the future (iat)');
    expect(await at(T, { iat: SEC + 2 }, { clockSkewMs: 1500 })).toBe('OK');
    expect(await at(T, { iat: SEC + 3 }, { clockSkewMs: 1500 })).toBe('Confidential Space token issued in the future (iat)');
    expect(await at(T, { iat: undefined })).toBe('OK');
    // skew sanitisation: negative / NaN / infinite behave as zero
    for (const clockSkewMs of [-5000, NaN, Infinity, -Infinity]) {
      expect(await at(T + 1000, { exp: SEC }, { clockSkewMs }), String(clockSkewMs)).toBe('Confidential Space token expired');
      expect(await at(T, { nbf: SEC + 1 }, { clockSkewMs }), String(clockSkewMs)).toBe('Confidential Space token not yet valid (nbf)');
    }
  });
});

describe('verify: Confidential Space claims', () => {
  it('submods.confidential_space is required and must be an object', async () => {
    const m = 'token carries no submods.confidential_space (not a Confidential Space token)';
    for (const submods of [undefined, null, 'x', [], 5, {}, { confidential_space: null }, { confidential_space: 'x' }, { confidential_space: [] }, { confidential_space: 5 }]) {
      expect(await tokReason({ submods: submods === undefined ? { container: { image_digest: IMG } } : submods }), JSON.stringify(submods)).toBe(m);
    }
    expect(await tokReason({ payload: { submods: undefined } })).toBe(m);
  });
  it('swname and swversion', async () => {
    expect(await tokReason({ payload: { swname: 'OTHER' } })).toBe("unexpected swname 'OTHER' (expected 'CONFIDENTIAL_SPACE')");
    expect(await tokReason({ payload: { swname: undefined } })).toBe("unexpected swname 'undefined' (expected 'CONFIDENTIAL_SPACE')");
    expect(await tokReason({ payload: { swname: 5 } })).toBe("unexpected swname 'undefined' (expected 'CONFIDENTIAL_SPACE')");
    expect(await tokReason({ payload: { swname: 'MINE' } }, policy({ expectedSwName: 'MINE' }))).toBe('OK');
    expect(await tokReason({ payload: { swname: 'CONFIDENTIAL_SPACE' } }, policy({ expectedSwName: 'MINE' }))).toBe("unexpected swname 'CONFIDENTIAL_SPACE' (expected 'MINE')");
    expect(await tokReason({ payload: { swname: 'CONFIDENTIAL_SPACE' } }, { policy: { imageDigests: [IMG], expectedSwName: 5 as never } })).toBe('OK');
    expect(await tokReason({ payload: { swname: '' } }, policy({ expectedSwName: '' }))).toBe('OK');
    const sv = 'swversion not in policy allowlist';
    expect(await tokReason({ payload: { swversion: ['1', '2'] } }, policy({ allowedSwVersions: ['2'] }))).toBe('OK');
    expect(await tokReason({ payload: { swversion: ['1', '2'] } }, policy({ allowedSwVersions: ['3'] }))).toBe(sv);
    expect(await tokReason({ payload: { swversion: '2' } }, policy({ allowedSwVersions: ['2'] }))).toBe('OK');
    expect(await tokReason({ payload: { swversion: '2' } }, policy({ allowedSwVersions: ['3'] }))).toBe(sv);
    expect(await tokReason({ payload: { swversion: '' } }, policy({ allowedSwVersions: [''] }))).toBe(sv);
    expect(await tokReason({ payload: { swversion: undefined } }, policy({ allowedSwVersions: ['1'] }))).toBe(sv);
    expect(await tokReason({ payload: { swversion: ['2', 5] } }, policy({ allowedSwVersions: ['2'] }))).toBe(sv); // a mixed array is not a string array
    expect(await tokReason({ payload: { swversion: 5 } }, policy({ allowedSwVersions: ['5'] }))).toBe(sv);
    expect(await tokReason({ payload: { swversion: ['9'] } }, policy({ allowedSwVersions: [] }))).toBe(sv); // an empty allowlist admits nothing
    expect(await tokReason({ payload: { swversion: ['9'] } })).toBe('OK'); // no allowlist, no gate
  });
  it('hwmodel and isolation family policy', async () => {
    expect(await tokReason({ payload: { hwmodel: undefined } })).toBe('token carries no hwmodel claim');
    expect(await tokReason({ payload: { hwmodel: '' } })).toBe('token carries no hwmodel claim');
    expect(await tokReason({ payload: { hwmodel: 5 } })).toBe('token carries no hwmodel claim');
    expect(await tokReason({ payload: { hwmodel: 'GCP_NITRO' } })).toBe("unrecognized hwmodel 'GCP_NITRO' (not a known AMD SEV-SNP / Intel TDX model)");
    expect(await tokReason({ payload: { hwmodel: 'GCP_AMD_SEV_SNP' } }, policy({ allowedTeeTypes: ['tdx'] }))).toBe("attestation type 'sev-snp' (hwmodel 'GCP_AMD_SEV_SNP') is not in the policy allowlist");
    expect(await tokReason({ payload: { hwmodel: 'GCP_INTEL_TDX' } }, policy({ allowedTeeTypes: ['sev-snp'] }))).toBe("attestation type 'tdx' (hwmodel 'GCP_INTEL_TDX') is not in the policy allowlist");
    expect(await tokReason({ payload: { hwmodel: 'GCP_INTEL_TDX' } }, policy({ allowedTeeTypes: ['sev-snp', 'tdx'] }))).toBe('OK');
    expect(await tokReason({ payload: { hwmodel: 'gcp_amd_sev_next' } })).toBe('OK');
  });
  it('debug state', async () => {
    const m = (v: string) => `token dbgstat '${v}' is not 'disabled-since-boot' (debug build — no confidentiality)`;
    expect(await tokReason({ payload: { dbgstat: 'enabled' } })).toBe(m('enabled'));
    expect(await tokReason({ payload: { dbgstat: undefined } })).toBe(m('undefined'));
    expect(await tokReason({ payload: { dbgstat: 'disabled-since-boot ' } })).toBe(m('disabled-since-boot '));
    expect(await tokReason({ payload: { dbgstat: 'enabled' } }, policy({ allowDebug: true }))).toBe('OK');
    expect(await tokReason({ payload: { dbgstat: 'enabled' } }, policy({ allowDebug: false }))).toBe(m('enabled'));
    expect(await tokReason({ payload: { dbgstat: 'enabled' } }, { policy: { imageDigests: [IMG], allowDebug: 'yes' as never } })).toBe(m('enabled'));
    expect(await tokReason({ payload: { dbgstat: undefined } }, policy({ allowDebug: true }))).toBe('OK');
  });
});

describe('verify: eat_nonce binding', () => {
  const nonceOk = (nonce: unknown, p: Partial<GcpCsPolicy> = {}) => tokReason(nonce === undefined ? { payload: { eat_nonce: undefined } } : { nonce }, policy(p));
  const bound = 'eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)';
  it('expected binding is required and must be constructible', async () => {
    expect(await tokReason({}, {}, { expected: undefined })).toBe('no expected attestation binding supplied');
    expect(await tokReason({}, {}, { expected: { ...EXPECTED, epoch: -1 } })).toBe('binding not constructible: binding: epoch must be a non-negative safe integer');
    expect(await tokReason({}, {}, { expected: { ...EXPECTED, nonce: '' } })).toBe('binding not constructible: binding: nonce required');
  });
  it('absent / empty claims', async () => {
    const m = 'token carries no eat_nonce claim to bind the PCA challenge';
    for (const n of [undefined, '', [], [''], ['', '']]) expect(await nonceOk(n), JSON.stringify(n)).toBe(m);
    for (const n of [5, null, [5], ['a', 5], {}]) expect(await nonceOk(n), JSON.stringify(n)).toBe(m);
  });
  it('encodings: base64, base64url, hex with optional 0x / 0X prefix and surrounding whitespace', async () => {
    const h = hex(BOUND);
    expect(await nonceOk(b64(BOUND))).toBe('OK');
    expect(await nonceOk(b64u(BOUND))).toBe('OK');
    expect(await nonceOk(h)).toBe('OK');
    expect(await nonceOk(h.toUpperCase())).toBe('OK');
    expect(await nonceOk(`0x${h}`)).toBe('OK');
    expect(await nonceOk(`0X${h}`)).toBe('OK');
    expect(await nonceOk(`  ${h}\n`)).toBe('OK');
    expect(await nonceOk(`\t0x${h}  `)).toBe('OK');
    expect(await nonceOk(`  ${b64(BOUND)} `)).toBe('OK');
    expect(await nonceOk(h.slice(0, -2))).toBe(bound);
    expect(await nonceOk(`${h}aa`)).toBe(bound);
    expect(await nonceOk(`${h}a`)).toBe(bound); // odd-length hex is not hex
    expect(await nonceOk(`x${h}`)).toBe(bound);
    expect(await nonceOk(`${h.slice(0, 10)}zz${h.slice(12)}`)).toBe(bound);
    expect(await nonceOk(`00${h}`)).toBe(bound);
    expect(await nonceOk('0x')).toBe(bound);
    expect(await nonceOk('!!!')).toBe(bound);
  });
  it('a base64url nonce is not mistaken for hex just because it ends in hex digits', async () => {
    // find a nonce whose binding encodes to an even-length base64url string ending in a hex digit
    for (let i = 0; i < 200; i++) {
      const exp = { ...EXPECTED, nonce: `n-${i}` };
      const bytes = attestationBinding(exp);
      const s = b64u(bytes);
      if (/[0-9a-fA-F]$/.test(s) && !/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) {
        const v = withTok({ nonce: s });
        expect(await reasonOf(v, { expected: exp })).toBe('OK');
        const prefixed = `${s.slice(0, 0)}${s}`;
        expect(await reasonOf(withTok({ nonce: prefixed }), { expected: EXPECTED })).toBe(bound);
        return;
      }
    }
    throw new Error('no suitable nonce found');
  });
  it('arrays: any bound entry accepts; unusable entries are skipped', async () => {
    expect(await nonceOk([b64(new Uint8Array(64)), b64(BOUND)])).toBe('OK');
    expect(await nonceOk([b64(BOUND), b64(new Uint8Array(64))])).toBe('OK');
    expect(await nonceOk(['', '!!!', hex(BOUND)])).toBe('OK');
    expect(await nonceOk([b64(new Uint8Array(64)), '!!!'])).toBe(bound);
    expect(await nonceOk(['a', 'b'])).toBe(bound);
  });
  it('nonceHash selects the digest applied to the binding', async () => {
    const sha = (a: string) => crypto.createHash(a).update(Buffer.from(BOUND)).digest();
    expect(await nonceOk(b64(sha('sha256')), { nonceHash: 'sha256' })).toBe('OK');
    expect(await nonceOk(b64(sha('sha512')), { nonceHash: 'sha512' })).toBe('OK');
    expect(await nonceOk(b64(sha('sha256')), { nonceHash: 'none' })).toBe(bound);
    expect(await nonceOk(b64(sha('sha256')))).toBe(bound);
    expect(await nonceOk(b64(sha('sha512')), { nonceHash: 'sha256' })).toBe(bound);
    expect(await nonceOk(b64(sha('sha256')), { nonceHash: 'sha512' })).toBe(bound);
    expect(await nonceOk(b64(BOUND), { nonceHash: 'sha256' })).toBe(bound);
    expect(await nonceOk(b64(BOUND), { nonceHash: 'none' })).toBe('OK');
    expect(await nonceOk(b64(BOUND), { nonceHash: 'md5' as never })).toBe('OK');
    expect(await nonceOk(hex(sha('sha256')), { nonceHash: 'sha256' })).toBe('OK');
  });
});

describe('verify: workload image and result', () => {
  it('image digest requirements', async () => {
    const missing = 'token carries no submods.container.image_digest to measure the workload';
    for (const container of [null, {}, { image_digest: '' }, { image_digest: 5 }, { image_reference: REF }]) expect(await tokReason({ container }), JSON.stringify(container)).toBe(missing);
    expect(await tokReason({ submods: { container: 'x', confidential_space: {} } })).toBe(missing);
    expect(await tokReason({ submods: { container: [], confidential_space: {} } })).toBe(missing);
    expect(await tokReason({ container: { image_digest: `sha256:${'cd'.repeat(32)}` } })).toBe('workload image_digest not in policy allowlist');
    expect(await tokReason({ container: { image_digest: IMG.toUpperCase() } })).toBe('OK');
    expect(await tokReason({}, { policy: { imageDigests: [IMG.toUpperCase()] } })).toBe('OK');
    expect(await tokReason({}, { policy: { imageDigests: ['sha256:00', IMG] } })).toBe('OK');
  });
  it('the verdict: measured identity, host assertions, custom derivation', async () => {
    const r = await run(withTok({}));
    expect(r).toEqual({
      ok: true,
      bound: true,
      measured: { model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: IMG, operator: '' },
      hostAsserted: { attestation_type: 'tdx', hwmodel: 'GCP_INTEL_TDX', image_digest: IMG, image_reference: REF },
    });
    const snp = await run(withTok({ payload: { hwmodel: 'GCP_AMD_SEV_SNP' } }));
    expect(snp.hostAsserted).toEqual({ attestation_type: 'sev-snp', hwmodel: 'GCP_AMD_SEV_SNP', image_digest: IMG, image_reference: REF });
    for (const image_reference of [undefined, '', 5]) {
      const x = await run(withTok({ container: { image_digest: IMG, image_reference } }));
      expect(x.hostAsserted, String(image_reference)).toStrictEqual({ attestation_type: 'tdx', hwmodel: 'GCP_INTEL_TDX', image_digest: IMG });
    }
    const seen: unknown[] = [];
    const custom = { model_id: 'M', weights_digest: 'w', weights_measured: true, runtime_measurement: 'rm', operator: 'op' };
    const t = token();
    const payload = parseGcpCsJwt(t).payload;
    const y = await run(mk({ policy: { imageDigests: [IMG], deriveIdentity: (c) => (seen.push(c), custom) } }, { token: t }));
    expect(y.measured).toBe(custom);
    expect(seen).toEqual([{ teeType: 'tdx', hwmodel: 'GCP_INTEL_TDX', imageDigest: IMG, container: { image_reference: REF, image_digest: IMG }, payload }]);
  });
});

describe('fetchGcpConfidentialSpaceJwks', () => {
  const res = (j: unknown, ok = true, status = 200) => ({ ok, status, json: async () => j }) as unknown as Response;
  it('resolves jwks_uri through the OpenID configuration, trimming trailing slashes', async () => {
    const urls: string[] = [];
    const f = (async (u: string) => (urls.push(u), u.endsWith('openid-configuration') ? res({ jwks_uri: 'https://j.example/keys' }) : res({ keys: [{ kid: 'a', kty: 'RSA', n: 'n', e: 'e' }] }))) as unknown as typeof fetch;
    const out = await fetchGcpConfidentialSpaceJwks('https://i.example//', { fetch: f });
    expect(urls).toEqual(['https://i.example/.well-known/openid-configuration', 'https://j.example/keys']);
    expect(out).toStrictEqual({ keys: [{ kid: 'a', kty: 'RSA', n: 'n', e: 'e' }] });
    urls.length = 0;
    await fetchGcpConfidentialSpaceJwks('https://i.example', { fetch: f });
    expect(urls[0]).toBe('https://i.example/.well-known/openid-configuration');
  });
  it('a supplied jwksUri skips the configuration', async () => {
    const urls: string[] = [];
    const f = (async (u: string) => (urls.push(u), res({ keys: [] }))) as unknown as typeof fetch;
    expect(await fetchGcpConfidentialSpaceJwks('https://i.example', { fetch: f, jwksUri: 'https://direct.example/k' })).toStrictEqual({ keys: [] });
    expect(urls).toEqual(['https://direct.example/k']);
  });
  it('failure modes', async () => {
    const e = (f: typeof fetch, o: Record<string, unknown> = {}) => fetchGcpConfidentialSpaceJwks('https://i.example', { fetch: f, ...o }).then(() => 'NO THROW', (x: Error) => x.message);
    expect(await e((async () => res({}, false, 503)) as never)).toBe('Confidential Space OpenID config fetch failed: HTTP 503 for https://i.example/.well-known/openid-configuration');
    for (const conf of [{}, { jwks_uri: 5 }, { jwks_uri: '' }, null, [], 'x']) expect(await e((async () => res(conf)) as never), JSON.stringify(conf)).toBe('Confidential Space OpenID config carries no jwks_uri');
    expect(await e((async () => res({}, false, 404)) as never, { jwksUri: 'https://j.example/k' })).toBe('Confidential Space JWKS fetch failed: HTTP 404 for https://j.example/k');
    for (const body of [{}, { keys: 'x' }, { keys: null }, null, [], 'x']) expect(await e((async () => res(body)) as never, { jwksUri: 'https://j.example/k' }), JSON.stringify(body)).toBe('Confidential Space JWKS fetch: response has no keys array');
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'fetch')!;
    Object.defineProperty(globalThis, 'fetch', { value: undefined, configurable: true, writable: true });
    try {
      await expect(fetchGcpConfidentialSpaceJwks('https://i.example')).rejects.toThrow(new Error('fetchGcpConfidentialSpaceJwks: no fetch implementation available'));
    } finally {
      Object.defineProperty(globalThis, 'fetch', saved);
    }
  });
  it('keys are copied field by field, only when typed correctly; non-records are dropped', async () => {
    const f = (async () =>
      res({
        keys: [
          { kid: 'k', kty: 'RSA', alg: 'RS256', use: 'sig', n: 'N', e: 'E', crv: 'P-256', x: 'X', y: 'Y', x5c: ['a', 'b'], extra: 1 },
          null,
          'str',
          5,
          [],
          { kid: 5, kty: 5, alg: 5, use: 5, n: 5, e: 5, crv: 5, x: 5, y: 5, x5c: 'a' },
          { x5c: ['a', 5] },
          {},
        ],
      })) as unknown as typeof fetch;
    const out = await fetchGcpConfidentialSpaceJwks('https://i.example', { fetch: f, jwksUri: 'https://j.example/k' });
    expect(out).toStrictEqual({
      keys: [{ kid: 'k', kty: 'RSA', alg: 'RS256', use: 'sig', n: 'N', e: 'E', crv: 'P-256', x: 'X', y: 'Y', x5c: ['a', 'b'] }, {}, {}, {}],
    });
  });
});
