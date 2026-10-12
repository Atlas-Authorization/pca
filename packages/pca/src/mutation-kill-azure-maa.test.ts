/**
 * Mutation-kill tests for attest-azure-maa.ts. Certificates and tokens are minted with the forge-x509 test support
 * (EC P-256 / P-384 chains, an RSA leaf) so every parse, chain, signature, claim and policy branch is observable with
 * its exact failure reason.
 */
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { fetchMaaJwks, createAzureMaaVerifier, parseMaaJwt, verifyX5cChain, type MaaJwks } from './attest-azure-maa';
import { attestationBinding, type ExpectedAttestationBinding } from './attestation';
import { ecdsaSign, forgeCert, forgeKey, type ForgeKey } from './test-support/forge-x509';

const enc = (s: string) => new TextEncoder().encode(s);
const hexOf = (b: Uint8Array) => Buffer.from(b).toString('hex');
const b64 = (d: Uint8Array) => Buffer.from(d).toString('base64');
const NB = new Date('2026-01-01T00:00:00Z');
const NA = new Date('2030-01-01T00:00:00Z');
const NOW = Date.parse('2027-06-01T00:00:00Z');
const NOWSEC = Math.floor(NOW / 1000);

const rootK = forgeKey('maa-root', 'P-256');
const midK = forgeKey('maa-mid', 'P-256');
const leafK = forgeKey('maa-leaf', 'P-256');
const otherK = forgeKey('maa-other', 'P-256');
const p384K = forgeKey('maa-p384', 'P-384');
const cert = (cn: string, key: ForgeKey, issuerCn: string, signer: ForgeKey, nb = NB, na = NA, serial = 1n) =>
  forgeCert({ subject: [['CN', cn]], issuer: [['CN', issuerCn]], subjectKey: key, signer, serial, notBefore: nb, notAfter: na });
const root = cert('root', rootK, 'root', rootK);
const mid = cert('mid', midK, 'root', rootK, NB, NA, 2n);
const leaf = cert('leaf', leafK, 'mid', midK, NB, NA, 3n);
const x5c = (...cs: { der: Uint8Array }[]) => cs.map((c) => b64(c.der));
const FULL = x5c(leaf, mid, root);
const rootPin = rootK.spkiSha256;
const bad = (reason: string) => ({ ok: false, reason });

// ── parseMaaJwt ─────────────────────────────────────────────────────────────────────────────────────
const j = (o: unknown) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
describe('parseMaaJwt', () => {
  const sig = Buffer.from([1, 2, 3]).toString('base64url');
  it('exact messages for each structural defect', () => {
    expect(() => parseMaaJwt('')).toThrow(new TypeError('parseMaaJwt: empty token'));
    expect(() => parseMaaJwt(5 as never)).toThrow(new TypeError('parseMaaJwt: empty token'));
    expect(() => parseMaaJwt('a.b')).toThrow('parseMaaJwt: a compact JWS has exactly three dot-separated parts');
    expect(() => parseMaaJwt('a.b.c.d')).toThrow('exactly three dot-separated parts');
    expect(() => parseMaaJwt(`.${j({})}.${sig}`)).toThrow(new TypeError('parseMaaJwt: empty JWS segment'));
    expect(() => parseMaaJwt(`${j({ alg: 'ES256' })}..${sig}`)).toThrow(new TypeError('parseMaaJwt: empty JWS segment'));
    expect(() => parseMaaJwt(`${j({ alg: 'ES256' })}.${j({})}.`)).toThrow(new TypeError('parseMaaJwt: empty JWS segment'));
    expect(() => parseMaaJwt(`${j('{')}.${j({})}.${sig}`)).toThrow(/^parseMaaJwt: malformed JSON segment: .+/);
    expect(() => parseMaaJwt(`${j({ alg: 'ES256' })}.${j('{')}.${sig}`)).toThrow(/^parseMaaJwt: malformed JSON segment: .+/);
    for (const h of ['[]', 'null', '5', '"x"']) expect(() => parseMaaJwt(`${j(h)}.${j({})}.${sig}`)).toThrow(new TypeError('parseMaaJwt: header is not a JSON object'));
    for (const p of ['[]', 'null', '5']) expect(() => parseMaaJwt(`${j({ alg: 'ES256' })}.${j(p)}.${sig}`)).toThrow(new TypeError('parseMaaJwt: payload is not a JSON object'));
    expect(() => parseMaaJwt(`${j({})}.${j({})}.${sig}`)).toThrow(new TypeError('parseMaaJwt: header has no alg'));
    expect(() => parseMaaJwt(`${j({ alg: '' })}.${j({})}.${sig}`)).toThrow('header has no alg');
    expect(() => parseMaaJwt(`${j({ alg: 5 })}.${j({})}.${sig}`)).toThrow('header has no alg');
  });
  it('an undecodable signature segment is an empty signature', () => {
    expect(() => parseMaaJwt(`${j({ alg: 'ES256' })}.${j({})}.%%%`)).toThrow(new TypeError('parseMaaJwt: empty signature'));
  });
  it('keeps only string kid/jku/typ and an all-string x5c; payload and signing input are exact', () => {
    const h = j({ alg: 'ES256', kid: 'k', jku: 'https://j', typ: 'JWT', x5c: ['a', 'b'] });
    const p = j({ iss: 'x' });
    const t = parseMaaJwt(`${h}.${p}.${sig}`);
    expect(t.header).toStrictEqual({ alg: 'ES256', kid: 'k', jku: 'https://j', typ: 'JWT', x5c: ['a', 'b'] });
    expect(t.payload).toEqual({ iss: 'x' });
    expect(Buffer.from(t.signingInput).toString()).toBe(`${h}.${p}`);
    expect([...t.signature]).toEqual([1, 2, 3]);
    const odd = parseMaaJwt(`${j({ alg: 'RS256', kid: 5, jku: 5, typ: 5, x5c: ['a', 5] })}.${p}.${sig}`);
    expect(odd.header).toStrictEqual({ alg: 'RS256' });
    expect(parseMaaJwt(`${j({ alg: 'RS256', x5c: 'a' })}.${p}.${sig}`).header).toStrictEqual({ alg: 'RS256' });
    expect(parseMaaJwt(`${j({ alg: 'RS256', x5c: [] })}.${p}.${sig}`).header).toStrictEqual({ alg: 'RS256', x5c: [] });
  });
});

// ── verifyX5cChain ──────────────────────────────────────────────────────────────────────────────────
const vx = (chain: readonly string[], anchors: Parameters<typeof verifyX5cChain>[1], o: { nowMs?: number; clockSkewMs?: number } = {}) => verifyX5cChain(chain, anchors, { nowMs: o.nowMs ?? NOW, ...(o.clockSkewMs !== undefined ? { clockSkewMs: o.clockSkewMs } : {}) });
describe('verifyX5cChain', () => {
  it('rejects an empty / non-array chain, empty entries and malformed certificates with the index', async () => {
    expect(await vx([], { rootSpkiSha256: [rootPin] })).toEqual(bad('empty x5c certificate chain'));
    expect(await vx(null as never, { rootSpkiSha256: [rootPin] })).toEqual(bad('empty x5c certificate chain'));
    expect(await vx([FULL[0]!, ''], { rootSpkiSha256: [rootPin] })).toEqual(bad('empty x5c entry at index 1'));
    expect(await vx([FULL[0]!, 5 as never], { rootSpkiSha256: [rootPin] })).toEqual(bad('empty x5c entry at index 1'));
    const m = await vx([FULL[0]!, Buffer.from('not a cert').toString('base64')], { rootSpkiSha256: [rootPin] });
    expect(m.ok).toBe(false);
    expect(m.reason).toMatch(/^malformed x5c certificate at index 1: .+/);
  });
  it('validity window: both edges inclusive, skew widens both, negative / NaN skew is zero', async () => {
    const c = x5c(cert('w', leafK, 'w', leafK, new Date('2027-01-01T00:00:00Z'), new Date('2027-02-01T00:00:00Z')));
    const a = { rootSpkiSha256: [leafK.spkiSha256] };
    const from = Date.parse('2027-01-01T00:00:00Z');
    const to = Date.parse('2027-02-01T00:00:00Z');
    const OUT = 'x5c certificate at index 0 is outside its validity window';
    expect((await vx(c, a, { nowMs: from })).ok).toBe(true);
    expect(await vx(c, a, { nowMs: from - 1 })).toEqual(bad(OUT));
    expect((await vx(c, a, { nowMs: to })).ok).toBe(true);
    expect(await vx(c, a, { nowMs: to + 1 })).toEqual(bad(OUT));
    expect((await vx(c, a, { nowMs: from - 500, clockSkewMs: 500 })).ok).toBe(true);
    expect(await vx(c, a, { nowMs: from - 501, clockSkewMs: 500 })).toEqual(bad(OUT));
    expect((await vx(c, a, { nowMs: to + 500, clockSkewMs: 500 })).ok).toBe(true);
    expect(await vx(c, a, { nowMs: to + 501, clockSkewMs: 500 })).toEqual(bad(OUT));
    expect((await vx(c, a, { nowMs: from + 1, clockSkewMs: -1e9 })).ok).toBe(true);
    expect((await vx(c, a, { nowMs: to - 1, clockSkewMs: -1e9 })).ok).toBe(true);
    expect((await vx(c, a, { nowMs: from + 1, clockSkewMs: Number.NaN })).ok).toBe(true);
    // the failing index is reported
    const two = [FULL[0]!, ...x5c(cert('old', rootK, 'old', rootK, new Date('2020-01-01T00:00:00Z'), new Date('2021-01-01T00:00:00Z')))];
    expect(await vx(two, { rootSpkiSha256: [rootPin] })).toEqual(bad('x5c certificate at index 1 is outside its validity window'));
  });
  it('needs at least one real anchor (empty-string pins do not count)', async () => {
    const NO = bad('no MAA trust anchor configured (fail closed)');
    expect(await vx(FULL, {})).toEqual(NO);
    expect(await vx(FULL, { rootSpkiSha256: [''] })).toEqual(NO);
    expect(await vx(FULL, { rootSpkiSha256: [5 as never] })).toEqual(NO);
    expect(await vx(FULL, { rootSpkiSha256: [], rootCertsPem: [] })).toEqual(NO);
  });
  it('anchors on a pinned SPKI anywhere in the chain (case-insensitive) and returns the leaf + its fingerprint', async () => {
    for (const pins of [[leafK.spkiSha256], [midK.spkiSha256], [rootPin.toUpperCase()]]) {
      const r = await vx(FULL, { rootSpkiSha256: pins });
      expect(r.ok).toBe(true);
      expect(r.reason).toBeUndefined();
      expect(r.leafSpkiSha256).toBe(leafK.spkiSha256);
      expect(r.leaf!.subject).toBe('CN=leaf');
    }
  });
  it('in-chain anchor: every link BELOW the first matching anchor must verify, links above are not checked', async () => {
    const badMid = cert('mid', midK, 'root', otherK, NB, NA, 2n); // mid NOT signed by root
    const chain = x5c(leaf, badMid, root);
    expect(await vx(chain, { rootSpkiSha256: [rootPin] })).toEqual(bad('x5c link 1 is not signed by the certificate above it'));
    // pinning mid anchors there: link 0 (leaf<-mid) is checked, mid<-root is not
    expect((await vx(chain, { rootSpkiSha256: [midK.spkiSha256] })).ok).toBe(true);
    // both pinned: the FIRST match (mid) wins
    expect((await vx(chain, { rootSpkiSha256: [midK.spkiSha256, rootPin] })).ok).toBe(true);
    const badLeaf = cert('leaf', leafK, 'mid', otherK, NB, NA, 3n); // leaf NOT signed by mid
    expect(await vx(x5c(badLeaf, mid, root), { rootSpkiSha256: [rootPin] })).toEqual(bad('x5c link 0 is not signed by the certificate above it'));
    // a single pinned cert needs no links
    expect((await vx(x5c(root), { rootSpkiSha256: [rootPin] })).ok).toBe(true);
  });
  it('external root: the whole chain must link and the top must be signed by a configured root certificate', async () => {
    const chain = x5c(leaf, mid);
    const ok = await vx(chain, { rootCertsPem: [root.pem] });
    expect(ok.ok).toBe(true);
    expect(ok.leafSpkiSha256).toBe(leafK.spkiSha256);
    expect(await vx(chain, { rootCertsPem: [cert('o', otherK, 'o', otherK).pem] })).toEqual(bad('x5c chain does not anchor in a configured MAA trust root'));
    expect(await vx(x5c(cert('leaf', leafK, 'mid', otherK, NB, NA, 3n), mid), { rootCertsPem: [root.pem] })).toEqual(bad('x5c link 0 is not signed by the certificate above it'));
    // a single leaf signed directly by the external root
    expect((await vx(x5c(cert('direct', leafK, 'root', rootK, NB, NA, 9n)), { rootCertsPem: [root.pem] })).ok).toBe(true);
    // a pem anchor also pins by fingerprint (root appears in the chain)
    expect((await vx(FULL, { rootCertsPem: [root.pem] })).ok).toBe(true);
  });
  it('a non-string pin is ignored even if it has a length; a PEM anchor pins its key by fingerprint', async () => {
    expect(await vx(FULL, { rootSpkiSha256: [['x'] as never] })).toEqual(bad('no MAA trust anchor configured (fail closed)'));
    // chain [leaf, mid]; the anchor PEM carries mid's key but mid was NOT signed by it: only the fingerprint match anchors
    const midSelf = cert('midself', midK, 'midself', midK);
    expect((await vx(x5c(leaf, mid), { rootCertsPem: [midSelf.pem] })).ok).toBe(true);
  });
  it('a bad root PEM is a fail-closed verification error', async () => {
    const r = await vx(FULL, { rootCertsPem: ['-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n'] });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^x5c chain verification error \(fail closed\): .+/);
  });
});

// ── the verifier ────────────────────────────────────────────────────────────────────────────────────
const EXPECTED: ExpectedAttestationBinding = { holderPub: 'h', grantRef: 'g', epoch: 2, nonce: 'n' };
const BIND = attestationBinding(EXPECTED);
const BIND_HEX = hexOf(BIND);
const ISS = 'https://maa.example';
const MRTD = 'ab'.repeat(48);
const MEAS = 'cd'.repeat(48);

function mkJwt(opts: { rawPayload?: string; header?: Record<string, unknown>; payload?: Record<string, unknown>; alg?: string; sign?: 'ec' | 'rsa' | 'none'; sigBytes?: Uint8Array; leafKey?: ForgeKey } = {}) {
  const header = { alg: opts.alg ?? 'ES256', x5c: FULL, ...opts.header };
  const h = j(header);
  const p = j(opts.rawPayload ?? opts.payload ?? {});
  const input = enc(`${h}.${p}`);
  const sig = opts.sigBytes ?? ecdsaSign(opts.leafKey ?? leafK, 'sha256', input).raw;
  return `${h}.${p}.${Buffer.from(sig).toString('base64url')}`;
}
const tdxTee = (over: Record<string, unknown> = {}) => ({ 'x-ms-attestation-type': 'tdxvm', tdx_mrtd: MRTD, tdx_report_data: BIND_HEX, ...over });
const snpTee = (over: Record<string, unknown> = {}) => ({ 'x-ms-attestation-type': 'sevsnpvm', 'x-ms-sevsnpvm-launchmeasurement': MEAS, 'x-ms-sevsnpvm-reportdata': BIND_HEX, ...over });
const payload = (tee: Record<string, unknown>, over: Record<string, unknown> = {}) => ({ iss: ISS, exp: NOWSEC + 3600, iat: NOWSEC - 10, nbf: NOWSEC - 10, 'x-ms-isolation-tee': tee, ...over });

function mkV(policy: Record<string, unknown> = {}, o: Record<string, unknown> = {}) {
  return createAzureMaaVerifier({
    trustedIssuers: [ISS],
    trustAnchors: { rootSpkiSha256: [rootPin] },
    policy: { tdxMrtds: [MRTD], sevSnpMeasurements: [MEAS], ...policy } as never,
    resolveEvidence: () => undefined,
    ...o,
  } as never);
}
const verify = (v: ReturnType<typeof mkV>, token: string, over: { jwks?: MaaJwks; expected?: ExpectedAttestationBinding | null; nowMs?: number } = {}) => {
  const vv = v as unknown as { verify: (i: unknown) => Promise<{ ok: boolean; reason?: string; measured?: unknown; hostAsserted?: Record<string, string>; bound?: boolean }> };
  return vv.verify({ document: {}, ctx: {}, nowMs: over.nowMs ?? NOW, ...(over.expected === null ? {} : { expected: over.expected ?? EXPECTED }) });
};
const withEvidence = (policy: Record<string, unknown>, ev: unknown, o: Record<string, unknown> = {}) => mkV(policy, { resolveEvidence: () => ev, ...o });
const go = (token: string, policy: Record<string, unknown> = {}, over: Parameters<typeof verify>[2] = {}, o: Record<string, unknown> = {}) => verify(withEvidence(policy, { token, ...(over.jwks ? { jwks: over.jwks } : {}) }, o), token, over);

describe('createAzureMaaVerifier constructor', () => {
  const f = (o: unknown) => () => createAzureMaaVerifier(o as never);
  const good = { trustedIssuers: [ISS], trustAnchors: { rootSpkiSha256: ['a'] }, policy: { tdxMrtds: ['a'] } };
  it('trusted issuers', () => {
    const MSG = 'createAzureMaaVerifier: trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs';
    expect(f(undefined)).toThrow(MSG);
    expect(f({ ...good, trustedIssuers: 'x' })).toThrow(MSG);
    expect(f({ ...good, trustedIssuers: [] })).toThrow(MSG);
    expect(f({ ...good, trustedIssuers: [''] })).toThrow('createAzureMaaVerifier: every trusted issuer must be a non-empty URL string');
    expect(f({ ...good, trustedIssuers: [ISS, 5] })).toThrow('every trusted issuer must be a non-empty URL string');
    expect(f(good)).not.toThrow();
  });
  it('trust anchors: any of rootCertsPem / rootSpkiSha256, never none', () => {
    const MSG = 'createAzureMaaVerifier: trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted';
    expect(f({ ...good, trustAnchors: undefined })).toThrow(MSG);
    expect(f({ ...good, trustAnchors: {} })).toThrow(MSG);
    expect(f({ ...good, trustAnchors: { rootSpkiSha256: [], rootCertsPem: [] } })).toThrow(MSG);
    expect(f({ ...good, trustAnchors: { rootCertsPem: ['x'], rootSpkiSha256: ['y'] } })).not.toThrow();
    expect(f({ ...good, trustAnchors: { rootCertsPem: ['x'] } })).not.toThrow();
    expect(f({ ...good, trustAnchors: { rootSpkiSha256: ['x'] } })).not.toThrow();
  });
  it('policy allowlists', () => {
    const MSG = 'createAzureMaaVerifier: policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)';
    expect(f({ ...good, policy: undefined })).toThrow(MSG);
    expect(f({ ...good, policy: {} })).toThrow(MSG);
    expect(f({ ...good, policy: { tdxMrtds: [], sevSnpMeasurements: [] } })).toThrow(MSG);
    expect(f({ ...good, policy: { tdxMrtds: 'x' } })).toThrow(MSG);
    expect(f({ ...good, policy: { sevSnpMeasurements: ['a'] } })).not.toThrow();
  });
  it('sevSnpMinTcb shape', () => {
    const p = (m: unknown) => f({ ...good, policy: { tdxMrtds: ['a'], sevSnpMinTcb: m } });
    for (const bad of [null, [], 'x', 5]) expect(p(bad)).toThrow('createAzureMaaVerifier: policy.sevSnpMinTcb must be an object');
    expect(p({ nope: 1 })).toThrow('createAzureMaaVerifier: policy.sevSnpMinTcb.nope is not a known field (bootloader | snp | microcode | tee)');
    for (const v of [-1, 1.5, '1', null]) expect(p({ tee: v })).toThrow('createAzureMaaVerifier: policy.sevSnpMinTcb.tee must be a non-negative integer');
    expect(p({ bootloader: 0, snp: 1, microcode: 2, tee: undefined })).not.toThrow();
    expect(p({})).not.toThrow();
  });
});

describe('verify: evidence, parse, algorithm, signer resolution', () => {
  const T = mkJwt({ payload: payload(tdxTee()) });
  it('baseline success', async () => {
    const r = await go(T);
    expect(r.reason).toBeUndefined();
    expect(r).toEqual({ ok: true, bound: true, measured: { model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: MRTD, operator: '' }, hostAsserted: { attestation_type: 'tdxvm' } });
  });
  it('resolver / token presence', async () => {
    expect(await verify(mkV({}, { resolveEvidence: undefined }), T)).toEqual(bad('no Azure MAA evidence resolver configured (fail closed)'));
    for (const ev of [undefined, {}, { token: '' }, { token: 5 }]) expect(await verify(withEvidence({}, ev), T)).toEqual(bad('no Azure MAA token for this action'));
    expect(await go('garbage')).toEqual(bad('MAA token parse failed: parseMaaJwt: a compact JWS has exactly three dot-separated parts'));
    expect(await verify(withEvidence({}, { token: T }, { resolveEvidence: () => { throw new Error('boom'); } }), T)).toEqual(bad('azure-maa verification error (fail closed): boom'));
    expect(await verify(withEvidence({}, { token: T }, { resolveEvidence: () => { throw 'x'; } }), T)).toEqual(bad('azure-maa verification error (fail closed): unknown'));
  });
  it('only ES256 / RS256', async () => {
    for (const alg of ['none', 'HS256', 'ES384']) expect(await go(mkJwt({ alg, payload: payload(tdxTee()) }))).toEqual(bad(`unsupported JWS alg '${alg}' (MAA uses ES256 / RS256)`));
  });
  it('signing x5c: header chain, JWKS by kid, kid-less single key, ambiguity, missing chain', async () => {
    const noX5c = (kid?: string) => mkJwt({ header: { x5c: undefined, ...(kid ? { kid } : {}) }, payload: payload(tdxTee()) });
    expect(await go(noX5c())).toEqual(bad('no signing x5c available (no JWKS and no header x5c)'));
    expect(await go(mkJwt({ header: { x5c: [] }, payload: payload(tdxTee()) }))).toEqual(bad('no signing x5c available (no JWKS and no header x5c)'));
    expect(await go(noX5c(), {}, { jwks: { keys: [] } })).toEqual(bad('no signing x5c available (no JWKS and no header x5c)'));
    const jwks = (...keys: object[]): MaaJwks => ({ keys: keys as never });
    expect((await go(noX5c('k1'), {}, { jwks: jwks({ kid: 'k0', x5c: ['zz'] }, { kid: 'k1', x5c: FULL }) })).ok).toBe(true);
    expect(await go(noX5c('k9'), {}, { jwks: jwks({ kid: 'k1', x5c: FULL }) })).toEqual(bad("no JWKS key matches the token kid 'k9' (untrusted signer)"));
    expect(await go(noX5c('k1'), {}, { jwks: jwks({ kid: 'k1' }) })).toEqual(bad("JWKS key 'k1' carries no x5c chain"));
    expect(await go(noX5c('k1'), {}, { jwks: jwks({ kid: 'k1', x5c: [] }) })).toEqual(bad("JWKS key 'k1' carries no x5c chain"));
    // kid-less
    expect((await go(noX5c(), {}, { jwks: jwks({ x5c: FULL }) })).ok).toBe(true);
    expect(await go(noX5c(), {}, { jwks: jwks({ x5c: FULL }, { x5c: FULL }) })).toEqual(bad('token has no kid and the JWKS publishes multiple keys (ambiguous)'));
    expect(await go(noX5c(), {}, { jwks: jwks({}) })).toEqual(bad('JWKS key carries no x5c chain'));
    expect(await go(noX5c(), {}, { jwks: jwks({ x5c: [] }) })).toEqual(bad('JWKS key carries no x5c chain'));
    // empty-string kid is "no kid"
    expect((await go(mkJwt({ header: { x5c: undefined, kid: '' }, payload: payload(tdxTee()) }), {}, { jwks: jwks({ x5c: FULL }) })).ok).toBe(true);
    // a JWKS wins over a header chain: an unrelated JWKS chain does not anchor, even though the header chain would
    const other = x5c(cert('o', otherK, 'o', otherK));
    expect((await go(mkJwt({ header: { kid: 'k' }, payload: payload(tdxTee()) }), {}, { jwks: jwks({ kid: 'k', x5c: other }) })).reason).toMatch(/^MAA signing chain invalid: /);
    // a JWKS object without a keys array falls back to the header chain
    expect((await go(T, {}, { jwks: {} as never })).ok).toBe(true);
  });
  it('chain failure carries the chain reason', async () => {
    const r = await go(mkJwt({ header: { x5c: x5c(cert('o', otherK, 'o', otherK)) }, payload: payload(tdxTee()) }), {}, {});
    expect(r).toEqual(bad('MAA signing chain invalid: x5c chain does not anchor in a configured MAA trust root'));
  });
});

describe('verify: JWS signature', () => {
  const pl = payload(tdxTee());
  it('ES256: wrong key, wrong length, bad signature, high-S accepted', async () => {
    expect((await go(mkJwt({ payload: pl }))).ok).toBe(true);
    expect(await go(mkJwt({ payload: pl, leafKey: otherK }))).toEqual(bad('JWS ES256 signature does not verify under the MAA signing key'));
    expect(await go(mkJwt({ payload: pl, sigBytes: new Uint8Array(63).fill(1) }))).toEqual(bad('ES256 signature is 63 bytes (expected 64: r‖s)'));
    expect(await go(mkJwt({ payload: pl, sigBytes: new Uint8Array(65).fill(1) }))).toEqual(bad('ES256 signature is 65 bytes (expected 64: r‖s)'));
    for (const fill of [0, 255]) expect(await go(mkJwt({ payload: pl, sigBytes: new Uint8Array(64).fill(fill) }))).toEqual(bad('JWS ES256 signature does not verify under the MAA signing key'));
    // a high-S signature (n - s) is valid ECDSA and must be accepted
    const input = enc(`${j({ alg: 'ES256', x5c: FULL })}.${j(pl)}`);
    const raw = ecdsaSign(leafK, 'sha256', input).raw;
    const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const s = BigInt('0x' + hexOf(raw.subarray(32)));
    const hi = s > n / 2n ? s : n - s;
    const lo = n - hi;
    for (const sv of [hi, lo]) {
      const sig = new Uint8Array(64); sig.set(raw.subarray(0, 32)); sig.set(Buffer.from(sv.toString(16).padStart(64, '0'), 'hex'), 32);
      expect((await go(mkJwt({ payload: pl, sigBytes: sig }))).ok).toBe(true);
    }
  });
  it('ES256 with a P-384 or an RSA signing key is refused with the key description', async () => {
    const p384Leaf = cert('p384', p384K, 'root', rootK, NB, NA, 7n);
    const hdr = { x5c: x5c(p384Leaf) };
    const a = { rootCertsPem: [root.pem] };
    expect(await go(mkJwt({ header: hdr, payload: pl }), {}, {}, { trustAnchors: a })).toEqual(bad('ES256 token but signing key is EC/P-384 (not EC P-256)'));
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaSpki = new Uint8Array(rsa.publicKey.export({ type: 'spki', format: 'der' }));
    const rsaLeaf = forgeCert({ subject: [['CN', 'rsa']], issuer: [['CN', 'root']], subjectKey: { ...leafK, spki: rsaSpki } as ForgeKey, signer: rootK, serial: 8n, notBefore: NB, notAfter: NA });
    expect(await go(mkJwt({ header: { x5c: x5c(rsaLeaf) }, payload: pl }), {}, {}, { trustAnchors: a })).toEqual(bad('ES256 token but signing key is RSA/undefined (not EC P-256)'));
    // RS256: valid with the RSA leaf, tampered, and refused for an EC leaf
    const mkRs = (tamper = false) => {
      const h = j({ alg: 'RS256', x5c: x5c(rsaLeaf) });
      const p = j(pl);
      const sig = nodeSign('RSA-SHA256', enc(`${h}.${p}`), rsa.privateKey);
      if (tamper) sig[0] = (sig[0] ?? 0) ^ 1;
      return `${h}.${p}.${sig.toString('base64url')}`;
    };
    expect((await go(mkRs(), {}, {}, { trustAnchors: a })).ok).toBe(true);
    expect(await go(mkRs(true), {}, {}, { trustAnchors: a })).toEqual(bad('JWS RS256 signature does not verify under the MAA signing key'));
    expect(await go(mkJwt({ alg: 'RS256', payload: pl }))).toEqual(bad('RS256 token but signing key is EC (not RSA)'));
  }, 60_000);
});

describe('verify: standard claims', () => {
  const go2 = (over: Record<string, unknown>, policy: Record<string, unknown> = {}, o: Parameters<typeof verify>[2] = {}, extra: Record<string, unknown> = {}) => go(mkJwt({ payload: payload(tdxTee(), over) }), policy, o, extra);
  it('issuer must be a configured string', async () => {
    expect(await go2({ iss: 'https://evil' })).toEqual(bad("token iss 'https://evil' is not a configured trusted MAA instance"));
    expect(await go2({ iss: undefined })).toEqual(bad("token iss 'undefined' is not a configured trusted MAA instance"));
    expect(await go2({ iss: '' })).toEqual(bad("token iss '' is not a configured trusted MAA instance"));
    expect(await go2({ iss: 5 })).toEqual(bad("token iss 'undefined' is not a configured trusted MAA instance"));
  });
  it('exp is required and must be a finite number', async () => {
    const NO = bad('token has no exp (cannot bound validity — fail closed)');
    expect(await go2({ exp: undefined })).toEqual(NO);
    expect(await go2({ exp: String(NOWSEC + 100) })).toEqual(NO);
    expect(await go(mkJwt({ rawPayload: JSON.stringify(payload(tdxTee())).replace(/"exp":\d+/, '"exp":1e999') }))).toEqual(NO);
    expect(await go2({ exp: true })).toEqual(NO);
  });
  it('exp boundary, with skew rounded UP to whole seconds and now rounded DOWN', async () => {
    const EXP = bad('MAA token expired');
    expect((await go2({ exp: NOWSEC })).ok).toBe(true);
    expect(await go2({ exp: NOWSEC - 1 })).toEqual(EXP);
    // nowMs inside second NOWSEC+0.999: exp = NOWSEC still valid (floor)
    expect((await go(mkJwt({ payload: payload(tdxTee(), { exp: NOWSEC }) }), {}, { nowMs: NOW + 999 })).ok).toBe(true);
    expect((await go2({ exp: NOWSEC - 1 }, {}, {}, { clockSkewMs: 1000 })).ok).toBe(true);
    expect(await go2({ exp: NOWSEC - 2 }, {}, {}, { clockSkewMs: 1000 })).toEqual(EXP);
    expect((await go2({ exp: NOWSEC - 2 }, {}, {}, { clockSkewMs: 1001 })).ok).toBe(true);
    expect(await go2({ exp: NOWSEC - 3 }, {}, {}, { clockSkewMs: 1001 })).toEqual(EXP);
    // negative / non-finite skew is zero
    expect(await go2({ exp: NOWSEC - 1 }, {}, {}, { clockSkewMs: -5000 })).toEqual(EXP);
    expect(await go2({ exp: NOWSEC - 1 }, {}, {}, { clockSkewMs: Number.NaN })).toEqual(EXP);
    expect((await go2({ exp: NOWSEC }, {}, {}, { clockSkewMs: -5000 })).ok).toBe(true);
  });
  it('nbf and iat boundaries (inclusive) with skew; absent are not gated', async () => {
    expect((await go2({ nbf: NOWSEC })).ok).toBe(true);
    expect(await go2({ nbf: NOWSEC + 1 })).toEqual(bad('MAA token not yet valid (nbf)'));
    expect((await go2({ nbf: NOWSEC + 1 }, {}, {}, { clockSkewMs: 1000 })).ok).toBe(true);
    expect(await go2({ nbf: NOWSEC + 2 }, {}, {}, { clockSkewMs: 1000 })).toEqual(bad('MAA token not yet valid (nbf)'));
    expect((await go2({ iat: NOWSEC })).ok).toBe(true);
    expect(await go2({ iat: NOWSEC + 1 })).toEqual(bad('MAA token issued in the future (iat)'));
    expect((await go2({ iat: NOWSEC + 1 }, {}, {}, { clockSkewMs: 1000 })).ok).toBe(true);
    expect(await go2({ iat: NOWSEC + 2 }, {}, {}, { clockSkewMs: 1000 })).toEqual(bad('MAA token issued in the future (iat)'));
    expect((await go2({ nbf: undefined, iat: undefined })).ok).toBe(true);
    expect(await go2({ nbf: NOWSEC + 5, iat: NOWSEC - 5 })).toEqual(bad('MAA token not yet valid (nbf)')); // nbf checked before iat
  });
});

describe('verify: isolation type and PCA binding', () => {
  const tok = (tee: Record<string, unknown> | undefined, over: Record<string, unknown> = {}) => mkJwt({ payload: tee ? payload(tee, over) : { iss: ISS, exp: NOWSEC + 100, ...over } });
  it('isolation type location and values', async () => {
    const UNEXP = (v: string) => bad(`unexpected x-ms-attestation-type '${v}' (expected sevsnpvm | tdxvm)`);
    expect(await go(tok(tdxTee({ 'x-ms-attestation-type': 'vbs' })))).toEqual(UNEXP('vbs'));
    expect(await go(tok({ tdx_mrtd: MRTD }))).toEqual(UNEXP('undefined'));
    // no isolation-tee subtree: claims live in the payload itself
    const flat = mkJwt({ payload: { iss: ISS, exp: NOWSEC + 100, 'x-ms-attestation-type': 'tdxvm', tdx_mrtd: MRTD, tdx_report_data: BIND_HEX } });
    expect((await go(flat)).ok).toBe(true);
    // type only at the payload top-level while the tee subtree exists
    const split = mkJwt({ payload: payload({ tdx_mrtd: MRTD, tdx_report_data: BIND_HEX }, { 'x-ms-attestation-type': 'tdxvm' }) });
    expect((await go(split)).ok).toBe(true);
    // the tee subtree's value wins over the top-level one
    const both = mkJwt({ payload: payload(tdxTee({ 'x-ms-attestation-type': 'vbs' }), { 'x-ms-attestation-type': 'tdxvm' }) });
    expect(await go(both)).toEqual(UNEXP('vbs'));
    // an array is not a subtree
    const arr = mkJwt({ payload: { iss: ISS, exp: NOWSEC + 100, 'x-ms-isolation-tee': [], 'x-ms-attestation-type': 'tdxvm', tdx_mrtd: MRTD, tdx_report_data: BIND_HEX } });
    expect((await go(arr)).ok).toBe(true);
  });
  it('an expected binding is required, and an unconstructible one is reported', async () => {
    expect(await go(tok(tdxTee()), {}, { expected: null })).toEqual(bad('no expected attestation binding supplied'));
    const r = await go(tok(tdxTee()), {}, { expected: { ...EXPECTED, nonce: '' } });
    expect(r).toEqual(bad('binding not constructible: binding: nonce required'));
    const r2 = await go(tok(tdxTee()), { runtimeUserDataBinding: true }, { expected: { ...EXPECTED, nonce: '' } });
    expect(r2).toEqual(bad('binding not constructible: binding: nonce required'));
  });
  it('direct report-data: hex / 0x / 0X / upper-case / padded / base64url / base64, per TEE key spelling', async () => {
    const claim = (v: string, keys = ['tdx_report_data']) => tok(tdxTee({ tdx_report_data: undefined, ...Object.fromEntries(keys.map((k) => [k, v])) }));
    for (const v of [BIND_HEX, BIND_HEX.toUpperCase(), `0x${BIND_HEX}`, `0X${BIND_HEX}`, `  ${BIND_HEX}\n`, Buffer.from(BIND).toString('base64url'), Buffer.from(BIND).toString('base64')]) {
      const r = await go(claim(v));
      expect(r.reason).toBeUndefined();
    }
    for (const k of ['tdx_report_data', 'x-ms-tdx-report-data', 'x-ms-tdx-reportdata']) expect((await go(claim(BIND_HEX, [k]))).ok).toBe(true);
    // a first key with an empty string falls through to the next spelling
    expect((await go(tok(tdxTee({ tdx_report_data: '', 'x-ms-tdx-report-data': BIND_HEX })))).ok).toBe(true);
    // SEV-SNP spelling
    expect((await go(tok(snpTee()))).ok).toBe(true);
    // odd-length / non-hex strings are decoded as base64, not hex
    const b64Odd = Buffer.from(BIND.subarray(0, 63)).toString('base64');
    expect(b64Odd.length % 2).toBeDefined();
    const DNB = 'report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)';
    expect(await go(claim(BIND_HEX.slice(0, -2)))).toEqual(bad(DNB)); // 63 bytes
    expect(await go(claim(BIND_HEX + '00'))).toEqual(bad(DNB)); // 65 bytes with a zero tail
    expect(await go(claim(BIND_HEX.slice(0, 64)))).toEqual(bad(DNB)); // a 32-byte prefix
    expect(await go(claim(BIND_HEX.replace(/^../, (m) => (m === 'ff' ? '00' : 'ff'))))).toEqual(bad(DNB));
    expect(await go(claim(`${BIND_HEX.slice(0, -1)}`))).toEqual(bad(DNB)); // odd length -> base64 decode of hex text
    // odd-length all-hex text is NOT hex: a hex reading would truncate to the 64 bytes of the binding and wrongly accept it
    expect(await go(claim(BIND_HEX + 'a'))).toEqual(bad(DNB));
    // base64 text with embedded blanks is base64, not hex, even when it starts and ends with hex characters
    let found = '';
    for (let n = 0; n < 4000 && !found; n++) {
      const e2 = { ...EXPECTED, nonce: `n${n}` };
      const s64 = Buffer.from(attestationBinding(e2)).toString('base64url');
      if (/^[0-9a-fA-F]/.test(s64) && /[0-9a-fA-F]$/.test(s64) && s64.length % 2 === 0 && /[^0-9a-fA-F]/.test(s64)) found = `${e2.nonce}|${s64.slice(0, 40)}  ${s64.slice(40)}`;
    }
    expect(found).not.toBe('');
    const [nonce2, spaced] = found.split('|') as [string, string];
    expect(spaced.length % 2).toBe(0);
    const spacedTok = tok(tdxTee({ tdx_report_data: spaced }));
    expect((await go(spacedTok, {}, { expected: { ...EXPECTED, nonce: nonce2 } })).ok).toBe(true);
    expect(await go(claim('   '))).toEqual(bad('report-data claim is not decodable (hex/base64)'));
    expect(await go(claim('!!!'))).toEqual(bad('report-data claim is not decodable (hex/base64)'));
    expect(await go(tok(tdxTee({ tdx_report_data: undefined })))).toEqual(bad('token carries no report-data claim to bind the PCA challenge'));
    expect(await go(tok(snpTee({ 'x-ms-sevsnpvm-reportdata': undefined, tdx_report_data: BIND_HEX })))).toEqual(bad('token carries no report-data claim to bind the PCA challenge'));
  });
  it('reportDataHash: none / sha256 / sha512 select the comparison value', async () => {
    const v = (h: Uint8Array) => tok(tdxTee({ tdx_report_data: hexOf(h) }));
    expect((await go(v(sha256(BIND)), { reportDataHash: 'sha256' })).ok).toBe(true);
    expect((await go(v(sha512(BIND)), { reportDataHash: 'sha512' })).ok).toBe(true);
    expect((await go(v(BIND), { reportDataHash: 'none' })).ok).toBe(true);
    expect((await go(v(BIND))).ok).toBe(true);
    expect((await go(v(sha256(BIND)), { reportDataHash: 'sha512' })).ok).toBe(false);
    expect((await go(v(sha512(BIND)), { reportDataHash: 'sha256' })).ok).toBe(false);
    expect((await go(v(sha256(BIND)))).ok).toBe(false);
    expect((await go(v(BIND), { reportDataHash: 'sha256' })).ok).toBe(false);
  });
  it('runtime user-data binding', async () => {
    const P = { runtimeUserDataBinding: true };
    const rt = (r: unknown) => tok(tdxTee({ tdx_report_data: undefined }), { 'x-ms-runtime': r });
    expect((await go(rt({ 'user-data': BIND_HEX }), P)).ok).toBe(true);
    expect((await go(rt({ 'user-data': `0x${BIND_HEX}` }), P)).ok).toBe(true);
    expect(await go(tok(tdxTee()), P)).toEqual(bad('token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)'));
    expect(await go(rt([]), P)).toEqual(bad('token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)'));
    expect(await go(rt({}), P)).toEqual(bad('x-ms-runtime carries no user-data to bind the PCA challenge'));
    expect(await go(rt({ 'user-data': '' }), P)).toEqual(bad('x-ms-runtime carries no user-data to bind the PCA challenge'));
    const DNB = bad('runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound token)');
    expect(await go(rt({ 'user-data': BIND_HEX.slice(0, 64) }), P)).toEqual(DNB);
    expect(await go(rt({ 'user-data': BIND_HEX + '00' }), P)).toEqual(DNB);
    expect(await go(rt({ 'user-data': '   ' }), P)).toEqual(DNB);
    // the raw report_data claim is NOT used in this mode, and the hash setting is ignored
    expect(await go(tok(tdxTee(), { 'x-ms-runtime': { 'user-data': hexOf(sha256(BIND)) } }), { ...P, reportDataHash: 'sha256' })).toEqual(DNB);
    // runtimeUserDataBinding must be exactly true
    expect((await go(tok(tdxTee()), { runtimeUserDataBinding: 'yes' })).ok).toBe(true);
  });
});

describe('verify: SEV-SNP policy', () => {
  const snp = (tee: Record<string, unknown> = {}, over: Record<string, unknown> = {}) => mkJwt({ payload: payload(snpTee(tee), over) });
  it('success shape: lowercased measurement, no host data, no svns unless present', async () => {
    const r = await go(snp({ 'x-ms-sevsnpvm-launchmeasurement': MEAS.toUpperCase() }), { sevSnpMeasurements: [MEAS.toUpperCase()] });
    expect(r).toEqual({ ok: true, bound: true, measured: { model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: MEAS, operator: '' }, hostAsserted: { attestation_type: 'sevsnpvm' } });
  });
  it('allowlist presence, claim presence, membership', async () => {
    expect(await go(snp(), { sevSnpMeasurements: undefined })).toEqual(bad('sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)'));
    expect(await go(snp({ 'x-ms-sevsnpvm-launchmeasurement': undefined }))).toEqual(bad('sevsnpvm token carries no launch-measurement claim'));
    expect(await go(snp({ 'x-ms-sevsnpvm-launchmeasurement': '' }))).toEqual(bad('sevsnpvm token carries no launch-measurement claim'));
    expect(await go(snp({ 'x-ms-sevsnpvm-launchmeasurement': '00'.repeat(48) }))).toEqual(bad('SEV-SNP launch measurement not in policy allowlist'));
  });
  it('debuggable guests are refused unless allowDebug is exactly true', async () => {
    const D = bad('SEV-SNP guest is debuggable (no confidentiality)');
    expect(await go(snp({ 'x-ms-sevsnpvm-is-debuggable': true }))).toEqual(D);
    expect(await go(snp({ 'x-ms-sevsnpvm-is-debuggable': true }), { allowDebug: false })).toEqual(D);
    expect((await go(snp({ 'x-ms-sevsnpvm-is-debuggable': true }), { allowDebug: true })).ok).toBe(true);
    expect((await go(snp({ 'x-ms-sevsnpvm-is-debuggable': false }))).ok).toBe(true);
    expect((await go(snp({ 'x-ms-sevsnpvm-is-debuggable': 'true' }))).ok).toBe(true); // not a boolean: ignored
  });
  it('host data allowlist (case-insensitive) and the lowercased value surfaced', async () => {
    const H = 'AaBb';
    const r = await go(snp({ 'x-ms-sevsnpvm-hostdata': H }), { sevSnpHostData: ['aabb'] });
    expect(r.ok).toBe(true);
    expect(r.hostAsserted).toEqual({ attestation_type: 'sevsnpvm', host_data: 'aabb' });
    expect((await go(snp({ 'x-ms-sevsnpvm-hostdata': 'aabb' }), { sevSnpHostData: ['AABB'] })).ok).toBe(true);
    const NO = bad('SEV-SNP host-data not in policy allowlist');
    expect(await go(snp({ 'x-ms-sevsnpvm-hostdata': 'ccdd' }), { sevSnpHostData: ['aabb'] })).toEqual(NO);
    expect(await go(snp(), { sevSnpHostData: ['aabb'] })).toEqual(NO);
    expect((await go(snp({ 'x-ms-sevsnpvm-hostdata': 'ccdd' }), { sevSnpHostData: [] })).ok).toBe(true);
    expect((await go(snp({ 'x-ms-sevsnpvm-hostdata': 'ccdd' }), {})).hostAsserted).toEqual({ attestation_type: 'sevsnpvm', host_data: 'ccdd' });
  });
  it('reported-TCB floors: equal passes, one below fails, missing / non-integer / negative claims fail closed, values surfaced', async () => {
    const svns = { 'x-ms-sevsnpvm-bootloader-svn': 4, 'x-ms-sevsnpvm-snpfw-svn': 5, 'x-ms-sevsnpvm-microcode-svn': 6, 'x-ms-sevsnpvm-tee-svn': 7 };
    const ok = await go(snp(svns), { sevSnpMinTcb: { bootloader: 4, snp: 5, microcode: 6, tee: 7 } });
    expect(ok.hostAsserted).toEqual({ attestation_type: 'sevsnpvm', bootloader_svn: '4', snpfw_svn: '5', microcode_svn: '6', tee_svn: '7' });
    for (const [name, claim, v] of [['bootloader', 'x-ms-sevsnpvm-bootloader-svn', 4], ['snp', 'x-ms-sevsnpvm-snpfw-svn', 5], ['microcode', 'x-ms-sevsnpvm-microcode-svn', 6], ['tee', 'x-ms-sevsnpvm-tee-svn', 7]] as const) {
      expect(await go(snp(svns), { sevSnpMinTcb: { [name]: v + 1 } })).toEqual(bad(`SEV-SNP ${name} SVN ${v} is below the policy minimum ${v + 1}`));
      expect((await go(snp(svns), { sevSnpMinTcb: { [name]: v } })).ok).toBe(true);
      for (const badv of [undefined, '7', 1.5, -1, null]) expect(await go(snp({ ...svns, [claim]: badv }), { sevSnpMinTcb: { [name]: 0 } })).toEqual(bad(`SEV-SNP ${name} SVN claim '${claim}' is missing or not a non-negative integer (policy requires a minimum)`));
    }
    // a floor of 0 passes the claim 0; unset floors never gate; bad claims without a floor are simply not surfaced
    const zero = await go(snp({ ...svns, 'x-ms-sevsnpvm-tee-svn': 0 }), { sevSnpMinTcb: { tee: 0 } });
    expect(zero.hostAsserted!.tee_svn).toBe('0');
    const noFloor = await go(snp({ 'x-ms-sevsnpvm-tee-svn': -1, 'x-ms-sevsnpvm-snpfw-svn': 1.5, 'x-ms-sevsnpvm-bootloader-svn': '3' }), {});
    expect(noFloor.hostAsserted).toEqual({ attestation_type: 'sevsnpvm' });
    expect((await go(snp({ 'x-ms-sevsnpvm-tee-svn': 3 }), { sevSnpMinTcb: { tee: 1 } })).ok).toBe(true);
    // floors are checked in table order: bootloader first
    expect((await go(snp({}), { sevSnpMinTcb: { tee: 1, bootloader: 1 } })).reason).toMatch(/bootloader SVN claim/);
  });
  it('deriveIdentity receives the context and its result is returned', async () => {
    let ctx: { isolationType?: string; runtimeMeasurement?: string; teeClaims?: unknown; payload?: unknown } = {};
    const id = { model_id: 'm', weights_digest: 'w', weights_measured: true, runtime_measurement: 'r', operator: 'o' };
    const r = await go(snp(), { deriveIdentity: (c: typeof ctx) => { ctx = c; return id; } });
    expect(r.measured).toEqual(id);
    expect(ctx.isolationType).toBe('sevsnpvm');
    expect(ctx.runtimeMeasurement).toBe(MEAS);
    expect((ctx.teeClaims as Record<string, unknown>)['x-ms-sevsnpvm-launchmeasurement']).toBe(MEAS);
    expect((ctx.payload as Record<string, unknown>).iss).toBe(ISS);
  });
});

describe('verify: TDX policy', () => {
  const tdx = (tee: Record<string, unknown> = {}, over: Record<string, unknown> = {}) => mkJwt({ payload: payload(tdxTee(tee), over) });
  it('allowlist presence, claim presence, spelling fallback, membership', async () => {
    expect(await go(tdx(), { tdxMrtds: undefined })).toEqual(bad('tdxvm token but policy configures no TDX MRTD allowlist (fail closed)'));
    expect(await go(tdx({ tdx_mrtd: undefined }))).toEqual(bad('tdxvm token carries no MRTD claim'));
    expect(await go(tdx({ tdx_mrtd: '' }))).toEqual(bad('tdxvm token carries no MRTD claim'));
    expect((await go(tdx({ tdx_mrtd: '', 'x-ms-tdx-mrtd': MRTD }))).ok).toBe(true);
    expect((await go(tdx({ tdx_mrtd: undefined, 'x-ms-tdx-mrtd': MRTD }))).ok).toBe(true);
    expect(await go(tdx({ tdx_mrtd: '00'.repeat(48) }))).toEqual(bad('TDX MRTD not in policy allowlist'));
    const up = await go(tdx({ tdx_mrtd: MRTD.toUpperCase() }), { tdxMrtds: [MRTD.toUpperCase()] });
    expect(up.measured).toMatchObject({ runtime_measurement: MRTD });
  });
  it('debug signals: td attribute, dbgstat other than "disabled"; allowDebug exactly true waives', async () => {
    const D = bad('TDX guest is debuggable (no confidentiality)');
    expect(await go(tdx({ tdx_td_attributes_debug: true }))).toEqual(D);
    expect(await go(tdx({ dbgstat: 'enabled' }))).toEqual(D);
    expect(await go(tdx({ dbgstat: '' }))).toEqual(D);
    expect(await go(tdx({ dbgstat: 'enabled' }), { allowDebug: false })).toEqual(D);
    expect((await go(tdx({ dbgstat: 'disabled' }))).ok).toBe(true);
    expect((await go(tdx({ tdx_td_attributes_debug: false }))).ok).toBe(true);
    expect((await go(tdx({ tdx_td_attributes_debug: 'true' }))).ok).toBe(true);
    expect((await go(tdx({ dbgstat: 7 }))).ok).toBe(true);
    expect((await go(tdx({ tdx_td_attributes_debug: true, dbgstat: 'enabled' }), { allowDebug: true })).ok).toBe(true);
  });
  it('attester TCB status: default accepted set, custom set, absent claim not gated, surfaced', async () => {
    for (const s of ['UpToDate', 'SWHardeningNeeded']) {
      const r = await go(tdx({ attester_tcb_status: s }));
      expect(r.hostAsserted).toStrictEqual({ attestation_type: 'tdxvm', tcb_status: s });
    }
    expect(await go(tdx({ attester_tcb_status: 'OutOfDate' }))).toEqual(bad("TDX platform TCB status 'OutOfDate' is not accepted by policy"));
    expect(await go(tdx({ attester_tcb_status: 'ConfigurationNeeded' }), { tdxAllowedTcbStatuses: ['UpToDate'] })).toEqual(bad("TDX platform TCB status 'ConfigurationNeeded' is not accepted by policy"));
    expect((await go(tdx({ attester_tcb_status: 'OutOfDate' }), { tdxAllowedTcbStatuses: ['OutOfDate'] })).ok).toBe(true);
    expect(await go(tdx({ attester_tcb_status: 'UpToDate' }), { tdxAllowedTcbStatuses: [] })).toEqual(bad("TDX platform TCB status 'UpToDate' is not accepted by policy"));
    expect((await go(tdx())).hostAsserted).toStrictEqual({ attestation_type: 'tdxvm' });
    expect(await go(tdx({ attester_tcb_status: '' }))).toEqual(bad("TDX platform TCB status '' is not accepted by policy"));
  });
  it('RTMR0 allowlist and surfacing (lowercased), both spellings', async () => {
    const R = 'AB'.repeat(48);
    const r = await go(tdx({ tdx_rtmr0: R }), { tdxRtmrs: ['ab'.repeat(48)] });
    expect(r.hostAsserted).toEqual({ attestation_type: 'tdxvm', rtmr0: 'ab'.repeat(48) });
    expect((await go(tdx({ 'x-ms-tdx-rtmr0': 'ab'.repeat(48) }), { tdxRtmrs: [R] })).ok).toBe(true);
    const NO = bad('TDX RTMR0 not in policy allowlist');
    expect(await go(tdx({ tdx_rtmr0: 'cd'.repeat(48) }), { tdxRtmrs: ['ab'.repeat(48)] })).toEqual(NO);
    expect(await go(tdx(), { tdxRtmrs: ['ab'.repeat(48)] })).toEqual(NO);
    expect((await go(tdx({ tdx_rtmr0: 'cd'.repeat(48) }), { tdxRtmrs: [] })).ok).toBe(true);
    expect((await go(tdx({ tdx_rtmr0: '', 'x-ms-tdx-rtmr0': 'ef' }))).hostAsserted).toEqual({ attestation_type: 'tdxvm', rtmr0: 'ef' });
  });
  it('deriveIdentity receives the TDX context', async () => {
    let ctx: { isolationType?: string; runtimeMeasurement?: string } = {};
    const r = await go(tdx(), { deriveIdentity: (c: typeof ctx) => { ctx = c; return { model_id: 'x', weights_digest: '', weights_measured: false, runtime_measurement: 'q', operator: '' }; } });
    expect(r.measured).toMatchObject({ model_id: 'x' });
    expect(ctx).toMatchObject({ isolationType: 'tdxvm', runtimeMeasurement: MRTD });
  });
  it('a policy with only SEV-SNP rejects TDX tokens and vice versa', async () => {
    expect((await go(tdx(), { tdxMrtds: undefined, sevSnpMeasurements: [MEAS] })).reason).toMatch(/^tdxvm token but policy/);
    expect((await go(mkJwt({ payload: payload(snpTee()) }), { sevSnpMeasurements: undefined, tdxMrtds: [MRTD] })).reason).toMatch(/^sevsnpvm token but policy/);
  });
});

describe('fetchMaaJwks', () => {
  const jsonRes = (body: unknown, ok = true, status = 200) => ({ ok, status, json: async () => body });
  it('builds the URL (trailing slashes stripped, custom path), filters and copies string fields only', async () => {
    const urls: string[] = [];
    const f = async (u: string) => { urls.push(u); return jsonRes({ keys: [{ kid: 'a', kty: 'RSA', alg: 'RS256', x5c: ['x'], extra: 1 }, 5, null, { kid: 7, kty: 7, alg: 7, x5c: ['x', 1] }, {}] }); };
    const out = await fetchMaaJwks('https://i.example///', { fetch: f as never });
    expect(urls[0]).toBe('https://i.example/certs');
    expect(out).toStrictEqual({ keys: [{ kid: 'a', kty: 'RSA', alg: 'RS256', x5c: ['x'] }, {}, {}] });
    await fetchMaaJwks('https://i.example', { fetch: f as never, certsPath: '/c2' });
    expect(urls[1]).toBe('https://i.example/c2');
  });
  it('errors: non-2xx, no keys array, no fetch', async () => {
    await expect(fetchMaaJwks('https://i', { fetch: (async () => jsonRes({}, false, 503)) as never })).rejects.toThrow('MAA JWKS fetch failed: HTTP 503 for https://i/certs');
    await expect(fetchMaaJwks('https://i', { fetch: (async () => jsonRes({ keys: 'x' })) as never })).rejects.toThrow('MAA JWKS fetch: response has no keys array');
    await expect(fetchMaaJwks('https://i', { fetch: (async () => jsonRes([])) as never })).rejects.toThrow('MAA JWKS fetch: response has no keys array');
    await expect(fetchMaaJwks('https://i', { fetch: (async () => jsonRes(null)) as never })).rejects.toThrow('MAA JWKS fetch: response has no keys array');
    const orig = globalThis.fetch;
    // @ts-expect-error simulate an environment without fetch
    globalThis.fetch = undefined;
    try { await expect(fetchMaaJwks('https://i')).rejects.toThrow('fetchMaaJwks: no fetch implementation available'); } finally { globalThis.fetch = orig; }
  });
});
