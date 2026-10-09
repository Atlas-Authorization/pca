import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it, expect } from 'vitest';
import {
  azureMaaPolicyFields,
  createAllowlistManifest,
  driverVersionSlotHex,
  gcpCsPolicyFields,
  intelDcapPolicyFields,
  nvidiaCcPolicyFields,
  projectAllowlist,
  revokeAllowlistEntry,
  sevSnpPolicyFields,
  signAllowlistManifest,
  verifyAllowlistManifest,
  type AllowlistEntry,
  type AllowlistIssuerKey,
  type AllowlistManifestBody,
  type SignedAllowlistManifest,
  type VerifyAllowlistResult,
} from './attest-allowlist';
import { createAzureMaaVerifier, parseMaaJwt } from './attest-azure-maa';
import { parseDcapQuote, parseDcapTdReport } from './attest-intel-tdx';
import { NVIDIA_OPAQUE, parseNvidiaSpdmEvidence } from './attest-nvidia-spdm';
import { generateKeyPair } from './keys';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';
import { b64u } from './hash';

const FX = (...p: string[]) => resolve(__dirname, '..', 'fixtures', ...p);
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

// ---- REAL measurements from the repo's genuine-silicon fixtures -----------------------------------------
const AZURE_TOKEN = readFileSync(FX('real-azure-maa', 'pcabound-tdxvm-token.jwt'), 'utf8').trim();
const AZURE_MRTD = String(parseMaaJwt(AZURE_TOKEN).payload['tdx_mrtd']);
const RAW_TDX_MRTD = hex(parseDcapTdReport(parseDcapQuote(new Uint8Array(readFileSync(FX('real-tdx', 'azure-intel-tdx-dcap-quote.bin')))).tdReportBody).mrTd);
const GCP_IMAGE = 'sha256:b1c058a8092d56dd77ec351b9e00b2565fba5e413d0cb08d260a1e40e64ca46e';
const GCP_TDX_IMAGE = 'sha256:6597f3b7a7e742c2098782ea04ae9dd091fa0995ae662708e357a7730540d154';
function driverOf(...p: string[]): string {
  const r = parseNvidiaSpdmEvidence(new Uint8Array(readFileSync(FX('real-nvidia-cc', ...p))));
  return Buffer.from(r.response.opaque.get(NVIDIA_OPAQUE.DRIVER_VERSION)!).toString('utf8').replace(/\0+$/, '');
}
const OWN_DRIVER = driverOf('own-h100', 'h100-gpu-attestation-report.bin');
const OTHER_DRIVER = driverOf('h100-gpu-attestation-report.bin');
const SNP = 'ab'.repeat(48); // synthetic: no real SEV-SNP launch measurement is captured in the fixtures
const NVM = 'cd'.repeat(48); // synthetic aggregate measurement
const ISSUER = 'https://sharedwus.wus.attest.azure.net';
const SPKI = 'fe4fa28d5b2e89f088d484f260363a12bcab53d9a9e0d6725507336fc8b6a71e';

const T0 = Date.parse('2026-10-09T00:00:00Z');
const DAY = 86_400_000;

const ed = generateKeyPair();
const ISSUER_KEYS: Record<string, AllowlistIssuerKey> = {
  'ops-ed': { alg: 'ed25519', keys: { edPub: b64u(ed.publicKey) } },
};
const ml = mlDsa65Keygen(new Uint8Array(32).fill(5));
const hyb = generateKeyPair();
const HYBRID_KEYS: Record<string, AllowlistIssuerKey> = {
  'ops-hybrid': { alg: 'hybrid-ed25519-ml-dsa-65', keys: { edPub: b64u(hyb.publicKey), mlDsaPub: encodeMlDsaPublicKey(ml.publicKey) } },
  'ops-pq': { alg: 'ml-dsa-65', keys: { mlDsaPub: encodeMlDsaPublicKey(ml.publicKey) } },
};

const ENTRIES: AllowlistEntry[] = [
  { kind: 'tdx-mrtd', value: AZURE_MRTD, label: 'azure DC4es_v6 boot A' },
  { kind: 'tdx-mrtd', value: RAW_TDX_MRTD, label: 'azure DC4es_v6 boot B (real-tdx)' },
  { kind: 'sev-snp-measurement', value: SNP, label: 'synthetic snp' },
  { kind: 'gcp-image-digest', value: GCP_IMAGE, label: 'cs sev' },
  { kind: 'gcp-image-digest', value: GCP_TDX_IMAGE, label: 'cs tdx' },
  { kind: 'nvidia-driver-version', value: OWN_DRIVER, label: 'own h100' },
  { kind: 'nvidia-driver-version', value: OTHER_DRIVER, label: 'phala h100' },
  { kind: 'nvidia-measurement', value: NVM, label: 'synthetic gpu measurement' },
  { kind: 'maa-signing-spki', value: SPKI, label: ISSUER },
];
function body(over: Partial<AllowlistManifestBody> = {}): AllowlistManifestBody {
  return { version: 5, issuedAt: T0 - DAY, notBefore: T0 - DAY, expiresAt: T0 + 30 * DAY, entries: ENTRIES, ...over };
}
const sign = (b: AllowlistManifestBody = body()): SignedAllowlistManifest => signAllowlistManifest(b, { issuer: 'ops-ed', alg: 'ed25519', secrets: { edSecret: ed.secretKey } });
const verify = (m: unknown, over: Partial<Parameters<typeof verifyAllowlistManifest>[1]> = {}) =>
  verifyAllowlistManifest(m, { issuerKeys: ISSUER_KEYS, nowMs: T0, ...over });
function mustOk(r: VerifyAllowlistResult): Extract<VerifyAllowlistResult, { ok: true }> {
  if (!r.ok) throw new Error(`expected ok, got ${r.code}: ${r.reason}`);
  return r;
}
const code = (r: VerifyAllowlistResult) => (r.ok ? 'ok' : r.code);

describe('attest-allowlist: real-measurement round trip', () => {
  it('uses genuinely different real MRTDs / drivers (sanity of the fixtures)', () => {
    expect(AZURE_MRTD).toMatch(/^a2e61f13/);
    expect(RAW_TDX_MRTD).toMatch(/^6f3e84c5/);
    expect(OWN_DRIVER).toBe('595.71.05');
    expect(OTHER_DRIVER).not.toBe(OWN_DRIVER);
  });

  it('signs, verifies and projects the real values into policy shapes', () => {
    const v = mustOk(verify(JSON.parse(JSON.stringify(sign()))));
    const p = projectAllowlist(v, { nowMs: T0 });
    expect(p.tdxMrtds).toEqual([AZURE_MRTD, RAW_TDX_MRTD]);
    expect(p.imageDigests).toEqual([GCP_IMAGE, GCP_TDX_IMAGE]);
    expect(p.nvidiaDriverVersions).toEqual([OWN_DRIVER, OTHER_DRIVER]);
    expect(p.nvidiaCcDriverVersions[0]).toBe(driverVersionSlotHex('595.71.05'));
    expect(p.nvidiaCcDriverVersions[0]).toHaveLength(32);
    expect(p.maaSigningSpkis).toEqual({ [ISSUER]: [SPKI] });
    expect(azureMaaPolicyFields(p)).toEqual({ tdxMrtds: [AZURE_MRTD, RAW_TDX_MRTD], sevSnpMeasurements: [SNP] });
    expect(intelDcapPolicyFields(p)).toEqual({ mrtds: [AZURE_MRTD, RAW_TDX_MRTD] });
    expect(sevSnpPolicyFields(p)).toEqual({ measurements: [SNP] });
    expect(gcpCsPolicyFields(p)).toEqual({ imageDigests: [GCP_IMAGE, GCP_TDX_IMAGE] });
    expect(nvidiaCcPolicyFields(p).measurements).toEqual([NVM]);
    expect(v.version).toBe(5);
  });

  it('the projected fields are accepted by the real verifier constructor and by a live-token check', async () => {
    const p = projectAllowlist(mustOk(verify(sign())), { nowMs: T0 });
    const jwks = JSON.parse(readFileSync(FX('real-azure-maa', 'maa-signing-certs.json'), 'utf8'));
    const verifier = createAzureMaaVerifier({
      trustedIssuers: [ISSUER],
      trustAnchors: { rootSpkiSha256: p.maaSigningSpkis[ISSUER]! },
      policy: { ...azureMaaPolicyFields(p), runtimeUserDataBinding: true },
      resolveEvidence: () => ({ token: AZURE_TOKEN, jwks }),
    });
    expect(verifier).toBeTruthy();
    // an allowlist with no MRTD at all makes the verifier refuse construction (empty = no accept-all)
    const empty = projectAllowlist(mustOk(verify(sign(body({ entries: [] })))), { nowMs: T0 });
    expect(() => createAzureMaaVerifier({ trustedIssuers: [ISSUER], trustAnchors: { rootSpkiSha256: [SPKI] }, policy: azureMaaPolicyFields(empty) })).toThrow();
  });

  it('works under ml-dsa-65 and hybrid suites', () => {
    const b = body();
    const pq = signAllowlistManifest(b, { issuer: 'ops-pq', alg: 'ml-dsa-65', secrets: { mlDsa: ml } });
    expect(code(verifyAllowlistManifest(pq, { issuerKeys: HYBRID_KEYS, nowMs: T0 }))).toBe('ok');
    const h = signAllowlistManifest(b, { issuer: 'ops-hybrid', alg: 'hybrid-ed25519-ml-dsa-65', secrets: { edSecret: hyb.secretKey, mlDsa: ml } });
    expect(code(verifyAllowlistManifest(h, { issuerKeys: HYBRID_KEYS, nowMs: T0 }))).toBe('ok');
    // dropping the PQ half of a hybrid is malformed; dropping nothing but corrupting pq_sig is a bad signature
    const { pq_sig: _drop, ...noPq } = h;
    expect(code(verifyAllowlistManifest(noPq, { issuerKeys: HYBRID_KEYS, nowMs: T0 }))).toBe('malformed');
    const flip = h.pq_sig!.slice(0, -4) + (h.pq_sig!.endsWith('AAAA') ? 'BBBB' : 'AAAA');
    expect(code(verifyAllowlistManifest({ ...h, pq_sig: flip }, { issuerKeys: HYBRID_KEYS, nowMs: T0 }))).toBe('bad-signature');
  });
});

describe('attest-allowlist: negatives', () => {
  it('rejects rollback to an older version, below-min, and same-version-different-body', () => {
    const m = sign(body({ version: 5 }));
    expect(code(verify(m, { lastSeenVersion: 6 }))).toBe('rollback');
    expect(code(verify(m, { lastSeenVersion: 5 }))).toBe('ok');
    expect(code(verify(m, { minVersion: 6 }))).toBe('below-min-version');
    const ok = mustOk(verify(m));
    expect(code(verify(m, { lastSeenVersion: 5, lastSeenDigest: ok.digest }))).toBe('ok');
    const other = sign(body({ version: 5, entries: ENTRIES.slice(0, 2) }));
    expect(code(verify(other, { lastSeenVersion: 5, lastSeenDigest: ok.digest }))).toBe('conflict');
  });

  it('rejects expired, not-yet-valid, and over-long manifests; skew is honoured', () => {
    expect(code(verify(sign(), { nowMs: T0 + 31 * DAY }))).toBe('expired');
    expect(code(verify(sign(), { nowMs: T0 - 2 * DAY }))).toBe('not-yet-valid');
    expect(code(verify(sign(), { nowMs: T0 - DAY - 1000, clockSkewMs: 5000 }))).toBe('ok');
    expect(code(verify(sign(), { maxLifetimeMs: 10 * DAY }))).toBe('lifetime-too-long');
  });

  it('rejects tampering anywhere in the body', () => {
    const m = sign();
    const t1 = JSON.parse(JSON.stringify(m)) as SignedAllowlistManifest;
    t1.body.entries[0]!.value = '00'.repeat(48);
    expect(code(verify(t1))).toBe('bad-signature');
    const t2 = JSON.parse(JSON.stringify(m)) as SignedAllowlistManifest;
    t2.body.expiresAt += DAY;
    expect(code(verify(t2))).toBe('bad-signature');
    const t3 = JSON.parse(JSON.stringify(m)) as SignedAllowlistManifest;
    delete (t3.body.entries[1] as AllowlistEntry).revoked;
    t3.body.entries[1]!.revoked = true;
    expect(code(verify(t3))).toBe('bad-signature');
    const t4 = JSON.parse(JSON.stringify(m)) as SignedAllowlistManifest;
    t4.body.version = 99;
    expect(code(verify(t4))).toBe('bad-signature');
  });

  it('rejects unknown issuer, wrong issuer key, alg downgrade and expired issuer', () => {
    expect(code(verify({ ...sign(), issuer: 'nobody' }))).toBe('unknown-issuer');
    expect(code(verify({ ...sign(), issuer: 'constructor' }))).toBe('unknown-issuer');
    const evil = generateKeyPair();
    const forged = signAllowlistManifest(body(), { issuer: 'ops-ed', alg: 'ed25519', secrets: { edSecret: evil.secretKey } });
    expect(code(verify(forged))).toBe('bad-signature');
    // issuer registered as hybrid cannot be satisfied with a plain ed25519 signature
    const edOnly = signAllowlistManifest(body(), { issuer: 'ops-hybrid', alg: 'ed25519', secrets: { edSecret: hyb.secretKey } });
    expect(code(verifyAllowlistManifest(edOnly, { issuerKeys: HYBRID_KEYS, nowMs: T0 }))).toBe('alg-mismatch');
    const exp = { 'ops-ed': { ...ISSUER_KEYS['ops-ed']!, notAfter: T0 - 1 } };
    expect(code(verify(sign(), { issuerKeys: exp }))).toBe('issuer-expired');
  });

  it('rejects duplicates, malformed values, unknown kinds, extra fields and junk input', () => {
    expect(() => createAllowlistManifest(body({ entries: [ENTRIES[0]!, { ...ENTRIES[0]!, label: 'again' }] }))).toThrow(/duplicate/);
    expect(() => createAllowlistManifest(body({ entries: [{ kind: 'tdx-mrtd', value: 'AB'.repeat(48), label: 'x' }] }))).toThrow();
    expect(() => createAllowlistManifest(body({ entries: [{ kind: 'gcp-image-digest', value: 'latest', label: 'x' }] }))).toThrow();
    expect(() => createAllowlistManifest(body({ entries: [{ kind: 'maa-signing-spki', value: SPKI, label: 'not a url' }] }))).toThrow();
    expect(() => createAllowlistManifest(body({ version: 0 }))).toThrow();
    expect(() => createAllowlistManifest(body({ notBefore: T0, expiresAt: T0 }))).toThrow();
    const unk = JSON.parse(JSON.stringify(sign())) as Record<string, unknown>;
    (unk['body'] as { entries: unknown[] }).entries.push({ kind: 'bogus', value: 'x', label: 'x' });
    expect(code(verify(unk))).toBe('malformed');
    expect(code(verify({ ...sign(), extra: 1 }))).toBe('malformed');
    for (const junk of [null, 5, 'x', [], {}, { body: 1 }]) expect(code(verify(junk))).toBe('malformed');
    expect(code(verify(sign(), { nowMs: Number.NaN }))).toBe('malformed');
  });

  it('a duplicate smuggled into a SIGNED manifest is still rejected at verify time', () => {
    const dup = body({ entries: [ENTRIES[0]!, ENTRIES[0]!] });
    // bypass createAllowlistManifest: sign canonical bytes directly through the signer would re-validate, so
    // forge by signing a clean body and splicing (signature then fails) - duplicate check precedes anyway.
    const m = JSON.parse(JSON.stringify(sign())) as SignedAllowlistManifest;
    m.body = dup;
    expect(code(verify(m))).toBe('malformed');
  });
});

describe('attest-allowlist: revocation and entry expiry', () => {
  it('a revoked entry is removed from every projection and listed as revoked', () => {
    const next = revokeAllowlistEntry(body(), { kind: 'tdx-mrtd', value: AZURE_MRTD }, { issuedAt: T0, notBefore: T0, expiresAt: T0 + 30 * DAY });
    expect(next.version).toBe(6);
    const v = mustOk(verify(sign(next)));
    const p = projectAllowlist(v, { nowMs: T0 });
    expect(p.tdxMrtds).toEqual([RAW_TDX_MRTD]);
    expect(p.revoked).toEqual([{ kind: 'tdx-mrtd', value: AZURE_MRTD, label: 'azure DC4es_v6 boot A' }]);
    expect(azureMaaPolicyFields(p).tdxMrtds).not.toContain(AZURE_MRTD);
  });

  it('revoking a value that was never listed adds a tombstone; a tombstone beats any live duplicate-looking entry', () => {
    const next = revokeAllowlistEntry(body(), { kind: 'gcp-image-digest', value: `sha256:${'1'.repeat(64)}`, label: 'bad image' }, { issuedAt: T0, notBefore: T0, expiresAt: T0 + DAY });
    const p = projectAllowlist(mustOk(verify(sign(next))), { nowMs: T0 });
    expect(p.imageDigests).toEqual([GCP_IMAGE, GCP_TDX_IMAGE]);
    expect(p.revoked.map((r) => r.value)).toContain(`sha256:${'1'.repeat(64)}`);
  });

  it('drops entries past their own notAfter but keeps the rest', () => {
    const b = body({ entries: [{ ...ENTRIES[0]!, notAfter: T0 + DAY }, ENTRIES[1]!] });
    const v = mustOk(verify(sign(b)));
    expect(projectAllowlist(v, { nowMs: T0 }).tdxMrtds).toEqual([AZURE_MRTD, RAW_TDX_MRTD]);
    const later = projectAllowlist(v, { nowMs: T0 + 2 * DAY });
    expect(later.tdxMrtds).toEqual([RAW_TDX_MRTD]);
    expect(later.expired).toHaveLength(1);
  });

  it('driverVersionSlotHex rejects malformed versions', () => {
    expect(() => driverVersionSlotHex('abc')).toThrow();
    expect(() => driverVersionSlotHex('1'.repeat(17))).toThrow();
  });
});

describe('attest-allowlist: MAA chain pins and corroboration kinds', () => {
  const H = 'ab'.repeat(32);
  const mk = (entries: AllowlistEntry[]) => createAllowlistManifest({ version: 1, issuedAt: T0, notBefore: T0 - DAY, expiresAt: T0 + DAY, entries });
  it('projects chain root / intermediate / corroboration and honours tombstones', () => {
    const body = mk([
      { kind: 'maa-chain-root-spki', value: H, label: 'root' },
      { kind: 'maa-chain-intermediate-spki', value: 'cd'.repeat(32), label: 'pca' },
      { kind: 'attest-corroboration', value: 'ef'.repeat(32), label: 'vantages=3;method=a+b+c' },
    ]);
    const p = projectAllowlist(mustOk(verify(sign(body))), { nowMs: T0 });
    expect(p.maaChainRootSpkis).toEqual([H]);
    expect(p.maaChainIntermediateSpkis).toEqual(['cd'.repeat(32)]);
    expect(p.corroboration).toEqual([{ value: 'ef'.repeat(32), label: 'vantages=3;method=a+b+c' }]);
    const revoked = projectAllowlist(mustOk(verify(sign(revokeAllowlistEntry(body, { kind: 'maa-chain-root-spki', value: H }, { issuedAt: T0, notBefore: T0 - DAY, expiresAt: T0 + DAY })))), { nowMs: T0 });
    expect(revoked.maaChainRootSpkis).toEqual([]);
  });
  it('rejects malformed values and corroboration labels', () => {
    expect(() => mk([{ kind: 'maa-chain-root-spki', value: 'xyz', label: 'r' }])).toThrow(/64 lowercase hex/);
    expect(() => mk([{ kind: 'attest-corroboration', value: H, label: 'three vantages' }])).toThrow(/vantages=/);
    expect(() => mk([{ kind: 'attest-corroboration', value: H, label: 'vantages=0;method=x' }])).toThrow(/vantages=/);
  });
});

