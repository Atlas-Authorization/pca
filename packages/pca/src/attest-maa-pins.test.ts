import { spawnSync } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, it, expect } from 'vitest';
import { BUILTIN_MAA_PINS_ISSUER_KEYS, BUILTIN_CHAIN_LEAF_CN, loadBuiltinMaaPins, type BuiltinMaaPinsSource } from './attest-maa-pins';
import { BUILTIN_PINS_MANIFEST, BUILTIN_PINS_MIN_VERSION } from './attest-maa-pins.data';
import { corroborateMaaKeySets, createMaaKeyTrust, createMemoryMaaKeyStateStore, evaluateMaaJwks, type MaaKeyPolicy, type MaaTrustResult } from './attest-maa-keys';
import { signAllowlistManifest, type AllowlistEntry, type AllowlistIssuerKey, type SignedAllowlistManifest } from './attest-allowlist';
import { createAzureMaaVerifier, parseMaaJwt, verifyX5cChain, type MaaJwks } from './attest-azure-maa';
import type { AttestationDocument, ExpectedAttestationBinding } from './attestation';
import { generateKeyPair } from './keys';
import { b64u } from './hash';

const PKG = resolve(__dirname, '..');
const FIX = (f: string) => resolve(PKG, 'fixtures', 'real-azure-maa', f);
const VANT = (f: string) => resolve(PKG, 'fixtures', 'maa-pins-vantages', f);
const JWKS_WUS = JSON.parse(readFileSync(FIX('maa-signing-certs.json'), 'utf8')) as MaaJwks;
const JWKS_EUS = JSON.parse(readFileSync(FIX('maa-signing-certs-eus.json'), 'utf8')) as MaaJwks;
const WUS = 'https://sharedwus.wus.attest.azure.net';
const EUS = 'https://sharedeus.eus.attest.azure.net';
const WUS_TOKEN = readFileSync(FIX('pcabound-tdxvm-token.jwt'), 'utf8').trim();
const bound = parseMaaJwt(WUS_TOKEN).payload as Record<string, unknown>;
const NOW = ((bound['iat'] as number) + 3600) * 1000;
const DAY = 86_400_000;
const HOUR = 3_600_000;

const SPKI_A = 'fe4fa28d5b2e89f088d484f260363a12bcab53d9a9e0d6725507336fc8b6a71e';
const SPKI_B = '97cda3af47e762fb8673d1664066082ad7a9e82120eb9523da1a39f6a84de3cc';
const MS_ROOT_SPKI = '02376d0908ac23041cc7d666d9daf192554f7fc36317aa9cb800908616b28af8';
const MS_PCA_SPKI = '9ab67a5d1926476a794bcb4fa6cd74faa1486cd05931010aa7bbf1f57f1a8f58';
const spkiOf = (c: X509Certificate) => createHash('sha256').update(new Uint8Array(c.publicKey.export({ type: 'spki', format: 'der' }))).digest('hex');

const respond = (jwks: unknown) => new Response(JSON.stringify(jwks), { status: 200, headers: { 'content-type': 'application/json' } });
const fetchOf = (jwks: MaaJwks) => (async () => respond(jwks)) as unknown as typeof fetch;
const code = (r: MaaTrustResult) => (r.ok ? 'ok' : r.code);
const trustWith = (jwks: MaaJwks, policy: Partial<MaaKeyPolicy> = {}, issuer = WUS) =>
  createMaaKeyTrust({ policy: { trustedIssuers: [issuer], ...policy }, store: createMemoryMaaKeyStateStore(), fetch: fetchOf(jwks) });

// A custom signed source (own key) so tamper / expiry / rollback / vantage-count cases can be built.
const op = generateKeyPair();
const OPKEYS: Record<string, AllowlistIssuerKey> = { rel: { alg: 'ed25519', keys: { edPub: b64u(op.publicKey) } } };
const goodEntries = (vantages = 3): AllowlistEntry[] => [
  { kind: 'maa-signing-spki', value: SPKI_A, label: WUS },
  { kind: 'maa-signing-spki', value: SPKI_B, label: WUS },
  { kind: 'maa-chain-root-spki', value: MS_ROOT_SPKI, label: 'Microsoft Root Certificate Authority 2011' },
  { kind: 'maa-chain-intermediate-spki', value: MS_PCA_SPKI, label: 'Microsoft Azure Attestation PCA 2019' },
  { kind: 'attest-corroboration', value: 'ab'.repeat(32), label: `vantages=${vantages};method=test` },
];
const signed = (over: { version?: number; entries?: AllowlistEntry[]; notBefore?: number; expiresAt?: number } = {}): SignedAllowlistManifest =>
  signAllowlistManifest(
    { version: over.version ?? 1, issuedAt: NOW, notBefore: over.notBefore ?? NOW - DAY, expiresAt: over.expiresAt ?? NOW + 100 * DAY, entries: over.entries ?? goodEntries() },
    { issuer: 'rel', alg: 'ed25519', secrets: { edSecret: op.secretKey } },
  );
const src = (manifest: unknown, over: Partial<BuiltinMaaPinsSource> = {}): BuiltinMaaPinsSource => ({ manifest, issuerKeys: OPKEYS, ...over });

describe('attest-maa-pins: the shipped release-signed manifest', () => {
  it('verifies against the embedded issuer key and records >= 3 vantages', () => {
    const r = loadBuiltinMaaPins({ nowMs: NOW });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.vantages).toBeGreaterThanOrEqual(3);
    expect(r.method).toMatch(/gcp-cloudbuild/);
    expect(r.version).toBe(BUILTIN_PINS_MIN_VERSION);
    expect(r.maaSigningSpkis[WUS]!.sort()).toEqual([SPKI_A, SPKI_B].sort());
    expect(r.maaSigningSpkis[EUS]!.sort()).toEqual([SPKI_A, SPKI_B].sort());
    expect(r.maaChainRootSpkis).toEqual([MS_ROOT_SPKI]);
    expect(r.maaChainIntermediateSpkis).toEqual([MS_PCA_SPKI]);
    expect(r.expiresAt).toBeGreaterThan(NOW + 300 * DAY);
  });

  it('the pinned values equal the SPKIs of the real fixture certs (self-signed keys, MS root, MS PCA)', () => {
    const a = new X509Certificate(Buffer.from(JWKS_WUS.keys.find((k) => k.x5c!.length === 1 && spkiOf(new X509Certificate(Buffer.from(k.x5c![0]!, 'base64'))) === SPKI_A)!.x5c![0]!, 'base64'));
    expect(spkiOf(a)).toBe(SPKI_A);
    const chained = JWKS_WUS.keys.find((k) => k.x5c!.length === 3)!;
    expect(spkiOf(new X509Certificate(Buffer.from(chained.x5c![2]!, 'base64')))).toBe(MS_ROOT_SPKI);
    expect(spkiOf(new X509Certificate(Buffer.from(chained.x5c![1]!, 'base64')))).toBe(MS_PCA_SPKI);
    // and the Microsoft repository copies shipped as fixtures are byte-for-byte those certs
    const root = new X509Certificate(readFileSync(VANT('ms-root-ca-2011.crt')));
    expect(spkiOf(root)).toBe(MS_ROOT_SPKI);
    expect(root.fingerprint).toBe('8F:43:28:8A:D2:72:F3:10:3B:6F:B1:42:84:85:EA:30:14:C0:BC:FE');
    expect(root.verify(root.publicKey)).toBe(true);
    const pca = new X509Certificate(readFileSync(VANT('ms-azure-attestation-pca-2019.crt')));
    expect(pca.verify(root.publicKey)).toBe(true);
    expect(spkiOf(pca)).toBe(MS_PCA_SPKI);
  });

  it('the Microsoft-chained keys verify through the REAL fixture chain to the Microsoft root, offline', async () => {
    for (const jwks of [JWKS_WUS, JWKS_EUS]) {
      for (const k of jwks.keys.filter((x) => x.x5c!.length === 3)) {
        const leaf = new X509Certificate(Buffer.from(k.x5c![0]!, 'base64'));
        const mid = new X509Certificate(Buffer.from(k.x5c![1]!, 'base64'));
        const top = new X509Certificate(Buffer.from(k.x5c![2]!, 'base64'));
        expect(leaf.verify(mid.publicKey)).toBe(true);
        expect(mid.verify(top.publicKey)).toBe(true);
        expect(top.verify(top.publicKey)).toBe(true);
        expect(spkiOf(top)).toBe(MS_ROOT_SPKI);
        // downstream chain verifier, anchored ONLY on the pinned intermediate:
        const ok = await verifyX5cChain(k.x5c!, { rootSpkiSha256: [MS_PCA_SPKI] }, { nowMs: NOW });
        expect(ok.reason).toBeUndefined();
        expect(ok.ok).toBe(true);
        // a different intermediate pin does not anchor it
        expect((await verifyX5cChain(k.x5c!, { rootSpkiSha256: ['00'.repeat(32)] }, { nowMs: NOW })).ok).toBe(false);
      }
    }
  });
});

describe('attest-maa-pins: default createMaaKeyTrust bootstrap has NO trust-on-first-use', () => {
  it('first fetch on the default policy is accepted from the built-in pins and verifies the real wus token end to end', async () => {
    const t = trustWith(JWKS_WUS);
    const r = await t.getTrustAnchors(WUS, { nowMs: NOW });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.trustAnchors.rootSpkiSha256).toEqual(expect.arrayContaining([SPKI_A, SPKI_B, MS_PCA_SPKI]));
    expect(r.trustAnchors.rootSpkiSha256).not.toContain(MS_ROOT_SPKI); // narrowed to the MAA intermediate
    expect(r.anchors.some((a) => a.kind === 'chained-intermediate')).toBe(true);
    const EXPECTED: ExpectedAttestationBinding = { holderPub: 'pca-realsilicon-azure-tdx-holder', grantRef: 'grant_pca_azure_maa_realsilicon', epoch: 1, nonce: 'srv-nonce-maa-5d3b8e1f9a27c604' };
    const v = createAzureMaaVerifier({
      trustedIssuers: [WUS],
      trustAnchors: r.trustAnchors,
      policy: { tdxMrtds: [String(bound['tdx_mrtd'])], runtimeUserDataBinding: true },
      resolveEvidence: () => ({ token: WUS_TOKEN, jwks: JWKS_WUS }),
    });
    const out = await v.verify({ document: {} as unknown as AttestationDocument, ctx: {} as never, nowMs: NOW, expected: EXPECTED });
    expect(out.reason).toBeUndefined();
    expect(out.ok).toBe(true);
  });

  it('the eus instance (real SEV-SNP token fixture) bootstraps from the built-in pins too', async () => {
    const snp = parseMaaJwt(readFileSync(FIX('sevsnp-token.jwt'), 'utf8').trim()).payload as Record<string, unknown>;
    const t = trustWith(JWKS_EUS, {}, EUS);
    const r = await t.getTrustAnchors(EUS, { nowMs: ((snp['iat'] as number) + 600) * 1000 });
    expect(r.ok).toBe(true);
    expect(r.ok && r.trustAnchors.rootSpkiSha256).toEqual(expect.arrayContaining([SPKI_A, SPKI_B]));
  });

  it('an issuer that is not in the built-in pins gets NO baseline: still refuses trust-on-first-use', async () => {
    const other = 'https://sharedcus.cus.attest.azure.net';
    const t = trustWith(JWKS_WUS, {}, other); // CN mismatch aside, the chained keys alone must not bootstrap it
    expect(code(await t.getTrustAnchors(other, { nowMs: NOW }))).toMatch(/no-valid-keys|no-baseline/);
    // TOFU remains an explicit opt-in
    expect(code(await trustWith(JWKS_WUS, { builtinPins: false }).getTrustAnchors(WUS, { nowMs: NOW }))).toBe('no-baseline');
    expect(code(await trustWith(JWKS_WUS, { builtinPins: false, allowTrustOnFirstUse: true }).getTrustAnchors(WUS, { nowMs: NOW }))).toBe('ok');
  });

  it('a key the release did not pin is not accepted as a first set (rotation rules still apply)', async () => {
    // custom pin source pins only SPKI_B; the instance serves only SPKI_A -> no overlap with the signed pins
    const only = src(signed({ entries: goodEntries().filter((e) => e.value !== SPKI_A) }));
    const t = trustWith({ keys: [JWKS_WUS.keys.find((k) => k.x5c!.length === 1 && k.kid!.startsWith('XxRc'))!] }, { builtinPins: only });
    expect(code(await t.getTrustAnchors(WUS, { nowMs: NOW }))).toBe('no-overlap');
  });

  it('explicit policy overrides the built-in chain pins; a wrong intermediate rejects the chained key', () => {
    const ok = evaluateMaaJwks(JWKS_WUS, WUS, { trustedIssuers: [WUS], chainRootSpkiSha256: [MS_ROOT_SPKI], chainIntermediateSpkiSha256: [MS_PCA_SPKI], chainLeafCn: [...BUILTIN_CHAIN_LEAF_CN] }, NOW);
    expect(ok.accepted.map((a) => a.spki).sort()).toEqual([SPKI_A, SPKI_B, MS_PCA_SPKI].sort());
    const bad = evaluateMaaJwks(JWKS_WUS, WUS, { trustedIssuers: [WUS], chainRootSpkiSha256: [MS_ROOT_SPKI], chainIntermediateSpkiSha256: ['11'.repeat(32)] }, NOW);
    expect(bad.rejected.filter((r) => /pinned intermediate/.test(r.reason))).toHaveLength(2);
    expect(bad.accepted.map((a) => a.spki)).not.toContain(MS_PCA_SPKI);
  });
});

describe('attest-maa-pins: tamper / key / expiry / rollback / corroboration', () => {
  it('a custom source signed by its own key loads (control)', () => {
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(signed()) }).ok).toBe(true);
  });

  it('rejects a tampered manifest (entry value, body field, corroboration label)', () => {
    const m = JSON.parse(JSON.stringify(signed())) as SignedAllowlistManifest;
    m.body.entries[0]!.value = 'aa'.repeat(32);
    const r1 = loadBuiltinMaaPins({ nowMs: NOW, source: src(m) });
    expect(r1.ok).toBe(false);
    expect(!r1.ok && r1.reason).toMatch(/bad-signature/);
    const m2 = JSON.parse(JSON.stringify(signed())) as SignedAllowlistManifest;
    m2.body.expiresAt += 10 * DAY;
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(m2) }).ok).toBe(false);
    const m3 = JSON.parse(JSON.stringify(signed())) as SignedAllowlistManifest;
    m3.body.entries[4]!.label = 'vantages=9;method=test';
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(m3) }).ok).toBe(false);
  });

  it('rejects the shipped manifest when tampered or checked against another issuer key', () => {
    const m = JSON.parse(JSON.stringify(BUILTIN_PINS_MANIFEST)) as SignedAllowlistManifest;
    m.body.entries[0]!.value = m.body.entries[1]!.value === m.body.entries[0]!.value ? 'cd'.repeat(32) : m.body.entries[1]!.value;
    // swapping to a duplicate/other value -> either malformed or bad signature, never ok
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: { manifest: m, issuerKeys: BUILTIN_MAA_PINS_ISSUER_KEYS, minVersion: 1 } }).ok).toBe(false);
    const wrongKeys: Record<string, AllowlistIssuerKey> = { [BUILTIN_PINS_MANIFEST.issuer]: { alg: BUILTIN_PINS_MANIFEST.alg, keys: { edPub: b64u(generateKeyPair().publicKey), mlDsaPub: (BUILTIN_MAA_PINS_ISSUER_KEYS[BUILTIN_PINS_MANIFEST.issuer]!.keys.mlDsaPub)! } } };
    const r = loadBuiltinMaaPins({ nowMs: NOW, source: { manifest: BUILTIN_PINS_MANIFEST, issuerKeys: wrongKeys } });
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toMatch(/bad-signature/);
  });

  it('rejects a manifest signed by a key that is not the embedded issuer (wrong issuer key)', () => {
    const r = loadBuiltinMaaPins({ nowMs: NOW, source: { manifest: signed(), issuerKeys: BUILTIN_MAA_PINS_ISSUER_KEYS } });
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toMatch(/unknown-issuer/);
  });

  it('rejects an expired and a not-yet-valid pin set, with the failure surfaced by the default trust bootstrap', async () => {
    const m = signed({ expiresAt: NOW + HOUR });
    const late = loadBuiltinMaaPins({ nowMs: NOW + 2 * HOUR, source: src(m) });
    expect(!late.ok && late.reason).toMatch(/expired/);
    const early = loadBuiltinMaaPins({ nowMs: NOW - 3 * DAY, source: src(m) });
    expect(early.ok).toBe(false);
    const t = trustWith(JWKS_WUS, { builtinPins: src(m) });
    const r = await t.getTrustAnchors(WUS, { nowMs: NOW + 2 * HOUR });
    expect(code(r)).toBe('builtin-pins-invalid');
    // ...and the real shipped manifest also expires (fail closed a year on)
    expect(loadBuiltinMaaPins({ nowMs: NOW + 420 * DAY }).ok).toBe(false);
    expect(code(await trustWith(JWKS_WUS).getTrustAnchors(WUS, { nowMs: NOW + 420 * DAY }))).not.toBe('ok');
  });

  it('rejects rollback below the version floor and an over-long lifetime', () => {
    const rb = loadBuiltinMaaPins({ nowMs: NOW, source: src(signed({ version: 1 }), { minVersion: 2 }) });
    expect(!rb.ok && rb.reason).toMatch(/below-min-version/);
    const long = loadBuiltinMaaPins({ nowMs: NOW, source: src(signed({ expiresAt: NOW + 1000 * DAY })) });
    expect(!long.ok && long.reason).toMatch(/lifetime-too-long/);
  });

  it('rejects fewer than 3 recorded vantages, a missing corroboration record, and missing chain pins', () => {
    const few = loadBuiltinMaaPins({ nowMs: NOW, source: src(signed({ entries: goodEntries(2) })) });
    expect(!few.ok && few.reason).toMatch(/2 vantages < required 3/);
    const none = loadBuiltinMaaPins({ nowMs: NOW, source: src(signed({ entries: goodEntries().filter((e) => e.kind !== 'attest-corroboration') })) });
    expect(!none.ok && none.reason).toMatch(/corroboration/);
    const noChain = loadBuiltinMaaPins({ nowMs: NOW, source: src(signed({ entries: goodEntries().filter((e) => !e.kind.startsWith('maa-chain')) })) });
    expect(!noChain.ok && noChain.reason).toMatch(/chain/);
  });

  it('a signed tombstone for a pinned key strips it from the baseline', async () => {
    const entries = goodEntries().map((e) => (e.value === SPKI_A ? { ...e, revoked: true as const } : e));
    const t = trustWith(JWKS_WUS, { builtinPins: src(signed({ entries })) });
    const r = await t.getTrustAnchors(WUS, { nowMs: NOW });
    expect(r.ok && r.trustAnchors.rootSpkiSha256).not.toContain(SPKI_A);
    expect(r.ok && r.trustAnchors.rootSpkiSha256).toContain(SPKI_B);
  });
});

describe('corroborateMaaKeySets: k independent observations must agree', () => {
  const obs = (vantage: string, jwks: MaaJwks = JWKS_WUS) => ({ vantage, issuer: WUS, jwks });
  const policy: Partial<MaaKeyPolicy> = { chainRootSpkiSha256: [MS_ROOT_SPKI], chainIntermediateSpkiSha256: [MS_PCA_SPKI] };

  it('accepts when >= k distinct vantages see the identical set', () => {
    const r = corroborateMaaKeySets([obs('a'), obs('b'), obs('c')], 3, { issuer: WUS, nowMs: NOW, policy });
    expect(r.ok).toBe(true);
    expect(r.ok && r.spkis).toEqual([SPKI_A, SPKI_B, MS_PCA_SPKI].sort());
    expect(r.ok && r.vantages).toEqual(['a', 'b', 'c']);
  });

  it('rejects too few distinct vantages (a repeated label counts once) and k < 2', () => {
    expect(corroborateMaaKeySets([obs('a'), obs('a'), obs('b')], 3, { issuer: WUS, nowMs: NOW })).toMatchObject({ ok: false, code: 'insufficient-vantages' });
    expect(corroborateMaaKeySets([obs('a')], 1, { issuer: WUS, nowMs: NOW })).toMatchObject({ ok: false, code: 'malformed' });
  });

  it('rejects ANY disagreement, even from a single vantage beyond k', () => {
    const justA: MaaJwks = { keys: JWKS_WUS.keys.filter((k) => k.kid!.startsWith('XxRc')) };
    const r = corroborateMaaKeySets([obs('a'), obs('b'), obs('c'), obs('evil', justA)], 3, { issuer: WUS, nowMs: NOW });
    expect(r).toMatchObject({ ok: false, code: 'vantage-disagreement' });
    expect(!r.ok && r.reason).toMatch(/evil/);
  });

  it('rejects an observation with no valid key and one for another issuer', () => {
    expect(corroborateMaaKeySets([obs('a'), obs('b'), obs('c', { keys: [] })], 3, { issuer: WUS, nowMs: NOW })).toMatchObject({ ok: false, code: 'no-valid-keys' });
    expect(corroborateMaaKeySets([obs('a'), obs('b'), { vantage: 'c', issuer: EUS, jwks: JWKS_WUS }], 3, { issuer: WUS, nowMs: NOW })).toMatchObject({ ok: false, code: 'malformed' });
  });

  it('the corroborated pins seed a TOFU-free bootstrap via initialPins', async () => {
    const c = corroborateMaaKeySets([obs('a'), obs('b'), obs('c')], 3, { issuer: WUS, nowMs: NOW, policy });
    if (!c.ok) throw new Error('setup');
    const t = trustWith(JWKS_WUS, { builtinPins: false, initialPins: { [WUS]: c.spkis }, ...policy });
    expect(code(await t.getTrustAnchors(WUS, { nowMs: NOW }))).toBe('ok');
  });
});

describe('scripts/sign-maa-pins.ts: re-corroborates from vantage files and re-signs', () => {
  const tsx = join(PKG, 'node_modules', '.bin', 'tsx');
  const script = join(PKG, 'scripts', 'sign-maa-pins.ts');
  const run = (args: string[]) => spawnSync(tsx, [script, ...args], { encoding: 'utf8', env: { ...process.env, PATH: `/usr/local/bin:${process.env['PATH'] ?? ''}` } });

  it('refuses a vantage disagreement, signs on agreement, and the output verifies under the new key', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pca-pins-'));
    try {
      const keys = join(dir, 'keys.json');
      const out = join(dir, 'pins.data.ts');
      expect(run(['init-keys', '--keys', keys]).status).toBe(0);
      const base = ['--keys', keys, '--out', out, '--ms-root', VANT('ms-root-ca-2011.crt'), '--ms-intermediate', VANT('ms-azure-attestation-pca-2019.crt'), '--method', 'test-run', '--now', String(NOW)];
      // disagreement: drop one self-signed key from the third vantage
      const bad = JSON.parse(readFileSync(VANT('aci.json'), 'utf8')) as Record<string, Array<{ kid: string; chain: unknown[] }>>;
      bad['sharedwus.wus.attest.azure.net'] = bad['sharedwus.wus.attest.azure.net']!.filter((k) => !k.kid.startsWith('XxRc'));
      const badPath = join(dir, 'bad.json');
      writeFileSync(badPath, JSON.stringify(bad));
      const dis = run(['sign', ...base, '--vantage', `a=${VANT('local.json')}`, '--vantage', `b=${VANT('gcb.json')}`, '--vantage', `c=${badPath}`]);
      expect(dis.status).not.toBe(0);
      expect(dis.stderr).toMatch(/VANTAGE DISAGREEMENT/);
      expect(existsSync(out)).toBe(false);
      // too few vantages
      const few = run(['sign', ...base, '--vantage', `a=${VANT('local.json')}`, '--vantage', `b=${VANT('gcb.json')}`]);
      expect(few.status).not.toBe(0);
      expect(few.stderr).toMatch(/vantages < k/);
      // a root that is not the Microsoft root
      const notRoot = run(['sign', ...base.map((x) => (x === VANT('ms-root-ca-2011.crt') ? VANT('ms-azure-attestation-pca-2019.crt') : x)), '--vantage', `a=${VANT('local.json')}`, '--vantage', `b=${VANT('gcb.json')}`, '--vantage', `c=${VANT('aci.json')}`]);
      expect(notRoot.status).not.toBe(0);
      // agreement
      const good = run(['sign', ...base, '--vantage', `a=${VANT('local.json')}`, '--vantage', `b=${VANT('gcb.json')}`, '--vantage', `c=${VANT('aci.json')}`]);
      expect(good.stderr).toBe('');
      expect(good.status).toBe(0);
      const text = readFileSync(out, 'utf8');
      expect(text).not.toMatch(/edSecret|mlDsaSecret/);
      expect(text).toMatch(/BUILTIN_PINS_MIN_VERSION = 1;/);
      expect(text).toMatch(/vantages=3;method=test-run/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);
});
