import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash, X509Certificate } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import { createMaaKeyTrust, createMemoryMaaKeyStateStore, evaluateMaaJwks, fetchMaaCerts, type MaaKeyPolicy, type MaaRepin, type MaaTrustResult } from './attest-maa-keys';
import { signAllowlistManifest, type AllowlistEntry, type AllowlistIssuerKey } from './attest-allowlist';
import { createAzureMaaVerifier, parseMaaJwt, type MaaJwks } from './attest-azure-maa';
import { attestationBinding, type AttestationDocument, type ExpectedAttestationBinding } from './attestation';
import { generateKeyPair } from './keys';
import { b64u } from './hash';

const FIX = (f: string) => resolve(__dirname, '..', 'fixtures', 'real-azure-maa', f);
const JWKS = JSON.parse(readFileSync(FIX('maa-signing-certs.json'), 'utf8')) as MaaJwks;
const BOUND = readFileSync(FIX('pcabound-tdxvm-token.jwt'), 'utf8').trim();
const ISSUER = 'https://sharedwus.wus.attest.azure.net';
const bound = parseMaaJwt(BOUND).payload as Record<string, unknown>;
const MRTD = String(bound['tdx_mrtd']);
const NOW = ((bound['iat'] as number) + 3600) * 1000;
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

const spkiOfKey = (i: number) => {
  const c = new X509Certificate(Buffer.from(JWKS.keys[i]!.x5c![0]!, 'base64'));
  return createHash('sha256').update(new Uint8Array(c.publicKey.export({ type: 'spki', format: 'der' }))).digest('hex');
};
const SPKI_A = spkiOfKey(0); // XxRc...  fe4fa28d... (signs the real token)
const SPKI_B = spkiOfKey(3); // rFl9...  97cda3af...
const JWKS_A: MaaJwks = { keys: [JWKS.keys[0]!] };
const JWKS_B: MaaJwks = { keys: [JWKS.keys[3]!] };
const JWKS_AB: MaaJwks = { keys: [JWKS.keys[0]!, JWKS.keys[3]!] };
const MS_ROOT = new X509Certificate(Buffer.from(JWKS.keys[1]!.x5c![2]!, 'base64'));
const MS_ROOT_SPKI = createHash('sha256').update(new Uint8Array(MS_ROOT.publicKey.export({ type: 'spki', format: 'der' }))).digest('hex');

const respond = (jwks: unknown) => new Response(JSON.stringify(jwks), { status: 200, headers: { 'content-type': 'application/json' } });
function fetchOf(seq: Array<MaaJwks | Error | (() => Response)>) {
  let i = 0;
  const calls: string[] = [];
  const f = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push(String(url));
    expect(init?.redirect).toBe('error');
    const step = seq[Math.min(i++, seq.length - 1)]!;
    if (step instanceof Error) throw step;
    if (typeof step === 'function') return step();
    return respond(step);
  }) as typeof fetch;
  return { f, calls };
}
const basePolicy = (over: Partial<MaaKeyPolicy> = {}): MaaKeyPolicy => ({ trustedIssuers: [ISSUER], allowTrustOnFirstUse: true, builtinPins: false, ...over });
function trust(seq: Parameters<typeof fetchOf>[0], over: Partial<MaaKeyPolicy> = {}, store = createMemoryMaaKeyStateStore()) {
  const { f, calls } = fetchOf(seq);
  return { t: createMaaKeyTrust({ policy: basePolicy(over), store, fetch: f }), store, calls };
}
const spkis = (r: MaaTrustResult) => (r.ok ? r.trustAnchors.rootSpkiSha256 : r.code);
const code = (r: MaaTrustResult) => (r.ok ? 'ok' : r.code);

describe('attest-maa-keys: real instance certs', () => {
  it('the real self-signed instance certs pass the CN == issuer check; chained keys are ignored without a pinned root', () => {
    const ev = evaluateMaaJwks(JWKS, ISSUER, basePolicy(), NOW);
    expect(ev.accepted.map((a) => a.spki).sort()).toEqual([SPKI_A, SPKI_B].sort());
    expect(ev.rejected).toHaveLength(2);
    expect(ev.rejected[0]!.reason).toMatch(/chained key ignored/);
  });

  it('with the Microsoft root pinned, chained keys anchor on the (single, deduped) root SPKI', () => {
    const ev = evaluateMaaJwks(JWKS, ISSUER, basePolicy({ chainRootSpkiSha256: [MS_ROOT_SPKI], chainLeafCn: ['Microsoft Azure Attestation 2020'] }), NOW);
    expect(ev.accepted.map((a) => a.spki).sort()).toEqual([SPKI_A, SPKI_B, MS_ROOT_SPKI].sort());
    const wrongCn = evaluateMaaJwks(JWKS, ISSUER, basePolicy({ chainRootSpkiSha256: [MS_ROOT_SPKI], chainLeafCn: ['Something Else'] }), NOW);
    expect(wrongCn.accepted.map((a) => a.spki)).not.toContain(MS_ROOT_SPKI);
    const wrongRoot = evaluateMaaJwks(JWKS, ISSUER, basePolicy({ chainRootSpkiSha256: ['00'.repeat(32)] }), NOW);
    expect(wrongRoot.rejected.some((r) => /not pinned/.test(r.reason))).toBe(true);
  });

  it('rejects CN mismatch (another instance URL), expired certs, and over-age keys', () => {
    const other = 'https://sharedeus.eus.attest.azure.net';
    const ev = evaluateMaaJwks(JWKS, other, basePolicy({ trustedIssuers: [other] }), NOW);
    expect(ev.accepted).toHaveLength(0);
    expect(ev.rejected.some((r) => /CN does not equal/.test(r.reason))).toBe(true);
    expect(evaluateMaaJwks(JWKS, ISSUER, basePolicy(), Date.parse('2027-11-01T00:00:00Z')).accepted).toHaveLength(0);
    expect(evaluateMaaJwks(JWKS, ISSUER, basePolicy({ maxKeyAgeMs: 1000 }), NOW).accepted).toHaveLength(0);
    expect(evaluateMaaJwks(JWKS, ISSUER, basePolicy(), Date.parse('2026-01-01T00:00:00Z')).accepted).toHaveLength(0); // not yet valid
  });

  it('produces anchors that verify the REAL token end-to-end through createAzureMaaVerifier', async () => {
    const { t } = trust([JWKS]);
    const r = await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.source).toBe('fetched');
    expect(r.trustAnchors.rootSpkiSha256).toContain(SPKI_A);
    const EXPECTED: ExpectedAttestationBinding = {
      holderPub: 'pca-realsilicon-azure-tdx-holder',
      grantRef: 'grant_pca_azure_maa_realsilicon',
      epoch: 1,
      nonce: 'srv-nonce-maa-5d3b8e1f9a27c604',
    };
    expect(attestationBinding(EXPECTED).length).toBeGreaterThan(0);
    const v = createAzureMaaVerifier({
      trustedIssuers: [ISSUER],
      trustAnchors: r.trustAnchors,
      policy: { tdxMrtds: [MRTD], runtimeUserDataBinding: true },
      resolveEvidence: () => ({ token: BOUND, jwks: JWKS }),
    });
    const out = await v.verify({ document: {} as unknown as AttestationDocument, ctx: {} as never, nowMs: NOW, expected: EXPECTED });
    expect(out.reason).toBeUndefined();
    expect(out.ok).toBe(true);
    // Anchors that exclude the signing key must NOT verify it.
    const other = createAzureMaaVerifier({
      trustedIssuers: [ISSUER],
      trustAnchors: { rootSpkiSha256: [SPKI_B] },
      policy: { tdxMrtds: [MRTD], runtimeUserDataBinding: true },
      resolveEvidence: () => ({ token: BOUND, jwks: JWKS }),
    });
    expect((await other.verify({ document: {} as unknown as AttestationDocument, ctx: {} as never, nowMs: NOW, expected: EXPECTED })).ok).toBe(false);
  });
});

describe('attest-maa-keys: bootstrap and rotation', () => {
  it('refuses trust-on-first-use by default; accepts seeded initialPins', async () => {
    const a = trust([JWKS_A], { allowTrustOnFirstUse: false });
    expect(code(await a.t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('no-baseline');
    const b = trust([JWKS_A], { allowTrustOnFirstUse: false, initialPins: { [ISSUER]: [SPKI_A] } });
    expect(spkis(await b.t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toEqual([SPKI_A]);
    const c = trust([JWKS_B], { allowTrustOnFirstUse: false, initialPins: { [ISSUER]: [SPKI_A] } });
    expect(code(await c.t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('no-overlap');
  });

  it('a new key added WITH overlap is accepted and persisted; the old key may later drop', async () => {
    const { t, store } = trust([JWKS_A, JWKS_AB, JWKS_B]);
    const r1 = await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(spkis(r1)).toEqual([SPKI_A]);
    const r2 = await t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR });
    expect(r2.ok && r2.newKeys).toEqual([SPKI_B]);
    expect(spkis(r2)).toEqual([SPKI_A, SPKI_B].sort());
    const r3 = await t.getTrustAnchors(ISSUER, { nowMs: NOW + 4 * HOUR });
    expect(r3.ok && r3.removedKeys).toEqual([SPKI_A]);
    expect(spkis(r3)).toEqual([SPKI_B]);
    expect(store.snapshot().get(ISSUER)!.anchors.map((a) => a.spki)).toEqual([SPKI_B]);
    // firstSeenMs survives across fetches
    expect(store.snapshot().get(ISSUER)!.anchors[0]!.firstSeenMs).toBe(NOW + 2 * HOUR);
  });

  it('total replacement without overlap is rejected and does not touch persisted state', async () => {
    const { t, store } = trust([JWKS_A, JWKS_B]);
    await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const before = JSON.stringify(store.snapshot().get(ISSUER));
    const r = await t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR });
    expect(code(r)).toBe('no-overlap');
    expect(JSON.stringify(store.snapshot().get(ISSUER))).toBe(before);
  });

  it('total replacement is accepted when an operator-signed re-pin approves the new key', async () => {
    const op = generateKeyPair();
    const issuerKeys: Record<string, AllowlistIssuerKey> = { ops: { alg: 'ed25519', keys: { edPub: b64u(op.publicKey) } } };
    const mk = (entries: AllowlistEntry[], version = 1): MaaRepin => ({
      manifest: signAllowlistManifest(
        { version, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + 30 * DAY, entries },
        { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: op.secretKey } },
      ),
      verify: { issuerKeys },
    });
    const { t } = trust([JWKS_A, JWKS_B, JWKS_B]);
    await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const repin = mk([{ kind: 'maa-signing-spki', value: SPKI_B, label: ISSUER }]);
    const r = await t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR, repin });
    expect(spkis(r)).toEqual([SPKI_B]);
    // approval for a DIFFERENT issuer label does not help
    const t2 = trust([JWKS_A, JWKS_B]);
    await t2.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const wrong = mk([{ kind: 'maa-signing-spki', value: SPKI_B, label: 'https://other.attest.azure.net' }]);
    expect(code(await t2.t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR, repin: wrong }))).toBe('no-overlap');
    // an invalid (expired / tampered / unknown issuer) manifest fails closed
    const t3 = trust([JWKS_A, JWKS_B]);
    await t3.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const forged: MaaRepin = { ...repin, verify: { issuerKeys: { ops: { alg: 'ed25519', keys: { edPub: b64u(generateKeyPair().publicKey) } } } } };
    expect(code(await t3.t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR, repin: forged }))).toBe('repin-invalid');
    const late = await t3.t.getTrustAnchors(ISSUER, { nowMs: NOW + 40 * DAY, repin });
    expect(code(late)).toBe('repin-invalid');
  });

  it('a signed revocation strips a key the JWKS still serves', async () => {
    const op = generateKeyPair();
    const repin: MaaRepin = {
      manifest: signAllowlistManifest(
        { version: 2, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + 30 * DAY, entries: [{ kind: 'maa-signing-spki', value: SPKI_A, label: ISSUER, revoked: true }] },
        { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: op.secretKey } },
      ),
      verify: { issuerKeys: { ops: { alg: 'ed25519', keys: { edPub: b64u(op.publicKey) } } } },
    };
    const { t } = trust([JWKS_AB]);
    const r = await t.getTrustAnchors(ISSUER, { nowMs: NOW, repin });
    expect(spkis(r)).toEqual([SPKI_B]);
    const only = trust([JWKS_A]);
    expect(code(await only.t.getTrustAnchors(ISSUER, { nowMs: NOW, repin }))).toBe('no-valid-keys');
  });

  it('enforces maxNewKeysPerFetch', async () => {
    const { t } = trust([JWKS_A, JWKS_AB], { maxNewKeysPerFetch: 0 });
    await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(code(await t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR }))).toBe('too-many-new-keys');
    const init = trust([JWKS_AB], { maxInitialKeys: 1 });
    expect(code(await init.t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('too-many-new-keys');
  });

  it('rejects an untrusted issuer and a corrupt persisted state; clock regression fails closed', async () => {
    const { t, store } = trust([JWKS_A]);
    expect(code(await t.getTrustAnchors('https://evil.example', { nowMs: NOW }))).toBe('untrusted-issuer');
    await store.set(ISSUER, { v: 1, issuer: ISSUER, fetchedAtMs: NOW, anchors: [{ spki: 'zz', kind: 'self-signed', notBeforeMs: 0, notAfterMs: 1, firstSeenMs: 0 }] });
    expect(code(await t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('corrupt-state');
    const ok = trust([JWKS_A]);
    await ok.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(code(await ok.t.getTrustAnchors(ISSUER, { nowMs: NOW - DAY }))).toBe('clock-regression');
  });
});

describe('attest-maa-keys: cache, staleness, fetch failures', () => {
  it('serves from cache within the TTL without refetching', async () => {
    const { t, calls } = trust([JWKS_A]);
    await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const r = await t.getTrustAnchors(ISSUER, { nowMs: NOW + 10 * 60_000 });
    expect(r.ok && r.source).toBe('cache');
    expect(calls).toEqual([`${ISSUER}/certs`]);
  });

  it('on fetch failure uses the cache within maxStaleMs, then fails closed', async () => {
    const { t } = trust([JWKS_A, new Error('network down')], { ttlMs: HOUR, maxStaleMs: 6 * HOUR });
    await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const stale = await t.getTrustAnchors(ISSUER, { nowMs: NOW + 3 * HOUR });
    expect(stale.ok && stale.source).toBe('stale-cache');
    expect(spkis(stale)).toEqual([SPKI_A]);
    expect(code(await t.getTrustAnchors(ISSUER, { nowMs: NOW + 7 * HOUR }))).toBe('stale-exceeded');
  });

  it('fails closed on fetch failure with no cache; stale never resurrects an expired key', async () => {
    const none = trust([new Error('down')]);
    expect(code(await none.t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('fetch-failed');
    const { t } = trust([JWKS_A, new Error('down')], { ttlMs: HOUR, maxStaleMs: 1000 * DAY });
    await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(code(await t.getTrustAnchors(ISSUER, { nowMs: Date.parse('2027-11-01T00:00:00Z') }))).toBe('stale-exceeded');
  });

  it('a policy violation never falls back to stale data', async () => {
    const { t } = trust([JWKS_A, JWKS_B], { ttlMs: HOUR });
    await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(code(await t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR }))).toBe('no-overlap');
  });
});

describe('attest-maa-keys: guarded fetch', () => {
  it('rejects non-https / path issuers and a missing fetch', async () => {
    await expect(fetchMaaCerts('http://x.attest.azure.net', { fetch: fetchOf([JWKS]).f })).rejects.toThrow(/https/);
    await expect(fetchMaaCerts('https://x.attest.azure.net/path', { fetch: fetchOf([JWKS]).f })).rejects.toThrow(/https/);
    await expect(fetchMaaCerts(ISSUER, { fetch: undefined as unknown as typeof fetch })).rejects.toThrow(/injected/);
  });

  it('rejects HTTP errors, redirects, oversize bodies, timeouts and malformed JWKS', async () => {
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([() => new Response('x', { status: 500 })]).f })).rejects.toThrow(/HTTP 500/);
    const redirected = () => {
      const r = respond(JWKS);
      Object.defineProperty(r, 'url', { value: 'https://evil.example/certs' });
      return r;
    };
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([redirected]).f })).rejects.toThrow(/redirect/);
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([JWKS]).f, maxBytes: 100 })).rejects.toThrow(/size limit/);
    const never = (async () => new Promise<Response>(() => undefined)) as unknown as typeof fetch;
    await expect(fetchMaaCerts(ISSUER, { fetch: never, timeoutMs: 20 })).rejects.toThrow(/timed out/);
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([() => respond({ nope: 1 })]).f })).rejects.toThrow(/keys array/);
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([() => respond({ keys: [{ kid: 'a' }] })]).f })).rejects.toThrow(/x5c/);
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([() => new Response('not json')]).f })).rejects.toThrow(/JSON/);
  });

  it('returns the real JWKS shape on success', async () => {
    const j = await fetchMaaCerts(ISSUER, { fetch: fetchOf([JWKS]).f });
    expect(j.keys).toHaveLength(4);
  });

  it('createMaaKeyTrust validates its configuration', () => {
    const { f } = fetchOf([JWKS]);
    const store = createMemoryMaaKeyStateStore();
    expect(() => createMaaKeyTrust({ policy: { trustedIssuers: [] }, store, fetch: f })).toThrow();
    expect(() => createMaaKeyTrust({ policy: { trustedIssuers: ['http://x'] }, store, fetch: f })).toThrow();
    expect(() => createMaaKeyTrust({ policy: { trustedIssuers: [ISSUER] }, store, fetch: undefined as unknown as typeof fetch })).toThrow();
  });
});
