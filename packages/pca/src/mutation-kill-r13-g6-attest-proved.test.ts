/**
 * r13 mutation kills for attest-proved.ts (runtime mutants): where the PROVED integer arithmetic and the double fallback
 * differ (operands near 2^52 / 2^53, where a double sum rounds), hostile contexts whose getters change between reads,
 * non-string attestor keys, the hook's kept-by-reference stores / verifiers, its defaults, the durable store answering a
 * corrupt record at update time, and the anchored verifier's fallback freshness, feed scan and conflict reporting.
 */
import { describe, expect, it } from 'vitest';
import { attestationBindingB64u, createAttestationVerifier, verifyAttestation, type AttestationDocument, type ExpectedAttestationBinding } from './attestation';
import { allowlistAnchorCommit, anchorAllowlistHead, createAllowlistAnchorLog, verifyAllowlistAnchored, type AllowlistAnchorEntry, type AnchorTrust } from './attest-allowlist-anchor';
import { signAllowlistManifest, verifyAllowlistDurable, verifyAllowlistManifest, type AllowlistIssuerKey, type VerifyAllowlistResult } from './attest-allowlist';
import { createMemoryDurableKv } from './durable-state';
import { mintGrant } from './envelope';
import { b64u, canonicalBytes, utf8 } from './hash';
import { encodeKey, generateKeyPair, sign } from './keys';
import { signTreeHead, TransparencyLedger } from './ledger';
import { DEFAULT_RISK_POLICY } from './risk';

const P52 = 2 ** 52;
const P53 = 2 ** 53;
const T = 5_000_000;
const NONCE = 'q3Vx8mZ0aT7bLk2RwYp9Hs';
const HOLDER = 'holder-key';
const GREF = 'grant-ref-1';
const att = generateKeyPair();
const ATT_PUB = encodeKey(att.publicKey);
const EXPECTED: ExpectedAttestationBinding = { holderPub: HOLDER, grantRef: GREF, epoch: 1, nonce: NONCE };
const BOUND = attestationBindingB64u(EXPECTED);
const principal = generateKeyPair();
const GRANT = mintGrant({ principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: HOLDER, goal: 'g', envelope: { predicates: [{ verb: 'read', resource: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } }).grant;
const PCACTN = { grant_ref: GREF, attestation: { epoch: 1, quote_digest: NONCE }, cap_chain: [{ holder: HOLDER }] };
const mkCtx = () => ({ pcactn: PCACTN, grant: GRANT }) as never;
const doc = (o: Record<string, unknown> = {}): AttestationDocument => {
  const b = { model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o', nonce: NONCE, issued_at: T - 1000, expires_at: T + 1000, attestor: ATT_PUB, mode: 'software', binding: BOUND, ...o };
  const m = canonicalBytes(b);
  const p = utf8('atlas-pca/attest/v1\0');
  const msg = new Uint8Array(p.length + m.length);
  msg.set(p);
  msg.set(m, p.length);
  return { ...b, sig: b64u(sign(att.secretKey, msg)) } as never;
};
type RunOpts = { document?: AttestationDocument; ctx?: unknown; expected?: Partial<ExpectedAttestationBinding>; nowMs?: number; maxNonceAgeMs?: number; clockSkewMs?: number; trusted?: unknown[] };
const run = (o: RunOpts = {}) =>
  verifyAttestation({
    document: o.document ?? doc(),
    ctx: ('ctx' in o ? o.ctx : mkCtx()) as never,
    expected: { ...EXPECTED, ...(o.expected ?? {}) },
    nowMs: o.nowMs ?? T,
    trustedAttestorKeys: (o.trusted ?? [ATT_PUB]) as string[],
    ...(o.maxNonceAgeMs !== undefined ? { maxNonceAgeMs: o.maxNonceAgeMs } : {}),
    ...(o.clockSkewMs !== undefined ? { clockSkewMs: o.clockSkewMs } : {}),
  });
const outcome = async (o: RunOpts) => {
  const v = await run(o);
  return v.ok ? 'ok' : v.reason;
};

describe('nonce age: the proved integer decision vs the double fallback', () => {
  it('integer operands near 2^52 with a fractional skew: decided exactly (now + floor(skew) < issued), not on a rounded double sum', async () => {
    const now = P52 + 1;
    // now + 0.5 rounds (ties to even) to 2^52 + 2 in doubles, which would hide the future nonce
    expect(await outcome({ nowMs: now, clockSkewMs: 0.5, expected: { nonceIssuedAt: P52 + 2 }, document: doc({ issued_at: P52, expires_at: P52 + 1000 }) })).toBe('nonce issued in the future');
  });
  it('an upper bound (maxAge + skew) at or beyond 2^52 takes the double fallback', async () => {
    const d = doc({ issued_at: 1, expires_at: 1000 });
    expect(await outcome({ nowMs: 2, clockSkewMs: P52 - 0.5, expected: { nonceIssuedAt: P52 + 2 }, document: d })).toBe('ok');
    expect(await outcome({ nowMs: 2, clockSkewMs: P52 - 0.5, maxNonceAgeMs: 0.5, expected: { nonceIssuedAt: P52 + 2 }, document: d })).toBe('ok');
  });
});

describe('validity window: the proved integer decision vs the double fallback', () => {
  it('integer times near 2^53 with a fractional skew are not yet valid exactly when now + floor(skew) < issued_at', async () => {
    const now = P53 - 2;
    expect(await outcome({ nowMs: now, clockSkewMs: 0.75, expected: { nonceIssuedAt: undefined }, document: doc({ issued_at: P53 - 1, expires_at: P53 - 1 }) })).toBe('attestation not yet valid');
  });
});

describe('hostile contexts whose members change between reads', () => {
  it('an absent context is a grant_ref refusal, not an error', async () => {
    expect(await outcome({ ctx: undefined })).toBe('attestation binding: PCActn grant_ref differs from expected grant');
  });
  const flaky = (goodReads: number) => {
    let n = 0;
    return { get pcactn() { return n++ < goodReads ? PCACTN : undefined; }, grant: GRANT };
  };
  it('a pcactn that disappears after the grant_ref read: epoch refusal', async () => {
    expect(await outcome({ ctx: flaky(1) })).toBe('attestation binding: PCActn attestation epoch differs from expected epoch');
  });
  it('a pcactn that disappears after the epoch read: quote refusal', async () => {
    expect(await outcome({ ctx: flaky(2) })).toBe('attestation nonce does not bind to this PCActn');
  });
  it('an attestation that disappears after the epoch read: quote refusal', async () => {
    let n = 0;
    const pcactn = { grant_ref: GREF, get attestation() { return n++ < 1 ? { epoch: 1, quote_digest: NONCE } : undefined; } };
    expect(await outcome({ ctx: { pcactn, grant: GRANT } })).toBe('attestation nonce does not bind to this PCActn');
  });
});

describe('attestor trust', () => {
  it('a non-string attestor is never trusted, even if the trusted list holds the same value', async () => {
    expect(await outcome({ trusted: [5], document: doc({ attestor: 5 }) })).toBe('attestor key is not trusted');
  });
});

describe('the attestation hook', () => {
  const expectedBinding = () => EXPECTED;
  it('a plain-object nonce store with data state is used by reference (its state can change)', async () => {
    const store = { seen: [] as string[], consume(n: string) { if (this.seen.includes(n)) return false; this.seen.push(n); return true; } };
    const h = createAttestationVerifier({ trustedAttestorKeys: [ATT_PUB], resolveDocument: () => doc(), now: () => T, expectedBinding, nonceStore: store });
    expect(await h(mkCtx())).toMatchObject({ ok: true });
    expect(await h(mkCtx())).toMatchObject({ ok: false, reason: 'attestation nonce already consumed (replay)' });
    expect(store.seen).toStrictEqual([NONCE]);
  });
  it('a plain-object hardware verifier with data state is used by reference', async () => {
    const hw = {
      calls: [] as number[],
      async verify() { this.calls.push(1); return { ok: true, bound: true, measured: { model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o' } }; },
    };
    const h = createAttestationVerifier({ trustedAttestorKeys: [ATT_PUB], resolveDocument: () => doc({ mode: 'hardware' }), now: () => T, expectedBinding: () => ({ ...EXPECTED, nonceIssuedAt: T - 1000 }), hardwareVerifier: hw });
    expect(await h(mkCtx())).toMatchObject({ ok: true });
    expect(hw.calls).toStrictEqual([1]);
  });
  it('no trusted key list trusts no attestor', async () => {
    const d = doc({ attestor: 'Stryker was here' });
    const h = createAttestationVerifier({ resolveDocument: () => d, now: () => T, expectedBinding } as never);
    expect(await h(mkCtx())).toMatchObject({ ok: false, reason: 'attestor key is not trusted' });
  });
  it('the default clock is the wall clock: a document that expired a second ago is expired', async () => {
    const d = doc({ issued_at: Date.now() - 120_000, expires_at: Date.now() - 1000 });
    const h = createAttestationVerifier({ trustedAttestorKeys: [ATT_PUB], resolveDocument: () => d, expectedBinding });
    expect(await h(mkCtx())).toMatchObject({ ok: false, reason: 'attestation expired' });
  });
  it('self-declared nonce: a pcactn without an attestation is a binding refusal, not an error', async () => {
    const h = createAttestationVerifier({ trustedAttestorKeys: [ATT_PUB], resolveDocument: () => doc(), now: () => T, insecure_selfDeclaredNonce: true });
    const r = await h({ pcactn: { grant_ref: GREF, cap_chain: [{ holder: HOLDER }] }, grant: GRANT } as never);
    expect(r).toMatchObject({ ok: false, reason: 'attestation binding not constructible: binding: nonce required' });
  });
});

// ---- allowlist: durable + anchored ------------------------------------------------------------
type Ok = Extract<VerifyAllowlistResult, { ok: true }>;
const NOW = Date.parse('2026-10-09T00:00:00Z');
const DAY = 86_400_000;
const ops = generateKeyPair();
const keys: Record<string, AllowlistIssuerKey> = { ops: { alg: 'ed25519', keys: { edPub: b64u(ops.publicKey) } } };
const guardian = generateKeyPair();
const trust: AnchorTrust = { logKey: b64u(guardian.publicKey), instanceId: 'inst-1', principal: 'allowlist-log' };
const signed = (version: number, label = 'boot') =>
  signAllowlistManifest({ version, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + 30 * DAY, entries: [{ kind: 'tdx-mrtd', value: 'ab'.repeat(48), label: `${label} v${version}` }] }, { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: ops.secretKey } });
const manifest = (version: number, label?: string): Ok => {
  const v = verifyAllowlistManifest(signed(version, label), { issuerKeys: keys, nowMs: NOW });
  if (!v.ok) throw new Error('setup');
  return v;
};
const why = (r: ReturnType<typeof verifyAllowlistAnchored>) => (r.ok ? 'ok' : `${r.code}: ${r.reason}`);
const feed = (es: AllowlistAnchorEntry[], at: number, timestamp = NOW) => {
  const l = TransparencyLedger.fromEntries(es.map((e) => ({ commit: allowlistAnchorCommit(e) })), trust.principal);
  const head = signTreeHead(guardian.secretKey, { instance_id: trust.instanceId, principal: trust.principal, size: es.length, root: l.head().root, prev_root: '', timestamp });
  return { head, entries: es, proof: l.inclusionProof(at) };
};
const E = (version: number, d: string, issuer = 'ops'): AllowlistAnchorEntry => ({ issuer, version, digest: d.repeat(43) });
const asVerified = (e: AllowlistAnchorEntry) => ({ ok: true, ...e }) as unknown as Ok;

describe('durable allowlist', () => {
  it('a function manifest is not a record: malformed before anything else', async () => {
    const fn = Object.assign(() => undefined, signed(1));
    expect(await verifyAllowlistDurable(fn, { issuerKeys: keys, nowMs: NOW }, createMemoryDurableKv())).toEqual({ ok: false, code: 'malformed', reason: 'issuer must be a string' });
  });
  it('a record that turned corrupt between the read and the update is decided on the pre-update state', async () => {
    const kv = { ...createMemoryDurableKv(), get: async () => undefined, update: async (_k: string, fn: (c: unknown) => unknown) => fn('garbage') ?? 'garbage' };
    expect(await verifyAllowlistDurable(signed(2), { issuerKeys: keys, nowMs: NOW }, kv as never)).toEqual({ ok: false, code: 'rollback', reason: 'a newer manifest was accepted concurrently' });
  });
});

describe('anchored allowlist: inputs', () => {
  it('a function as evidence is no evidence', () => {
    const v = manifest(1);
    const log = createAllowlistAnchorLog({ instanceId: trust.instanceId, principal: trust.principal });
    const ev = anchorAllowlistHead(log, v, { guardianSecret: guardian.secretKey, nowMs: NOW });
    const fn = Object.assign(() => undefined, ev);
    expect(why(verifyAllowlistAnchored(v, fn as never, { trust, nowMs: NOW }))).toBe('missing-proof: no anchor evidence (head + entries + inclusion proof) supplied');
  });
  it('a function feed entry is malformed', () => {
    const a = E(1, 'A');
    const ev = feed([a], 0);
    const fn = Object.assign(() => undefined, a);
    expect(why(verifyAllowlistAnchored(asVerified(a), { ...ev, entries: [fn as never] }, { trust, nowMs: NOW }))).toBe('feed-mismatch: entries do not match the signed tree size');
  });
  it('an issuer of exactly 200 characters is a valid entry', () => {
    const a = E(1, 'A', 'x'.repeat(200));
    expect(why(verifyAllowlistAnchored(asVerified(a), feed([a], 0), { trust, nowMs: NOW }))).toBe('ok');
  });
  it('a throwing non-Error inside the verifier is a bad-head with the generic reason', () => {
    const a = E(1, 'A');
    const opts = { nowMs: NOW, get trust(): AnchorTrust { throw 'boom'; } };
    expect(why(verifyAllowlistAnchored(asVerified(a), feed([a], 0), opts as never))).toBe('bad-head: anchor verification error');
  });
});

describe('anchored allowlist: freshness, proved vs fallback', () => {
  const a = E(1, 'A');
  const at = (timestamp: number, nowMs: number, o: { clockSkewMs?: number; maxHeadAgeMs?: number } = {}) =>
    why(verifyAllowlistAnchored(asVerified(a), feed([a], 0, timestamp), { trust, nowMs, ...o }));
  it('integer clock near 2^52, fractional skew: exact (proved) future check', () => {
    expect(at(P52 + 2, P52 + 1, { clockSkewMs: 0.5 })).toBe('stale-head: tree head is timestamped in the future');
  });
  it('maxHeadAgeMs of 2^52 or more takes the double fallback, with its own boundaries and reasons', () => {
    expect(at(P52 + 2, P52 + 1, { clockSkewMs: 0.5, maxHeadAgeMs: P52 })).toBe('ok'); // the double sum rounds up to the timestamp
    expect(at(NOW, NOW - 60_001, { maxHeadAgeMs: P52 })).toBe('stale-head: tree head is timestamped in the future');
    expect(at(NOW, NOW - 60_000, { maxHeadAgeMs: P52 })).toBe('ok');
    expect(at(NOW, NOW, { maxHeadAgeMs: P52 })).toBe('ok');
    expect(at(NOW, NOW + P52, { maxHeadAgeMs: P52 })).toBe('ok');
    expect(at(NOW, NOW + P52 + 1, { maxHeadAgeMs: P52 })).toBe(`stale-head: tree head is older than maxHeadAgeMs (${P52})`);
  });
});

describe('anchored allowlist: feed scan', () => {
  it('the highest anchored version is the maximum, not the last entry', () => {
    const es = [E(1, 'A'), E(3, 'B'), E(2, 'C')];
    expect(why(verifyAllowlistAnchored(asVerified(es[2]!), feed(es, 2), { trust, nowMs: NOW }))).toBe("anchored-rollback: manifest version 2 < highest anchored 3 for 'ops'");
  });
  it('a duplicated identical entry does not hide a later conflict, and the conflict names its own version', () => {
    const es = [E(1, 'A'), E(1, 'A'), E(2, 'B'), E(2, 'C')];
    expect(why(verifyAllowlistAnchored(asVerified(es[2]!), feed(es, 2), { trust, nowMs: NOW }))).toBe('log-conflict: log anchors two different digests for version 2');
  });
  it('a feed with no entry of this issuer is a proof failure (never an internal error)', () => {
    const other = E(1, 'A', 'someone');
    expect(why(verifyAllowlistAnchored(asVerified(E(1, 'B')), feed([other], 0), { trust, nowMs: NOW }))).toBe('bad-proof: inclusion proof does not place this manifest under the signed root');
  });
});
