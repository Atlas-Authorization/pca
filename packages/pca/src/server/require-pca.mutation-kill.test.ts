/** Mutation-kill tests for server/require-pca.ts: every error code/reason/status, lock hand-off, replay-store pins, principal rule, authn-vs-authz split. */
import { describe, expect, it } from 'vitest';
import { beaconRef, issueLivenessBeacon } from '../beacons';
import { encodeKey, generateKeyPair } from '../keys';
import { RevocationSet, signRevocationEpoch, type RevocationEpoch } from '../revocation';
import { defaultExtract, memoryPcaStore, requirePCA, type PcaStateStore } from './require-pca';
import { AUD, NOW, setup } from './fixture.test-util';

const b64u = (s: string) => Buffer.from(s).toString('base64url');
const s = setup();
const revocation = () => ({ enforced: true as const, ok: true });
const base = () => ({
  resolveGrant: async (ref: string) => (ref === s.grant.id ? s.grant : null),
  now: () => NOW,
  audience: AUD,
  context: () => ({ plan: s.plan, planAuthorized: true, risk: s.lowRisk }),
});
const guard = (extra = {}) => requirePCA({ ...base(), budgetStore: memoryPcaStore(), hooks: { revocation }, ...extra });
const body = (p: unknown) => ({ headers: {}, body: { pcactn: p } });
const challenge = (realm: string, error: string) => `PCA realm="${realm}", error="${error}", hint="send PCA-Action: <base64url PCActn> or JSON body {pcactn}"`;

describe('requirePCA: pre-verification rejections (status, code, reason, verdict shape)', () => {
  it('no PCActn: undefined and null both 401 missing_pcactn with the canonical deny verdict', async () => {
    for (const ret of [undefined, null]) {
      const r = await guard({ extract: () => ret as never })({ headers: {} });
      expect(r).toEqual({
        ok: false,
        status: 401,
        wwwAuthenticate: challenge('pca', 'missing_pcactn'),
        verdict: { allow: false, r: 1, requiredThreshold: { t: 3, proof: 'strong', optimisticAllowed: false }, checks: { pcactn: 'fail' }, reasons: ['no PCActn presented'] },
      });
    }
  });
  it('a custom realm is used in the challenge', async () => {
    const r = await guard({ realm: 'my-rs' })({ headers: {} });
    expect(!r.ok && r.wwwAuthenticate).toBe(challenge('my-rs', 'missing_pcactn'));
  });
  it('an extractor that throws is 401 invalid_request "unreadable PCActn: <message>"', async () => {
    const r = await guard({ extract: () => { throw new Error('bad-hdr'); } })({ headers: {} });
    expect(!r.ok && r.status).toBe(401);
    expect(!r.ok && r.verdict.reasons).toEqual(['unreadable PCActn: bad-hdr']);
    expect(!r.ok && r.wwwAuthenticate).toBe(challenge('pca', 'invalid_request'));
  });
  it('an undecodable string is 401 invalid_pcactn "undecodable PCActn: ..."', async () => {
    const r = await guard()({ headers: { 'pca-action': b64u('not json') } });
    expect(!r.ok && r.verdict.reasons[0]).toMatch(/^undecodable PCActn: .+/);
    expect(!r.ok && r.wwwAuthenticate).toBe(challenge('pca', 'invalid_pcactn'));
  });
  it('an object with no grant_ref (or a non-object) is 401 "malformed PCActn" invalid_pcactn', async () => {
    for (const bad of [{ foo: 1 }, 5, { grant_ref: 7 }]) {
      const r = await guard({ extract: () => bad as never })({ headers: {} });
      expect(!r.ok && r.status).toBe(401);
      expect(!r.ok && r.verdict.reasons).toEqual(['malformed PCActn']);
      expect(!r.ok && r.wwwAuthenticate).toBe(challenge('pca', 'invalid_pcactn'));
    }
  });
  it('the string "null" never reaches the verifier: 401, not a guard error', async () => {
    const r = await guard({ extract: () => 'null' })({ headers: {} });
    expect(!r.ok && r.status).toBe(401);
    expect(!r.ok && r.verdict.reasons[0]).not.toMatch(/guard error/);
  });
  it('an unknown grant_ref is 401 unknown_grant', async () => {
    const r = await guard()(body({ ...s.mk(s.plan[0]!), grant_ref: 'nope' }));
    expect(!r.ok && r.verdict.reasons).toEqual(['unknown grant_ref']);
    expect(!r.ok && r.wwwAuthenticate).toBe(challenge('pca', 'unknown_grant'));
  });
  it('an internal error fails closed 403 with the message, or "unknown" for a non-Error throw', async () => {
    const e1 = await guard({ resolveGrant: async () => { throw new Error('db-down'); } })(body(s.mk(s.plan[0]!)));
    expect(e1).toMatchObject({ ok: false, status: 403, verdict: { reasons: ['guard error (fail closed): db-down'] } });
    const e2 = await guard({ resolveGrant: async () => { throw 'x'; } })(body(s.mk(s.plan[0]!)));
    expect(e2).toMatchObject({ ok: false, status: 403, verdict: { reasons: ['guard error (fail closed): unknown'] } });
  });
});

describe('requirePCA: default extraction', () => {
  it('header lookup is case-insensitive and ignores unrelated headers', () => {
    const text = '{"k":1}';
    expect(defaultExtract({ headers: { 'X-Other': 'zzz', 'PCA-Action': b64u(text) } })).toBe(text);
    expect(defaultExtract({ headers: { 'pca-action': b64u(text), 'x-other': 'zzz' } })).toBe(text);
  });
  it('0.4.1: surrounding whitespace in the header value is refused, not trimmed (strict unpadded base64url)', () => {
    const text = '{"k":1}';
    expect(defaultExtract({ headers: { 'pca-action': b64u(text) } })).toBe(text);
    expect(() => defaultExtract({ headers: { 'pca-action': `  ${b64u(text)} \n` } })).toThrow(/strict unpadded base64url/);
  });
  it('decodes the URL-safe alphabet back to the standard one ("-" -> "+", "_" -> "/")', () => {
    const text = '{"a":"???>>>~~~"}';
    expect(Buffer.from(text).toString('base64')).toMatch(/[+/]/);
    expect(defaultExtract({ headers: { 'pca-action': b64u(text) } })).toBe(text);
    expect(defaultExtract({ headers: { 'pca-action': Buffer.from(text).toString('base64url') } })).toBe(text);
  });
  it('a string-valued or object-valued body pcactn is returned as is; null / missing is null', () => {
    expect(defaultExtract({ headers: {}, body: { pcactn: 'abc' } })).toBe('abc');
    const o = { a: 1 };
    expect(defaultExtract({ headers: {}, body: { pcactn: o } })).toBe(o);
    expect(defaultExtract({ headers: {}, body: { pcactn: null } })).toBeNull();
    expect(defaultExtract({ headers: {}, body: { pcactn: 5 } })).toBeNull();
    expect(defaultExtract({ headers: {}, body: {} })).toBeNull();
    expect(defaultExtract({ headers: {}, body: '{not json' })).toBeNull();
  });
});

describe('requirePCA: per-grant critical section', () => {
  it('a request arriving while a queued one runs is still serialised behind it (the lock chain is not dropped early)', async () => {
    const m = new Map<string, unknown>();
    const delay = () => new Promise((r) => setTimeout(r, 40));
    const store: PcaStateStore = {
      get: async (k) => { const v = m.get(k) as never; await delay(); return v; }, // snapshot first: a concurrent request sees the pre-write state
      put: async (k, v) => { m.set(k, v); },
    };
    const g = guard({ budgetStore: store });
    const pc = (n: number) => body(s.mk(s.plan[0]!, { counter: n }));
    const p1 = g(pc(1));
    const p2 = g(pc(2));
    const r1 = await p1; // p1 is done; p2 has started and is waiting in store.get
    const p3 = g(pc(2)); // replay of p2's counter: must queue behind p2 and be denied
    const [r2, r3] = [await p2, await p3];
    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(true);
    expect(r3.ok).toBe(false);
    expect(!r3.ok && r3.verdict.checks.counter).toBe('fail');
  });
});

describe('requirePCA: replay counter reporting', () => {
  it('a replayed counter is denied with the exact reason even when default-deny is off', async () => {
    const store = memoryPcaStore();
    const g = guard({ budgetStore: store, insecureAllowUnenforced: true });
    const first = await g(body(s.mk(s.plan[0]!, { counter: 5 })));
    expect(first.ok).toBe(true);
    const again = await g(body(s.mk(s.plan[0]!, { counter: 5 })));
    expect(again.ok).toBe(false);
    if (!again.ok) {
      expect(again.status).toBe(403);
      expect(again.verdict.allow).toBe(false);
      expect(again.verdict.checks.counter).toBe('fail');
      expect(again.verdict.reasons).toContain('counter: 5 is not greater than last seen 5 (replay)');
    }
    const lower = await g(body(s.mk(s.plan[0]!, { counter: 4 })));
    expect(lower.ok).toBe(false);
    const higher = await g(body(s.mk(s.plan[0]!, { counter: 6 })));
    expect(higher.ok).toBe(true);
    expect(higher.ok && higher.verdict.checks.counter).toBe('pass');
  });
  it('without a store the counter is reported not-enforced (never pass)', async () => {
    const r = await requirePCA({ ...base(), insecureAllowUnenforced: true })(body(s.mk(s.plan[0]!)));
    expect(r.ok && r.verdict.checks.counter).toBe('not-enforced');
  });
});

describe('requirePCA: context, epoch and beacon wiring', () => {
  it('works with no `now` option and no `context` option (defaults), never a guard error', async () => {
    const { now: _n, context: _c, ...rest } = base();
    const r = await requirePCA({ ...rest, insecureAllowUnenforced: true })(body(s.mk(s.plan[0]!)));
    // real clock: the fixture PCActn (2026) may be expired, but the guard must have produced a verifier verdict, not crashed
    expect(r.verdict.reasons.join(' ')).not.toMatch(/guard error/);
  });
  it('a context-supplied budget wins over the stored one; the stored one fills in when absent', async () => {
    const store = memoryPcaStore();
    const key = `${s.grant.id}:${s.aPub}`;
    await store.put(key, { budget: { B: 0, tau: NOW, asOf: NOW } });
    const risk = { ...s.lowRisk, blastRadius: 0.5 };
    const mkReq = () => body(s.mk(s.plan[0]!));
    const withCtx = await guard({ budgetStore: store, context: () => ({ plan: s.plan, planAuthorized: true, risk, budget: { B: 1, tau: NOW, asOf: NOW } }) })(mkReq());
    expect(withCtx.ok).toBe(true);
    const store2 = memoryPcaStore();
    await store2.put(key, { budget: { B: 0, tau: NOW, asOf: NOW } });
    const fromState = await guard({ budgetStore: store2, context: () => ({ plan: s.plan, planAuthorized: true, risk }) })(mkReq());
    expect(fromState.ok).toBe(false); // B=0 from the store cannot afford the cost
    expect(!fromState.ok && fromState.verdict.checks.budget).toBe('pass');
  });
  it('a revocationEpoch / beacon already in the context is not re-fetched', async () => {
    let calls = 0;
    const ctxEpoch = { epoch: { v: 1 } as never, guardianPublic: 'x' };
    const g = guard({
      context: () => ({ plan: s.plan, planAuthorized: true, risk: s.lowRisk, revocationEpoch: ctxEpoch, beacon: { beacon: {} as never, issuers: [], instance: 'i' } }),
      revocationEpoch: async () => { calls++; return null; },
      beacon: async () => { calls++; return null; },
    });
    await g(body(s.mk(s.plan[0]!)));
    expect(calls).toBe(0);
  });
  it('an unavailable epoch / beacon is not silently skipped: the required checks are not-enforced -> denied', async () => {
    const r = await guard({ revocationEpoch: async () => null, beacon: async () => undefined })(body(s.mk(s.plan[0]!)));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.verdict.checks.freshness).toBe('fail');
      expect(r.verdict.checks.beacon).toBe('fail');
      expect(r.verdict.reasons.some((x) => /^freshness: required check is not-enforced/.test(x))).toBe(true);
      expect(r.verdict.reasons.some((x) => /^beacon: required check is not-enforced/.test(x))).toBe(true);
    }
  });
  const G = generateKeyPair();
  const guardianPublic = encodeKey(G.publicKey);
  const mkEpoch = (epoch: number): RevocationEpoch => {
    const set = new RevocationSet();
    return signRevocationEpoch(G.secretKey, { instance_id: 'i', grant_ref: s.grant.id, epoch, set_size: set.size, root: set.root, issued_at: NOW, not_after: NOW + 300_000 });
  };
  const P = generateKeyPair();
  const issuer = encodeKey(P.publicKey);
  const mkB = (seq: number) => issueLivenessBeacon({ issuerSecret: P.secretKey, instance: 'ins_1', scope: s.grant.id, seq, issuedAt: NOW });
  const spyStore = () => {
    const inner = memoryPcaStore();
    const puts: Array<[string, Record<string, unknown>]> = [];
    const store: PcaStateStore = { get: (k) => inner.get(k), put: async (k, v) => { puts.push([k, v as never]); await inner.put(k, v); } };
    return { inner, store, puts };
  };
  it('the epoch pin is written when first seen (including epoch 0) and never rewritten for an equal value', async () => {
    const g = (store: PcaStateStore) => guard({ budgetStore: store, revocationEpoch: async () => ({ epoch: mkEpoch(0), guardianPublic }) });
    const a = spyStore();
    expect((await g(a.store)(body(s.mk(s.plan[0]!, { counter: 1 })))).ok).toBe(true);
    expect(a.puts.filter(([k]) => k === `${s.grant.id}:epoch`)).toEqual([[`${s.grant.id}:epoch`, { lastEpoch: 0 }]]);
    const b = spyStore();
    await b.inner.put(`${s.grant.id}:epoch`, { lastEpoch: 0 });
    expect((await g(b.store)(body(s.mk(s.plan[0]!, { counter: 1 })))).ok).toBe(true);
    expect(b.puts.filter(([k]) => k === `${s.grant.id}:epoch`)).toEqual([]);
  });
  it('the beacon seq pin is written when first seen (including seq 0) and never rewritten for an equal value', async () => {
    const g = (store: PcaStateStore, seq: number) => {
      const b = mkB(seq);
      return { run: () => guard({ budgetStore: store, beacon: async () => ({ beacon: b, issuers: [issuer], instance: 'ins_1' }) })(body(s.mk(s.plan[0]!, { counter: 1, beaconRef: beaconRef(b) }))) };
    };
    const a = spyStore();
    expect((await g(a.store, 0).run()).ok).toBe(true);
    expect(a.puts.filter(([k]) => k === `${s.grant.id}:beacon`)).toEqual([[`${s.grant.id}:beacon`, { lastBeaconSeq: 0 }]]);
    const b = spyStore();
    await b.inner.put(`${s.grant.id}:beacon`, { lastBeaconSeq: 4 });
    expect((await g(b.store, 4).run()).ok).toBe(true);
    expect(b.puts.filter(([k]) => k === `${s.grant.id}:beacon`)).toEqual([]);
    const c = spyStore();
    await c.inner.put(`${s.grant.id}:beacon`, { lastBeaconSeq: 4 });
    expect((await g(c.store, 3).run()).ok).toBe(false); // older seq: replay
  });
  it('epoch / beacon verification works without a state store (nothing to pin, nothing crashes)', async () => {
    const b = mkB(1);
    const r = await requirePCA({
      ...base(), hooks: { revocation }, insecureAllowUnenforced: true,
      revocationEpoch: async () => ({ epoch: mkEpoch(0), guardianPublic }),
      beacon: async () => ({ beacon: b, issuers: [issuer], instance: 'ins_1' }),
    })(body(s.mk(s.plan[0]!, { beaconRef: beaconRef(b) })));
    expect(r.ok).toBe(true);
    expect(r.ok && r.verdict.checks.freshness).toBe('pass');
    expect(r.ok && r.verdict.checks.beacon).toBe('pass');
  });
});

describe('requirePCA: resolved principal rules', () => {
  const ok = { pub: 'p', subject_type: 'user' as const, subject_id: 'u1', verified: true };
  it('a verified principal passes and is attached', async () => {
    const r = await guard({ resolvePrincipal: async () => ok })(body(s.mk(s.plan[0]!)));
    expect(r.ok && r.verdict.checks.principal).toBe('pass');
    expect(r.ok && r.verdict.principal).toEqual(ok);
  });
  it('an unverified principal is not-enforced unless verification is required', async () => {
    const r = await guard({ resolvePrincipal: async () => ({ ...ok, verified: false }) })(body(s.mk(s.plan[0]!)));
    expect(r.ok && r.verdict.checks.principal).toBe('not-enforced');
  });
  it('a null resolution becomes an "unverified" principal for the grant issuer', async () => {
    const r = await guard({ resolvePrincipal: async () => null })(body(s.mk(s.plan[0]!)));
    expect(r.ok && r.verdict.principal).toEqual({ pub: s.grant.issuer, subject_type: 'unverified', subject_id: null, verified: false });
  });
  it('requireVerifiedPrincipal denies an unverified one with its reason, and a missing resolver with its own', async () => {
    const un = await guard({ resolvePrincipal: async () => null, requireVerifiedPrincipal: true })(body(s.mk(s.plan[0]!)));
    expect(un.ok).toBe(false);
    if (!un.ok) {
      expect(un.status).toBe(403);
      expect(un.verdict.checks.principal).toBe('fail');
      expect(un.verdict.reasons).toContain('principal: the grant issuer is not an enrolled, verified principal');
    }
    const none = await guard({ requireVerifiedPrincipal: true })(body(s.mk(s.plan[0]!)));
    expect(none.ok).toBe(false);
    if (!none.ok) {
      expect(none.verdict.checks.principal).toBe('fail');
      expect(none.verdict.reasons).toContain('principal: requireVerifiedPrincipal needs a resolvePrincipal resolver');
    }
  });
});

describe('requirePCA: 401 (authentication) vs 403 (authorization)', () => {
  it('an unsupported (integer) version is 401 invalid_pcactn', async () => {
    const r = await guard()(body(s.mk(s.plan[0]!, { extra: { ver: 99 } })));
    expect(!r.ok && r.verdict.checks.version).toBe('fail');
    expect(!r.ok && r.status).toBe(401);
    expect(!r.ok && r.wwwAuthenticate).toBe(challenge('pca', 'invalid_pcactn'));
  });
  it('a broken delegation chain alone (tampered hop) is 401', async () => {
    const good = s.mk(s.plan[0]!);
    const hop = good.cap_chain[1]!;
    const tampered = [good.cap_chain[0]!, { ...hop, caveats: [...hop.caveats, { type: 'delegation_depth', max: 9 }] }];
    const r = await guard()(body(s.mk(s.plan[0]!, { extra: { cap_chain: tampered } })));
    expect(!r.ok && r.verdict.checks.cap_chain).toBe('fail');
    expect(!r.ok && r.verdict.checks.leaf_signature).not.toBe('fail');
    expect(!r.ok && r.status).toBe(401);
  });
  it('an internal verifier exception (only `malformed` reported) is 401', async () => {
    const r = await guard({ require: [], context: () => ({ plan: s.plan, planAuthorized: true, risk: s.lowRisk, params: { x: 1n } as never }) })(body(s.mk(s.plan[0]!)));
    expect(!r.ok && r.verdict.checks).toMatchObject({ malformed: 'fail' });
    expect(!r.ok && Object.entries(r.verdict.checks).filter(([, v]) => v === 'fail').map(([k]) => k)).toEqual(['malformed']);
    expect(!r.ok && r.status).toBe(401);
  });
  it('a policy denial (all authn checks pass) is 403 with no challenge', async () => {
    const n = { ...s.plan[0]!, verb: 'delete_account' };
    const r = await guard()(body(s.mk(n)));
    expect(r).toMatchObject({ ok: false, status: 403 });
    expect(!r.ok && r.wwwAuthenticate).toBeUndefined();
  });
  it('a PCActn with an empty cap_chain is 401 and does not crash the guard', async () => {
    for (const cap_chain of [[], undefined]) {
      const r = await guard()(body({ ...s.mk(s.plan[0]!), cap_chain }));
      expect(!r.ok && r.status).toBe(401);
      expect(!r.ok && r.verdict.reasons.join(' ')).not.toMatch(/guard error/);
    }
  });
});

describe('requirePCA: attestation option without any hooks', () => {
  it('builds the attestation hook even when `hooks` is absent (no guard error)', async () => {
    const r = await requirePCA({
      ...base(), insecureAllowUnenforced: true,
      attestation: { trustedAttestorKeys: [], resolveDocument: async () => null, expectedBinding: () => ({ holderPub: s.aPub, grantRef: s.grant.id, epoch: 0, nonce: 'n', nonceIssuedAt: NOW }) } as never,
    })(body(s.mk(s.plan[0]!)));
    expect(r.verdict.reasons.join(' ')).not.toMatch(/guard error/);
    expect(r.verdict.checks.attestation).toBeDefined();
    expect(r.verdict.checks.attestation).not.toBe('not-enforced');
  });
});

describe('requirePCA: differential for the redundant authn check names', () => {
  it('a wire failure always reports `malformed` too; a grant_ref mismatch always reports another authn check as well', async () => {
    const wire = await guard()(body({ ...s.mk(s.plan[0]!), extraneous: 1 }));
    expect(!wire.ok && wire.verdict.checks.wire).toBe('fail');
    expect(!wire.ok && wire.verdict.checks.malformed).toBe('fail');
    // grant_ref points to a different (resolvable) grant than the chain root: grant_ref, grant_ref_bound and cap_chain fail together
    const other = setup();
    const r = await requirePCA({ ...base(), resolveGrant: async () => other.grant, budgetStore: memoryPcaStore(), hooks: { revocation } })(body(s.mk(s.plan[0]!)));
    expect(!r.ok && r.status).toBe(401);
    expect(!r.ok && r.verdict.checks.cap_chain).toBe('fail');
    expect(!r.ok && r.verdict.checks.grant_ref).toBe('fail');
    // grant_ref resolves to the chain root's grant but the signed grant_ref is something else: grant_ref + grant_ref_bound fail, cap_chain passes
    const r2 = await requirePCA({ ...base(), resolveGrant: async () => s.grant, budgetStore: memoryPcaStore(), hooks: { revocation } })(body({ ...s.mk(s.plan[0]!, { extra: { grant_ref: other.grant.id } }) }));
    expect(!r2.ok && r2.status).toBe(401);
    expect(!r2.ok && r2.verdict.checks.cap_chain).toBe('pass');
    expect(!r2.ok && r2.verdict.checks.grant_ref).toBe('fail');
    expect(!r2.ok && r2.verdict.checks.grant_ref_bound).toBe('fail');
  });
});
