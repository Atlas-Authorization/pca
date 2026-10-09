import { describe, expect, it } from 'vitest';
import { createDevAttestor, attestationRegistry } from '../attestation';
import { issueLivenessBeacon, beaconRef } from '../beacons';
import { encodeKey, generateKeyPair } from '../keys';
import { encodePCActn } from '../pcactn';
import { signRevocationEpoch, RevocationSet, type RevocationEpoch } from '../revocation';
import { defaultExtract, memoryPcaStore, requirePCA } from './require-pca';
import { AUD, NOW, setup } from './fixture.test-util';

const b64u = (s: string) => Buffer.from(s).toString('base64url');

describe('requirePCA', () => {
  const s = setup();
  // The full default-deny profile: replay counter (budgetStore), revocation checker, authorized plan root.
  const revocation = () => ({ enforced: true, ok: true });
  const base = () => ({
    resolveGrant: async (ref: string) => (ref === s.grant.id ? s.grant : null),
    now: () => NOW, audience: AUD,
    context: () => ({ plan: s.plan, planAuthorized: true, risk: s.lowRisk }),
  });
  const guard = (extra = {}) => requirePCA({ ...base(), budgetStore: memoryPcaStore(), hooks: { revocation }, ...extra });

  it('401 + WWW-Authenticate when no PCActn', async () => {
    const r = await guard()({ headers: {} });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(401);
      expect(r.wwwAuthenticate).toMatch(/^PCA realm=/);
    }
  });

  it('wire v2: audience is REQUIRED config, a wrong audience / expired PCActn is denied', async () => {
    expect(() => requirePCA({ resolveGrant: async () => s.grant })).toThrow(/audience/);
    const a = s.mk(s.plan[0]!);
    const wrong = await guard({ audience: 'another-rs' })({ headers: {}, body: { pcactn: a } });
    expect(!wrong.ok && wrong.status).toBe(401);
    expect(!wrong.ok && wrong.verdict.checks.audience).toBe('fail');
    const late = await guard({ now: () => NOW + 700_000 })({ headers: {}, body: { pcactn: a } });
    expect(!late.ok && late.status).toBe(401);
    expect(!late.ok && late.verdict.checks.validity).toBe('fail');
    const strictJson = await guard()({ headers: { 'pca-action': b64u(encodePCActn(a).replace('"counter":1', '"counter":1.0')) } });
    expect(!strictJson.ok && strictJson.status).toBe(401);
  });

  it('401 on undecodable header', async () => {
    const r = await guard()({ headers: { 'pca-action': b64u('not json') } });
    expect(!r.ok && r.status).toBe(401);
  });

  it('401 on unknown grant', async () => {
    const a = { ...s.mk(s.plan[0]!), grant_ref: 'nope' };
    const r = await guard()({ headers: {}, body: { pcactn: a } });
    expect(!r.ok && r.status).toBe(401);
  });

  it('ok via header and via JSON body', async () => {
    const a = s.mk(s.plan[0]!);
    const h = await guard()({ headers: { 'pca-action': b64u(encodePCActn(a)) } });
    expect(h.ok).toBe(true);
    const b = await guard()({ headers: new Headers(), body: JSON.stringify({ pcactn: a }) });
    expect(b.ok).toBe(true);
  });

  it('403 on policy deny', async () => {
    const n = { ...s.plan[0]!, verb: 'delete_account' };
    const r = await guard()({ headers: {}, body: { pcactn: s.mk(n) } });
    expect(!r.ok && r.status).toBe(403);
  });

  it('401 on tampered signature', async () => {
    const r = await guard()({ headers: {}, body: { pcactn: { ...s.mk(s.plan[0]!), counter: 7 } } });
    expect(!r.ok && r.status).toBe(401);
  });

  it('replay is denied with a store; budget drains', async () => {
    const store = memoryPcaStore();
    const g = guard({ budgetStore: store });
    const a = s.mk(s.plan[0]!, { counter: 5 });
    expect((await g({ headers: {}, body: { pcactn: a } })).ok).toBe(true);
    const again = await g({ headers: {}, body: { pcactn: a } });
    expect(again.ok).toBe(false);
    if (!again.ok) expect(again.verdict.checks.counter).toBe('fail');
  });

  describe('default-deny enforcement profile (audit P0-4)', () => {
    const a = () => s.mk(s.plan[0]!);
    const req = () => ({ headers: {}, body: { pcactn: a() } });

    it('allows only when counter, revocation and plan_root_authorized are all ENFORCED', async () => {
      const r = await guard()(req());
      expect(r.ok).toBe(true);
      if (r.ok) expect(r.verdict.checks).toMatchObject({ counter: 'pass', revocation: 'pass', plan_root_authorized: 'pass' });
    });

    it.each([
      ['counter', { budgetStore: undefined }],
      ['revocation', { hooks: {} }],
      ['plan_root_authorized', { context: () => ({ plan: s.plan, risk: s.lowRisk }) }],
    ])('a required-but-not-enforced %s check DENIES (403)', async (check, extra) => {
      const r = await guard(extra)(req());
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.status).toBe(403);
        expect(r.verdict.checks[check]).toBe('fail');
        expect(r.verdict.reasons.join(' ')).toMatch(/default-deny/);
      }
    });

    it('an UNauthorized plan root (planAuthorized: false) is denied outright', async () => {
      const r = await guard({ context: () => ({ plan: s.plan, planAuthorized: false, risk: s.lowRisk }) })(req());
      expect(!r.ok && r.status).toBe(403);
      if (!r.ok) expect(r.verdict.checks.plan_root_authorized).toBe('fail');
    });

    it('`require` is configurable (minimum rung) and the opt-out is explicit and loudly named', async () => {
      const noStore = { budgetStore: undefined };
      expect((await guard({ ...noStore, require: ['revocation', 'plan_root_authorized'] })(req())).ok).toBe(true);
      expect((await guard({ ...noStore, require: ['counter'] })(req())).ok).toBe(false);
      expect((await guard({ ...noStore, hooks: {}, context: () => ({ risk: s.lowRisk }), insecureAllowUnenforced: true })(req())).ok).toBe(true);
    });

    it('resolves the principal into the verdict and can require a verified one', async () => {
      const verified = { pub: s.grant.issuer, subject_type: 'org' as const, subject_id: 'org_1', verified: true };
      const ok = await guard({ resolvePrincipal: async () => verified, requireVerifiedPrincipal: true })(req());
      expect(ok.ok).toBe(true);
      if (ok.ok) expect(ok.verdict.principal).toEqual(verified);

      const unknown = await guard({ resolvePrincipal: async () => null })(req());
      expect(unknown.ok).toBe(true);
      if (unknown.ok) expect(unknown.verdict.principal).toMatchObject({ pub: s.grant.issuer, verified: false, subject_type: 'unverified' });

      const denied = await guard({ resolvePrincipal: async () => null, requireVerifiedPrincipal: true })(req());
      expect(!denied.ok && denied.status).toBe(403);
      if (!denied.ok) expect(denied.verdict.checks.principal).toBe('fail');
      // requiring identity without a resolver cannot silently pass
      expect((await guard({ requireVerifiedPrincipal: true })(req())).ok).toBe(false);
    });
  });
  describe('signed revocation epoch (P2-3: freshness is enforced, no wire change)', () => {
    const G = generateKeyPair();
    const guardianPublic = encodeKey(G.publicKey);
    const mkEpoch = (epoch: number, o: { issued?: number; notAfter?: number } = {}): RevocationEpoch => {
      const set = new RevocationSet();
      const issued = o.issued ?? NOW;
      return signRevocationEpoch(G.secretKey, {
        instance_id: 'i', grant_ref: s.grant.id, epoch, set_size: set.size, root: set.root, issued_at: issued, not_after: o.notAfter ?? issued + 300_000,
      });
    };
    const req = (counter = 1) => ({ headers: {}, body: { pcactn: s.mk(s.plan[0]!, { counter }) } });
    const withEpoch = (e: RevocationEpoch | null, store = memoryPcaStore()) =>
      requirePCA({ ...base(), budgetStore: store, hooks: { revocation }, revocationEpoch: async () => (e ? { epoch: e, guardianPublic } : null) });

    it('passes a fresh signed epoch and reports freshness=pass', async () => {
      const r = await withEpoch(mkEpoch(0))(req());
      expect(r.ok).toBe(true);
      if (r.ok) expect(r.verdict.checks.freshness).toBe('pass');
    });

    it('is REQUIRED once an epoch source is configured: none available -> deny (default-deny)', async () => {
      const r = await withEpoch(null)(req());
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.verdict.checks.freshness).toBe('fail');
    });

    it('rejects an expired not_after, a forged signature, and an epoch newer than the action (stale pre-revocation action)', async () => {
      expect((await withEpoch(mkEpoch(0, { issued: NOW - 400_000, notAfter: NOW - 1 }))(req())).ok).toBe(false);
      expect((await withEpoch({ ...mkEpoch(0), epoch: 7 })(req())).ok).toBe(false); // body changed after signing
      const r = await withEpoch(mkEpoch(3))(req()); // action signed with freshness.epoch 0 < 3
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.verdict.reasons.join(' ')).toMatch(/predates/);
    });

    it('rejects an epoch older than the last one this verifier accepted (rollback)', async () => {
      const store = memoryPcaStore();
      await store.put(`${s.grant.id}:epoch`, { lastEpoch: 2 });
      const r = await withEpoch(mkEpoch(0), store)(req());
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.verdict.reasons.join(' ')).toMatch(/rollback/);
    });

    it('pins the accepted epoch number for later calls', async () => {
      const store = memoryPcaStore();
      expect((await withEpoch(mkEpoch(0), store)(req(1))).ok).toBe(true);
      expect((await store.get(`${s.grant.id}:epoch`))?.lastEpoch).toBe(0);
    });
  });

  describe('attestation: bound expectedBinding + require-when-bound (audit P4-1, finding 3)', () => {
    const att = createDevAttestor(generateKeyPair().secretKey);
    const sb = setup({ agentBinding: { operator: 'op' } });
    const NONCE = 'srv-nonce-1';
    const claims = (o: { holder?: string; epoch?: number; nonce?: string } = {}) => ({
      model_id: 'm', weights_digest: 'w', runtime_measurement: 'x', operator: 'op', nonce: NONCE,
      issued_at: NOW - 1000, expires_at: NOW + 60_000,
      holder_pub: o.holder ?? sb.aPub, grant_ref: sb.grant.id, epoch: o.epoch ?? 7, ...(o.nonce ? { nonce: o.nonce } : {}),
    });
    const guardFor = (doc?: ReturnType<typeof att.attest>, issuedAt = NOW - 1000, grant = sb.grant) =>
      requirePCA({
        resolveGrant: async () => grant,
        now: () => NOW, audience: AUD,
        context: () => ({ plan: sb.plan, planAuthorized: true, risk: sb.lowRisk }),
        budgetStore: memoryPcaStore(),
        hooks: { revocation },
        attestation: {
          trustedAttestorKeys: [att.publicKey],
          resolveDocument: attestationRegistry(doc ? [doc] : []),
          expectedBinding: (ctx) => ({
            holderPub: ctx.pcactn.cap_chain[ctx.pcactn.cap_chain.length - 1]!.holder,
            grantRef: sb.grant.id, epoch: 7, nonce: NONCE, nonceIssuedAt: issuedAt,
          }),
        },
      });
    const req = () => ({ headers: {}, body: { pcactn: sb.mk(sb.plan[0]!, { nonce: NONCE, attEpoch: 7 }) } });

    it('allows a bound attestation', async () => {
      const r = await guardFor(att.attest(claims()))(req());
      expect(r.ok).toBe(true);
      if (r.ok) expect(r.verdict.checks.attestation).toBe('pass');
    });
    it('denies a missing attestation when the grant binds the agent (require-when-bound), even with no attestation hook', async () => {
      const r = await guardFor(undefined)(req());
      expect(r.ok).toBe(false);
      const bare = await requirePCA({
        resolveGrant: async () => sb.grant, now: () => NOW, audience: AUD, budgetStore: memoryPcaStore(), hooks: { revocation },
        context: () => ({ plan: sb.plan, planAuthorized: true, risk: sb.lowRisk }),
      })(req());
      expect(bare.ok).toBe(false);
      if (!bare.ok) expect(bare.verdict.checks.attestation).toBe('fail');
    });
    it('denies a relayed document bound to another holder / epoch / nonce', async () => {
      for (const o of [{ holder: encodeKey(generateKeyPair().publicKey) }, { epoch: 8 }, { nonce: 'other' }]) {
        expect((await guardFor(att.attest(claims(o)))(req())).ok).toBe(false);
      }
    });
    it('freshness comes from the server nonce issue time, not the document dates', async () => {
      const spoofed = att.attest({ ...claims(), issued_at: NOW - 10, expires_at: NOW + 10_000_000 });
      expect((await guardFor(spoofed, NOW - 3_600_000)(req())).ok).toBe(false);
    });
    it('an unbound grant keeps attestation optional', async () => {
      const r = await guard()({ headers: {}, body: { pcactn: s.mk(s.plan[0]!) } });
      expect(r.ok).toBe(true);
    });
  });
  describe('dead-man liveness beacon (P2-4)', () => {
    const P = generateKeyPair();
    const issuer = encodeKey(P.publicKey);
    const mkB = (o: { seq?: number; issuedAt?: number; validityMs?: number; instance?: string } = {}) =>
      issueLivenessBeacon({ issuerSecret: P.secretKey, instance: o.instance ?? 'ins_1', scope: s.grant.id, seq: o.seq ?? 1, issuedAt: o.issuedAt ?? NOW, validityMs: o.validityMs });
    const reqB = (b: ReturnType<typeof mkB> | null, counter = 1) => ({
      headers: {},
      body: { pcactn: s.mk(s.plan[0]!, { counter, beaconRef: b ? beaconRef(b) : '' }) },
    });
    const withB = (b: ReturnType<typeof mkB> | null, store = memoryPcaStore()) =>
      requirePCA({ ...base(), budgetStore: store, hooks: { revocation }, beacon: async () => (b ? { beacon: b, issuers: [issuer], instance: 'ins_1' } : null) });

    it('passes a fresh bound beacon', async () => {
      const b = mkB();
      const r = await withB(b)(reqB(b));
      expect(r.ok).toBe(true);
      if (r.ok) expect(r.verdict.checks.beacon).toBe('pass');
    });
    it('absent beacon source => DENY (fail closed)', async () => {
      const r = await withB(null)(reqB(null));
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.verdict.checks.beacon).toBe('fail');
    });
    it('stale beacon (principal stopped issuing) => DENY', async () => {
      const b = mkB({ issuedAt: NOW - 600_000, validityMs: 60_000 });
      expect((await withB(b)(reqB(b))).ok).toBe(false);
    });
    it('an action that does not commit the beacon (freshness.beacon_ref) is denied', async () => {
      expect((await withB(mkB())(reqB(null))).ok).toBe(false);
    });
    it('rejects a beacon from an unpinned issuer and one for another instance', async () => {
      const rogue = issueLivenessBeacon({ issuerSecret: generateKeyPair().secretKey, instance: 'ins_1', scope: s.grant.id, seq: 1, issuedAt: NOW });
      expect((await withB(rogue)(reqB(rogue))).ok).toBe(false);
      const wrong = mkB({ instance: 'ins_2' });
      expect((await withB(wrong)(reqB(wrong))).ok).toBe(false);
    });
    it('rolling back to an older seq than the last accepted is denied', async () => {
      const store = memoryPcaStore();
      const b5 = mkB({ seq: 5 });
      expect((await withB(b5, store)(reqB(b5, 1))).ok).toBe(true);
      const b4 = mkB({ seq: 4 });
      expect((await withB(b4, store)(reqB(b4, 2))).ok).toBe(false);
    });
  });
});

describe('defaultExtract: PCA-Action header lookup is case-insensitive and unambiguous', () => {
  const payload = '{"cap_chain":[]}';
  const enc = Buffer.from(payload).toString('base64url');
  const req = (headers: unknown, body?: unknown) => ({ headers, body }) as unknown as Parameters<typeof defaultExtract>[0];

  it('finds the header under any case on a plain object (what pcaHeaders() emits, and what Node lowercases to)', () => {
    for (const name of ['PCA-Action', 'pca-action', 'PCA-ACTION', 'Pca-Action']) {
      expect(defaultExtract(req({ [name]: enc }))).toBe(payload);
    }
  });

  it('takes the first value of an array header and works with a Headers instance', () => {
    expect(defaultExtract(req({ 'PCA-Action': [enc, 'ignored'] }))).toBe(payload);
    expect(defaultExtract(req(new Headers({ 'PCA-Action': enc })))).toBe(payload);
  });

  it('identical duplicates in different cases are accepted; DIFFERENT values are ambiguous and treated as absent', () => {
    expect(defaultExtract(req({ 'PCA-Action': enc, 'pca-action': enc }))).toBe(payload);
    const other = Buffer.from('{"cap_chain":[1]}').toString('base64url');
    expect(defaultExtract(req({ 'PCA-Action': enc, 'pca-action': other }))).toBeNull();
  });

  it('never matches an inherited property, and ignores non-string values', () => {
    const inherited = Object.create({ 'pca-action': enc }) as Record<string, string>;
    expect(defaultExtract(req(inherited))).toBeNull();
    expect(defaultExtract(req({ 'PCA-Action': 42 }))).toBeNull();
    expect(defaultExtract(req({ 'PCA-Action': undefined }))).toBeNull();
  });

  it('an ambiguous header does not fall through to authenticating something else: with no body the result is absent', () => {
    expect(defaultExtract(req({ 'PCA-Action': enc, 'pca-action': 'AAAA' }))).toBeNull();
  });
});

