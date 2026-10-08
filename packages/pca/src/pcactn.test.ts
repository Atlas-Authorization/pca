import { describe, expect, it } from 'vitest';
import { attenuate, delegate, mintRoot } from './capability';
import { encodeKey, generateKeyPair } from './keys';
import { commitPlan, conditionsDigest, paramsDigest } from './merkle';
import {
  type PCActn,
  type PCActnBody,
  PCACTN_MAX_LIFETIME_MS,
  PCACTN_MAX_SKEW_MS,
  buildPCActn,
  decodePCActn,
  encodePCActn,
  notEnforced,
  pcactnDigest,
  signPCActn,
  verifyPCActnCore,
} from './pcactn';
import { BEACON_EPOCH_MS } from './beacons';
import { InMemoryTrustedInputRegistry } from './taint';
import { attestationRegistry, createAttestationVerifier, createDevAttestor } from './attestation';
import { type AgentBinding, mintGrant } from './envelope';
import { DEFAULT_RISK_POLICY } from './risk';

const NOW = 1_800_000_000_000;

function build() {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const S = generateKeyPair();
  const grant = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), caveats: [{ type: 'ttl', secs: 60 }] });
  const c1 = attenuate(grant, [{ type: 'x' }], A.secretKey);
  const sub = delegate(c1, encodeKey(S.publicKey), [], A.secretKey);
  const nodes = [
    { id: 'n1', verb: 'revoke_session', resource: 'sess/1', params_digest: paramsDigest({ a: 1 }), reversibility_class: 'R1', pre: { a: 1 } },
    { id: 'n2', verb: 'read', resource: 'acct', params_digest: paramsDigest({ b: 2 }), reversibility_class: 'R0' },
  ];
  const plan = commitPlan(nodes);
  const mk = (idx: 0 | 1): PCActn => {
    const n = nodes[idx]!;
    return signPCActn(
      {
        ver: 2,
        action: { verb: n.verb, resource: n.resource, params_digest: n.params_digest, reversibility_class: n.reversibility_class },
        grant_ref: grant.id,
        cap_chain: [grant, c1, sub],
        plan: { root: plan.root, inclusion_proof: plan.proofFor(n.id), node_id: n.id, conditions_digest: conditionsDigest(n.pre, undefined) },
        attestation: { quote_digest: 'q', epoch: 1, model_id: 'm', measurement: 'x', operator: 'o' },
        provenance: { causal_hash: 'c', taint_level: 0, trusted_refs: [] },
        freshness: { beacon_ref: 'b', epoch: 1, accumulator_witness: 'w' },
        counter: 7,
        risk_claim: { r: 0.1, inputs: {} },
        aud: 'rs-1',
        iat: NOW,
        exp: NOW + 60_000,
      },
      S.secretKey,
    );
  };
  return { grant, S, A, mk, nodes };
}

describe('verifyPCActnCore', () => {
  it('well-formed PCActn is allowed; later checks are not-enforced', async () => {
    const { grant, mk } = build();
    const r = await verifyPCActnCore(mk(0), { grant, nowEpoch: NOW, audience: 'rs-1' });
    expect(r.allow).toBe(true);
    expect(r.checks).toMatchObject({ wire: 'pass', version: 'pass', audience: 'pass', validity: 'pass', cap_chain: 'pass', plan_inclusion: 'pass', leaf_signature: 'pass', counter: 'pass', attestation: 'not-enforced', threshold: 'not-enforced', revocation: 'not-enforced' });
  });
  it('tampered action breaks plan inclusion (and signature)', async () => {
    const { grant, mk } = build();
    const p = mk(0);
    p.action = { ...p.action, resource: 'sess/ALL' };
    const r = await verifyPCActnCore(p, { grant, nowEpoch: NOW });
    expect(r.allow).toBe(false);
    expect(r.checks.plan_inclusion).toBe('fail');
    expect(r.checks.leaf_signature).toBe('fail');
  });
  it('out-of-plan action fails even when freshly signed', async () => {
    const { grant, mk, S } = build();
    const p = mk(0);
    const { sig: _s, ...body } = { ...p, action: { ...p.action, verb: 'wire_money' } };
    const r = await verifyPCActnCore(signPCActn(body, S.secretKey), { grant, nowEpoch: NOW });
    expect(r.allow).toBe(false);
    expect(r.checks.plan_inclusion).toBe('fail');
    expect(r.checks.leaf_signature).toBe('pass');
  });
  it('wrong-key body signature fails', async () => {
    const { grant, mk } = build();
    const p = mk(1);
    const { sig: _s, ...body } = p;
    const r = await verifyPCActnCore(signPCActn(body, generateKeyPair().secretKey), { grant, nowEpoch: NOW });
    expect(r.allow).toBe(false);
    expect(r.checks.leaf_signature).toBe('fail');
  });
  it('chain not rooted at the supplied grant fails', async () => {
    const { mk } = build();
    const other = build();
    const r = await verifyPCActnCore(mk(0), { grant: other.grant, nowEpoch: NOW });
    expect(r.allow).toBe(false);
    expect(r.checks.cap_chain).toBe('fail');
  });
  it('bad counter fails; enforced hook can reject; malformed does not throw', async () => {
    const { grant, mk, S } = build();
    const { sig: _s, ...body } = mk(0);
    const neg = signPCActn({ ...body, counter: -1 }, S.secretKey);
    expect((await verifyPCActnCore(neg, { grant, nowEpoch: NOW })).checks.counter).toBe('fail');
    const bad = signPCActn({ ...body, counter: 'x' as unknown as number }, S.secretKey);
    expect((await verifyPCActnCore(bad, { grant, nowEpoch: NOW })).checks.wire).toBe('fail');
    const r = await verifyPCActnCore(mk(0), { grant, nowEpoch: NOW, audience: 'rs-1', hooks: { revocation: () => ({ enforced: true, ok: false, reason: 'revoked' }) } });
    expect(r.allow).toBe(false);
    expect(r.reason).toMatch(/revoked/);
    const m = await verifyPCActnCore({} as PCActn, { grant, nowEpoch: NOW });
    expect(m.allow).toBe(false);
  });
  it('encode/decode roundtrip and digest stable', async () => {
    const { grant, mk } = build();
    const p = mk(0);
    const q = decodePCActn(encodePCActn(p));
    expect(pcactnDigest(q)).toBe(pcactnDigest(p));
    expect((await verifyPCActnCore(q, { grant, nowEpoch: NOW, audience: 'rs-1' })).allow).toBe(true);
  });

  it('wire v2: ver 1 is rejected (version), unknown/missing fields are a wire failure', async () => {
    const { grant, mk, S } = build();
    const { sig: _s, ...body } = mk(0);
    const v1 = signPCActn({ ...body, ver: 1 }, S.secretKey);
    const r1 = await verifyPCActnCore(v1, { grant, nowEpoch: NOW });
    expect(r1.allow).toBe(false);
    expect(r1.checks.version).toBe('fail');
    const { aud: _a, ...noAud } = body;
    const r2 = await verifyPCActnCore(signPCActn(noAud as never, S.secretKey), { grant, nowEpoch: NOW });
    expect(r2.checks).toEqual({ wire: 'fail' });
    const r3 = await verifyPCActnCore(signPCActn({ ...body, extra: 1 } as never, S.secretKey), { grant, nowEpoch: NOW });
    expect(r3.checks).toEqual({ wire: 'fail' });
  });

  it('freshness binding: audience mismatch, expiry, future iat, lifetime and exp<=iat are rejected', async () => {
    const { grant, mk, S } = build();
    const p = mk(0);
    expect((await verifyPCActnCore(p, { grant, nowEpoch: NOW, audience: 'other-rs' })).checks.audience).toBe('fail');
    // FAIL-CLOSED: a signed aud + no verifier audience is a failure (was 'not-enforced')...
    expect((await verifyPCActnCore(p, { grant, nowEpoch: NOW })).checks.audience).toBe('fail');
    // ...unless the caller explicitly opts out with audience: null.
    expect((await verifyPCActnCore(p, { grant, nowEpoch: NOW, audience: null })).checks.audience).toBe('not-enforced');
    expect((await verifyPCActnCore(p, { grant, nowEpoch: NOW + 60_000 })).checks.validity).toBe('pass'); // == exp
    expect((await verifyPCActnCore(p, { grant, nowEpoch: NOW + 60_001 })).checks.validity).toBe('fail');
    expect((await verifyPCActnCore(p, { grant, nowEpoch: NOW - PCACTN_MAX_SKEW_MS })).checks.validity).toBe('pass');
    expect((await verifyPCActnCore(p, { grant, nowEpoch: NOW - PCACTN_MAX_SKEW_MS - 1 })).checks.validity).toBe('fail');
    const { sig: _s, ...body } = p;
    const long = signPCActn({ ...body, exp: NOW + PCACTN_MAX_LIFETIME_MS + 1 }, S.secretKey);
    expect((await verifyPCActnCore(long, { grant, nowEpoch: NOW })).checks.validity).toBe('fail');
    const inv = signPCActn({ ...body, exp: NOW }, S.secretKey);
    expect((await verifyPCActnCore(inv, { grant, nowEpoch: NOW })).checks.validity).toBe('fail');
    // aud / iat / exp are SIGNED: editing them without re-signing breaks the leaf signature
    const tampered = { ...p, exp: p.exp + 1000 };
    expect((await verifyPCActnCore(tampered, { grant, nowEpoch: NOW })).checks.leaf_signature).toBe('fail');
  });

  it('optional slots are signed when present and absent => unchanged', async () => {
    const { grant, mk, S } = build();
    const p = mk(0);
    const { sig: _s, ...body } = p;
    const withSlots = signPCActn({ ...body, caution: 0.4, nonce: 'n-1', tool_binding: paramsDigest({ t: 1 }), rationale_commitment: paramsDigest({ r: 1 }), progress_step: { k: 1 }, prohibition_evidence: [] }, S.secretKey);
    expect((await verifyPCActnCore(withSlots, { grant, nowEpoch: NOW, audience: 'rs-1' })).allow).toBe(true);
    expect((await verifyPCActnCore({ ...withSlots, caution: 0.1 }, { grant, nowEpoch: NOW })).checks.leaf_signature).toBe('fail');
    expect((await verifyPCActnCore({ ...withSlots, caution: 2 }, { grant, nowEpoch: NOW })).checks.wire).toBe('fail');
  });

  it('aud fail-closed: signed aud needs a verifier audience (or an explicit null opt-out)', async () => {
    const { grant, mk, S } = build();
    const p = mk(0); // carries a signed aud = 'rs-1'
    // (a) signed aud + undefined (unsupplied) audience => FAIL (was silently 'not-enforced')
    const a = await verifyPCActnCore(p, { grant, nowEpoch: NOW });
    expect(a.checks.audience).toBe('fail');
    expect(a.allow).toBe(false);
    expect(a.reason).toMatch(/audience/);
    // (b) signed aud + explicit null => deliberate opt-out => not-enforced, allowed
    const b = await verifyPCActnCore(p, { grant, nowEpoch: NOW, audience: null });
    expect(b.checks.audience).toBe('not-enforced');
    expect(b.allow).toBe(true);
    // (c) signed aud + matching audience => pass (and a non-matching one still fails)
    const c = await verifyPCActnCore(p, { grant, nowEpoch: NOW, audience: 'rs-1' });
    expect(c.checks.audience).toBe('pass');
    expect(c.allow).toBe(true);
    expect((await verifyPCActnCore(p, { grant, nowEpoch: NOW, audience: 'other' })).checks.audience).toBe('fail');
    // (d) no aud at all => UNCHANGED: the wire check rejects a missing aud before the audience branch
    // runs, so the fail-closed logic does not alter that path.
    const { sig: _s, aud: _aud, ...noAud } = p;
    const d = await verifyPCActnCore(signPCActn(noAud as never, S.secretKey), { grant, nowEpoch: NOW });
    expect(d.checks).toEqual({ wire: 'fail' });
  });

  it('buildPCActn stamps aud/iat/exp (and requires aud)', () => {
    const P = generateKeyPair();
    const A = generateKeyPair();
    const grant = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), caveats: [] });
    const plan = [{ id: 'n1', verb: 'v', resource: 'r' }];
    const base = { grant, chain: [grant], plan, nodeId: 'n1', counter: 1, signerSecret: A.secretKey };
    expect(() => buildPCActn(base as never)).toThrow(/aud/);
    const p = buildPCActn({ ...base, aud: 'x', now: NOW, ttlMs: 1000, nonce: 'abc' });
    expect([p.ver, p.aud, p.iat, p.exp, p.nonce]).toEqual([2, 'x', NOW, NOW + 1000, 'abc']);
  });
});

// A re-sign helper: edit SIGNED fields (provenance / freshness) and re-sign under S.
function resigner(b: { S: { secretKey: Uint8Array }; body: PCActnBody }) {
  return (over: Partial<PCActnBody>): PCActn => signPCActn({ ...b.body, ...over }, b.S.secretKey);
}

describe('verifyPCActnCore — M1 taint gate (enforce.taint)', () => {
  const common = { nowEpoch: NOW, audience: 'rs-1' as const };
  it('gated OFF by default: taint_gate stays not-enforced (unchanged behaviour)', async () => {
    const { grant, mk } = build();
    const r = await verifyPCActnCore(mk(0), { grant, ...common });
    expect(r.allow).toBe(true);
    expect(r.checks.taint_gate).toBe('not-enforced');
  });
  it('gated ON: server-verified-trusted lineage passes at maxTaint 0', async () => {
    const { grant, S, mk } = build();
    const resign = resigner({ S, body: (() => { const { sig: _s, ...body } = mk(0); return body; })() });
    const registry = new InMemoryTrustedInputRegistry().recordTrusted('ref-x');
    const p = resign({ provenance: { causal_hash: 'c', taint_level: 0, trusted_refs: ['ref-x'] } });
    const r = await verifyPCActnCore(p, { grant, ...common, enforce: { taint: { ctx: { registry }, maxTaint: 0 } } });
    expect(r.checks.taint_gate).toBe('pass');
    expect(r.allow).toBe(true);
  });
  it('gated ON: an agent CANNOT forge low taint — a ref the server cannot vouch for is denied', async () => {
    const { grant, S, mk } = build();
    const resign = resigner({ S, body: (() => { const { sig: _s, ...body } = mk(0); return body; })() });
    const registry = new InMemoryTrustedInputRegistry().recordTrusted('ref-x'); // 'ref-y' is NOT vouched
    const p = resign({ provenance: { causal_hash: 'c', taint_level: 0, trusted_refs: ['ref-y'] } });
    const r = await verifyPCActnCore(p, { grant, ...common, enforce: { taint: { ctx: { registry }, maxTaint: 0.25 } } });
    expect(r.checks.taint_gate).toBe('fail');
    expect(r.allow).toBe(false);
    expect(r.reason).toMatch(/taint/);
  });
  it('gated ON: an empty-lineage stub fails closed to worst-case taint 1', async () => {
    const { grant, mk } = build(); // mk(0) provenance.trusted_refs === []
    const registry = new InMemoryTrustedInputRegistry();
    const r = await verifyPCActnCore(mk(0), { grant, ...common, enforce: { taint: { ctx: { registry }, maxTaint: 0.5 } } });
    expect(r.checks.taint_gate).toBe('fail');
    expect(r.allow).toBe(false);
  });
});

describe('verifyPCActnCore — M3 freshness gate (enforce.freshness)', () => {
  const common = { nowEpoch: NOW, audience: 'rs-1' as const };
  const FRESH_EPOCH = Math.floor(NOW / BEACON_EPOCH_MS); // anchor == NOW
  const freshFor = (epoch: number) => ({ beacon_ref: 'b', epoch, accumulator_witness: 'w' });
  it('gated OFF by default: no freshness check is emitted (byte-identical output)', async () => {
    const { grant, mk } = build();
    const r = await verifyPCActnCore(mk(0), { grant, ...common });
    expect(r.allow).toBe(true);
    expect(r.checks.freshness).toBeUndefined();
  });
  it('gated ON: a fresh anchor passes', async () => {
    const { grant, S, mk } = build();
    const resign = resigner({ S, body: (() => { const { sig: _s, ...body } = mk(0); return body; })() });
    const p = resign({ freshness: freshFor(FRESH_EPOCH) });
    const r = await verifyPCActnCore(p, { grant, ...common, enforce: { freshness: { maxAgeMs: 5 * BEACON_EPOCH_MS } } });
    expect(r.checks.freshness).toBe('pass');
    expect(r.allow).toBe(true);
  });
  it('gated ON: a stale anchor is rejected with a specific reason', async () => {
    const { grant, mk } = build(); // mk(0).freshness.epoch === 1 => anchor at ~1970 => very stale
    const r = await verifyPCActnCore(mk(0), { grant, ...common, enforce: { freshness: { maxAgeMs: 5 * BEACON_EPOCH_MS } } });
    expect(r.checks.freshness).toBe('fail');
    expect(r.allow).toBe(false);
    expect(r.reason).toMatch(/stale/);
  });
  it('gated ON: an empty/stub anchor (buildPCActn default) is rejected as missing', async () => {
    const { grant, S, mk } = build();
    const resign = resigner({ S, body: (() => { const { sig: _s, ...body } = mk(0); return body; })() });
    const p = resign({ freshness: { beacon_ref: '', epoch: 0, accumulator_witness: '' } });
    const r = await verifyPCActnCore(p, { grant, ...common, enforce: { freshness: { maxAgeMs: 5 * BEACON_EPOCH_MS } } });
    expect(r.checks.freshness).toBe('fail');
    expect(r.reason).toMatch(/missing/);
  });
  it('gated ON: an anchor in the future is rejected', async () => {
    const { grant, S, mk } = build();
    const resign = resigner({ S, body: (() => { const { sig: _s, ...body } = mk(0); return body; })() });
    const p = resign({ freshness: freshFor(FRESH_EPOCH) });
    const r = await verifyPCActnCore(p, { grant, ...common, enforce: { freshness: { maxAgeMs: 5 * BEACON_EPOCH_MS, now: NOW - 10 * BEACON_EPOCH_MS } } });
    expect(r.checks.freshness).toBe('fail');
    expect(r.reason).toMatch(/future/);
  });
});

describe('verifyPCActnCore — M5 TEE attestation gate (enforce.attestation)', () => {
  const T = 1_000_000;
  const P = generateKeyPair();
  const A = generateKeyPair();
  const HOLDER = encodeKey(A.publicKey);
  const NONCE = 'nonce-epoch-1';
  const binding: AgentBinding = { model_allowlist: ['gpt-x'], min_measurement: 'm1', operator: 'acme', weights_allowlist: ['w1'] };
  const grant = mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: HOLDER,
    goal: 'secure my account',
    envelope: { predicates: [{ verb: 'read', resource: '/acct/*' }], caveats: [], agent_binding: binding, risk_policy: DEFAULT_RISK_POLICY },
  }).grant;
  const attested = (): PCActn =>
    buildPCActn({
      aud: 'rs-m5',
      grant,
      chain: [grant],
      plan: [{ id: 'n1', verb: 'read', resource: '/acct/1', reversibility_class: 'reversible' }],
      nodeId: 'n1',
      counter: 1,
      signerSecret: A.secretKey,
      now: T,
      attestation: { quote_digest: NONCE, epoch: 1, model_id: 'gpt-x', measurement: 'm1', operator: 'acme' },
    });
  const CLAIMS = { model_id: 'gpt-x', weights_digest: 'w1', runtime_measurement: 'm1', operator: 'acme', nonce: NONCE, issued_at: T - 1000, expires_at: T + 60_000 };
  const expectedBinding = () => ({ holderPub: HOLDER, grantRef: grant.id, epoch: 1, nonce: NONCE, nonceIssuedAt: T - 1000 });
  const common = { grant, nowEpoch: T, audience: 'rs-m5' as const };
  const attestor = createDevAttestor(generateKeyPair().secretKey);
  const doc = attestor.attest({ ...CLAIMS, holder_pub: HOLDER, grant_ref: grant.id, epoch: 1 });
  const realVerifier = createAttestationVerifier({ trustedAttestorKeys: [attestor.publicKey], resolveDocument: attestationRegistry([doc]), expectedBinding, now: () => T });

  it('gated OFF by default: attestation stays not-enforced and the action is allowed', async () => {
    const r = await verifyPCActnCore(attested(), common);
    expect(r.checks.attestation).toBe('not-enforced');
    expect(r.allow).toBe(true);
  });
  it('gated ON: a VALID bound attestation passes', async () => {
    const r = await verifyPCActnCore(attested(), { ...common, enforce: { attestation: { verifier: realVerifier } } });
    expect(r.checks.attestation).toBe('pass');
    expect(r.allow).toBe(true);
  });
  it('gated ON: an untrusted-attestor document is rejected (fail closed)', async () => {
    const rogue = createAttestationVerifier({
      trustedAttestorKeys: [createDevAttestor(generateKeyPair().secretKey).publicKey],
      resolveDocument: attestationRegistry([doc]),
      expectedBinding,
      now: () => T,
    });
    const r = await verifyPCActnCore(attested(), { ...common, enforce: { attestation: { verifier: rogue } } });
    expect(r.checks.attestation).toBe('fail');
    expect(r.allow).toBe(false);
  });
  it('gated ON: an absent attestation document is rejected (fail closed)', async () => {
    const empty = createAttestationVerifier({ trustedAttestorKeys: [attestor.publicKey], resolveDocument: attestationRegistry([]), expectedBinding, now: () => T });
    const r = await verifyPCActnCore(attested(), { ...common, enforce: { attestation: { verifier: empty } } });
    expect(r.checks.attestation).toBe('fail');
    expect(r.allow).toBe(false);
  });
  it('gated ON + required (default): a verifier that reports not-enforced fails closed', async () => {
    const r = await verifyPCActnCore(attested(), { ...common, enforce: { attestation: { verifier: notEnforced } } });
    expect(r.checks.attestation).toBe('fail');
    expect(r.allow).toBe(false);
    expect(r.reason).toMatch(/attestation required/);
  });
  it('gated ON + required:false: a not-enforced result is tolerated (explicit opt-out)', async () => {
    const r = await verifyPCActnCore(attested(), { ...common, enforce: { attestation: { verifier: notEnforced, required: false } } });
    expect(r.checks.attestation).toBe('not-enforced');
    expect(r.allow).toBe(true);
  });
});
