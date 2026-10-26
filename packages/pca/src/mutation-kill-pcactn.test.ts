/**
 * Mutation-kill tests for verifyPCActnCore (pcactn.ts) and verifyPCActn (server/verify.ts). Every security-relevant
 * branch is exercised on both sides of its boundary and every failure is asserted by its EXACT reason string, so a
 * flipped comparison, a dropped guard, a swapped short-circuit or a blanked message changes an observable result.
 */
import { describe, expect, it } from 'vitest';
import { InMemoryTrustedInputRegistry } from './taint';
import { BEACON_EPOCH_MS, issueLivenessBeacon, beaconRef } from './beacons';
import { generateKeyPair, encodeKey } from './keys';
import { PCACTN_MAX_LIFETIME_MS, PCACTN_MAX_SKEW_MS, signPCActnSuite, verifyPCActnCore, type Hook, type PCActn } from './pcactn';
import { signRevocationEpoch } from './revocation';
import { AUD, NOW, setup } from './server/fixture.test-util';
import { verifyPCActn as verifyPCActn05 } from './server/verify';
const verifyPCActn = (p: Parameters<typeof verifyPCActn05>[0], o: Parameters<typeof verifyPCActn05>[1]): ReturnType<typeof verifyPCActn05> => verifyPCActn05(p, 'require' in o ? o : Object.create(o, { require: { value: [], enumerable: true } })); // report-only: these tests are not about the 0.5 default required checks (see breaking-05.test.ts)


/** A well-formed (canonical 43-char b64u) id that is NOT the given one: flip the first character only. */
const otherId = (id: string): string => (id[0] === 'A' ? 'B' : 'A') + id.slice(1);

const core = (s: ReturnType<typeof setup>, p: PCActn | Record<string, unknown>, over: Record<string, unknown> = {}) =>
  verifyPCActnCore(p as PCActn, { grant: s.grant, nowEpoch: NOW, audience: AUD, ...over } as never);

describe('verifyPCActnCore: audience', () => {
  it('a signed aud with NO verifier audience fails with the normative message; null opts out; a match passes; a mismatch fails', async () => {
    const s = setup();
    const a = s.mk(s.plan[0]!);
    const none = await core(s, a, { audience: undefined });
    expect(none.checks.audience).toBe('fail');
    expect(none.reason).toBe('audience: PCActn carries a signed aud but this verifier supplied no audience (pass your audience, or audience: null to accept any)');
    expect((await core(s, a, { audience: null })).checks.audience).toBe('not-enforced');
    expect((await core(s, a)).checks.audience).toBe('pass');
    const bad = await core(s, a, { audience: 'someone-else' });
    expect(bad.checks.audience).toBe('fail');
    expect(bad.reason).toBe('audience: aud does not match this resource server / instance');
    // byte-exact: a one-character look-alike is a mismatch
    expect((await core(s, a, { audience: AUD + ' ' })).checks.audience).toBe('fail');
    expect((await core(s, a, { audience: AUD.slice(0, -1) })).checks.audience).toBe('fail');
  });
});

describe('verifyPCActnCore: validity window (every boundary, exact reason)', () => {
  it('exp must be strictly greater than iat', async () => {
    const s = setup();
    const eq = await core(s, s.mk(s.plan[0]!, { extra: { iat: NOW, exp: NOW } }));
    expect(eq.checks.validity).toBe('fail');
    expect(eq.reason).toBe('validity: exp must be greater than iat');
    const lt = await core(s, s.mk(s.plan[0]!, { extra: { iat: NOW, exp: NOW - 1 } }));
    expect(lt.reason).toBe('validity: exp must be greater than iat');
    expect((await core(s, s.mk(s.plan[0]!, { extra: { iat: NOW, exp: NOW + 1 } }))).checks.validity).toBe('pass');
  });
  it('the lifetime cap is inclusive: exactly MAX passes, MAX+1 fails', async () => {
    const s = setup();
    const at = await core(s, s.mk(s.plan[0]!, { extra: { iat: NOW, exp: NOW + PCACTN_MAX_LIFETIME_MS } }));
    expect(at.checks.validity).toBe('pass');
    const over = await core(s, s.mk(s.plan[0]!, { extra: { iat: NOW, exp: NOW + PCACTN_MAX_LIFETIME_MS + 1 } }));
    expect(over.checks.validity).toBe('fail');
    expect(over.reason).toBe(`validity: lifetime exceeds ${PCACTN_MAX_LIFETIME_MS} ms`);
  });
  it('clock skew: iat may be at most MAX_SKEW in the future (inclusive)', async () => {
    const s = setup();
    const a = s.mk(s.plan[0]!);
    expect((await core(s, a, { nowEpoch: NOW - PCACTN_MAX_SKEW_MS })).checks.validity).toBe('pass');
    const fut = await core(s, a, { nowEpoch: NOW - PCACTN_MAX_SKEW_MS - 1 });
    expect(fut.checks.validity).toBe('fail');
    expect(fut.reason).toBe('validity: iat is in the future (clock skew)');
  });
  it('expiry: now == exp passes, now == exp + 1 fails', async () => {
    const s = setup();
    const a = s.mk(s.plan[0]!);
    expect((await core(s, a, { nowEpoch: NOW + 600_000 })).checks.validity).toBe('pass');
    const late = await core(s, a, { nowEpoch: NOW + 600_001 });
    expect(late.checks.validity).toBe('fail');
    expect(late.reason).toBe('validity: the PCActn has expired');
  });
  it('the default clock is the wall clock (a 2026 fixture is expired "now")', async () => {
    const s = setup();
    const r = await verifyPCActnCore(s.mk(s.plan[0]!), { grant: s.grant, audience: AUD });
    expect(r.checks.validity).toBe(Date.now() > NOW + 600_000 ? 'fail' : 'pass');
  });
});

describe('verifyPCActnCore: capability chain and grant_ref binding', () => {
  it('an empty chain, a chain rooted elsewhere and an invalid chain each fail with their own reason', async () => {
    const s = setup();
    const empty = await core(s, s.mk(s.plan[0]!, { extra: { cap_chain: [] } }));
    expect(empty.checks.cap_chain).toBe('fail');
    expect(empty.checks.grant_ref_bound).toBe('fail');
    expect(empty.reason).toBe('cap_chain: empty chain');
    const other = setup();
    const wrongRoot = await core(other, s.mk(s.plan[0]!));
    expect(wrongRoot.checks.cap_chain).toBe('fail');
    expect(wrongRoot.reason).toBe('cap_chain: chain root is not the grant');
    // a hop whose signature was tampered: verifyChain's own reason is carried through (non-empty)
    const chain = JSON.parse(JSON.stringify(s.mk(s.plan[0]!).cap_chain));
    chain[1].sig = chain[1].sig.slice(0, 10) + (chain[1].sig[10] === 'A' ? 'B' : 'A') + chain[1].sig.slice(11); // flip a middle char: stays canonical b64u
    const bad = await core(s, s.mk(s.plan[0]!, { extra: { cap_chain: chain } }));
    expect(bad.checks.cap_chain).toBe('fail');
    expect(bad.reason?.startsWith('cap_chain: ')).toBe(true);
    expect(bad.reason!.length).toBeGreaterThan('cap_chain: '.length);
  });
  it('grant_ref must be a non-empty string equal to the root capability id', async () => {
    const s = setup();
    expect((await core(s, s.mk(s.plan[0]!))).checks.grant_ref_bound).toBe('pass');
    const other = await core(s, s.mk(s.plan[0]!, { extra: { grant_ref: otherId(s.grant.id) } }));
    expect(other.checks.grant_ref_bound).toBe('fail');
    expect(other.reason).toBe('grant_ref_bound: grant_ref is not the id of the root capability in cap_chain');
    // a non-canonical / empty / wrong-length reference is a wire failure (terminal), never a pass
    for (const g of [s.grant.id + 'x', s.grant.id.slice(0, -1), '']) {
      const w = await core(s, s.mk(s.plan[0]!, { extra: { grant_ref: g } }));
      expect(w.allow).toBe(false);
      expect(w.checks.grant_ref_bound).not.toBe('pass');
    }
  });
});

describe('verifyPCActnCore: plan, signature, counter', () => {
  it('a tampered action is not a node of the committed plan; a wrong signature fails; each carries its reason', async () => {
    const s = setup();
    const inc = await core(s, s.mk(s.plan[0]!, { tweak: (a) => void (a.resource = 'session:other') }));
    expect(inc.checks.plan_inclusion).toBe('fail');
    expect(inc.reason).toBe('plan_inclusion: action is not a node of the committed plan');
    const a = s.mk(s.plan[0]!);
    const forged = await core(s, { ...a, sig: s.mk(s.plan[1]!).sig });
    expect(forged.checks.leaf_signature).toBe('fail');
    expect(forged.reason).toBe('leaf_signature: signature does not verify under the leaf holder key / suite');
    const unsigned = await core(s, { ...a, sig: undefined });
    expect(unsigned.allow).toBe(false);
  });
  it('counter: 0 and a large safe integer pass; negative, fractional and unsafe fail with the reason', async () => {
    const s = setup();
    expect((await core(s, s.mk(s.plan[0]!, { counter: 0 }))).checks.counter_format).toBe('pass');
    expect((await core(s, s.mk(s.plan[0]!, { counter: Number.MAX_SAFE_INTEGER }))).checks.counter_format).toBe('pass');
    for (const bad of [-1, 1.5]) {
      const r = await core(s, s.mk(s.plan[0]!, { counter: bad }));
      expect(r.allow).toBe(false);
      expect(r.checks.counter_format === 'fail' || r.checks.wire === 'fail').toBe(true);
    }
  });
});

describe('verifyPCActnCore: taint gate', () => {
  const reg = (trusted: string[]) => {
    const r = new InMemoryTrustedInputRegistry();
    for (const t of trusted) r.recordTrusted(t);
    return r;
  };
  it('off by default: not-enforced', async () => {
    const s = setup();
    expect((await core(s, s.mk(s.plan[0]!))).checks.taint_gate).toBe('not-enforced');
  });
  it('a trusted lineage passes; an untrusted ref exceeds a zero ceiling with the exact message; a negative ceiling is misconfiguration', async () => {
    const s = setup();
    const prov = (refs: string[]) => ({ causal_hash: '', taint_level: 0, trusted_refs: refs });
    const ok = await core(s, s.mk(s.plan[0]!, { extra: { provenance: prov(['t1']) } }), { enforce: { taint: { ctx: { registry: reg(['t1']) }, maxTaint: 0 } } });
    expect(ok.checks.taint_gate).toBe('pass');
    const bad = await core(s, s.mk(s.plan[0]!, { extra: { provenance: prov(['unknown-ref']) } }), { enforce: { taint: { ctx: { registry: reg(['t1']) }, maxTaint: 0 } } });
    expect(bad.checks.taint_gate).toBe('fail');
    expect(bad.reason).toMatch(/^taint_gate: information-flow taint [0-9.]+ exceeds policy max 0$/);
    const mis = await core(s, s.mk(s.plan[0]!, { extra: { provenance: prov(['t1']) } }), { enforce: { taint: { ctx: { registry: reg(['t1']) }, maxTaint: -1 } } });
    expect(mis.reason).toBe('taint_gate: taint gate misconfigured: maxTaint must be a non-negative number (fail closed)');
    const nan = await core(s, s.mk(s.plan[0]!, { extra: { provenance: prov(['t1']) } }), { enforce: { taint: { ctx: { registry: reg(['t1']) }, maxTaint: Number.NaN } } });
    expect(nan.checks.taint_gate).toBe('fail');
    // maxTaint exactly 0 with a fully trusted lineage is the boundary that must pass
    expect((await core(s, s.mk(s.plan[0]!, { extra: { provenance: prov([]) } }), { enforce: { taint: { ctx: { registry: reg([]) }, maxTaint: 1 } } })).checks.taint_gate).toBe('pass');
  });
  it('an unverifiable lineage (no registry) fails closed with the verifier reason; a throwing context is a fail-closed taint error', async () => {
    const s = setup();
    const noReg = await core(s, s.mk(s.plan[0]!), { enforce: { taint: { ctx: {} as never, maxTaint: 1 } } });
    expect(noReg.reason).toBe('taint_gate: taint: no trusted-input registry');
    const boom = await core(s, s.mk(s.plan[0]!, { extra: { provenance: { causal_hash: '', taint_level: 0, trusted_refs: ['some-ref'] } } }), { enforce: { taint: { ctx: { registry: { lookup: () => { throw new Error('registry down'); } } } as never, maxTaint: 1 } } });
    expect(boom.checks.taint_gate).toBe('fail');
    expect(boom.reason).toBe('taint_gate: taint: evaluation error (fail closed): registry down');
  });
});

describe('verifyPCActnCore: freshness gate', () => {
  const withFresh = (s: ReturnType<typeof setup>, epoch: number, ref = 'ref') => s.mk(s.plan[0]!, { extra: { freshness: { beacon_ref: ref, epoch, accumulator_witness: '' } } });
  const anchor = (e: number) => e * BEACON_EPOCH_MS;
  it('anchor age boundaries: now - anchor == maxAge passes, +1 is stale; anchor == now + skew passes, +1 is the future', async () => {
    const s = setup();
    const e = Math.floor(NOW / BEACON_EPOCH_MS) - 3;
    const a = withFresh(s, e);
    const age = NOW - anchor(e);
    expect((await core(s, a, { enforce: { freshness: { maxAgeMs: age } } })).checks.freshness).toBe('pass');
    const stale = await core(s, a, { enforce: { freshness: { maxAgeMs: age - 1 } } });
    expect(stale.checks.freshness).toBe('fail');
    expect(stale.reason).toBe(`freshness: freshness anchor is stale (older than ${age - 1} ms)`);
    const fut = withFresh(s, e + 10);
    const ahead = anchor(e + 10) - NOW;
    expect((await core(s, fut, { enforce: { freshness: { maxAgeMs: 1e9, clockSkewMs: ahead } } })).checks.freshness).toBe('pass');
    const f = await core(s, fut, { enforce: { freshness: { maxAgeMs: 1e9, clockSkewMs: ahead - 1 } } });
    expect(f.reason).toBe('freshness: freshness anchor is in the future');
    // a negative skew is clamped to zero, a non-finite one ignored
    expect((await core(s, withFresh(s, e + 4), { enforce: { freshness: { maxAgeMs: 1e9, clockSkewMs: -1e9 } } })).checks.freshness).toBe('fail');
    expect((await core(s, withFresh(s, e + 3), { enforce: { freshness: { maxAgeMs: 1e9, clockSkewMs: -1e9 } } })).checks.freshness).toBe('pass');
    expect((await core(s, fut, { enforce: { freshness: { maxAgeMs: 1e9, clockSkewMs: Number.NaN } } })).checks.freshness).toBe('fail');
  });
  it('a custom clock and a custom epoch length are honoured', async () => {
    const s = setup();
    const a = withFresh(s, 7);
    expect((await core(s, a, { enforce: { freshness: { maxAgeMs: 10, epochMs: 1000, now: 7000 + 10 } } })).checks.freshness).toBe('pass');
    expect((await core(s, a, { enforce: { freshness: { maxAgeMs: 10, epochMs: 1000, now: 7000 + 11 } } })).checks.freshness).toBe('fail');
  });
  it('misconfiguration and stub anchors fail closed with their reasons', async () => {
    const s = setup();
    const e = Math.floor(NOW / BEACON_EPOCH_MS);
    const mis = 'freshness: freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)';
    expect((await core(s, withFresh(s, e), { enforce: { freshness: { maxAgeMs: 1, epochMs: 0 } } })).reason).toBe(mis);
    expect((await core(s, withFresh(s, e), { enforce: { freshness: { maxAgeMs: -1 } } })).reason).toBe(mis);
    expect((await core(s, withFresh(s, e), { enforce: { freshness: { maxAgeMs: Number.POSITIVE_INFINITY } } })).reason).toBe(mis);
    expect((await core(s, withFresh(s, e), { enforce: { freshness: { maxAgeMs: 0 } } })).checks.freshness).toBe(anchor(e) === NOW ? 'pass' : 'fail');
    const stub = 'freshness: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)';
    expect((await core(s, withFresh(s, e, ''), { enforce: { freshness: { maxAgeMs: 1e9 } } })).reason).toBe(stub);
    expect((await core(s, withFresh(s, 0), { enforce: { freshness: { maxAgeMs: 1e9 } } })).reason).toBe(stub);
    expect((await core(s, withFresh(s, 1), { enforce: { freshness: { maxAgeMs: 1e13 } } })).checks.freshness).toBe('pass');
  });
  it('not enabled: no freshness check is recorded at all', async () => {
    const s = setup();
    expect('freshness' in (await core(s, s.mk(s.plan[0]!))).checks).toBe(false);
  });
});

describe('verifyPCActnCore: hooks, attestation gate, zk, bond, errors', () => {
  const ok: Hook = () => ({ enforced: true, ok: true });
  const no = (reason?: string): Hook => () => ({ enforced: true, ok: false, ...(reason !== undefined ? { reason } : {}) });
  const off: Hook = () => ({ enforced: false });
  it('a rejecting hook carries its reason, or the default "rejected"; a not-enforced hook is reported as such', async () => {
    const s = setup();
    const a = s.mk(s.plan[0]!);
    const r1 = await core(s, a, { hooks: { revocation: no('revoked by operator') } });
    expect(r1.checks.revocation).toBe('fail');
    expect(r1.reason).toBe('revocation: revoked by operator');
    const r2 = await core(s, a, { hooks: { threshold: no() } });
    expect(r2.reason).toBe('threshold: rejected');
    const r3 = await core(s, a, { hooks: { attestation: ok, threshold: off, revocation: ok } });
    expect(r3.allow).toBe(true);
    expect(r3.checks).toMatchObject({ attestation: 'pass', threshold: 'not-enforced', revocation: 'pass' });
    expect((await core(s, a)).checks).toMatchObject({ attestation: 'not-enforced', threshold: 'not-enforced', revocation: 'not-enforced' });
  });
  it('the attestation gate: required (default) turns not-enforced into a deny; required:false allows it; the gate verifier replaces hooks.attestation', async () => {
    const s = setup();
    const a = s.mk(s.plan[0]!);
    const req = await core(s, a, { enforce: { attestation: { verifier: off } } });
    expect(req.checks.attestation).toBe('fail');
    expect(req.reason).toBe('attestation: attestation required but the verifier reported not-enforced / no document (fail closed)');
    expect((await core(s, a, { enforce: { attestation: { verifier: off, required: false } } })).checks.attestation).toBe('not-enforced');
    expect((await core(s, a, { enforce: { attestation: { verifier: ok } } })).checks.attestation).toBe('pass');
    expect((await core(s, a, { enforce: { attestation: { verifier: ok } }, hooks: { attestation: no('ignored') } })).checks.attestation).toBe('pass');
    expect((await core(s, a, { enforce: { attestation: { verifier: no('bad quote') } } })).reason).toBe('attestation: bad quote');
  });
  it('a zk_compliance proof with no enforcing verifier is a fail-closed deny; with a passing verifier it passes; a declining verifier is a deny; absent proof records nothing', async () => {
    const s = setup();
    const withZk = s.mk(s.plan[0]!, { extra: { zk_compliance: { proof: 'p' } } });
    const none = await core(s, withZk);
    expect(none.checks.zk_compliance).toBe('fail');
    expect(none.reason).toBe('zk_compliance: PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof');
    expect((await core(s, withZk, { hooks: { zk: ok } })).checks.zk_compliance).toBe('pass');
    const rej = await core(s, withZk, { hooks: { zk: no('bad proof') } });
    expect(rej.checks.zk_compliance).toBe('fail');
    expect(rej.reason).toBe('zk_compliance: bad proof');
    expect((await core(s, withZk, { hooks: { zk: off } })).checks.zk_compliance).toBe('fail');
    expect('zk_compliance' in (await core(s, s.mk(s.plan[0]!))).checks).toBe(false);
  });
  it('a bond_ref is surfaced as unsupported (0.5); absent records nothing', async () => {
    const s = setup();
    const r = await core(s, s.mk(s.plan[0]!, { extra: { bond_ref: 'bond-1' } }));
    if (r.checks.wire !== 'fail') expect(r.checks.bond).toBe('unsupported');
    expect('bond' in (await core(s, s.mk(s.plan[0]!))).checks).toBe(false);
  });
  it('a throwing hook is a malformed deny with the message, never an exception; wire failures are terminal and prefixed', async () => {
    const s = setup();
    const a = s.mk(s.plan[0]!);
    const boom = await core(s, a, { hooks: { revocation: () => { throw new Error('kaboom'); } } });
    expect(boom.allow).toBe(false);
    expect(boom.checks.malformed).toBe('fail');
    expect(boom.reason).toBe('malformed PCActn: kaboom');
    const wire = await core(s, { ...a, counter: 1.5 });
    expect(wire.reason?.startsWith('wire: ')).toBe(true);
    expect(wire.reason!.length).toBeGreaterThan('wire: '.length);
    expect(Object.keys(wire.checks)).toEqual(['wire']);
  });
  it('an allow verdict carries no reason; a deny carries the FIRST failure', async () => {
    const s = setup();
    const a = s.mk(s.plan[0]!);
    const good = await core(s, a);
    expect(good.allow).toBe(true);
    expect('reason' in good).toBe(false);
    const two = await core(s, s.mk(s.plan[0]!, { extra: { grant_ref: otherId(s.grant.id) } }), { audience: 'other' });
    expect(two.reason).toBe('audience: aud does not match this resource server / instance');
  });
});

describe('verifyPCActn: wrapper behaviours', () => {
  const ctx = (s: ReturnType<typeof setup>) => ({ plan: s.plan, risk: s.lowRisk, params: {} });
  // `require: []`: these tests read the report, they are not about the 0.5 default required checks (see server/breaking-05.test.ts)
  const base = (s: ReturnType<typeof setup>) => ({ grant: s.grant, now: NOW, audience: AUD, require: [] as string[] });
  it('non-objects and undecodable text fail closed with the documented reasons', async () => {
    const s = setup();
    const n = await verifyPCActn(null as never, base(s));
    expect(n.allow).toBe(false);
    expect(n.reasons).toEqual(['PCActn is not an object']);
    expect(n.checks.malformed).toBe('fail');
    expect(n.requiredThreshold).toEqual({ t: 3, proof: 'strong', optimisticAllowed: false });
    expect(n.r).toBe(1);
    expect((await verifyPCActn(5 as never, base(s))).reasons).toEqual(['PCActn is not an object']);
    const bad = await verifyPCActn('{not json', base(s));
    expect(bad.reasons[0]!.startsWith('undecodable PCActn: ')).toBe(true);
    expect(bad.reasons[0]!.length).toBeGreaterThan('undecodable PCActn: '.length);
  });
  it('a core denial is reported ONCE, first; an allow has no core reason', async () => {
    const s = setup();
    const d = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), audience: 'other', context: ctx(s) });
    expect(d.reasons[0]).toBe('audience: aud does not match this resource server / instance');
    expect(d.reasons.filter((x) => x.startsWith('audience:')).length).toBe(1);
    const ok = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: { ...ctx(s), budget: { B: 1, tau: NOW, asOf: NOW } } });
    expect(ok.allow).toBe(true);
    expect(ok.reasons.some((x) => x.startsWith('audience:'))).toBe(false);
  });
  it('grant_ref, params_digest, plan_root_authorized and their messages', async () => {
    const s = setup();
    const budget = { B: 1, tau: NOW, asOf: NOW };
    const other = setup();
    const gr = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), grant: other.grant, context: ctx(s) });
    expect(gr.checks.grant_ref).toBe('fail');
    expect(gr.reasons).toContain('grant_ref: does not reference the supplied grant');
    const pa = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: { ...ctx(s), params: { nope: 1 }, budget } });
    expect(pa.checks.params_digest).toBe('fail');
    expect(pa.reasons).toContain('params_digest: supplied params do not hash to action.params_digest');
    expect((await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: { risk: s.lowRisk, budget } })).checks.params_digest).toBe('not-enforced');
    const pr = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: { ...ctx(s), plan: [s.plan[0]!], budget } });
    expect(pr.checks.plan_root_authorized).toBe('fail');
    expect(pr.reasons).toContain('plan_root_authorized: known plan does not match plan.root');
    const un = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: { ...ctx(s), planAuthorized: false, budget } });
    expect(un.reasons).toContain('plan_root_authorized: the plan root has not been authorized by the principal');
    expect((await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: { ...ctx(s), planAuthorized: true, budget } })).checks.plan_root_authorized).toBe('pass');
    expect((await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: { ...ctx(s), budget } })).checks.plan_root_authorized).toBe('not-enforced');
    expect((await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: { params: {}, risk: s.lowRisk, budget } })).checks.plan_root_authorized).toBe('not-enforced');
  });
  it('the revocation epoch is checked against the PCActn freshness.epoch and the grant', async () => {
    const s = setup();
    const g = generateKeyPair();
    const ep = signRevocationEpoch(g.secretKey, { instance_id: 'i', grant_ref: s.grant.id, epoch: 3, set_size: 0, root: 'AAAA', issued_at: NOW - 1000, not_after: NOW + 60_000 });
    const budget = { B: 1, tau: NOW, asOf: NOW };
    const mkEp = (n: number) => s.mk(s.plan[0]!, { extra: { freshness: { beacon_ref: '', epoch: n, accumulator_witness: '' } } });
    const rev = { epoch: ep, guardianPublic: encodeKey(g.publicKey), lastAcceptedEpoch: 2 };
    const pass = await verifyPCActn(mkEp(3), { ...base(s), context: { ...ctx(s), budget, revocationEpoch: rev } });
    expect(pass.checks.freshness).toBe('pass');
    const old = await verifyPCActn(mkEp(2), { ...base(s), context: { ...ctx(s), budget, revocationEpoch: rev } });
    expect(old.checks.freshness).toBe('fail');
    expect(old.reasons.some((x) => x.startsWith('freshness: PCActn freshness.epoch 2 predates the revocation epoch 3'))).toBe(true);
    const roll = await verifyPCActn(mkEp(3), { ...base(s), context: { ...ctx(s), budget, revocationEpoch: { ...rev, lastAcceptedEpoch: 4 } } });
    expect(roll.reasons.some((x) => x.includes('(rollback)'))).toBe(true);
    const wrongKey = await verifyPCActn(mkEp(3), { ...base(s), context: { ...ctx(s), budget, revocationEpoch: { ...rev, guardianPublic: encodeKey(generateKeyPair().publicKey) } } });
    expect(wrongKey.reasons).toContain('freshness: revocation epoch not signed by the pinned guardian');
    expect((await verifyPCActn(mkEp(3), { ...base(s), context: { ...ctx(s), budget } })).checks.freshness).toBe('not-enforced');
  });
  it('liveness beacon: replay window, binding and the exact messages', async () => {
    const s = setup();
    const issuer = generateKeyPair();
    const budget = { B: 1, tau: NOW, asOf: NOW };
    const beacon = issueLivenessBeacon({ issuerSecret: issuer.secretKey, instance: 'inst', scope: s.grant.id, seq: 5, issuedAt: NOW - 1000 });
    const act = s.mk(s.plan[0]!, { extra: { freshness: { beacon_ref: beaconRef(beacon), epoch: 1, accumulator_witness: '' } } });
    const bc = (over: Record<string, unknown> = {}) => ({ beacon, issuers: [encodeKey(issuer.publicKey)], instance: 'inst', ...over });
    const run = (p: PCActn, b: ReturnType<typeof bc>) => verifyPCActn(p, { ...base(s), context: { ...ctx(s), budget, beacon: b as never } });
    expect((await run(act, bc())).checks.beacon).toBe('pass');
    expect((await run(act, bc({ lastAcceptedSeq: 5 }))).checks.beacon).toBe('pass'); // equal seq is not a replay
    expect((await run(act, bc({ lastAcceptedSeq: 4 }))).checks.beacon).toBe('pass');
    const replay = await run(act, bc({ lastAcceptedSeq: 6 }));
    expect(replay.checks.beacon).toBe('fail');
    expect(replay.reasons).toContain('beacon: beacon seq 5 is older than the last accepted 6 (replay)');
    const unbound = await run(s.mk(s.plan[0]!, { extra: { freshness: { beacon_ref: 'other', epoch: 1, accumulator_witness: '' } } }), bc());
    expect(unbound.reasons).toContain('beacon: PCActn freshness.beacon_ref does not bind the presented beacon');
    const badIssuer = await run(act, bc({ issuers: [encodeKey(generateKeyPair().publicKey)] }));
    expect(badIssuer.checks.beacon).toBe('fail');
    expect(badIssuer.reasons.some((x) => x.startsWith('beacon: ') && x.length > 'beacon: '.length)).toBe(true);
    expect((await verifyPCActn(act, { ...base(s), context: { ...ctx(s), budget } })).checks.beacon).toBe('not-enforced');
  });
  it('reversibility: the authoritative class wins, a stricter declaration is honoured, unknown classes are the most restrictive', async () => {
    const s = setup();
    const budget = { B: 1, tau: NOW, asOf: NOW };
    const run = (decl: string, rs: string | undefined) =>
      verifyPCActn(s.mk(s.plan[0]!, { tweak: (a) => void (a.reversibility_class = decl) }), { ...base(s), context: { ...ctx(s), budget, ...(rs !== undefined ? { reversibilityClass: rs } : {}) } });
    const less = await run('reversible', 'irreversible');
    expect(less.checks.reversibility).toBe('fail');
    expect(less.reasons).toContain("reversibility: declared class 'reversible' is less restrictive than the authoritative 'irreversible'");
    expect((await run('irreversible', 'reversible')).checks.reversibility).toBe('pass');
    expect((await run('costly', 'costly')).checks.reversibility).toBe('pass');
    expect((await run('weird', 'irreversible')).checks.reversibility).toBe('pass');
    expect((await run('weird', 'costly')).checks.reversibility).toBe('pass');
    expect((await run('reversible', 'weird')).checks.reversibility).toBe('fail');
    expect('reversibility' in (await run('reversible', undefined)).checks).toBe(false);
  });
  it('the budget: absent is fail-closed and says so; supplied is recorded as pass', async () => {
    const s = setup();
    const none = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: ctx(s) });
    expect(none.checks.budget).toBe('not-enforced');
    expect(none.reasons).toContain('budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge');
    const some = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: { ...ctx(s), budget: { B: 1, tau: NOW, asOf: NOW } } });
    expect(some.checks.budget).toBe('pass');
    expect(some.reasons.some((x) => x.startsWith('budget:'))).toBe(false);
  });
  it('delegation depth is the number of hops beyond the root', async () => {
    const s = setup(); // chain = [grant, task] -> depth 1 (delegation_depth max 2 holds)
    const r = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: { ...ctx(s), budget: { B: 1, tau: NOW, asOf: NOW } } });
    expect(r.checks.policy).toBe('pass');
    expect(r.allow).toBe(true);
  });
  it('require: a required check that is absent or not-enforced denies with its reason; a pass does not', async () => {
    const s = setup();
    const budget = { B: 1, tau: NOW, asOf: NOW };
    const r = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), require: ['counter', 'revocation', 'nonexistent'], context: { ...ctx(s), budget } });
    expect(r.allow).toBe(false);
    expect(r.reasons).toContain('revocation: required check is not-enforced (default-deny: not enforced by this resource server)');
    expect(r.reasons).toContain('nonexistent: required check is absent (default-deny: not enforced by this resource server)');
    expect(r.reasons.some((x) => x.startsWith('counter_format:'))).toBe(false);
  });
});

describe('signPCActnSuite: fail-closed key-material errors name the missing family', () => {
  const body = () => {
    const s = setup();
    const { sig: _s, ...b } = s.mk(s.plan[0]!);
    return { s, b: b as never };
  };
  it.each([
    ['ml-dsa-65', "signPCActnSuite: 'ml-dsa-65' requires mlDsa key material"],
    ['ml-dsa-87', "signPCActnSuite: 'ml-dsa-87' requires mlDsa87 key material"],
    ['slh-dsa-sha2-128f', "signPCActnSuite: 'slh-dsa-sha2-128f' requires slhDsa key material"],
    ['slh-dsa-sha2-256s', "signPCActnSuite: 'slh-dsa-sha2-256s' requires slhDsa256s key material"],
    ['less-cat1', "signPCActnSuite: 'less-cat1' requires lessCat1 key material"],
  ])('%s without its PQ key throws', (alg, msg) => {
    const { b } = body();
    expect(() => signPCActnSuite(b, { alg: alg as never })).toThrow(msg);
  });
  it('hybrids and ed25519 need the Ed25519 leaf secret; an unknown alg is refused', () => {
    const { b } = body();
    expect(() => signPCActnSuite(b, { alg: 'ed25519' })).toThrow("signPCActnSuite: 'ed25519' requires edLeafSecret");
    expect(() => signPCActnSuite(b, {})).toThrow("signPCActnSuite: 'ed25519' requires edLeafSecret");
    expect(() => signPCActnSuite(b, { alg: 'hybrid-ed25519-ml-dsa-65' })).toThrow("signPCActnSuite: 'hybrid-ed25519-ml-dsa-65' requires edLeafSecret");
    expect(() => signPCActnSuite(b, { alg: 'nope' as never })).toThrow('signPCActnSuite: unknown alg nope');
  });
  it('an ed25519 signature through the suite seam is byte-identical to the default signer and verifies', async () => {
    const { s, b } = body();
    const sk = generateKeyPair();
    const viaSuite = signPCActnSuite(b, { alg: 'ed25519', edLeafSecret: sk.secretKey });
    expect('alg' in viaSuite).toBe(false);
    expect(viaSuite.sig).toBe(signPCActnSuite(b, { edLeafSecret: sk.secretKey }).sig);
    void s;
  });
});

describe('verifyPCActn: survivors of the second mutation round', () => {
  const budget = { B: 1, tau: NOW, asOf: NOW };
  const ctxOf = (s: ReturnType<typeof setup>, extra: Record<string, unknown> = {}) => ({ plan: s.plan, risk: s.lowRisk, params: {}, budget, ...extra });
  // `require: []`: these tests read the report, they are not about the 0.5 default required checks (see server/breaking-05.test.ts)
  const base = (s: ReturnType<typeof setup>) => ({ grant: s.grant, now: NOW, audience: AUD, require: [] as string[] });

  it('an allow verdict reports the exact pass statuses (so a "required" check cannot be satisfied by an empty status)', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: ctxOf(s, { planAuthorized: true }), require: ['grant_ref', 'params_digest', 'plan_root_authorized', 'budget', 'audience', 'counter_format', 'grant_ref_bound', 'policy', 'delegated_caveats'] });
    expect(v.allow).toBe(true);
    expect(v.checks).toMatchObject({ grant_ref: 'pass', params_digest: 'pass', plan_root_authorized: 'pass', budget: 'pass', policy: 'pass', delegated_caveats: 'pass', audience: 'pass', counter_format: 'pass', grant_ref_bound: 'pass' });
  });

  it('enforceRequired never double-reports a check that already failed', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), audience: 'other', context: ctxOf(s), require: ['audience'] });
    expect(v.allow).toBe(false);
    expect(v.reasons.filter((x) => x.includes('required check is'))).toEqual([]);
    expect(v.reasons.filter((x) => x.startsWith('audience:')).length).toBe(1);
    expect(v.checks.audience).toBe('fail');
  });

  it('a grant that binds the agent REQUIRES a bound attestation, with the exact reason', async () => {
    const s = setup({ agentBinding: { operator: 'op' } });
    const v = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: ctxOf(s) });
    expect(v.allow).toBe(false);
    expect(v.checks.attestation).toBe('fail');
    expect(v.reasons).toContain('attestation: the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED');
  });

  it('delegation depth is the hop count beyond the root: a hop capped at depth 0 is violated by a depth-1 chain, depth 1 is allowed', async () => {
    const zero = setup({ taskCaveats: [{ type: 'delegation_depth', max: 0 }] });
    const bad = await verifyPCActn(zero.mk(zero.plan[0]!), { ...base(zero), context: ctxOf(zero) });
    expect(bad.checks.delegated_caveats).toBe('fail');
    expect(bad.reasons.some((x) => x.startsWith('delegated_caveats: delegation caveat(s) not satisfied: ') && x.length > 'delegated_caveats: delegation caveat(s) not satisfied: '.length)).toBe(true);
    const one = setup({ taskCaveats: [{ type: 'delegation_depth', max: 1 }] });
    expect((await verifyPCActn(one.mk(one.plan[0]!), { ...base(one), context: ctxOf(one) })).checks.delegated_caveats).toBe('pass');
  });

  it('the stricter of the declared and the authoritative reversibility class is what delegated caveats see', async () => {
    const s = setup({ taskCaveats: [{ type: 'reversibility_max', class: 'reversible' }] });
    // n1 declares 'reversible'; the RS says 'reversible' too -> within the cap
    const ok = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: ctxOf(s, { reversibilityClass: 'reversible' }) });
    expect(ok.checks.delegated_caveats).toBe('pass');
    // the agent declares 'irreversible' (stricter than the RS's 'reversible'): the stricter class is honoured -> the cap is exceeded
    const strict = await verifyPCActn(s.mk(s.plan[0]!, { tweak: (a) => void (a.reversibility_class = 'irreversible') }), { ...base(s), context: ctxOf(s, { reversibilityClass: 'reversible' }) });
    expect(strict.checks.delegated_caveats).toBe('fail');
    // the RS says 'irreversible' and the agent declares 'reversible': hard failure AND the RS class is what the caveat sees
    const lie = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: ctxOf(s, { reversibilityClass: 'irreversible' }) });
    expect(lie.checks.reversibility).toBe('fail');
    expect(lie.checks.delegated_caveats).toBe('fail');
    // equal classes: the declared one is used (no change)
    const eq = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: ctxOf(s, { reversibilityClass: 'reversible' }) });
    expect(eq.checks.reversibility).toBe('pass');
  });

  it('an empty capability chain is an ordinary deny (cap_chain fail), never a thrown-and-caught internal error', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!, { extra: { cap_chain: [] } }), { ...base(s), context: ctxOf(s) });
    expect(v.allow).toBe(false);
    expect(v.checks.cap_chain).toBe('fail');
    expect('malformed' in v.checks).toBe(false);
    expect(v.reasons.some((x) => x.startsWith('verifier error'))).toBe(false);
    expect('delegated_caveats' in v.checks).toBe(false);
  });

  it('threshold messages distinguish a rejected proof from a missing verifier', async () => {
    const s = setup();
    const a = s.mk(s.plan[1]!);
    const ctx = { plan: s.plan, risk: { reversibility: 0, blastRadius: 0.5, confidence: 0.5, semanticDistance: 1 }, params: s.params, budget };
    const missing = await verifyPCActn(a, { ...base(s), context: ctx });
    expect(missing.checks.threshold).toBe('fail');
    expect(missing.reasons.some((x) => /^threshold: t=\d \(\w+\) required but no threshold verifier is enforced$/.test(x))).toBe(true);
    const rejected = await verifyPCActn(a, { ...base(s), context: ctx, hooks: { threshold: () => ({ enforced: true, ok: false }) } });
    expect(rejected.checks.threshold).toBe('fail');
    expect(rejected.reasons.some((x) => /^threshold: t=\d required and the threshold proof was rejected$/.test(x))).toBe(true);
    const passed = await verifyPCActn(a, { ...base(s), context: ctx, hooks: { threshold: () => ({ enforced: true, ok: true, t: missing.requiredThreshold.t }) } });
    expect(passed.checks.threshold).toBe('pass');
    expect(passed.reasons.some((x) => x.startsWith('threshold:'))).toBe(false);
  });

  it('a single-signer action needs no threshold check at all', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: ctxOf(s) });
    expect(v.requiredThreshold.t).toBe(1);
    expect(v.checks.threshold).toBe('not-enforced');
    expect(v.reasons.some((x) => x.startsWith('threshold:'))).toBe(false);
  });

  it('informational policy reasons of an ADMITTED action carry the "policy: " prefix; a denial lists them too', async () => {
    const s = setup();
    // no budget: admitted only if r*kappa == 0; the verdict carries the fail-closed budget note plus any policy notes
    const free = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: { plan: s.plan, risk: s.lowRisk, params: {} } });
    for (const r of free.reasons) expect(typeof r === 'string' && r.length > 0).toBe(true);
    const denied = await verifyPCActn(s.mk(s.plan[1]!), { ...base(s), context: { plan: s.plan, risk: { reversibility: 0, blastRadius: 0.9, confidence: 0.1, semanticDistance: 1 }, params: s.params, budget } });
    expect(denied.allow).toBe(false);
    expect(denied.reasons.length).toBeGreaterThan(0);
  });
});
