import * as agentNative from '../agent-native';
import { describe, expect, it } from 'vitest';
import { enforceRequired, verifyPCActn } from './verify';
import { AUD, NOW, setup } from './fixture.test-util';
import { encodePCActn } from '../pcactn';

describe('verifyPCActn', () => {
  it('allows a valid in-plan low-risk action; later-milestone hooks report not-enforced', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), { grant: s.grant, now: NOW, audience: AUD, context: { plan: s.plan, risk: s.lowRisk, params: {} } });
    expect(v.allow).toBe(true);
    expect(v.requiredThreshold.t).toBe(1);
    expect(v.checks.cap_chain).toBe('pass');
    expect(v.checks.plan_inclusion).toBe('pass');
    expect(v.checks.leaf_signature).toBe('pass');
    expect(v.checks.attestation).toBe('not-enforced');
    expect(v.checks.plan_root_authorized).toBe('not-enforced'); // no planAuthorized asserted
    expect(v.checks.revocation).toBe('not-enforced');
    expect(v.checks.threshold).toBe('not-enforced');
  });

  it('accepts a string-encoded PCActn', async () => {
    const s = setup();
    const v = await verifyPCActn(encodePCActn(s.mk(s.plan[0]!)), { grant: s.grant, now: NOW, audience: AUD, context: { plan: s.plan, risk: s.lowRisk } });
    expect(v.allow).toBe(true);
  });

  it('denies an out-of-plan action (bad inclusion)', async () => {
    const s = setup();
    const a = s.mk(s.plan[0]!, { tweak: (x) => { x.resource = 'session:other'; } });
    const v = await verifyPCActn(a, { grant: s.grant, now: NOW, audience: AUD, context: { risk: s.lowRisk } });
    expect(v.allow).toBe(false);
    expect(v.checks.plan_inclusion).toBe('fail');
    expect(v.reasons.join(' ')).toMatch(/plan_inclusion/);
  });

  it('denies a tampered body (signature)', async () => {
    const s = setup();
    const a = s.mk(s.plan[0]!);
    const t = { ...a, counter: 99 };
    const v = await verifyPCActn(t, { grant: s.grant, now: NOW, context: { risk: s.lowRisk } });
    expect(v.allow).toBe(false);
    expect(v.checks.leaf_signature).toBe('fail');
  });

  it('denies when a RevocationChecker hook reports revoked', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), {
      grant: s.grant, now: NOW, audience: AUD, context: { plan: s.plan, risk: s.lowRisk },
      hooks: { revocation: () => ({ enforced: true, ok: false, reason: 'leaf revoked' }) },
    });
    expect(v.allow).toBe(false);
    expect(v.checks.revocation).toBe('fail');
    expect(v.reasons.join(' ')).toContain('leaf revoked');
  });

  it('denies by policy when action is outside the envelope predicates', async () => {
    const s = setup();
    const n = { ...s.plan[0]!, verb: 'delete_account' };
    const v = await verifyPCActn(s.mk(n), { grant: s.grant, now: NOW, context: { risk: s.lowRisk } });
    expect(v.allow).toBe(false);
    expect(v.checks.policy).toBe('fail');
  });

  it('denies an expired delegation caveat', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), { grant: s.grant, now: NOW + 700_000, context: { plan: s.plan, risk: s.lowRisk } });
    expect(v.allow).toBe(false);
    expect(v.checks.delegated_caveats).toBe('fail');
  });

  it('denies params that do not open the digest', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), { grant: s.grant, now: NOW, context: { params: { evil: 1 }, risk: s.lowRisk } });
    expect(v.allow).toBe(false);
    expect(v.checks.params_digest).toBe('fail');
  });

  it('step-up (t>1) without an enforced threshold verifier is denied; with one it passes', async () => {
    const s = setup();
    const a = s.mk(s.plan[1]!);
    const ctx = { plan: s.plan, risk: { reversibility: 0, blastRadius: 0.5, confidence: 0.5, semanticDistance: 1 }, params: s.params };
    const no = await verifyPCActn(a, { grant: s.grant, now: NOW, audience: AUD, context: ctx });
    expect(no.requiredThreshold.t).toBeGreaterThan(1);
    expect(no.allow).toBe(false);
    expect(no.checks.threshold).toBe('fail');
    const yes = await verifyPCActn(a, { grant: s.grant, now: NOW, audience: AUD, context: ctx, hooks: { threshold: () => ({ enforced: true, ok: true }) } });
    expect(yes.allow).toBe(true);
  });

  it('never throws on garbage; fails closed', async () => {
    const s = setup();
    for (const g of ['not json', '{}', 'null', '[]'] as const) {
      const v = await verifyPCActn(g, { grant: s.grant, now: NOW });
      expect(v.allow).toBe(false);
      expect(v.reasons.length).toBeGreaterThan(0);
    }
    expect((await verifyPCActn(undefined as never, { grant: s.grant })).allow).toBe(false);
  });

  it('plan_root_authorized only passes when the RS asserts the root is principal-authorized', async () => {
    const s = setup();
    const run = (planAuthorized?: boolean) =>
      verifyPCActn(s.mk(s.plan[0]!), { grant: s.grant, now: NOW, audience: AUD, context: { plan: s.plan, risk: s.lowRisk, planAuthorized } });
    const yes = await run(true);
    expect(yes.allow).toBe(true);
    expect(yes.checks.plan_root_authorized).toBe('pass');
    const no = await run(false);
    expect(no.allow).toBe(false);
    expect(no.checks.plan_root_authorized).toBe('fail');
    expect((await run(undefined)).checks.plan_root_authorized).toBe('not-enforced');
  });

  it('`require` makes a required-but-not-enforced check DENY (default-deny), and absent keys count as not enforced', async () => {
    const s = setup();
    const ctx = { plan: s.plan, risk: s.lowRisk };
    const loose = await verifyPCActn(s.mk(s.plan[0]!), { grant: s.grant, now: NOW, audience: AUD, context: ctx });
    expect(loose.allow).toBe(true);
    const strict = await verifyPCActn(s.mk(s.plan[0]!), { grant: s.grant, now: NOW, audience: AUD, context: ctx, require: ['revocation', 'plan_root_authorized'] });
    expect(strict.allow).toBe(false);
    expect(strict.checks.revocation).toBe('fail');
    expect(strict.checks.plan_root_authorized).toBe('fail');
    expect(strict.reasons.join(' ')).toMatch(/default-deny/);
    const met = await verifyPCActn(s.mk(s.plan[0]!), {
      grant: s.grant, now: NOW, audience: AUD, require: ['revocation', 'plan_root_authorized'],
      context: { ...ctx, planAuthorized: true }, hooks: { revocation: () => ({ enforced: true, ok: true }) },
    });
    expect(met.allow).toBe(true);
    expect(enforceRequired({ allow: true, r: 0, requiredThreshold: strict.requiredThreshold, checks: {}, reasons: [] }, ['nope']).allow).toBe(false);
  });

  it('the agent cannot lower risk through taint: the claimed taint_level is ignored, a missing RS taint fails closed', async () => {
    const s = setup();
    const a = s.mk(s.plan[0]!); // claims taint_level 0
    const { taint: _t, ...noTaint } = s.lowRisk;
    const closed = await verifyPCActn(a, { grant: s.grant, now: NOW, context: { plan: s.plan, risk: noTaint } });
    const vouched = await verifyPCActn(a, { grant: s.grant, now: NOW, context: { plan: s.plan, risk: s.lowRisk } });
    expect(closed.r).toBeGreaterThan(vouched.r); // worst-case taint, not the agent's 0
  });

  it('the RS-authoritative reversibility class wins: a less-restrictive declaration is a hard failure, a stricter one is honoured', async () => {
    const s = setup();
    const n2 = s.mk(s.plan[1]!); // declares 'irreversible'
    const base = { grant: s.grant, now: NOW };
    const lie = await verifyPCActn(s.mk(s.plan[0]!), { ...base, context: { plan: s.plan, risk: s.lowRisk, reversibilityClass: 'costly' } });
    expect(lie.allow).toBe(false);
    expect(lie.checks.reversibility).toBe('fail');
    const match = await verifyPCActn(s.mk(s.plan[0]!), { ...base, context: { plan: s.plan, risk: s.lowRisk, reversibilityClass: 'reversible' } });
    expect(match.checks.reversibility).toBe('pass');
    const stricter = await verifyPCActn(n2, { ...base, context: { plan: s.plan, risk: s.lowRisk, params: s.params, reversibilityClass: 'costly' } });
    expect(stricter.checks.reversibility).toBe('pass');
    // an unknown server class is treated as the most restrictive
    const unknown = await verifyPCActn(s.mk(s.plan[0]!), { ...base, context: { plan: s.plan, risk: s.lowRisk, reversibilityClass: 'weird' } });
    expect(unknown.checks.reversibility).toBe('fail');
  });
});

describe('verifyPCActn: delegated agent-native caveats are enforced', () => {
  const run = (s: ReturnType<typeof setup>, params: Record<string, unknown>) => {
    const a = s.mk(s.plan[0]!, { tweak: undefined });
    return verifyPCActn(a, { grant: s.grant, now: NOW, audience: AUD, context: { plan: s.plan, risk: s.lowRisk, params } });
  };
  // plan node n1 commits params_digest of {}, so the conforming/violating call is expressed via a node with params.

  it('tool_schema: conforming call allowed, violating call denied', async () => {
    const s = setup({ taskCaveats: [agentNative.toolSchemaCaveat('rotate_recovery_keys', { props: { scope: { type: 'string', enum: ['all'] } }, required: ['scope'] })] });
    // n2 = rotate_recovery_keys with params {scope:'all'} (irreversible => t=3; the delegated-caveat check is independent)
    const ok = await verifyPCActn(s.mk(s.plan[1]!), { grant: s.grant, now: NOW, context: { plan: s.plan, risk: s.lowRisk, params: s.params } });
    expect(ok.checks.delegated_caveats).toBe('pass');
    expect(ok.checks.policy).toBe('pass');
    const strict = setup({ taskCaveats: [agentNative.toolSchemaCaveat('rotate_recovery_keys', { props: { scope: { type: 'string', enum: ['mine'] } }, required: ['scope'] })] });
    const bad = await verifyPCActn(strict.mk(strict.plan[1]!), { grant: strict.grant, now: NOW, context: { plan: strict.plan, risk: strict.lowRisk, params: strict.params } });
    expect(bad.allow).toBe(false);
    expect(bad.checks.delegated_caveats).toBe('fail');
  });

  it('a tool_schema for a DIFFERENT tool denies (authority exists only for that tool)', async () => {
    const s = setup({ taskCaveats: [agentNative.toolSchemaCaveat('rotate_recovery_keys', { props: {} })] });
    const v = await run(s, {});
    expect(v.allow).toBe(false);
    expect(v.checks.delegated_caveats).toBe('fail');
  });

  it('predicates: in-scope allowed, out-of-scope denied', async () => {
    const inScope = setup({ taskCaveats: [agentNative.predicatesCaveat([{ verb: 'list_sessions', resource: 'session:*' }])] });
    const ok = await run(inScope, {});
    expect(ok.checks.delegated_caveats).toBe('pass');
    expect(ok.allow).toBe(true);
    const narrow = setup({ taskCaveats: [agentNative.predicatesCaveat([{ verb: 'rotate_recovery_keys', resource: 'account:me' }])] });
    const bad = await run(narrow, {});
    expect(bad.allow).toBe(false);
    expect(bad.checks.delegated_caveats).toBe('fail');
  });

  it('unknown delegated caveat types still fail closed', async () => {
    const s = setup({ taskCaveats: [{ type: 'made_up' }] });
    const v = await run(s, {});
    expect(v.allow).toBe(false);
    expect(v.checks.delegated_caveats).toBe('fail');
  });
});

describe('verifyPCActn: wire v2 freshness + optional slots', () => {
  const ctx = (s: ReturnType<typeof setup>) => ({ plan: s.plan, risk: s.lowRisk, params: {} });

  it('audience: matching passes, mismatching denies, absent fails-closed (a signed aud needs an audience), null opts out', async () => {
    const s = setup();
    const a = s.mk(s.plan[0]!); // the fixture always signs aud: AUD
    expect((await verifyPCActn(a, { grant: s.grant, now: NOW, audience: AUD, context: ctx(s) })).checks.audience).toBe('pass');
    const bad = await verifyPCActn(a, { grant: s.grant, now: NOW, audience: 'other-rs', context: ctx(s) });
    expect(bad.allow).toBe(false);
    expect(bad.checks.audience).toBe('fail');
    // FAIL-CLOSED: a PCActn carrying a signed aud whose verifier supplies NO audience must not silently lose
    // its cross-instance binding — the audience check fails and the action is denied.
    const absent = await verifyPCActn(a, { grant: s.grant, now: NOW, context: ctx(s) });
    expect(absent.checks.audience).toBe('fail');
    expect(absent.allow).toBe(false);
    // `audience: null` is the explicit opt-out ("accept any audience"): reported not-enforced.
    expect((await verifyPCActn(a, { grant: s.grant, now: NOW, audience: null, context: ctx(s) })).checks.audience).toBe('not-enforced');
    // `require` turns even the opted-out (not-enforced) audience into a denial (default-deny).
    expect((await verifyPCActn(a, { grant: s.grant, now: NOW, audience: null, require: ['audience'], context: ctx(s) })).allow).toBe(false);
  });

  it('validity: an expired / not-yet-valid PCActn is denied', async () => {
    const s = setup();
    const a = s.mk(s.plan[0]!);
    expect((await verifyPCActn(a, { grant: s.grant, now: NOW + 600_001, context: ctx(s) })).checks.validity).toBe('fail');
    expect((await verifyPCActn(a, { grant: s.grant, now: NOW - 61_000, context: ctx(s) })).checks.validity).toBe('fail');
    expect((await verifyPCActn(a, { grant: s.grant, now: NOW + 600_000, context: ctx(s) })).checks.validity).toBe('pass');
  });

  it('a wire-form violation is terminal (only the wire check is reported)', async () => {
    const s = setup();
    const a = { ...s.mk(s.plan[0]!), counter: 1.5 };
    const v = await verifyPCActn(a, { grant: s.grant, now: NOW, context: ctx(s) });
    expect(v.allow).toBe(false);
    expect(Object.keys(v.checks).sort()).toEqual(['malformed', 'wire']);
    const raw = await verifyPCActn(encodePCActn(s.mk(s.plan[0]!)).replace('"counter":1', '"counter":1.0'), { grant: s.grant, now: NOW, context: ctx(s) });
    expect(raw.allow).toBe(false);
  });

  it('caution is MONOTONE: it can raise r (and the required threshold) but never lower it', async () => {
    const s = setup();
    const base = await verifyPCActn(s.mk(s.plan[0]!), { grant: s.grant, now: NOW, audience: AUD, context: ctx(s) });
    expect(base.allow).toBe(true);
    const cautious = await verifyPCActn(s.mk(s.plan[0]!, { extra: { caution: 0.95 } }), { grant: s.grant, now: NOW, audience: AUD, context: ctx(s) });
    expect(cautious.r).toBeGreaterThanOrEqual(0.95);
    expect(cautious.requiredThreshold.t).toBe(3);
    expect(cautious.allow).toBe(false); // no threshold proof supplied
    const zero = await verifyPCActn(s.mk(s.plan[0]!, { extra: { caution: 0 } }), { grant: s.grant, now: NOW, audience: AUD, context: ctx(s) });
    expect(zero.r).toBe(base.r);
  });

  it('tool_binding binds the semantic firewall to the signed tool signature', async () => {
    const sig = { name: 'rotate_recovery_keys', v: 1 };
    const cav = agentNative.toolSchemaCaveat(sig, { props: { scope: { type: 'string', enum: ['all'] } }, required: ['scope'] });
    const s = setup({ taskCaveats: [cav] });
    const run = (extra?: Record<string, unknown>) =>
      verifyPCActn(s.mk(s.plan[1]!, { extra }), { grant: s.grant, now: NOW, context: { plan: s.plan, risk: s.lowRisk, params: s.params } });
    expect((await run()).checks.delegated_caveats).toBe('pass'); // absent => current behaviour
    expect((await run({ tool_binding: cav.signature_digest })).checks.delegated_caveats).toBe('pass');
    const swapped = await run({ tool_binding: hashOf({ name: 'rotate_recovery_keys', v: 2 }) });
    expect(swapped.checks.delegated_caveats).toBe('fail');
    expect(swapped.allow).toBe(false);
  });
});

describe('verifyPCActn: omitted budget fails CLOSED (DENY-METERED)', () => {
  // r = gamma * 0.5 = 0.1 <= theta1 => t=1 band, but cost = kappa*r = 0.1 > 0 (a would-be machine-only action).
  const machineRisk = (s: ReturnType<typeof setup>) => ({ ...s.lowRisk, blastRadius: 0.5 });

  it('omitted budget does NOT auto-admit a would-be machine-only (t=1) action; it is forced to step-up', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), {
      grant: s.grant, now: NOW, audience: AUD, context: { plan: s.plan, risk: machineRisk(s), params: {} },
    });
    expect(v.r).toBeCloseTo(0.1);
    expect(v.checks.budget).toBe('not-enforced'); // visibility preserved
    expect(v.allow).toBe(false); // B=0 cannot afford cost => step-up; no threshold proof supplied
    expect(v.requiredThreshold.t).toBe(3);
    expect(v.reasons.join(' ')).toMatch(/fail-closed default \(B=0/);
    expect(v.reasons.join(' ')).toMatch(/recharge/);
  });

  it('a supplied budget is UNAFFECTED: the same t=1 action auto-admits', async () => {
    const s = setup();
    const budget = { B: 1, tau: NOW, asOf: NOW };
    const v = await verifyPCActn(s.mk(s.plan[0]!), {
      grant: s.grant, now: NOW, audience: AUD, context: { plan: s.plan, risk: machineRisk(s), params: {}, budget },
    });
    expect(v.checks.budget).toBe('pass');
    expect(v.requiredThreshold.t).toBe(1);
    expect(v.allow).toBe(true);
  });

  it('omitted budget still admits a genuinely free (r=0 => cost 0) machine action (backward-compatible)', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), {
      grant: s.grant, now: NOW, audience: AUD, context: { plan: s.plan, risk: s.lowRisk, params: {} },
    });
    expect(v.r).toBe(0);
    expect(v.allow).toBe(true);
  });
});

import { hashCanonical as hashOf } from '../hash';
