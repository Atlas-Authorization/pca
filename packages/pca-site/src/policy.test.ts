import { describe, expect, it } from 'vitest';
import { parseSitePolicy } from './index';

const SKYAIR = {
  v: 2,
  intent: { require: true, max_residual_risk_ppm: 20000, replay: 'on_first_use', max_prior_admitted_ppm: 0 },
  session: { require: true, principal_signed_deltas_only: true, max_revocation_age_s: 60, accept_sequencers: [] },
  schema: { accept_previous_for_s: 86400, closed_world: true },
  tiers: {
    'air.search': { tier: 1, rate: { max: 30, per_secs: 60, key: 'agent' } },
    'air.hold': { tier: 2 },
    'air.book': { tier: 3, jit: { irreversible: 'typed', reversible: 'none' }, max_total_cents: 500000 },
    'air.refund': { tier: 4, bond_min_cents: 10000 },
  },
  lazy: { enabled: true, deliver: 'wallet_direct', question_ttl_s: 900, max_questions_per_session: 6 },
  provenance: { critical_max: 'first_party', material_tainted: 'question_typed' },
  oracles: {},
  classifiers: {},
  frame: { monitor: ['account.contact_email', 'bookings'], on_violation: 'veto_and_alert' },
  evidence: { store: true, retain_days: 540, anchor: 'atlas' },
  web_bot_auth: { accept: true, directory: 'https://skyair.example/.well-known/agent-keys' },
};

describe('the §5 verifier policy', () => {
  it('parses the SkyAir policy of the walkthrough', () => {
    const p = parseSitePolicy(SKYAIR);
    expect(p.tiers['air.book']!.tier).toBe(3);
    expect(p.tiers['air.refund']!.bond_min_cents).toBe(10000);
    expect(p.web_bot_auth.accept).toBe(true);
    expect(p.lazy.question_ttl_s).toBe(900);
  });
  it('a missing member means the documented default', () => {
    const p = parseSitePolicy({});
    expect(p.intent).toEqual({ require: true, max_residual_risk_ppm: 20000, replay: 'on_first_use', max_prior_admitted_ppm: 0 });
    expect(p.session.max_revocation_age_s).toBe(60);
    expect(p.lazy).toEqual({ enabled: true, deliver: 'wallet_direct', question_ttl_s: 900, max_questions_per_session: 6 });
    expect(p.provenance).toEqual({ critical_max: 'first_party', material_tainted: 'question_typed' });
    expect(p.web_bot_auth.accept).toBe(false);
  });
  it('unknown members anywhere are a configuration error (fail closed)', () => {
    expect(() => parseSitePolicy({ ...SKYAIR, extra: 1 })).toThrow(/unknown member "extra"/);
    expect(() => parseSitePolicy({ intent: { requir: true } })).toThrow(/unknown member/);
    expect(() => parseSitePolicy({ tiers: { x: { tier: 2, foo: 1 } } })).toThrow(/unknown member/);
    expect(() => parseSitePolicy({ web_bot_auth: { accept: true, keys: [] } })).toThrow(/unknown member/);
  });
  it('non-conforming values are refused', () => {
    expect(() => parseSitePolicy({ v: 1 })).toThrow();
    expect(() => parseSitePolicy({ session: { principal_signed_deltas_only: false } })).toThrow(/only conforming/);
    expect(() => parseSitePolicy({ schema: { closed_world: false } })).toThrow(/closed-world/);
    expect(() => parseSitePolicy({ intent: { replay: 'sometimes' } })).toThrow();
    expect(() => parseSitePolicy({ intent: { max_residual_risk_ppm: 2_000_000 } })).toThrow();
    expect(() => parseSitePolicy({ provenance: { critical_max: 'friend' } })).toThrow();
    expect(() => parseSitePolicy({ schema: { digest: 'not-a-digest' } })).toThrow();
  });
});
