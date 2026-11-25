/**
 * Mutation kills for the 0.5.0 flagship gate survivors in intent-v2.ts (the rule 22 engine / call_context / actions shape
 * of the verifier context, the v2 schema floor check, the `pin` and `traits` checks with the exact engine input and every
 * reason, the single-source worlds, the ceilings' predicates and the `tighten` triggers), intent-acc.ts (the scope list, a
 * scoped accumulator's holder), intent-binding.ts (the v3 prefix, a non-object approved goal, the v3 refusal),
 * intent-required.ts (verifyIntentRequiredAt) and intent.ts.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { EVOLUTION_RECORD_KIND, decidePin, evolutionDiffDigest, registryKeyOf, signEvolutionRecord, signReapproval, type UnsignedEvolutionRecord } from './action-pin';
import { actionSchemaKeyOf, signActionSchema, type ActionSchema } from './action-schema';
import { b64u, sha256, utf8 } from './hash';
import { ACC_SCOPES, accumulatorDeclError } from './intent-acc';
import { INTENT_GOAL_V3_PREFIX, decideIntentBinding, intentGoalV3, isApprovedGoalRef } from './intent-binding';
import { signIntentRequired, verifyIntentRequiredAt } from './intent-required';
import { decideIntentV2, intentV2ContextError, type IntentV2Context } from './intent-v2';
import { publicKeyOf } from './keys';
import { paramsDigest } from './merkle';
import { DEFAULT_RISK_POLICY } from './risk';

const NOW = 1_800_000_000_000;
const SITE = sha256(utf8('gate3-intent-v2/site'));
const PRINCIPAL = sha256(utf8('gate3-intent-v2/principal'));
const REG = sha256(utf8('gate3-intent-v2/registry'));
const KEYS = [actionSchemaKeyOf('k1', SITE)];
const REG_KEYS = [registryKeyOf('r1', REG)];
const d32 = (n: number) => b64u(new Uint8Array(32).fill(n));
const D = d32(7);
const D2 = d32(9);
const ROOT = d32(8);
const VERB = 'a.b';
const FLOORS = { risk: 0, rev: 'reversible', blast_ppm: 0, esc: 0, caveats: [], context: [], prules: [] };
const PARAMS_DECL = { 'action.params.x': { type: 'string', semantic: 's', sensitivity: 'free' }, 'action.params.flag': { type: 'boolean', semantic: 'f', sensitivity: 'free', required: false } };
const schemaV2 = (def = D): ActionSchema =>
  signActionSchema({ v: 2, kind: 'pca-action-schema', site: 'https://s.example', aud: 's.example', version: '1', pack: { ns: 'acme', version: '1', root: ROOT }, verbs: [{ verb: VERB, kind: 'write', params: PARAMS_DECL, effects: ['update'], traits: [], def, floors: FLOORS }] } as never, 'k1', SITE);
const SCHEMA_V1 = signActionSchema({ v: 1, kind: 'pca-action-schema', site: 'https://s.example', aud: 's.example', version: '1', verbs: [{ verb: VERB, kind: 'write', params: PARAMS_DECL, reversibility: 'reversible' }] } as never, 'k1', SITE);
const S2 = schemaV2();
const PIN = { pack: { ns: 'acme', root: ROOT }, defs: { [VERB]: D }, on_new_action: 'deny', max_esc: 2, preauth_esc: 1, caveats: ['amount_cap'] };
const GRANT_ID = 'G'.repeat(43);
const ISSUER = b64u(publicKeyOf(PRINCIPAL));
const envelope = (extra: Record<string, unknown>) => ({ type: 'envelope', goal_commit: 'g', predicates: [], caveats: [{ type: 'window' }, { foo: 1 }, null], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY, ...extra });
const grantWith = (extra: Record<string, unknown> | null) => ({ id: GRANT_ID, issuer: ISSUER, caveats: extra === null ? [] : [envelope(extra)] }) as never;
const PARAMS = { x: 'hi', flag: true };
const VIEW = { aud: 's.example', action: { verb: VERB, resource: 'r', params_digest: paramsDigest(PARAMS) } } as never;

type Calls = { schemaError: unknown[][]; decide: unknown[] };
function engine(result: 'allow' | 'escalate' | 'deny' = 'allow', forged: string | null = null) {
  const calls: Calls = { schemaError: [], decide: [] };
  const rule22 = {
    schemaError: (...a: unknown[]) => {
      calls.schemaError.push(a);
      return forged;
    },
    decide: (i: unknown) => {
      calls.decide.push(i);
      return result;
    },
  };
  return { rule22, calls };
}
const ctxOf = (extra: Record<string, unknown> = {}, docs: unknown[] = [S2]) => ({ schema: { docs, keys: KEYS }, params: PARAMS, ...extra }) as IntentV2Context;
const names = (d: ReturnType<typeof decideIntentV2>) => d.checks.map((c) => c.name);
const rec = (from: string, to: string, cls: UnsignedEvolutionRecord['class']) => signEvolutionRecord({ v: 1, kind: EVOLUTION_RECORD_KIND, ns: 'acme', verb: VERB, from, to, class: cls, reasons: [] }, 'r1', REG);
const pinReason = (doc: ActionSchema, extra: Record<string, unknown> = {}, pin: unknown = PIN) => {
  const d = decidePin({ pin, doc, verb: VERB, records: [], keys: [], reapprovals: [], grant: { id: GRANT_ID, issuer: ISSUER }, ...extra } as never) as { ok: false; code: string; reason: string; escalate?: boolean; needs_reapproval?: string };
  return `${d.escalate ? 'escalate: ' : ''}${d.code}: ${d.reason}${d.needs_reapproval !== undefined ? ` (re-approve diff ${d.needs_reapproval})` : ''}`;
};

describe('intentV2ContextError: rule22, call_context and actions', () => {
  const fn = () => null;
  it('each engine member must be a function on its own', () => {
    expect(intentV2ContextError({ rule22: 5 })).toBe('rule22 must be {schemaError, decide}');
    expect(intentV2ContextError({ rule22: { schemaError: 5, decide: fn } })).toBe('rule22 must be {schemaError, decide}');
    expect(intentV2ContextError({ rule22: { schemaError: fn, decide: 5 } })).toBe('rule22 must be {schemaError, decide}');
    expect(intentV2ContextError({ rule22: { schemaError: fn, decide: fn } })).toBeNull();
  });
  it('call_context: an array of strings passes; one non-string or a non-array fails', () => {
    expect(intentV2ContextError({ call_context: [] })).toBeNull();
    expect(intentV2ContextError({ call_context: ['a'] })).toBeNull();
    expect(intentV2ContextError({ call_context: ['a', 5] })).toBe('call_context must be an array of strings');
    expect(intentV2ContextError({ call_context: 'a' })).toBe('call_context must be an array of strings');
  });
  it('actions must be an object and each list member an array', () => {
    expect(intentV2ContextError({ actions: 5 })).toBe('actions must be an object');
    expect(intentV2ContextError({ actions: { records: 5 } })).toBe('actions.records must be an array');
    expect(intentV2ContextError({ actions: { keys: 5 } })).toBe('actions.keys must be an array');
    expect(intentV2ContextError({ actions: { reapprovals: 5 } })).toBe('actions.reapprovals must be an array');
    expect(intentV2ContextError({ actions: { records: [], keys: [], reapprovals: [] } })).toBeNull();
  });
});

describe('decideIntentV2: the pin and traits checks of a pinned grant over a v2 schema', () => {
  it('both pass; the engine sees the doc, the verb, the grant caveats and the pin floors exactly', () => {
    const e = engine();
    const d = decideIntentV2(VIEW, grantWith({ actions: PIN }), ctxOf({ rule22: e.rule22, reviewers: { keys: ['rv'] } }), NOW);
    expect(d.checks).toEqual([{ name: 'pin', ok: true }, { name: 'traits', ok: true }]);
    expect(e.calls.decide).toEqual([{ doc: S2, verb: VERB, grant: { caveats: ['window', 'amount_cap'], max_esc: 2, preauth_esc: 1 }, context: [] }]);
    expect(e.calls.schemaError).toEqual([[S2, { keys: ['rv'] }]]);
  });
  it('the call context is passed through', () => {
    const e = engine();
    decideIntentV2(VIEW, grantWith({ actions: PIN }), ctxOf({ rule22: e.rule22, call_context: ['c1'] }), NOW);
    expect((e.calls.decide[0] as { context: unknown }).context).toEqual(['c1']);
  });
  it('escalate and deny from the engine each have their own reason', () => {
    expect(decideIntentV2(VIEW, grantWith({ actions: PIN }), ctxOf({ rule22: engine('escalate').rule22 }), NOW).checks).toEqual([
      { name: 'pin', ok: true },
      { name: 'traits', ok: false, reason: 'escalate: the action floors need a caveat, context or confirmation the grant does not provide (rule 22)' },
    ]);
    expect(decideIntentV2(VIEW, grantWith({ actions: PIN }), ctxOf({ rule22: engine('deny').rule22 }), NOW).checks).toEqual([
      { name: 'pin', ok: true },
      { name: 'traits', ok: false, reason: 'the action floors exceed what the grant authorizes (rule 22)' },
    ]);
  });
  it('a forged floor is refused by name; no engine is a fail-closed refusal (the traits check then has no schema to run on)', () => {
    expect(decideIntentV2(VIEW, grantWith({ actions: PIN }), ctxOf({ rule22: engine('allow', 'forged floors').rule22 }), NOW).checks).toEqual([{ name: 'pin', ok: false, reason: 'schema_floor_forged: forged floors' }]);
    expect(decideIntentV2(VIEW, grantWith({ actions: PIN }), ctxOf(), NOW).checks).toEqual([{ name: 'pin', ok: false, reason: 'schema_floor_unchecked: a v2 schema needs the rule 22 trait engine to check its floors (fail closed)' }]);
  });
  it('no schema configured: the pin check fails and decideIntentV2 does not throw', () => {
    expect(decideIntentV2(VIEW, grantWith({ actions: PIN }), { rule22: engine().rule22 } as never, NOW).checks).toEqual([{ name: 'pin', ok: false, reason: 'this verifier has no action schema configured' }]);
  });
  it('a changed definition is refused with the pin reason; the traits check still runs', () => {
    const doc = schemaV2(D2);
    const d = decideIntentV2(VIEW, grantWith({ actions: PIN }), ctxOf({ rule22: engine().rule22 }, [doc]), NOW);
    expect(d.checks).toEqual([{ name: 'pin', ok: false, reason: pinReason(doc) }, { name: 'traits', ok: true }]);
    expect(pinReason(doc)).toMatch(/^def_changed: /);
  });
  it('a narrow chain of registry-signed records moves the pin (records and keys from the context)', () => {
    const doc = schemaV2(D2);
    const actions = { records: [rec(D, D2, 'narrow')], keys: REG_KEYS };
    expect(decideIntentV2(VIEW, grantWith({ actions: PIN }), ctxOf({ rule22: engine().rule22, actions }, [doc]), NOW).checks).toEqual([{ name: 'pin', ok: true }, { name: 'traits', ok: true }]);
  });
  it('a widen step needs the principal reapproval bound to this grant; without it the reason names the diff', () => {
    const doc = schemaV2(D2);
    const r = rec(D, D2, 'widen');
    const a = signReapproval({ grantId: GRANT_ID, record: r, principalSecret: PRINCIPAL });
    const ok = decideIntentV2(VIEW, grantWith({ actions: PIN }), ctxOf({ rule22: engine().rule22, actions: { records: [r], keys: REG_KEYS, reapprovals: [a] } }, [doc]), NOW);
    expect(ok.checks).toEqual([{ name: 'pin', ok: true }, { name: 'traits', ok: true }]);
    const blocked = decideIntentV2(VIEW, grantWith({ actions: PIN }), ctxOf({ rule22: engine().rule22, actions: { records: [r], keys: REG_KEYS } }, [doc]), NOW);
    const why = pinReason(doc, { records: [r], keys: REG_KEYS });
    expect(why).toBe(`def_changed: ${(decidePin({ pin: PIN, doc, verb: VERB, records: [r], keys: REG_KEYS, grant: { id: GRANT_ID, issuer: ISSUER } }) as { reason: string }).reason} (re-approve diff ${evolutionDiffDigest(r)})`);
    expect(blocked.checks[0]).toEqual({ name: 'pin', ok: false, reason: why });
  });
  it("a verb the pin does not name with on_new_action 'escalate' is an escalate-class reason", () => {
    const pin = { ...PIN, defs: { 'acme.x.y': D }, on_new_action: 'escalate' };
    const d = decideIntentV2(VIEW, grantWith({ actions: pin }), ctxOf({ rule22: engine().rule22 }), NOW);
    expect(d.checks[0]).toEqual({ name: 'pin', ok: false, reason: pinReason(S2, {}, pin) });
    expect(pinReason(S2, {}, pin)).toMatch(/^escalate: new_action: /);
  });
  it('a malformed pin fails the pin check and contributes no caveats or floors to the engine', () => {
    const e = engine();
    const bad = { ...PIN, extra: 1 };
    const d = decideIntentV2(VIEW, grantWith({ actions: bad }), ctxOf({ rule22: e.rule22 }), NOW);
    expect(d.checks.map((c) => [c.name, c.ok])).toEqual([['pin', false], ['traits', true]]);
    expect(d.checks[0]!.reason).toMatch(/^bad_pin: /);
    expect(e.calls.decide).toEqual([{ doc: S2, verb: VERB, grant: { caveats: ['window'], max_esc: 3, preauth_esc: 0 }, context: [] }]);
  });
  it('an engine that is gone by the traits check (a context getter) fails closed with its own reason', () => {
    let gone = false;
    const rule22 = { schemaError: () => ((gone = true), null), decide: () => 'allow' };
    const ctx = ctxOf();
    Object.defineProperty(ctx, 'rule22', { get: () => (gone ? undefined : rule22), enumerable: true });
    expect(decideIntentV2(VIEW, grantWith({ actions: PIN }), ctx, NOW).checks).toEqual([{ name: 'pin', ok: true }, { name: 'traits', ok: false, reason: 'schema_floor_unchecked: no rule 22 trait engine (fail closed)' }]);
  });
  it('a pin over a v1 schema runs no traits check', () => {
    expect(names(decideIntentV2(VIEW, grantWith({ actions: PIN }), ctxOf({ rule22: engine().rule22 }, [SCHEMA_V1]), NOW))).toEqual(['pin']);
  });
});

describe('decideIntentV2: a closed-world v2 schema', () => {
  it('without an envelope: traits runs with the default floors and no caveats or context', () => {
    const e = engine();
    const d = decideIntentV2(VIEW, grantWith(null), ctxOf({ rule22: e.rule22, policy: { schema: { closed_world: true } } }), NOW);
    expect(d.checks).toEqual([{ name: 'schema', ok: true }, { name: 'traits', ok: true }]);
    expect(e.calls.decide).toEqual([{ doc: S2, verb: VERB, grant: { caveats: [], max_esc: 3, preauth_esc: 0 }, context: [] }]);
  });
  it('with a pin: the schema already checked is reused (the floor check runs once) and the pin passes', () => {
    const e = engine();
    const d = decideIntentV2(VIEW, grantWith({ actions: PIN }), ctxOf({ rule22: e.rule22, policy: { schema: { closed_world: true } } }), NOW);
    expect(d.checks).toEqual([{ name: 'schema', ok: true }, { name: 'pin', ok: true }, { name: 'traits', ok: true }]);
    expect(e.calls.schemaError).toHaveLength(1);
  });
});

describe('decideIntentV2: rule 21 triggers', () => {
  const MODEL = (field: string) => [{ verb: '*', where: [{ field, op: 'eq', value: 'a' }] }];
  const reads = (p: string) => `a grant's where reads model-derived path(s) ${p}: a model may only tighten (move them into tighten[]) (rule 21)`;
  it('each ceiling layer (org, site, std) contributes its predicates', () => {
    for (const k of ['org', 'site', 'std']) {
      const d = decideIntentV2(VIEW, grantWith(null), { layers: { [k]: { predicates: MODEL('env.class.x') } } } as never, NOW);
      expect(d.checks, k).toEqual([{ name: 'tighten', ok: false, reason: reads('env.class.x') }]);
    }
  });
  it('env.world itself is not model-derived when no world is single-sourced', () => {
    expect(decideIntentV2(VIEW, grantWith(null), { layers: { org: { predicates: [{ verb: '*', where: [{ field: 'env.world', op: 'exists' }] }] } } } as never, NOW).checks).toEqual([]);
  });
  it("policy model_polarity 'strict' alone reports the check (with no envelope)", () => {
    expect(decideIntentV2(VIEW, grantWith(null), { policy: { model_polarity: 'strict' } } as never, NOW).checks).toEqual([{ name: 'tighten', ok: true }]);
  });
  it('an envelope tighten list with no verifier context', () => {
    expect(decideIntentV2(VIEW, grantWith({ tighten: [] }), undefined, NOW).checks).toEqual([{ name: 'tighten', ok: true }]);
  });
  it("a tighten rule reads the verifier-computed env (env.canon from the schema check)", () => {
    const tighten = [{ id: 't1', when: { field: 'env.canon.flag', op: 'eq', value: 'true' }, signal: 'deny' }];
    const d = decideIntentV2(VIEW, grantWith({ tighten }), ctxOf({ policy: { schema: { closed_world: true } } }, [SCHEMA_V1]), NOW);
    expect(d.checks).toEqual([{ name: 'schema', ok: true }, { name: 'tighten', ok: false, reason: "denied by tighten rule 't1'" }]);
  });
});

describe('decideIntentV2: single-source worlds', () => {
  const cases: Array<{ name: string; now: number; p: string; grant: string; ctx: string }> = JSON.parse(gunzipSync(readFileSync(resolve(__dirname, '..', 'testdata', 'k042-intentv2-r13-subset.json.gz'))).toString('utf8')).cases;
  const c = cases.find((x) => x.name === 'wb16/wb16-single-source')!;
  it('the decision lists them, and a ceiling reading such a world is a model-derived read', () => {
    const p = JSON.parse(c.p);
    const g = JSON.parse(c.grant);
    const ctx = JSON.parse(c.ctx);
    expect(decideIntentV2(p, g, ctx, c.now).single_source).toEqual(['fare']);
    const d = decideIntentV2(p, g, { ...ctx, layers: { org: { predicates: [{ verb: '*', where: [{ field: 'env.world.fare', op: 'lte', value: 5 }] }] } } }, c.now);
    expect(d.checks.find((k) => k.name === 'tighten')?.reason).toMatch(/model-derived path\(s\) env\.world\.fare:/);
  });
});

describe('intent-acc: scopes', () => {
  const decl = { id: 'q', agg: 'count', sel: { event: 'intent_required' }, win: { kind: 'task' }, key: null, cap: 6, holder: { kind: 'wallet' }, domain_max: 10 };
  it('the published scope list', () => {
    expect(ACC_SCOPES).toEqual(['session', 'principal', 'org', 'fleet']);
  });
  it('every scope but session needs a site_local holder', () => {
    for (const scope of ['principal', 'org', 'fleet']) expect(accumulatorDeclError({ ...decl, scope }), scope).toBe(`accumulator 'q': a ${scope}-scoped accumulator has a site_local holder (the ledger is the holder)`);
    expect(accumulatorDeclError({ ...decl, scope: 'session' })).toBeNull();
    expect(accumulatorDeclError({ ...decl, scope: 'galaxy' })).toBe("accumulator 'q': unknown scope");
  });
});

describe('intent-binding: v3 goals', () => {
  const ref = { goal_digest: d32(1), policy_digest: d32(2) };
  it('the v3 goal string carries the published prefix', () => {
    expect(INTENT_GOAL_V3_PREFIX).toBe('pca-intent:v3:');
    expect(intentGoalV3(ref)).toBe(`pca-intent:v3:${d32(1)}:${d32(2)}`);
  });
  it('a missing approved goal is not one (never a throw)', () => {
    expect(isApprovedGoalRef(undefined)).toBe(false);
    expect(isApprovedGoalRef('ab')).toBe(false);
  });
  it('a root commitment that does not open to the approved goal is refused with the v3 reason', () => {
    const intent = { ref: d32(3), map_digest: d32(4), goal_salt: 's', fidelity_ppm: 1_000_000, residual_risk_ppm: 0 };
    expect(decideIntentBinding(intent, { caveats: [{ type: 'envelope', goal_commit: 'not-it' }] }, { approved_goal: ref })).toEqual({
      status: 'fail',
      reason: "the root grant's goal commitment does not open to the approved goal and compiled policy (v3)",
    });
  });
});

describe('verifyIntentRequiredAt', () => {
  const body = {
    v: 1 as const, kind: 'pca-intent-required' as const, session: d32(1), map_digest: d32(2), schema: d32(3), pcactn_digest: d32(4), action_digest: d32(5),
    cell: { verb: VERB, coords: { 'env.acc.trip_spend.post': [2, 3] as [number, number] } }, reason: 'uncertain' as const, question_id: 'q_1', friction: 'typed' as const, delivered_to: 'wallet' as const, expires_at: NOW + 1000,
  };
  const s = signIntentRequired(body, 'k1', SITE);
  it('a valid body under a safe-integer clock verifies', () => {
    expect(verifyIntentRequiredAt(s, KEYS, NOW)).toEqual({ ok: true });
  });
  it('a clock that is not a safe integer is refused with the exact result', () => {
    for (const now of [Number.NaN, 1.5, '1' as never, undefined as never]) expect(verifyIntentRequiredAt(s, KEYS, now)).toEqual({ ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' });
  });
});
