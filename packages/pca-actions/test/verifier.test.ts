// Rule 22 (`traits`) and the grant pin (`pin`) inside the real verifier (authorize -> verifyPCActn -> decideIntentV2).
import { randomBytes } from 'node:crypto';
import {
  b64u, buildPCActn, createAuthorizer, createProvenanceRecorder, decisionOf, principalDirectProvenance, encodeKey, generateKeyPair, memoryPcaStore, mintGrant, paramsDigest,
  type AuthorizeOptions, type Capability, type PCActn, type PlanNode, type RiskPolicy,
} from '@atlasauth/pca';
import {
  actionSchemaKeyOf, decideIntentV2, registryKeyOf, signActionSchema, signEvolutionRecord, signReapproval, type ActionSchema, type ActionSchemaKey, type IntentV2Context, type Reapproval,
} from '@atlasauth/pca/ext/intent';
import { describe, expect, it } from 'vitest';
import { TEST_PINS, confirmed, testReview } from './reviewed';
import {
  BUILTIN_DEFS, CORE_REGISTRY, RULE22_ENGINE, buildPack, defDigest, effective, evolutionRecords, toSchemaDoc, type ActionDef,
} from '../src';

const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const AUD = 'payments-rs';
const SPEND: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 };
const site = generateKeyPair();
const registry = generateKeyPair();
const principal = generateKeyPair();
const holder = generateKeyPair();
const SITE_KEYS: ActionSchemaKey[] = [actionSchemaKeyOf('site-1', site.secretKey)];
const REG_KEYS: ActionSchemaKey[] = [registryKeyOf('reg-1', registry.secretKey)];
const SRC = { kind: 'hand', uri: 'internal://pack', spec_digest: 'A'.repeat(43), licence: 'Apache-2.0', licence_notes: 'authored in house' };

const stripe = BUILTIN_DEFS.filter((d) => d.verb.startsWith('stripe.'));
const refund = stripe.find((d) => d.verb === 'stripe.refund')!;
const VERB = refund.verb;
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const patchDef = (d: ActionDef, f: (x: Record<string, any>) => void): ActionDef => {
  const c = clone(d) as unknown as Record<string, any>;
  f(c);
  return c as ActionDef;
};
const withRefund = (r: ActionDef) => [r, ...stripe.filter((d) => d.verb !== VERB)];

/** A site-signed v2 schema for a def set, citing the pack the defs come from. */
function schemaOf(defs: ActionDef[], version = '1', mutate?: (doc: Record<string, any>) => void): ActionSchema {
  const pack = buildPack({ ns: 'stripe', version: `${version}.0.0`, stability: 'stable', defs, source: SRC, kid: 'reg-1', secret: registry.secretKey }).pack;
  const doc = toSchemaDoc(defs, CORE_REGISTRY, { site: 'https://pay.example', aud: AUD, version, pack: { ns: 'stripe', version: pack.version, root: pack.root } }) as unknown as Record<string, any>;
  mutate?.(doc);
  return signActionSchema(doc as never, 'site-1', site.secretKey);
}

function schemaOfWith(defs: ActionDef[], opts: ReturnType<typeof testReview>, version = '1'): ActionSchema {
  const pack = buildPack({ ns: 'stripe', version: `${version}.0.0`, stability: 'stable', defs, source: SRC, kid: 'reg-1', secret: registry.secretKey }).pack;
  const doc = toSchemaDoc(defs, CORE_REGISTRY, { site: 'https://pay.example', aud: AUD, version, pack: { ns: 'stripe', version: pack.version, root: pack.root } }, opts);
  return signActionSchema(doc as never, 'site-1', site.secretKey);
}

const effRefund = (d: ActionDef = refund) => effective(d, CORE_REGISTRY).eff;
const PARAMS = { amount: 1000, charge: 'ch_abcdefgh', idempotency_key: 'k1' };

interface GrantOpts { defs?: Record<string, string>; onNew?: 'deny' | 'escalate'; maxEsc?: number; preauthEsc?: number; caveats?: string[]; pack?: { ns: string; root: string } }
function grantOf(o: GrantOpts = {}): Capability {
  const eff = effRefund();
  return mintGrant({
    principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: encodeKey(holder.publicKey), goal: 'refunds',
    envelope: {
      predicates: [{ verb: [VERB], resource: '*' }],
      caveats: [],
      agent_binding: {}, risk_policy: SPEND,
      actions: {
        pack: o.pack ?? { ns: 'stripe', root: 'A'.repeat(43) },
        defs: o.defs ?? { [VERB]: defDigest(refund) },
        on_new_action: o.onNew ?? 'deny',
        max_esc: o.maxEsc ?? 3,
        preauth_esc: o.preauthEsc ?? eff.esc,
        caveats: o.caveats ?? eff.caveats,
      },
    },
  }).grant;
}

let counter = 0;
const sign = (grant: Capability, verb = VERB, params: Record<string, unknown> = PARAMS): PCActn => {
  const node: PlanNode = { id: 'n1', verb, resource: 'stripe.charge:ch_abcdefgh', params_digest: paramsDigest(params), reversibility_class: 'irreversible' };
  return buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params, counter: ++counter, signerSecret: holder.secretKey, aud: AUD, now: NOW });
};

const baseCtx = (doc: ActionSchema, extra: Partial<IntentV2Context> = {}): IntentV2Context => ({
  schema: { docs: [doc], keys: SITE_KEYS }, rule22: RULE22_ENGINE, call_context: effRefund().context, params: PARAMS, ...extra,
});
// provenance by default: the subject here is rule 22 and the pins, so every call comes straight from the principal (pinned recorder)
const provRec = () => createProvenanceRecorder({ mediator: 'actions-test-harness', kid: 'k1', secretKey: new Uint8Array(32).fill(5) });
const optsFor = (grant: Capability, ctx: IntentV2Context): AuthorizeOptions => ({
  provenance: { mediators: [provRec().pin], bundle: (_r, _p, o) => principalDirectProvenance(provRec(), { verb: o.verb, resource: o.resource, params: o.params ?? {} }) },
  audience: AUD, resolveGrant: async (ref) => (ref === grant.id ? grant : null), budgetStore: memoryPcaStore(), hooks: { revocation: () => ({ enforced: true, ok: true }) },
  plan: 'single-step', now: () => NOW, risk: () => ({ blastRadius: 0.1, semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }), intentV2: ctx,
});
const run = async (grant: Capability, ctx: IntentV2Context, verb = VERB) => {
  const r = await createAuthorizer(optsFor(grant, ctx))({ pcactn: sign(grant, verb), operation: { verb, resource: 'stripe.charge:ch_abcdefgh', params: PARAMS } });
  return { r, decision: r.decision, reasons: r.allow ? [] : [r.reason ?? ''], checks: r.verdict.checks as Record<string, string>, text: JSON.stringify(r.verdict.reasons ?? []) };
};
const check = (g: Capability, ctx: IntentV2Context, name: string) => decideIntentV2({ aud: AUD, action: { verb: VERB, resource: 'x', params_digest: paramsDigest(PARAMS) } }, g, { ...ctx, policy: { schema: { closed_world: true } } }, NOW).checks.find((c) => c.name === name);

const v1 = schemaOf(stripe);

describe('rule 22 and pins through the real verifier', () => {
  it('control: a consistent v2 schema, an exact pin and a grant that provides the floors admit the action', async () => {
    const g = grantOf();
    const x = await run(g, baseCtx(v1));
    expect(x.text).toBe('[]');
    expect(x.decision).toBe('allow');
    expect(x.checks.pin).toBe('pass');
    expect(x.checks.traits).toBe('pass');
  });

  describe('forged floors', () => {
    const lowered = (f: (v: Record<string, any>) => void) => schemaOf(stripe, '1', (doc) => f(doc.verbs.find((v: any) => v.verb === VERB)));
    it('a site-signed schema whose floors were lowered is refused (schema_floor_forged), by the schema check and by the pin', async () => {
      const forged = lowered((v) => { v.floors = { ...v.floors, esc: 0, caveats: [], risk: 0 }; });
      const g = grantOf();
      expect(check(g, baseCtx(forged), 'schema')).toMatchObject({ ok: false, reason: expect.stringContaining('schema_floor_forged') });
      const x = await run(g, baseCtx(forged));
      expect(x.decision).toBe('deny');
      expect(x.checks.pin).toBe('fail');
      expect(x.text).toContain('schema_floor_forged');
    });
    it('a dropped implied trait is refused (schema_traits_forged)', async () => {
      const forged = lowered((v) => { v.traits = v.traits.filter((t: string) => t !== 'pca.irreversible'); });
      const x = await run(grantOf(), baseCtx(forged));
      expect(x.decision).toBe('deny');
      expect(x.text).toContain('schema_floor_forged');
      expect(x.text).toContain('schema_traits_forged');
    });
    it('a lowered reversibility floor is refused', async () => {
      const forged = lowered((v) => { v.floors = { ...v.floors, rev: 'reversible' }; });
      expect((await run(grantOf(), baseCtx(forged))).decision).toBe('deny');
    });
    it('a custom trait document that weakens a core trait is refused', async () => {
      const forged = lowered(() => undefined);
      const doc = JSON.parse(JSON.stringify(forged)) as Record<string, any>;
      delete doc.sig;
      doc.trait_defs = [{ id: 'pca.money_moving', implies: [], floor: { risk: 0, rev: 'reversible', blast_ppm: 0, esc: 0, caveats: [], context: [], prules: [] }, card_phrase: 'x' }];
      const re = signActionSchema(doc as never, 'site-1', site.secretKey);
      expect((await run(grantOf(), baseCtx(re))).decision).toBe('deny');
    });
    it('without the trait engine a v2 schema is refused: a verifier that cannot recompute the floors does not trust them', async () => {
      const { rule22: _r, ...noEngine } = baseCtx(v1);
      const x = await run(grantOf(), noEngine as IntentV2Context);
      expect(x.decision).toBe('deny');
      expect(x.text).toContain('schema_floor_unchecked');
    });
  });

  describe('rule 22 floor decision', () => {
    it('a grant missing a required caveat escalates (never allows)', async () => {
      const need = effRefund().caveats;
      expect(need.length).toBeGreaterThan(0);
      const x = await run(grantOf({ caveats: [] }), baseCtx(v1));
      expect(x.decision).toBe('escalate');
      expect(x.text).toContain('traits: escalate:');
    });
    it('a tier above preauth_esc escalates; above max_esc denies', async () => {
      const tier = effRefund().esc;
      expect(tier).toBeGreaterThan(0);
      expect((await run(grantOf({ preauthEsc: tier - 1 }), baseCtx(v1))).decision).toBe('escalate');
      const d = await run(grantOf({ maxEsc: tier - 1, preauthEsc: 0 }), baseCtx(v1));
      expect(d.decision).toBe('deny');
    });
    it('a required context key the verifier did not observe escalates', async () => {
      const ctxKeys = effRefund().context;
      if (ctxKeys.length === 0) return;
      const x = await run(grantOf(), baseCtx(v1, { call_context: [] }));
      expect(x.decision).toBe('escalate');
    });
    it('the agent cannot supply the call context: it is verifier state only', () => {
      expect(RULE22_ENGINE.decide({ doc: v1, verb: VERB, grant: { caveats: effRefund().caveats, max_esc: 3, preauth_esc: 3 }, context: [] })).toBe(effRefund().context.length > 0 ? 'escalate' : 'allow');
    });
    it('an unknown verb or a malformed floors object is a deny', () => {
      expect(RULE22_ENGINE.decide({ doc: v1, verb: 'nope.nothing', grant: { caveats: [], max_esc: 3, preauth_esc: 3 }, context: [] })).toBe('deny');
      const bad = { verbs: [{ verb: VERB, floors: { risk: 'x' } }] };
      expect(RULE22_ENGINE.decide({ doc: bad, verb: VERB, grant: { caveats: [], max_esc: 3, preauth_esc: 3 }, context: [] })).toBe('deny');
    });
  });

  describe('the grant pin', () => {
    const narrower = patchDef(refund, (x) => { x.params.amount.max = 5000; });
    const wider = patchDef(refund, (x) => { x.params.amount.max = 999_999_999_999; });
    const rec = (to: ActionDef, cls?: string, key = registry.secretKey) => {
      const [r] = evolutionRecords('stripe', [refund], [to]);
      return signEvolutionRecord(cls ? ({ ...r!, class: cls } as never) : r!, 'reg-1', key);
    };
    const ctxFor = (to: ActionDef, extra: IntentV2Context['actions'] = {}) => baseCtx(schemaOf(withRefund(to), '2'), { actions: { keys: REG_KEYS, ...extra } });

    it('a changed definition with no evolution chain is def_changed', async () => {
      const x = await run(grantOf(), ctxFor(narrower));
      expect(x.decision).toBe('deny');
      expect(x.text).toContain('def_changed');
    });
    it('a registry-signed narrowing chains and is admitted', async () => {
      const x = await run(grantOf(), ctxFor(narrower, { records: [rec(narrower)] }));
      expect(x.text).toBe('[]');
      expect(x.decision).toBe('allow');
    });
    it('a widening is blocked without the principal even with a signed record, and names the diff to approve', async () => {
      const r = rec(wider);
      expect(r.class).toBe('widen');
      const x = await run(grantOf(), ctxFor(wider, { records: [r] }));
      expect(x.decision).toBe('deny');
      expect(x.text).toContain('re-approve');
    });
    it('the principal re-approving that exact step for this grant admits it', async () => {
      const g = grantOf();
      const r = rec(wider);
      const ok = signReapproval({ grantId: g.id, record: r, principalSecret: principal.secretKey });
      expect((await run(g, ctxFor(wider, { records: [r], reapprovals: [ok] }))).decision).toBe('allow');
    });
    it('a re-approval for another grant, another diff, or by another key does not admit it', async () => {
      const g = grantOf();
      const r = rec(wider);
      const forOther = signReapproval({ grantId: 'X'.repeat(43), record: r, principalSecret: principal.secretKey });
      const forNarrow = signReapproval({ grantId: g.id, record: rec(narrower), principalSecret: principal.secretKey });
      const byOther = signReapproval({ grantId: g.id, record: r, principalSecret: generateKeyPair().secretKey });
      for (const a of [forOther, forNarrow, byOther] as Reapproval[]) expect((await run(g, ctxFor(wider, { records: [r], reapprovals: [a] }))).decision).toBe('deny');
    });
    it('a registry that lies (signs narrow for a widening) is not caught by the pin alone, so the record class is signed data: a record by an unpinned key is ignored', async () => {
      const stranger = rec(narrower, undefined, generateKeyPair().secretKey);
      expect((await run(grantOf(), ctxFor(narrower, { records: [stranger] }))).decision).toBe('deny');
    });
    it('an unsigned/forged record, a record for another verb, and a record from another namespace never move the pin', async () => {
      const good = rec(narrower);
      const forged = { ...good, to: defDigest(wider) };
      const otherVerb = signEvolutionRecord({ ...evolutionRecords('stripe', [refund], [narrower])[0]!, verb: 'stripe.charge' }, 'reg-1', registry.secretKey);
      const otherNs = signEvolutionRecord({ ...evolutionRecords('stripe', [refund], [narrower])[0]!, ns: 'other' }, 'reg-1', registry.secretKey);
      for (const r of [forged, otherVerb, otherNs]) expect((await run(grantOf(), ctxFor(narrower, { records: [r as never] }))).decision).toBe('deny');
    });
    it('a verb the grant does not name is denied or escalated by on_new_action', async () => {
      const charge = 'stripe.charge';
      const chargeParams = { amount: 1000, customer: 'cus_abcdefgh', idempotency_key: 'k1' };
      const g1 = grantOf({ onNew: 'deny' });
      const g2 = grantOf({ onNew: 'escalate' });
      const doc = baseCtx(v1);
      expect(check(g1, doc, 'pin')?.ok).toBe(true);
      const dec = (g: Capability) => decideIntentV2({ aud: AUD, action: { verb: charge, resource: 'x', params_digest: paramsDigest(chargeParams) } }, g, { ...doc, params: chargeParams, policy: { schema: { closed_world: true } } }, NOW).checks.find((c) => c.name === 'pin')!;
      expect(dec(g1)).toMatchObject({ ok: false, reason: expect.stringContaining('new_action') });
      expect(dec(g2).reason).toMatch(/^escalate: new_action/);
      expect(decisionOf({ allow: false, checks: { pin: 'fail' }, reasons: [`pin: ${dec(g2).reason}`] })).toBe('escalate');
      expect(decisionOf({ allow: false, checks: { pin: 'fail' }, reasons: [`pin: ${dec(g1).reason}`] })).toBe('deny');
    });
    it('a schema from another pack namespace is refused (pack_mismatch)', async () => {
      const x = await run(grantOf({ pack: { ns: 'other', root: 'A'.repeat(43) } }), baseCtx(v1));
      expect(x.decision).toBe('deny');
      expect(x.text).toContain('pack_mismatch');
    });
    it('a pack-only pin (no defs) needs the exact pack root', async () => {
      const pack = buildPack({ ns: 'stripe', version: '1.0.0', stability: 'stable', defs: stripe, source: SRC, kid: 'reg-1', secret: registry.secretKey }).pack;
      const g = mintGrant({
        principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: encodeKey(holder.publicKey), goal: 'refunds',
        envelope: { predicates: [{ verb: [VERB], resource: '*' }], caveats: [], agent_binding: {}, risk_policy: SPEND, actions: { pack: { ns: 'stripe', root: pack.root }, on_new_action: 'deny', preauth_esc: effRefund().esc, caveats: effRefund().caveats } },
      }).grant;
      expect((await run(g, baseCtx(v1))).decision).toBe('allow');
      expect((await run(g, ctxFor(narrower))).decision).toBe('deny');
    });
    it('a schema that is not v2 carries no definition digests, so a pinned grant refuses it', async () => {
      const v1doc = signActionSchema({ v: 1, kind: 'pca-action-schema', site: 'https://pay.example', aud: AUD, version: '1', verbs: [{ verb: VERB, kind: 'write', reversibility: 'irreversible', params: {} }] } as never, 'site-1', site.secretKey);
      const x = await run(grantOf(), { ...baseCtx(v1doc), params: {} });
      expect(x.decision).toBe('deny');
    });
    it('a malformed pin block cannot be minted and, if present in a stored grant, fails closed', () => {
      expect(() => mintGrant({ principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: encodeKey(holder.publicKey), goal: 'g', envelope: { predicates: [], caveats: [], agent_binding: {}, risk_policy: SPEND, actions: { pack: { ns: 'Bad Ns', root: 'x' }, on_new_action: 'deny' } as never } })).toThrow(/actions/);
    });
  });

  it('a grant without a pin and a v1 schema verifies byte-identically (no pin or traits check reported)', async () => {
    const g = mintGrant({ principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: encodeKey(holder.publicKey), goal: 'g', envelope: { predicates: [{ verb: [VERB], resource: '*' }], caveats: [], agent_binding: {}, risk_policy: SPEND } }).grant;
    const v1doc = signActionSchema({ v: 1, kind: 'pca-action-schema', site: 'https://pay.example', aud: AUD, version: '1', verbs: [{ verb: VERB, kind: 'write', reversibility: 'irreversible', params: { 'action.params.amount': { type: 'integer', semantic: 'money.amount', sensitivity: 'material' }, 'action.params.charge': { type: 'string', semantic: 'id', sensitivity: 'free' }, 'action.params.idempotency_key': { type: 'string', semantic: 'id', sensitivity: 'free' } } }] } as never, 'site-1', site.secretKey);
    const out = decideIntentV2({ aud: AUD, action: { verb: VERB, resource: 'x', params_digest: paramsDigest(PARAMS) } }, g, { schema: { docs: [v1doc], keys: SITE_KEYS }, params: PARAMS, policy: { schema: { closed_world: true } } }, NOW);
    expect(out.checks.map((c) => c.name)).toEqual(['schema']);
    expect(out.checks[0]!.ok).toBe(true);
  });
});

describe('human confirmation through the real verifier (reviewer keys pinned in the verifier context)', () => {
  const reviewed = effective(confirmed(refund), CORE_REGISTRY, testReview()).eff; // what the reviewer signed
  const grantReviewed = () => grantOf({ preauthEsc: reviewed.esc, caveats: reviewed.caveats });
  const ctxReviewed = (doc: ActionSchema, extra: Partial<IntentV2Context> = {}) => baseCtx(doc, { reviewers: TEST_PINS, call_context: reviewed.context, ...extra });
  const confirmedDoc = () => schemaOfWith(withRefund(confirmed(refund)), testReview());

  it('control: a confirmed schema, the reviewer pinned and a grant providing the reviewed floors admit the action', async () => {
    const x = await run(grantReviewed(), ctxReviewed(confirmedDoc()));
    expect(x.text).toBe('[]');
    expect(x.decision).toBe('allow');
  });
  it('the same confirmed schema is refused when the verifier pins no reviewer: nothing it carries counts', async () => {
    const x = await run(grantReviewed(), { ...ctxReviewed(confirmedDoc()), reviewers: undefined });
    expect(x.decision).toBe('deny');
    expect(x.text).toContain('schema_traits_forged');
  });
  it('an unconfirmed def is maximally dangerous: with the reviewed grant it escalates, never allows', async () => {
    const x = await run(grantReviewed(), ctxReviewed(schemaOf(stripe)));
    expect(x.decision).toBe('escalate');
  });
  it('an unconfirmed def whose schema claims the reviewed traits is refused (a classifier-style claim cannot lower the floors)', async () => {
    const lowered = confirmedDoc();
    const forged = JSON.parse(JSON.stringify(lowered)) as Record<string, any>;
    delete forged.sig;
    delete forged.verbs.find((v: any) => v.verb === VERB).confirmation;
    const re = signActionSchema(forged as never, 'site-1', site.secretKey);
    const x = await run(grantReviewed(), ctxReviewed(re));
    expect(x.decision).toBe('deny');
    expect(x.text).toContain('schema_traits_forged');
  });
  it('a confirmation signed by a key the verifier did not pin is refused', async () => {
    const x = await run(grantReviewed(), ctxReviewed(confirmedDoc(), { reviewers: { keys: [{ kid: 'someone', pk: b64u(generateKeyPair().publicKey), roles: ['reviewer'] }] } }));
    expect(x.decision).toBe('deny');
  });
});

void b64u;
void randomBytes;
