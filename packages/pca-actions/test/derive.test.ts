import { generateKeyPair } from '@atlasauth/pca';
import { actionSchemaKeyOf, actionSchemaShapeError, conformAction, signActionSchema, verifyActionSchema, type ActionSchema, type ActionVerbDecl } from '@atlasauth/pca/ext/intent';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  BUILTIN_DEFS, CORE_REGISTRY, cardOf, defDigest, effective, effectClass, escalationOf, extendRegistry, flattenParams, mcpAnnotationsOf, operationOf, paramByRole, predicatesOf, riskOf,
  registryOfSchema, schemaFloorError, schemaVerbFloorError, toOntology, toSchemaDoc, toSchemaVerb, traitsDigest, validateDef, CORE_TRAIT_DEFS, CORE_TRAIT_IDS, CORE_ROLES, EFFECTS, CAVEAT_KINDS, CONTEXT_KEYS, PARAM_RULE_IDS, PARAM_TAGS, PROVENANCE_LEVELS,
  type ActionDef,
} from '../src';
import { SCHEMA_V2_CAVEATS, SCHEMA_V2_CONTEXT, SCHEMA_V2_EFFECTS, SCHEMA_V2_PRULES, SCHEMA_V2_PROVENANCE, SCHEMA_V2_TAGS } from '@atlasauth/pca/ext/intent';
import { arbDef } from './arb';
import { runs } from './runs';
import { TEST_PINS, confirmed, eff as effOf, testReview } from './reviewed';
const T = testReview();

const refund = BUILTIN_DEFS.find((d) => d.verb === 'stripe.refund')!;
const invoice: ActionDef = {
  v: 1, kind: 'pca-action-def', verb: 'acme.invoice.send', title: 'Send an invoice', effects: ['send'],
  resource: { type: 'acme.invoice', id: { prefix: 'inv_', class: 'alnum', len: [8, 32] }, scope: 'one' },
  params: {
    invoice: { type: 'string', role: 'id.acme.invoice', max_len: 64 },
    to: { type: 'string', role: 'contact.email', format: 'email', tags: ['pii'], max_len: 254 },
    note: { type: 'string', max_len: 500 },
  },
  bindings: { mcp: { tool: 'send_invoice' }, openapi: { operationId: 'sendInvoice' } },
  review: { state: 'authored' },
};
const customer: ActionDef = { ...invoice, verb: 'acme.customer.update', title: 'Update a customer', effects: ['update'], reversibility: 'reversible', resource: { type: 'acme.customer', id: '*', scope: 'set' }, params: {
  'customer.email': { type: 'string', role: 'contact.email', format: 'email', max_len: 254, required: false },
  'customer.name': { type: 'string', max_len: 100 },
  when: { type: 'datetime' }, ttl: { type: 'duration', max: 86_400_000 }, ref: { type: 'object_ref', format: 'id:acme.customer' },
}, bindings: undefined } as unknown as ActionDef;

describe('signed schema v2', () => {
  const doc = toSchemaDoc([confirmed(invoice, CORE_REGISTRY), confirmed(refund, CORE_REGISTRY)], CORE_REGISTRY, { site: 'https://api.example.com', aud: 'example', version: '1' }, T);
  it('derives a valid v2 document with normative effects, traits, def digest and materialized floors', () => {
    expect(actionSchemaShapeError(doc, { signed: false })).toBeNull();
    expect(doc.v).toBe(2);
    expect(doc.verbs.map((v) => v.verb)).toEqual(['acme.invoice.send', 'stripe.refund']);
    const v = doc.verbs[0]!;
    expect(v.effects).toEqual(['send']);
    expect(v.traits).toEqual(['pca.external_communication', 'pca.irreversible', 'pca.pii_access']);
    expect(v.def).toBe(defDigest(invoice));
    expect(v.floors).toEqual({ risk: 2, rev: 'irreversible', blast_ppm: 50_000, esc: 1, caveats: ['rate_cap', 'recipient_scope', 'resource_scope'], context: ['fresh_revocation'], prules: ['recipient_param_declared'] });
    expect(v.kind).toBe('write');
    expect(v.reversibility).toBe('irreversible');
    expect(v.mcp).toEqual({ tool: 'send_invoice' });
    expect(v.openapi).toEqual({ operationId: 'sendInvoice' });
    expect(v.params['action.params.to']).toEqual({ type: 'string', semantic: 'contact.email', sensitivity: 'material', max_len: 254, format: 'email', role: 'contact.email', tags: ['pii'] });
    expect(doc.traits_digest).toBe(traitsDigest(CORE_REGISTRY));
    expect(doc.units).toEqual({ 'money.usd': { kind: 'money', currency: 'USD', exponent: 2 } });
    expect(doc.verbs[1]!.params['action.params.amount']).toMatchObject({ type: 'integer', unit: 'money.usd', accumulates_into: ['money.usd'], sensitivity: 'critical', role: 'money.amount' });
  });
  it('signs and verifies, and a tampered floor is rejected by the signature', () => {
    const kp = generateKeyPair();
    const signed = signActionSchema(doc, 'k1', kp.secretKey);
    const key = actionSchemaKeyOf('k1', kp.secretKey);
    expect(verifyActionSchema(signed, [key])).toEqual({ ok: true });
    const forged = JSON.parse(JSON.stringify(signed)) as ActionSchema;
    forged.verbs[0]!.floors!.esc = 0;
    expect(verifyActionSchema(forged, [key]).ok).toBe(false);
  });
  it('v1 documents are validated as before: the new members are unknown there', () => {
    const v1 = { v: 1, kind: 'pca-action-schema', site: 's', aud: 'a', version: '1', verbs: [{ verb: 'a.b', kind: 'read', params: {} }] };
    expect(actionSchemaShapeError(v1, { signed: false })).toBeNull();
    expect(actionSchemaShapeError({ ...v1, verbs: [{ ...v1.verbs[0], traits: [] }] }, { signed: false })).toMatch(/unknown member 'traits'/);
    expect(actionSchemaShapeError({ ...v1, traits_digest: 'x' }, { signed: false })).toMatch(/unknown member 'traits_digest'/);
    expect(actionSchemaShapeError({ ...v1, verbs: [{ verb: 'a.b', kind: 'read', params: { 'action.params.x.y': { type: 'string', semantic: 's', sensitivity: 'free' } } }] }, { signed: false })).toMatch(/not action.params/);
    expect(actionSchemaShapeError({ ...v1, verbs: [{ verb: 'a.b', kind: 'read', params: { 'action.params.x': { type: 'datetime', semantic: 's', sensitivity: 'free' } } }] }, { signed: false })).toMatch(/unknown type/);
    expect(actionSchemaShapeError({ ...v1, v: 3 }, { signed: false })).toMatch(/unsupported/);
  });
  it('rejects malformed v2 verbs', () => {
    const mut = (f: (v: Record<string, any>) => void) => { const d = JSON.parse(JSON.stringify(doc)); f(d.verbs[0]); return actionSchemaShapeError(d, { signed: false }); };
    expect(mut((v) => { delete v.traits; })).toMatch(/traits/);
    expect(mut((v) => { delete v.floors; })).toMatch(/floors/);
    expect(mut((v) => { delete v.def; })).toMatch(/def/);
    expect(mut((v) => { v.def = 'short'; })).toMatch(/def/);
    expect(mut((v) => { v.effects = ['send', 'create']; })).toMatch(/sorted/);
    expect(mut((v) => { v.effects = ['read']; })).toMatch(/kind read/);
    expect(mut((v) => { v.effects = ['teleport']; })).toMatch(/effects/);
    expect(mut((v) => { v.traits = ['pca.b', 'pca.a']; })).toMatch(/sorted/);
    expect(mut((v) => { v.floors.caveats = ['window', 'amount_cap']; })).toMatch(/sorted/);
    expect(mut((v) => { v.floors.esc = 4; })).toMatch(/esc/);
    expect(mut((v) => { v.floors.rev = 'sometimes'; })).toMatch(/rev/);
    expect(mut((v) => { v.floors.extra = 1; })).toMatch(/unknown member/);
  });
  it('the schema vocabularies mirror the pca-actions tables', () => {
    expect([...SCHEMA_V2_EFFECTS]).toEqual([...EFFECTS]);
    expect([...SCHEMA_V2_CAVEATS]).toEqual([...CAVEAT_KINDS]);
    expect([...SCHEMA_V2_CONTEXT]).toEqual([...CONTEXT_KEYS]);
    expect([...SCHEMA_V2_PRULES]).toEqual([...PARAM_RULE_IDS]);
    expect([...SCHEMA_V2_TAGS]).toEqual([...PARAM_TAGS]);
    expect([...SCHEMA_V2_PROVENANCE]).toEqual([...PROVENANCE_LEVELS]);
    expect(CORE_ROLES.length).toBeGreaterThan(20);
  });
  it('def -> schema verb -> conformAction accepts the example and rejects each mutation (type swap, range, missing, extra)', () => {
    const d = toSchemaDoc([confirmed(refund, CORE_REGISTRY)], CORE_REGISTRY, { site: 's', aud: 'a', version: '1' }, T);
    const ok = { amount: 500, charge: 'ch_abc12345', idempotency_key: 'k-1' };
    expect(conformAction(d, 'stripe.refund', ok).ok).toBe(true);
    const code = (p: unknown) => { const r = conformAction(d, 'stripe.refund', p); return r.ok ? 'ok' : r.code; };
    expect(code({ ...ok, amount: '500' })).toBe('bad_type');
    expect(code({ ...ok, amount: 0 })).toBe('out_of_domain');
    expect(code({ ...ok, amount: 100_000_000_01 })).toBe('out_of_domain');
    expect(code({ amount: 500, charge: 'ch_abc12345' })).toBe('missing_param');
    expect(code({ ...ok, extra: 1 })).toBe('undeclared_param');
    expect(code({ ...ok, charge: 5 })).toBe('bad_type');
    expect(conformAction(d, 'nope.verb', ok)).toMatchObject({ ok: false, code: 'unknown_verb' });
  });
  it('v2 types, formats and dotted params are checked on the flattened form', () => {
    const d = toSchemaDoc([confirmed(customer, CORE_REGISTRY)], CORE_REGISTRY, { site: 's', aud: 'a', version: '1' }, T);
    expect(actionSchemaShapeError(d, { signed: false })).toBeNull();
    const nested = { customer: { email: 'a@b.com', name: 'Ann' }, when: '2026-10-26T10:00:00Z', ttl: 1000, ref: 'cus_1' };
    expect(flattenParams(nested)).toEqual({ 'customer.email': 'a@b.com', 'customer.name': 'Ann', when: '2026-10-26T10:00:00Z', ttl: 1000, ref: 'cus_1' });
    expect(conformAction(d, 'acme.customer.update', flattenParams(nested)).ok).toBe(true);
    const c = (p: Record<string, unknown>) => { const r = conformAction(d, 'acme.customer.update', flattenParams({ ...nested, ...p })); return r.ok ? 'ok' : `${r.code}:${r.path}`; };
    expect(c({ customer: { email: 'not-an-email', name: 'Ann' } })).toBe('out_of_domain:action.params.customer.email');
    expect(c({ when: '2026-13-26T10:00:00Z' })).toBe('out_of_domain:action.params.when');
    expect(c({ when: '2026-10-26T10:00:00+01:00' })).toBe('out_of_domain:action.params.when');
    expect(c({ when: 5 })).toBe('bad_type:action.params.when');
    expect(c({ ttl: -1 })).toBe('out_of_domain:action.params.ttl');
    expect(c({ ttl: 86_400_001 })).toBe('out_of_domain:action.params.ttl');
    expect(c({ ref: 'has space' })).toBe('out_of_domain:action.params.ref');
    expect(c({ ref: '' })).toBe('bad_type:action.params.ref');
    expect(c({ customer: { name: 'Ann', extra: 1, email: 'a@b.com' } })).toBe('undeclared_param:action.params.customer.extra');
    expect(c({ customer: { name: 'Ann' } })).toBe('ok'); // email is optional
  });
});

describe('rule 22 integrity: forged traits and floors are detected from the verb alone', () => {
  const verb = (): ActionVerbDecl => JSON.parse(JSON.stringify(toSchemaVerb(confirmed(refund, CORE_REGISTRY), CORE_REGISTRY, T).verb));
  it('accepts every derived verb (builtins and generated defs)', () => {
    for (const d of BUILTIN_DEFS) expect(schemaVerbFloorError(toSchemaVerb(confirmed(d, CORE_REGISTRY), CORE_REGISTRY, T).verb, CORE_REGISTRY, TEST_PINS), d.verb).toBeNull();
    fc.assert(fc.property(arbDef, (d) => schemaVerbFloorError(toSchemaVerb(confirmed(d, CORE_REGISTRY), CORE_REGISTRY, T).verb, CORE_REGISTRY, TEST_PINS) === null), { seed: 31, numRuns: runs(3000) });
  });
  it('rejects lowered floors, dropped implied traits, unknown traits and a lowered reversibility floor', () => {
    const a = verb(); a.floors!.esc = 0;
    expect(schemaVerbFloorError(a, CORE_REGISTRY, TEST_PINS)).toMatch(/schema_floor_forged/);
    const b = verb(); b.traits = b.traits!.filter((t) => t !== 'pca.money_moving');
    expect(schemaVerbFloorError(b, CORE_REGISTRY, TEST_PINS)).toMatch(/schema_traits_forged: missing implied trait pca.money_moving/);
    const c = verb(); c.traits = [...c.traits!, 'pca.invented'].sort();
    expect(schemaVerbFloorError(c, CORE_REGISTRY, TEST_PINS)).toMatch(/unknown_trait/);
    const d = verb(); d.floors!.rev = 'reversible'; d.floors!.esc = 3;
    expect(schemaVerbFloorError(d, CORE_REGISTRY, TEST_PINS)).toMatch(/schema_floor_forged/);
    const e = verb(); e.floors!.blast_ppm = 0;
    expect(schemaVerbFloorError(e, CORE_REGISTRY, TEST_PINS)).toMatch(/forged/);
    const f = verb(); delete (f as { floors?: unknown }).floors;
    expect(schemaVerbFloorError(f, CORE_REGISTRY, TEST_PINS)).toMatch(/not a v2 verb/);
  });
  it('custom traits travel in the document and extend the registry', () => {
    const custom = { id: 'acme.refund_over_threshold', implies: ['pca.money_moving'], floor: { ...CORE_REGISTRY.traits.get('pca.money_moving')!.floor, esc: 3, caveats: [...CORE_REGISTRY.traits.get('pca.money_moving')!.floor.caveats, 'approval_ref' as const].sort() }, card_phrase: 'refunds a large amount' };
    const reg = extendRegistry(CORE_REGISTRY, [custom]);
    const d: ActionDef = { ...refund, traits: ['acme.refund_over_threshold'] };
    const doc = toSchemaDoc([confirmed(d, reg)], reg, { site: 's', aud: 'a', version: '1' }, T);
    expect(doc.trait_defs).toEqual([custom]);
    expect(doc.verbs[0]!.floors!.esc).toBe(3);
    expect(schemaVerbFloorError(doc.verbs[0]!, reg, TEST_PINS)).toBeNull();
    expect(schemaVerbFloorError(doc.verbs[0]!, CORE_REGISTRY, TEST_PINS)).toMatch(/unknown_trait/);
  });
});

describe('whole-document integrity', () => {
  const custom = { id: 'acme.refund_over_threshold', implies: ['pca.money_moving'], floor: { ...CORE_REGISTRY.traits.get('pca.money_moving')!.floor, esc: 3 }, card_phrase: 'refunds a large amount' };
  const reg = extendRegistry(CORE_REGISTRY, [custom]);
  const doc = toSchemaDoc([{ ...refund, traits: ['acme.refund_over_threshold'] }, invoice], reg, { site: 's', aud: 'a', version: '1' });
  it('loads the registry from the document and accepts an honest one', () => {
    expect(registryOfSchema(doc).traits.size).toBe(23);
    expect(registryOfSchema({}).traits.size).toBe(22);
    expect(schemaFloorError(doc, TEST_PINS)).toBeNull();
    expect(schemaFloorError(toSchemaDoc(BUILTIN_DEFS.map((d) => confirmed(d)), CORE_REGISTRY, { site: 's', aud: 'a', version: '1' }, T), TEST_PINS)).toBeNull();
  });
  it('refuses a wrong digest, a bad custom trait and a forged verb, naming the verb', () => {
    expect(schemaFloorError({ ...doc, traits_digest: 'x'.repeat(43) }, TEST_PINS)).toBe("traits_digest_mismatch: the document's traits_digest does not match its trait registry");
    expect(schemaFloorError({ ...doc, trait_defs: [{ ...custom, floor: { ...custom.floor, risk: 0, esc: 0, rev: 'reversible', blast_ppm: 0, caveats: [], context: [], prules: [] } }] }, TEST_PINS)).toMatch(/^bad_registry: trait 'acme.refund_over_threshold': floor is below/);
    const forged = JSON.parse(JSON.stringify(doc)) as typeof doc;
    forged.verbs[1]!.floors!.risk = 0;
    expect(schemaFloorError(forged, TEST_PINS)).toMatch(/^stripe.refund: schema_floor_forged/);
  });
});

describe('operation binding', () => {
  it('builds the resource from the id param and projects declared params only', () => {
    const r = operationOf(refund, { params: { amount: 500, charge: 'ch_abc12345', idempotency_key: 'k', junk: 1 } });
    expect(r).toEqual({ ok: true, op: { verb: 'stripe.refund', resource: 'stripe.charge:ch_abc12345', params: { amount: 500, charge: 'ch_abc12345', idempotency_key: 'k' } } });
  });
  it('refuses a missing or non-matching id instead of guessing', () => {
    expect(operationOf(refund, { params: { amount: 5 } })).toEqual({ ok: false, reason: 'stripe.refund needs a parameter with role id.stripe.charge to name its resource' });
    expect(operationOf(refund, { params: { amount: 5, charge: 'zz_1' } })).toEqual({ ok: false, reason: "the id 'zz_1' does not match the resource pattern of stripe.refund" });
  });
  it('uses the exact id, or a wildcard resource for set scopes', () => {
    expect(operationOf({ ...refund, resource: { type: 'a.b', id: { exact: 'only' }, scope: 'one' } }, { params: {} })).toMatchObject({ ok: true, op: { resource: 'a.b:only' } });
    const files = BUILTIN_DEFS.find((d) => d.verb === 'files.read')!;
    expect(operationOf(files, { params: { path: '/a/b' } })).toEqual({ ok: true, op: { verb: 'files.read', resource: 'files.file:*', params: { path: '/a/b' } } });
  });
  it('reads nested params through their dotted names', () => {
    const r = operationOf(customer, { params: { customer: { email: 'a@b.com', name: 'A' }, junk: 2 } });
    expect(r).toMatchObject({ ok: true, op: { params: { 'customer.email': 'a@b.com', 'customer.name': 'A' } } });
  });
});

describe('risk, predicates, escalation', () => {
  const eff = effOf(refund);
  it('prices a money action from amount / kappa and falls back to the worst case', () => {
    expect(riskOf(refund, eff, { amount: 5000 }, { kappa: 100_000 })).toEqual({ reversibility: 0, blastRadius: 0.05, confidence: 1 });
    expect(riskOf(refund, eff, { amount: 5000 }, {})).toMatchObject({ blastRadius: 1 });
    expect(riskOf(refund, eff, {}, { kappa: 100_000 })).toMatchObject({ blastRadius: 1 });
    expect(riskOf(refund, eff, { amount: -1 }, { kappa: 100_000 })).toMatchObject({ blastRadius: 1 });
    expect(riskOf(refund, eff, { amount: 5000 }, { kappa: 100_000, taint: 2 })).toMatchObject({ taint: 1 });
  });
  it('prices a non-money action from the effective class and blast', () => {
    const del = BUILTIN_DEFS.find((d) => d.verb === 'calendar.delete_event')!;
    // the built-ins keep the old catalog's blast presets exactly (never priced below what the catalog said)
    expect(riskOf(del, effOf(del), {}, {})).toEqual({ reversibility: 0.4, blastRadius: 0.5, confidence: 1 });
    const read = BUILTIN_DEFS.find((d) => d.verb === 'github.read')!;
    expect(riskOf(read, effOf(read), {}, {})).toEqual({ reversibility: 1, blastRadius: 0.05, confidence: 1 });
  });
  it('compiles a money limit to a per-call ceiling on the role param, and refuses an unenforceable one', () => {
    expect(predicatesOf(refund, { max_amount: 20_000 })).toEqual({
      verb: 'stripe.refund', resource: 'stripe.charge:ch_*',
      where: [{ field: 'action.params.amount', op: 'lte', value: 20_000 }, { field: 'action.params.amount', op: 'gte', value: 0 }],
    });
    expect(predicatesOf(refund)).toEqual({ verb: 'stripe.refund', resource: 'stripe.charge:ch_*' });
    expect(() => predicatesOf(BUILTIN_DEFS.find((d) => d.verb === 'gmail.send')!, { max_amount: 5 })).toThrow(/no parameter with role money.amount/);
    expect(() => predicatesOf(refund, { max_amount: 1.5 })).toThrow(/non-negative safe integer/);
    expect(() => paramByRole({ verb: 'x.y', params: { a: { type: 'integer', role: 'money.amount' }, b: { type: 'integer', role: 'money.amount' } } }, 'money.amount')).toThrow(/several/);
  });
  it('escalation tier and card text', () => {
    expect(escalationOf(eff)).toEqual({ tier: 2, name: 'cosign' });
    expect(cardOf(refund, eff, CORE_REGISTRY)).toEqual({
      verb: 'stripe.refund', title: 'Refund a charge', text: 'Refund a charge. This action moves money and cannot be undone.',
      risk: 'critical', escalation: 'cosign', reversibility: 'irreversible', blast_ppm: 900_000,
      needs: ['amount_cap', 'count_cap', 'window'], context: ['fresh_revocation', 'idempotency'],
    });
    const inv = cardOf(invoice, effOf(invoice), CORE_REGISTRY);
    expect(inv.text).toBe('Send an invoice. This action sends to people outside your organisation, cannot be undone and touches personal data.');
    expect(inv).toMatchObject({ risk: 'high', escalation: 'confirm', needs: ['rate_cap', 'recipient_scope', 'resource_scope'] });
    const read = BUILTIN_DEFS.find((d) => d.verb === 'github.read')!;
    expect(cardOf(read, effOf(read), CORE_REGISTRY).text).toBe('Read repository contents. This action only reads.');
  });
  it('MCP annotations', () => {
    const ann = (d: ActionDef) => mcpAnnotationsOf(d, effOf(d));
    expect(ann(BUILTIN_DEFS.find((d) => d.verb === 'github.read')!)).toEqual({ readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false });
    expect(ann(BUILTIN_DEFS.find((d) => d.verb === 'files.delete')!)).toEqual({ readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false });
    expect(ann(refund)).toEqual({ readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false });
    expect(ann(BUILTIN_DEFS.find((d) => d.verb === 'http.get')!).openWorldHint).toBe(true);
  });
});

describe('Goal IR ontology terms', () => {
  it('effect class is derived, aliases are total, types and units come from the defs', () => {
    expect(effectClass(refund)).toBe('irreversible');
    expect(effectClass(BUILTIN_DEFS.find((d) => d.verb === 'github.read')!)).toBe('read');
    expect(effectClass(BUILTIN_DEFS.find((d) => d.verb === 'calendar.create_event')!)).toBe('irreversible');
    expect(effectClass({ ...invoice, reversibility: 'rate_limited' })).toBe('external_send');
    expect(effectClass(invoice)).toBe('irreversible');
    const o = toOntology(BUILTIN_DEFS.map((d) => confirmed(d)), CORE_REGISTRY, T);
    expect(o.verbs.find((v) => v.id === 'stripe.refund')).toEqual({
      id: 'stripe.refund', effect: 'irreversible', resource_type: 'stripe.charge',
      params: { amount: { kind: 'money', ccys: ['USD'] }, charge: { kind: 'id', of: 'stripe.charge' }, idempotency_key: { kind: 'text' } },
    });
    expect(o.aliases.refund).toBe('stripe.refund');
    expect(o.aliases.charge_customer).toBe('stripe.charge');
    expect(o.units.USD).toEqual({ kind: 'money', exponent: 2 });
    expect(o.types.find((t) => t.id === 'stripe.charge')).toEqual({ id: 'stripe.charge', id_prefix: 'ch_' });
    expect(o.traits['stripe.refund']).toEqual(['pca.irreversible', 'pca.money_moving']);
    expect(() => toOntology([{ ...refund, aliases: ['dup'] }, { ...invoice, aliases: ['dup'] }], CORE_REGISTRY)).toThrow(/names two verbs/);
  });
});

describe('builtin pack', () => {
  it('all 21 are valid, satisfy the param rules their traits require, and have distinct verbs, aliases and digests', () => {
    expect(BUILTIN_DEFS).toHaveLength(21);
    const aliases = new Set<string>();
    for (const d of BUILTIN_DEFS) {
      expect(validateDef(d), d.verb).toBeNull();
      const e = effective(d, CORE_REGISTRY);
      expect(e.clamps, d.verb).toEqual([]); // clamps are measured on the reviewed (hint) view
      expect(e.confirmed, d.verb).toBe(false); // an unsigned built-in is unconfirmed (top)
      for (const a of d.aliases ?? []) { expect(aliases.has(a)).toBe(false); aliases.add(a); }
    }
    expect(new Set(BUILTIN_DEFS.map(defDigest)).size).toBe(21);
    expect(CORE_TRAIT_IDS).toHaveLength(CORE_TRAIT_DEFS.length);
  });
});
