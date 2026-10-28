// lint-fixtures.ts - for every lint rule, defs that trigger it (bad) and defs that do not (good). Shared by the rule test and
// the examples. `clean()` is lint-clean: no finding of any kind.
import { CORE_REGISTRY, action, defDigest, p, traitsDigest, type ActionDef, type LintOptions, type TraitDef } from '../src';

export const clean = (): ActionDef =>
  action('acme.invoice.send', {
    title: 'Send an invoice',
    description: 'Emails an existing invoice to the customer.',
    effects: ['send'],
    resource: 'acme.invoice:inv_*',
    params: { invoice: p.id('acme.invoice'), to: p.email(), note: p.message(500) },
    since: '0.1.0',
  });

/** A clean def with members replaced (raw: no validation, so vocabulary and structure faults can be expressed). */
export const d = (patch: Record<string, unknown> = {}): Record<string, unknown> => {
  const x: Record<string, unknown> = { ...JSON.parse(JSON.stringify(clean())), ...patch };
  // replacing the params without naming idempotency drops the auto-added key declaration with them
  if ('params' in patch && !('idempotency' in patch) && !('idempotency_key' in (patch.params as object))) delete x.idempotency;
  for (const k of Object.keys(x)) if (x[k] === undefined) delete x[k];
  return x;
};
const other = (verb: string, patch: Record<string, unknown> = {}): Record<string, unknown> => d({ verb, resource: { type: 'acme.invoice', id: { prefix: 'inv_', class: 'alnum', len: [8, 32] }, scope: 'one' }, ...patch });
const params = (extra: Record<string, unknown>): Record<string, unknown> => ({ ...(clean().params as Record<string, unknown>), ...extra });

export interface Case { defs: unknown[]; opts?: LintOptions }
export interface Fixture { bad: Case[]; good: Case[] }

const payParams = (amount: unknown): Record<string, unknown> => ({ charge: p.id('acme.charge'), amount, idempotency_key: { type: 'string', max_len: 64 } });
const pay = (patch: Record<string, unknown> = {}): Record<string, unknown> => d({
  verb: 'acme.charge.refund', title: 'Refund a charge', description: 'Returns money.', effects: ['pay'],
  resource: { type: 'acme.charge', id: { prefix: 'ch_', class: 'alnum', len: [8, 32] }, scope: 'one' },
  params: payParams(p.money('USD', { max: 1000 })), idempotency: { mode: 'key_param', param: 'idempotency_key' },
  examples: [{ params: { charge: 'ch_12345678', amount: 100, idempotency_key: 'k' }, expect: 'escalate' }], ...patch,
});
const del = (patch: Record<string, unknown> = {}): Record<string, unknown> => d({
  verb: 'acme.invoice.delete', title: 'Delete an invoice', description: 'Deletes an invoice.', effects: ['delete'],
  params: { invoice: p.id('acme.invoice') }, examples: [{ params: { invoice: 'inv_12345678' }, expect: 'escalate' }], ...patch,
});
const upd = (patch: Record<string, unknown> = {}): Record<string, unknown> => d({ verb: 'acme.invoice.update', title: 'Update an invoice', effects: ['update'], ...patch });
const read = (patch: Record<string, unknown> = {}): Record<string, unknown> => d({
  verb: 'acme.invoice.get', title: 'Read an invoice', description: 'Reads an invoice.', effects: ['read'], params: { invoice: p.id('acme.invoice') }, ...patch,
});

const attested = (state: 'confirmed', dismissed: { trait: string; reason: string }[] = []): Record<string, unknown> => {
  const base = d();
  return { ...base, review: { state, attestation: { def_digest: defDigest(base as unknown as ActionDef), traits_digest: traitsDigest(CORE_REGISTRY), facts_digest: 'AAAA', final_traits: [], dismissed, reviewer_kid: 'rev-1', ts: 1, sig: 'c2ln' } } };
};

const weakTrait: TraitDef = { id: 'acme.weak', implies: ['pca.money_moving'], floor: { risk: 0, rev: 'reversible', blast_ppm: 0, esc: 0, caveats: [], context: [], prules: [] }, card_phrase: 'weak' };
const okTrait: TraitDef = { id: 'acme.strong', implies: ['pca.destructive'], floor: { ...CORE_REGISTRY.traits.get('pca.destructive')!.floor, esc: 2 }, card_phrase: 'is strong' };

export const FIXTURES: Record<string, Fixture> = {
  'LD-001': { bad: [{ defs: [d({ verb: 'acme.invoice.remove', effects: ['update'] })] }], good: [{ defs: [del()] }] },
  'LD-002': {
    bad: [
      { defs: [pay({ params: payParams({ type: 'integer', role: 'money.amount', min: 1, max: 100 }) })] },
      { defs: [pay({ params: { ...payParams(p.money('USD', { max: 100 })), ccy: { type: 'string', role: 'money.currency', max_len: 3 } } })] },
      { defs: [pay({ params: { ...payParams(p.money({ from: 'nope' }, { max: 100 })), nope: p.text(5) } })] },
    ],
    good: [{ defs: [pay()] }, { defs: [pay({ params: { ...payParams(p.money({ from: 'ccy' }, { max: 100 })), ccy: p.ccy() } })] }],
  },
  'LD-003': { bad: [{ defs: [d({ params: params({ n: p.int() }) })] }, { defs: [d({ params: params({ n: p.int(0, 10), t: p.duration() }) })] }], good: [{ defs: [d({ params: params({ n: p.int(0, 10), t: p.duration(1000) }) })] }] },
  'LD-004': { bad: [{ defs: [pay({ idempotency: { mode: 'none' } })] }], good: [{ defs: [pay({ idempotency: { mode: 'natural' } })] }, { defs: [pay()] }] },
  'LD-005': {
    bad: [
      { defs: [d({ verb: 'acme.contact.export_list', effects: ['read'], params: { invoice: p.id('acme.invoice'), email: p.email() } })] },
      { defs: [d({ effects: ['update'], side_effects: [{ target: 'customer.email', kind: 'send' }] })] },
    ],
    good: [{ defs: [d({ verb: 'acme.contact.export_list', effects: ['export'], resource: { type: 'acme.contact', id: { prefix: 'c_', class: 'alnum', len: [8, 32] }, scope: 'one' }, params: { invoice: p.id('acme.contact'), email: p.email() } })] }, { defs: [clean()] }],
  },
  'LD-006': { bad: [{ defs: [del({ reversibility: 'reversible', compensates: 'acme.invoice.restore' })] }, { defs: [d({ blast: { radius: 'one' }, effects: ['pay'], params: payParams(p.money('USD', { max: 100 })), idempotency: { mode: 'natural' } })] }], good: [{ defs: [del({ reversibility: 'irreversible' })] }, { defs: [clean()] }] },
  'LD-007': {
    bad: [
      { defs: [d({ params: params({ x: { type: 'string', role: 'party.nobody', max_len: 5 } }) })] },
      { defs: [d({ traits: ['acme.nope'] })] },
      { defs: [d({ context: ['teleport'] })] },
      { defs: [d({ params: params({ x: { type: 'string', format: 'zip', max_len: 5 } }) })] },
      { defs: [d({ effects: ['teleport'] })] },
      { defs: [clean()], opts: { customTraits: [weakTrait] } },
    ],
    good: [{ defs: [d({ traits: ['acme.strong'] })], opts: { customTraits: [okTrait] } }, { defs: [d({ context: ['session_taint_max:low'] })] }],
  },
  'LD-008': { bad: [{ defs: [d({ resource: { type: 'acme.invoice', id: '*', scope: 'one' } })] }], good: [{ defs: [d({ resource: { type: 'acme.invoice', id: '*', scope: 'set' } })] }] },
  'LD-009': {
    bad: [{ defs: [clean(), clean()] }, { defs: [d({ aliases: ['acme.invoice.get'] }), read()] }, { defs: [d({ aliases: ['shared'] }), other('acme.invoice.send2', { aliases: ['shared'] })] }],
    good: [{ defs: [clean(), read()] }],
  },
  'LD-010': {
    bad: [{ defs: [upd({ reversibility: 'reversible' })] }, { defs: [upd({ reversibility: 'reversible', compensates: 'acme.invoice.undo' })] }],
    good: [{ defs: [upd({ reversibility: 'reversible', compensates: 'acme.invoice.undo' }), other('acme.invoice.undo', { title: 'Undo an invoice update', effects: ['update'] })] }, { defs: [read({ reversibility: 'reversible' })] }],
  },
  'LD-011': {
    bad: [
      { defs: [d({ review: { state: 'confirmed' } })] },
      { defs: [{ ...attested('confirmed'), title: 'Send another invoice' }] },
      { defs: [(() => { const a = attested('confirmed') as { review: { attestation: Record<string, unknown> } }; a.review.attestation.traits_digest = 'AAAA'; return a; })()] },
      { defs: [(() => { const a = attested('confirmed') as { review: { attestation: Record<string, unknown> } }; delete a.review.attestation.sig; return a; })()] },
    ],
    good: [{ defs: [attested('confirmed')] }],
  },
  'LD-012': {
    bad: [{ defs: [d({ params: { invoice: p.id('acme.invoice') } })] }, { defs: [read({ resource: { type: 'acme.invoice', id: { prefix: 'inv_', class: 'alnum', len: [8, 32] }, scope: 'set' }, params: { invoice: p.id('acme.invoice'), ids: { type: 'array', items: 'string' } } })] }],
    good: [{ defs: [clean()] }],
  },
  'LD-013': {
    bad: [{ defs: [read({ params: { invoice: p.id('acme.invoice'), q: { type: 'string', role: 'query.sql', max_len: 200 } } })] }, { defs: [read({ params: { invoice: p.id('acme.invoice'), tok: { type: 'string', tags: ['credential', 'secret'], max_len: 50 } } })] }],
    good: [{ defs: [read({ context: ['sandbox_attested'], params: { invoice: p.id('acme.invoice'), q: { type: 'string', role: 'query.sql', max_len: 200 } } })] }, { defs: [read()] }],
  },
  'LD-014': {
    bad: [{ defs: [d({ bindings: { mcp: { tool: 't1' } } }), other('acme.invoice.send2', { bindings: { mcp: { tool: 't1' } } })] }, { defs: [d({ bindings: { http: { method: 'post', path: '/x' } } }), other('acme.invoice.send2', { bindings: { http: { method: 'POST', path: '/x' } } })] }],
    good: [{ defs: [d({ bindings: { mcp: { tool: 't1' } } }), other('acme.invoice.send2', { bindings: { mcp: { tool: 't2' } } })] }],
  },
  'LW-001': {
    bad: [{ defs: [(() => { const x = d(); delete x.description; return x; })()] }, { defs: [d({ title: 'Sending invoices' })] }, { defs: [d({ description: 'x'.repeat(401) })] }, { defs: [d({ title: 'An invoice sender' })] }],
    good: [{ defs: [clean()] }],
  },
  'LW-002': { bad: [{ defs: [d({ params: params({ x: { type: 'string' } }) })] }], good: [{ defs: [d({ params: params({ x: { type: 'string', max_len: 20 } }) })] }, { defs: [d({ params: params({ x: p.enum(['a', 'b']) }) })] }] },
  'LW-003': { bad: [{ defs: [d({ params: params({ note: p.text(500) }) })] }], good: [{ defs: [clean()] }, { defs: [del({ params: { invoice: p.id('acme.invoice'), note: p.text(500) } })] }] },
  'LW-004': { bad: [{ defs: [d({ review: { state: 'unreviewed' } })], opts: { stability: 'stable' } }, { defs: [d({ review: { state: 'suggested' } })], opts: { stability: 'stable' } }], good: [{ defs: [d({ review: { state: 'unreviewed' } })], opts: { stability: 'beta' } }, { defs: [clean()], opts: { stability: 'stable' } }] },
  'LW-005': { bad: [{ defs: [attested('confirmed', [{ trait: 'pca.bulk', reason: 'no' }])] }], good: [{ defs: [attested('confirmed', [{ trait: 'pca.bulk', reason: 'an invoice is one document' }])] }] },
  'LW-006': { bad: [{ defs: [d({ params: params({ ids: p.array('string') }) })] }], good: [{ defs: [d({ params: params({ ids: p.array('string', 10) }) })] }] },
  'LW-007': { bad: [{ defs: [d({ params: params({ x: { type: 'string', max_len: 9, sensitivity: 'critical' } }) })] }], good: [{ defs: [d({ params: params({ x: { type: 'string', max_len: 9, sensitivity: 'critical', provenance_min: 'first_party' } }) })] }] },
  'LW-008': {
    bad: [{ defs: [clean()], opts: { ns: 'other' } }, { defs: [other('acme.invoice.create_draft'), other('acme.invoice.create_final'), other('acme.invoice.new_copy')] }],
    good: [{ defs: [clean()], opts: { ns: 'acme' } }, { defs: [other('acme.invoice.create_draft'), other('acme.invoice.create_final')] }],
  },
  'LW-009': { bad: [{ defs: [pay({ examples: undefined })] }, { defs: [del({ examples: [] })] }], good: [{ defs: [pay()] }, { defs: [del()] }] },
  'LW-010': { bad: [{ defs: [(() => { const x = d(); delete x.since; return x; })()] }], good: [{ defs: [clean()] }] },
};
