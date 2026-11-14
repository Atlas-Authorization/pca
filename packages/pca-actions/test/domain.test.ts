import { describe, expect, it } from 'vitest';
import {
  ALIAS_RE, BUILTIN_DEFS, CORE_PACK_DEFS, CORE_REGISTRY, DOMAIN_DEFS, DOMAIN_VERBS, domainRoles, domainVerbs, effectClass, effective, facadeSpecs, specOfDef, toOntology, validateDef,
  type DomainName,
} from '../src';

const DOMAINS = Object.keys(DOMAIN_VERBS) as DomainName[];

describe('the domain vocabularies are ActionDefs', () => {
  it('every domain def is well formed, authored, and the pack has one verb and one alias namespace', () => {
    for (const d of DOMAIN_DEFS) { expect(validateDef(d), d.verb).toBeNull(); expect(d.review.state).toBe('authored'); }
    const verbs = CORE_PACK_DEFS.map((d) => d.verb);
    expect(new Set(verbs).size).toBe(verbs.length);
    const seen = new Map<string, string>();
    for (const d of CORE_PACK_DEFS) for (const a of d.aliases ?? []) {
      expect(ALIAS_RE.test(a), a).toBe(true);
      expect(seen.get(a) ?? d.verb, `alias '${a}' names two verbs`).toBe(d.verb);
      seen.set(a, d.verb);
    }
    // an alias never shadows a verb of another def
    for (const a of seen.keys()) expect(verbs.includes(a)).toBe(false);
  });

  it('every binding names a def whose aliases include the short id; every verb of a domain is bound once', () => {
    for (const dom of DOMAINS) {
      const ids = DOMAIN_VERBS[dom].map((b) => b.id);
      expect(new Set(ids).size).toBe(ids.length);
      for (const b of DOMAIN_VERBS[dom]) {
        const d = CORE_PACK_DEFS.find((x) => x.verb === b.verb)!;
        expect(d, b.verb).toBeDefined();
        expect(d.aliases ?? [], b.id).toContain(b.id);
        for (const dp of Object.values(b.params)) expect(Object.keys(d.params), `${b.id}.${dp}`).toContain(dp);
      }
    }
  });

  it('the effect class of each verb is derived from its def; the send and publish verbs are still irreversible in effect', () => {
    const cls = (v: string) => effectClass(CORE_PACK_DEFS.find((d) => d.verb === v)!);
    expect(['mail.send', 'mail.forward', 'repo.release', 'data.export'].map(cls)).toEqual(['external_send', 'external_send', 'external_send', 'external_send']);
    for (const v of ['mail.send', 'mail.forward', 'repo.release']) {
      const e = effective(CORE_PACK_DEFS.find((d) => d.verb === v)!, CORE_REGISTRY);
      expect(e.eff.rev, v).toBe('irreversible');
    }
    expect(effective(CORE_PACK_DEFS.find((d) => d.verb === 'data.export')!, CORE_REGISTRY).eff.caveats).toEqual(expect.arrayContaining(['count_cap', 'resource_scope']));
    expect(['stripe.refund', 'stripe.charge', 'stripe.transfer', 'stripe.payout', 'travel.book', 'mail.delete', 'repo.merge'].map(cls)).toEqual(Array(7).fill('irreversible'));
    expect(['stripe.read_charge', 'mail.read_thread', 'repo.read', 'data.query', 'travel.search'].map(cls)).toEqual(Array(5).fill('read'));
  });

  it('domainVerbs: one ontology verb per binding, aliases from the defs, params surfaced by name; roles are exposed for the selector layer', () => {
    const pay = domainVerbs('payments');
    expect(pay.verbs.map((v) => v.id)).toEqual(['read_charge', 'refund', 'charge_customer', 'transfer', 'payout', 'cancel_subscription']);
    expect(pay.verbs.find((v) => v.id === 'refund')).toEqual({ id: 'refund', effect: 'irreversible', resource_type: 'charge', params: { amount: { kind: 'money', ccys: ['USD', 'EUR', 'GBP', 'JPY'] } } });
    expect(pay.aliases).toMatchObject({ issue_refund: 'refund', reimburse: 'refund', bill: 'charge_customer', send_money: 'transfer', pay_out: 'payout', cancel_plan: 'cancel_subscription', view_charge: 'read_charge' });
    expect(domainRoles('payments').refund).toEqual({ 'money.amount': ['amount'] });
    expect(domainRoles('payments').read_charge).toEqual({});
    for (const dom of DOMAINS) expect(() => domainVerbs(dom)).not.toThrow();
  });

  it('the pack ontology of all defs agrees with the per-domain classes', () => {
    const all = toOntology(CORE_PACK_DEFS, CORE_REGISTRY);
    for (const dom of DOMAINS) for (const v of domainVerbs(dom).verbs) {
      const b = DOMAIN_VERBS[dom].find((x) => x.id === v.id)!;
      expect(all.verbs.find((x) => x.id === b.verb)!.effect, b.verb).toBe(v.effect);
    }
  });
});

describe('the facade rows (specOfDef)', () => {
  it('reversibility and blast are the effective values, the amount field is the money.amount parameter, aliases ride along', () => {
    const rows = facadeSpecs(BUILTIN_DEFS, CORE_REGISTRY, { reviewed: true });
    expect(rows).toHaveLength(21);
    const refund = specOfDef(BUILTIN_DEFS.find((d) => d.verb === 'stripe.refund')!, CORE_REGISTRY, { reviewed: true });
    expect(refund).toMatchObject({ connector: 'stripe', action: 'refund', reversibility: 'irreversible', blastRadius: 0.9, amountField: 'amount', aliases: ['issue_refund', 'refund', 'refund_charge', 'reimburse'] });
    expect(refund.traits).toContain('pca.money_moving');
    expect(rows.find((r) => r.verb === 'gmail.send')!.amountField).toBeUndefined();
    // a def with two money.amount parameters has no single amount field: a `$` limit must refuse to compile rather than guess
    const two = { ...BUILTIN_DEFS.find((d) => d.verb === 'stripe.refund')!, params: { a: { type: 'integer', role: 'money.amount' }, b: { type: 'integer', role: 'money.amount' } } } as never;
    expect(specOfDef(two).amountField).toBeUndefined();
  });
});
