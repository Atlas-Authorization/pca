// Domain binding defects, role maps and the facade row, pinned exactly.
import { describe, expect, it } from 'vitest';
import { BUILTIN_DEFS, CORE_PACK_DEFS, CORE_REGISTRY, DOMAIN_VERBS, domainRoles, domainVerbs, effective, specOfDef, toOntology, type ActionDef, type DomainName, type DomainVerb } from '../src';

type Mut = DomainVerb[];
const withBindings = <T>(dom: DomainName, extra: DomainVerb[], fn: () => T, only = false): T => {
  const arr = DOMAIN_VERBS[dom] as unknown as Mut;
  const saved = arr.splice(0, arr.length);
  arr.push(...(only ? [] : saved), ...extra);
  try { return fn(); } finally { arr.splice(0, arr.length, ...saved); }
};
const bind = (o: Partial<DomainVerb> & { id: string; verb: string }): DomainVerb => ({ resourceType: 'charge', params: {}, ...o });
const defNamed = (v: string) => CORE_PACK_DEFS.find((d) => d.verb === v)!;

describe('domain binding defects', () => {
  it('a binding that names no def throws, for ontologies and roles alike', () => {
    const b = bind({ id: 'x', verb: 'nope.nope' });
    expect(() => withBindings('payments', [b], () => domainVerbs('payments'))).toThrow("domain binding names unknown def 'nope.nope'");
    expect(() => withBindings('payments', [b], () => domainRoles('payments'))).toThrow("domain binding names unknown def 'nope.nope'");
  });

  it('a short id that is not an alias of its def throws', () => {
    expect(() => withBindings('payments', [bind({ id: 'zzz', verb: 'stripe.read_charge' })], () => domainVerbs('payments'))).toThrow("domain binding 'zzz' is not an alias of 'stripe.read_charge'");
  });

  it('a def without aliases accepts no short id', () => {
    const d = defNamed('stripe.read_charge') as { aliases?: string[] };
    const saved = d.aliases;
    delete d.aliases;
    try {
      expect(() => withBindings('payments', [bind({ id: 'Stryker was here', verb: 'stripe.read_charge' })], () => domainVerbs('payments'), true)).toThrow("domain binding 'Stryker was here' is not an alias of 'stripe.read_charge'");
    } finally { d.aliases = saved; }
  });

  it('a binding surfacing an unknown parameter throws', () => {
    expect(() => withBindings('payments', [bind({ id: 'view_charge', verb: 'stripe.read_charge', params: { c: 'nonexistent' } })], () => domainVerbs('payments'))).toThrow("domain binding 'view_charge' surfaces unknown parameter 'nonexistent'");
  });
});

describe('domainVerbs surfaced parameters and aliases', () => {
  it('currencies replace the money parameter only; other kinds and currency-less money pass through', () => {
    const onto = (v: string) => toOntology([defNamed(v)], CORE_REGISTRY).verbs[0]!.params;
    const nonMoney = withBindings('payments', [bind({ id: 'view_charge', verb: 'stripe.read_charge', params: { c: 'charge' }, ccys: ['USD'] })], () => domainVerbs('payments').verbs.find((v) => v.id === 'view_charge')!.params, false);
    expect(nonMoney.c).toEqual(onto('stripe.read_charge').charge);
    expect(nonMoney.c!.kind).not.toBe('money');
    const bare = withBindings('payments', [bind({ id: 'send_money', verb: 'stripe.transfer', params: { a: 'amount' } })], () => domainVerbs('payments').verbs.find((v) => v.id === 'send_money')!.params, false);
    expect(bare.a).toEqual(onto('stripe.transfer').amount);
    const money = domainVerbs('payments').verbs.find((v) => v.id === 'transfer')!.params.amount;
    expect(money).toEqual({ kind: 'money', ccys: ['USD', 'EUR', 'GBP', 'JPY'] });
  });

  it('the alias map never lists the short id itself', () => {
    for (const dom of Object.keys(DOMAIN_VERBS) as DomainName[]) {
      const { aliases } = domainVerbs(dom);
      for (const b of DOMAIN_VERBS[dom]) {
        expect(aliases, `${dom}.${b.id}`).not.toHaveProperty(b.id);
        for (const a of defNamed(b.verb).aliases ?? []) if (a !== b.id) expect(aliases[a]).toBe(b.id);
      }
    }
  });
});

describe('domainRoles', () => {
  it('a surfaced parameter without a role contributes nothing', () => {
    expect(domainRoles('email').label).toEqual({});
    expect(domainRoles('email').send).toEqual({});
  });
  it('a binding naming a parameter the def lacks yields no role instead of throwing', () => {
    const r = withBindings('payments', [bind({ id: 'view_charge', verb: 'stripe.read_charge', params: { x: 'nonexistent' } })], () => domainRoles('payments'));
    expect(r.view_charge).toEqual({});
  });
});

describe('specOfDef', () => {
  const read = BUILTIN_DEFS.find((d) => d.verb === 'github.read')!;
  it('an unreviewed def is priced at the effective (top) values; reviewed uses the hint', () => {
    const full = effective(read, CORE_REGISTRY);
    const plain = specOfDef(read);
    expect(plain.reversibility).toBe(full.eff.rev);
    expect(plain.blastRadius).toBe(full.eff.blast_ppm / 1_000_000);
    expect(plain.traits).toEqual(full.closure);
    const rev = specOfDef(read, CORE_REGISTRY, { reviewed: true });
    expect(rev.traits).toEqual(full.hint.closure);
    expect(rev.traits).not.toEqual(plain.traits);
    const flagFalse = specOfDef(read, CORE_REGISTRY, { reviewed: false });
    expect(flagFalse).toEqual(plain);
  });
  it('the action is everything after the first dot', () => {
    const d: ActionDef = { ...read, verb: 'svc.sub.act' };
    const s = specOfDef(d);
    expect(s.connector).toBe('svc');
    expect(s.action).toBe('sub.act');
    expect(s.verb).toBe('svc.sub.act');
  });
  it('aliases appear sorted only when there is at least one', () => {
    expect(specOfDef({ ...read, aliases: [] })).not.toHaveProperty('aliases');
    const { aliases: _a, ...none } = read;
    expect(specOfDef(none as ActionDef)).not.toHaveProperty('aliases');
    expect(specOfDef({ ...read, aliases: ['zed', 'abc'] }).aliases).toEqual(['abc', 'zed']);
  });
});
