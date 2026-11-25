// Kills the remaining survivors of ontology.ts (refsCond 'or', the example-instantiation guard, quantityOf's string/array guard) and
// interpret.ts (llmInterpreter.deterministic). ontology.ts:267 enum/id mutants are equivalent: see the note at the end.
import { describe, expect, it } from 'vitest';
import { checkOntology, llmInterpreter, slotLits } from './index';
import type { IntentOntology, SlotValue, Template, TemplateSlot } from './index';

const T = (extra: Partial<Template>): Template => ({ id: 't', title: 't', phrases: [], slots: [], grants: [], prohibits: [], bounds: [], example: {}, ...extra });
const O = (templates: Template[]): IntentOntology => ({
  id: 'o', version: 1, domain: 'o', types: [{ id: 'acct', id_prefix: 'ac_' }], units: { USD: { kind: 'money', exponent: 2 } }, relations: [],
  verbs: [{ id: 'look', effect: 'read', resource_type: 'acct', params: { q: { kind: 'text' } } }], aliases: {}, templates,
});
const TRUE = { k: 'true' as const };

describe('ontology.ts refsCond / example guard', () => {
  it('collects slot references below an or (127)', () => {
    const cond = { k: 'or' as const, a: { k: 'cmp' as const, op: 'eq' as const, l: { k: 'param' as const, path: 'q' }, r: { k: 'slot' as const, slot: 'ghost' } }, b: TRUE };
    const issues = checkOntology(O([T({ grants: [{ gid: 'g1', verb: 'look', res: { k: 'any', reason: 'r' }, cond }] })]));
    expect(issues.filter((i) => i.code === 'slot_undeclared')).toEqual([{ code: 'slot_undeclared', where: 'template:t', msg: 'slot ghost is used but not declared' }]);
  });
  it('still instantiates the example when no money parameter lacks a currency (230)', () => {
    const slot: TemplateSlot = { name: 'acct', kind: 'id', of: 'acct', mandatory: true };
    const issues = checkOntology(O([T({ slots: [slot], grants: [{ gid: 'g1', verb: 'look', res: { k: 'exact', id: '$acct' }, cond: TRUE }] })]));
    const eh = issues.filter((i) => i.code === 'example_holes');
    expect(eh).toHaveLength(1);
    expect(eh[0]!.where).toBe('template:t');
    expect(eh[0]!.msg.startsWith('example leaves holes: ')).toBe(true);
  });
});

describe('ontology.ts slotLits on non-object values (297)', () => {
  const o = O([]);
  const money: TemplateSlot = { name: 'm', kind: 'money', ccy: 'USD', mandatory: true };
  const count: TemplateSlot = { name: 'c', kind: 'count', mandatory: true };
  it('rejects strings and arrays as ill-typed instead of throwing', () => {
    for (const s of [money, count]) {
      expect(slotLits(o, s, 'abc' as SlotValue)).toBe('ill-typed');
      expect(slotLits(o, s, ['abc'] as SlotValue)).toBe('ill-typed');
    }
  });
  it('accepts the matching object', () => {
    expect(slotLits(o, money, { ccy: 'USD', minor: 5 })).toEqual([{ k: 'q', q: { u: { k: 'money', ccy: 'USD' }, n: 5 } }]);
  });
});

describe('interpret.ts llmInterpreter (233)', () => {
  it('is declared non-deterministic', () => {
    const i = llmInterpreter({ id: 'm', family: 'f', complete: async () => '' });
    expect(i.deterministic).toBe(false);
  });
});

// ontology.ts:267 'enum' / 'id' survivors (cols 106, 117, 176, 187) are equivalent: okKind is `p.kind === s.kind || (p.kind === 'enum' && (s.kind === 'enum' || ...)) || ...`.
// Whenever p.kind === 'enum' and s.kind === 'enum' the first disjunct is already true, so replacing the inner `s.kind === 'enum'` (or 'id') by false / "" never changes okKind.
