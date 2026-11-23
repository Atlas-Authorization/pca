// Kills the slot-value typing (slotLits: missing, maximum, id, id_list, enum, enum_list, text_list) and the head of
// instantiateTemplate (unknown template, the question and shape of a hole). Every expected value is exact.
import { describe, expect, it } from 'vitest';
import { instantiateTemplate, slotLits } from '../src';
import type { IntentOntology, SlotKind, SlotValue, TemplateSlot } from '../src';
import type { Unit, Value } from '../src/ir';

const ONT: IntentOntology = {
  id: 't', version: 1, domain: 't',
  types: [{ id: 'acct', id_prefix: 'ac_' }, { id: 'usr', id_prefix: 'us_' }],
  units: {}, relations: [], verbs: [], aliases: {},
  templates: [{
    id: 'holes', title: 'holes', phrases: [],
    slots: [
      { name: 'my_slot_x', kind: 'money', ccy: 'USD', mandatory: true },
      { name: 'n', kind: 'count', mandatory: true },
    ],
    grants: [], prohibits: [], bounds: [], example: {},
  }],
};
type Extra = Partial<Pick<TemplateSlot, 'ccy' | 'of' | 'values' | 'max'>>;
const slot = (kind: SlotKind, extra: Extra = {}): TemplateSlot => ({ name: 'x', kind, mandatory: true, ...extra });
const raw = (x: unknown): SlotValue => x as SlotValue;
const sv = (s: string): Value => ({ k: 's', s });
const q = (u: Unit, n: number): Value[] => [{ k: 'q', q: { u, n } }];
const ILL = 'ill-typed';

describe('slotLits: missing and the template maximum', () => {
  it('an undefined value is missing', () => {
    expect(slotLits(ONT, slot('count'), undefined)).toBe('missing');
  });
  it('a money slot refuses a value above max and accepts exactly max', () => {
    const s = slot('money', { ccy: 'USD', max: 100 });
    expect(slotLits(ONT, s, { ccy: 'USD', minor: 100 })).toEqual(q({ k: 'money', ccy: 'USD' }, 100));
    expect(slotLits(ONT, s, { ccy: 'USD', minor: 101 })).toBe('above the template maximum');
  });
  it('a count and a duration slot are bounded by max too', () => {
    expect(slotLits(ONT, slot('count', { max: 5 }), { n: 5 })).toEqual(q({ k: 'count' }, 5));
    expect(slotLits(ONT, slot('count', { max: 5 }), { n: 6 })).toBe('above the template maximum');
    expect(slotLits(ONT, slot('duration', { max: 5 }), { ms: 6 })).toBe('above the template maximum');
  });
  it('an instant slot compares 0, not the instant, against max', () => {
    expect(slotLits(ONT, slot('instant', { max: 100 }), { epoch_ms: 1000 })).toEqual(q({ k: 'instant' }, 1000));
    expect(slotLits(ONT, slot('instant', { max: 0 }), { epoch_ms: 1000 })).toEqual(q({ k: 'instant' }, 1000));
  });
  it('a slot without max accepts a large value', () => {
    expect(slotLits(ONT, slot('count'), { n: Number.MAX_SAFE_INTEGER })).toEqual(q({ k: 'count' }, Number.MAX_SAFE_INTEGER));
  });
});

describe('slotLits: id', () => {
  const s = slot('id', { of: 'acct' });
  it('accepts a prefixed id of the declared type', () => {
    expect(slotLits(ONT, s, 'ac_1')).toEqual([sv('ac_1')]);
    expect(slotLits(ONT, s, 'ac_a-B_9')).toEqual([sv('ac_a-B_9')]);
  });
  it('uses the prefix of the slot type, not of the first type', () => {
    expect(slotLits(ONT, slot('id', { of: 'usr' }), 'us_1')).toEqual([sv('us_1')]);
    expect(slotLits(ONT, slot('id', { of: 'usr' }), 'ac_1')).toBe(ILL);
  });
  it('refuses a wrong prefix, the bare prefix, bad characters and non-strings', () => {
    expect(slotLits(ONT, s, 'zz_1')).toBe(ILL);
    expect(slotLits(ONT, s, 'ac_')).toBe(ILL);
    expect(slotLits(ONT, s, 'ac_ x')).toBe(ILL);
    expect(slotLits(ONT, s, 'ac_x y')).toBe(ILL);
    expect(slotLits(ONT, s, ['ac_1'])).toBe(ILL);
    expect(slotLits(ONT, s, { n: 1 })).toBe(ILL);
  });
  it('refuses an undeclared type without reading its prefix', () => {
    expect(slotLits(ONT, slot('id', { of: 'nope' }), 'undefined_x')).toBe(ILL);
    expect(slotLits(ONT, slot('id', { of: 'nope' }), 'ac_1')).toBe(ILL);
  });
});

describe('slotLits: id_list', () => {
  const s = slot('id_list', { of: 'acct' });
  it('accepts a non-empty list of prefixed ids, in order', () => {
    expect(slotLits(ONT, s, ['ac_2', 'ac_1'])).toEqual([sv('ac_2'), sv('ac_1')]);
  });
  it('uses the prefix of the slot type', () => {
    expect(slotLits(ONT, slot('id_list', { of: 'usr' }), ['us_1'])).toEqual([sv('us_1')]);
    expect(slotLits(ONT, slot('id_list', { of: 'usr' }), ['ac_1'])).toBe(ILL);
  });
  it('refuses an empty list and a non-list', () => {
    expect(slotLits(ONT, s, [])).toBe(ILL);
    expect(slotLits(ONT, s, 'ac_1')).toBe(ILL);
    expect(slotLits(ONT, s, { n: 1 })).toBe(ILL);
  });
  it('refuses a list with any bad element', () => {
    expect(slotLits(ONT, s, ['ac_1', 'zz_2'])).toBe(ILL);
    expect(slotLits(ONT, s, ['zz_2'])).toBe(ILL);
    expect(slotLits(ONT, s, ['ac_1', 'ac_ x'])).toBe(ILL);
    expect(slotLits(ONT, s, ['ac_1', 'ac_x y'])).toBe(ILL);
    expect(slotLits(ONT, s, ['ac_1', 'x_ac_'])).toBe(ILL);
  });
  it('refuses every list for an undeclared type', () => {
    expect(slotLits(ONT, slot('id_list', { of: 'nope' }), ['undefined_x'])).toBe(ILL);
    expect(slotLits(ONT, slot('id_list', { of: 'nope' }), ['ac_1'])).toBe(ILL);
  });
});

describe('slotLits: enum and enum_list', () => {
  const e = slot('enum', { values: ['a', 'b'] });
  const el = slot('enum_list', { values: ['a', 'b'] });
  it('enum accepts a member', () => {
    expect(slotLits(ONT, e, 'b')).toEqual([sv('b')]);
  });
  it('enum refuses a non-member, a non-string and an undeclared value set', () => {
    expect(slotLits(ONT, e, 'z')).toBe(ILL);
    expect(slotLits(ONT, e, ['a'])).toBe(ILL);
    expect(slotLits(ONT, e, { n: 1 })).toBe(ILL);
    expect(slotLits(ONT, slot('enum'), 'a')).toBe(ILL);
  });
  it('enum_list accepts a non-empty list of members, in order', () => {
    expect(slotLits(ONT, el, ['b', 'a'])).toEqual([sv('b'), sv('a')]);
  });
  it('enum_list refuses an empty list, a non-list, a non-member and an undeclared value set', () => {
    expect(slotLits(ONT, el, [])).toBe(ILL);
    expect(slotLits(ONT, el, 'a')).toBe(ILL);
    expect(slotLits(ONT, el, ['a', 'z'])).toBe(ILL);
    expect(slotLits(ONT, el, ['z'])).toBe(ILL);
    expect(slotLits(ONT, slot('enum_list'), ['a'])).toBe(ILL);
  });
});

describe('slotLits: text_list', () => {
  const s = slot('text_list');
  it('accepts a non-empty list of non-empty NFKC strings, in order', () => {
    expect(slotLits(ONT, s, ['beta', 'alpha'])).toEqual([sv('beta'), sv('alpha')]);
  });
  it('refuses an empty list and a non-list', () => {
    expect(slotLits(ONT, s, [])).toBe(ILL);
    expect(slotLits(ONT, s, 'alpha')).toBe(ILL);
  });
  it('refuses a list with an empty string, even beside a good one', () => {
    expect(slotLits(ONT, s, [''])).toBe(ILL);
    expect(slotLits(ONT, s, ['ok', ''])).toBe(ILL);
  });
  it('refuses a string that is not in NFKC form', () => {
    expect(slotLits(ONT, s, ['ﬁle'])).toBe(ILL);
  });
  it('refuses a non-string element', () => {
    expect(slotLits(ONT, s, raw([['ab']]))).toBe(ILL);
    expect(slotLits(ONT, s, raw([5]))).toBe(ILL);
  });
});

describe('instantiateTemplate head', () => {
  const opts = { principal: 'p', nl: 'x' };
  it('an unknown template is an error naming it', () => {
    expect(() => instantiateTemplate(ONT, 'nope', {}, opts)).toThrow(/^unknown template nope$/);
  });
  it('a missing slot becomes a hole with an exact question and empty shape', () => {
    const g = instantiateTemplate(ONT, 'holes', {}, opts);
    expect(g.holes).toStrictEqual([
      { hid: 'my_slot_x', q: 'What is the my slot x (money USD)? (missing)', domain: [], affects: [], global: false },
      { hid: 'n', q: 'What is the n (count)? (missing)', domain: [], affects: [], global: false },
    ]);
  });
  it('an ill-typed slot becomes a hole carrying the reason', () => {
    const g = instantiateTemplate(ONT, 'holes', { my_slot_x: { ccy: 'USD', minor: 5 }, n: { n: -1 } }, opts);
    expect(g.holes).toStrictEqual([{ hid: 'n', q: 'What is the n (count)? (ill-typed)', domain: [], affects: [], global: false }]);
  });
});
