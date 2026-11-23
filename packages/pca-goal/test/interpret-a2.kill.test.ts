import { describe, expect, it } from 'vitest';
import { extractCandidates, fillTemplate, ruleInterpreter, slotStems } from '../src/interpret';
import type { IntentOntology, Template, TemplateSlot } from '../src/ontology';

const ONT: IntentOntology = {
  id: 'o', version: 1, domain: 'd', units: {}, relations: [], verbs: [], aliases: {}, templates: [],
  types: [{ id: 'user', id_prefix: 'usr_' }, { id: 'order', id_prefix: 'ord_' }],
};
const slot = (over: Partial<TemplateSlot> & Pick<TemplateSlot, 'name' | 'kind'>): TemplateSlot => ({ mandatory: true, ...over });
const tmpl = (slots: TemplateSlot[]): Template => ({ id: 't', title: 'T', phrases: ['go'], slots, grants: [], prohibits: [], bounds: [], example: {} });
const fill = (slots: TemplateSlot[], text: string): { values: unknown; notes: string[] } => {
  const r = fillTemplate(tmpl(slots), ONT, text);
  return { values: r.values, notes: r.notes };
};
const USD = { ccy: 'USD' } as const;

describe('extractCandidates: counts', () => {
  it('once, one time and twice are 1, 1 and 2, in any case', () => {
    expect(extractCandidates('ONCE or Twice or ONE TIME', ONT).counts.map((c) => c.n)).toEqual([1, 2, 1]);
    expect(extractCandidates('once', ONT).counts.map((c) => c.n)).toEqual([1]);
    expect(extractCandidates('one time', ONT).counts.map((c) => c.n)).toEqual([1]);
    expect(extractCandidates('twice', ONT).counts.map((c) => c.n)).toEqual([2]);
  });
  it('before is the 40 lowercased characters ahead, after the 18 lowercased characters behind the number', () => {
    const far = extractCandidates(`${'X'.repeat(50)} 5 QUERIES PER DAY AND MORE`, ONT).counts;
    expect(far).toEqual([{ n: 5, before: `${'x'.repeat(39)} `, after: ' queries per day a' }]);
    const near = extractCandidates(`CAP 5 ${'z'.repeat(60)}`, ONT).counts;
    expect(near).toEqual([{ n: 5, before: 'cap ', after: ` ${'z'.repeat(17)}` }]);
  });
});

describe('extractCandidates: domains and words', () => {
  it('a domain after a space, a multi-label domain, several domains', () => {
    expect(extractCandidates('see example.com now', ONT).domains).toEqual(['example.com']);
    expect(extractCandidates('mail.sub.example.com', ONT).domains).toEqual(['mail.sub.example.com']);
    expect(extractCandidates('go to bar.io, then foo.io.', ONT).domains).toEqual(['bar.io', 'foo.io']);
  });
  it('a one-letter top-level label is not a domain', () => {
    expect(extractCandidates('x.y', ONT).domains).toEqual([]);
    expect(extractCandidates('example.com-x', ONT).domains).toEqual([]);
  });
  it('words is the lowercased text', () => {
    expect(extractCandidates('Hello WORLD', ONT).words).toBe('hello world');
  });
});

describe('slotStems', () => {
  const stems = (name: string): string[] => slotStems(slot({ name, kind: 'count' }));
  it('drops max_ and the plural ending, only at the end of the word', () => {
    expect(stems('max_queries')).toEqual(['queri']);
    expect(stems('max_boxes')).toEqual(['box']);
    expect(stems('max_status')).toEqual(['statu']);
  });
  it('max_ is dropped only as a prefix', () => {
    expect(stems('foo_max_bar')).toEqual(['foo', 'max', 'bar']);
  });
  it('stems of two letters or fewer are dropped', () => {
    expect(stems('max_ab_big_items')).toEqual(['big', 'item']);
    expect(stems('max_ids')).toEqual([]);
  });
});

describe('fillSlot: id and id_list', () => {
  const id = slot({ name: 'u', kind: 'id', of: 'user' });
  const ids = slot({ name: 'us', kind: 'id_list', of: 'user' });
  it('one id of the slot type fills it, also when it is repeated or next to an id of another type', () => {
    expect(fill([id], 'refund usr_1 now')).toEqual({ values: { u: 'usr_1' }, notes: [] });
    expect(fill([id], 'usr_1 and usr_1')).toEqual({ values: { u: 'usr_1' }, notes: [] });
    expect(fill([id], 'usr_1 ord_9')).toEqual({ values: { u: 'usr_1' }, notes: [] });
  });
  it('several ids leave an id slot a hole', () => {
    expect(fill([id], 'usr_1 and usr_2')).toEqual({ values: {}, notes: ['u: ambiguous: several ids'] });
  });
  it('an id of the wrong type, or none, is not found', () => {
    expect(fill([id], 'ord_9 only')).toEqual({ values: {}, notes: ['u: not found'] });
    expect(fill([id], 'nothing')).toEqual({ values: {}, notes: ['u: not found'] });
    expect(fill([ids], 'ord_3')).toEqual({ values: {}, notes: ['us: not found'] });
  });
  it('an id_list takes every id of its type, even one', () => {
    expect(fill([ids], 'usr_1 usr_2 ord_3')).toEqual({ values: { us: ['usr_1', 'usr_2'] }, notes: [] });
    expect(fill([ids], 'usr_1')).toEqual({ values: { us: ['usr_1'] }, notes: [] });
  });
});

describe('ruleInterpreter: an id slot whose type is not declared', () => {
  it('is a hole, with no fill note and no throw', async () => {
    const o: IntentOntology = { ...ONT, templates: [tmpl([slot({ name: 'u', kind: 'id', of: 'ghost' })])] };
    const r = await ruleInterpreter('r').interpret({ principal: 'P', text: 'go usr_1', ontology: o });
    expect(r.notes).toEqual([]);
    expect(r.goal.holes.map((h) => h.hid)).toEqual(['u']);
  });
});

describe('fillSlot: money', () => {
  const m = slot({ name: 'm', kind: 'money', ...USD });
  it('one amount in the slot currency fills it in minor units', () => {
    expect(fill([m], 'limit $50 total')).toEqual({ values: { m: { ccy: 'USD', minor: 5000 } }, notes: [] });
  });
  it('an amount in another currency is never converted', () => {
    const note = 'm: an amount in another currency: never convert or guess';
    expect(fill([m], 'give €50')).toEqual({ values: {}, notes: [note] });
    expect(fill([m], '$50 and €20')).toEqual({ values: {}, notes: [note] });
  });
  it('an ambiguous amount anywhere in the text refuses, even beside a clear one', () => {
    const note = 'm: an amount in the text is ambiguous or untyped: never guess which one is the limit';
    expect(fill([m], '$1.234')).toEqual({ values: {}, notes: [note] });
    expect(fill([m], '$1.234 and $5')).toEqual({ values: {}, notes: [note] });
  });
  it('no amount is not found, two amounts are ambiguous', () => {
    expect(fill([m], 'no amounts here')).toEqual({ values: {}, notes: ['m: not found'] });
    expect(fill([m], '$50 and $20')).toEqual({ values: {}, notes: ['m: ambiguous: several amounts'] });
  });
  it('a single money slot ignores its cue, so two amounts stay ambiguous', () => {
    expect(fill([slot({ name: 'm', kind: 'money', ...USD, cue: ['daily'] })], 'daily $50 weekly $20')).toEqual({ values: {}, notes: ['m: ambiguous: several amounts'] });
  });
  it('with several money slots each one takes only the amount its cue words precede', () => {
    const text = `daily cap $100 ${'z'.repeat(45)} weekly cap $20`;
    const a = slot({ name: 'daily_cap', kind: 'money', ...USD, cue: ['daily'] });
    const b = slot({ name: 'weekly_cap', kind: 'money', ...USD, cue: ['weekly'] });
    expect(fill([a, b], text)).toEqual({ values: { daily_cap: { ccy: 'USD', minor: 10000 }, weekly_cap: { ccy: 'USD', minor: 2000 } }, notes: [] });
    expect(fill([a, b, slot({ name: 'plain', kind: 'money', ...USD })], text)).toEqual({
      values: { daily_cap: { ccy: 'USD', minor: 10000 }, weekly_cap: { ccy: 'USD', minor: 2000 } }, notes: ['plain: not found'],
    });
    expect(fill([slot({ name: 'p', kind: 'money', ...USD, cue: ['cap'] }), slot({ name: 'q', kind: 'money', ...USD, cue: ['cap'] })], text)).toEqual({
      values: {}, notes: ['p: ambiguous: several amounts', 'q: ambiguous: several amounts'],
    });
    expect(fill([slot({ name: 'x', kind: 'money', ...USD, cue: ['monthly'] }), b], text)).toEqual({ values: { weekly_cap: { ccy: 'USD', minor: 2000 } }, notes: ['x: not found'] });
  });
});

describe('fillSlot: count', () => {
  it('a count whose stems the text names wins over another number', () => {
    const r = fillTemplate(tmpl([slot({ name: 'max_queries', kind: 'count' })]), ONT, '3 queries and 7 files');
    expect(r).toEqual({ values: { max_queries: { n: 3 } }, notes: [], unattributed: [7] });
  });
  it('one stem of several is enough to name a count', () => {
    expect(fill([slot({ name: 'max_big_items', kind: 'count' })], '5 items and 7 bananas')).toEqual({ values: { max_big_items: { n: 5 } }, notes: [] });
  });
  it('without a cue, the only number is taken and two numbers are not found', () => {
    const rows = slot({ name: 'rows', kind: 'count' });
    expect(fill([rows], 'do it 5')).toEqual({ values: { rows: { n: 5 } }, notes: [] });
    expect(fill([rows], '5 and 7')).toEqual({ values: {}, notes: ['rows: not found'] });
    expect(fill([rows], 'nothing')).toEqual({ values: {}, notes: ['rows: not found'] });
  });
  it('with a cue, the lone number must follow a cue word', () => {
    expect(fill([slot({ name: 'burst', kind: 'count', cue: ['within'] })], 'do it 5')).toEqual({ values: {}, notes: ['burst: not found'] });
  });
  it('a cue picks the number it precedes, one cue word is enough', () => {
    const burst = slot({ name: 'burst', kind: 'count', cue: ['within', 'inside'] });
    expect(fillTemplate(tmpl([burst]), ONT, '10 within 5 minutes')).toEqual({ values: { burst: { n: 5 } }, notes: [], unattributed: [10] });
  });
  it('a number another count slot is named by is not taken by a cue', () => {
    const burst = slot({ name: 'burst', kind: 'count', cue: ['within'] });
    const retries = slot({ name: 'max_retries', kind: 'count' });
    const r = fillTemplate(tmpl([burst, retries]), ONT, 'within 3 retries and 5 minutes');
    expect(r).toEqual({ values: { burst: { n: 5 }, max_retries: { n: 3 } }, notes: [], unattributed: [] });
  });
  it('two different numbers after the cue are ambiguous, the same number twice is not', () => {
    const burst = slot({ name: 'burst', kind: 'count', cue: ['within'] });
    expect(fillTemplate(tmpl([burst]), ONT, 'within 3 and 5')).toEqual({ values: {}, notes: ['burst: ambiguous: several counts'], unattributed: [3, 5] });
    expect(fillTemplate(tmpl([burst]), ONT, 'within 5 and 5')).toEqual({ values: { burst: { n: 5 } }, notes: [], unattributed: [] });
  });
});

describe('fillSlot: enum and enum_list', () => {
  const en = (values?: string[]): TemplateSlot => slot({ name: 'tier', kind: 'enum', ...(values ? { values } : {}) });
  const el = (values?: string[]): TemplateSlot => slot({ name: 'c', kind: 'enum_list', ...(values ? { values } : {}) });
  it('one value named as a whole word fills an enum', () => {
    expect(fill([en(['gold', 'silver'])], 'give gold access')).toEqual({ values: { tier: 'gold' }, notes: [] });
    expect(fill([en(['gold', 'silver'])], 'golden access')).toEqual({ values: {}, notes: ['tier: not found'] });
    expect(fill([en(['gold', 'silver'])], 'gold or silver')).toEqual({ values: {}, notes: ['tier: ambiguous: several values'] });
  });
  it('matching is case-insensitive and reads underscores as spaces', () => {
    expect(fill([en(['Gold', 'Silver'])], 'GOLD please')).toEqual({ values: { tier: 'Gold' }, notes: [] });
    expect(fill([en(['on_hold', 'active'])], 'put on hold')).toEqual({ values: { tier: 'on_hold' }, notes: [] });
    expect(fill([en(['on_hold', 'active'])], 'put onhold')).toEqual({ values: {}, notes: ['tier: not found'] });
    expect(fill([en(['dev', 'prod'])], 'use dev')).toEqual({ values: { tier: 'dev' }, notes: [] });
  });
  it('a value with regex metacharacters matches only literally', () => {
    expect(fill([en(['a.b'])], 'axb')).toEqual({ values: {}, notes: ['tier: not found'] });
    expect(fill([en(['a.b'])], 'ab')).toEqual({ values: {}, notes: ['tier: not found'] });
    expect(fill([en(['a.b'])], 'a.b')).toEqual({ values: { tier: 'a.b' }, notes: [] });
    expect(fill([en(['c++'])], 'c++')).toEqual({ values: { tier: 'c++' }, notes: [] });
    expect(fill([en(['x(y)'])], 'x(y)')).toEqual({ values: { tier: 'x(y)' }, notes: [] });
    expect(fill([en(['d|e'])], 'd')).toEqual({ values: {}, notes: ['tier: not found'] });
    expect(fill([en(['d|e'])], 'd|e')).toEqual({ values: { tier: 'd|e' }, notes: [] });
  });
  it('an enum without values is never filled', () => {
    expect(fill([en()], 'stryker was here')).toEqual({ values: {}, notes: ['tier: not found'] });
    expect(fill([el()], 'stryker was here')).toEqual({ values: {}, notes: ['c: not found'] });
  });
  it('an enum_list takes every named value, in the order declared', () => {
    const c = el(['red', 'green', 'light_blue']);
    expect(fill([c], 'Light blue and red')).toEqual({ values: { c: ['red', 'light_blue'] }, notes: [] });
    expect(fill([c], 'only green')).toEqual({ values: { c: ['green'] }, notes: [] });
    expect(fill([c], 'nothing')).toEqual({ values: {}, notes: ['c: not found'] });
  });
});

describe('fillSlot: text_list, duration and instant', () => {
  it('a text_list takes the distinct domains', () => {
    const d = slot({ name: 'd', kind: 'text_list' });
    expect(fill([d], 'allow a.com and b.org and a.com')).toEqual({ values: { d: ['a.com', 'b.org'] }, notes: [] });
    expect(fill([d], 'allow nobody')).toEqual({ values: {}, notes: ['d: not found'] });
  });
  it('a duration and an instant are never read from free text', () => {
    expect(fill([slot({ name: 'dur', kind: 'duration' }), slot({ name: 'at', kind: 'instant' })], 'for 5 minutes at noon')).toEqual({
      values: {}, notes: ['dur: unsupported in free text', 'at: unsupported in free text'],
    });
  });
});
