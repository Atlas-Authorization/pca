import { describe, expect, it } from 'vitest';
import { hashCanonical } from '@atlasauth/pca';
import { extractCandidates, formInterpreter, sourceDigest, type Candidates } from '../src/interpret';
import { nlDigest } from '../src/digests';
import { ontologyDigest, type IntentOntology, type Template } from '../src/ontology';

const T: Template = {
  id: 't1', title: 'Refund', phrases: ['refund'],
  slots: [
    { name: 'customer', kind: 'id', of: 'cust', mandatory: true },
    { name: 'max_amount', kind: 'money', ccy: 'USD', mandatory: true },
  ],
  grants: [{ gid: 'g1', verb: 'pay.refund', res: { k: 'exact', id: '$customer' }, cond: { k: 'cmp', op: 'lte', l: { k: 'param', path: 'amount' }, r: { k: 'slot', slot: 'max_amount' } } }],
  prohibits: [], bounds: [], example: {},
};
const IONT: IntentOntology = {
  id: 'o1', version: 1, domain: 'testdom',
  types: [{ id: 'cust', id_prefix: 'cust_' }], units: {}, relations: [],
  verbs: [{ id: 'pay.refund', effect: 'reversible', resource_type: 'cust', params: { amount: { kind: 'money', ccys: ['USD'] } } }],
  aliases: {}, templates: [T],
};
const CAND_ONT: IntentOntology = { ...IONT, types: [{ id: 'cust', id_prefix: 'cust_' }, { id: 'ord', id_prefix: 'ord.' }] };
const FORM = { template: 't1', slots: { customer: 'cust_A1', max_amount: { ccy: 'USD', minor: 5000 } } };

describe('sourceDigest and the unsignable draft', () => {
  it('sourceDigest hashes the text under the goal-source domain', () => {
    expect(sourceDigest('doc one')).toBe(hashCanonical({ d: 'atlas-pca/goal-source/v1', text: 'doc one' }));
    expect(sourceDigest('doc one')).not.toBe(sourceDigest('doc two'));
  });
  it('no form: one global form hole, an otherwise empty goal, no sources', async () => {
    const req = { principal: 'P1', text: 'hello', ontology: IONT };
    const r = await formInterpreter().interpret(req);
    expect(r).toEqual({
      id: 'form', family: 'rule', deterministic: true, notes: ['no form'],
      goal: {
        v: 1, principal: 'P1', ontDigest: ontologyDigest(IONT), nlDigest: nlDigest('hello'), sources: [],
        grants: [], prohibits: [], bounds: [],
        validity: { notBefore: 0, notAfter: Number.MAX_SAFE_INTEGER, maxIdle: 0 },
        deleg: { maxDepth: 0, narrowOnly: true, mayTouch: [] },
        escalateOn: [], wildcardAck: [],
        holes: [{ hid: 'form', q: 'No form was provided.', domain: [], affects: [], global: true }],
      },
    });
  });
  it('no form with sources: the sources are digested in order', async () => {
    const r = await formInterpreter('f2').interpret({ principal: 'P1', text: 'hello', ontology: IONT, sources: ['doc one', 'doc two'] });
    expect(r.id).toBe('f2');
    expect(r.goal.sources).toEqual([hashCanonical({ d: 'atlas-pca/goal-source/v1', text: 'doc one' }), sourceDigest('doc two')]);
  });
  it('a form without sources yields an empty source list; with sources, their digests', async () => {
    const a = await formInterpreter().interpret({ principal: 'P1', text: 'refund cust_A1', ontology: IONT, form: FORM });
    expect(a.goal.sources).toEqual([]);
    expect(a.goal.holes).toEqual([]);
    expect(a.goal.nlDigest).toBe(nlDigest('refund cust_A1'));
    expect(a.notes).toEqual([]);
    const b = await formInterpreter().interpret({ principal: 'P1', text: 'refund cust_A1', ontology: IONT, form: FORM, sources: ['doc one'] });
    expect(b.goal.sources).toEqual([sourceDigest('doc one')]);
  });
});

const LOCALES = [undefined, 'en', 'de'] as const;
const X = (text: string, over: Partial<Candidates> = {}): Candidates => ({ ids: [], amounts: [], ambiguousAmounts: 0, counts: [], words: text.toLowerCase(), domains: [], ...over });

describe('extractCandidates: ids', () => {
  it('ids need a clean left edge and the exact prefix, regex characters in a prefix are literal', () => {
    for (const loc of LOCALES) {
      const text = 'refund cust_A1 and cust_b-x, xcust_Z9 ord.7 ordx1 ord.7';
      expect(extractCandidates(text, CAND_ONT, loc)).toEqual(X(text, { ids: ['cust_A1', 'cust_b-x', 'ord.7', 'ord.7'] }));
    }
  });
});

describe('extractCandidates: amounts', () => {
  it('a single-digit amount with a symbol', () => {
    for (const loc of LOCALES) {
      const text = 'pay up to $5 total';
      expect(extractCandidates(text, IONT, loc)).toEqual(X(text, { amounts: [{ ccy: 'USD', minor: 500, before: 'pay up to ' }] }));
    }
  });
  it('a decimal amount reads the same in every locale', () => {
    for (const loc of LOCALES) {
      const text = 'fee $1.50 each';
      expect(extractCandidates(text, IONT, loc)).toEqual(X(text, { amounts: [{ ccy: 'USD', minor: 150, before: 'fee ' }] }));
    }
  });
  it('two amounts keep their order and what precedes each', () => {
    for (const loc of LOCALES) {
      const text = 'send $5 or $10.50 max';
      expect(extractCandidates(text, IONT, loc)).toEqual(X(text, { amounts: [{ ccy: 'USD', minor: 500, before: 'send ' }, { ccy: 'USD', minor: 1050, before: 'send $5 or ' }] }));
    }
  });
  it('a lone separator group is ambiguous without a locale, a thousands group in en, too many decimals in de', () => {
    const text = 'limit of $1,000 only';
    expect(extractCandidates(text, IONT)).toEqual(X(text, { ambiguousAmounts: 1 }));
    expect(extractCandidates(text, IONT, 'en')).toEqual(X(text, { amounts: [{ ccy: 'USD', minor: 100000, before: 'limit of ' }] }));
    expect(extractCandidates(text, IONT, 'de')).toEqual(X(text, { ambiguousAmounts: 1 }));
  });
  it('a dot group is the mirror image', () => {
    const text = 'limit of $1.000 only';
    expect(extractCandidates(text, IONT)).toEqual(X(text, { ambiguousAmounts: 1 }));
    expect(extractCandidates(text, IONT, 'en')).toEqual(X(text, { ambiguousAmounts: 1 }));
    expect(extractCandidates(text, IONT, 'de')).toEqual(X(text, { amounts: [{ ccy: 'USD', minor: 100000, before: 'limit of ' }] }));
  });
  it('both separators fix the decimal one in every locale', () => {
    for (const loc of LOCALES) {
      const text = 'cap €1.000,50 now';
      expect(extractCandidates(text, IONT, loc)).toEqual(X(text, { amounts: [{ ccy: 'EUR', minor: 100050, before: 'cap ' }] }));
    }
  });
  it('a zero-exponent currency has no minor digits', () => {
    const text = 'cap ¥1,000 now';
    expect(extractCandidates(text, IONT)).toEqual(X(text, { ambiguousAmounts: 1 }));
    expect(extractCandidates(text, IONT, 'en')).toEqual(X(text, { amounts: [{ ccy: 'JPY', minor: 1000, before: 'cap ' }] }));
    expect(extractCandidates(text, IONT, 'de')).toEqual(X(text, { ambiguousAmounts: 1 }));
  });
  it('a currency word after the number: plural, singular and any case; the number is not also a count', () => {
    for (const loc of LOCALES) {
      const a = 'up to 5 dollars';
      expect(extractCandidates(a, IONT, loc)).toEqual(X(a, { amounts: [{ ccy: 'USD', minor: 500, before: 'up to' }] }));
      const b = '3 dollar';
      expect(extractCandidates(b, IONT, loc)).toEqual(X(b, { amounts: [{ ccy: 'USD', minor: 300, before: '' }] }));
      const c = '4 euro';
      expect(extractCandidates(c, IONT, loc)).toEqual(X(c, { amounts: [{ ccy: 'EUR', minor: 400, before: '' }] }));
      const d = '5 Dollars';
      expect(extractCandidates(d, IONT, loc)).toEqual(X(d, { amounts: [{ ccy: 'USD', minor: 500, before: '' }] }));
      const e = '2 pounds';
      expect(extractCandidates(e, IONT, loc)).toEqual(X(e, { amounts: [{ ccy: 'GBP', minor: 200, before: '' }] }));
      const f = '100 yen';
      expect(extractCandidates(f, IONT, loc)).toEqual(X(f, { amounts: [{ ccy: 'JPY', minor: 100, before: '' }] }));
      const g = '8 GBP';
      expect(extractCandidates(g, IONT, loc)).toEqual(X(g, { amounts: [{ ccy: 'GBP', minor: 800, before: '' }] }));
      const h = '7 usd';
      expect(extractCandidates(h, IONT, loc)).toEqual(X(h, { amounts: [{ ccy: 'USD', minor: 700, before: '' }] }));
    }
  });
  it('a currency code must stand alone: glued to the number or to a letter it is no currency', () => {
    for (const loc of LOCALES) {
      expect(extractCandidates('5USD', IONT, loc)).toEqual(X('5USD'));
      expect(extractCandidates('5 USDx', IONT, loc)).toEqual(X('5 USDx'));
    }
  });
});

describe('extractCandidates: counts', () => {
  it('a count followed by a noun keeps what is around it', () => {
    for (const loc of LOCALES) {
      const text = 'refund 3 times';
      expect(extractCandidates(text, IONT, loc)).toEqual(X(text, { counts: [{ n: 3, before: 'refund ', after: ' times' }] }));
    }
  });
  it('once, twice and one time in any case read as 1, 2, 1 with lower-cased context', () => {
    for (const loc of LOCALES) {
      const text = 'Pay once or Twice or One Time';
      expect(extractCandidates(text, IONT, loc)).toEqual(X(text, {
        counts: [
          { n: 1, before: 'pay ', after: ' or twice or one t' },
          { n: 2, before: 'pay once or ', after: ' or one time' },
          { n: 1, before: 'pay once or twice or ', after: '' },
        ],
      }));
    }
  });
  it('a number that is part of a decimal is no count', () => {
    for (const loc of LOCALES) {
      const a = 'ratio 3.5 here';
      expect(extractCandidates(a, IONT, loc)).toEqual(X(a));
      const b = 'ratio 3 .5 here';
      expect(extractCandidates(b, IONT, loc)).toEqual(X(b));
    }
  });
  it('a number followed by a separator and a non-digit, or by a space and a non-separator, stays a count', () => {
    for (const loc of LOCALES) {
      const a = 'ok 3.x go';
      expect(extractCandidates(a, IONT, loc)).toEqual(X(a, { counts: [{ n: 3, before: 'ok ', after: '.x go' }] }));
      const b = 'set 3 x5 now';
      expect(extractCandidates(b, IONT, loc)).toEqual(X(b, { counts: [{ n: 3, before: 'set ', after: ' x5 now' }] }));
    }
  });
  it('a number before a currency word is an amount, not a count (singular and plural)', () => {
    for (const loc of LOCALES) {
      for (const t of ['3 dollars', '3 dollar', '4 euro', '4 euros']) {
        expect(extractCandidates(t, IONT, loc).counts).toEqual([]);
      }
    }
  });
  it('a number right after a currency symbol is no count, with or without a space', () => {
    for (const loc of LOCALES) {
      const a = '$5 times';
      expect(extractCandidates(a, IONT, loc)).toEqual(X(a, { amounts: [{ ccy: 'USD', minor: 500, before: '' }] }));
      const b = '$ 5 times';
      expect(extractCandidates(b, IONT, loc)).toEqual(X(b, { amounts: [{ ccy: 'USD', minor: 500, before: '' }] }));
    }
  });
  it('only the two characters before the number are looked at for a symbol', () => {
    for (const loc of LOCALES) {
      const a = '$-5 times';
      expect(extractCandidates(a, IONT, loc)).toEqual(X(a, { counts: [{ n: 5, before: '$-', after: ' times' }] }));
      const b = '5 times $';
      expect(extractCandidates(b, IONT, loc)).toEqual(X(b, { counts: [{ n: 5, before: '', after: ' times $' }] }));
    }
  });
  it('a digit count glued to a word character or dash is no count; a word count is', () => {
    for (const loc of LOCALES) {
      const a = 'keep 5-day logs';
      expect(extractCandidates(a, IONT, loc)).toEqual(X(a));
      const b = 'do once-only';
      expect(extractCandidates(b, IONT, loc)).toEqual(X(b, { counts: [{ n: 1, before: 'do ', after: '-only' }] }));
    }
  });
});
