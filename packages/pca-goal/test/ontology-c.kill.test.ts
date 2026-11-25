// Kills the ontology checker's condition and literal checks (checkCond, litCheck), the Allow-witness gate and the slot-quantity typing.
// One valid base ontology; each case changes exactly one thing in the single grant's condition. The grant's resource is a slot
// reference left unfilled by the example, so instantiation takes the hole path and drops the grant: only the condition check speaks.
import { describe, expect, it } from 'vitest';
import { ALL_ONTOLOGIES, checkOntology, slotLits } from '../src';
import type { IntentOntology, OntParam, OntologyIssue, SlotKind, TCond, Template, TemplateSlot, TTerm } from '../src';
import type { Op, Unit, Value } from '../src/ir';
import { and, cmp } from '../src/ontologies/dsl';

const W = 'template:t.g1';

const PARAMS: Record<string, OntParam> = {
  amt: { kind: 'money', ccys: ['USD', 'EUR'] },
  m0: { kind: 'money' },
  mblank: { kind: 'money', ccys: [''] },
  cnt: { kind: 'count' },
  dur: { kind: 'duration' },
  inst: { kind: 'instant' },
  byt: { kind: 'bytes' },
  rat: { kind: 'ratio' },
  idp: { kind: 'id', of: 'acct' },
  en: { kind: 'enum', values: ['a', 'b'] },
  e0: { kind: 'enum' },
  txt: { kind: 'text' },
};
const SLOTS: TemplateSlot[] = [
  { name: 'acct', kind: 'id', of: 'acct', mandatory: true },
  { name: 's_money', kind: 'money', ccy: 'USD', mandatory: true },
  { name: 's_jpy', kind: 'money', ccy: 'JPY', mandatory: true },
  { name: 's_nocy', kind: 'money', mandatory: true },
  { name: 's_count', kind: 'count', ccy: 'USD', mandatory: true },
  { name: 's_duration', kind: 'duration', mandatory: true },
  { name: 's_instant', kind: 'instant', mandatory: true },
  { name: 's_id', kind: 'id', of: 'acct', mandatory: true },
  { name: 's_id_list', kind: 'id_list', of: 'acct', mandatory: true },
  { name: 's_enum', kind: 'enum', values: ['a', 'b'], mandatory: true },
  { name: 's_enum_list', kind: 'enum_list', values: ['a', 'b'], mandatory: true },
  { name: 's_text_list', kind: 'text_list', mandatory: true },
];
const ont = (cond: TCond): IntentOntology => ({
  id: 't', version: 1, domain: 't',
  types: [{ id: 'acct', id_prefix: 'ac_' }],
  units: { USD: { kind: 'money', exponent: 2 }, EUR: { kind: 'money', exponent: 2 }, JPY: { kind: 'money', exponent: 0 }, count: { kind: 'count' } },
  relations: [],
  verbs: [{ id: 'act', effect: 'reversible', resource_type: 'acct', params: PARAMS }],
  aliases: {},
  templates: [{
    id: 't', title: 't', phrases: [], slots: SLOTS,
    grants: [{ gid: 'g1', verb: 'act', res: { k: 'exact', id: '$acct' }, cond }],
    prohibits: [], bounds: [], example: {},
  }],
});
const run = (cond: TCond): OntologyIssue[] => checkOntology(ont(cond)).filter((i) => i.where === W);
const I = (code: string, msg: string): OntologyIssue => ({ code, where: W, msg });

const P = (path: string): TTerm => ({ k: 'param', path });
const S = (slot: string): TTerm => ({ k: 'slot', slot });
const L = (v: Value): TTerm => ({ k: 'lit', v });
const C = (op: Op, l: TTerm, r: TTerm): TCond => ({ k: 'cmp', op, l, r });
const str = (s: string): Value => ({ k: 's', s });
const qty = (u: Unit): Value => ({ k: 'q', q: { u, n: 1 } });
const set = (...items: Value[]): Value => ({ k: 'set', items });

const COND_PARAM = 'left side of a comparison must be a declared parameter of the verb';
const ORDER = 'ordering on a text/enum/id parameter';
const SLOT_UNIT = 'slot currency is not accepted by the parameter';
const LIST_PAIR = 'list slots pair with in/nin and scalar slots with the other operators';
const EMPTY_LIST = 'empty literal list';
const SET_OP = 'a literal set pairs with in/nin';
const NEED_LIST = 'in/nin needs a list';
const TERM = 'unsupported right-hand term';
const KIND = 'literal kind differs from the parameter kind';
const LIT_UNIT = 'literal currency is not accepted by the parameter';
const ENUM = 'enum literal is not a member';
const NESTED = 'nested literal set';

describe('the base fixture is clean', () => {
  it('a true condition and a well-typed comparison raise nothing at the grant', () => {
    expect(run({ k: 'true' })).toEqual([]);
    expect(run(C('lte', P('amt'), S('s_money')))).toEqual([]);
  });
});

describe('checkCond structure', () => {
  const bad = C('eq', L(str('x')), L(str('x')));
  it('descends through not, and and or', () => {
    expect(run({ k: 'not', c: bad })).toEqual([I('cond_param', COND_PARAM)]);
    expect(run({ k: 'and', a: bad, b: { k: 'true' } })).toEqual([I('cond_param', COND_PARAM)]);
    expect(run({ k: 'or', a: { k: 'true' }, b: bad })).toEqual([I('cond_param', COND_PARAM)]);
    expect(run({ k: 'not', c: { k: 'not', c: bad } })).toEqual([I('cond_param', COND_PARAM)]);
  });
  it('the left side must be a declared parameter of the verb', () => {
    expect(run(bad)).toEqual([I('cond_param', COND_PARAM)]);
    expect(run(C('eq', S('s_count'), L(qty({ k: 'count' }))))).toEqual([I('cond_param', COND_PARAM)]);
    expect(run(C('eq', P('nope'), L(str('a'))))).toEqual([I('cond_param', COND_PARAM)]);
  });
  it('an undeclared slot on the right is left to the slot check', () => {
    expect(run(C('eq', P('cnt'), S('ghost')))).toEqual([]);
  });
  it('a parameter on the right is an unsupported term', () => {
    expect(run(C('eq', P('cnt'), P('cnt')))).toEqual([I('cond_term', TERM)]);
  });
});

describe('ordering', () => {
  const ORDERED: Op[] = ['lt', 'lte', 'gt', 'gte'];
  for (const op of ORDERED) {
    for (const p of ['en', 'txt', 'idp']) {
      it(`${op} on ${p} is refused`, () => {
        expect(run(C(op, P(p), L(str('a'))))).toEqual([I('cond_order', ORDER)]);
      });
    }
    it(`${op} on a count or money parameter is fine`, () => {
      expect(run(C(op, P('cnt'), L(qty({ k: 'count' }))))).toEqual([]);
      expect(run(C(op, P('amt'), S('s_money')))).toEqual([]);
    });
  }
  it('equality on an enum is fine', () => {
    expect(run(C('eq', P('en'), L(str('a'))))).toEqual([]);
    expect(run(C('ne', P('en'), L(str('a'))))).toEqual([]);
  });
});

describe('slot terms: kind, currency and list pairing, over every parameter kind x slot kind x operator', () => {
  const PNAME: Record<string, string> = { money: 'amt', count: 'cnt', duration: 'dur', instant: 'inst', bytes: 'byt', ratio: 'rat', id: 'idp', enum: 'en', text: 'txt' };
  const ALLOWED: Record<string, string[]> = {
    money: ['money'], count: ['count'], duration: ['duration'], instant: ['instant'], bytes: [], ratio: [],
    id: ['id', 'id_list'], enum: ['enum', 'enum_list'], text: ['text_list'],
  };
  const SKINDS: SlotKind[] = ['money', 'count', 'duration', 'instant', 'id', 'id_list', 'enum', 'enum_list', 'text_list'];
  const OPS: Op[] = ['eq', 'in', 'nin'];
  for (const [pk, pname] of Object.entries(PNAME)) {
    for (const sk of SKINDS) {
      for (const op of OPS) {
        it(`${pk} parameter vs ${sk} slot with ${op}`, () => {
          const want: OntologyIssue[] = [];
          if (!ALLOWED[pk]!.includes(sk)) want.push(I('cond_type', `slot s_${sk} (${sk}) does not type-check against parameter kind ${pk}`));
          const list = sk === 'id_list' || sk === 'enum_list' || sk === 'text_list';
          if (list !== (op !== 'eq')) want.push(I('cond_type', LIST_PAIR));
          expect(run(C(op, P(pname), S(`s_${sk}`)))).toEqual(want);
        });
      }
    }
  }
  it('a money slot in a currency the parameter does not list is refused', () => {
    expect(run(C('eq', P('amt'), S('s_jpy')))).toEqual([I('cond_unit', SLOT_UNIT)]);
    expect(run(C('eq', P('amt'), S('s_money')))).toEqual([]);
  });
  it('a money parameter that lists no currency accepts no slot currency', () => {
    expect(run(C('eq', P('m0'), S('s_money')))).toEqual([I('cond_unit', SLOT_UNIT)]);
  });
  it('a slot with no currency is looked up as the empty currency', () => {
    expect(run(C('eq', P('mblank'), S('s_nocy')))).toEqual([]);
    expect(run(C('eq', P('amt'), S('s_nocy')))).toEqual([I('cond_unit', SLOT_UNIT)]);
  });
});

describe('literal terms', () => {
  it('a single quantity literal must match the parameter kind', () => {
    expect(run(C('eq', P('cnt'), L(qty({ k: 'count' }))))).toEqual([]);
    expect(run(C('eq', P('cnt'), L(qty({ k: 'duration' }))))).toEqual([I('cond_type', KIND)]);
    expect(run(C('eq', P('dur'), L(qty({ k: 'count' }))))).toEqual([I('cond_type', KIND)]);
  });
  it('a money literal must be in a currency the parameter lists', () => {
    expect(run(C('eq', P('amt'), L(qty({ k: 'money', ccy: 'USD' }))))).toEqual([]);
    expect(run(C('eq', P('amt'), L(qty({ k: 'money', ccy: 'EUR' }))))).toEqual([]);
    expect(run(C('eq', P('amt'), L(qty({ k: 'money', ccy: 'JPY' }))))).toEqual([I('cond_unit', LIT_UNIT)]);
    expect(run(C('eq', P('m0'), L(qty({ k: 'money', ccy: 'USD' }))))).toEqual([I('cond_unit', LIT_UNIT)]);
  });
  it('a money literal against a non-money parameter fails on kind and on currency', () => {
    expect(run(C('eq', P('cnt'), L(qty({ k: 'money', ccy: 'USD' }))))).toEqual([I('cond_type', KIND), I('cond_unit', LIT_UNIT)]);
  });
  it('a non-money literal is never checked for currency', () => {
    expect(run(C('eq', P('amt'), L(qty({ k: 'count' }))))).toEqual([I('cond_type', KIND)]);
  });
  it('a string literal fits only enum, id and text parameters', () => {
    const want: Record<string, OntologyIssue[]> = {
      money: [I('cond_type', KIND)], count: [I('cond_type', KIND)], duration: [I('cond_type', KIND)], instant: [I('cond_type', KIND)],
      bytes: [I('cond_type', KIND)], ratio: [I('cond_type', KIND)], id: [], enum: [], text: [],
    };
    const PN: Record<string, string> = { money: 'amt', count: 'cnt', duration: 'dur', instant: 'inst', bytes: 'byt', ratio: 'rat', id: 'idp', enum: 'en', text: 'txt' };
    for (const [k, p] of Object.entries(PN)) expect(run(C('eq', P(p), L(str('a'))))).toEqual(want[k]);
  });
  it('an enum literal must be a member of the parameter values', () => {
    expect(run(C('eq', P('en'), L(str('b'))))).toEqual([]);
    expect(run(C('eq', P('en'), L(str('zzz'))))).toEqual([I('cond_enum', ENUM)]);
    expect(run(C('eq', P('e0'), L(str('a'))))).toEqual([I('cond_enum', ENUM)]);
    expect(run(C('eq', P('txt'), L(str('zzz'))))).toEqual([]);
    expect(run(C('eq', P('idp'), L(str('zzz'))))).toEqual([]);
  });
  it('in/nin needs a list when the literal is a single value', () => {
    for (const op of ['in', 'nin'] as const) {
      expect(run(C(op, P('en'), L(str('a'))))).toEqual([I('cond_type', NEED_LIST)]);
      expect(run(C(op, P('cnt'), L(qty({ k: 'count' }))))).toEqual([I('cond_type', NEED_LIST)]);
    }
    expect(run(C('ne', P('en'), L(str('a'))))).toEqual([]);
  });
});

describe('literal sets', () => {
  it('pair with in and nin only', () => {
    const s = set(str('a'), str('b'));
    expect(run(C('in', P('en'), L(s)))).toEqual([]);
    expect(run(C('nin', P('en'), L(s)))).toEqual([]);
    expect(run(C('eq', P('en'), L(s)))).toEqual([I('cond_type', SET_OP)]);
    expect(run(C('ne', P('en'), L(s)))).toEqual([I('cond_type', SET_OP)]);
  });
  it('an empty set is refused', () => {
    expect(run(C('in', P('en'), L(set())))).toEqual([I('cond_type', EMPTY_LIST)]);
  });
  it('every member is checked against the parameter', () => {
    expect(run(C('in', P('cnt'), L(set(str('a')))))).toEqual([I('cond_type', KIND)]);
    expect(run(C('in', P('en'), L(set(qty({ k: 'count' })))))).toEqual([I('cond_type', KIND)]);
    expect(run(C('in', P('en'), L(set(str('a'), str('zzz')))))).toEqual([I('cond_enum', ENUM)]);
    expect(run(C('in', P('amt'), L(set(qty({ k: 'money', ccy: 'JPY' })))))).toEqual([I('cond_unit', LIT_UNIT)]);
  });
  it('a nested set is refused', () => {
    expect(run(C('in', P('en'), L(set(set(str('a'))))))).toEqual([I('cond_type', NESTED)]);
    expect(run(C('in', P('cnt'), L(set(set()))))).toEqual([I('cond_type', NESTED)]);
  });
});

describe('the Allow-witness gate', () => {
  it('a template with one satisfiable and one unsatisfiable grant is refused', () => {
    const pay = ALL_ONTOLOGIES.payments!;
    const t: Template = {
      id: 'two', title: 'two', phrases: [],
      slots: [{ name: 'charge', kind: 'id', of: 'charge', mandatory: true }, { name: 'max', kind: 'money', ccy: 'USD', mandatory: true }],
      grants: [
        { gid: 'g1', verb: 'refund', res: { k: 'exact', id: '$charge' }, cond: cmp('lte', 'amount', 'max') },
        { gid: 'g2', verb: 'refund', res: { k: 'exact', id: '$charge' }, cond: and(cmp('lte', 'amount', 'max'), cmp('gt', 'amount', 'max')) },
      ],
      prohibits: [], bounds: [],
      example: { charge: 'ch_1', max: { ccy: 'USD', minor: 100 } },
    };
    const issues = checkOntology({ ...pay, templates: [t] }).filter((i) => i.where === 'template:two');
    expect(issues).toEqual([{ code: 'empty_allow', where: 'template:two', msg: 'instantiated template has an empty Allow set' }]);
  });
});

describe('slotLits types a quantity by the slot kind', () => {
  const o = ont({ k: 'true' });
  const slot = (kind: SlotKind, ccy?: string): TemplateSlot => ({ name: 'x', kind, mandatory: true, ...(ccy !== undefined ? { ccy } : {}) });
  const q = (u: Unit, n: number): Value[] => [{ k: 'q', q: { u, n } }];
  it('money', () => {
    expect(slotLits(o, slot('money', 'USD'), { ccy: 'USD', minor: 5 })).toEqual(q({ k: 'money', ccy: 'USD' }, 5));
    expect(slotLits(o, slot('money', 'USD'), { ccy: 'EUR', minor: 5 })).toBe('ill-typed');
    expect(slotLits(o, slot('money', 'USD'), { ccy: 'USD', minor: -1 })).toBe('ill-typed');
    expect(slotLits(o, slot('count', 'USD'), { ccy: 'USD', minor: 5 })).toBe('ill-typed');
    expect(slotLits(o, slot('money', 'USD'), { n: 5 })).toBe('ill-typed');
  });
  it('count', () => {
    expect(slotLits(o, slot('count'), { n: 5 })).toEqual(q({ k: 'count' }, 5));
    expect(slotLits(o, slot('count'), { n: 0 })).toEqual(q({ k: 'count' }, 0));
    expect(slotLits(o, slot('count'), { n: -1 })).toBe('ill-typed');
    expect(slotLits(o, slot('count'), { n: 1.5 })).toBe('ill-typed');
    expect(slotLits(o, slot('duration'), { n: 5 })).toBe('ill-typed');
  });
  it('duration', () => {
    expect(slotLits(o, slot('duration'), { ms: 5 })).toEqual(q({ k: 'duration' }, 5));
    expect(slotLits(o, slot('duration'), { ms: 0 })).toEqual(q({ k: 'duration' }, 0));
    expect(slotLits(o, slot('duration'), { ms: -1 })).toBe('ill-typed');
    expect(slotLits(o, slot('duration'), { ms: 1.5 })).toBe('ill-typed');
    expect(slotLits(o, slot('duration'), { ms: -0 })).toBe('ill-typed');
    expect(slotLits(o, slot('count'), { ms: 5 })).toBe('ill-typed');
    expect(slotLits(o, slot('money', 'USD'), { ms: 5 })).toBe('ill-typed');
    expect(slotLits(o, slot('instant'), { ms: 5 })).toBe('ill-typed');
    expect(slotLits(o, slot('duration'), { epoch_ms: 5 })).toBe('ill-typed');
  });
  it('instant', () => {
    expect(slotLits(o, slot('instant'), { epoch_ms: 5 })).toEqual(q({ k: 'instant' }, 5));
    expect(slotLits(o, slot('instant'), { epoch_ms: -5 })).toEqual(q({ k: 'instant' }, -5));
    expect(slotLits(o, slot('instant'), { epoch_ms: 1.5 })).toBe('ill-typed');
    expect(slotLits(o, slot('instant'), { epoch_ms: -0 })).toBe('ill-typed');
    expect(slotLits(o, slot('count'), { epoch_ms: 5 })).toBe('ill-typed');
    expect(slotLits(o, slot('money', 'USD'), { epoch_ms: 5 })).toBe('ill-typed');
    expect(slotLits(o, slot('duration'), { epoch_ms: 5 })).toBe('ill-typed');
    expect(slotLits(o, slot('instant'), { ms: 5 })).toBe('ill-typed');
  });
});
