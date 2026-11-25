// Kills the survivors of src/interpret.ts from fillTemplate onward: the count-slot bookkeeping of fillTemplate, the form
// interpreter and the head of the rule interpreter (template choice, ambiguity, unattributed numbers). Every expected value is
// traced by hand; ontologies are built inside the test bodies' helpers so every mutant is live when they run.
import { describe, expect, it } from 'vitest';
import { fillTemplate, formInterpreter, ruleInterpreter, sourceDigest, type InterpretRequest } from '../src/interpret';
import { instantiateTemplate, ontologyDigest, type IntentOntology, type Template, type TemplateSlot } from '../src/ontology';
import { nlDigest } from '../src/digests';
import { canonicalizeGoal } from '../src/normalize';
import type { Goal, Hole } from '../src/ir';

const LIMIT: TemplateSlot = { name: 'limit', kind: 'money', ccy: 'USD', mandatory: true };
const tpl = (id: string, title: string, phrases: string[], slots: TemplateSlot[] = [LIMIT]): Template => ({
  id, title, phrases, slots, prohibits: [], bounds: [], example: {},
  grants: [{ gid: `g_${id}`, verb: 'pay.refund', res: { k: 'any', reason: 'r' }, cond: { k: 'cmp', op: 'lte', l: { k: 'param', path: 'amount' }, r: { k: 'slot', slot: 'limit' } } }],
});
const ont = (templates: Template[]): IntentOntology => ({
  id: 'o', version: 1, domain: 'payments', types: [{ id: 'charge', id_prefix: 'ch_' }], units: { USD: { kind: 'money', exponent: 2 } }, relations: [],
  verbs: [{ id: 'pay.refund', effect: 'reversible', resource_type: 'charge', params: { amount: { kind: 'money', ccys: ['USD'] } } }],
  aliases: {}, templates,
});
const reqOf = (o: IntentOntology, text: string, over: Partial<InterpretRequest> = {}): InterpretRequest => ({ principal: 'P1', text, ontology: o, ...over });
const count = (name: string, cue?: string[]): TemplateSlot => ({ name, kind: 'count', mandatory: false, ...(cue ? { cue } : {}) });
const emptyGoal = (r: InterpretRequest, holes: Hole[]): Goal => ({
  v: 1, principal: r.principal, ontDigest: ontologyDigest(r.ontology), nlDigest: nlDigest(r.text), sources: [],
  grants: [], prohibits: [], bounds: [], validity: { notBefore: 0, notAfter: Number.MAX_SAFE_INTEGER, maxIdle: 0 }, deleg: { maxDepth: 0, narrowOnly: true, mayTouch: [] },
  escalateOn: [], wildcardAck: [], holes,
});
const glob = (hid: string, q: string): Hole => ({ hid, q, domain: [], affects: [], global: true });
const LIMIT_HOLE: Hole = { hid: 'limit', q: 'What is the limit (money USD)? (missing)', domain: [], affects: [], global: false };

describe('fillTemplate', () => {
  const fill = (slots: TemplateSlot[], text: string) => fillTemplate({ ...tpl('t', 'T', ['t'], slots), grants: [] }, ont([]), text);
  it('a full fill names every count by its slot, has no notes and no unattributed number', () => {
    expect(fill([count('max_queries'), count('max_pages')], '3 pages, and also 5 queries')).toStrictEqual({ values: { max_queries: { n: 5 }, max_pages: { n: 3 } }, notes: [], unattributed: [] });
  });
  it('a partial fill leaves the number no slot consumed unattributed', () => {
    expect(fill([count('max_pages')], '3 pages and 8 queries')).toStrictEqual({ values: { max_pages: { n: 3 } }, notes: [], unattributed: [8] });
  });
  it('an empty fill has no value and one note per slot', () => {
    expect(fill([count('max_pages')], 'hello')).toStrictEqual({ values: {}, notes: ['max_pages: not found'], unattributed: [] });
  });
  it('a cue picks a count even when a non-count slot is named by its noun', () => {
    expect(fill([count('tries', ['up to']), { name: 'amount', kind: 'enum', values: ['x'], mandatory: false }], 'up to 3 amounts')).toStrictEqual({ values: { tries: { n: 3 } }, notes: ['amount: not found'], unattributed: [] });
  });
  it('a cued count that another count slot names is left to that slot', () => {
    expect(fill([count('max_pages'), count('max_queries', ['up to'])], 'up to 3 pages')).toStrictEqual({ values: { max_pages: { n: 3 } }, notes: ['max_queries: not found'], unattributed: [] });
  });
});

describe('formInterpreter', () => {
  const O = ont([tpl('R', 'Refund', ['refund'])]);
  const slots = { limit: { ccy: 'USD', minor: 5000 } };
  it('defaults its id to form and is a deterministic rule-family reader', () => {
    const i = formInterpreter();
    expect([i.id, i.family, i.deterministic]).toEqual(['form', 'rule', true]);
    expect(formInterpreter('f2').id).toBe('f2');
  });
  it('without a form it answers with the form hole and the no-form note', async () => {
    const r = reqOf(O, 'refund 50 dollars');
    expect(await formInterpreter().interpret(r)).toEqual({ id: 'form', family: 'rule', deterministic: true, notes: ['no form'], goal: emptyGoal(r, [glob('form', 'No form was provided.')]) });
  });
  it('a complete form is the instantiated template with the request text, no notes and no sources', async () => {
    const r = reqOf(O, 'refund 50 dollars', { form: { template: 'R', slots } });
    const out = await formInterpreter('f2').interpret(r);
    expect(out).toEqual({ id: 'f2', family: 'rule', deterministic: true, notes: [], goal: instantiateTemplate(O, 'R', slots, { principal: 'P1', nl: r.text, sources: [] }) });
    expect(out.goal.holes).toEqual([]);
    expect(out.goal.sources).toEqual([]);
    expect(out.goal.grants.map((g) => g.gid)).toEqual(['g_R']);
  });
  it('the sources are digested into the goal', async () => {
    const r = reqOf(O, 'refund 50 dollars', { sources: ['doc'], form: { template: 'R', slots } });
    expect((await formInterpreter().interpret(r)).goal.sources).toEqual([sourceDigest('doc')]);
  });
  it('a form that misses a slot yields that slot hole and drops the grant', async () => {
    const out = await formInterpreter().interpret(reqOf(O, 'refund', { form: { template: 'R', slots: {} } }));
    expect(out.notes).toEqual([]);
    expect(out.goal.holes).toEqual([LIMIT_HOLE]);
    expect(out.goal.grants).toEqual([]);
  });
});

describe('ruleInterpreter', () => {
  const run = (templates: Template[], text: string, over: Partial<InterpretRequest> = {}) => ruleInterpreter().interpret(reqOf(ont(templates), text, over));
  const P = tpl('P', 'Partial', ['partial refund', 'refund']);
  const C = tpl('C', 'Charge', ['charge back', 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz']);
  it('defaults its id to rule and is a deterministic rule-family reader', () => {
    const i = ruleInterpreter();
    expect([i.id, i.family, i.deterministic]).toEqual(['rule', 'rule', true]);
    expect(ruleInterpreter('r2').id).toBe('r2');
  });
  it('no phrase in the text means the template hole, even when templates are declared', async () => {
    for (const templates of [[P], [P, C]]) {
      const r = reqOf(ont(templates), 'hello there');
      expect(await ruleInterpreter('r2').interpret(r)).toEqual({
        id: 'r2', family: 'rule', deterministic: true, notes: ['no template'],
        goal: emptyGoal(r, [glob('template', 'Which kind of task is this? No supported template matches.')]),
      });
    }
  });
  it('the template with the longest matched phrase wins whatever the declaration order, and the shorter one is no tie', async () => {
    const text = 'partial refund and charge back please, 50 dollars';
    for (const templates of [[P, C], [C, P]]) {
      const out = await run(templates, text);
      expect(out.goal.grants.map((g) => g.gid)).toEqual(['g_P']);
      expect(out.goal.holes).toEqual([]);
      expect(out.notes).toEqual([]);
    }
  });
  it('equal longest phrases are ambiguous, naming both titles in declaration order', async () => {
    for (const [templates, text, q] of [
      [[tpl('A', 'Full', ['partial refund', 'refund']), tpl('B', 'Partial', ['partial refund'])], 'partial refund 50 dollars', 'Is this "Full" or "Partial"?'],
      [[tpl('A', 'Plain', ['refund']), tpl('B', 'Wide', ['refund', 'zzzzzzzzzzzzzz'])], 'refund 50 dollars', 'Is this "Plain" or "Wide"?'],
    ] as const) {
      const r = reqOf(ont([...templates]), text);
      expect(await ruleInterpreter().interpret(r)).toEqual({ id: 'rule', family: 'rule', deterministic: true, notes: ['ambiguous template'], goal: emptyGoal(r, [glob('template', q)]) });
    }
  });
  it('a clean request is the instantiated template with no hole, no note and no source', async () => {
    const O = ont([tpl('R', 'Refund', ['refund'])]);
    const r = reqOf(O, 'refund 50 dollars');
    const out = await ruleInterpreter().interpret(r);
    expect(out).toEqual({ id: 'rule', family: 'rule', deterministic: true, notes: [], goal: instantiateTemplate(O, 'R', { limit: { ccy: 'USD', minor: 5000 } }, { principal: 'P1', nl: r.text, sources: [] }) });
    expect(out.goal.sources).toEqual([]);
  });
  it('numbers no slot uses become one unattributed-number hole listing them in order', async () => {
    const O = ont([tpl('R', 'Refund', ['refund'])]);
    const unattr = glob('unattributed_number', 'The request mentions 3, 7 but no limit uses it. Which limit is it?');
    const r = reqOf(O, 'refund 50 dollars, 3 times, 7 pages');
    const out = await ruleInterpreter().interpret(r);
    const base = instantiateTemplate(O, 'R', { limit: { ccy: 'USD', minor: 5000 } }, { principal: 'P1', nl: r.text, sources: [] });
    expect(out).toEqual({ id: 'rule', family: 'rule', deterministic: true, notes: [], goal: canonicalizeGoal({ ...base, holes: [unattr] }) });
    expect(out.goal.sources).toEqual([]);
    const miss = await ruleInterpreter().interpret(reqOf(O, 'refund 3 times, 7 pages'));
    expect(miss.notes).toEqual(['limit: not found']);
    expect(miss.goal.holes).toEqual([LIMIT_HOLE, unattr]);
    expect(miss.goal.sources).toEqual([]);
  });
});
