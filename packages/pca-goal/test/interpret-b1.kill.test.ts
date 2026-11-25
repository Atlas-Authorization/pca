import { describe, expect, it } from 'vitest';
import { buildPrompt, grounded, llmInterpreter, parseTemplateJSON, type Candidates, type InterpretRequest } from '../src/interpret';
import type { IntentOntology, SlotValue, TemplateSlot } from '../src/ontology';

const ONT: IntentOntology = { id: 'o', version: 1, domain: 'payments', types: [], units: {}, relations: [], verbs: [], aliases: {}, templates: [] };
const reqOf = (over: Partial<InterpretRequest> = {}): InterpretRequest => ({ principal: 'P1', text: 'hello', ontology: ONT, ...over });
const cand = (over: Partial<Candidates> = {}): Candidates => ({ ids: [], amounts: [], ambiguousAmounts: 0, counts: [], words: '', domains: [], ...over });
const slot = (kind: TemplateSlot['kind']): TemplateSlot => ({ name: 's', kind, ccy: 'USD', mandatory: true });
const g = (kind: TemplateSlot['kind'], v: SlotValue, c: Candidates): boolean => grounded(slot(kind), v, c, ONT);
const cnt = (n: number): { n: number; before: string; after: string } => ({ n, before: '', after: '' });

describe('buildPrompt user text', () => {
  it('a request without sources and includeSources set does not throw and carries only the request', () => {
    expect(buildPrompt(reqOf(), true).user).toBe('<principal_request>\nhello\n</principal_request>');
  });
  it('sources are joined with a newline, indexed, and only when requested', () => {
    const r = reqOf({ sources: ['doc a', 'doc b'] });
    expect(buildPrompt(r, true).user).toBe('<principal_request>\nhello\n</principal_request>\n<untrusted_data index="0">\ndoc a\n</untrusted_data>\n<untrusted_data index="1">\ndoc b\n</untrusted_data>');
    expect(buildPrompt(r).user).toBe('<principal_request>\nhello\n</principal_request>');
    expect(buildPrompt(reqOf({ sources: [] }), true).user).toBe('<principal_request>\nhello\n</principal_request>');
  });
});

describe('parseTemplateJSON', () => {
  it('trims non-JSON whitespace before parsing', () => {
    expect(parseTemplateJSON(' {"template":null,"slots":{}}')).toEqual({ template: null, slots: {} });
  });
  it('not JSON', () => { expect(parseTemplateJSON('nope')).toBe('not JSON'); });
  it('not an object', () => {
    for (const raw of ['5', 'null', '[]', '"s"', 'true']) expect(parseTemplateJSON(raw)).toBe('not an object');
  });
  it('unexpected keys', () => {
    expect(parseTemplateJSON('{"template":null,"slots":{},"x":1}')).toBe('unexpected keys');
    expect(parseTemplateJSON('{"template":"a","slots":{},"extra":1}')).toBe('unexpected keys');
    expect(parseTemplateJSON('{"x":1}')).toBe('unexpected keys');
  });
  it('template must be a string or null', () => {
    expect(parseTemplateJSON('{"template":5,"slots":{}}')).toBe('template must be a string or null');
    expect(parseTemplateJSON('{"slots":{}}')).toBe('template must be a string or null');
  });
  it('slots must be an object', () => {
    for (const raw of ['{"template":null,"slots":5}', '{"template":null,"slots":null}', '{"template":null,"slots":[]}', '{"template":null}', '{"template":"t","slots":"x"}']) {
      expect(parseTemplateJSON(raw)).toBe('slots must be an object');
    }
  });
  it('a well-formed object is returned as is', () => {
    expect(parseTemplateJSON('{"template":"t","slots":{"a":{"n":1}}}')).toEqual({ template: 't', slots: { a: { n: 1 } } });
    expect(parseTemplateJSON(' {"template":null,"slots":{}}\n')).toEqual({ template: null, slots: {} });
  });
});

describe('grounded: money', () => {
  const usd = (minor: number): { ccy: string; minor: number } => ({ ccy: 'USD', minor });
  it('grounded when the one stated amount matches', () => {
    expect(g('money', usd(5000), cand({ amounts: [{ ccy: 'USD', minor: 5000, before: '' }] }))).toBe(true);
    expect(g('money', usd(5000), cand({ amounts: [{ ccy: 'USD', minor: 100, before: '' }, { ccy: 'USD', minor: 5000, before: '' }] }))).toBe(true);
  });
  it('an ambiguous amount anywhere in the text refuses', () => {
    expect(g('money', usd(5000), cand({ ambiguousAmounts: 1, amounts: [{ ccy: 'USD', minor: 5000, before: '' }] }))).toBe(false);
  });
  it('an amount in another currency refuses even when the value is stated', () => {
    expect(g('money', usd(5000), cand({ amounts: [{ ccy: 'USD', minor: 5000, before: '' }, { ccy: 'EUR', minor: 5000, before: '' }] }))).toBe(false);
    expect(g('money', { ccy: 'EUR', minor: 5000 }, cand({ amounts: [{ ccy: 'USD', minor: 5000, before: '' }] }))).toBe(false);
  });
  it('a wrong minor amount or no amount refuses', () => {
    expect(g('money', usd(6000), cand({ amounts: [{ ccy: 'USD', minor: 5000, before: '' }] }))).toBe(false);
    expect(g('money', usd(5000), cand())).toBe(false);
  });
  it('a non-money value refuses without throwing', () => {
    expect(g('money', 'USD5000', cand())).toBe(false);
    expect(g('money', ['USD'], cand())).toBe(false);
    expect(g('money', { n: 5000 }, cand())).toBe(false);
  });
});

describe('grounded: count', () => {
  const c = cand({ counts: [cnt(3), cnt(5)] });
  it('stated count', () => { expect(g('count', { n: 3 }, c)).toBe(true); expect(g('count', { n: 5 }, c)).toBe(true); });
  it('unstated count', () => { expect(g('count', { n: 4 }, c)).toBe(false); expect(g('count', { n: 3 }, cand())).toBe(false); });
  it('non-count values refuse without throwing', () => {
    expect(g('count', '3', c)).toBe(false);
    expect(g('count', ['3'], c)).toBe(false);
    expect(g('count', { ms: 3 }, c)).toBe(false);
    expect(g('count', Object.assign(['x'], { n: 3 }), c)).toBe(false);
  });
});

describe('grounded: ids', () => {
  const c = cand({ ids: ['ch_1', 'ch_2'], words: 'x' });
  it('id', () => {
    expect(g('id', 'ch_1', c)).toBe(true);
    expect(g('id', 'ch_9', c)).toBe(false);
    expect(g('id', ['ch_1'], c)).toBe(false);
  });
  it('id_list', () => {
    expect(g('id_list', ['ch_1', 'ch_2'], c)).toBe(true);
    expect(g('id_list', ['ch_1', 'ch_9'], c)).toBe(false);
    expect(g('id_list', 'ch_1', c)).toBe(false);
  });
  it('the id check applies only to id slots', () => {
    expect(g('enum', 'refund', cand({ words: 'please refund', ids: [] }))).toBe(true);
    expect(g('id_list', ['ch_1'], cand({ ids: ['ch_1'] }))).toBe(true);
    expect(g('enum_list', ['refund'], cand({ words: 'refund', ids: [] }))).toBe(true);
  });
});

describe('grounded: enums and text lists', () => {
  it('enum matches whole words, underscores read as spaces', () => {
    expect(g('enum', 'refund', cand({ words: 'please refund it' }))).toBe(true);
    expect(g('enum', 'partial_refund', cand({ words: 'a partial refund' }))).toBe(true);
    expect(g('enum', 'refund', cand({ words: 'please refunds' }))).toBe(false);
    expect(g('enum', 'refund', cand({ words: 'x' }))).toBe(false);
    expect(g('enum', ['refund'], cand({ words: 'refund' }))).toBe(false);
  });
  it('enum_list needs every value stated', () => {
    expect(g('enum_list', ['refund', 'partial_refund'], cand({ words: 'refund and partial refund' }))).toBe(true);
    expect(g('enum_list', ['refund', 'void'], cand({ words: 'refund' }))).toBe(false);
    expect(g('enum_list', 'refund', cand({ words: 'refund' }))).toBe(false);
  });
  it('text_list needs every domain stated', () => {
    const c = cand({ domains: ['a.com', 'b.com'], words: 'x' });
    expect(g('text_list', ['a.com', 'b.com'], c)).toBe(true);
    expect(g('text_list', ['a.com', 'c.com'], c)).toBe(false);
    expect(g('text_list', 'a.com', c)).toBe(false);
  });
  it('kinds that cannot be grounded from free text never are', () => {
    expect(g('duration', { ms: 1000 }, cand({ words: '1000', counts: [cnt(1000)] }))).toBe(false);
    expect(g('instant', { epoch_ms: 1 }, cand())).toBe(false);
    expect(g('duration', ['a.com'], cand({ domains: ['a.com'] }))).toBe(false);
  });
});

describe('llmInterpreter failure and refusal paths', () => {
  it('a throwing model yields the model hole, the message, and a non-deterministic reading', async () => {
    const r = await llmInterpreter({ id: 'm', family: 'fam', complete: async () => { throw new Error('boom'); } }).interpret(reqOf());
    expect(r.deterministic).toBe(false);
    expect(r.id).toBe('m');
    expect(r.family).toBe('fam');
    expect(r.notes).toEqual(['model error: boom']);
    expect(r.goal.holes).toEqual([{ hid: 'model', q: 'The interpreter failed.', domain: [], affects: [], global: true }]);
  });
  it('a model that answers no-template yields the template hole and a non-deterministic reading', async () => {
    const r = await llmInterpreter({ id: 'm', family: 'fam', complete: async () => '{"template":null,"slots":{}}' }).interpret(reqOf());
    expect(r.deterministic).toBe(false);
    expect(r.notes).toEqual(['no template']);
    expect(r.goal.holes.map((h) => h.hid)).toEqual(['template']);
  });
});
