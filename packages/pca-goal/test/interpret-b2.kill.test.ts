import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  anthropicCompletion, interpretForm, llmInterpreter, openaiCompletion, promptKey, recordingCompletion, replayCompletion, sourceDigest,
  type Completion, type InterpretRequest, type Prompt, type Recordings, type RefundForm,
} from '../src/interpret';
import type { Reading } from '../src/disambiguate';
import type { Template, IntentOntology } from '../src/ontology';
import { ONT } from './fixtures';

const KEY = 'test-key-not-real';
const P: Prompt = { system: 'SYS', user: 'USR' };

// ---------------- llmInterpreter (second half) ----------------

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
const TEXT = 'refund cust_A1 up to $50.00';
const GOOD = { template: 't1', slots: { customer: 'cust_A1', max_amount: { ccy: 'USD', minor: 5000 } } };
const req = (text: string, extra: Partial<InterpretRequest> = {}): InterpretRequest => ({ principal: 'P1', text, ontology: IONT, ...extra });
const run = (raw: string, r: InterpretRequest): Promise<Reading> => llmInterpreter({ id: 'm1', family: 'fam', complete: async () => raw }).interpret(r);
const TEMPLATE_HOLE = { hid: 'template', q: 'No supported template matches.', domain: [], affects: [], global: true };

describe('llmInterpreter: malformed output, unknown template, grounding, unknown slots, sources', () => {
  it('malformed model output is a parse hole with the parser reason, the raw text and no grants', async () => {
    const r = await run('not json', req(TEXT));
    expect(r.goal.holes).toEqual([{ hid: 'parse', q: 'The model output was malformed.', domain: [], affects: [], global: true }]);
    expect(r.notes).toEqual(['not JSON']);
    expect((r as Reading & { raw?: string }).raw).toBe('not json');
    expect(r.deterministic).toBe(false);
    expect([r.id, r.family]).toEqual(['m1', 'fam']);
    expect(r.goal.grants).toEqual([]);
  });
  it('a null template is "no template", an unknown template is "unknown template"; both are one global template hole', async () => {
    const a = await run('{"template":null,"slots":{}}', req(TEXT));
    expect(a.goal.holes).toEqual([TEMPLATE_HOLE]);
    expect(a.notes).toEqual(['no template']);
    expect(a.deterministic).toBe(false);
    expect((a as Reading & { raw?: string }).raw).toBeUndefined();
    const b = await run('{"template":"nope","slots":{}}', req(TEXT));
    expect(b.goal.holes).toEqual([TEMPLATE_HOLE]);
    expect(b.notes).toEqual(['unknown template']);
    expect(b.deterministic).toBe(false);
  });
  it('a fully grounded filling has no notes, no holes, one grant and no sources', async () => {
    const r = await run(JSON.stringify(GOOD), req(TEXT));
    expect(r.notes).toEqual([]);
    expect(r.goal.holes).toEqual([]);
    expect(r.goal.grants.map((g) => g.gid)).toEqual(['g1']);
    expect(r.goal.grants[0]!.res).toEqual({ k: 'exact', id: 'cust_A1' });
    expect(r.goal.sources).toEqual([]);
    expect(r.deterministic).toBe(false);
  });
  it('request sources become digests in the goal', async () => {
    const r = await run(JSON.stringify(GOOD), req(TEXT, { sources: ['doc one'] }));
    expect(r.goal.sources).toEqual([sourceDigest('doc one')]);
  });
  it('a slot value the text never states is dropped with a note and becomes a hole', async () => {
    const r = await run(JSON.stringify({ template: 't1', slots: { customer: 'cust_B2', max_amount: { ccy: 'USD', minor: 5000 } } }), req(TEXT));
    expect(r.notes).toEqual(["customer: not grounded in the principal's text"]);
    expect(r.goal.holes).toEqual([{ hid: 'customer', q: 'What is the customer (id)? (missing)', domain: [], affects: [], global: false }]);
    expect(r.goal.grants).toEqual([]);
  });
  it('an unknown slot name is noted and ignored; known slot names are not', async () => {
    const r = await run(JSON.stringify({ ...GOOD, slots: { ...GOOD.slots, bogus: 'x' } }), req(TEXT));
    expect(r.notes).toEqual(['bogus: unknown slot ignored']);
    expect(r.goal.holes).toEqual([]);
    expect(r.goal.grants.map((g) => g.gid)).toEqual(['g1']);
  });
});

// ---------------- recorded completions ----------------

const msgOf = async (p: Promise<unknown>): Promise<string> => { try { await p; } catch (e) { return (e as Error).message; } return 'NO_THROW'; };

describe('replayCompletion / recordingCompletion', () => {
  it('a missing recording throws the exact message with the first 12 hex characters of the key', async () => {
    const k = promptKey('model-x', P);
    expect(await msgOf(replayCompletion('model-x', {})(P))).toBe(`no recorded output for model-x ${k.slice(0, 12)}`);
    expect(k.length).toBe(64);
  });
  it('a recording is returned verbatim, including the empty string', async () => {
    const rec: Recordings = { [promptKey('m', P)]: 'out' };
    expect(await replayCompletion('m', rec)(P)).toBe('out');
    expect(await replayCompletion('m', { [promptKey('m', P)]: '' })(P)).toBe('');
    expect(await msgOf(replayCompletion('other', rec)(P))).toContain('no recorded output for other ');
  });
  it('the recorder returns the inner output and stores it under the prompt key', async () => {
    const store: Recordings = {};
    const inner: Completion = async (p) => `<${p.system}|${p.user}>`;
    expect(await recordingCompletion('m', inner, store)(P)).toBe('<SYS|USR>');
    expect(store).toEqual({ [promptKey('m', P)]: '<SYS|USR>' });
  });
});

// ---------------- vendor completions ----------------

type Init = { method: string; headers: Record<string, string>; body: string };
type Resp = { ok: boolean; status: number; json(): Promise<unknown> };
const okResp = (j: unknown): Resp => ({ ok: true, status: 200, json: async () => j });
const fake = (r: Resp | Error) => {
  const calls: { url: string; init: Init }[] = [];
  const fetch = async (url: string, init: Init): Promise<Resp> => { calls.push({ url, init }); if (r instanceof Error) throw r; return r; };
  return { calls, fetch };
};

beforeEach(() => { vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('NETWORK_FORBIDDEN'); })); });
afterEach(() => { vi.unstubAllGlobals(); });

describe('anthropicCompletion', () => {
  it('posts the exact request and joins the text blocks only', async () => {
    const f = fake(okResp({ content: [{ type: 'thinking', text: 'T' }, { type: 'text', text: 'A' }, { type: 'text' }, { type: 'text', text: 'B' }] }));
    const out = await anthropicCompletion({ apiKey: KEY, model: 'mm', fetch: f.fetch })(P);
    expect(out).toBe('AB');
    expect(f.calls).toHaveLength(1);
    expect(f.calls[0]!.url).toBe('https://api.anthropic.com/v1/messages');
    expect(f.calls[0]!.init.method).toBe('POST');
    expect(f.calls[0]!.init.headers).toEqual({ 'content-type': 'application/json', 'x-api-key': KEY, 'anthropic-version': '2023-06-01' });
    expect(f.calls[0]!.init.body).toBe(JSON.stringify({ model: 'mm', max_tokens: 1024, temperature: 0, system: 'SYS', messages: [{ role: 'user', content: 'USR' }] }));
  });
  it('maxTokens overrides the default', async () => {
    const f = fake(okResp({ content: [] }));
    expect(await anthropicCompletion({ apiKey: KEY, model: 'mm', maxTokens: 256, fetch: f.fetch })(P)).toBe('');
    expect(f.calls[0]!.init.body).toBe(JSON.stringify({ model: 'mm', max_tokens: 256, temperature: 0, system: 'SYS', messages: [{ role: 'user', content: 'USR' }] }));
  });
  it('a body with no content is the empty string', async () => {
    expect(await anthropicCompletion({ apiKey: KEY, model: 'mm', fetch: fake(okResp({})).fetch })(P)).toBe('');
  });
  it('a non-OK status throws HTTP <status>', async () => {
    expect(await msgOf(anthropicCompletion({ apiKey: KEY, model: 'mm', fetch: fake({ ok: false, status: 429, json: async () => ({}) }).fetch })(P))).toBe('HTTP 429');
  });
  it('the key never appears in a thrown message, however often it occurs', async () => {
    const m = await msgOf(anthropicCompletion({ apiKey: KEY, model: 'mm', fetch: fake(new Error(`conn to ${KEY}/x failed ${KEY}`)).fetch })(P));
    expect(m).toBe('conn to [redacted]/x failed [redacted]');
    expect(m).not.toContain(KEY);
    const j = await msgOf(anthropicCompletion({ apiKey: KEY, model: 'mm', fetch: fake({ ok: true, status: 200, json: async () => { throw new Error(`bad json ${KEY}`); } }).fetch })(P));
    expect(j).toBe('bad json [redacted]');
  });
  it('an empty key leaves the message untouched', async () => {
    expect(await msgOf(anthropicCompletion({ apiKey: '', model: 'mm', fetch: fake(new Error('plain failure')).fetch })(P))).toBe('plain failure');
  });
  it('without an injected fetch it uses the global fetch with the same arguments', async () => {
    const g = vi.fn(async (_u: string, _i: Init): Promise<Resp> => okResp({ content: [{ type: 'text', text: 'viaglobal' }] }));
    vi.stubGlobal('fetch', g);
    expect(await anthropicCompletion({ apiKey: KEY, model: 'mm' })(P)).toBe('viaglobal');
    expect(g).toHaveBeenCalledTimes(1);
    expect(g.mock.calls[0]![0]).toBe('https://api.anthropic.com/v1/messages');
    expect(g.mock.calls[0]![1].method).toBe('POST');
  });
  it('an injected fetch is used instead of the global one', async () => {
    const f = fake(okResp({ content: [{ type: 'text', text: 'inj' }] }));
    expect(await anthropicCompletion({ apiKey: KEY, model: 'mm', fetch: f.fetch })(P)).toBe('inj');
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });
});

describe('openaiCompletion', () => {
  const body = JSON.stringify({ model: 'mm', temperature: 0, messages: [{ role: 'system', content: 'SYS' }, { role: 'user', content: 'USR' }] });
  it('posts the exact request to the default base URL and returns the first choice', async () => {
    const f = fake(okResp({ choices: [{ message: { content: 'hello' } }] }));
    expect(await openaiCompletion({ apiKey: KEY, model: 'mm', fetch: f.fetch })(P)).toBe('hello');
    expect(f.calls).toHaveLength(1);
    expect(f.calls[0]!.url).toBe('https://api.openai.com/v1/chat/completions');
    expect(f.calls[0]!.init.method).toBe('POST');
    expect(f.calls[0]!.init.headers).toEqual({ 'content-type': 'application/json', authorization: `Bearer ${KEY}` });
    expect(f.calls[0]!.init.body).toBe(body);
  });
  it('a custom base URL replaces the host', async () => {
    const f = fake(okResp({ choices: [{ message: { content: 'x' } }] }));
    await openaiCompletion({ apiKey: KEY, model: 'mm', baseUrl: 'https://llm.example.test', fetch: f.fetch })(P);
    expect(f.calls[0]!.url).toBe('https://llm.example.test/v1/chat/completions');
  });
  it('missing choices, an empty choices list, a choice without a message or content all give the empty string', async () => {
    for (const j of [{}, { choices: [] }, { choices: [{}] }, { choices: [{ message: {} }] }]) {
      expect(await openaiCompletion({ apiKey: KEY, model: 'mm', fetch: fake(okResp(j)).fetch })(P)).toBe('');
    }
  });
  it('a non-OK status throws HTTP <status>', async () => {
    expect(await msgOf(openaiCompletion({ apiKey: KEY, model: 'mm', fetch: fake({ ok: false, status: 503, json: async () => ({}) }).fetch })(P))).toBe('HTTP 503');
  });
  it('the key never appears in a thrown message, however often it occurs', async () => {
    const m = await msgOf(openaiCompletion({ apiKey: KEY, model: 'mm', fetch: fake(new Error(`${KEY} and ${KEY}`)).fetch })(P));
    expect(m).toBe('[redacted] and [redacted]');
    expect(m).not.toContain(KEY);
    expect(await msgOf(openaiCompletion({ apiKey: '', model: 'mm', fetch: fake(new Error('plain failure')).fetch })(P))).toBe('plain failure');
  });
  it('without an injected fetch it uses the global fetch; an injected one wins', async () => {
    const g = vi.fn(async (_u: string, _i: Init): Promise<Resp> => okResp({ choices: [{ message: { content: 'viaglobal' } }] }));
    vi.stubGlobal('fetch', g);
    expect(await openaiCompletion({ apiKey: KEY, model: 'mm' })(P)).toBe('viaglobal');
    expect(g.mock.calls[0]![0]).toBe('https://api.openai.com/v1/chat/completions');
    const f = fake(okResp({ choices: [{ message: { content: 'inj' } }] }));
    expect(await openaiCompletion({ apiKey: KEY, model: 'mm', fetch: f.fetch })(P)).toBe('inj');
    expect(g).toHaveBeenCalledTimes(1);
  });
});

// ---------------- interpretForm ----------------

describe('interpretForm currency type check', () => {
  const form = (ccy: unknown): RefundForm => ({ template: 'refund_duplicate', slots: { customer: 'cust:C1', max_amount_minor: 5000, ccy, max_refunds: 3 }, nl: 'x' }) as never;
  it('a non-string currency whose string form looks like a code is refused, not coerced', () => {
    expect(interpretForm(form(['USD']), ONT)).toEqual({ ok: false, error: 'SLOT_amount' });
    expect(interpretForm(form({ toString: () => 'USD' }), ONT)).toEqual({ ok: false, error: 'SLOT_amount' });
    expect(interpretForm(form('USD'), ONT).ok).toBe(true);
  });
});
