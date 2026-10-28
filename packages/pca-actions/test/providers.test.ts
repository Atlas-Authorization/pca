// Model assist over a provider: pinned model, key from the environment only, recorded fake transport. The output stays unreviewed.
import { describe, expect, it } from 'vitest';
import { CORE_REGISTRY, IMPORTERS, modelConfigFromEnv, providerAdapter, suggestDefs, traitsOf, type FetchLike } from '../src';

const KEY = 'sk-test-SECRET-123';
const ENV = { ANTHROPIC_API_KEY: KEY, OPENAI_API_KEY: KEY };

/** A recorded transport: replays a canned response and records what it was sent. */
function recorded(answer: unknown, status = 200): { f: FetchLike; calls: { url: string; headers: Record<string, string>; body: any }[] } {
  const calls: { url: string; headers: Record<string, string>; body: any }[] = [];
  return { calls, f: async (url, init) => { calls.push({ url, headers: init.headers, body: JSON.parse(init.body) }); return { ok: status === 200, status, json: async () => answer }; } };
}
const anthropicAnswer = (t: string) => ({ content: [{ type: 'text', text: t }] });
const doc = { tools: [{ name: 'run_report', description: 'Run it', inputSchema: { type: 'object', properties: { q: { type: 'string' } } } }] };

describe('modelConfigFromEnv', () => {
  it('needs a pinned model and the provider key from the environment', () => {
    expect(() => modelConfigFromEnv(ENV)).toThrow(/--model/);
    expect(() => modelConfigFromEnv({}, { model: 'm-1' })).toThrow(/ANTHROPIC_API_KEY is not set/);
    expect(() => modelConfigFromEnv(ENV, { model: 'm-1', provider: 'acme' })).toThrow(/unknown provider/);
    expect(() => modelConfigFromEnv(ENV, { model: 'bad model!' })).toThrow(/--model/);
    expect(modelConfigFromEnv({ ...ENV, ATLAS_PCA_SUGGEST_MODEL: 'm-2' }, {})).toMatchObject({ provider: 'anthropic', model: 'm-2' });
    expect(modelConfigFromEnv({ OPENAI_API_KEY: KEY }, { model: 'g', provider: 'openai' }).provider).toBe('openai');
  });
  it('the key is not enumerable: it never appears in JSON, logs or spreads', () => {
    const c = modelConfigFromEnv(ENV, { model: 'm-1' });
    expect(JSON.stringify(c)).not.toContain(KEY);
    expect(JSON.stringify({ ...c })).not.toContain(KEY);
    expect(String(Object.keys(c))).not.toContain('apiKey');
  });
});

describe('providerAdapter', () => {
  it('anthropic: sends the names-and-types prompt at temperature 0 with the key in a header only', async () => {
    const t = recorded(anthropicAnswer('["pca.code_execution"]'));
    const a = providerAdapter(modelConfigFromEnv(ENV, { model: 'm-1' }), t.f);
    expect(a.id).toBe('anthropic:m-1');
    const out = await a.complete({ system: 'S', user: 'U', temperature: 0 });
    expect(out).toBe('["pca.code_execution"]');
    expect(t.calls[0]!.url).toBe('https://api.anthropic.com/v1/messages');
    expect(t.calls[0]!.headers['x-api-key']).toBe(KEY);
    expect(t.calls[0]!.body).toMatchObject({ model: 'm-1', temperature: 0, system: 'S', messages: [{ role: 'user', content: 'U' }] });
    expect(JSON.stringify(t.calls[0]!.body)).not.toContain(KEY);
  });
  it('openai-compatible: bearer header and chat shape', async () => {
    const t = recorded({ choices: [{ message: { content: '["pca.bulk"]' } }] });
    const a = providerAdapter(modelConfigFromEnv(ENV, { model: 'g-1', provider: 'openai' }), t.f);
    expect(await a.complete({ system: 'S', user: 'U', temperature: 0 })).toBe('["pca.bulk"]');
    expect(t.calls[0]!.headers.authorization).toBe(`Bearer ${KEY}`);
    expect(t.calls[0]!.body.messages.map((m: { role: string }) => m.role)).toEqual(['system', 'user']);
  });
  it('errors carry the status only, never the key, request or body', async () => {
    const a = providerAdapter(modelConfigFromEnv(ENV, { model: 'm-1' }), recorded({ error: KEY }, 401).f);
    await expect(a.complete({ system: 'S', user: 'U', temperature: 0 })).rejects.toThrow('anthropic returned HTTP 401');
    const boom = providerAdapter(modelConfigFromEnv(ENV, { model: 'm-1' }), async () => { throw new Error(`socket ${KEY}`); });
    let msg = '';
    try { await boom.complete({ system: 'S', user: 'U', temperature: 0 }); } catch (e) { msg = (e as Error).message; }
    expect(msg).toBe('anthropic request failed');
    await expect(providerAdapter(modelConfigFromEnv(ENV, { model: 'm-1' }), recorded({ content: [] }).f).complete({ system: 'S', user: 'U', temperature: 0 })).rejects.toThrow(/no text/);
  });
});

describe('model-assisted import stays unreviewed', () => {
  it('adds only vocabulary traits, records the model, never confirms, and the request holds no values', async () => {
    const t = recorded(anthropicAnswer('Sure: ["pca.credential_access", "pca.fly", "pca.unreviewed"]'));
    const r = IMPORTERS['mcp']!(doc, { ns: 'rep' });
    const s = await suggestDefs(r.defs, { mode: 'model', models: [providerAdapter(modelConfigFromEnv(ENV, { model: 'm-1' }), t.f)] });
    const d = s.defs[0]!;
    expect(d.traits).toContain('pca.credential_access');
    expect(d.traits).not.toContain('pca.fly');
    expect(d.review.state).toBe('suggested');
    expect(d.review.attestation).toBeUndefined();
    expect(traitsOf(d, CORE_REGISTRY)).toContain('pca.unreviewed');
    const sb = d.review.suggested_by as { models: { id: string; temperature: number; traits: string[] }[] };
    expect(sb.models).toHaveLength(1);
    expect(sb.models[0]).toMatchObject({ id: 'anthropic:m-1', temperature: 0, traits: ['pca.credential_access'] });
    const sent = JSON.stringify(t.calls[0]!.body);
    expect(sent).toContain('q: string');
    expect(sent).not.toContain(KEY);
    expect(JSON.stringify(d)).not.toContain(KEY);
    expect(CORE_REGISTRY.traits.has('pca.credential_access')).toBe(true);
  });
  it('a provider failure leaves the rules-only suggestion and is reported', async () => {
    const r = IMPORTERS['mcp']!(doc, { ns: 'rep' });
    const s = await suggestDefs(r.defs, { mode: 'model', models: [providerAdapter(modelConfigFromEnv(ENV, { model: 'm-1' }), recorded({}, 500).f)] });
    expect(s.errors).toEqual([{ verb: r.defs[0]!.verb, model: 'anthropic:m-1', error: 'anthropic returned HTTP 500' }]);
    expect(s.defs[0]!.review.state).toBe('suggested');
  });
});
