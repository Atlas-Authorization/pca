// Exact outcomes of the provider adapters: every configuration refusal, the wire request (method, URL, headers, body), the
// response parsing for both providers, and the request timeout (it aborts a hung call and is cleared after a finished one).
import { describe, expect, it } from 'vitest';
import { modelConfigFromEnv, providerAdapter, type FetchLike } from '../src';

const KEY = 'sk-test-123';
const ENV = { ANTHROPIC_API_KEY: KEY, OPENAI_API_KEY: KEY };
const REQ = { system: 'S', user: 'U', temperature: 0 } as const;
const err = (f: () => unknown): string => {
  try { f(); } catch (e) { return `${(e as { code?: string }).code}: ${(e as Error).message}`; }
  return 'none';
};
type Seen = { url: string; init: Parameters<FetchLike>[1] };
const answering = (json: unknown, seen: Seen[] = []): FetchLike => async (url, init) => { seen.push({ url, init }); return { ok: true, status: 200, json: async () => json }; };
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

describe('modelConfigFromEnv: exact refusals', () => {
  it('unknown provider, missing or malformed model, missing key', () => {
    expect(err(() => modelConfigFromEnv(ENV, { model: 'm', provider: 'acme' }))).toBe('bad_model_config: unknown provider (one of anthropic, openai)');
    const bad = 'bad_model_config: --model <pinned model id> (or ATLAS_PCA_SUGGEST_MODEL) is required';
    expect(err(() => modelConfigFromEnv(ENV))).toBe(bad);
    expect(err(() => modelConfigFromEnv(ENV, { model: '' }))).toBe(bad);
    expect(err(() => modelConfigFromEnv(ENV, { model: ' m-1' }))).toBe(bad);
    expect(err(() => modelConfigFromEnv(ENV, { model: 'a'.repeat(129) }))).toBe(bad);
    expect(err(() => modelConfigFromEnv(ENV, { model: 'a'.repeat(128) }))).toBe('none');
    expect(err(() => modelConfigFromEnv({}, { model: 'm' }))).toBe('bad_model_config: ANTHROPIC_API_KEY is not set');
    expect(err(() => modelConfigFromEnv({}, { model: 'm', provider: 'openai' }))).toBe('bad_model_config: OPENAI_API_KEY is not set');
    expect(err(() => modelConfigFromEnv({ ATLAS_PCA_SUGGEST_PROVIDER: 'openai', ATLAS_PCA_SUGGEST_MODEL: 'g' }, {}))).toBe('bad_model_config: OPENAI_API_KEY is not set');
  });
});

describe('providerAdapter: the wire request', () => {
  it('anthropic', async () => {
    const seen: Seen[] = [];
    const a = providerAdapter(modelConfigFromEnv(ENV, { model: 'm-1' }), answering({ content: [{ type: 'tool_use', text: 'no' }, { type: 'text', text: 'yes' }] }, seen));
    expect(await a.complete(REQ)).toBe('yes');
    expect(seen).toHaveLength(1);
    expect(seen[0]!.url).toBe('https://api.anthropic.com/v1/messages');
    expect(seen[0]!.init.method).toBe('POST');
    expect(seen[0]!.init.headers).toEqual({ 'content-type': 'application/json', 'x-api-key': KEY, 'anthropic-version': '2023-06-01' });
    expect(JSON.parse(seen[0]!.init.body)).toEqual({ model: 'm-1', max_tokens: 512, temperature: 0, system: 'S', messages: [{ role: 'user', content: 'U' }] });
  });
  it('openai', async () => {
    const seen: Seen[] = [];
    const a = providerAdapter(modelConfigFromEnv(ENV, { model: 'g-1', provider: 'openai' }), answering({ choices: [{ message: { content: 'hi' } }] }, seen));
    expect(await a.complete(REQ)).toBe('hi');
    expect(seen[0]!.url).toBe('https://api.openai.com/v1/chat/completions');
    expect(seen[0]!.init.method).toBe('POST');
    expect(seen[0]!.init.headers).toEqual({ 'content-type': 'application/json', authorization: `Bearer ${KEY}` });
    expect(JSON.parse(seen[0]!.init.body)).toEqual({ model: 'g-1', max_tokens: 512, temperature: 0, messages: [{ role: 'system', content: 'S' }, { role: 'user', content: 'U' }] });
  });
});

describe('providerAdapter: a response without text', () => {
  const none = async (provider: 'anthropic' | 'openai', json: unknown): Promise<string> => {
    const a = providerAdapter(modelConfigFromEnv(ENV, { model: 'm', provider }), answering(json));
    try { await a.complete(REQ); } catch (e) { return (e as Error).message; }
    return 'none';
  };
  it('is "returned no text", never a TypeError', async () => {
    expect(await none('anthropic', {})).toBe('anthropic returned no text');
    expect(await none('anthropic', { content: [] })).toBe('anthropic returned no text');
    expect(await none('anthropic', { content: [{ type: 'tool_use', text: 'x' }] })).toBe('anthropic returned no text');
    expect(await none('openai', {})).toBe('openai returned no text');
    expect(await none('openai', { choices: [] })).toBe('openai returned no text');
    expect(await none('openai', { choices: [{}] })).toBe('openai returned no text');
    expect(await none('openai', { choices: [{ message: { content: 5 } }] })).toBe('openai returned no text');
  });
});

describe('providerAdapter: the timeout', () => {
  it('aborts a call that never answers', async () => {
    const hung: FetchLike = (_u, init) => new Promise((_res, rej) => { init.signal!.addEventListener('abort', () => rej(new Error('aborted'))); });
    const a = providerAdapter(modelConfigFromEnv(ENV, { model: 'm' }), hung, 10);
    await expect(a.complete(REQ)).rejects.toThrow('anthropic request failed');
  }, 5000);
  it('clears the timer once the call finished, so the signal is never aborted afterwards', async () => {
    let signal: AbortSignal | undefined;
    const f: FetchLike = async (_u, init) => { signal = init.signal; return { ok: true, status: 200, json: async () => ({ content: [{ type: 'text', text: 't' }] }) }; };
    expect(await providerAdapter(modelConfigFromEnv(ENV, { model: 'm' }), f, 20).complete(REQ)).toBe('t');
    await sleep(80);
    expect(signal!.aborted).toBe(false);
    // also after a failure
    const bad: FetchLike = async (_u, init) => { signal = init.signal; return { ok: false, status: 500, json: async () => ({}) }; };
    await expect(providerAdapter(modelConfigFromEnv(ENV, { model: 'm' }), bad, 20).complete(REQ)).rejects.toThrow('anthropic returned HTTP 500');
    await sleep(80);
    expect(signal!.aborted).toBe(false);
  });
});
