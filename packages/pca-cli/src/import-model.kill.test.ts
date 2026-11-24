import { describe, expect, it } from 'vitest';
import { DEFAULT_RULES, loadActionsText, rulesDigest } from '@atlasauth/pca-actions';
import { cmdImport, cmdImportModel } from './actions';

const MCP = JSON.stringify({ tools: [
  { name: 'search_orders', description: 'Search orders', inputSchema: { type: 'object', properties: { q: { type: 'string', maxLength: 100 } }, required: ['q'] }, annotations: { readOnlyHint: true } },
  { name: 'delete_order', inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] }, annotations: { destructiveHint: true, idempotentHint: true } },
  { name: 'price', inputSchema: { type: 'object', properties: { amount: { type: 'number' } } } },
] });
const ONE_TOOL = JSON.stringify({ tools: [{ name: 'search_orders', description: 'Search orders', inputSchema: { type: 'object', properties: { q: { type: 'string', maxLength: 100 } }, required: ['q'] } }] });
const SDL = 'type Query { user(id: ID!): String } type Mutation { sendEmail(to: String!): String }';
const PROTO = 'syntax="proto3"; message M { string a = 1; } service S { rpc Do(M) returns (M); }';

interface Call { url: string; headers: Record<string, string>; body: string }
const fakeFor = (kind: 'anthropic' | 'openai', calls: Call[] = []) => async (url: string, init: { headers: Record<string, string>; body: string }) => {
  calls.push({ url, headers: init.headers, body: init.body });
  const payload = kind === 'anthropic' ? { content: [{ type: 'text', text: '["pca.data_export"]' }] } : { choices: [{ message: { content: '["pca.data_export"]' } }] };
  return { ok: true, status: 200, json: async () => payload };
};
const down = async () => ({ ok: false, status: 500, json: async () => ({}) });

describe('cmdImport details', () => {
  it('records the source uri and licence, and applies the default rules as the suggester', () => {
    const r = cmdImport(ONE_TOOL, { from: 'mcp', ns: 'shop', uri: 'https://shop.example.com/mcp', licence: 'MIT' });
    expect(r.ok).toBe(true);
    const def = loadActionsText(r.yaml).defs[0]!;
    expect(def.source).toMatchObject({ kind: 'mcp', uri: 'https://shop.example.com/mcp', licence: 'MIT' });
    const plain = loadActionsText(cmdImport(ONE_TOOL, { from: 'mcp', ns: 'shop' }).yaml).defs[0]!;
    expect(plain.source).toMatchObject({ uri: 'source:mcp', licence: 'unknown' });
    const by = def.review.suggested_by as { rules?: { version: unknown; digest: unknown; fired: unknown } };
    expect(by.rules).toMatchObject({ version: DEFAULT_RULES.version, digest: rulesDigest(DEFAULT_RULES) });
    expect(Array.isArray(by.rules!.fired)).toBe(true);
    expect(def.review.state).toBe('suggested');
    const none = loadActionsText(cmdImport(ONE_TOOL, { from: 'mcp', ns: 'shop', suggest: 'none' }).yaml).defs[0]!;
    expect(none.review.state).toBe('unreviewed');
  });
  it('a document the importer rejects is a plain refusal', () => {
    expect(cmdImport('{}', { from: 'openapi', ns: 'shop' })).toStrictEqual({ ok: false, yaml: '', todo: [], text: expect.stringMatching(/.+/) });
  });
});

describe('cmdImportModel', () => {
  const env = { ANTHROPIC_API_KEY: 'key-a', OPENAI_API_KEY: 'key-o' };

  it('a source the rules import refuses is returned as that refusal, and the provider is never called', async () => {
    const calls: Call[] = [];
    const want = cmdImport('{', { from: 'mcp', ns: 'shop', suggest: 'rules' });
    expect(want.ok).toBe(false);
    expect(await cmdImportModel('{', { from: 'mcp', ns: 'shop' }, env, fakeFor('anthropic', calls) as never)).toStrictEqual(want);
    expect(calls).toEqual([]);
  });
  it('the summary counts the defs with the right plural and names the provider and model', async () => {
    const one = await cmdImportModel(ONE_TOOL, { from: 'mcp', ns: 'shop', model: 'pinned-1' }, env, fakeFor('anthropic') as never);
    expect(one.ok).toBe(true);
    expect(one.text).toBe('1 draft action (suggested by rules and anthropic:pinned-1; still unreviewed: every one escalates until confirmed)');
    const three = await cmdImportModel(MCP, { from: 'mcp', ns: 'shop', model: 'pinned-1' }, env, fakeFor('anthropic') as never);
    expect(three.text).toBe('3 draft actions (suggested by rules and anthropic:pinned-1; still unreviewed: every one escalates until confirmed)');
    expect(loadActionsText(three.yaml).defs).toHaveLength(3);
  });
  it('--provider picks the provider, its key variable and its endpoint', async () => {
    const calls: Call[] = [];
    const r = await cmdImportModel(ONE_TOOL, { from: 'mcp', ns: 'shop', model: 'pinned-2', provider: 'openai' }, env, fakeFor('openai', calls) as never);
    expect(r.ok, r.text).toBe(true);
    expect(r.text).toContain('rules and openai:pinned-2;');
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe('https://api.openai.com/v1/chat/completions');
    expect(calls[0]!.headers.authorization).toBe('Bearer key-o');
    const missing = await cmdImportModel(ONE_TOOL, { from: 'mcp', ns: 'shop', model: 'pinned-2', provider: 'openai' }, { ANTHROPIC_API_KEY: 'key-a' }, fakeFor('openai') as never);
    expect(missing).toStrictEqual({ ok: false, yaml: '', todo: [], text: 'OPENAI_API_KEY is not set' });
  });
  it('the model name and provider default from the environment and a missing model is refused without any call', async () => {
    const calls: Call[] = [];
    const r = await cmdImportModel(ONE_TOOL, { from: 'mcp', ns: 'shop' }, { ...env, ATLAS_PCA_SUGGEST_MODEL: 'from-env' }, fakeFor('anthropic', calls) as never);
    expect(r.text).toContain('anthropic:from-env;');
    const none = await cmdImportModel(ONE_TOOL, { from: 'mcp', ns: 'shop' }, env, fakeFor('anthropic', calls) as never);
    expect(none.ok).toBe(false);
    expect(none.yaml).toBe('');
    expect(none.todo).toEqual([]);
    expect(none.text).toMatch(/--model/);
    expect(calls).toHaveLength(1);
  });
  it('the source uri, licence and verb reach the second import', async () => {
    const r = await cmdImportModel(ONE_TOOL, { from: 'mcp', ns: 'shop', model: 'm1', uri: 'https://shop.example.com/mcp', licence: 'MIT' }, env, fakeFor('anthropic') as never);
    expect(r.ok, r.text).toBe(true);
    expect(loadActionsText(r.yaml).defs[0]!.source).toMatchObject({ uri: 'https://shop.example.com/mcp', licence: 'MIT' });
    const schema = JSON.stringify({ title: 'Ping', properties: { host: { type: 'string', maxLength: 64 } }, required: ['host'] });
    const js = await cmdImportModel(schema, { from: 'jsonschema', ns: 'ops', model: 'm1', verb: 'ops.host.ping' }, env, fakeFor('anthropic') as never);
    expect(js.ok, js.text).toBe(true);
    expect(loadActionsText(js.yaml).defs.map((d) => d.verb)).toEqual(['ops.host.ping']);
  });
  it('GraphQL and gRPC sources are passed as text, not parsed as JSON', async () => {
    const g = await cmdImportModel(SDL, { from: 'graphql', ns: 'g', model: 'm1' }, env, fakeFor('anthropic') as never);
    expect(g.ok, g.text).toBe(true);
    expect(loadActionsText(g.yaml).defs.length).toBeGreaterThan(0);
    expect(g.text).not.toMatch(/JSON/);
    const p = await cmdImportModel(PROTO, { from: 'grpc', ns: 'p', model: 'm1' }, env, fakeFor('anthropic') as never);
    expect(p.ok, p.text).toBe(true);
    expect(loadActionsText(p.yaml).defs.length).toBeGreaterThan(0);
  });
  it('a model that gives no answer is reported per action after the importer\'s own notes', async () => {
    const r = await cmdImportModel(MCP, { from: 'mcp', ns: 'shop', model: 'pinned-1' }, env, down as never);
    expect(r.ok, r.text).toBe(true);
    const own = cmdImport(MCP, { from: 'mcp', ns: 'shop' }).todo;
    expect(own.length).toBeGreaterThan(0);
    expect(r.todo.slice(0, own.length)).toEqual(own);
    const rest = r.todo.slice(own.length);
    expect(rest).toHaveLength(3);
    for (const line of rest) expect(line).toMatch(/^shop\.[a-z_.]+: model anthropic:pinned-1 gave no suggestion \(.+\)$/);
    expect(new Set(rest.map((x) => x.split(':')[0])).size).toBe(3);
    expect(r.text).toContain('3 draft actions');
  });
  it('the key never appears in the result', async () => {
    const r = await cmdImportModel(MCP, { from: 'mcp', ns: 'shop', model: 'pinned-1' }, env, down as never);
    expect(JSON.stringify(r)).not.toContain('key-a');
  });
});
