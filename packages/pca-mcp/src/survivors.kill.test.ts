import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair, type PcaCall } from '@atlasauth/pca';
import { applySchemaDecisions, conformToolCall, draftActionSchemaFromMcp, verbOfTool } from './schema';
import { guardToolResult, parseChallenges, pcaFetch, pcaNeedProblem, planStepUp, withPCA } from './index';

const AUD = 'ins_kill';
const mkAgent = () => agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });

describe('parseChallenges', () => {
  it('reads spaces and tabs around the equals sign, in either order', () => {
    expect(parseChallenges('Bearer a = b')).toEqual([{ scheme: 'bearer', params: { a: 'b' } }]);
    expect(parseChallenges('Bearer a =b')).toEqual([{ scheme: 'bearer', params: { a: 'b' } }]);
    expect(parseChallenges('Bearer a= b')).toEqual([{ scheme: 'bearer', params: { a: 'b' } }]);
    expect(parseChallenges('Bearer a\t=b')).toEqual([{ scheme: 'bearer', params: { a: 'b' } }]);
    expect(parseChallenges('Bearer a=\tb')).toEqual([{ scheme: 'bearer', params: { a: 'b' } }]);
    expect(parseChallenges('Bearer a\t=\t"x y"')).toEqual([{ scheme: 'bearer', params: { a: 'x y' } }]);
    expect(parseChallenges('Bearer a = "x"')).toEqual([{ scheme: 'bearer', params: { a: 'x' } }]);
  });
  it('reads unquoted values and separators between parameters and challenges', () => {
    expect(parseChallenges('Bearer a=b, c=d')).toEqual([{ scheme: 'bearer', params: { a: 'b', c: 'd' } }]);
    expect(parseChallenges('Bearer a=b,Basic c=d')).toEqual([
      { scheme: 'bearer', params: { a: 'b' } },
      { scheme: 'basic', params: { c: 'd' } },
    ]);
    expect(parseChallenges(' \t,Bearer a=b')).toEqual([{ scheme: 'bearer', params: { a: 'b' } }]);
  });
  it('terminates on tokens that end the header', () => {
    expect(parseChallenges('Bearer')).toEqual([{ scheme: 'bearer', params: {} }]);
    expect(parseChallenges('Bearer a=b')).toEqual([{ scheme: 'bearer', params: { a: 'b' } }]);
    expect(parseChallenges('Bearer a=')).toEqual([{ scheme: 'bearer', params: { a: '' } }]);
  });
  it('ignores parameters that precede any scheme', () => {
    expect(parseChallenges('a=b, Bearer c=d')).toEqual([{ scheme: 'bearer', params: { c: 'd' } }]);
  });
  it('keeps a trailing backslash inside a quoted value', () => {
    expect(parseChallenges('Bearer a="x\\')[0]?.params.a).toBe('x\\');
  });
});

describe('planStepUp and pcaNeedProblem', () => {
  const bearer = 'Bearer error="insufficient_scope"';
  it('a challenge without a scope adds nothing', () => {
    expect(planStepUp(403, bearer, { requested: [], attempts: 0 })).toEqual({ action: 'give_up', reason: 'no_new_scope' });
    expect(planStepUp(403, bearer, { requested: ['a'], attempts: 0 })).toEqual({ action: 'give_up', reason: 'no_new_scope' });
  });
  it('splits scopes on single spaces and drops empty entries', () => {
    expect(planStepUp(403, 'Bearer error="insufficient_scope", scope="  b  a "', { requested: [], attempts: 0 })).toEqual({ action: 'scope', scopes: ['a', 'b'], attempts: 1 });
  });
  it('a PCA-aware client without a pca_need falls back to scopes', () => {
    expect(planStepUp(403, `${bearer}, scope="a"`, { requested: [], attempts: 0, pcaAware: true })).toEqual({ action: 'scope', scopes: ['a'], attempts: 1 });
  });
  it('reports why a pca_need was ignored, and null when absent or fine', () => {
    expect(pcaNeedProblem('Bearer pca_need="!!!"')).toBe('bad_base64');
    expect(pcaNeedProblem('Bearer error="x"')).toBeNull();
    expect(pcaNeedProblem(undefined)).toBeNull();
  });
});

describe('withPCA options', () => {
  const handler = () => ({ content: [{ type: 'text', text: 'ok' }] });
  it('passes the audience override to the proof, and the agent default otherwise', async () => {
    const a = mkAgent();
    const seen: PcaCall[] = [];
    await withPCA(a, { verb: 'stripe.refund', resource: 'charge:1', aud: 'other_aud', onProof: (p) => seen.push(p) }, handler)({ amount: 1 });
    await withPCA(a, { verb: 'stripe.refund', resource: 'charge:1', onProof: (p) => seen.push(p) }, handler)({ amount: 1 });
    expect(seen.map((p) => p.pcactn.aud)).toEqual(['other_aud', AUD]);
  });
  it('failFast: false lets an over-cap call reach the handler', async () => {
    const a = mkAgent();
    const out = await withPCA(a, { verb: 'stripe.refund', resource: 'charge:1', failFast: false }, handler)({ amount: 9999 });
    expect(out).toEqual({ content: [{ type: 'text', text: 'ok' }] });
  });
  it('runs without an onProof callback', async () => {
    expect(await withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'charge:1' }, handler)({ amount: 1 })).toEqual({ content: [{ type: 'text', text: 'ok' }] });
  });
  it('rethrows an error that is not a local denial', async () => {
    const boom = new Error('boom');
    await expect(withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'charge:1' }, () => { throw boom; })({ amount: 1 })).rejects.toBe(boom);
  });
  it('guardToolResult ignores a _meta that is not an object', () => {
    const pca = { encoded: 'ENC' } as unknown as PcaCall;
    expect(guardToolResult(pca, { content: [], _meta: 'abc' })._meta).toEqual({ 'x-pca-action': 'ENC' });
    expect(guardToolResult(pca, { content: [] })._meta).toEqual({ 'x-pca-action': 'ENC' });
    expect(guardToolResult(pca, { content: [], _meta: { k: 1 } })._meta).toEqual({ k: 1, 'x-pca-action': 'ENC' });
  });
});

describe('pcaFetch request screening', () => {
  const rpc = (method: string, params?: unknown) => JSON.stringify({ jsonrpc: '2.0', id: 1, method, ...(params !== undefined ? { params } : {}) });
  function run(body: unknown, mapSeen: unknown[] = []) {
    const heads: (string | null)[] = [];
    const inner = (async (_u: unknown, init?: { headers?: ConstructorParameters<typeof Headers>[0] }) => {
      heads.push(new Headers(init?.headers).get('PCA-Action'));
      return new Response('{}');
    }) as unknown as typeof fetch;
    const f = pcaFetch(mkAgent(), (tool, args) => (mapSeen.push([tool, args]), { verb: 'stripe.refund', resource: 'charge:1' }), { fetch: inner });
    return f('http://x/mcp', { method: 'POST', body: body as never }).then(() => heads);
  }
  it('sends no proof for a JSON null body or a non tools/call message', async () => {
    expect(await run('null')).toEqual([null]);
    expect(await run('5')).toEqual([null]);
    expect(await run(rpc('other/method', { name: 'refund', arguments: {} }))).toEqual([null]);
    expect(await run(rpc('tools/call'))).toEqual([null]);
    expect(await run(rpc('tools/call', null))).toEqual([null]);
    expect(await run(rpc('tools/call', { name: 5, arguments: {} }))).toEqual([null]);
  });
  it('only a string body is read', async () => {
    expect(await run([rpc('tools/call', { name: 'refund', arguments: {} })])).toEqual([null]);
    expect(await run({ toString: () => rpc('tools/call', { name: 'refund', arguments: {} }) })).toEqual([null]);
  });
  it('hands the mapper an object for the arguments, {} when they are not one', async () => {
    const seen: unknown[] = [];
    expect((await run(rpc('tools/call', { name: 'refund', arguments: { a: 1 } }), seen))[0]).toBeTruthy();
    for (const args of [undefined, null, 'x', [1, 2], 5]) await run(rpc('tools/call', { name: 'refund', ...(args !== undefined ? { arguments: args } : {}) }), seen);
    expect(seen).toEqual([['refund', { a: 1 }], ['refund', {}], ['refund', {}], ['refund', {}], ['refund', {}], ['refund', {}]]);
  });
});

describe('schema helpers', () => {
  const TOOLS = [
    { name: 'book', inputSchema: { type: 'object', properties: { total: { type: 'integer' } }, required: ['total'] }, annotations: { destructiveHint: true } },
    { name: 'search', inputSchema: { type: 'object', properties: { q: { type: 'string' } }, required: ['q'] }, annotations: { readOnlyHint: true } },
  ];
  const draft = () => draftActionSchemaFromMcp(TOOLS, { site: 'https://s', aud: 's', version: '1', verbPrefix: 'air.' });

  it('records a reversibility and parameter decisions, and leaves other verbs alone', async () => {
    const { schema } = await draft();
    const before = schema.verbs.find((v) => v.verb === 'air.search')!;
    const out = applySchemaDecisions(schema, { verbs: { 'air.search': { reversibility: 'irreversible', params: { 'action.params.q': { semantic: 'free_text', sensitivity: 'critical' } } } } });
    const v = out.verbs.find((x) => x.verb === 'air.search')!;
    expect(v.reversibility).toBe('irreversible');
    expect(v.params['action.params.q']).toMatchObject({ semantic: 'free_text', sensitivity: 'critical' });
    expect(before.reversibility).not.toBe('irreversible');
    const book = applySchemaDecisions(schema, { verbs: { 'air.book': { params: {} } } }).verbs.find((x) => x.verb === 'air.book')!;
    expect(book.reversibility).toBe(schema.verbs.find((x) => x.verb === 'air.book')!.reversibility);
  });
  it('merges units into existing ones and adds none when no decision names any', async () => {
    const { schema } = await draft();
    const base = { ...schema, units: { a: { kind: 'money', currency: 'USD', exponent: 2 } } } as never;
    const merged = applySchemaDecisions(base, { verbs: {}, units: { b: { kind: 'money', currency: 'EUR', exponent: 2 } } } as never);
    expect(Object.keys(merged.units ?? {}).sort()).toEqual(['a', 'b']);
    expect(applySchemaDecisions(base, { verbs: {} }).units).toEqual({ a: { kind: 'money', currency: 'USD', exponent: 2 } });
    expect('units' in applySchemaDecisions({ ...schema, units: undefined } as never, { verbs: {} })).toBe(false);
  });
  it('maps tools to verbs even when a verb has no mcp binding', () => {
    expect(verbOfTool({ verbs: [{ verb: 'a' }, { verb: 'b', mcp: { tool: 't' } }] } as never, 't')).toBe('b');
    expect(verbOfTool({ verbs: [{ verb: 'a' }] } as never, 't')).toBeUndefined();
  });
  it('refuses an unmapped tool with its name', () => {
    expect(conformToolCall({ verbs: [] }, 'ghost', {})).toEqual({ ok: false, code: 'unknown_verb', reason: "MCP tool 'ghost' is not declared by the site schema" });
  });
});
