import { afterEach, describe, expect, it, vi } from 'vitest';
import { b64u, sha256, utf8 } from '@atlasauth/pca';
import { actionSchemaDigest, verifyActionSchema, type ActionSchema } from '@atlasauth/pca/ext/intent';
import { cmdSchemaConform, cmdSchemaInit, cmdSchemaPublish, cmdSchemaSign, cmdSchemaVerify } from './schema';

afterEach(() => vi.unstubAllGlobals());

const OPENAPI = JSON.stringify({
  paths: { '/book': { post: { operationId: 'createBooking', 'x-pca-verb': 'air.book', 'x-pca-reversibility': 'irreversible', requestBody: { content: { 'application/json': { schema: { properties: { total: { type: 'integer', minimum: 0 } }, required: ['total'] } } } } } } },
});
const SITE = { site: 'https://s.example', aud: 's', version: '1' };
const secret = b64u(sha256(utf8('schema-site-key')));
const jsonError = (text: string): string => { try { JSON.parse(text); } catch (e) { return (e as Error).message; } throw new Error('valid JSON'); };
const signedDoc = () => {
  const s = cmdSchemaSign(cmdSchemaInit(OPENAPI, { from: 'openapi', ...SITE }).schema, { kid: 'k1', secret });
  return { ...s, keys: JSON.stringify([s.key]) };
};

describe('input that is not JSON names the input', () => {
  it('init, verify, conform and publish', async () => {
    const m = jsonError('{');
    expect(() => cmdSchemaInit('{', { from: 'openapi', ...SITE })).toThrow(new Error(`the OpenAPI document is not JSON: ${m}`));
    expect(() => cmdSchemaInit('{', { from: 'mcp', ...SITE })).toThrow(new Error(`the MCP tool list is not JSON: ${m}`));
    const s = signedDoc();
    expect(() => cmdSchemaVerify('{', s.keys)).toThrow(new Error(`the schema is not JSON: ${m}`));
    expect(() => cmdSchemaConform('{', 'air.book', '{}')).toThrow(new Error(`the schema is not JSON: ${m}`));
    expect(() => cmdSchemaConform(s.schema, 'air.book', '{')).toThrow(new Error(`the params is not JSON: ${m}`));
    await expect(cmdSchemaPublish('{', s.keys, { api: 'https://i.example', secretKey: 'sk' })).rejects.toThrow(new Error(`the schema is not JSON: ${m}`));
  });
});

describe('cmdSchemaInit', () => {
  it('an MCP input with no tool list is refused with the exact reason', () => {
    for (const input of ['{}', '{"tools": "x"}', '5']) {
      expect(() => cmdSchemaInit(input, { from: 'mcp', ...SITE })).toThrow(new Error('the MCP input must be a tools/list result {tools: [...]} or a tool array'));
    }
  });
});

describe('cmdSchemaSign', () => {
  it('a draft that is not an object reaches the signer, which refuses it', () => {
    for (const draft of ['null', '5', '"x"']) expect(() => cmdSchemaSign(draft, { kid: 'k1', secret })).toThrow(new Error('signActionSchema: schema is not an object'));
  });
});

describe('keys', () => {
  const MSG = new Error('keys must be a key array or a discovery document with intent.schema_keys');
  it('a document without intent.schema_keys as a list is refused', () => {
    const s = signedDoc();
    for (const keys of ['null', '5', '{}', '{"intent": null}', '{"intent": {}}', '{"intent": {"schema_keys": {}}}']) expect(() => cmdSchemaVerify(s.schema, keys)).toThrow(MSG);
  });
});

describe('cmdSchemaConform', () => {
  it('a violation prints its path when it has one, and nothing when it has not', () => {
    const s = signedDoc();
    expect(cmdSchemaConform(s.schema, 'air.book', '{"total": 5, "x": 1}')).toEqual({ ok: false, text: "DENY  schema_violation undeclared_param (action.params.x): parameter 'action.params.x' is not declared for 'air.book'" });
    expect(cmdSchemaConform(s.schema, 'air.nope', '{}')).toEqual({ ok: false, text: "DENY  schema_violation unknown_verb: verb 'air.nope' is not declared by the schema" });
  });
});

describe('cmdSchemaPublish', () => {
  interface Init { method: string; headers: Record<string, string>; body: string }
  it('a schema that does not verify is refused with the verifier reason', async () => {
    const s = signedDoc();
    const wrong = JSON.stringify([{ ...s.key, kid: 'other' }]);
    const v = verifyActionSchema(JSON.parse(s.schema), JSON.parse(wrong));
    expect(v.ok).toBe(false);
    const r = await cmdSchemaPublish(s.schema, wrong, { api: 'https://i.example', secretKey: 'sk', fetchImpl: async () => ({ status: 201, json: async () => ({}) }) });
    expect(r).toEqual({ ok: false, text: `FAIL  not publishing a schema that does not verify: ${(v as { reason: string }).reason}` });
  });
  it('without any fetch it throws', async () => {
    const s = signedDoc();
    vi.stubGlobal('fetch', undefined);
    await expect(cmdSchemaPublish(s.schema, s.keys, { api: 'https://i.example', secretKey: 'sk' })).rejects.toThrow(new Error('no fetch available'));
  });
  it('POSTs JSON to the instance with every trailing slash of the api removed', async () => {
    const s = signedDoc();
    const calls: Array<{ url: string; init: Init }> = [];
    const r = await cmdSchemaPublish(s.schema, s.keys, { api: 'https://i.example//', secretKey: 'sk_1', fetchImpl: async (url, init) => { calls.push({ url, init }); return { status: 200, json: async () => ({ digest: 'd9', anchor: { index: 2 } }) }; } });
    expect(r).toEqual({ ok: true, text: 'OK  anchored d9 at log index 2' });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe('https://i.example/v1/pca/intent/schemas');
    expect(calls[0]!.init.method).toBe('POST');
    expect(calls[0]!.init.headers).toEqual({ 'content-type': 'application/json', authorization: 'Bearer sk_1' });
    expect(JSON.parse(calls[0]!.init.body)).toEqual({ schema: JSON.parse(s.schema), keys: [s.key] });
  });
  it('a body that is not JSON, or lacks the digest or the anchor, still reports the anchoring', async () => {
    const s = signedDoc();
    const digest = actionSchemaDigest(JSON.parse(s.schema) as ActionSchema);
    const reply = (json: () => Promise<unknown>) => cmdSchemaPublish(s.schema, s.keys, { api: 'https://i.example', secretKey: 'sk', fetchImpl: async () => ({ status: 201, json }) });
    expect(await reply(async () => { throw new Error('not json'); })).toEqual({ ok: true, text: `OK  anchored ${digest} at log index undefined` });
    expect(await reply(async () => null)).toEqual({ ok: true, text: `OK  anchored ${digest} at log index undefined` });
    expect(await reply(async () => ({ digest: 'd2' }))).toEqual({ ok: true, text: 'OK  anchored d2 at log index undefined' });
    expect(await reply(async () => ({ anchor: {} }))).toEqual({ ok: true, text: `OK  anchored ${digest} at log index undefined` });
  });
});
