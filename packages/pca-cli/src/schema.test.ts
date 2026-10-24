import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { cmdSchemaConform, cmdSchemaInit, cmdSchemaPublish, cmdSchemaSign, cmdSchemaVerify } from './schema';

const OPENAPI = JSON.stringify({
  paths: { '/book': { post: { operationId: 'createBooking', 'x-pca-verb': 'air.book', 'x-pca-reversibility': 'irreversible', requestBody: { content: { 'application/json': { schema: { properties: { total: { type: 'integer', minimum: 0 } }, required: ['total'] } } } } } } },
});

describe('pca schema', () => {
  it('init (OpenAPI and MCP) -> sign -> verify -> conform -> publish', async () => {
    const init = cmdSchemaInit(OPENAPI, { from: 'openapi', site: 'https://s', aud: 's', version: '1' });
    expect(JSON.parse(init.schema).verbs[0]).toMatchObject({ verb: 'air.book', kind: 'write', reversibility: 'irreversible' });
    expect(init.todo.some((t) => t.includes('semantic'))).toBe(true);
    const mcp = cmdSchemaInit(JSON.stringify({ tools: [{ name: 'search', inputSchema: { type: 'object', properties: { q: { type: 'string' } } }, annotations: { readOnlyHint: true } }] }), { from: 'mcp', site: 'https://s', aud: 's', version: '1', verbPrefix: 'x.' });
    expect(JSON.parse(mcp.schema).verbs[0]).toMatchObject({ verb: 'x.search', kind: 'read', mcp: { tool: 'search' } });
    expect(() => cmdSchemaInit('{}', { from: 'mcp', site: 's', aud: 's', version: '1' })).toThrow(/tools/);

    const kp = generateKeyPair();
    const signed = cmdSchemaSign(init.schema, { kid: 'k1', secret: b64u(kp.secretKey) });
    const keys = JSON.stringify([signed.key]);
    expect(cmdSchemaVerify(signed.schema, keys)).toEqual({ ok: true, text: `OK  digest ${signed.digest}` });
    expect(cmdSchemaVerify(signed.schema, JSON.stringify({ intent: { schema_keys: [signed.key] } })).ok).toBe(true);
    expect(cmdSchemaVerify(signed.schema, JSON.stringify([{ ...signed.key, kid: 'k2' }])).ok).toBe(false);
    expect(cmdSchemaSign(signed.schema, { kid: 'k1', secret: b64u(kp.secretKey) }).digest).toBe(signed.digest); // re-sign is deterministic
    expect(() => cmdSchemaSign(init.schema, { kid: 'k1', secret: 'AAAA' })).toThrow(/32-byte/);

    expect(cmdSchemaConform(signed.schema, 'air.book', '{"total": 5}').ok).toBe(true);
    expect(cmdSchemaConform(signed.schema, 'air.book', '{"total": 5, "x": 1}').text).toMatch(/^DENY  schema_violation undeclared_param/);

    const calls: { url: string; body: string; auth: string }[] = [];
    const fetchImpl = async (url: string, init: { method: string; headers: Record<string, string>; body: string }) => {
      calls.push({ url, body: init.body, auth: init.headers.authorization! });
      return { status: 201, json: async () => ({ digest: signed.digest, anchor: { index: 4 } }) };
    };
    const pub = await cmdSchemaPublish(signed.schema, keys, { api: 'https://inst.example/', secretKey: 'sk_test_x', fetchImpl });
    expect(pub).toEqual({ ok: true, text: `OK  anchored ${signed.digest} at log index 4` });
    expect(calls[0]).toMatchObject({ url: 'https://inst.example/v1/pca/intent/schemas', auth: 'Bearer sk_test_x' });
    expect(JSON.parse(calls[0]!.body).keys).toEqual([signed.key]);
    const refused = await cmdSchemaPublish(signed.schema, JSON.stringify([{ ...signed.key, pk: b64u(generateKeyPair().publicKey) }]), { api: 'x', secretKey: 'y', fetchImpl });
    expect(refused.ok).toBe(false);
    expect(calls).toHaveLength(1); // nothing sent for a schema that does not verify
  });
});
