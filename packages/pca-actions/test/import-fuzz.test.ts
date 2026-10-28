// Fuzz: whatever bytes or JSON an importer is given, it either refuses with an ActionKitError or returns defs that all validate
// and are unreviewed. It never throws anything else, never emits a def with a confirmed floor, and never hangs.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { ActionKitError, CORE_REGISTRY, effective, importActions, suggestDefs, traitsOf, validateDef, type ActionDef, type ImportKind, type ImportReport } from '../src';
import { runs } from './runs';

const KINDS: ImportKind[] = ['openapi', 'mcp', 'graphql', 'grpc', 'asyncapi'];
const LIM = { max_nodes: 20_000, max_ref_nodes: 500, max_ops: 500, max_bytes: 200_000 };

function check(r: ImportReport): void {
  for (const d of r.defs) {
    expect(validateDef(d)).toBeNull();
    expect(d.review).toEqual({ state: 'unreviewed' });
    expect(d.review.attestation).toBeUndefined();
    expect(traitsOf(d, CORE_REGISTRY)).toContain('pca.unreviewed');
    expect(effective(d, CORE_REGISTRY).eff.rev).toBe('irreversible');
  }
  expect(new Set(r.defs.map((d) => d.verb)).size).toBe(r.defs.length);
}
function run(kind: ImportKind, src: unknown): ImportReport | null {
  try {
    return importActions(kind, src, { ns: 'fz', limits: LIM });
  } catch (e) {
    if (e instanceof ActionKitError) return null;
    throw e;
  }
}

const json: fc.Arbitrary<unknown> = fc.letrec((tie) => ({
  tree: fc.oneof({ depthSize: 'small' }, fc.constant(null), fc.boolean(), fc.integer(), fc.double({ noNaN: true, noDefaultInfinity: true }), fc.string({ maxLength: 12 }),
    fc.array(tie('tree'), { maxLength: 4 }), fc.dictionary(fc.string({ maxLength: 8 }), tie('tree'), { maxKeys: 5 })),
})).tree;

// documents that look right, with fuzzed leaves, so the deep paths run
const keyName = fc.oneof(fc.constantFrom('type', 'properties', 'required', 'enum', 'items', '$ref', 'allOf', 'oneOf', 'format', 'minimum', 'maximum', 'maxLength', 'readOnly', 'description', 'x-pca-role', 'x-pca-verb', '__proto__'), fc.string({ maxLength: 6 }));
const schema: fc.Arbitrary<unknown> = fc.letrec((tie) => ({
  s: fc.oneof({ depthSize: 'small' }, json, fc.dictionary(keyName, fc.oneof(json, tie('s')), { maxKeys: 6 }), fc.record({ type: fc.constantFrom('object', 'string', 'integer', 'array', 'boolean'), properties: fc.dictionary(fc.string({ maxLength: 6 }), tie('s'), { maxKeys: 4 }), items: tie('s') }, { requiredKeys: ['type'] })),
})).s;
const pathStr = fc.constantFrom('/a', '/a/{id}', '/v1/x/{x}/y', '/a b', '/');
const oaDoc = fc.record({
  openapi: fc.constantFrom('3.0.0', '3.1.0'),
  components: fc.record({ schemas: fc.dictionary(fc.constantFrom('A', 'B', 'C'), schema, { maxKeys: 3 }) }),
  paths: fc.dictionary(pathStr, fc.dictionary(fc.constantFrom('get', 'post', 'put', 'delete', 'parameters', 'x-y'), fc.oneof(json, fc.record({
    operationId: fc.oneof(fc.string({ maxLength: 12 }), fc.constantFrom('getA', 'create_b', 'a.b.c')), summary: fc.string({ maxLength: 20 }), deprecated: fc.boolean(),
    parameters: fc.array(fc.record({ name: fc.string({ maxLength: 8 }), in: fc.constantFrom('path', 'query', 'header', 'cookie', 'body'), required: fc.boolean(), schema }), { maxLength: 3 }),
    requestBody: fc.record({ content: fc.dictionary(fc.constantFrom('application/json', 'text/plain', 'multipart/form-data'), fc.record({ schema }), { maxKeys: 2 }) }),
  })), { maxKeys: 4 }), { maxKeys: 4 }),
});
const mcpDoc = fc.array(fc.record({ name: fc.oneof(fc.string({ maxLength: 12 }), fc.constantFrom('a', 'send_mail', 'DeleteAll')), description: fc.string({ maxLength: 30 }), inputSchema: schema, annotations: fc.record({ readOnlyHint: fc.boolean(), destructiveHint: fc.boolean(), openWorldHint: fc.boolean() }, { requiredKeys: [] }) }, { requiredKeys: ['name'] }), { maxLength: 6 });

describe('importer fuzz', () => {
  for (const kind of KINDS) {
    it(`${kind}: arbitrary JSON never throws anything but ActionKitError`, () => {
      fc.assert(fc.property(json, (src) => { const r = run(kind, src); if (r) check(r); }), { seed: 71, numRuns: runs(2000) });
    });
  }
  it('openapi: documents with fuzzed schemas validate, are unreviewed, and stay within bounds', () => {
    fc.assert(fc.property(oaDoc, (doc) => { const r = run('openapi', doc); if (r) check(r); }), { seed: 72, numRuns: runs(3000) });
  });
  it('mcp: tool lists with fuzzed schemas validate and are unreviewed', () => {
    fc.assert(fc.property(mcpDoc, (tools) => { const r = run('mcp', tools); if (r) check(r); }), { seed: 73, numRuns: runs(3000) });
  });
  it('asyncapi: fuzzed channels', () => {
    const doc = fc.record({ asyncapi: fc.constantFrom('2.6.0', '3.0.0'), components: fc.record({ schemas: fc.dictionary(fc.constantFrom('A', 'B'), schema, { maxKeys: 2 }) }), channels: fc.dictionary(fc.string({ maxLength: 8 }), fc.record({ publish: fc.record({ operationId: fc.string({ maxLength: 8 }), message: fc.record({ payload: schema }) }), subscribe: json }), { maxKeys: 3 }), operations: fc.dictionary(fc.string({ maxLength: 6 }), fc.record({ action: fc.constantFrom('send', 'receive', 'x'), channel: json }), { maxKeys: 3 }) });
    fc.assert(fc.property(doc, (d) => { const r = run('asyncapi', d); if (r) check(r); }), { seed: 74, numRuns: runs(2000) });
  });
  it('graphql: random token soup and mutated valid SDL', () => {
    const toks = ['type', 'input', 'enum', 'Query', 'Mutation', 'A', 'b', 'c', '{', '}', '(', ')', ':', '!', '[', ']', '=', '@', 'deprecated', '"x"', '"""d"""', 'Int', 'String', '1', '#c\n', '|', '&', 'implements', 'union', 'schema', 'extend', ','];
    const soup = fc.array(fc.constantFrom(...toks), { maxLength: 40 }).map((a) => a.join(' '));
    fc.assert(fc.property(soup, (s) => { const r = run('graphql', s); if (r) check(r); }), { seed: 75, numRuns: runs(4000) });
    const valid = 'type Query { a(x: Int!, y: [String]): String } type Mutation { createB(input: In!): String } input In { z: String! n: Int } enum E { X Y }';
    fc.assert(fc.property(fc.nat(valid.length - 1), fc.constantFrom('', '{', ')', ' ! ', '"', '@@', 'type'), (i, ins) => { const r = run('graphql', valid.slice(0, i) + ins + valid.slice(i + 1)); if (r) check(r); }), { seed: 76, numRuns: runs(4000) });
  });
  it('grpc: random token soup, mutated proto and random bytes', () => {
    const toks = ['syntax', '=', '"proto3"', ';', 'package', 'a.b', 'message', 'M', '{', '}', 'string', 'int64', 'x', '1', 'service', 'S', 'rpc', 'R', '(', ')', 'returns', 'stream', 'repeated', 'map', '<', '>', ',', 'option', '[', ']', 'oneof', 'enum', 'E', 'google.api.http', 'get', '"/v1"'];
    const soup = fc.array(fc.constantFrom(...toks), { maxLength: 50 }).map((a) => a.join(' '));
    fc.assert(fc.property(soup, (s) => { const r = run('grpc', s); if (r) check(r); }), { seed: 77, numRuns: runs(4000) });
    const valid = 'syntax="proto3"; package p; message M { string x = 1; repeated int64 y = 2 [(google.api.field_behavior)=REQUIRED]; map<string,string> m = 3; } service S { rpc R(M) returns (M) { option (google.api.http) = { get: "/v1" }; } }';
    fc.assert(fc.property(fc.nat(valid.length - 1), fc.constantFrom('', '{', ')', '"', ';;', 'rpc'), (i, ins) => { const r = run('grpc', valid.slice(0, i) + ins + valid.slice(i + 1)); if (r) check(r); }), { seed: 78, numRuns: runs(4000) });
    fc.assert(fc.property(fc.uint8Array({ maxLength: 200 }), (b) => { const r = run('grpc', b); if (r) check(r); }), { seed: 79, numRuns: runs(4000) });
  });
  it('suggestions on imported defs only add and never confirm', async () => {
    await fc.assert(fc.asyncProperty(oaDoc, async (doc) => {
      const r = run('openapi', doc);
      if (!r) return;
      const s = await suggestDefs(r.defs);
      expect(s.defs).toHaveLength(r.defs.length);
      s.defs.forEach((d: ActionDef, i) => {
        const before = r.defs[i]!;
        expect(['unreviewed', 'suggested']).toContain(d.review.state);
        expect(d.review.attestation).toBeUndefined();
        for (const t of before.traits ?? []) expect(d.traits).toContain(t);
        expect(Object.keys(d.params)).toEqual(Object.keys(before.params));
        for (const k of Object.keys(before.params)) if (before.params[k]!.role !== undefined) expect(d.params[k]!.role).toBe(before.params[k]!.role);
      });
    }), { seed: 80, numRuns: runs(500) });
  });
});
