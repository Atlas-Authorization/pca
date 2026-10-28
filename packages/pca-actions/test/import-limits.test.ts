// Importers refuse hostile input within fixed bounds: size, depth, node count, reference bombs, cycles, remote references,
// operation counts, truncated binary descriptors. A bound that is exceeded refuses the whole source; a shortfall inside one
// operation is a todo and the def fails closed.
import { describe, expect, it } from 'vitest';
import {
  ActionKitError, DEFAULT_IMPORT_LIMITS, HARD_IMPORT_LIMITS, importAsyncApi, importGraphql, importGrpc, importJsonSchema, importMcp, importOpenApi, resolveLimits, validateDef,
} from '../src';

const O = { ns: 'x' };
const code = (f: () => unknown): string => {
  try { f(); } catch (e) { return e instanceof ActionKitError ? e.code : `other:${(e as Error).message}`; }
  return 'none';
};

/** A reference bomb: schema N refers to N+1 twice, `depth` levels deep, so a naive expansion visits 2^depth nodes. */
const bomb = (depth: number): Record<string, unknown> => {
  const schemas: Record<string, unknown> = {};
  for (let i = 0; i < depth; i++) schemas[`S${i}`] = { type: 'object', properties: { a: { $ref: `#/components/schemas/S${i + 1}` }, b: { $ref: `#/components/schemas/S${i + 1}` } } };
  schemas[`S${depth}`] = { type: 'string' };
  return { openapi: '3.0.0', components: { schemas }, paths: { '/a': { post: { operationId: 'op', requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/S0' } } } } } } } };
};
const allOfBomb = (width: number, depth: number): Record<string, unknown> => {
  const schemas: Record<string, unknown> = {};
  for (let i = 0; i < depth; i++) schemas[`S${i}`] = { allOf: Array.from({ length: width }, () => ({ $ref: `#/components/schemas/S${i + 1}` })) };
  schemas[`S${depth}`] = { type: 'object', properties: { x: { type: 'string' } } };
  return { openapi: '3.0.0', components: { schemas }, paths: { '/a': { post: { operationId: 'op', requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/S0' } } } } } } } };
};

describe('limits', () => {
  it('clamps a caller limit to the hard ceiling and rejects nonsense', () => {
    expect(resolveLimits({ max_ops: 10 }).max_ops).toBe(10);
    expect(resolveLimits({ max_ops: 10 ** 12 }).max_ops).toBe(HARD_IMPORT_LIMITS.max_ops);
    expect(resolveLimits().max_bytes).toBe(DEFAULT_IMPORT_LIMITS.max_bytes);
    expect(code(() => resolveLimits({ max_ops: 0 }))).toBe('bad_limit');
    expect(code(() => resolveLimits({ max_ops: 1.5 }))).toBe('bad_limit');
  });
});

describe('size and shape bounds', () => {
  it('refuses a text source over the byte limit (each text importer)', () => {
    const big = 'x'.repeat(2000);
    expect(code(() => importGraphql(big, { ...O, limits: { max_bytes: 1000 } }))).toBe('import_limit');
    expect(code(() => importGrpc(big, { ...O, limits: { max_bytes: 1000 } }))).toBe('import_limit');
    expect(code(() => importGrpc(new Uint8Array(2000), { ...O, limits: { max_bytes: 1000 } }))).toBe('import_limit');
  });
  it('refuses a parsed source over the byte, node or depth limit', () => {
    const doc = { openapi: '3.0.0', paths: {}, filler: 'y'.repeat(5000) };
    expect(code(() => importOpenApi(doc, { ...O, limits: { max_bytes: 1000 } }))).toBe('import_limit');
    expect(code(() => importOpenApi({ openapi: '3.0.0', paths: {}, a: Array.from({ length: 100 }, () => 1) }, { ...O, limits: { max_nodes: 50 } }))).toBe('import_limit');
    let deep: unknown = 1;
    for (let i = 0; i < 200; i++) deep = { a: deep };
    expect(code(() => importOpenApi({ openapi: '3.0.0', paths: {}, deep }, O))).toBe('import_limit');
    expect(code(() => importMcp([deep], O))).toBe('import_limit');
  });
  it('terminates on a cyclic object without a stack overflow', () => {
    const a: Record<string, unknown> = { openapi: '3.0.0', paths: {} };
    a.self = a;
    expect(code(() => importOpenApi(a, O))).toBe('import_limit');
  });
  it('refuses non-JSON values: functions, bigint, NaN, class instances', () => {
    expect(code(() => importOpenApi({ openapi: '3.0.0', paths: {}, f: () => 1 }, O))).toBe('bad_source');
    expect(code(() => importOpenApi({ openapi: '3.0.0', paths: {}, n: Number.NaN }, O))).toBe('bad_source');
    expect(code(() => importOpenApi({ openapi: '3.0.0', paths: {}, d: new Date() }, O))).toBe('bad_source');
    expect(code(() => importOpenApi({ openapi: '3.0.0', paths: {}, b: 10n }, O))).toBe('bad_source');
  });
  it('refuses more operations than the limit', () => {
    const paths: Record<string, unknown> = {};
    for (let i = 0; i < 30; i++) paths[`/p${i}`] = { get: { operationId: `op${i}` } };
    expect(code(() => importOpenApi({ openapi: '3.0.0', paths }, { ...O, limits: { max_ops: 10 } }))).toBe('import_limit');
    expect(importOpenApi({ openapi: '3.0.0', paths }, { ...O, limits: { max_ops: 30 } }).defs).toHaveLength(30);
    expect(code(() => importMcp(Array.from({ length: 30 }, (_, i) => ({ name: `t${i}` })), { ...O, limits: { max_ops: 10 } }))).toBe('import_limit');
  });
});

describe('reference bombs and cycles', () => {
  it('a binary reference bomb costs a bounded amount of work and fails closed', () => {
    const t0 = Date.now();
    const r = importOpenApi(bomb(40), O);
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(r.defs).toHaveLength(1);
    expect(validateDef(r.defs[0])).toBeNull();
    // objects expand one level per dotted segment, so the chain is cut at three segments with a placeholder
    expect(Object.keys(r.defs[0]!.params).every((k) => k.split('.').length <= 3)).toBe(true);
    expect(r.todo.some((t) => t.code === 'object_leaf')).toBe(true);
  });
  it('an allOf fan-out bomb is bounded by the node budget', () => {
    const t0 = Date.now();
    const r = importOpenApi(allOfBomb(50, 12), { ...O, limits: { max_ref_nodes: 5000 } });
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(r.todo.some((t) => t.code === 'ref_budget' || t.code === 'ref_depth')).toBe(true);
  });
  it('a smaller budget stops sooner and says so once per operation', () => {
    const r = importOpenApi(bomb(6), { ...O, limits: { max_ref_nodes: 10 } });
    expect(r.todo.filter((t) => t.code === 'ref_budget')).toHaveLength(1);
  });
  it('a cyclic reference is noted and the parameter is a string placeholder', () => {
    const r = importOpenApi({ openapi: '3.0.0', components: { schemas: { A: { type: 'object', properties: { next: { $ref: '#/components/schemas/A' } } } } }, paths: { '/a': { post: { operationId: 'op', requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/A' } } } } } } } }, O);
    expect(r.defs).toHaveLength(1);
    expect(r.todo.some((t) => t.code === 'cyclic_ref' || t.code === 'ref_depth' || t.code === 'object_leaf')).toBe(true);
    expect(validateDef(r.defs[0])).toBeNull();
  });
  it('a remote reference is never fetched: it is noted and fails closed', () => {
    const r = importOpenApi({ openapi: '3.0.0', paths: { '/a': { post: { operationId: 'op', requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { x: { $ref: 'https://evil.test/s.json#/A' }, y: { $ref: 'file:///etc/passwd' } } } } } } } } } }, O);
    expect(r.todo.filter((t) => t.code === 'unresolved_ref')).toHaveLength(2);
    expect(r.defs[0]!.params['x']).toMatchObject({ type: 'string' });
  });
  it('a path item or request body that is a cyclic reference chain terminates', () => {
    const r = importOpenApi({ openapi: '3.0.0', components: { requestBodies: { A: { $ref: '#/components/requestBodies/B' }, B: { $ref: '#/components/requestBodies/A' } } }, paths: { '/a': { post: { operationId: 'op', requestBody: { $ref: '#/components/requestBodies/A' } } } } }, O);
    expect(r.defs).toHaveLength(1);
    expect(r.todo.some((t) => t.code === 'cyclic_ref')).toBe(true);
  });
  it('a self-referencing JSON Schema, MCP input schema and AsyncAPI payload terminate', () => {
    const rec = { $defs: { N: { type: 'object', properties: { child: { $ref: '#/$defs/N' }, v: { type: 'string' } } } }, $ref: '#/$defs/N' };
    expect(importJsonSchema(rec, { ns: 'x', verb: 'x.a.b' }).defs).toHaveLength(1);
    expect(importMcp([{ name: 't', inputSchema: { ...rec, type: 'object' } }], O).defs).toHaveLength(1);
    const ev = importAsyncApi({ asyncapi: '2.0.0', components: { schemas: { N: { type: 'object', properties: { c: { $ref: '#/components/schemas/N' } } } } }, channels: { c: { publish: { message: { payload: { $ref: '#/components/schemas/N' } } } } } }, O);
    expect(ev.defs).toHaveLength(1);
  });
  it('a recursive GraphQL input type and a recursive proto message terminate and note it', () => {
    const g = importGraphql('input F { and: [F] or: F value: String } type Query { search(filter: F): String }', O);
    expect(g.defs).toHaveLength(1);
    expect(g.todo.some((t) => t.code === 'cyclic_ref')).toBe(true);
    const p = importGrpc('syntax="proto3"; message Node { Node next = 1; string v = 2; } service S { rpc Walk(Node) returns (Node); }', O);
    expect(p.defs).toHaveLength(1);
    expect(p.todo.some((t) => t.code === 'cyclic_ref')).toBe(true);
  });
  it('deep nesting stops at three dotted segments and the rest is a placeholder', () => {
    let s: Record<string, unknown> = { type: 'string' };
    for (let i = 0; i < 8; i++) s = { type: 'object', properties: { n: s } };
    const r = importJsonSchema(s, { ns: 'x', verb: 'x.a.b' });
    const names = Object.keys(r.defs[0]!.params);
    expect(names).toEqual(['n.n.n']);
    expect(r.todo.some((t) => t.code === 'object_leaf')).toBe(true);
  });
});

describe('hostile content', () => {
  it('at most 64 params; the rest are dropped and noted', () => {
    const props: Record<string, unknown> = {};
    for (let i = 0; i < 200; i++) props[`p${i}`] = { type: 'string' };
    const r = importJsonSchema({ type: 'object', properties: props }, { ns: 'x', verb: 'x.a.b' });
    expect(Object.keys(r.defs[0]!.params)).toHaveLength(64);
    expect(r.todo.some((t) => t.code === 'too_many_params')).toBe(true);
  });
  it('reserved and unsafe names never reach the def', () => {
    const props = JSON.parse('{"__proto__": {"type":"string"}, "constructor": {"type":"string"}, "prototype": {"type":"string"}, "a b": {"type":"string"}, "ok": {"type":"string"}}');
    const r = importJsonSchema({ type: 'object', properties: props }, { ns: 'x', verb: 'x.a.b' });
    expect(Object.keys(r.defs[0]!.params).sort()).toEqual(['a_b', 'ok']);
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });
  it('control characters, bidi overrides and lone surrogates are removed from titles and descriptions', () => {
    const r = importMcp([{ name: 't', description: 'ok‮evil\u0000 \ud800 text', annotations: { title: 'T⁦x' } }], O);
    const d = r.defs[0]!;
    expect(validateDef(d)).toBeNull();
    expect(d.description).toBe('ok evil text');
    expect(d.title).toBe('T x');
  });
  it('an oversized description or enum is cut or dropped, never copied through', () => {
    const r = importJsonSchema({ type: 'object', properties: { e: { type: 'string', enum: Array.from({ length: 300 }, (_, i) => `v${i}`), description: 'd'.repeat(5000) }, s: { type: 'string', enum: ['a'.repeat(1000)] } } }, { ns: 'x', verb: 'x.a.b', description: 'z'.repeat(9000) });
    const d = r.defs[0]!;
    expect(validateDef(d)).toBeNull();
    expect(d.params['e']!.values).toBeUndefined();
    expect(d.params['s']!.values).toBeUndefined();
    expect(new TextEncoder().encode(d.description!).length).toBeLessThanOrEqual(600);
    expect(r.todo.filter((t) => t.code === 'enum_dropped')).toHaveLength(2);
  });
  it('an integer outside the safe range is not carried into min/max', () => {
    const d = importJsonSchema({ type: 'object', properties: { n: { type: 'integer', minimum: 1e30, maximum: -0.5 } } }, { ns: 'x', verb: 'x.a.b' }).defs[0]!;
    expect(d.params['n']).toEqual({ type: 'integer', required: false });
  });
  it('many todos are capped', () => {
    const props: Record<string, unknown> = {};
    for (let i = 0; i < 60; i++) props[`p${i}`] = { type: 'number' };
    const paths: Record<string, unknown> = {};
    for (let i = 0; i < 200; i++) paths[`/p${i}`] = { post: { operationId: `op${i}`, requestBody: { content: { 'application/json': { schema: { type: 'object', properties: props } } } } } };
    const r = importOpenApi({ openapi: '3.0.0', paths }, O);
    expect(r.todo.length).toBeLessThanOrEqual(5001);
    expect(r.todo[r.todo.length - 1]!.code).toBe('todo_truncated');
  });
  it('a binary descriptor with a length beyond the buffer, a bad varint or a wire type 7 is refused', () => {
    expect(code(() => importGrpc(Uint8Array.from([0x0a, 0x10, 1, 2, 3]), O))).toBe('bad_source');
    expect(code(() => importGrpc(Uint8Array.from([0x0a, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]), O))).toBe('bad_source');
    expect(code(() => importGrpc(Uint8Array.from([0x0f]), O))).toBe('bad_source');
    expect(importGrpc(new Uint8Array(0), O).defs).toHaveLength(0);
  });
  it('a long but ordinary SDL imports without hitting a bound', () => {
    expect(code(() => importGraphql('type Q { ' + 'a: Int '.repeat(50) + '}', { ...O, limits: { max_bytes: 10_000_000 } }))).toBe('none');
  });
  it('a deeply nested GraphQL list type or value does not overflow the stack', () => {
    const t = '['.repeat(500) + 'Int' + ']'.repeat(500);
    expect(code(() => importGraphql(`type Query { a(x: ${t}): Int }`, O))).toBe('import_limit');
    const v = '['.repeat(500) + ']'.repeat(500);
    expect(code(() => importGraphql(`type Query { a(x: Int = ${v}): Int }`, O))).toBe('import_limit');
  });
});
