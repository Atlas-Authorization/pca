// Mutation-kill tests for the shared leaf-param reader, the corpus document builders and the GraphQL schema walker.
import { describe, expect, it, vi } from 'vitest';
import { leafParam, newBudget, newCtx } from './common';
import { importCorpus, type CorpusEntry } from './eval';
import { importGraphql } from './graphql';
import { importActions } from './pipeline';

vi.mock('./pipeline', () => ({ importActions: vi.fn(() => ({ defs: [], todo: [] })) }));
const imp = vi.mocked(importActions);

const run = (s: Record<string, unknown>) => {
  const c = newCtx('openapi', {}, { ns: 't' });
  const p = leafParam(s as never, true, c, newBudget(c), 'w');
  return { p, todo: c.todo };
};
const dropped = [{ where: 'w', code: 'enum_dropped', message: 'enum values are not 1..256 plain strings (declared as a free string; refine)' }];

describe('leafParam string enum bounds', () => {
  it('an empty enum declares no values and notes nothing', () => {
    const r = run({ type: 'string', enum: [] });
    expect(r.p).toEqual({ type: 'string' });
    expect(r.todo).toEqual([]);
  });
  it('keeps an enum of exactly 256 values', () => {
    const en = Array.from({ length: 256 }, (_, i) => `v${i}`);
    expect(run({ type: 'string', enum: en }).p).toEqual({ type: 'string', values: en });
  });
  it('drops an enum of 257 values', () => {
    const r = run({ type: 'string', enum: Array.from({ length: 257 }, (_, i) => `v${i}`) });
    expect(r.p).toEqual({ type: 'string' });
    expect(r.todo).toEqual(dropped);
  });
  it('drops an enum when only one item is not a string', () => {
    const r = run({ type: 'string', enum: ['ok', ['a']] });
    expect(r.p).toEqual({ type: 'string' });
    expect(r.todo).toEqual(dropped);
  });
  it('keeps a 256-byte value and drops a 257-byte one', () => {
    expect(run({ type: 'string', enum: ['a'.repeat(256)] }).p).toEqual({ type: 'string', values: ['a'.repeat(256)] });
    expect(run({ type: 'string', enum: ['a'.repeat(257)] }).p).toEqual({ type: 'string' });
  });
  it('drops an enum holding the empty string', () => {
    const r = run({ type: 'string', enum: [''] });
    expect(r.p).toEqual({ type: 'string' });
    expect(r.todo).toEqual(dropped);
  });
});

describe('leafParam role extension and array item enums', () => {
  it('ignores a non-string x-pca-role silently', () => {
    const r = run({ type: 'string', 'x-pca-role': 5 });
    expect(r.p).toEqual({ type: 'string' });
    expect(r.todo).toEqual([]);
  });
  it('a unique-items array whose item enum holds a non-string stays a plain string array', () => {
    const r = run({ type: 'array', uniqueItems: true, items: { type: 'string', enum: [['a']] } });
    expect(r.p).toEqual({ type: 'array', items: 'string' });
  });
});

describe('corpus document builders', () => {
  const E = (o: Partial<CorpusEntry> & { id: string }): CorpusEntry => ({ src: 'hand', kind: 'graphql', name: o.id, params: [], labels: [], description: 'd', ...o });
  const src = (e: CorpusEntry): string => { imp.mockClear(); importCorpus([e]); return imp.mock.calls[0]![1] as string; };

  it('a lower-case name ending in no s is a Query field', () => {
    expect(src(E({ id: 'a', name: 'foo' }))).toBe('type Query {\n  "d"\n  foo: String\n}\n');
  });
  it('graphql arg types: no colon, a leading colon and a long first segment', () => {
    const s = src(E({ id: 'b', name: 'foo', params: ['abc', 'nn:integer', ':integer:boolean'] }));
    expect(s).toBe('type Query {\n  "d"\n  foo(ab: String, nn: Int, : String): String\n}\n');
  });
  it('proto field types: no colon, a leading colon and a long first segment', () => {
    const s = src(E({ id: 'c', kind: 'grpc', name: 'svc/M', params: ['abc', 'nn:integer', ':integer:boolean'] }));
    expect(s).toContain('message MRequest {\n  string ab = 1;\n  int64 nn = 2;\n  string  = 3;\n}');
  });
});

describe('GraphQL schema walker placeholders keep the non-null flag', () => {
  it('an output-type argument marked non-null is required', () => {
    const r = importGraphql('type Out { a: String } type Query { probe(x: Out!): Int }', { ns: 'g' });
    expect(r.defs[0]!.params).toEqual({ x: { type: 'string' } });
  });
  it('an argument cut off by the node budget keeps its non-null flag', () => {
    const r = importGraphql('type Query { probe(a: String!, b: String!): Int }', { ns: 'g', limits: { max_ref_nodes: 1 } });
    expect(r.defs[0]!.params).toEqual({ a: { type: 'string' }, b: { type: 'string' } });
  });
});
