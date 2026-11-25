// GraphQL importer: whitespace forms, description tokens that look like punctuation, absent introspection roots and required wrappers on skipped types.
import { describe, expect, it } from 'vitest';
import { fromIntrospection, importGraphql, parseGraphqlSdl } from '../src';

describe('GraphQL importer edge forms', () => {
  it('skips tabs, carriage returns and a byte-order mark as whitespace', () => {
    expect([...parseGraphqlSdl('\uFEFFscalar\tA\r\nscalar B').types.keys()]).toEqual(['A', 'B']);
  });
  it('a description string that equals a closing brace does not end the field list', () => {
    const f = parseGraphqlSdl('type A { "}" f: Int }').types.get('A')!.fields;
    expect(f.map((x) => [x.name, x.desc])).toEqual([['f', '}']]);
  });
  it('an introspection result without root types sets no root names', () => {
    expect(fromIntrospection({ __schema: { types: [] } })).toStrictEqual({ types: new Map() });
  });
  it('keeps the required flag on unknown and recursive input types', () => {
    const r = importGraphql('input N { next: N! } type Query { probe(n: N!, z: Zed!): Int }', { ns: 'g' });
    expect(r.defs[0]!.params).toEqual({ 'n.next': { type: 'string' }, z: { type: 'string' } });
  });
});
