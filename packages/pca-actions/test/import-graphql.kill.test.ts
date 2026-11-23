// The SDL lexer treats a tab, a carriage return and a byte-order mark as white space.
import { describe, expect, it } from 'vitest';
import { fromIntrospection, importGraphql } from '../src';

const defsOf = (sdl: string) => importGraphql(sdl, { ns: 't' });

describe('GraphQL SDL white space', () => {
  it('a tab, a carriage return and a byte-order mark between tokens change nothing', () => {
    const plain = defsOf('type Query { a(x: Int): String }');
    expect(plain.defs).toHaveLength(1);
    for (const sdl of ['type\tQuery\t{\ta(x:\tInt):\tString\t}', 'type Query {\r\n  a(x: Int): String\r\n}\r\n', '\uFEFFtype Query { a(x: Int): String }']) {
      const r = defsOf(sdl);
      expect(r.defs.map((d) => d.verb), JSON.stringify(sdl)).toEqual(plain.defs.map((d) => d.verb));
      expect(r.todo).toEqual(plain.todo);
    }
  });
});

describe('GraphQL parser', () => {
  it('a description string is not read as the keyword or punctuation it spells', () => {
    const r = importGraphql('type Query { "}" a: String "type" b: String }', { ns: 't' });
    expect(r.defs.map((d) => (d.bindings as { graphql?: { field?: string } } | undefined)?.graphql?.field).sort()).toEqual(['a', 'b']);
  });
});

describe('GraphQL introspection', () => {
  it('a schema with no query, mutation or subscription type names none of them', () => {
    expect(Object.keys(fromIntrospection({ __schema: { types: [] } }))).toEqual(['types']);
    expect(Object.keys(fromIntrospection({ __schema: { types: [], queryType: { name: 'Q' } } })).sort()).toEqual(['query', 'types']);
  });
});

describe('GraphQL arguments of a type that cannot be expanded', () => {
  const sdlOf = (args: string) => `type Query { f(${args}): String }`;
  const paramsOf = (sdl: string, limits?: { max_ref_nodes: number }) => importGraphql(sdl, { ns: 't', ...(limits ? { limits } : {}) }).defs[0]!.params;
  it('a non-null argument of an unknown type is required', () => {
    expect(paramsOf(sdlOf('x: Nope!, y: Nope'))).toEqual({ x: { type: 'string' }, y: { type: 'string', required: false } });
  });
  it('a non-null argument of an output type is required', () => {
    expect(paramsOf('type Obj { a: String } type Query { f(x: Obj!, y: Obj): String }')).toEqual({ x: { type: 'string' }, y: { type: 'string', required: false } });
  });
  it('a non-null argument of a recursive input type is required', () => {
    const p = paramsOf('input R { next: R! } type Query { f(x: R!, y: R): String }');
    expect(p['x.next']).toEqual({ type: 'string' });
    expect(p['y.next']).toEqual({ type: 'string', required: false });
  });
  it('a non-null argument met after the node budget is spent is required', () => {
    const p = paramsOf(sdlOf('x: Int!, y: Int!'), { max_ref_nodes: 1 });
    expect(p.y).toEqual({ type: 'string' });
  });
});
