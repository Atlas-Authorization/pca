// The source documents the corpus importer builds for GraphQL and gRPC entries: the cases the behaviour tests left open (a name that
// is plain letters, parameter specs with no type or with a colon in a later position, names of two or more characters).
// The importer is replaced by a recording fake, as in eval.mutation.test.ts, so every expected document is exact.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { importActions } from '../src/import/pipeline';
import { importCorpus, type CorpusEntry } from '../src/import/eval';

vi.mock('../src/import/pipeline', () => ({ importActions: vi.fn() }));

const imp = vi.mocked(importActions);
const E = (o: Partial<CorpusEntry> & { id: string }): CorpusEntry => ({ src: 'hand', kind: 'mcp', name: o.id, params: [], labels: [], description: '', ...o });
const run = (entries: CorpusEntry[]) => { imp.mockReturnValue({ defs: [], todo: [] } as never); importCorpus(entries); return imp.mock.calls; };

beforeEach(() => { imp.mockReset(); });

describe('GraphQL document', () => {
  it('a name of plain lowercase letters is a query whether or not it ends in s; one with a capital is a mutation', () => {
    const calls = run([
      E({ id: '1', kind: 'graphql', name: 'user', description: 'd' }),
      E({ id: '2', kind: 'graphql', name: 'users', description: 'd' }),
      E({ id: '3', kind: 'graphql', name: 'updateUser', description: 'd' }),
    ]);
    expect(calls[0]![1]).toBe(['type Query {', '  "d"', '  user: String', '  "d"', '  users: String', '}', 'type Mutation {', '  "d"', '  updateUser: String', '}', ''].join('\n'));
  });
  it('the type of an argument is the letters right after the first colon: a spec with no type or a later colon reads as a string', () => {
    const calls = run([E({ id: '1', kind: 'graphql', name: 'doIt', description: 'd', params: ['a:1:integer', 'plain', 'ab:integer', 'c:boolean'] })]);
    expect(calls[0]![1]).toBe(['type Mutation {', '  "d"', '  doIt(a: String, plai: String, ab: Int, c: Boolean): String', '}', ''].join('\n'));
  });
});

describe('proto document', () => {
  it('the type of a field follows the same rule: a spec with no type or a later colon reads as a string', () => {
    const calls = run([E({ id: '1', kind: 'grpc', name: 'Svc/Do', params: ['a:1:integer', 'plain', 'ab:integer', 'c:boolean', 'd:array'] })]);
    expect(calls[0]![1]).toBe([
      'syntax = "proto3";',
      'package corpus;',
      'message Empty {}',
      'message DoRequest {', '  string a = 1;', '  string plai = 2;', '  int64 ab = 3;', '  bool c = 4;', '  repeated string d = 5;', '}',
      'service Svc {', '  rpc Do(DoRequest) returns (Empty);', '}',
      '',
    ].join('\n'));
  });
});
