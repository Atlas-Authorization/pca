// Behaviour tests for the suggestion measurement: the corpus parsers, the exact source documents each entry kind is turned into, the
// mapping of imported drafts back to entries, the scoring arithmetic, the Markdown report and the floor check. The importer, the
// suggestion engine and the statistics bound are replaced by recording fakes so every expected value below is exact.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { clopperPearsonUpper } from '@atlasauth/pca-intent';
import { importActions } from '../src/import/pipeline';
import { applySuggestion, suggestWithRules } from '../src/import/suggest';
import { hintTraits } from '../src/effective';
import { CORE_REGISTRY } from '../src/core-traits';
import { DEFAULT_RULES } from '../src/import/rules';
import type { Registry } from '../src/traits';
import {
  LABEL_SHORT, evalSuggest, floorFailures, importCorpus, parseCorpusJsonl, parseHandTsv, realSplit, renderEvalMarkdown,
  type CorpusEntry, type EvalReport, type Floors, type TraitStat,
} from '../src/import/eval';

vi.mock('@atlasauth/pca-intent', async (orig) => ({ ...(await orig<Record<string, unknown>>()), clopperPearsonUpper: vi.fn() }));
vi.mock('../src/import/pipeline', () => ({ importActions: vi.fn() }));
vi.mock('../src/import/suggest', async (orig) => ({ ...(await orig<Record<string, unknown>>()), suggestWithRules: vi.fn(), applySuggestion: vi.fn() }));
vi.mock('../src/effective', async (orig) => ({ ...(await orig<Record<string, unknown>>()), hintTraits: vi.fn() }));

const imp = vi.mocked(importActions);
const E = (o: Partial<CorpusEntry> & { id: string }): CorpusEntry => ({ src: 'hand', kind: 'mcp', name: o.id, params: [], labels: [], description: '', ...o });
const LIMITS = { max_ops: 50_000, max_nodes: 20_000_000, max_bytes: 200_000_000 };

beforeEach(() => { vi.clearAllMocks(); imp.mockReset(); });

describe('parseHandTsv', () => {
  const row = (...c: string[]): string => c.join('\t');
  it('turns each row into an entry with a sequential id, expanded labels, params and an openapi method and path', () => {
    const text = [
      '# a comment',
      '',
      '   ',
      row('openapi', 'listPets', 'GET /pets/{id}', 'id:string,limit:integer', 'money,destr', 'Lists pets'),
      '# another comment',
      row('mcp', 'tool', '-', '-', '-', 'does a thing'),
      row('openapi', 'odd', 'POST /a b', 'x:array', 'pii,pub,money_moving', 'Spaced path', 'ignored seventh column'),
    ].join('\n');
    expect(parseHandTsv(text)).toStrictEqual([
      { id: 'hand-0001', src: 'hand', kind: 'openapi', name: 'listPets', params: ['id:string', 'limit:integer'], labels: ['money_moving', 'destructive'], description: 'Lists pets', method: 'GET', path: '/pets/{id}' },
      { id: 'hand-0002', src: 'hand', kind: 'mcp', name: 'tool', params: [], labels: [], description: 'does a thing' },
      { id: 'hand-0003', src: 'hand', kind: 'openapi', name: 'odd', params: ['x:array'], labels: ['pii_access', 'public_exposure', 'money_moving'], description: 'Spaced path', method: 'POST', path: '/a b' },
    ]);
  });
  it('expands every short label name and pads the id to four digits', () => {
    const lines = Object.keys(LABEL_SHORT).map((k) => row('mcp', `n_${k}`, '-', '-', k, 'd'));
    const out = parseHandTsv(lines.join('\n'));
    Object.keys(LABEL_SHORT).forEach((k, i) => {
      expect(out[i]!.labels).toEqual([LABEL_SHORT[k]]);
      expect(out[i]!.id).toBe(`hand-${String(i + 1).padStart(4, '0')}`);
    });
    expect(out[19]!.id).toBe('hand-0020');
  });
  it('refuses a row with fewer than six columns, quoting at most its first 80 characters, and accepts exactly six', () => {
    const five = ['mcp', 'x'.repeat(100), '-', '-', '-'].join('\t');
    expect(() => parseHandTsv(five)).toThrowError(new Error(`hand corpus line needs 6 columns: ${five.slice(0, 80)}`));
    expect(() => parseHandTsv(row('mcp', 'x', '-', '-', '-', ''))).not.toThrow();
  });
  it('refuses an unknown label by name', () => {
    expect(() => parseHandTsv(row('mcp', 'tool', '-', '-', 'bogus', 'd'))).toThrowError(new Error("unknown label 'bogus' in tool"));
  });
});

describe('parseCorpusJsonl', () => {
  it('parses one entry per non-blank line', () => {
    expect(parseCorpusJsonl('{"id":"a"}\n\n   \n{"id":"b"}\n')).toEqual([{ id: 'a' }, { id: 'b' }]);
    expect(parseCorpusJsonl('')).toEqual([]);
  });
});

describe('realSplit', () => {
  const ref = (spec: string | undefined): 'tune' | 'holdout' => {
    let h = 2166136261n;
    for (const ch of spec ?? '') h = ((h ^ BigInt(ch.charCodeAt(0))) * 16777619n) & 0xffffffffn;
    return (h >> 7n) % 2n === 0n ? 'tune' : 'holdout';
  };
  it('is FNV-1a over the code units, bit 7 of the hash decides, and a missing spec hashes as the empty string', () => {
    const specs = ['', 'a', 'b', 'stripe', 'discord', 'github', 'twilio', 'x-ray', 'Zeta', 'spec/with/slash', 'ünï', 'long-specification-name-number-one'];
    for (let i = 0; i < 60; i++) specs.push(`spec-${i}`, String.fromCharCode(97 + (i % 26)).repeat(1 + (i % 7)));
    for (const s of specs) expect(realSplit(s), s).toBe(ref(s));
    expect(realSplit(undefined)).toBe(ref(''));
    expect(realSplit(undefined)).toBe('holdout');
    expect(new Set(specs.map(realSplit)).size).toBe(2);
  });
});

describe('importCorpus: the source document each kind is turned into', () => {
  const run = (entries: CorpusEntry[]) => { imp.mockReturnValue({ defs: [], todo: [] } as never); importCorpus(entries); return imp.mock.calls; };

  it('hands every group to the importer with the corpus namespace and the large limits', () => {
    const calls = run([E({ id: 'a', kind: 'mcp', spec: 's1' }), E({ id: 'b', kind: 'mcp', spec: 's2' }), E({ id: 'c', kind: 'mcp', spec: 's1' }), E({ id: 'd', kind: 'mcp' }), E({ id: 'e', kind: 'graphql' })]);
    expect(calls.map((c) => c[0])).toEqual(['mcp', 'mcp', 'mcp', 'graphql']);
    expect(calls.map((c) => (c[1] as { name: string }[]).map?.((t) => t.name))).toEqual([['a', 'c'], ['b'], ['d'], undefined]);
    for (const c of calls) expect(c[2]).toEqual({ ns: 'corpus', limits: LIMITS });
  });

  it('builds an MCP tool list with a JSON schema per parameter', () => {
    const calls = run([E({ id: 'one', name: 'n', description: 'd', params: ['a:string', 'b:integer', 'c:number', 'd:boolean', 'e:array', 'f:string:date-time', 'g:integer:int64', 'h:string:x:y'] })]);
    expect(calls).toHaveLength(1);
    expect(calls[0]![0]).toBe('mcp');
    expect(calls[0]![1]).toEqual([{
      name: 'n', description: 'd',
      inputSchema: {
        type: 'object',
        properties: {
          a: { type: 'string' }, b: { type: 'integer' }, c: { type: 'number' }, d: { type: 'boolean' }, e: { type: 'array', items: { type: 'string' } },
          f: { type: 'string', format: 'date-time' }, g: { type: 'integer', format: 'int64' }, h: { type: 'string', format: 'x:y' },
        },
      },
    }]);
  });

  it('only reads a type that is lowercase letters, anchored at both ends, and defaults anything else to string', () => {
    const calls = run([E({ id: 'one', params: ['ab:integer', '1:2:x', 'p:integer!', 'q:UPPER', 'r:Integer'] })]);
    expect((calls[0]![1] as { inputSchema: { properties: unknown } }[])[0]!.inputSchema.properties).toEqual({
      ab: { type: 'integer' }, '1': { type: 'string' }, p: { type: 'string' }, q: { type: 'string' }, r: { type: 'string' },
    });
  });

  it('builds an OpenAPI document: operation ids, summaries, path and query parameters, and a JSON body only for post, put and patch', () => {
    const calls = run([
      E({ id: 'a', kind: 'openapi', method: 'POST', path: '/pets/{id}', name: 'addPet', description: 'Add', params: ['id:string', 'n:integer:int32'] }),
      E({ id: 'b', kind: 'openapi', method: 'GET', path: '/pets/{id}', name: '', description: '', params: ['id:string', 'q:boolean'] }),
      E({ id: 'c', kind: 'openapi', path: '/', name: 'root' }),
      E({ id: 'd', kind: 'openapi', method: 'put', path: '/x/{a}/{b}', name: 'put', description: 'P' }),
      E({ id: 'e', kind: 'openapi', method: 'PATCH', path: '/y', name: 'p', params: ['z:array'] }),
      E({ id: 'f', kind: 'openapi', method: 'DELETE', path: '/y', name: 'd', params: ['k:string'] }),
      E({ id: 'g', kind: 'openapi', name: 'nopath' }),
    ]);
    expect(calls).toHaveLength(1);
    expect(calls[0]![0]).toBe('openapi');
    const idParam = { name: 'id', in: 'path', required: true, schema: { type: 'string' } };
    expect(calls[0]![1]).toStrictEqual({
      openapi: '3.0.3',
      info: { title: 'corpus', version: '1' },
      paths: {
        '/pets/{id}': {
          post: {
            operationId: 'addPet', summary: 'Add', parameters: [idParam],
            requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { id: { type: 'string' }, n: { type: 'integer', format: 'int32' } }, required: [] } } } },
          },
          get: { parameters: [idParam, { name: 'q', in: 'query', schema: { type: 'boolean' } }] },
        },
        '/': { get: { operationId: 'root', parameters: [] } },
        '/x/{a}/{b}': {
          put: { operationId: 'put', summary: 'P', parameters: [{ name: 'a', in: 'path', required: true, schema: { type: 'string' } }, { name: 'b', in: 'path', required: true, schema: { type: 'string' } }] },
        },
        '/y': {
          patch: {
            operationId: 'p', parameters: [],
            requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { z: { type: 'array', items: { type: 'string' } } }, required: [] } } } },
          },
          delete: { operationId: 'd', parameters: [{ name: 'k', in: 'query', schema: { type: 'string' } }] },
        },
        undefined: { get: { operationId: 'nopath', parameters: [] } },
      },
    });
  });

  it('builds a GraphQL SDL: read-looking names are queries, the rest mutations, quotes in descriptions become apostrophes', () => {
    const calls = run([
      E({ id: '1', kind: 'graphql', name: 'getUser', description: 'Fetch "a" user', params: ['id:string', 'age:integer'] }),
      E({ id: '2', kind: 'graphql', name: 'createUser', description: 'Make' }),
      E({ id: '3', kind: 'graphql', name: 'tags', description: 'T', params: ['x:array', 'y:boolean', 'z:number'] }),
      E({ id: '4', kind: 'graphql', name: 'ListAll', description: 'L' }),
      E({ id: '5', kind: 'graphql', name: '_hidden', description: 'H' }),
      E({ id: '6', kind: 'graphql', name: '1get', description: 'O' }),
    ]);
    expect(calls[0]![0]).toBe('graphql');
    expect(calls[0]![1]).toBe([
      'type Query {',
      `  "Fetch 'a' user"`, '  getUser(id: String, age: Int): String',
      '  "T"', '  tags(x: [String], y: Boolean, z: String): String',
      '  "L"', '  ListAll: String',
      '}',
      'type Mutation {',
      '  "Make"', '  createUser: String',
      '  "H"', '  _hidden: String',
      '  "O"', '  1get: String',
      '}',
      '',
    ].join('\n'));
  });

  it('leaves out the empty half of a GraphQL SDL', () => {
    expect(run([E({ id: '1', kind: 'graphql', name: 'doIt', description: 'x' })])[0]![1]).toBe('type Mutation {\n  "x"\n  doIt: String\n}\n');
    imp.mockClear();
    expect(run([E({ id: '1', kind: 'graphql', name: 'users', description: 'x', params: ['a:string'] })])[0]![1]).toBe('type Query {\n  "x"\n  users(a: String): String\n}\n');
  });

  it('builds a proto file: one message per rpc, services grouped by first name segment, numbered fields', () => {
    const calls = run([
      E({ id: '1', kind: 'grpc', name: 'Pets/Get', params: ['id:string', 'n:integer', 'f:boolean', 't:array', 'x:number'] }),
      E({ id: '2', kind: 'grpc', name: 'Users/Add', params: ['u:string'] }),
      E({ id: '3', kind: 'grpc', name: 'Pets/Del' }),
    ]);
    expect(calls[0]![0]).toBe('grpc');
    expect(calls[0]![1]).toBe([
      'syntax = "proto3";',
      'package corpus;',
      'message Empty {}',
      'message GetRequest {', '  string id = 1;', '  int64 n = 2;', '  bool f = 3;', '  repeated string t = 4;', '  string x = 5;', '}',
      'message DelRequest {', '', '}',
      'message AddRequest {', '  string u = 1;', '}',
      'service Pets {', '  rpc Get(GetRequest) returns (Empty);', '  rpc Del(DelRequest) returns (Empty);', '}',
      'service Users {', '  rpc Add(AddRequest) returns (Empty);', '}',
      '',
    ].join('\n'));
  });

  it('builds an AsyncAPI document with one publish channel per entry', () => {
    const calls = run([
      E({ id: '1', kind: 'asyncapi', name: 'orders.created', description: 'D', params: ['id:string', 'n:integer'] }),
      E({ id: '2', kind: 'asyncapi', name: 'empty', description: '' }),
    ]);
    expect(calls[0]![0]).toBe('asyncapi');
    expect(calls[0]![1]).toEqual({
      asyncapi: '2.6.0',
      info: { title: 'corpus', version: '1' },
      channels: {
        'orders.created': { publish: { summary: 'D', message: { payload: { type: 'object', properties: { id: { type: 'string' }, n: { type: 'integer' } } } } } },
        empty: { publish: { summary: '', message: { payload: { type: 'object', properties: {} } } } },
      },
    });
  });
});

describe('importCorpus: matching imported drafts back to entries', () => {
  const D = (bindings: Record<string, unknown>) => ({ bindings }) as never;
  it('keys a draft by openapi method and path, operation id, mcp tool, graphql field, grpc service/method or asyncapi channel', () => {
    imp.mockImplementation(((kind: string) => {
      const byKind: Record<string, unknown[]> = {
        openapi: [D({ openapi: { method: 'POST', path: '/x' } }), D({ openapi: { method: 'GET', path: '/y' } }), D({ openapi: { method: 'GET', path: '/not-asked' } })],
        mcp: [D({ mcp: { tool: 'tool' } }), D({ openapi: { operationId: 'byOpId' } }), D({}), D({ mcp: { tool: 'unmatched' } })],
        graphql: [D({ graphql: { field: 'field' } })],
        grpc: [D({ grpc: { service: 'pkg.sub.Svc', method: 'M' } })],
        asyncapi: [D({ asyncapi: { channel: 'chan' } })],
      };
      return { defs: byKind[kind], todo: kind === 'mcp' ? [1, 2] : kind === 'grpc' ? [3] : [] };
    }) as never);
    const entries = [
      E({ id: 'oa1', kind: 'openapi', method: 'post', path: '/x' }),
      E({ id: 'oa2', kind: 'openapi', path: '/y' }),
      E({ id: 'oa3', kind: 'openapi', method: 'GET', path: '/missing' }),
      E({ id: 'm1', kind: 'mcp', name: 'tool' }),
      E({ id: 'm2', kind: 'mcp', name: 'byOpId' }),
      E({ id: 'm3', kind: 'mcp', name: '' }),
      E({ id: 'm4', kind: 'mcp', name: 'absent' }),
      E({ id: 'g1', kind: 'graphql', name: 'field' }),
      E({ id: 'r1', kind: 'grpc', name: 'Svc/M' }),
      E({ id: 'a1', kind: 'asyncapi', name: 'chan' }),
    ];
    const r = importCorpus(entries);
    expect([...r.defs.keys()]).toEqual(['oa1', 'oa2', 'm1', 'm2', 'm3', 'g1', 'r1', 'a1']);
    expect(r.defs.get('oa1')).toBe(imp.mock.results[0]!.value.defs[0]);
    expect(r.defs.get('oa2')).toBe(imp.mock.results[0]!.value.defs[1]);
    expect(r.defs.get('m3')).toBe(imp.mock.results[1]!.value.defs[2]);
    expect(r.todo).toBe(3);
  });
  it('is empty for no entries', () => {
    imp.mockReturnValue({ defs: [], todo: [] } as never);
    const r = importCorpus([]);
    expect(r.defs.size).toBe(0);
    expect(r.todo).toBe(0);
    expect(imp).not.toHaveBeenCalled();
  });
});

describe('evalSuggest', () => {
  const U = (k: number, n: number, a: number): number => k / 100 + n / 1000 + a / 10;
  const reg = (): Registry => {
    const implies: Record<string, string[]> = { a: ['pca.b'], b: [], c: [], d: [], e: [], f: [], unreviewed: [], irreversible: [] };
    return { traits: new Map(Object.entries(implies).map(([k, v]) => [`pca.${k}`, { id: `pca.${k}`, implies: v }])) } as unknown as Registry;
  };
  const store = new Map<string, { hints: string[]; sug: { traits: string[]; fired: string[] } }>();
  const def = (id: string, hints: string[], traits: string[]) => store.set(id, { hints, sug: { traits, fired: [`R-${id}`] } });
  const setup = (): void => {
    store.clear();
    imp.mockImplementation((() => ({ defs: [...store.entries()].map(([id, v]) => ({ bindings: { mcp: { tool: id } }, ...v })), todo: [] })) as never);
    vi.mocked(suggestWithRules).mockImplementation(((d: { sug: unknown }) => d.sug) as never);
    vi.mocked(applySuggestion).mockImplementation(((d: { hints: string[] }, s: { traits: string[] }, by: unknown) => ({ ...d, hints: [...d.hints, ...s.traits], by })) as never);
    vi.mocked(hintTraits).mockImplementation(((d: { hints: string[] }) => d.hints) as never);
    vi.mocked(clopperPearsonUpper).mockImplementation(U);
  };
  const stat = (trait: string, positives: number, predicted: number, tp: number, fp: number, fn: number, precision: number | null, recall: number | null, rl: [number, number] | null, pl: [number, number] | null, alpha = 0.05): TraitStat => ({
    trait, positives, predicted, tp, fp, fn, precision, recall,
    recall_lower: rl ? 1 - U(rl[0], rl[1], alpha) : null,
    precision_lower: pl ? 1 - U(pl[0], pl[1], alpha) : null,
  });
  const entries = [
    E({ id: 'e1', src: 'hand', labels: ['a', 'b'] }),
    E({ id: 'e2', src: 'hand', labels: ['a', 'e'] }),
    E({ id: 'e3', src: 'hand', labels: ['c'] }),
    E({ id: 'e4', src: 'real', spec: 'stripe', labels: ['b'] }),
    E({ id: 'e5', src: 'real', spec: 'discord', labels: [] }),
    E({ id: 'e6', src: 'syn', labels: ['a'] }),
  ];
  const fill = (): void => {
    def('e1', [], ['pca.a']);
    def('e2', [], []);
    def('e3', ['pca.unreviewed', 'pca.c'], []);
    def('e5', ['pca.f'], ['pca.b']);
    def('e6', ['pca.a'], []);
  };
  const sum = (s: TraitStat[]) => s.map((x) => [x.trait, x.tp, x.fp, x.fn]);

  it('scores what a reviewer sees (the closure of declared and suggested traits, minus unreviewed) against the labels', () => {
    setup(); fill();
    const r = evalSuggest(entries, { registry: reg() });
    expect(r.alpha).toBe(0.05);
    expect(r.entries).toBe(6);
    expect(r.mapped).toBe(5);
    expect(r.rules_version).toBe(DEFAULT_RULES.version);
    expect(r.flagged).toEqual([
      stat('a', 3, 2, 2, 0, 1, 1, 2 / 3, [1, 3], [0, 2]),
      stat('b', 2, 3, 1, 2, 1, 1 / 3, 1 / 2, [1, 2], [2, 3]),
      stat('c', 1, 1, 1, 0, 0, 1, 1, [0, 1], [0, 1]),
      stat('e', 1, 0, 0, 0, 1, null, 0, [1, 1], null),
      stat('f', 0, 1, 0, 1, 0, 0, null, null, [1, 1]),
    ]);
  });

  it('scores only what the suggestion engine added', () => {
    setup(); fill();
    const r = evalSuggest(entries, { registry: reg() });
    expect(r.suggested).toEqual([
      stat('a', 3, 1, 1, 0, 2, 1, 1 / 3, [2, 3], [0, 1]),
      // e5 is the only entry the engine suggested b for, and it is not labeled b (e1 and e4 are): no hit, one false alarm, two misses
      stat('b', 2, 1, 0, 1, 2, 0, 0, [2, 2], [1, 1]),
      stat('c', 1, 0, 0, 0, 1, null, 0, [1, 1], null),
      stat('e', 1, 0, 0, 0, 1, null, 0, [1, 1], null),
    ]);
  });

  it('splits by source: hand, syn, the real set as a whole and its tune and hold-out halves, sorted', () => {
    setup(); fill();
    const r = evalSuggest(entries, { registry: reg() });
    expect(Object.keys(r.by_source)).toEqual(['hand', 'real', 'real/holdout', 'real/tune', 'syn']);
    expect(Object.values(r.by_source).map((v) => v.entries)).toEqual([3, 2, 1, 1, 1]);
    expect(sum(r.by_source['hand']!.flagged)).toEqual([['a', 1, 0, 1], ['b', 1, 0, 0], ['c', 1, 0, 0], ['e', 0, 0, 1]]);
    expect(sum(r.by_source['real']!.flagged)).toEqual([['b', 0, 1, 1], ['f', 0, 1, 0]]);
    expect(sum(r.by_source['real/holdout']!.flagged)).toEqual([['b', 0, 1, 0], ['f', 0, 1, 0]]);
    expect(sum(r.by_source['real/tune']!.flagged)).toEqual([['b', 0, 0, 1]]);
    expect(sum(r.by_source['syn']!.flagged)).toEqual([['a', 1, 0, 0], ['b', 0, 1, 0]]);
    expect(r.by_source['syn']!.flagged[0]).toEqual(stat('a', 1, 1, 1, 0, 0, 1, 1, [0, 1], [0, 1]));
  });

  it('has no aggregate real source when no entry is real', () => {
    setup(); fill();
    const r = evalSuggest(entries.filter((e) => e.src !== 'real'), { registry: reg() });
    expect(Object.keys(r.by_source)).toEqual(['hand', 'syn']);
    expect(r.entries).toBe(4);
    expect(r.mapped).toBe(4);
  });

  it('runs the given rules with the given registry, records what fired, and uses the given alpha', () => {
    setup(); fill();
    const registry = reg();
    const rules = { v: 1, kind: 'pca-suggest-rules', version: '9.9.9', rules: [] } as never;
    const r = evalSuggest(entries, { rules, registry, alpha: 0.01 });
    expect(r.alpha).toBe(0.01);
    expect(r.rules_version).toBe('9.9.9');
    expect(r.flagged[0]).toEqual(stat('a', 3, 2, 2, 0, 1, 1, 2 / 3, [1, 3], [0, 2], 0.01));
    const d1 = vi.mocked(suggestWithRules).mock.calls[0]!;
    expect(d1[1]).toBe(rules);
    expect(d1[2]).toBe(registry);
    expect(vi.mocked(suggestWithRules)).toHaveBeenCalledTimes(5);
    const a1 = vi.mocked(applySuggestion).mock.calls[0]!;
    expect(a1[1]).toEqual({ traits: ['pca.a'], fired: ['R-e1'] });
    expect(a1[2]).toEqual({ rules: { version: '9.9.9', digest: '', fired: ['R-e1'] } });
    expect(vi.mocked(clopperPearsonUpper)).toHaveBeenCalledWith(1, 3, 0.01);
    expect(vi.mocked(clopperPearsonUpper)).toHaveBeenCalledWith(0, 2, 0.01);
  });

  it('defaults to the built-in rules, the core registry and alpha 0.05', () => {
    setup();
    evalSuggest([E({ id: 'only' })]);
    expect(vi.mocked(suggestWithRules)).not.toHaveBeenCalled();
    def('only', [], []);
    // no pre-registered traits fire, and every core trait the (fake) engine adds must be known to the core registry
    store.set('only', { hints: [], sug: { traits: ['pca.bulk'], fired: [] } });
    const r = evalSuggest([E({ id: 'only', labels: ['bulk'] })]);
    const call = vi.mocked(suggestWithRules).mock.calls[0]!;
    expect(call[1]).toBe(DEFAULT_RULES);
    expect(call[2]).toBe(CORE_REGISTRY);
    expect(r.alpha).toBe(0.05);
    expect(r.rules_version).toBe(DEFAULT_RULES.version);
    expect(r.flagged.map((s) => s.trait)).toContain('bulk');
    expect(r.flagged.map((s) => s.trait)).not.toContain('unreviewed');
    expect(r.flagged.map((s) => s.trait)).not.toContain('irreversible');
    expect(vi.mocked(clopperPearsonUpper)).toHaveBeenCalledWith(0, 1, 0.05);
  });

  it('computes the exact precision bound only for 600 flags or fewer', () => {
    setup();
    const many = (n: number): CorpusEntry[] => Array.from({ length: n }, (_, i) => { def(`m${i}`, [], ['pca.c']); return E({ id: `m${i}` }); });
    const at = evalSuggest(many(600), { registry: reg() }).flagged[0]!;
    expect(at.predicted).toBe(600);
    expect(at.precision_lower).toBe(1 - U(600, 600, 0.05));
    const over = evalSuggest(many(601), { registry: reg() }).flagged[0]!;
    expect(over.predicted).toBe(601);
    expect(over.precision_lower).toBeNull();
    expect(over.recall_lower).toBeNull();
    expect(over.precision).toBe(0);
  });
});

describe('renderEvalMarkdown', () => {
  const header = ['| trait | labeled | flagged | recall | recall lower bound | precision | missed | false alarms |', '|---|---:|---:|---:|---:|---:|---:|---:|'];
  const s = (o: Partial<TraitStat>): TraitStat => ({ trait: 't', positives: 0, predicted: 0, tp: 0, fp: 0, fn: 0, precision: null, recall: null, recall_lower: null, precision_lower: null, ...o });
  it('renders the report exactly, with one decimal percentages and a dash for a missing number', () => {
    const r: EvalReport = {
      alpha: 0.05, entries: 12, mapped: 11, rules_version: '2.1.0',
      flagged: [s({ trait: 'money_moving', positives: 10, predicted: 8, fn: 3, fp: 1, precision: 0.875, recall: 0.7, recall_lower: 0.4567 }), s({ trait: 'bulk', positives: 2, predicted: 0, fn: 2 })],
      suggested: [s({ trait: 'destructive', positives: 4, predicted: 5, fn: 0, fp: 2, precision: 1, recall: 1, recall_lower: 0.5 })],
      by_source: { hand: { entries: 7, flagged: [s({ trait: 'pii_access', positives: 1, predicted: 1, precision: 0, recall: 0.0049, recall_lower: 0 })] }, syn: { entries: 5, flagged: [] } },
    };
    expect(renderEvalMarkdown(r)).toBe([
      '# Suggestion rules 2.1.0: measured on a labeled corpus',
      '',
      '12 labeled operations (11 imported). Lower bounds are one-sided exact Clopper-Pearson at alpha = 0.05.',
      'These are heuristic numbers on a reviewed corpus. They are not a safety guarantee: an unreviewed action is always held at the most restrictive floor.',
      '',
      '## What a reviewer is shown (importer facts plus suggestions)',
      '',
      ...header,
      '| money_moving | 10 | 8 | 70.0% | 45.7% | 87.5% | 3 | 1 |',
      '| bulk | 2 | 0 | - | - | - | 2 | 0 |',
      '',
      '## What the suggestion rules added',
      '',
      ...header,
      '| destructive | 4 | 5 | 100.0% | 50.0% | 100.0% | 0 | 2 |',
      '',
      '## Source: hand (7 operations)',
      '',
      ...header,
      '| pii_access | 1 | 1 | 0.5% | 0.0% | 0.0% | 0 | 0 |',
      '',
      '## Source: syn (5 operations)',
      '',
      ...header,
      '',
    ].join('\n'));
  });
});

describe('floorFailures', () => {
  const st = (trait: string, positives: number, recall_lower: number | null): TraitStat => ({ trait, positives, predicted: 10, tp: 0, fp: 0, fn: 0, precision: null, recall: null, recall_lower, precision_lower: null });
  const rep = (o: Partial<EvalReport> & { by_source?: EvalReport['by_source'] } = {}): EvalReport => ({
    alpha: 0.05, entries: 100, mapped: 100, rules_version: '1', flagged: [], suggested: [],
    by_source: { 'real/holdout': { entries: 50, flagged: [st('money_moving', 100, 0.6)] }, syn: { entries: 10, flagged: [st('money_moving', 50, 0.9)] } }, ...o,
  });
  const f: Floors = { v: 2, alpha: 0.05, real: { min_entries: 50, min_positives: { money_moving: 100 }, recall_lower: { money_moving: 0.6 } }, regression: { recall_lower: { money_moving: 0.9 } } };

  it('passes exactly at every boundary', () => {
    expect(floorFailures(rep(), f)).toEqual([]);
  });
  it('fails one short of each boundary', () => {
    expect(floorFailures(rep({ by_source: { ...rep().by_source, 'real/holdout': { entries: 49, flagged: [st('money_moving', 100, 0.6)] } } }), f)).toEqual(['the real-spec hold-out has 49 operations, fewer than the required 50']);
    expect(floorFailures(rep({ by_source: { ...rep().by_source, 'real/holdout': { entries: 50, flagged: [st('money_moving', 99, 0.6)] } } }), f)).toEqual(['money_moving: 99 real labeled positives, fewer than the 100 the floor needs']);
    expect(floorFailures(rep({ by_source: { ...rep().by_source, syn: { entries: 10, flagged: [st('money_moving', 50, 0.89)] } } }), f)).toEqual(['money_moving: regression-set recall lower bound 89.0% is below 90.0%']);
  });
  it('reports a missing hold-out as zero operations, and its traits as having zero positives', () => {
    const r = rep({ by_source: { syn: { entries: 10, flagged: [st('money_moving', 50, 0.9)] } } });
    expect(floorFailures(r, f)).toEqual([
      'the real-spec hold-out has 0 operations, fewer than the required 50',
      'money_moving: 0 real labeled positives, fewer than the 100 the floor needs',
    ]);
  });
  it('treats a trait without a recorded positive minimum as needing none, but still requires it to be present', () => {
    const g: Floors = { ...f, real: { ...f.real, min_positives: {} } };
    expect(floorFailures(rep(), g)).toEqual([]);
    const r = rep({ by_source: { ...rep().by_source, 'real/holdout': { entries: 50, flagged: [] } } });
    expect(floorFailures(r, g)).toEqual(['money_moving: 0 real labeled positives, fewer than the 0 the floor needs']);
  });
  it('names a null recall bound with a dash, for the hold-out and for the regression set', () => {
    const r = rep({ by_source: { 'real/holdout': { entries: 50, flagged: [st('money_moving', 100, null)] }, syn: { entries: 10, flagged: [st('money_moving', 50, null)] } } });
    expect(floorFailures(r, f)).toEqual([
      'money_moving: hold-out recall lower bound - is below the recorded floor 60.0%',
      'money_moving: regression-set recall lower bound - is below 90.0%',
    ]);
  });
  it('reports a missing synthetic set or trait as a dash, and every failure in order', () => {
    const noSyn = rep({ by_source: { 'real/holdout': { entries: 50, flagged: [st('money_moving', 100, 0.6)] } } });
    expect(floorFailures(noSyn, f)).toEqual(['money_moving: regression-set recall lower bound - is below 90.0%']);
    const noTrait = rep({ by_source: { ...rep().by_source, syn: { entries: 10, flagged: [] } } });
    expect(floorFailures(noTrait, f)).toEqual(['money_moving: regression-set recall lower bound - is below 90.0%']);
    const all = rep({ mapped: 97, by_source: { 'real/holdout': { entries: 3, flagged: [st('money_moving', 5, 0.1)] }, syn: { entries: 10, flagged: [st('money_moving', 50, 0.1)] } } });
    expect(floorFailures(all, f)).toEqual([
      'the real-spec hold-out has 3 operations, fewer than the required 50',
      '3 corpus operations were not imported',
      'money_moving: 5 real labeled positives, fewer than the 100 the floor needs',
      'money_moving: regression-set recall lower bound 10.0% is below 90.0%',
    ]);
  });
  it('checks each floored trait on its own', () => {
    const g: Floors = { ...f, real: { min_entries: 50, min_positives: { money_moving: 1, bulk: 1 }, recall_lower: { money_moving: 0.6, bulk: 0.8 } } };
    const r = rep({ by_source: { 'real/holdout': { entries: 50, flagged: [st('money_moving', 100, 0.7), st('bulk', 100, 0.79)] }, syn: { entries: 10, flagged: [st('money_moving', 50, 0.95)] } } });
    expect(floorFailures(r, g)).toEqual(['bulk: hold-out recall lower bound 79.0% is below the recorded floor 80.0%']);
  });
});
