/** 0.4.2 mutation kills (rule 14): reversibility projections, MCP / OpenAPI importers and shape checks, pinned with literal expectations. */
import { describe, expect, it } from 'vitest';
import {
  type ActionVerbDecl,
  type JsonSchemaLike,
  actionSchemaShapeError,
  draftSchemaFromMcpTools,
  draftSchemaFromOpenApi,
  reversibilityFromMcpHints,
  reversibilityOf,
  verbReversibility,
} from './action-schema';

const SITE = { site: 'https://s.example', aud: 's.example', version: '1' };
const P = (type: string, extra: Record<string, unknown> = {}) => ({ type, semantic: 's', sensitivity: 'free', ...extra });

describe('reversibilityOf / verbReversibility', () => {
  const by = (map: Record<string, string>, def?: string, param = 'action.params.k'): ActionVerbDecl =>
    ({ verb: 'v', kind: 'write', params: { [param]: P('string', { values: ['a', 'b'] }) as never }, reversibility_by: { param, map, ...(def ? { default: def } : {}) } }) as never;
  it('plain verbs: declared, else read -> reversible, write -> irreversible', () => {
    expect(reversibilityOf({ verb: 'v', kind: 'read', params: {} }, {})).toBe('reversible');
    expect(reversibilityOf({ verb: 'v', kind: 'write', params: {} }, {})).toBe('irreversible');
    expect(reversibilityOf({ verb: 'v', kind: 'write', params: {}, reversibility: 'rate_limited' }, {})).toBe('rate_limited');
    expect(verbReversibility({ verb: 'v', kind: 'read', params: {} })).toBe('reversible');
    expect(verbReversibility({ verb: 'v', kind: 'write', params: {} })).toBe('irreversible');
    expect(verbReversibility({ verb: 'v', kind: 'read', params: {}, reversibility: 'rate_limited' })).toBe('rate_limited');
  });
  it('value-dependent: mapped value wins; unmapped / absent / non-keyable values use default, else irreversible', () => {
    const v = by({ a: 'reversible', b: 'rate_limited' }, 'rate_limited');
    expect(reversibilityOf(v, { k: 'a' })).toBe('reversible');
    expect(reversibilityOf(v, { k: 'b' })).toBe('rate_limited');
    expect(reversibilityOf(v, { k: 'zzz' })).toBe('rate_limited');
    expect(reversibilityOf(v, {})).toBe('rate_limited');
    expect(reversibilityOf(v, { k: ['a'] })).toBe('rate_limited');
    const noDef = by({ a: 'reversible' });
    expect(reversibilityOf(noDef, { k: 'zzz' })).toBe('irreversible');
    expect(reversibilityOf(noDef, {})).toBe('irreversible');
  });
  it('keys: booleans and safe integers are keyed by their string form; other numbers are not keyable', () => {
    const v: ActionVerbDecl = { verb: 'v', kind: 'write', params: {}, reversibility_by: { param: 'action.params.k', map: { true: 'reversible', '5': 'rate_limited', '1.5': 'reversible', NaN: 'reversible' }, default: 'irreversible' } };
    expect(reversibilityOf(v, { k: true })).toBe('reversible');
    expect(reversibilityOf(v, { k: 5 })).toBe('rate_limited');
    expect(reversibilityOf(v, { k: 1.5 })).toBe('irreversible');
    expect(reversibilityOf(v, { k: Number.NaN })).toBe('irreversible');
    expect(reversibilityOf(v, { k: -0 })).toBe('irreversible');
    expect(reversibilityOf(v, { k: null })).toBe('irreversible');
  });
  it('an inherited parameter is not a parameter', () => {
    const v = by({ a: 'reversible' }, 'rate_limited');
    expect(reversibilityOf(v, Object.create({ k: 'a' }))).toBe('rate_limited');
  });
  it('conservative projection: the max over the map, plus the default unless the map covers the whole domain', () => {
    expect(verbReversibility(by({ a: 'reversible', b: 'rate_limited' }, 'irreversible'))).toBe('rate_limited'); // covered enum
    expect(verbReversibility(by({ a: 'reversible' }, 'rate_limited'))).toBe('rate_limited'); // b uncovered -> default
    expect(verbReversibility(by({ a: 'reversible' }))).toBe('irreversible'); // uncovered, no default
    expect(verbReversibility(by({ a: 'reversible', b: 'reversible' }))).toBe('reversible');
    const bool: ActionVerbDecl = { verb: 'v', kind: 'write', params: { 'action.params.k': P('boolean') as never }, reversibility_by: { param: 'action.params.k', map: { true: 'reversible', false: 'reversible' } } };
    expect(verbReversibility(bool)).toBe('reversible');
    expect(verbReversibility({ ...bool, reversibility_by: { param: 'action.params.k', map: { true: 'reversible' } } })).toBe('irreversible');
    const int: ActionVerbDecl = { verb: 'v', kind: 'write', params: { 'action.params.k': P('integer') as never }, reversibility_by: { param: 'action.params.k', map: { '1': 'reversible' }, default: 'rate_limited' } };
    expect(verbReversibility(int)).toBe('rate_limited');
    const undeclared: ActionVerbDecl = { verb: 'v', kind: 'write', params: {}, reversibility_by: { param: 'action.params.k', map: { a: 'reversible' }, default: 'rate_limited' } };
    expect(verbReversibility(undeclared)).toBe('rate_limited');
    const strNoValues: ActionVerbDecl = { verb: 'v', kind: 'write', params: { 'action.params.k': P('string') as never }, reversibility_by: { param: 'action.params.k', map: { a: 'reversible' }, default: 'rate_limited' } };
    expect(verbReversibility(strNoValues)).toBe('rate_limited');
    expect(verbReversibility(by({ a: 'reversible', b: 'irreversible' }, 'reversible'))).toBe('irreversible');
  });
});

describe('reversibilityFromMcpHints', () => {
  it('read-only -> read/reversible; destructive -> write/rate_limited; otherwise write/reversible; read-only wins', () => {
    expect(reversibilityFromMcpHints({ readOnlyHint: true })).toEqual({ kind: 'read', atLeast: 'reversible' });
    expect(reversibilityFromMcpHints({ readOnlyHint: true, destructiveHint: true })).toEqual({ kind: 'read', atLeast: 'reversible' });
    expect(reversibilityFromMcpHints({ destructiveHint: true })).toEqual({ kind: 'write', atLeast: 'rate_limited' });
    expect(reversibilityFromMcpHints({ readOnlyHint: false, destructiveHint: false })).toEqual({ kind: 'write', atLeast: 'reversible' });
    expect(reversibilityFromMcpHints(undefined)).toEqual({ kind: 'write', atLeast: 'reversible' });
    expect(reversibilityFromMcpHints({ readOnlyHint: 'yes' as never, destructiveHint: 1 as never })).toEqual({ kind: 'write', atLeast: 'reversible' });
  });
});

describe('draftSchemaFromMcpTools', () => {
  it('maps every JSON-Schema shape, sorts parameters and verbs by UTF-8, and lists the todos', () => {
    const d = draftSchemaFromMcpTools(
      [
        {
          name: 'b_tool',
          description: 'x'.repeat(2000),
          inputSchema: {
            properties: {
              n: { type: 'integer', minimum: 1, maximum: 9, 'x-pca-semantic': 'money.amount', 'x-pca-unit': 'u', 'x-pca-accumulates-into': ['u'], description: 'amt' },
              frac: { type: 'integer', minimum: 1.5, maximum: 2.5 },
              flag: { type: 'boolean', 'x-pca-semantic': 'f', 'x-pca-sensitivity': 'free' },
              day: { type: 'string', format: 'date', 'x-pca-semantic': 'd' },
              s: { type: 'string', enum: ['x', 'y'], maxLength: 10, 'x-pca-semantic': 'q' },
              s2: { type: 'string', enum: ['x', 1], maxLength: 0, 'x-pca-semantic': 'q' },
              s3: { type: ['null', 'string'], maxLength: 2.5, 'x-pca-semantic': 'q' },
              set: { type: 'array', uniqueItems: true, items: { enum: ['a', 'b'] }, minItems: 1, maxItems: 2, 'x-pca-semantic': 'q' },
              set2: { type: 'array', uniqueItems: true, items: { enum: ['a', 'b'] }, minItems: 0.5, maxItems: 0.5, 'x-pca-semantic': 'q' },
              arr: { type: 'array', items: { type: 'integer' }, minItems: 0, maxItems: 3, 'x-pca-semantic': 'q' },
              arr2: { type: 'array', items: { type: ['integer', 'null'] }, uniqueItems: true, 'x-pca-semantic': 'q' },
              arr3: { type: 'array', 'x-pca-semantic': 'q' },
              arr4: { type: 'array', items: { type: 'string' }, maxItems: 1.5, minItems: 1.5, 'x-pca-semantic': 'q' },
              obj: { type: 'object', 'x-pca-semantic': 'q' },
              'bad-name': { type: 'string' },
              ['x'.repeat(65)]: { type: 'string' },
            },
            required: ['n'],
          },
        },
        { name: 'a_tool', annotations: { readOnlyHint: true }, inputSchema: { properties: {} } },
        { name: 'noschema', annotations: { destructiveHint: true } },
      ],
      { ...SITE, verbPrefix: 'p.' },
    );
    expect(d.schema.verbs.map((v) => v.verb)).toEqual(['p.a_tool', 'p.b_tool', 'p.noschema']);
    const [a, b, c] = d.schema.verbs;
    expect(a).toEqual({ verb: 'p.a_tool', kind: 'read', params: {}, reversibility: 'reversible', mcp: { tool: 'a_tool' } });
    expect(c).toEqual({ verb: 'p.noschema', kind: 'write', params: {}, reversibility: 'irreversible', mcp: { tool: 'noschema' } });
    expect(b!.description).toBe('x'.repeat(1024));
    expect(b!.reversibility).toBe('irreversible');
    expect(Object.keys(b!.params)).toEqual(['action.params.arr', 'action.params.arr2', 'action.params.arr3', 'action.params.arr4', 'action.params.day', 'action.params.flag', 'action.params.frac', 'action.params.n', 'action.params.obj', 'action.params.s', 'action.params.s2', 'action.params.s3', 'action.params.set', 'action.params.set2']);
    const p = b!.params;
    expect(p['action.params.n']).toEqual({ type: 'integer', semantic: 'money.amount', sensitivity: 'material', description: 'amt', min: 1, max: 9, unit: 'u', accumulates_into: ['u'] });
    expect(p['action.params.frac']).toEqual({ type: 'integer', semantic: 'unknown', sensitivity: 'material', required: false });
    expect(p['action.params.flag']).toEqual({ type: 'boolean', semantic: 'f', sensitivity: 'free', required: false });
    expect(p['action.params.day']).toEqual({ type: 'date', semantic: 'd', sensitivity: 'material', required: false });
    expect(p['action.params.s']).toEqual({ type: 'string', semantic: 'q', sensitivity: 'material', required: false, values: ['x', 'y'], max_len: 10 });
    expect(p['action.params.s2']).toEqual({ type: 'string', semantic: 'q', sensitivity: 'material', required: false });
    expect(p['action.params.s3']).toEqual({ type: 'string', semantic: 'q', sensitivity: 'material', required: false });
    expect(p['action.params.set']).toEqual({ type: 'set', semantic: 'q', sensitivity: 'material', required: false, values: ['a', 'b'], min_items: 1, max_items: 2 });
    expect(p['action.params.set2']).toEqual({ type: 'set', semantic: 'q', sensitivity: 'material', required: false, values: ['a', 'b'] });
    expect(p['action.params.arr']).toEqual({ type: 'array', semantic: 'q', sensitivity: 'material', required: false, items: 'integer', max_items: 3, min_items: 0 });
    expect(p['action.params.arr2']).toEqual({ type: 'array', semantic: 'q', sensitivity: 'material', required: false, items: 'integer' });
    expect(p['action.params.arr3']).toEqual({ type: 'array', semantic: 'q', sensitivity: 'material', required: false });
    expect(p['action.params.arr4']).toEqual({ type: 'array', semantic: 'q', sensitivity: 'material', required: false });
    expect(p['action.params.obj']).toEqual({ type: 'string', semantic: 'q', sensitivity: 'material', required: false });
    expect(d.todo).toEqual([
      "b_tool: parameter 'bad-name' is not a schema name ([A-Za-z0-9_]{1,64}); rename it",
      'action.params.frac: semantic type',
      "action.params.obj: type 'object' has no schema representation (declared string; refine or drop)",
      `b_tool: parameter '${'x'.repeat(65)}' is not a schema name ([A-Za-z0-9_]{1,64}); rename it`,
      'p.b_tool: reversibility (drafted irreversible)',
      'p.noschema: reversibility (drafted irreversible)',
    ]);
    expect(d.schema).toMatchObject({ v: 1, kind: 'pca-action-schema', site: 'https://s.example', aud: 's.example', version: '1' });
  });
  it('no prefix, a name that is exactly 64 characters is kept, a type that is only null is unrepresentable', () => {
    const d = draftSchemaFromMcpTools([{ name: 't', inputSchema: { properties: { ['y'.repeat(64)]: { type: 'string', 'x-pca-semantic': 's' }, z: { type: ['null'], 'x-pca-semantic': 's' } } } }], SITE);
    expect(d.schema.verbs[0]!.verb).toBe('t');
    expect(Object.keys(d.schema.verbs[0]!.params)).toEqual([`action.params.${'y'.repeat(64)}`, 'action.params.z']);
    expect(d.todo).toEqual(["action.params.z: type 'undefined' has no schema representation (declared string; refine or drop)", 't: reversibility (drafted irreversible)']);
    expect(actionSchemaShapeError({ ...d.schema, sig: { alg: 'ed25519', kid: 'k', value: 'AA' } }, { signed: true })).toBeNull();
  });
  it('the sort is by UTF-8 bytes, not UTF-16 code units', () => {
    const d = draftSchemaFromMcpTools([{ name: 'z\u{1F600}' }, { name: 'z\uFF21' }, { name: 'a' }], SITE);
    expect(d.schema.verbs.map((v) => v.verb)).toEqual(['a', 'z\uFF21', 'z\u{1F600}']);
  });
});

describe('draftSchemaFromOpenApi', () => {
  const body = (properties: Record<string, JsonSchemaLike>, required?: string[]) => ({ content: { 'application/json': { schema: { properties, ...(required ? { required } : {}) } } } });
  it('verbs per operation: kind from x-pca-kind or GET/HEAD; reversibility; verb names; sorted; todos', () => {
    const d = draftSchemaFromOpenApi(
      {
        paths: {
          '/b': {
            post: { operationId: 'createB', description: 'd'.repeat(1500), requestBody: body({ amt: { type: 'integer', 'x-pca-semantic': 'money.amount' }, 'bad name': { type: 'string' } }, ['amt']) },
            get: { operationId: 'getB' },
            head: { operationId: 'headB' },
            HEAD: { operationId: 'upperHead' },
            GET: { operationId: 'upperGet' },
            put: { operationId: 'putB', 'x-pca-kind': 'read' },
            patch: { operationId: 'patchB', 'x-pca-kind': 'write', 'x-pca-reversibility': 'rate_limited' },
            delete: {} as never,
            options: { operationId: 'optB', 'x-pca-verb': 'custom.verb' },
            trace: null as never,
          },
          '/a': { get: { operationId: 'getA', requestBody: { content: { 'text/plain': {} } } } },
        },
      },
      SITE,
    );
    const byVerb = Object.fromEntries(d.schema.verbs.map((v) => [v.verb, v]));
    expect(d.schema.verbs.map((v) => v.verb)).toEqual(['createB', 'custom.verb', 'getA', 'getB', 'headB', 'patchB', 'putB', 'upperGet', 'upperHead']);
    expect(byVerb.getA).toEqual({ verb: 'getA', kind: 'read', params: {}, reversibility: 'reversible', openapi: { operationId: 'getA' } });
    expect(byVerb.headB!.kind).toBe('read');
    expect(byVerb.upperGet!.kind).toBe('read');
    expect(byVerb.upperHead!.kind).toBe('read');
    expect(byVerb.putB).toMatchObject({ kind: 'read', reversibility: 'reversible' });
    expect(byVerb.patchB).toMatchObject({ kind: 'write', reversibility: 'rate_limited' });
    expect(byVerb['custom.verb']).toEqual({ verb: 'custom.verb', kind: 'write', params: {}, reversibility: 'irreversible', openapi: { operationId: 'optB' } });
    expect(byVerb.createB!.description).toBe('d'.repeat(1024));
    expect(byVerb.createB!.openapi).toEqual({ operationId: 'createB' });
    expect(byVerb.createB!.params).toEqual({ 'action.params.amt': { type: 'integer', semantic: 'money.amount', sensitivity: 'material' } });
    expect(d.todo).toEqual([
      'custom.verb: reversibility (drafted irreversible)', // methods are visited in sorted order: options before post
      "createB: parameter 'bad name' is not a schema name; rename it",
      'createB: reversibility (drafted irreversible)',
    ]);
  });
  it('an operation without an operationId, and no paths at all, produce nothing', () => {
    expect(draftSchemaFromOpenApi({ paths: { '/x': { get: { description: 'd' } } } }, SITE).schema.verbs).toEqual([]);
    expect(draftSchemaFromOpenApi({}, SITE).schema.verbs).toEqual([]);
  });
  it('a parameter name of exactly 64 characters is kept; a missing semantic is a todo per parameter', () => {
    const d = draftSchemaFromOpenApi({ paths: { '/x': { get: { operationId: 'g', requestBody: body({ ['q'.repeat(64)]: { type: 'boolean' } }) } } } }, SITE);
    expect(Object.keys(d.schema.verbs[0]!.params)).toEqual([`action.params.${'q'.repeat(64)}`]);
    expect(d.todo).toEqual([`action.params.${'q'.repeat(64)}: semantic type`]);
  });
});
