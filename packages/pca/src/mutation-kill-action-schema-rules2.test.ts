/** 0.4.2 mutation kills (rule 14), second batch: max-class projection order, null keys, importer edge shapes, wallet-floor ordering. */
import { describe, expect, it } from 'vitest';
import { type ActionVerbDecl, actionSchemaShapeError, draftSchemaFromMcpTools, draftSchemaFromOpenApi, reversibilityOf, verbReversibility, walletFloorOverrides } from './action-schema';

const SITE = { site: 'https://s.example', aud: 's.example', version: '1' };
const P = (type: string, extra: Record<string, unknown> = {}) => ({ type, semantic: 's', sensitivity: 'free', ...extra });

describe('verbReversibility: the maximum does not depend on the order of the map', () => {
  const v = (map: Record<string, string>): ActionVerbDecl =>
    ({ verb: 'v', kind: 'write', params: { 'action.params.k': P('string', { values: ['a', 'b', 'c'] }) as never }, reversibility_by: { param: 'action.params.k', map } }) as never;
  it('a lower class last does not hide a higher one earlier', () => {
    expect(verbReversibility(v({ a: 'irreversible', b: 'reversible', c: 'reversible' }))).toBe('irreversible');
    expect(verbReversibility(v({ a: 'rate_limited', b: 'reversible', c: 'reversible' }))).toBe('rate_limited');
    expect(verbReversibility(v({ a: 'reversible', b: 'irreversible', c: 'rate_limited' }))).toBe('irreversible');
  });
});

describe('reversibilityOf: a null value is not the key "null"', () => {
  it('null falls to the default even when the map has a "null" entry', () => {
    const d: ActionVerbDecl = { verb: 'v', kind: 'write', params: {}, reversibility_by: { param: 'action.params.k', map: { null: 'reversible' }, default: 'rate_limited' } };
    expect(reversibilityOf(d, { k: null })).toBe('rate_limited');
    expect(reversibilityOf(d, { k: undefined })).toBe('rate_limited');
  });
});

describe('unit declared by a number', () => {
  it('a numeric unit is refused even when a unit with that spelling is declared', () => {
    const doc = { v: 1, kind: 'pca-action-schema', site: 'https://s.example', aud: 's.example', version: '1', units: { '5': { kind: 'count' } }, verbs: [{ verb: 'a.b', kind: 'write', params: { 'action.params.x': P('integer', { unit: 5 }) } }] };
    expect(actionSchemaShapeError(doc, { signed: false })).toBe("verb 'a.b': action.params.x: unit must name a declared unit of an integer parameter");
  });
});

describe('importer edge shapes', () => {
  it('format "date" only makes a string a date', () => {
    const d = draftSchemaFromMcpTools([{ name: 't', inputSchema: { properties: { a: { type: 'array', format: 'date', 'x-pca-semantic': 's' }, o: { type: 'object', format: 'date', 'x-pca-semantic': 's' } } } }], SITE);
    expect(d.schema.verbs[0]!.params['action.params.a']!.type).toBe('array');
    expect(d.schema.verbs[0]!.params['action.params.o']!.type).toBe('string');
  });
  it('a set needs a string-only enum on its items: a mixed or absent enum makes an array', () => {
    const mk = (items: unknown) => draftSchemaFromMcpTools([{ name: 't', inputSchema: { properties: { a: { type: 'array', uniqueItems: true, items, 'x-pca-semantic': 's' } as never } } }], SITE).schema.verbs[0]!.params['action.params.a']!;
    expect(mk({ enum: ['a', 'b'] }).type).toBe('set');
    expect(mk({ enum: ['a', 1] }).type).toBe('array');
    expect(mk({ enum: [1, 'a'] }).type).toBe('array');
    expect(mk({ enum: 'ab' }).type).toBe('array');
    expect(mk({}).type).toBe('array');
    expect(mk({ enum: [1, 2] }).type).toBe('array');
    expect(mk({ enum: [] }).type).toBe('set');
  });
  it('descriptions are cut to 1024 characters on parameters too', () => {
    const d = draftSchemaFromMcpTools([{ name: 't', inputSchema: { properties: { a: { type: 'boolean', description: 'x'.repeat(3000), 'x-pca-semantic': 's' } } } }], SITE);
    expect(d.schema.verbs[0]!.params['action.params.a']!.description).toBe('x'.repeat(1024));
  });
  it('OpenAPI: todos follow the sorted path order and sorted parameter order; a request body without content is no schema', () => {
    const body = (properties: Record<string, unknown>) => ({ content: { 'application/json': { schema: { properties } } } });
    const d = draftSchemaFromOpenApi(
      {
        paths: {
          '/b': { post: { operationId: 'pb', requestBody: body({ zed: { type: 'boolean' }, alpha: { type: 'boolean' } }) } },
          '/a': { post: { operationId: 'pa', requestBody: {} as never } },
        },
      },
      SITE,
    );
    expect(d.todo).toEqual(['pa: reversibility (drafted irreversible)', 'action.params.alpha: semantic type', 'action.params.zed: semantic type', 'pb: reversibility (drafted irreversible)']);
  });
  it('an operation that is a primitive is skipped', () => {
    expect(draftSchemaFromOpenApi({ paths: { '/x': { get: 'nope' as never, put: 5 as never } } }, SITE).schema.verbs).toEqual([]);
  });
});

describe('walletFloorOverrides', () => {
  it('lists overrides per verb in sorted parameter order, regardless of declaration order', () => {
    const doc = { verbs: [{ verb: 'v', kind: 'write', params: { 'action.params.z': P('string', { semantic: 'money.amount' }), 'action.params.a': P('string', { semantic: 'party.payee' }), 'action.params.m': P('string', { semantic: 'other' }) } }] } as never;
    expect(walletFloorOverrides(doc).map((o) => o.path)).toEqual(['action.params.a', 'action.params.z']);
  });
});
