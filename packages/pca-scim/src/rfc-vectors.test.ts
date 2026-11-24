/**
 * Vectors taken from the SCIM RFCs: the filter examples of RFC 7644 section 3.4.2.2, the error example of section 3.12,
 * the PatchOp examples of section 3.5.2, and the message and meta shapes of RFC 7643 / 7644. This package supports only
 * `attr eq "value"` (documented), so for each RFC filter the expected outcome is fixed exactly: the supported ones parse
 * and select, every other one is a 400 `invalidFilter`, never ignored and never a full list.
 */
import { describe, expect, it } from 'vitest';
import {
  AGENT_SCHEMA_URN,
  AGENT_RESOURCE_TYPE,
  ERROR_SCHEMA,
  LIST_RESPONSE_SCHEMA,
  PATCH_OP_SCHEMA,
  createMemoryStore,
  parseFilter,
  scimError,
  scimHandler,
  type ScimAgent,
  type ScimErrorBody,
  type ScimListResponse,
} from './index';

const h = () => scimHandler(createMemoryStore(), { baseUrl: 'https://example.com/v2', now: () => 1_312_223_389_793, authenticate: () => true });
type Handler = ReturnType<typeof h>;
function seed(handler: Handler, displayName: string): ScimAgent {
  const res = handler({ method: 'POST', body: { schemas: [AGENT_SCHEMA_URN], displayName, externalId: displayName, owner: 'org:acme', model: 'm-' + displayName, operator: 'op' } });
  expect(res.status).toBe(201);
  return res.body as ScimAgent;
}
function codeOf(fn: () => unknown): { scimType: string; message: string } | 'ok' {
  try {
    fn();
  } catch (e) {
    const x = e as { scimType?: string; message?: string };
    return { scimType: String(x.scimType), message: String(x.message) };
  }
  return 'ok';
}

describe('RFC 7644 3.4.2.2 filter examples', () => {
  it('the supported subset: `userName eq "bjensen"` parses to the userName alias and selects exactly the match', () => {
    expect(parseFilter('userName eq "bjensen"')).toEqual({ attr: 'userName', value: 'bjensen' });
    const handler = h();
    seed(handler, 'bjensen');
    seed(handler, 'jsmith');
    const res = handler({ method: 'GET', query: { filter: 'userName eq "bjensen"' } });
    const list = res.body as ScimListResponse;
    expect(res.status).toBe(200);
    expect(list.totalResults).toBe(1);
    expect(list.Resources.map((a) => a.displayName)).toEqual(['bjensen']);
  });

  it('`externalId eq` and `id eq` select the single matching agent; a miss is an empty ListResponse, not an error', () => {
    const handler = h();
    const a = seed(handler, 'bjensen');
    expect((handler({ method: 'GET', query: { filter: 'externalId eq "bjensen"' } }).body as ScimListResponse).totalResults).toBe(1);
    expect((handler({ method: 'GET', query: { filter: `id eq "${a.id}"` } }).body as ScimListResponse).Resources.map((r) => r.id)).toEqual([a.id]);
    const miss = handler({ method: 'GET', query: { filter: 'userName eq "nobody"' } });
    expect(miss.status).toBe(200);
    expect(miss.body).toEqual({ schemas: [LIST_RESPONSE_SCHEMA], totalResults: 0, startIndex: 1, itemsPerPage: 0, Resources: [] });
  });

  const RFC_FILTERS: string[] = [
    'name.familyName co "O\'Malley"',
    'userName sw "J"',
    'urn:ietf:params:scim:schemas:core:2.0:User:userName sw "J"',
    'title pr',
    'meta.lastModified gt "2011-05-13T04:42:34Z"',
    'meta.lastModified ge "2011-05-13T04:42:34Z"',
    'meta.lastModified lt "2011-05-13T04:42:34Z"',
    'meta.lastModified le "2011-05-13T04:42:34Z"',
    'title pr and userType eq "Employee"',
    'title pr or userType eq "Intern"',
    'schemas eq "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"',
    'userType eq "Employee" and (emails co "example.com" or emails.value co "example.org")',
    'userType ne "Employee" and not (emails co "example.com" or emails.value co "example.org")',
    'userType eq "Employee" and (emails.type eq "work")',
    'userType eq "Employee" and emails[type eq "work" and value co "@example.com"]',
    'emails[type eq "work" and value co "@example.com"] or ims[type eq "xmpp" and value co "@foo.com"]',
  ];
  for (const filter of RFC_FILTERS) {
    it(`unsupported RFC filter is 400 invalidFilter with the exact body: ${filter.slice(0, 50)}`, () => {
      const handler = h();
      seed(handler, 'bjensen');
      const res = handler({ method: 'GET', query: { filter } });
      expect(res.status).toBe(400);
      expect(res.headers['content-type']).toBe('application/scim+json');
      const body = res.body as ScimErrorBody;
      expect(body.schemas).toEqual([ERROR_SCHEMA]);
      expect(body.status).toBe('400');
      expect(body.scimType).toBe('invalidFilter');
      expect(body.detail.length).toBeGreaterThan(0);
      expect(Object.keys(body).sort()).toEqual(['detail', 'schemas', 'scimType', 'status']);
    });
  }

  it('`schemas eq` (the enterprise-extension example) is rejected because the attribute is not filterable, with that reason', () => {
    expect(codeOf(() => parseFilter('schemas eq "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"'))).toEqual({
      scimType: 'invalidFilter',
      message: 'filter attribute not supported: schemas',
    });
  });

  it('every other RFC operator form is refused by the parser with the unsupported-filter message', () => {
    for (const f of RFC_FILTERS.filter((x) => !x.startsWith('schemas eq'))) {
      expect(codeOf(() => parseFilter(f))).toEqual({ scimType: 'invalidFilter', message: `unsupported filter (only \`attr eq "value"\` is supported): ${f}` });
    }
  });
});

describe('RFC 7644 3.12 error example', () => {
  it('scimError reproduces the mutability example byte for byte', () => {
    expect(scimError(400, "Attribute 'id' is readonly", 'mutability')).toEqual({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      scimType: 'mutability',
      detail: "Attribute 'id' is readonly",
      status: '400',
    });
  });

  it('the schema URNs are the RFC values', () => {
    expect(ERROR_SCHEMA).toBe('urn:ietf:params:scim:api:messages:2.0:Error');
    expect(LIST_RESPONSE_SCHEMA).toBe('urn:ietf:params:scim:api:messages:2.0:ListResponse');
    expect(PATCH_OP_SCHEMA).toBe('urn:ietf:params:scim:api:messages:2.0:PatchOp');
  });
});

describe('RFC 7644 3.5.2 PatchOp examples', () => {
  it('RFC "add" of an attribute the resource does not define (nickname) is refused as immutable or unknown', () => {
    const handler = h();
    const a = seed(handler, 'bjensen');
    const res = handler({
      method: 'PATCH',
      id: a.id,
      body: { schemas: [PATCH_OP_SCHEMA], Operations: [{ op: 'add', value: { nickname: 'Babs' } }] },
    });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ schemas: [ERROR_SCHEMA], status: '400', scimType: 'mutability', detail: 'attribute is immutable or unknown: nickname' });
  });

  it('RFC "remove" of a member by value path is refused: Agents have no members', () => {
    const handler = h();
    const a = seed(handler, 'bjensen');
    const path = 'members[value eq "2819c223-7f76-453a-919d-413861904646"]';
    const res = handler({ method: 'PATCH', id: a.id, body: { schemas: [PATCH_OP_SCHEMA], Operations: [{ op: 'remove', path }] } });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ schemas: [ERROR_SCHEMA], status: '400', scimType: 'mutability', detail: `attribute is immutable or unknown: ${path}` });
  });

  it('operation names are case-insensitive (RFC examples and IdPs use both "add" and "Add")', () => {
    const handler = h();
    const a = seed(handler, 'bjensen');
    const res = handler({ method: 'PATCH', id: a.id, body: { schemas: [PATCH_OP_SCHEMA], Operations: [{ op: 'Replace', path: 'active', value: false }] } });
    expect(res.status).toBe(200);
    expect((res.body as ScimAgent).active).toBe(false);
  });

  it('a PatchOp without Operations, with an empty array, or with an unknown op is 400 invalidValue', () => {
    const handler = h();
    const a = seed(handler, 'bjensen');
    for (const body of [{ schemas: [PATCH_OP_SCHEMA] }, { schemas: [PATCH_OP_SCHEMA], Operations: [] }, { schemas: [PATCH_OP_SCHEMA], Operations: [{ op: 'move', path: 'active' }] }]) {
      const res = handler({ method: 'PATCH', id: a.id, body });
      expect(res.status).toBe(400);
      expect((res.body as ScimErrorBody).scimType).toBe('invalidValue');
    }
  });
});

describe('RFC 7643 / 7644 message shapes', () => {
  it('a ListResponse has the RFC member names and nothing else', () => {
    const handler = h();
    seed(handler, 'bjensen');
    const body = handler({ method: 'GET' }).body as ScimListResponse;
    expect(Object.keys(body).sort()).toEqual(['Resources', 'itemsPerPage', 'schemas', 'startIndex', 'totalResults']);
    expect(body.schemas).toEqual(['urn:ietf:params:scim:api:messages:2.0:ListResponse']);
    expect(body.startIndex).toBe(1);
  });

  it('startIndex is 1-based and count limits the page (RFC 7644 3.4.2.4)', () => {
    const handler = h();
    ['a', 'b', 'c'].forEach((n) => seed(handler, n));
    const page = handler({ method: 'GET', query: { startIndex: '2', count: '1' } }).body as ScimListResponse;
    expect(page.totalResults).toBe(3);
    expect(page.startIndex).toBe(2);
    expect(page.itemsPerPage).toBe(1);
    expect(page.Resources.map((r) => r.displayName)).toEqual(['b']);
    const zero = handler({ method: 'GET', query: { count: '0' } }).body as ScimListResponse;
    expect(zero.itemsPerPage).toBe(0);
    expect(zero.totalResults).toBe(3);
  });

  it('meta has exactly the RFC 7643 3.1 members, with a weak ETag version and an absolute location', () => {
    const handler = h();
    const a = seed(handler, 'bjensen');
    expect(Object.keys(a.meta).sort()).toEqual(['created', 'lastModified', 'location', 'resourceType', 'version']);
    expect(a.meta.resourceType).toBe('Agent');
    expect(a.meta.created).toBe('2011-08-01T18:29:49.793Z');
    expect(a.meta.lastModified).toBe('2011-08-01T18:29:49.793Z');
    expect(a.meta.version).toMatch(/^W\/"[^"]+"$/);
    expect(a.meta.location).toBe(`https://example.com/v2/Agents/${a.id}`);
  });

  it('the Agent resource type name and schema URN are pinned', () => {
    expect(AGENT_RESOURCE_TYPE).toBe('Agent');
    expect(AGENT_SCHEMA_URN).toBe('urn:ietf:params:scim:schemas:atlas:2.0:Agent');
  });
});
