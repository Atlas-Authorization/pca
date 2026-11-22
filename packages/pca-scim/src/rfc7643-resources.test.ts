/**
 * RFC 7643 section 8 example resources (the User of 8.2 and the Group of 8.4). This server provisions Agents only, so the
 * outcome for each is fixed exactly: a User or Group body is never accepted as an Agent, whatever else it carries, and the
 * RFC's own member filters are refused as unsupported rather than ignored.
 */
import { describe, expect, it } from 'vitest';
import { AGENT_SCHEMA_URN, ERROR_SCHEMA, createMemoryStore, scimHandler, type ScimErrorBody } from './index';

const USER = {
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
  id: '2819c223-7f76-453a-919d-413861904646',
  externalId: 'bjensen',
  meta: {
    resourceType: 'User',
    created: '2011-08-01T18:29:49.793Z',
    lastModified: '2011-08-01T18:29:49.793Z',
    location: 'https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646',
    version: 'W/"f250dd84f0671c3"',
  },
  name: { formatted: 'Ms. Barbara J Jensen, III', familyName: 'Jensen', givenName: 'Barbara' },
  userName: 'bjensen',
  emails: [{ value: 'bjensen@example.com', type: 'work', primary: true }],
};
const GROUP = {
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
  id: 'e9e30dba-f08f-4109-8486-d5c6a331660a',
  displayName: 'Tour Guides',
  members: [
    { value: '2819c223-7f76-453a-919d-413861904646', $ref: 'https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646', type: 'User' },
  ],
  meta: { resourceType: 'Group', created: '2011-08-01T18:29:49.793Z', lastModified: '2011-08-01T18:29:49.793Z', location: 'https://example.com/v2/Groups/e9e30dba-f08f-4109-8486-d5c6a331660a', version: 'W/"3694e05e9dff592"' },
};
const h = () => scimHandler(createMemoryStore(), { baseUrl: 'https://example.com/v2', now: () => 1_312_223_389_793, authenticate: () => true });
const SCHEMA_REFUSAL: ScimErrorBody = { schemas: [ERROR_SCHEMA], status: '400', scimType: 'invalidValue', detail: `schemas must include ${AGENT_SCHEMA_URN}` };

describe('RFC 7643 section 8 resources are not Agents', () => {
  it('the RFC User example is refused with the exact schemas error', () => {
    const res = h()({ method: 'POST', body: USER });
    expect(res.status).toBe(400);
    expect(res.body).toEqual(SCHEMA_REFUSAL);
  });

  it('the RFC Group example is refused with the exact schemas error', () => {
    const res = h()({ method: 'POST', body: GROUP });
    expect(res.status).toBe(400);
    expect(res.body).toEqual(SCHEMA_REFUSAL);
  });

  it('a User that also carries Agent fields is still refused: the declared schemas decide', () => {
    const res = h()({ method: 'POST', body: { ...USER, model: 'm', operator: 'op' } });
    expect(res.status).toBe(400);
    expect(res.body).toEqual(SCHEMA_REFUSAL);
  });

  it('a body that lists the Agent schema among others is accepted (extension schemas are allowed)', () => {
    const res = h()({ method: 'POST', body: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User', AGENT_SCHEMA_URN], displayName: 'a', externalId: 'a', owner: 'org:acme', model: 'm', operator: 'op' } });
    expect(res.status).toBe(201);
  });

  it('a non-array or non-string-list schemas member is refused', () => {
    for (const schemas of ['urn:x', 5, null, {}, [5]]) {
      const res = h()({ method: 'POST', body: { schemas, model: 'm', operator: 'op' } });
      expect(res.status).toBe(400);
      expect(res.body).toEqual(SCHEMA_REFUSAL);
    }
  });

  it('the RFC resource filters are refused as unsupported, never ignored', () => {
    for (const f of ['members.value eq "2819c223-7f76-453a-919d-413861904646"', 'emails[type eq "work"]', 'name.familyName eq "Jensen"', 'meta.lastModified gt "2011-05-13T04:42:34Z"']) {
      const res = h()({ method: 'GET', query: { filter: f } });
      expect(res.status).toBe(400);
      expect((res.body as ScimErrorBody).scimType).toBe('invalidFilter');
    }
  });

  it('the RFC User attributes userName and externalId are the supported filters, selecting no Agent when none matches', () => {
    for (const f of ['userName eq "bjensen"', 'externalId eq "bjensen"', 'id eq "2819c223-7f76-453a-919d-413861904646"']) {
      const res = h()({ method: 'GET', query: { filter: f } });
      expect(res.status).toBe(200);
      expect((res.body as { totalResults: number }).totalResults).toBe(0);
    }
  });

  it('a User id is not found as an Agent', () => {
    const res = h()({ method: 'GET', id: USER.id });
    expect(res.status).toBe(404);
  });
});
