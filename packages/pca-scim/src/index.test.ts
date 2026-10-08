import { describe, expect, it, vi } from 'vitest';
import { issuePassport, type AgentPassport, type PassportIdentity } from '@atlasauth/pca';
import {
  AGENT_SCHEMA_URN,
  ENTRA_AGENT_EXTENSION_URN,
  ERROR_SCHEMA,
  LIST_RESPONSE_SCHEMA,
  OKTA_AGENT_EXTENSION_URN,
  createMemoryStore,
  parseFilter,
  passportToScim,
  pushProvision,
  scimError,
  scimHandler,
  scimToProvisioningRequest,
  toEntraAgentPayload,
  toOktaScimPayload,
  type EntraAgentPayload,
  type FetchLike,
  type OktaScimPayload,
  type ScimAgent,
  type ScimErrorBody,
  type ScimListResponse,
} from './index';

const NOW = () => 1_700_000_000_000;
const PATCH_OP = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

function handler() {
  const store = createMemoryStore();
  return { store, h: scimHandler(store, { baseUrl: 'https://scim.acme.com/scim/v2', now: NOW }) };
}

/** A SCIM POST body in the flat IdP form. */
function createBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemas: [AGENT_SCHEMA_URN],
    displayName: 'Refund Bot',
    externalId: 'idp-123',
    owner: 'org:acme',
    model: 'claude-opus-4-8',
    operator: 'anthropic',
    hardwareRooted: true,
    capabilities: ['stripe.refund', 'stripe.payout'],
    holder: 'HOLDER_KEY_B64U',
    ...overrides,
  };
}

function asAgent(body: unknown): ScimAgent {
  return body as ScimAgent;
}
function asList(body: unknown): ScimListResponse {
  return body as ScimListResponse;
}
function asError(body: unknown): ScimErrorBody {
  return body as ScimErrorBody;
}

describe('POST /Agents — register a passport', () => {
  it('creates an Agent, returns 201 with a well-formed SCIM resource, and registers the passport', () => {
    const { store, h } = handler();
    const res = h({ method: 'POST', body: createBody() });

    expect(res.status).toBe(201);
    const agent = asAgent(res.body);
    expect(agent.schemas).toEqual([AGENT_SCHEMA_URN]);
    expect(agent.displayName).toBe('Refund Bot');
    expect(agent.active).toBe(true);
    expect(agent.owner).toBe('org:acme');
    expect(agent.capabilities).toEqual(['stripe.refund', 'stripe.payout']);
    expect(agent.holder).toBe('HOLDER_KEY_B64U');
    // content-addressed id == passportRef == the issued passport id
    expect(agent.id).toBe(agent.passportRef);
    expect(agent.id).toBe(agent.passport.id);
    expect(agent.passport.model_id).toBe('claude-opus-4-8');
    expect(agent.passport.hardware_rooted).toBe(true);
    // meta
    expect(agent.meta.resourceType).toBe('Agent');
    expect(agent.meta.location).toBe(`https://scim.acme.com/scim/v2/Agents/${encodeURIComponent(agent.id)}`);
    expect(agent.meta.created).toBe(new Date(NOW()).toISOString());
    expect(agent.meta.version).toMatch(/^W\/".+"$/);
    // response headers
    expect(res.headers['content-type']).toBe('application/scim+json');
    expect(res.headers.location).toBe(agent.meta.location);
    expect(res.headers.etag).toBe(agent.meta.version);
    // the passport is in the registry view
    const reg = store.registry();
    expect(reg.has(agent.id)).toBe(true);
    expect(reg.get(agent.id)?.operator).toBe('anthropic');
  });

  it('rejects a second create of the same attested identity with 409 uniqueness', () => {
    const { h } = handler();
    expect(h({ method: 'POST', body: createBody() }).status).toBe(201);
    const dup = h({ method: 'POST', body: createBody({ displayName: 'Different name, same identity' }) });
    expect(dup.status).toBe(409);
    expect(asError(dup.body).scimType).toBe('uniqueness');
  });

  it('400s a body missing both a passport and model/operator', () => {
    const { h } = handler();
    const res = h({ method: 'POST', body: { displayName: 'x', owner: 'o' } });
    expect(res.status).toBe(400);
    expect(asError(res.body).scimType).toBe('invalidValue');
  });

  it('400s a non-object body', () => {
    const { h } = handler();
    const res = h({ method: 'POST', body: 'not json' });
    expect(res.status).toBe(400);
    expect(asError(res.body).scimType).toBe('invalidSyntax');
  });
});

describe('GET /Agents and /Agents/{id} — list + filter + fetch', () => {
  it('GETs a single Agent by id', () => {
    const { h } = handler();
    const id = asAgent(h({ method: 'POST', body: createBody() }).body).id;
    const res = h({ method: 'GET', id });
    expect(res.status).toBe(200);
    expect(asAgent(res.body).id).toBe(id);
  });

  it('404s an unknown id with a SCIM error envelope', () => {
    const { h } = handler();
    const res = h({ method: 'GET', id: 'nope' });
    expect(res.status).toBe(404);
    const err = asError(res.body);
    expect(err.schemas).toEqual([ERROR_SCHEMA]);
    expect(err.status).toBe('404');
    expect(err.scimType).toBeUndefined();
    expect(typeof err.detail).toBe('string');
  });

  it('lists Agents in a ListResponse envelope', () => {
    const { h } = handler();
    h({ method: 'POST', body: createBody() });
    h({ method: 'POST', body: createBody({ displayName: 'Payout Bot', operator: 'openai', model: 'gpt' }) });
    const res = h({ method: 'GET' });
    expect(res.status).toBe(200);
    const list = asList(res.body);
    expect(list.schemas).toEqual([LIST_RESPONSE_SCHEMA]);
    expect(list.totalResults).toBe(2);
    expect(list.startIndex).toBe(1);
    expect(list.itemsPerPage).toBe(2);
    expect(list.Resources).toHaveLength(2);
  });

  it('filters with `userName eq "..."` (aliased to displayName)', () => {
    const { h } = handler();
    h({ method: 'POST', body: createBody() });
    h({ method: 'POST', body: createBody({ displayName: 'Payout Bot', operator: 'openai', model: 'gpt' }) });
    const res = h({ method: 'GET', query: { filter: 'userName eq "Payout Bot"' } });
    const list = asList(res.body);
    expect(list.totalResults).toBe(1);
    expect(list.Resources[0]?.displayName).toBe('Payout Bot');
  });

  it('filters on active eq false', () => {
    const { h } = handler();
    h({ method: 'POST', body: createBody() });
    const res = h({ method: 'GET', query: { filter: 'active eq false' } });
    expect(asList(res.body).totalResults).toBe(0);
  });

  it('returns an empty ListResponse when nothing matches', () => {
    const { h } = handler();
    h({ method: 'POST', body: createBody() });
    const res = h({ method: 'GET', query: { filter: 'displayName eq "Ghost"' } });
    const emptyList = asList(res.body);
    expect(emptyList.totalResults).toBe(0);
    expect(emptyList.Resources).toEqual([]);
    expect(emptyList.itemsPerPage).toBe(0);
  });

  it('400s an unsupported filter with scimType invalidFilter', () => {
    const { h } = handler();
    const res = h({ method: 'GET', query: { filter: 'displayName co "Refund"' } });
    expect(res.status).toBe(400);
    expect(asError(res.body).scimType).toBe('invalidFilter');
  });

  it('paginates with startIndex + count', () => {
    const { h } = handler();
    for (let i = 0; i < 3; i++) {
      h({ method: 'POST', body: createBody({ displayName: `Bot ${i}`, operator: `op${i}`, model: `m${i}` }) });
    }
    const res = h({ method: 'GET', query: { startIndex: '2', count: '1' } });
    const list = asList(res.body);
    expect(list.totalResults).toBe(3);
    expect(list.startIndex).toBe(2);
    expect(list.itemsPerPage).toBe(1);
    expect(list.Resources).toHaveLength(1);
  });
});

describe('PATCH /Agents/{id} — RFC 7644 ops (deprovision)', () => {
  it('replaces active=false to deprovision the agent', () => {
    const { h } = handler();
    const id = asAgent(h({ method: 'POST', body: createBody() }).body).id;
    const res = h({
      method: 'PATCH',
      id,
      body: { schemas: [PATCH_OP], Operations: [{ op: 'replace', path: 'active', value: false }] },
    });
    expect(res.status).toBe(200);
    expect(asAgent(res.body).active).toBe(false);
    // persisted
    expect(asAgent(h({ method: 'GET', id }).body).active).toBe(false);
  });

  it('accepts active as the string "false" (Azure style)', () => {
    const { h } = handler();
    const id = asAgent(h({ method: 'POST', body: createBody() }).body).id;
    const res = h({ method: 'PATCH', id, body: { Operations: [{ op: 'replace', path: 'active', value: 'false' }] } });
    expect(asAgent(res.body).active).toBe(false);
  });

  it('adds capabilities and replaces displayName', () => {
    const { h } = handler();
    const id = asAgent(h({ method: 'POST', body: createBody() }).body).id;
    const res = h({
      method: 'PATCH',
      id,
      body: {
        Operations: [
          { op: 'add', path: 'capabilities', value: ['gmail.send'] },
          { op: 'replace', path: 'displayName', value: 'Renamed Bot' },
        ],
      },
    });
    const agent = asAgent(res.body);
    expect(agent.capabilities).toEqual(['stripe.refund', 'stripe.payout', 'gmail.send']);
    expect(agent.displayName).toBe('Renamed Bot');
  });

  it('applies a pathless replace that merges an object value', () => {
    const { h } = handler();
    const id = asAgent(h({ method: 'POST', body: createBody() }).body).id;
    const res = h({ method: 'PATCH', id, body: { Operations: [{ op: 'replace', value: { active: false, owner: 'org:new' } }] } });
    const agent = asAgent(res.body);
    expect(agent.active).toBe(false);
    expect(agent.owner).toBe('org:new');
  });

  it('refuses to PATCH an immutable attribute', () => {
    const { h } = handler();
    const id = asAgent(h({ method: 'POST', body: createBody() }).body).id;
    const res = h({ method: 'PATCH', id, body: { Operations: [{ op: 'replace', path: 'passportRef', value: 'x' }] } });
    expect(res.status).toBe(400);
    expect(asError(res.body).scimType).toBe('mutability');
  });

  it('404s a PATCH on an unknown id', () => {
    const { h } = handler();
    const res = h({ method: 'PATCH', id: 'nope', body: { Operations: [{ op: 'replace', path: 'active', value: false }] } });
    expect(res.status).toBe(404);
  });

  it('preserves meta.created across a PATCH', () => {
    const { h } = handler();
    const created0 = asAgent(h({ method: 'POST', body: createBody() }).body);
    const res = h({ method: 'PATCH', id: created0.id, body: { Operations: [{ op: 'replace', path: 'active', value: false }] } });
    expect(asAgent(res.body).meta.created).toBe(created0.meta.created);
  });
});

describe('PUT /Agents/{id} — replace governance attributes', () => {
  it('replaces displayName while keeping the immutable id/passport', () => {
    const { h } = handler();
    const created = asAgent(h({ method: 'POST', body: createBody() }).body);
    const res = h({ method: 'PUT', id: created.id, body: createBody({ displayName: 'Put Name' }) });
    expect(res.status).toBe(200);
    const agent = asAgent(res.body);
    expect(agent.displayName).toBe('Put Name');
    expect(agent.id).toBe(created.id);
    expect(agent.passport.id).toBe(created.passport.id);
  });
});

describe('DELETE /Agents/{id} — deprovision', () => {
  it('deletes and returns 204, after which GET 404s', () => {
    const { h } = handler();
    const id = asAgent(h({ method: 'POST', body: createBody() }).body).id;
    const del = h({ method: 'DELETE', id });
    expect(del.status).toBe(204);
    expect(del.body).toBeUndefined();
    expect(h({ method: 'GET', id }).status).toBe(404);
  });

  it('404s a DELETE on an unknown id', () => {
    const { h } = handler();
    expect(h({ method: 'DELETE', id: 'nope' }).status).toBe(404);
  });
});

describe('method guards', () => {
  it('405s POST on an individual Agent and PUT/PATCH/DELETE without an id', () => {
    const { h } = handler();
    expect(h({ method: 'POST', id: 'x', body: {} }).status).toBe(405);
    expect(h({ method: 'PUT', body: {} }).status).toBe(405);
    expect(h({ method: 'PATCH', body: {} }).status).toBe(405);
    expect(h({ method: 'DELETE' }).status).toBe(405);
  });
});

describe('passportToScim / scimToProvisioningRequest round-trip', () => {
  const identity: PassportIdentity = {
    model_id: 'claude-opus-4-8',
    weights_digest: 'wd',
    system_prompt_digest: 'spd',
    tool_manifest_digest: 'tmd',
    runtime_measurement: '42',
    operator: 'anthropic',
    hardware_rooted: true,
    weights_measured: true,
    issued_at: 123,
  };
  const passport: AgentPassport = issuePassport(identity);

  it('maps a passport to a SCIM resource and back to the same identity + projection', () => {
    const scim = passportToScim(passport, {
      displayName: 'Bot',
      externalId: 'ext-1',
      owner: 'org:acme',
      active: false,
      capabilities: ['a.b'],
      holder: 'KEY',
    });
    const prov = scimToProvisioningRequest(scim);
    // identity round-trips exactly (so issuePassport reproduces the same id)
    expect(prov.identity).toEqual(identity);
    expect(issuePassport(prov.identity).id).toBe(passport.id);
    // projection round-trips
    expect(prov.projection.displayName).toBe('Bot');
    expect(prov.projection.externalId).toBe('ext-1');
    expect(prov.projection.owner).toBe('org:acme');
    expect(prov.projection.active).toBe(false);
    expect(prov.projection.capabilities).toEqual(['a.b']);
    expect(prov.projection.holder).toBe('KEY');
  });

  it('defaults displayName and active when the projection omits them', () => {
    const scim = passportToScim(passport, { owner: 'org:acme' });
    expect(scim.displayName).toBe('claude-opus-4-8 (anthropic)');
    expect(scim.active).toBe(true);
    expect(scim.capabilities).toEqual([]);
    expect(scim.externalId).toBeUndefined();
  });
});

describe('Entra / Okta push payload shapes', () => {
  function agent(): ScimAgent {
    const { h } = handler();
    return asAgent(h({ method: 'POST', body: createBody() }).body);
  }

  it('toEntraAgentPayload shapes a SCIM body with the Microsoft extension', () => {
    const payload: EntraAgentPayload = toEntraAgentPayload(agent());
    expect(payload.schemas).toEqual([AGENT_SCHEMA_URN, ENTRA_AGENT_EXTENSION_URN]);
    expect(payload.externalId).toBe('idp-123');
    expect(payload.displayName).toBe('Refund Bot');
    expect(payload.active).toBe(true);
    const ext = payload[ENTRA_AGENT_EXTENSION_URN];
    expect(ext.model).toBe('claude-opus-4-8');
    expect(ext.operator).toBe('anthropic');
    expect(ext.hardwareRooted).toBe(true);
    expect(ext.capabilities).toEqual(['stripe.refund', 'stripe.payout']);
    expect(ext.owner).toBe('org:acme');
    expect(ext.holder).toBe('HOLDER_KEY_B64U');
    expect(ext.passportRef).toBe(agent().passportRef);
  });

  it('toOktaScimPayload shapes a User-style SCIM body with the Okta extension', () => {
    const a = agent();
    const payload: OktaScimPayload = toOktaScimPayload(a);
    expect(payload.schemas).toEqual([AGENT_SCHEMA_URN, OKTA_AGENT_EXTENSION_URN]);
    expect(payload.userName).toBe(a.passportRef);
    expect(payload.externalId).toBe('idp-123');
    expect(payload.active).toBe(true);
    expect(payload[OKTA_AGENT_EXTENSION_URN].model).toBe('claude-opus-4-8');
  });

  it('falls back externalId to passportRef when none was provided', () => {
    const { h } = handler();
    const a = asAgent(h({ method: 'POST', body: createBody({ externalId: undefined }) }).body);
    expect(toEntraAgentPayload(a).externalId).toBe(a.passportRef);
  });
});

describe('pushProvision — injectable fetch', () => {
  it('POSTs the payload with a bearer token and SCIM content type', async () => {
    const { h } = handler();
    const a = asAgent(h({ method: 'POST', body: createBody() }).body);
    const payload = toEntraAgentPayload(a);
    const calls: Array<{ url: string; init: { method: string; headers: Record<string, string>; body: string } }> = [];
    const fakeFetch: FetchLike = vi.fn(async (url, init) => {
      calls.push({ url, init });
      return { ok: true, status: 201, json: async () => ({ id: 'entra-obj-1' }) };
    });
    const result = await pushProvision(payload, { endpoint: 'https://graph.example/scim/Agents', token: 'TOK', fetch: fakeFetch });
    expect(result.ok).toBe(true);
    expect(result.status).toBe(201);
    expect(result.body).toEqual({ id: 'entra-obj-1' });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe('https://graph.example/scim/Agents');
    expect(calls[0]?.init.method).toBe('POST');
    expect(calls[0]?.init.headers.authorization).toBe('Bearer TOK');
    expect(calls[0]?.init.headers['content-type']).toBe('application/scim+json');
    expect(JSON.parse(calls[0]?.init.body ?? '{}').displayName).toBe('Refund Bot');
  });
});

describe('envelope + filter helpers', () => {
  it('scimError builds an Error-schema body with a string status', () => {
    const err = scimError(404, 'not found');
    expect(err.schemas).toEqual([ERROR_SCHEMA]);
    expect(err.status).toBe('404');
    expect(err.scimType).toBeUndefined();
  });

  it('parseFilter parses string and boolean eq, and rejects junk', () => {
    expect(parseFilter('userName eq "a b"')).toEqual({ attr: 'userName', value: 'a b' });
    expect(parseFilter('active eq true')).toEqual({ attr: 'active', value: true });
    expect(() => parseFilter('displayName sw "x"')).toThrow();
    expect(() => parseFilter('unknownAttr eq "x"')).toThrow();
  });
});
