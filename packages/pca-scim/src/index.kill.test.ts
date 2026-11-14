import { afterEach, describe, expect, it, vi } from 'vitest';
import { issuePassport, type StoredAgent } from './index';
import {
  AGENT_SCHEMA_URN,
  ENTRA_AGENT_EXTENSION_URN,
  ERROR_SCHEMA,
  LIST_RESPONSE_SCHEMA,
  createMemoryStore,
  parseFilter,
  passportToScim,
  pushProvision,
  pushToEntra,
  pushToOkta,
  scimError,
  scimHandler,
  scimToProvisioningRequest,
  toEntraAgentPayload,
  toOktaScimPayload,
  type FetchLike,
  type ScimAgent,
  type ScimErrorBody,
  type ScimListResponse,
  type ScimRequest,
  type ScimResponse,
} from './index';

const NOW = () => 1_700_000_000_000;
const PATCH_OP = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

afterEach(() => {
  vi.unstubAllGlobals();
});

function make(baseUrl = 'https://scim.acme.com/scim/v2') {
  const store = createMemoryStore();
  const h = scimHandler(store, { baseUrl, now: NOW, authenticate: () => true });
  return { store, h };
}
type H = (req: ScimRequest) => ScimResponse;

const agentBody = (o: Record<string, unknown> = {}) => ({
  schemas: [AGENT_SCHEMA_URN],
  displayName: 'Refund Bot',
  externalId: 'idp-123',
  owner: 'org:acme',
  model: 'claude',
  operator: 'anthropic',
  hardwareRooted: true,
  capabilities: ['stripe.refund', 'stripe.payout'],
  holder: 'HOLDER',
  ...o,
});
const asAgent = (b: unknown) => b as ScimAgent;
const asList = (b: unknown) => b as ScimListResponse;
const asErr = (b: unknown) => b as ScimErrorBody;
const view = (a: ScimAgent) => ({ displayName: a.displayName, externalId: a.externalId, active: a.active, owner: a.owner, capabilities: a.capabilities, holder: a.holder });
const BASE_VIEW = { displayName: 'Refund Bot', externalId: 'idp-123', active: true, owner: 'org:acme', capabilities: ['stripe.refund', 'stripe.payout'], holder: 'HOLDER' };

function create(h: H, o: Record<string, unknown> = {}): ScimAgent {
  const res = h({ method: 'POST', body: agentBody(o) });
  expect(res.status).toBe(201);
  return asAgent(res.body);
}
const patch = (h: H, id: string, ...ops: unknown[]) => h({ method: 'PATCH', id, body: { schemas: [PATCH_OP], Operations: ops } });
const bad = (res: ScimResponse, status: number, scimType: string | undefined, detail: string) => {
  expect(res.status).toBe(status);
  const e = asErr(res.body);
  expect(e.detail).toBe(detail);
  expect(e.scimType).toBe(scimType);
};
function thrown(fn: () => unknown): Error & { scimType?: string } {
  try {
    fn();
  } catch (e) {
    if (e instanceof Error) return e;
  }
  throw new Error('expected a throw');
}
const boomObject = (key: string, base: Record<string, unknown> = {}) =>
  Object.defineProperty(base, key, {
    enumerable: true,
    get() {
      throw new Error('boom');
    },
  });
const mkPassport = () => issuePassport({ model_id: 'm', operator: 'o', hardware_rooted: false, issued_at: 0 });

describe('meta and location', () => {
  it('builds location from the base URL with all trailing slashes trimmed, and "" without one', () => {
    const p = mkPassport();
    const loc = (m: Parameters<typeof passportToScim>[2]) => passportToScim(p, { owner: 'o' }, m).meta.location;
    const tail = `/Agents/${encodeURIComponent(p.id)}`;
    expect(loc({})).toBe(tail);
    expect(loc({ baseUrl: 'https://x/v2//' })).toBe(`https://x/v2${tail}`);
    expect(loc({ baseUrl: 'https://x/' })).toBe(`https://x${tail}`);
    const m = passportToScim(p, { owner: 'o' }, { now: NOW }).meta;
    expect(m.created).toBe('2023-11-14T22:13:20.000Z');
    expect(m.lastModified).toBe('2023-11-14T22:13:20.000Z');
  });
});

describe('scimToProvisioningRequest', () => {
  it('rejects non-objects and mismatched schemas with typed errors', () => {
    const e = thrown(() => scimToProvisioningRequest(1));
    expect(e.name).toBe('ScimValueError');
    expect(e.scimType).toBe('invalidSyntax');
    expect(e.message).toBe('request body must be a JSON object');
    expect(thrown(() => scimToProvisioningRequest([])).message).toBe('request body must be a JSON object');
    const s = thrown(() => scimToProvisioningRequest({ schemas: ['x'], model: 'm', operator: 'o' }));
    expect(s.scimType).toBe('invalidValue');
    expect(s.message).toBe(`schemas must include ${AGENT_SCHEMA_URN}`);
    expect(() => scimToProvisioningRequest({ schemas: AGENT_SCHEMA_URN, model: 'm', operator: 'o' })).toThrow(`schemas must include ${AGENT_SCHEMA_URN}`);
    expect(scimToProvisioningRequest({ model: 'm', operator: 'o' }).identity.model_id).toBe('m');
  });

  it('nested passport: required fields, defaults, digests and typing', () => {
    const msg = 'passport.model_id and passport.operator are required';
    for (const passport of [{ model_id: 'm' }, { operator: 'o' }, {}, { model_id: 5, operator: 'o' }]) {
      const e = thrown(() => scimToProvisioningRequest({ passport }));
      expect(e.scimType).toBe('invalidValue');
      expect(e.message).toBe(msg);
    }
    expect(scimToProvisioningRequest({ passport: { model_id: 'm', operator: 'o' } }).identity).toStrictEqual({ model_id: 'm', operator: 'o', hardware_rooted: false, issued_at: 0 });
    expect(scimToProvisioningRequest({ passport: { model_id: 'm', operator: 'o', issued_at: '5', hardware_rooted: 'true' } }).identity).toStrictEqual({ model_id: 'm', operator: 'o', hardware_rooted: true, issued_at: 0 });
    expect(scimToProvisioningRequest({ passport: { model_id: 'm', operator: 'o', issued_at: 5, hardware_rooted: 'false' } }).identity).toStrictEqual({ model_id: 'm', operator: 'o', hardware_rooted: false, issued_at: 5 });
    expect(
      scimToProvisioningRequest({
        passport: { model_id: 'm', operator: 'o', weights_digest: 'w', system_prompt_digest: 'p', tool_manifest_digest: 't', runtime_measurement: 'r', weights_measured: 'false' },
      }).identity,
    ).toStrictEqual({ model_id: 'm', operator: 'o', hardware_rooted: false, issued_at: 0, weights_digest: 'w', system_prompt_digest: 'p', tool_manifest_digest: 't', runtime_measurement: 'r', weights_measured: false });
    expect(Object.keys(scimToProvisioningRequest({ passport: { model_id: 'm', operator: 'o', weights_digest: 3, weights_measured: 'x' } }).identity).sort()).toEqual(['hardware_rooted', 'issued_at', 'model_id', 'operator']);
  });

  it('flat form: required fields, aliases, hardware flag and owner derivation', () => {
    const msg = 'an Agent requires either a `passport` object or `model` + `operator`';
    for (const body of [{ model: 'm' }, { operator: 'o' }, { model: 5, operator: 'o' }, {}]) {
      const e = thrown(() => scimToProvisioningRequest(body));
      expect(e.scimType).toBe('invalidValue');
      expect(e.message).toBe(msg);
    }
    expect(scimToProvisioningRequest({ model: 'm', operator: 'o' }).identity).toStrictEqual({ model_id: 'm', operator: 'o', hardware_rooted: false, issued_at: 0 });
    expect(scimToProvisioningRequest({ model_id: 'm2', operator: 'o', hardwareRooted: 'true' }).identity).toStrictEqual({ model_id: 'm2', operator: 'o', hardware_rooted: true, issued_at: 0 });
    expect(scimToProvisioningRequest({ model: 'm', operator: 'o', hardwareRooted: true }).identity.hardware_rooted).toBe(true);
    expect(scimToProvisioningRequest({ model: 'm', operator: 'o', owner: 'own' }).projection.owner).toBe('own');
    expect(scimToProvisioningRequest({ model: 'm', operator: 'o' }).projection.owner).toBe('o');
    expect(scimToProvisioningRequest({ passport: { model_id: 'm', operator: 'po' } }).projection.owner).toBe('po');
  });

  it('projection carries only the attributes that are present and well-typed', () => {
    const proj = (extra: Record<string, unknown>) => scimToProvisioningRequest({ model: 'm', operator: 'o', ...extra }).projection;
    expect(proj({})).toStrictEqual({ owner: 'o' });
    expect(proj({ displayName: 'D', externalId: 'E', holder: 'H', capabilities: ['a', 'b'], active: false })).toStrictEqual({
      owner: 'o',
      displayName: 'D',
      externalId: 'E',
      active: false,
      capabilities: ['a', 'b'],
      holder: 'H',
    });
    for (const capabilities of ['x', [1], ['a', 1], { length: 0 }]) expect(proj({ capabilities })).toStrictEqual({ owner: 'o' });
    expect(proj({ capabilities: [] })).toStrictEqual({ owner: 'o', capabilities: [] });
    expect(proj({ active: 'true' })).toStrictEqual({ owner: 'o', active: true });
    expect(proj({ active: 'false' })).toStrictEqual({ owner: 'o', active: false });
    expect(proj({ active: 'maybe', displayName: 5 })).toStrictEqual({ owner: 'o' });
  });
});

describe('small builders', () => {
  it('createMemoryStore keeps its seed; scimError omits an absent type', () => {
    const p = mkPassport();
    const resource = passportToScim(p, { owner: 'o' }, { now: NOW });
    const stored: StoredAgent = { resource, passport: p };
    const s = createMemoryStore([stored]);
    expect(s.get(p.id)).toBe(stored);
    expect(s.all()).toEqual([stored]);
    expect(scimError(404, 'x')).toStrictEqual({ schemas: [ERROR_SCHEMA], status: '404', detail: 'x' });
    expect(scimError(400, 'y', 't')).toStrictEqual({ schemas: [ERROR_SCHEMA], status: '400', scimType: 't', detail: 'y' });
  });
});

describe('parseFilter', () => {
  it('tolerates repeated and surrounding whitespace and unescapes quoted values', () => {
    expect(parseFilter('displayName  eq   "x" ')).toEqual({ attr: 'displayName', value: 'x' });
    expect(parseFilter('displayName eq  "x"')).toEqual({ attr: 'displayName', value: 'x' });
    expect(parseFilter('  active eq  TRUE  ')).toEqual({ attr: 'active', value: true });
    expect(parseFilter('displayName eq "a\\"b\\\\c"')).toEqual({ attr: 'displayName', value: 'a"b\\c' });
    expect(parseFilter('displayName eq ""')).toEqual({ attr: 'displayName', value: '' });
  });
});

describe('list, filter and pagination', () => {
  function seeded() {
    const { h } = make();
    const a = create(h, { model: 'm1', displayName: 'A', externalId: 'ea', owner: 'o1' });
    const b = create(h, { model: 'm2', displayName: 'B', externalId: 'eb', owner: 'o2', active: false });
    const c = create(h, { model: 'm3', displayName: 'C', externalId: 'ec', owner: 'o1' });
    const ids = (q: Record<string, string>) => asList(h({ method: 'GET', query: q }).body).Resources.map((r) => r.id);
    return { h, a, b, c, ids };
  }

  it('each filterable attribute selects exactly the matching agent', () => {
    const { a, b, c, ids } = seeded();
    expect(ids({ filter: 'displayName eq "B"' })).toEqual([b.id]);
    expect(ids({ filter: 'userName eq "C"' })).toEqual([c.id]);
    expect(ids({ filter: 'externalId eq "ea"' })).toEqual([a.id]);
    expect(ids({ filter: `id eq "${b.id}"` })).toEqual([b.id]);
    expect(ids({ filter: 'owner eq "o1"' })).toEqual([a.id, c.id]);
    expect(ids({ filter: 'owner eq "nobody"' })).toEqual([]);
    expect(ids({ filter: 'active eq false' })).toEqual([b.id]);
    expect(ids({ filter: 'active eq true' })).toEqual([a.id, c.id]);
    expect(ids({ filter: 'externalId eq "nope"' })).toEqual([]);
    expect(ids({ filter: `id eq "nope"` })).toEqual([]);
  });

  it('startIndex without count returns the tail', () => {
    const { b, c, h } = seeded();
    const res = asList(h({ method: 'GET', query: { startIndex: '2' } }).body);
    expect(res.schemas).toEqual([LIST_RESPONSE_SCHEMA]);
    expect(res.totalResults).toBe(3);
    expect(res.startIndex).toBe(2);
    expect(res.itemsPerPage).toBe(2);
    expect(res.Resources.map((r) => r.id)).toEqual([b.id, c.id]);
    expect(asList(h({ method: 'GET', query: { startIndex: '2', count: '1' } }).body).Resources.map((r) => r.id)).toEqual([b.id]);
    expect(asList(h({ method: 'GET', query: { count: 'x' } }).body).Resources).toHaveLength(3);
  });
});

describe('create', () => {
  it('rejects bad bodies and duplicates with exact SCIM errors', () => {
    const { h } = make();
    bad(h({ method: 'POST', body: 'x' }), 400, 'invalidSyntax', 'request body must be a JSON object');
    bad(h({ method: 'POST', body: { passport: {} } }), 400, 'invalidValue', 'passport.model_id and passport.operator are required');
    const first = create(h);
    bad(h({ method: 'POST', body: agentBody() }), 409, 'uniqueness', `an agent with this attested identity already exists (id ${first.id})`);
    bad(h({ method: 'POST', id: first.id, body: agentBody() }), 405, undefined, 'POST is not allowed on an individual Agent');
  });

  it('an unexpected error while reading the body is not turned into a 400', () => {
    const { h } = make();
    expect(() => h({ method: 'POST', body: boomObject('passport') })).toThrow('boom');
  });
});

describe('replace (PUT)', () => {
  it('404s, rejects non-object bodies and does not swallow unexpected errors', () => {
    const { h } = make();
    bad(h({ method: 'PUT', id: 'nope', body: {} }), 404, undefined, 'Agent nope not found');
    const a = create(h);
    bad(h({ method: 'PUT', id: a.id, body: 'x' }), 400, 'invalidSyntax', 'request body must be a JSON object');
    expect(() => h({ method: 'PUT', id: a.id, body: boomObject('owner') })).toThrow('boom');
    bad(h({ method: 'PUT', body: {} }), 405, undefined, 'PUT requires an Agent id');
  });

  it('keeps the existing owner when omitted, takes the operator or the owner when given, and keeps created', () => {
    const { h } = make();
    const a = create(h);
    const put = (body: Record<string, unknown>) => asAgent(h({ method: 'PUT', id: a.id, body }).body);
    const r1 = put({ displayName: 'New' });
    expect(r1.owner).toBe('org:acme');
    expect(r1.displayName).toBe('New');
    expect(r1.externalId).toBeUndefined();
    expect(r1.holder).toBeUndefined();
    expect(r1.capabilities).toEqual([]);
    expect(r1.meta.created).toBe(a.meta.created);
    expect(put({ operator: 'op2' }).owner).toBe('op2');
    expect(put({ owner: 'own3', operator: 'op2' }).owner).toBe('own3');
    expect(put({ passport: { operator: 'po' } }).owner).toBe('po');
  });
});

describe('PATCH', () => {
  function agentWithAll() {
    const { h } = make();
    return { h, a: create(h) };
  }

  it('rejects malformed bodies and operations with exact errors', () => {
    const { h, a } = agentWithAll();
    bad(patch(h, 'nope', { op: 'add', path: 'active', value: true }), 404, undefined, 'Agent nope not found');
    bad(h({ method: 'PATCH', id: a.id, body: 'x' }), 400, 'invalidSyntax', 'PATCH body must be a JSON object');
    bad(h({ method: 'PATCH', id: a.id }), 400, 'invalidSyntax', 'PATCH body must be a JSON object');
    bad(h({ method: 'PATCH', id: a.id, body: { Operations: [] } }), 400, 'invalidValue', 'PATCH requires a non-empty Operations array');
    bad(h({ method: 'PATCH', id: a.id, body: { Operations: 'x' } }), 400, 'invalidValue', 'PATCH requires a non-empty Operations array');
    bad(patch(h, a.id, { op: 'move', path: 'active' }), 400, 'invalidValue', 'unsupported PATCH op: move');
    bad(patch(h, a.id, null), 400, 'invalidValue', 'unsupported PATCH op: undefined');
    bad(patch(h, a.id, 'text'), 400, 'invalidValue', 'unsupported PATCH op: undefined');
    bad(patch(h, a.id, { op: 5 }), 400, 'invalidValue', 'unsupported PATCH op: 5');
    bad(h({ method: 'PATCH', body: {} }), 405, undefined, 'PATCH requires an Agent id');
    expect(() => h({ method: 'PATCH', id: a.id, body: boomObject('Operations') })).toThrow('boom');
  });

  it('active: add/replace take a boolean (or its string), remove restores true, anything else is refused', () => {
    const { h, a } = agentWithAll();
    const res = (...ops: unknown[]) => patch(h, a.id, ...ops);
    expect(view(asAgent(res({ op: 'Replace', path: 'active', value: false }).body))).toEqual({ ...BASE_VIEW, active: false });
    expect(asAgent(res({ op: 'add', path: 'active', value: 'true' }).body).active).toBe(true);
    expect(asAgent(res({ op: 'add', path: 'active', value: 'false' }).body).active).toBe(false);
    expect(asAgent(res({ op: 'remove', path: 'active' }).body).active).toBe(true);
    bad(res({ op: 'replace', path: 'active', value: 'maybe' }), 400, 'invalidValue', '`active` must be a boolean');
    bad(res({ op: 'replace', path: 'active' }), 400, 'invalidValue', '`active` must be a boolean');
  });

  it('capabilities: add appends, replace replaces, remove empties, non-arrays are refused', () => {
    const { h, a } = agentWithAll();
    const caps = (...ops: unknown[]) => asAgent(patch(h, a.id, ...ops).body).capabilities;
    expect(caps({ op: 'add', path: 'capabilities', value: ['x'] })).toEqual(['stripe.refund', 'stripe.payout', 'x']);
    expect(caps({ op: 'replace', path: 'capabilities', value: ['y'] })).toEqual(['y']);
    expect(caps({ op: 'remove', path: 'capabilities' })).toEqual([]);
    bad(patch(h, a.id, { op: 'replace', path: 'capabilities', value: 'x' }), 400, 'invalidValue', '`capabilities` must be a string array');
    bad(patch(h, a.id, { op: 'add', path: 'capabilities', value: [1] }), 400, 'invalidValue', '`capabilities` must be a string array');
    bad(patch(h, a.id, { op: 'add', path: 'capabilities' }), 400, 'invalidValue', '`capabilities` must be a string array');
  });

  it('string attributes: replace sets only that attribute and the rest survive', () => {
    const { h, a } = agentWithAll();
    const one = (path: string, value: unknown) => view(asAgent(patch(h, a.id, { op: 'replace', path, value }).body));
    expect(one('displayName', 'N')).toEqual({ ...BASE_VIEW, displayName: 'N' });
    expect(one('externalId', 'E')).toEqual({ ...BASE_VIEW, displayName: 'N', externalId: 'E' });
    expect(one('owner', 'O')).toEqual({ ...BASE_VIEW, displayName: 'N', externalId: 'E', owner: 'O' });
    expect(one('holder', 'H')).toEqual({ ...BASE_VIEW, displayName: 'N', externalId: 'E', owner: 'O', holder: 'H' });
    for (const path of ['displayName', 'externalId', 'owner', 'holder']) {
      bad(patch(h, a.id, { op: 'replace', path, value: 5 }), 400, 'invalidValue', `\`${path}\` must be a string`);
      bad(patch(h, a.id, { op: 'add', path }), 400, 'invalidValue', `\`${path}\` must be a string`);
    }
  });

  it('remove: externalId and holder are dropped independently; displayName and owner cannot be removed', () => {
    const { h, a } = agentWithAll();
    for (const path of ['displayName', 'owner']) bad(patch(h, a.id, { op: 'remove', path }), 400, 'mutability', `\`${path}\` cannot be removed`);
    const noHolder = view(asAgent(patch(h, a.id, { op: 'remove', path: 'holder' }).body));
    expect(noHolder).toEqual({ ...BASE_VIEW, holder: undefined });
    const noExt = view(asAgent(patch(h, a.id, { op: 'remove', path: 'externalId' }).body));
    expect(noExt.externalId).toBeUndefined();
    expect(noExt.holder).toBeUndefined();
    expect(noExt.displayName).toBe('Refund Bot');
  });

  it('removing externalId keeps the holder, and removing the holder keeps externalId', () => {
    const one = (path: string) => {
      const { h, a } = agentWithAll();
      return view(asAgent(patch(h, a.id, { op: 'remove', path }).body));
    };
    expect(one('externalId')).toEqual({ ...BASE_VIEW, externalId: undefined });
    expect(one('holder')).toEqual({ ...BASE_VIEW, holder: undefined });
  });

  it('pathless operations merge an object, refuse a remove, a non-object, and immutable keys', () => {
    const { h, a } = agentWithAll();
    bad(patch(h, a.id, { op: 'remove' }), 400, 'noTarget', 'a `remove` op requires a `path`');
    bad(patch(h, a.id, { op: 'add' }), 400, 'invalidValue', 'a pathless PATCH value must be an object');
    bad(patch(h, a.id, { op: 'replace', value: 'x' }), 400, 'invalidValue', 'a pathless PATCH value must be an object');
    bad(patch(h, a.id, { op: 'replace', value: { id: 'x' } }), 400, 'mutability', 'attribute is immutable or unknown: id');
    bad(patch(h, a.id, { op: 'replace', path: 'id', value: 'x' }), 400, 'mutability', 'attribute is immutable or unknown: id');
    const merged = asAgent(patch(h, a.id, { op: 'add', value: { displayName: 'M', capabilities: ['z'], active: false } }).body);
    expect(view(merged)).toEqual({ ...BASE_VIEW, displayName: 'M', capabilities: ['z'], active: false });
  });
});

describe('GET one, DELETE, routing', () => {
  it('reports missing agents and unsupported methods with exact messages', () => {
    const { h } = make();
    bad(h({ method: 'GET', id: 'nope' }), 404, undefined, 'Agent nope not found');
    bad(h({ method: 'DELETE', id: 'nope' }), 404, undefined, 'Agent nope not found');
    bad(h({ method: 'DELETE' }), 405, undefined, 'DELETE requires an Agent id');
    bad(h({ method: 'OPTIONS' as never }), 405, undefined, 'method not allowed: OPTIONS');
    const a = create(h);
    expect(asAgent(h({ method: 'GET', id: a.id }).body).id).toBe(a.id);
    expect(h({ method: 'DELETE', id: a.id })).toEqual({ status: 204, body: undefined, headers: {} });
    bad(h({ method: 'GET', id: a.id }), 404, undefined, `Agent ${a.id} not found`);
  });

  it('refuses a handler built without authenticate, with an exact message', () => {
    expect(() => scimHandler(createMemoryStore())).toThrow(new TypeError('scimHandler: `authenticate` is required (or pass allowUnauthenticated: true explicitly)'));
  });
});

describe('outbound payloads and push', () => {
  it('the extension attributes carry a holder only when the agent has one', () => {
    const { h } = make();
    const withHolder = create(h);
    const without = create(h, { model: 'other', holder: undefined });
    expect(toEntraAgentPayload(withHolder)[ENTRA_AGENT_EXTENSION_URN].holder).toBe('HOLDER');
    expect(Object.keys(toEntraAgentPayload(without)[ENTRA_AGENT_EXTENSION_URN])).not.toContain('holder');
    expect(Object.keys(toOktaScimPayload(without)['urn:okta:scim:schemas:custom:1.0:Agent'])).not.toContain('holder');
  });

  it('pushToEntra and pushToOkta POST their payload through the injected fetch', async () => {
    const { h } = make();
    const a = create(h);
    const calls: Array<{ url: string; init: Parameters<FetchLike>[1] }> = [];
    const fetchStub: FetchLike = async (url, init) => {
      calls.push({ url, init });
      return { ok: true, status: 201, json: async () => ({ done: true }) };
    };
    const target = { endpoint: 'https://dir/x', token: 'tok', fetch: fetchStub };
    expect(await pushToEntra(a, target)).toEqual({ ok: true, status: 201, body: { done: true } });
    expect(await pushToOkta(a, target)).toEqual({ ok: true, status: 201, body: { done: true } });
    expect(calls.map((c) => c.url)).toEqual(['https://dir/x', 'https://dir/x']);
    expect(calls[0]?.init).toEqual({ method: 'POST', headers: { authorization: 'Bearer tok', 'content-type': 'application/scim+json' }, body: JSON.stringify(toEntraAgentPayload(a)) });
    expect(calls[1]?.init.body).toBe(JSON.stringify(toOktaScimPayload(a)));
  });

  it('without an injected fetch it uses the global one, and fails with an exact error when there is none', async () => {
    const { h } = make();
    const payload = toEntraAgentPayload(create(h));
    const global = vi.fn(async () => ({ ok: false, status: 500, json: async () => ({ e: 1 }) }));
    vi.stubGlobal('fetch', global);
    expect(await pushProvision(payload, { endpoint: 'https://dir/y', token: 't' })).toEqual({ ok: false, status: 500, body: { e: 1 } });
    expect(global).toHaveBeenCalledTimes(1);
    vi.stubGlobal('fetch', undefined);
    await expect(pushProvision(payload, { endpoint: 'https://dir/y', token: 't' })).rejects.toThrow(new Error('pushProvision: no fetch available — pass one explicitly'));
  });
});
