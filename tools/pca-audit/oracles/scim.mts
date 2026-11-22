// Oracle: @atlasauth/pca-scim (passport <-> SCIM mapping, filter, PATCH, the /Agents handler, push adapters). Deterministic.
// Handler cases are sessions: a named options table (the native replay keeps the same table), some setup requests, then the
// requests whose responses are recorded. Push cases use a named fake fetch. Writes out/ref-scim.json.gz.
import { Oracle, variants, refWrite } from './lib.mjs';

const M: any = await import('../../../packages/pca-scim/src/index.ts');
const o = new Oracle('scim', 'tools/pca-audit/oracles/scim.mts', 'TS-reference oracle for the SCIM 2.0 /Agents server, the passport mapping and the push adapters.');

const T0 = 1_700_000_000_000;
let tick = 0;
const OPTS: Record<string, () => any> = {
  open: () => ({ baseUrl: 'https://scim.acme.com/scim/v2', now: () => T0, authenticate: () => true }),
  slash: () => ({ baseUrl: 'https://scim.acme.com/scim/v2///', now: () => T0, authenticate: () => true }),
  nobase: () => ({ now: () => T0, allowUnauthenticated: true }),
  tick: () => { tick = 0; return { baseUrl: 'https://x.example', now: () => T0 + 1000 * tick++, authenticate: () => true }; },
  deny: () => ({ now: () => T0, authenticate: () => false }),
  throwauth: () => ({ now: () => T0, authenticate: () => { throw new Error('x'); } }),
  truthy: () => ({ now: () => T0, authenticate: () => 'yes' }),
  noauth: () => ({ now: () => T0 }),
  notfn: () => ({ now: () => T0, authenticate: 'yes' }),
};
const session = (opts: string, setup: any[], reqs: any[]) => {
  const h = M.scimHandler(M.createMemoryStore(), OPTS[opts]());
  for (const r of setup) h(r);
  return reqs.map((r) => h(r));
};

const FLAT = { schemas: [M.AGENT_SCHEMA_URN], displayName: 'Refund Bot', externalId: 'idp-123', owner: 'org:acme', model: 'claude-opus-4-8', operator: 'anthropic', hardwareRooted: true, capabilities: ['stripe.refund', 'stripe.payout'], holder: 'HK' };
const NESTED = { schemas: [M.AGENT_SCHEMA_URN], displayName: 'Nested', passport: { model_id: 'gpt-x', operator: 'openai', hardware_rooted: 'true', issued_at: 5, weights_digest: 'w1', system_prompt_digest: 'sp', tool_manifest_digest: 'tm', runtime_measurement: '7', weights_measured: 'false' } };
const FLAT2 = { displayName: 'Second', model_id: 'm2', operator: 'op2', active: 'false', capabilities: [] };
const ID1 = M.issuePassport({ model_id: 'claude-opus-4-8', operator: 'anthropic', hardware_rooted: true, issued_at: 0 }).id;
const ID2 = M.issuePassport({ model_id: 'm2', operator: 'op2', hardware_rooted: false, issued_at: 0 }).id;
const post = (body: any) => ({ method: 'POST', body });
const SETUP = [post(FLAT), post(FLAT2)];
const run = (name: string, opts: string, setup: any[], reqs: any[]) => o.run('scimSession', name, session, [opts, setup, reqs]);

// ---- construction + auth ------------------------------------------------------------------------------------------
for (const k of Object.keys(OPTS)) {
  await run(`auth/${k}`, k, [], [{ method: 'GET' }, post(FLAT), { method: 'DELETE', id: 'x' }]);
}

// ---- create -------------------------------------------------------------------------------------------------------
await run('create/flat', 'open', [], [post(FLAT)]);
await run('create/nested', 'open', [], [post(NESTED)]);
await run('create/flat2-tick', 'tick', [], [post(FLAT2), post(FLAT)]);
await run('create/dup', 'open', [], [post(FLAT), post(FLAT)]);
await run('create/slash', 'slash', [], [post(FLAT)]);
await run('create/nobase', 'nobase', [], [post(FLAT)]);
const badBodies: any[] = [null, 'x', [], 5, {}, { schemas: ['urn:other'] }, { schemas: 'x' }, { schemas: null }, { schemas: [] }, { model: 'm' }, { operator: 'o' }, { passport: {} },
  { passport: { model_id: 'm' } }, { passport: { operator: 'o' } }, { passport: [] }, { passport: null, model: 'm', operator: 'o' }, { model: 'm', operator: 'o', schemas: [M.AGENT_SCHEMA_URN, 'x'] },
  { model: 'm', operator: 'o', hardwareRooted: 'true' }, { model: 'm', operator: 'o', hardwareRooted: 1 }, { model: 'm', operator: 'o', active: 'maybe', capabilities: 'x', holder: 5, displayName: 5, externalId: 5, owner: 5 },
  { model: 'm', operator: 'o', owner: '' }, { model: 'm', operator: 'o', capabilities: ['a', 1] }, { model: 'm', operator: 'o', capabilities: [] },
  { passport: { model_id: 'm', operator: 'o', issued_at: 'x', hardware_rooted: null } }, { passport: { model_id: 'm', operator: 'o', issued_at: 12 }, owner: 'own' }, { model_id: 'only-id', operator: 'o' }, { model: 'a', model_id: 'b', operator: 'o' }];
for (const [i, b] of badBodies.entries()) await run(`create/body${i}`, 'open', [], [post(b)]);
for (const [label, v] of variants(FLAT, { depth: 2, maxPaths: 30 })) await run(`create/flat ${label}`, 'open', [], [post(v)]);
for (const [label, v] of variants(NESTED, { depth: 3, maxPaths: 30 })) await run(`create/nested ${label}`, 'open', [], [post(v)]);

// ---- read / list / filter / paging --------------------------------------------------------------------------------
const get = (query?: any, id?: any) => ({ method: 'GET', ...(query !== undefined ? { query } : {}), ...(id !== undefined ? { id } : {}) });
await run('get/list', 'open', SETUP, [get(), get({}), get(undefined)]);
await run('get/one', 'open', SETUP, [get(undefined, ID1), get(undefined, ID2), get(undefined, 'nope'), get(undefined, ''), get(undefined, null), get(undefined, 5), get(undefined, [1]), get(undefined, 'a b/é')]);
const filters = ['userName eq "Refund Bot"', 'displayName eq "Second"', 'externalId eq "idp-123"', `id eq "${ID1}"`, 'owner eq "org:acme"', 'owner eq "anthropic"', 'active eq true', 'active eq false', 'ACTIVE eq true',
  'active EQ TRUE', '  displayName   eq   "Second"  ', 'displayName eq "Sec\\ond"', 'displayName eq "a\\"b"', 'displayName eq ""', 'displayName eq "Second" ', 'displayName\teq\t"Second"', ' displayName eq "Second"',
  'displayName eq "Second"\n', 'displayName co "x"', 'displayName sw "x"', 'displayName pr', 'displayName ne "x"', 'displayName eq "a" and active eq true', 'not (active eq true)', 'capabilities[value eq "a"]',
  'unknownAttr eq "x"', 'displayName eq x', 'displayName eq', ' ', 'displayName eq "unterminated', 'a'.repeat(2000), 'externalId eq "nope"', 'active eq "true"', 'displayName eq "x y"', 'dïsplayName eq "x"'];
for (const [i, f] of filters.entries()) await run(`filter/${i}`, 'open', SETUP, [get({ filter: f })]);
for (const [i, f] of ([['a'], 5, true, null, {}, ''] as any[]).entries()) await run(`filter/hostile${i}`, 'open', SETUP, [get({ filter: f })]);
const pages: any[] = [{ startIndex: '2' }, { startIndex: '0' }, { startIndex: '-3' }, { startIndex: 'abc' }, { startIndex: '' }, { startIndex: '1.5' }, { startIndex: '0x2' }, { startIndex: '1e0' }, { startIndex: ' 2 ' }, { startIndex: 'Infinity' },
  { startIndex: '2.0' }, { startIndex: '9007199254740993' }, { startIndex: '1e21' }, { startIndex: 2 }, { startIndex: null }, { startIndex: [2] }, { startIndex: {} }, { startIndex: true }, { startIndex: '.5e1' }, { startIndex: '0b1' },
  { count: '1' }, { count: '0' }, { count: '-1' }, { count: 'x' }, { count: '' }, { count: '100' }, { count: '1.5' }, { count: 1 }, { count: null }, { count: '1e1' }, { startIndex: '2', count: '1' }, { startIndex: '3', count: '5' },
  { startIndex: '1', count: '1', filter: 'active eq true' }, { filter: 'active eq false', startIndex: '1' }];
for (const [i, q] of pages.entries()) await run(`page/${i}`, 'open', SETUP, [get(q)]);
await run('page/empty', 'open', [], [get({ count: '5' }), get({ filter: 'id eq "x"' })]);
await run('get/query-str', 'open', SETUP, [get('x'), get(null), get(5)]);

// ---- PUT ----------------------------------------------------------------------------------------------------------
const put = (id: any, body: any) => ({ method: 'PUT', id, body });
const putBodies: any[] = [{ displayName: 'New', owner: 'o2', capabilities: ['x'], active: false, externalId: 'e', holder: 'h' }, {}, { displayName: 'Only' }, { owner: '' }, { owner: 'z' }, { active: 'false' }, { active: 5 }, { capabilities: 'x' }, null, 'x', [], 5,
  { model: 'ignored', operator: 'fallback' }, { passport: { operator: 'pop' } }, { displayName: 5, externalId: 5, holder: 5 }];
for (const [i, b] of putBodies.entries()) await run(`put/${i}`, 'tick', SETUP, [put(ID1, b)]);
await run('put/missing', 'open', SETUP, [put('nope', {}), { method: 'PUT', body: {} }]);

// ---- PATCH --------------------------------------------------------------------------------------------------------
const patch = (id: any, body: any) => ({ method: 'PATCH', id, body });
const ops = (...o: any[]) => ({ schemas: [M.PATCH_OP_SCHEMA], Operations: o });
const patches: any[] = [
  ops({ op: 'replace', path: 'active', value: false }), ops({ op: 'replace', path: 'active', value: 'false' }), ops({ op: 'replace', path: 'active', value: 'x' }), ops({ op: 'remove', path: 'active' }), ops({ op: 'add', path: 'active', value: true }),
  ops({ op: 'replace', path: 'displayName', value: 'D' }), ops({ op: 'replace', path: 'displayName', value: 5 }), ops({ op: 'remove', path: 'displayName' }), ops({ op: 'remove', path: 'owner' }), ops({ op: 'replace', path: 'owner', value: 'o' }),
  ops({ op: 'remove', path: 'externalId' }), ops({ op: 'remove', path: 'holder' }), ops({ op: 'add', path: 'holder', value: 'h2' }), ops({ op: 'replace', path: 'externalId', value: 'e2' }),
  ops({ op: 'add', path: 'capabilities', value: ['c'] }), ops({ op: 'replace', path: 'capabilities', value: ['c'] }), ops({ op: 'remove', path: 'capabilities' }), ops({ op: 'add', path: 'capabilities', value: 'c' }), ops({ op: 'add', path: 'capabilities', value: [1] }),
  ops({ op: 'REPLACE', path: 'active', value: false }), ops({ op: 'Add', path: 'capabilities', value: [] }), ops({ op: 'replace', value: { active: false, displayName: 'P', capabilities: ['q'] } }), ops({ op: 'add', value: { holder: 'hh' } }),
  ops({ op: 'replace', value: { id: 'x' } }), ops({ op: 'replace', value: { passport: {} } }), ops({ op: 'replace', value: { '1': 'x', active: true } }), ops({ op: 'replace', value: { active: true, '2': 'x', '1': 'y' } }), ops({ op: 'replace', value: 'x' }), ops({ op: 'replace', value: null }), ops({ op: 'replace' }),
  ops({ op: 'remove' }), ops({ op: 'replace', path: 'id', value: 'x' }), ops({ op: 'replace', path: 'meta', value: {} }), ops({ op: 'replace', path: 'passport', value: {} }), ops({ op: 'replace', path: 'unknown', value: 1 }), ops({ op: 'replace', path: '', value: 1 }),
  ops({ op: 'move', path: 'active' }), ops({ op: 5 }), ops({ op: null }), ops({ op: 1.5 }), ops({ op: 1e21 }), ops({ op: 1e-7 }), ops({ op: [1, null, 'a'] }), ops({ op: {} }), ops({ op: true }), ops({}), ops(5), ops(null), ops('x'), ops([]),
  ops({ op: 'replace', path: 5, value: 1 }), ops({ op: 'replace', path: 'active', value: false }, { op: 'add', path: 'capabilities', value: ['z'] }, { op: 'replace', path: 'displayName', value: 'Multi' }),
  ops({ op: 'replace', path: 'active', value: false }, { op: 'bad' }), { schemas: [M.PATCH_OP_SCHEMA] }, { Operations: [] }, { Operations: 'x' }, { Operations: {} }, null, 'x', [], 5,
  ops({ op: 'add', path: 'capabilities', value: ['a'] }, { op: 'add', path: 'capabilities', value: ['b'] }),
];
for (const [i, b] of patches.entries()) await run(`patch/${i}`, 'tick', SETUP, [patch(ID1, b)]);
await run('patch/missing', 'open', SETUP, [patch('nope', ops({ op: 'remove', path: 'active' })), { method: 'PATCH', body: ops() }]);
await run('patch/twice', 'tick', SETUP, [patch(ID1, ops({ op: 'replace', path: 'displayName', value: 'A' })), patch(ID1, ops({ op: 'add', path: 'capabilities', value: ['n'] })), get(undefined, ID1)]);

// ---- DELETE + methods ---------------------------------------------------------------------------------------------
await run('delete/ok', 'open', SETUP, [{ method: 'DELETE', id: ID1 }, get(undefined, ID1), get(), { method: 'DELETE', id: ID1 }]);
await run('delete/noid', 'open', SETUP, [{ method: 'DELETE' }, { method: 'POST', id: ID1, body: FLAT }, { method: 'OPTIONS' }, { method: 'get' }, {}, { method: 5 }, { method: null }, { method: 'HEAD', id: ID1 }]);

// ---- pure mapping + envelope helpers ------------------------------------------------------------------------------
const IDS: any[] = [
  { model_id: 'claude', operator: 'anthropic', hardware_rooted: false, issued_at: 5 },
  { model_id: 'gpt', operator: 'openai', hardware_rooted: true, issued_at: 9, weights_digest: 'w', system_prompt_digest: 's', tool_manifest_digest: 't', runtime_measurement: '3', weights_measured: true },
  { model_id: 'é', operator: 'o p', hardware_rooted: false, issued_at: 0 },
];
for (const [i, id] of IDS.entries()) {
  await o.run('passportFingerprint', `i${i}`, M.passportFingerprint, [id]);
  await o.run('issuePassport', `i${i}`, M.issuePassport, [id]);
}
const PASSPORTS = IDS.map((i) => M.issuePassport(i));
const projs: any[] = [{ owner: 'org' }, { owner: 'org', displayName: 'N', externalId: 'x', active: false, capabilities: ['a', 'b'], holder: 'h' }, { owner: '', capabilities: [] }, { owner: 'o', displayName: null, active: null, capabilities: null },
  { owner: 'o', externalId: null }, { owner: 'o', holder: null }, {}];
const metas: any[] = [{ created: '2024-01-01T00:00:00.000Z', lastModified: '2024-01-02T00:00:00.000Z' }, { baseUrl: 'https://s.example/v2/', created: 'c', lastModified: 'l' }, { baseUrl: '', created: 'c', lastModified: 'l' },
  { baseUrl: 'https://s.example///', created: 'c', lastModified: 'l' }, { created: 'c', lastModified: 'l', baseUrl: 'h' }];
for (const [i, p] of PASSPORTS.entries()) for (const [j, pr] of projs.entries()) for (const [k, m] of metas.entries()) {
  if (k > 1 && j > 1) continue;
  await o.run('passportToScim', `p${i}j${j}m${k}`, M.passportToScim, [p, pr, m]);
}
const nowMeta = [0, 1700000000123, 4102444800000, -1, 1.9, 253402300799999];
for (const [i, t] of nowMeta.entries()) await o.run('passportToScim', `now${i}`, (p: any, pr: any, ms: number) => M.passportToScim(p, pr, { now: () => ms }), [PASSPORTS[0], projs[0], t]);
for (const [i, p] of [{ ...PASSPORTS[0], id: 'a b/é?#' }, { ...PASSPORTS[0], id: "x!~*'()-_." }].entries()) await o.run('passportToScim', `id${i}`, M.passportToScim, [p, projs[0], { baseUrl: 'b', created: 'c', lastModified: 'l' }]);

const reqBodies = [FLAT, NESTED, FLAT2, ...badBodies];
for (const [i, b] of reqBodies.entries()) await o.run('scimToProvisioningRequest', `b${i}`, M.scimToProvisioningRequest, [b]);
for (const [i, f] of filters.entries()) await o.run('parseFilter', `f${i}`, M.parseFilter, [f]);
for (const [i, f] of ([['a'], 5, true, null, {}, ''] as any[]).entries()) await o.run('parseFilter', `h${i}`, M.parseFilter, [f]);
for (const [i, a] of ([[404, 'nf'], [400, 'bad', 'invalidFilter'], [500, ''], [201, 'x', undefined]] as any[]).entries()) await o.run('scimError', `e${i}`, M.scimError, a);
await o.run('scimListResponse', 'l0', M.scimListResponse, [[], 0, 1]);
await o.run('scimListResponse', 'l1', M.scimListResponse, [[{ id: 'a' }, { id: 'b' }], 5, 3]);
await o.run('registry', 'r0', (ps: any[], id: string) => { const r = M.buildRegistry(ps); return { all: r.all(), has: r.has(id), get: r.get(id) ?? null }; }, [PASSPORTS, PASSPORTS[1].id]);
await o.run('registry', 'r1', (ps: any[], id: string) => { const r = M.buildRegistry(ps); return { all: r.all(), has: r.has(id), get: r.get(id) ?? null }; }, [[PASSPORTS[0], PASSPORTS[0]], 'nope']);

// ---- push adapters ------------------------------------------------------------------------------------------------
const AGENTS = [
  M.passportToScim(PASSPORTS[0], projs[0], metas[0]), M.passportToScim(PASSPORTS[1], projs[1], metas[0]), M.passportToScim(PASSPORTS[2], { owner: 'o', externalId: 'ext' }, metas[0]),
];
for (const [i, a] of AGENTS.entries()) {
  await o.run('toEntraAgentPayload', `a${i}`, M.toEntraAgentPayload, [a]);
  await o.run('toOktaScimPayload', `a${i}`, M.toOktaScimPayload, [a]);
}
const FETCH: Record<string, (calls: any[]) => any> = {
  ok201: (calls) => async (url: string, init: any) => { calls.push({ url, init }); return { ok: true, status: 201, json: async () => ({ id: 'obj-1' }) }; },
  err500: (calls) => async (url: string, init: any) => { calls.push({ url, init }); return { ok: false, status: 500, json: async () => ({ detail: 'x' }) }; },
  badjson: (calls) => async (url: string, init: any) => { calls.push({ url, init }); return { ok: true, status: 204, json: async () => { throw new Error('no body'); } }; },
  nullbody: (calls) => async (url: string, init: any) => { calls.push({ url, init }); return { ok: true, status: 200, json: async () => null }; },
};
const push = async (fn: string, agent: any, mode: string) => {
  const calls: any[] = [];
  const target = { endpoint: 'https://dir.example/scim/Agents', token: 'TOK', fetch: FETCH[mode](calls) };
  const result = await M[fn](agent, target);
  return { result, calls };
};
for (const fn of ['pushToEntra', 'pushToOkta']) for (const [i, a] of AGENTS.entries()) for (const m of Object.keys(FETCH)) await o.run(fn, `a${i}/${m}`, push, [fn, a, m]);
await o.run('pushProvision', 'entra', async (agent: any, mode: string) => {
  const calls: any[] = [];
  const result = await M.pushProvision(M.toEntraAgentPayload(agent), { endpoint: 'e', token: 't', fetch: FETCH[mode](calls) });
  return { result, calls };
}, [AGENTS[1], 'ok201']);

refWrite(o, 'scim');
