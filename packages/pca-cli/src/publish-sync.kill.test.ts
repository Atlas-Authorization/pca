import { existsSync, mkdtempSync, readFileSync, rmSync, truncateSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { b64u, generateKeyPair, hashCanonical } from '@atlasauth/pca';
import { defsToYaml, loadActionsText } from '@atlasauth/pca-actions';
import { cmdBuild, cmdInit, cmdPublish, cmdSign, cmdSync, publishToRegistry, SYNC_MAX_BYTES, type SourceFetch } from './actions';

afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

const tmp = (): string => mkdtempSync(join(tmpdir(), 'pcacli-ps-'));
const put = (dir: string, name: string, text: string): string => { const f = join(dir, name); writeFileSync(f, text); return f; };
const read = (...p: string[]): string => readFileSync(join(...p), 'utf8');
const REG_URL = '/v1/pca/action-registry/packs';

interface Call { url: string; init: { method: string; headers: Record<string, string>; body: string } }
interface Reply { status: number; body: unknown }
function recorder(registry: Reply, schema: Reply = { status: 201, body: { digest: 'd1', anchor: { index: 7 } } }) {
  const calls: Call[] = [];
  const fetchImpl = async (url: string, init: Call['init']) => {
    calls.push({ url, init });
    const r = url.endsWith(REG_URL) ? registry : schema;
    return { status: r.status, json: async () => r.body };
  };
  return { fetchImpl: fetchImpl as never, calls };
}

function signed(template = 'minimal', ns = 'acme') {
  const root = tmp();
  const dir = join(root, 'actions');
  const out = join(root, '.pca');
  expect(cmdInit({ dir, ns, template }).ok).toBe(true);
  expect(cmdBuild([dir], { out }).ok).toBe(true);
  const s = cmdSign([dir], { out, kid: 'k', key: b64u(generateKeyPair().secretKey) });
  expect(s.ok, s.text).toBe(true);
  return { root, dir, out };
}

// ---- cmdPublish -------------------------------------------------------------------------------------------------------------------

describe('cmdPublish', () => {
  it('without a build and a signature it says so with the reason', async () => {
    const root = tmp();
    const dir = join(root, 'actions');
    cmdInit({ dir, ns: 'acme' });
    const r = await cmdPublish([dir], { out: join(root, 'nothing') });
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/^run pca actions build and sign first \(.+\)$/);
  });
  it('writes the discovery file and says where; a pack that does not verify is refused before anything is written', async () => {
    const { dir, out } = signed();
    const wk = join(out, '.well-known', 'pca-actions.json');
    const bad = JSON.parse(read(out, 'pack.signed.json'));
    bad.sig.alg = 'rsa';
    const good = read(out, 'pack.signed.json');
    put(out, 'pack.signed.json', JSON.stringify(bad));
    expect(await cmdPublish([dir], { out })).toEqual({ ok: false, text: 'not publishing: missing or malformed signature' });
    expect(existsSync(wk)).toBe(false);
    put(out, 'pack.signed.json', good);
    expect(await cmdPublish([dir], { out })).toEqual({ ok: true, text: `wrote ${wk}` });
    expect(readFileSync(wk, 'utf8')).toBe(read(out, 'pca-actions.json'));
  });
  it('--api and --sk go together, in either direction', async () => {
    const { dir, out } = signed();
    const want = { ok: false, text: 'publish: --api and --sk go together' };
    expect(await cmdPublish([dir], { out, api: 'https://api.example.com' })).toEqual(want);
    expect(await cmdPublish([dir], { out, sk: 'sk_x' })).toEqual(want);
    expect(await cmdPublish([dir], { out, api: '', sk: 'sk_x' })).toEqual(want);
    expect(await cmdPublish([dir], { out, api: 'https://api.example.com', sk: '' })).toEqual(want);
  });
  it('a refused anchor stops there and is the whole answer', async () => {
    const { dir, out } = signed();
    const { fetchImpl, calls } = recorder({ status: 201, body: {} }, { status: 500, body: {} });
    expect(await cmdPublish([dir], { out, api: 'https://api.example.com', sk: 'sk_x', fetchImpl })).toEqual({ ok: false, text: 'FAIL  HTTP 500' });
    expect(calls).toHaveLength(1);
  });
  it('anchors, then publishes the pack with its rules document and custom traits', async () => {
    const root = tmp();
    const dir = join(root, 'actions');
    const out = join(root, '.pca');
    expect(cmdInit({ dir, ns: 'store', template: 'ecommerce' }).ok).toBe(true);
    expect(cmdBuild([dir], { out }).ok).toBe(true);
    expect(cmdSign([dir], { out, kid: 'k', key: b64u(generateKeyPair().secretKey) }).ok).toBe(true);
    const cfg = JSON.parse(read(dir, 'pca.config.json')) as { traits: unknown[] };
    const { fetchImpl, calls } = recorder({ status: 201, body: { version: '0.1.0', status: 'active', changes: [] } });
    const r = await cmdPublish([dir], { out, api: 'https://api.example.com/', sk: 'sk_x', fetchImpl });
    expect(r.ok, r.text).toBe(true);
    expect(r.text).toBe(`wrote ${join(out, '.well-known', 'pca-actions.json')}\nOK  anchored d1 at log index 7\nregistry: store@0.1.0 active`);
    expect(calls.map((c) => c.url)).toEqual(['https://api.example.com/v1/pca/intent/schemas', `https://api.example.com${REG_URL}`]);
    const body = JSON.parse(calls[1]!.init.body) as { pack: unknown; rules: unknown; traits: unknown };
    expect(body.pack).toEqual(JSON.parse(read(out, 'pack.signed.json')));
    expect(body.rules).toEqual(JSON.parse(read(out, 'rules.json')));
    expect(body.traits).toEqual(cfg.traits);
    expect(cfg.traits.length).toBeGreaterThan(0);
  });
  it('without custom traits or a rules document the request carries only the pack; without a config it still publishes', async () => {
    const { dir, out } = signed();
    const a = recorder({ status: 201, body: {} });
    expect((await cmdPublish([dir], { out, api: 'https://api.example.com', sk: 'sk_x', fetchImpl: a.fetchImpl })).ok).toBe(true);
    expect(Object.keys(JSON.parse(a.calls[1]!.init.body)).sort()).toEqual(['pack', 'rules']);
    rmSync(join(out, 'rules.json'));
    rmSync(join(dir, 'pca.config.json'));
    const b = recorder({ status: 201, body: {} });
    expect((await cmdPublish([dir], { out, api: 'https://api.example.com', sk: 'sk_x', fetchImpl: b.fetchImpl })).ok).toBe(true);
    expect(Object.keys(JSON.parse(b.calls[1]!.init.body))).toEqual(['pack']);
  });
  it('a rules document that is not JSON stops the publish after the anchor, naming the problem', async () => {
    const { dir, out } = signed();
    put(out, 'rules.json', '{nope');
    const { fetchImpl, calls } = recorder({ status: 201, body: {} });
    const r = await cmdPublish([dir], { out, api: 'https://api.example.com', sk: 'sk_x', fetchImpl });
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/^rules\.json is not JSON: .+/);
    expect(calls).toHaveLength(1);
  });
  it('a refusal by the registry keeps what was already done in the answer', async () => {
    const { dir, out } = signed();
    const { fetchImpl } = recorder({ status: 409, body: { errors: [{ message: 'Widening without review', meta: { reason_code: 'widen_unreviewed', verbs: ['acme.invoice.send'] } }] } });
    const r = await cmdPublish([dir], { out, api: 'https://api.example.com', sk: 'sk_x', fetchImpl });
    expect(r).toEqual({
      ok: false,
      text: `wrote ${join(out, '.well-known', 'pca-actions.json')}\nOK  anchored d1 at log index 7\nFAIL  the registry refused the pack (409 widen_unreviewed): Widening without review\n  needs a reviewer: acme.invoice.send`,
    });
  });
});

// ---- publishToRegistry ------------------------------------------------------------------------------------------------------------

describe('publishToRegistry', () => {
  const pack = { ns: 'acme', version: '0.1.0' } as never;
  const run = (reply: Reply | (() => Promise<{ status: number; json(): Promise<unknown> }>), extra: Record<string, unknown> = {}) => {
    const calls: Call[] = [];
    const fetchImpl = async (url: string, init: Call['init']) => { calls.push({ url, init }); return typeof reply === 'function' ? reply() : { status: reply.status, json: async () => reply.body }; };
    return publishToRegistry({ api: 'https://api.example.com', sk: 'sk_x', pack, fetchImpl: fetchImpl as never, ...extra }).then((r) => ({ r, calls }));
  };

  it('without a fetch it says so; the global fetch is the default', async () => {
    vi.stubGlobal('fetch', undefined);
    expect(await publishToRegistry({ api: 'https://api.example.com', sk: 'sk_x', pack })).toEqual({ ok: false, text: 'no fetch available' });
    const seen: string[] = [];
    vi.stubGlobal('fetch', async (u: string) => { seen.push(u); return { status: 201, json: async () => ({}) }; });
    expect((await publishToRegistry({ api: 'https://api.example.com', sk: 'sk_x', pack })).ok).toBe(true);
    expect(seen).toEqual([`https://api.example.com${REG_URL}`]);
  });
  it('posts JSON with the bearer key to the registry, however many slashes end the address', async () => {
    const { calls } = await run({ status: 201, body: {} }, { api: 'https://api.example.com///' });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(`https://api.example.com${REG_URL}`);
    expect(calls[0]!.init.method).toBe('POST');
    expect(calls[0]!.init.headers).toEqual({ 'content-type': 'application/json', authorization: 'Bearer sk_x' });
    expect(JSON.parse(calls[0]!.init.body)).toEqual({ pack });
  });
  it('rules and custom traits are sent when given', async () => {
    const traits = [{ id: 'acme.x' }];
    const rules = { v: 1, kind: 'pca-action-rules' };
    expect(JSON.parse((await run({ status: 201, body: {} }, { rules })).calls[0]!.init.body)).toEqual({ pack, rules });
    expect(JSON.parse((await run({ status: 201, body: {} }, { traits })).calls[0]!.init.body)).toEqual({ pack, traits });
    expect(JSON.parse((await run({ status: 201, body: {} }, { rules, traits })).calls[0]!.init.body)).toEqual({ pack, rules, traits });
    expect(JSON.parse((await run({ status: 201, body: {} }, { rules: 0 })).calls[0]!.init.body)).toEqual({ pack, rules: 0 });
  });
  it('only a 2xx status is a success', async () => {
    for (const status of [200, 201, 299]) expect((await run({ status, body: {} })).r.ok, String(status)).toBe(true);
    for (const status of [199, 300, 301, 404, 500]) expect((await run({ status, body: {} })).r.ok, String(status)).toBe(false);
  });
  it('a refusal names the status, the reason code, the reason and the actions that need a reviewer', async () => {
    const e = (message: string | undefined, meta: unknown) => ({ errors: [{ ...(message !== undefined ? { message } : {}), ...(meta !== undefined ? { meta } : {}) }] });
    const text = async (status: number, body: unknown) => (await run({ status, body })).r.text;
    expect(await text(409, e('Widening', { reason_code: 'widen_unreviewed', verbs: ['a.x.y', 'a.x.z'] }))).toBe('FAIL  the registry refused the pack (409 widen_unreviewed): Widening\n  needs a reviewer: a.x.y, a.x.z');
    expect(await text(409, e('Widening', { reason_code: 'widen_unreviewed' }))).toBe('FAIL  the registry refused the pack (409 widen_unreviewed): Widening');
    expect(await text(409, e('Widening', { verbs: [] }))).toBe('FAIL  the registry refused the pack (409): Widening');
    expect(await text(409, e('Widening', {}))).toBe('FAIL  the registry refused the pack (409): Widening');
    expect(await text(403, e('Not allowed', undefined))).toBe('FAIL  the registry refused the pack (403): Not allowed');
    expect(await text(409, e(undefined, { reason_code: 'r1' }))).toBe('FAIL  the registry refused the pack (409 r1): no reason given');
    expect(await text(500, {})).toBe('FAIL  the registry refused the pack (500): no reason given');
    expect(await text(500, { errors: [] })).toBe('FAIL  the registry refused the pack (500): no reason given');
    expect(await text(500, null)).toBe('FAIL  the registry refused the pack (500): no reason given');
    const broken = await run(async () => ({ status: 502, json: async () => { throw new Error('not json'); } }));
    expect(broken.r).toEqual({ ok: false, text: 'FAIL  the registry refused the pack (502): no reason given' });
  });
  it('a success names the pack, version and status, then one line per change', async () => {
    const pad = (c: string) => c.padEnd(12);
    const body = { version: '2.0.0', status: 'active', changes: [{ verb: 'a.x.y', class: 'added' }, { verb: 'a.x.z', class: 'widen', reasons: ['r1', 'r2'] }, { verb: 'q.r.s', class: 'equal', reasons: [] }] };
    expect((await run({ status: 201, body })).r).toEqual({ ok: true, text: `registry: acme@2.0.0 active\n  ${pad('added')} a.x.y\n  ${pad('widen')} a.x.z: r1, r2\n  ${pad('equal')} q.r.s` });
    expect((await run({ status: 201, body: {} })).r).toEqual({ ok: true, text: 'registry: acme@0.1.0 stored' });
    expect((await run({ status: 201, body: { changes: [] } })).r).toEqual({ ok: true, text: 'registry: acme@0.1.0 stored' });
    expect((await run(async () => ({ status: 201, json: async () => { throw new Error('empty'); } }))).r).toEqual({ ok: true, text: 'registry: acme@0.1.0 stored' });
    expect((await run({ status: 201, body: { version: '1.1.0' } })).r.text).toBe('registry: acme@1.1.0 stored');
  });
});

// ---- cmdSync -------------------------------------------------------------------------------------------------------------------

const API = (ops: Record<string, unknown>): string => JSON.stringify({ openapi: '3.0.0', paths: ops });
const idParam = [{ name: 'id', in: 'path', required: true, schema: { type: 'string', maxLength: 40 } }];
const getOrder = { '/orders/{id}': { parameters: idParam, get: { operationId: 'getOrder', summary: 'Get an order' } } };
const cancelOrder = { '/orders/{id}/cancel': { parameters: idParam, post: { operationId: 'cancelOrder', summary: 'Cancel an order' } } };

function syncProject(spec: string, sources?: unknown[]) {
  const root = tmp();
  const dir = join(root, 'actions');
  expect(cmdInit({ dir, ns: 'shop' }).ok).toBe(true);
  writeFileSync(join(root, 'openapi.json'), spec);
  const cfg = JSON.parse(read(dir, 'pca.config.json'));
  put(dir, 'pca.config.json', JSON.stringify({ ...cfg, sources: sources ?? [{ name: 'api', from: 'openapi', file: '../openapi.json' }] }));
  return { root, dir, lock: join(dir, 'pca.sync.json'), file: join(dir, 'api.sync.yaml') };
}

describe('cmdSync refusals', () => {
  it('without a config it names every path', async () => {
    const a = tmp();
    const b = tmp();
    expect(await cmdSync([a, b])).toEqual({ ok: false, text: `no pca.config.json next to ${a}, ${b}` });
  });
  it('without sources it shows how to add them', async () => {
    const { dir } = project0();
    expect(await cmdSync([dir])).toEqual({ ok: false, text: 'pca.config.json names no sources (add "sources": [{"name", "from", "url" | "file"}])' });
  });
  it('a lock file that is not JSON stops the sync', async () => {
    const p = syncProject(API(getOrder));
    put(p.dir, 'pca.sync.json', '{nope');
    const r = await cmdSync([p.dir]);
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/^pca\.sync\.json is not JSON: .+/);
    expect(existsSync(p.file)).toBe(false);
  });
  it('an unknown source name is refused; a known one syncs only that source', async () => {
    const p = syncProject(API(getOrder), [{ name: 'api', from: 'openapi', file: '../openapi.json' }, { name: 'web', from: 'openapi', file: '../openapi.json' }]);
    expect(await cmdSync([p.dir], { source: 'zz' })).toEqual({ ok: false, text: "no source named 'zz'" });
    const r = await cmdSync([p.dir], { source: 'web', now: 1_700_000_000_000 });
    expect(r.ok, r.text).toBe(true);
    expect(r.text.startsWith('web (openapi):\n')).toBe(true);
    expect(r.text).not.toContain('api (openapi)');
    expect(existsSync(join(p.dir, 'web.sync.yaml'))).toBe(true);
    expect(existsSync(p.file)).toBe(false);
    expect(Object.keys(JSON.parse(read(p.dir, 'pca.sync.json')))).toEqual(['web']);
  });
  it('a source that cannot be read, imported or loaded is reported under its name', async () => {
    const p = syncProject(API(getOrder));
    writeFileSync(join(p.root, 'openapi.json'), '{nope');
    const bad = await cmdSync([p.dir]);
    expect(bad.ok).toBe(false);
    expect(bad.text).toMatch(/^api: the source is not JSON: .+/);
    const gone = syncProject(API(getOrder));
    rmSync(join(gone.root, 'openapi.json'));
    const r = await cmdSync([gone.dir]);
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/^api: .*ENOENT/);
    const corrupt = syncProject(API(getOrder));
    put(corrupt.dir, 'api.sync.yaml', 'ns: [unterminated');
    const c = await cmdSync([corrupt.dir]);
    expect(c.ok).toBe(false);
    expect(c.text.startsWith(`${corrupt.file}: `)).toBe(true);
  });
});

function project0() {
  const root = tmp();
  const dir = join(root, 'actions');
  expect(cmdInit({ dir, ns: 'shop' }).ok).toBe(true);
  return { root, dir };
}

describe('cmdSync results', () => {
  it('a first sync lists what was added, notes the review, and writes the file and the lock', async () => {
    const spec = API(getOrder);
    const p = syncProject(spec);
    const r = await cmdSync([p.dir], { now: 1_700_000_999_000 });
    expect(r.ok, r.text).toBe(true);
    expect(r.text).toMatch(/^api \(openapi\):\n {2}added {5}shop\.[a-z0-9_.]+\n {2}1 added, 0 changed, 0 removed \(deprecated\), 0 unchanged; added and changed actions are unreviewed \(strict\) until a reviewer confirms them$/);
    const lock = JSON.parse(read(p.dir, 'pca.sync.json')) as Record<string, { spec_digest: string; synced_at: number; ops: Record<string, string> }>;
    expect(read(p.dir, 'pca.sync.json')).toBe(JSON.stringify(lock, null, 2) + '\n');
    expect(lock.api!.synced_at).toBe(1_700_000_999);
    expect(lock.api!.spec_digest).toBe(hashCanonical(spec));
    expect(Object.keys(lock.api!.ops)).toHaveLength(1);
    const text = read(p.file);
    expect(text.startsWith('# Generated by pca actions sync from ../openapi.json (openapi). Add rules under an action; re-run sync to refresh.\n')).toBe(true);
    const l = loadActionsText(text);
    expect(l.errors).toEqual([]);
    expect(l.defs).toHaveLength(1);
    expect(l.defs[0]!.source?.uri).toBe('../openapi.json');
  });
  it('without a given time the lock records the current one in seconds', async () => {
    const p = syncProject(API(getOrder));
    await cmdSync([p.dir]);
    const at = (JSON.parse(read(p.lock)) as Record<string, { synced_at: number }>).api!.synced_at;
    expect(Number.isInteger(at)).toBe(true);
    expect(at).toBeGreaterThan(1_700_000_000);
    expect(at).toBeLessThan(Math.floor(Date.now() / 1000) + 5);
  });
  it('two sources are listed one after the other, each with its own heading', async () => {
    const p = syncProject(API(getOrder), [{ name: 'api', from: 'openapi', file: '../openapi.json' }, { name: 'web', from: 'openapi', file: '../openapi.json' }]);
    const r = await cmdSync([p.dir]);
    expect(r.text.split('\n').filter((l) => /^\S/.test(l))).toEqual(['api (openapi):', 'web (openapi):']);
    expect(r.text.indexOf('api (openapi):')).toBeLessThan(r.text.indexOf('web (openapi):'));
  });
  it('a check reports a change and writes nothing; once synced it passes; a plain sync after a change says nothing about checking', async () => {
    const p = syncProject(API(getOrder));
    await cmdSync([p.dir]);
    expect(await cmdSync([p.dir], { check: true })).toMatchObject({ ok: true });
    expect(await cmdSync([p.dir], { check: true })).toEqual({ ok: true, text: 'api (openapi):\n  0 added, 0 changed, 0 removed (deprecated), 1 unchanged' });
    writeFileSync(join(p.root, 'openapi.json'), API({ ...getOrder, ...cancelOrder }));
    const before = [read(p.file), read(p.lock)];
    const chk = await cmdSync([p.dir], { check: true });
    expect(chk.ok).toBe(false);
    expect(chk.text.endsWith('\nthe sources changed: run pca actions sync and review the added and changed actions')).toBe(true);
    expect([read(p.file), read(p.lock)]).toEqual(before);
    const real = await cmdSync([p.dir]);
    expect(real.ok).toBe(true);
    expect(real.text).not.toContain('the sources changed');
    expect(loadActionsText(read(p.file)).defs).toHaveLength(2);
  });
  it('the business rules written under an action survive a later sync', async () => {
    const p = syncProject(API(getOrder));
    await cmdSync([p.dir]);
    const l = loadActionsText(read(p.file));
    const verb = l.defs[0]!.verb;
    writeFileSync(p.file, defsToYaml('shop', l.defs, { [verb]: { required: ['id'] } }));
    expect(loadActionsText(read(p.file)).rules[verb]).toEqual({ required: ['id'] });
    writeFileSync(join(p.root, 'openapi.json'), API({ ...getOrder, ...cancelOrder }));
    const r = await cmdSync([p.dir]);
    expect(r.ok, r.text).toBe(true);
    const after = loadActionsText(read(p.file));
    expect(after.defs).toHaveLength(2);
    expect(Object.keys(after.rules)).toEqual([verb]);
    expect(after.rules[verb]).toEqual({ required: ['id'] });
  });
  it('a JSON Schema source takes its action name from the config', async () => {
    const schema = JSON.stringify({ title: 'Ping', properties: { host: { type: 'string', maxLength: 64 } }, required: ['host'] });
    const p = syncProject(schema, [{ name: 'ping', from: 'jsonschema', file: '../openapi.json', verb: 'shop.host.ping' }]);
    const r = await cmdSync([p.dir]);
    expect(r.ok, r.text).toBe(true);
    expect(loadActionsText(read(p.dir, 'ping.sync.yaml')).defs.map((d) => d.verb)).toEqual(['shop.host.ping']);
  });
  it('a file source larger than the cap is refused, one at the cap is read', async () => {
    const p = syncProject(API(getOrder));
    const f = join(p.root, 'openapi.json');
    truncateSync(f, SYNC_MAX_BYTES + 1);
    expect(await cmdSync([p.dir])).toEqual({ ok: false, text: `api: ../openapi.json is larger than ${SYNC_MAX_BYTES} bytes` });
    truncateSync(f, SYNC_MAX_BYTES);
    const at = await cmdSync([p.dir]);
    expect(at.ok).toBe(false);
    expect(at.text).not.toMatch(/larger than/);
  });
});

describe('cmdSync over https', () => {
  const urlProject = (spec = API(getOrder)) => syncProject(spec, [{ name: 'api', from: 'openapi', url: 'https://api.example.com/openapi.json' }]);
  const ok = (text: string, length: string | null = null): SourceFetch => async () => ({ ok: true, status: 200, headers: { get: (k) => (k.toLowerCase() === 'content-length' ? length : null) }, text: async () => text });

  it('asks for the document with GET, the accepted types, no redirects and a signal; the url is the recorded source', async () => {
    const p = urlProject();
    const seen: Array<Parameters<SourceFetch>> = [];
    const f: SourceFetch = async (...a) => { seen.push(a); return ok(API(getOrder))(...a); };
    const r = await cmdSync([p.dir], { fetchImpl: f });
    expect(r.ok, r.text).toBe(true);
    expect(seen).toHaveLength(1);
    const [url, init] = seen[0]!;
    expect(url).toBe('https://api.example.com/openapi.json');
    expect(init.method).toBe('GET');
    expect(init.headers).toEqual({ accept: 'application/json, application/yaml, text/plain' });
    expect(init.redirect).toBe('error');
    expect(init.signal).toBeInstanceOf(AbortSignal);
    expect(read(p.file).startsWith('# Generated by pca actions sync from https://api.example.com/openapi.json (openapi).')).toBe(true);
    expect(loadActionsText(read(p.file)).defs[0]!.source?.uri).toBe('https://api.example.com/openapi.json');
  });
  it('without a fetch it says so', async () => {
    const p = urlProject();
    vi.stubGlobal('fetch', undefined);
    expect(await cmdSync([p.dir])).toEqual({ ok: false, text: 'api: no fetch available' });
  });
  it('the size cap applies to the declared length and to the text, and the cap itself is allowed', async () => {
    const p = urlProject();
    const refused = `api: https://api.example.com/openapi.json is larger than ${SYNC_MAX_BYTES} bytes`;
    expect(await cmdSync([p.dir], { fetchImpl: ok('{}', String(SYNC_MAX_BYTES + 1)) })).toEqual({ ok: false, text: refused });
    const atCap = await cmdSync([p.dir], { fetchImpl: ok('{}', String(SYNC_MAX_BYTES)) });
    expect(atCap.text).not.toMatch(/larger than/);
    expect(await cmdSync([p.dir], { fetchImpl: ok('x'.repeat(SYNC_MAX_BYTES + 1)) })).toEqual({ ok: false, text: refused });
    const textAtCap = await cmdSync([p.dir], { fetchImpl: ok('x'.repeat(SYNC_MAX_BYTES)) });
    expect(textAtCap.text).not.toMatch(/larger than/);
  });
  it('a request that takes 30 seconds is aborted, and the timer is cleared once an answer arrives', async () => {
    const p = urlProject();
    vi.useFakeTimers();
    let signal: AbortSignal | undefined;
    const hang: SourceFetch = (_u, init) => new Promise<never>((_res, rej) => { signal = init.signal; init.signal.addEventListener('abort', () => rej(new Error('aborted'))); });
    const pending = cmdSync([p.dir], { fetchImpl: hang });
    await vi.advanceTimersByTimeAsync(29_999);
    expect(signal!.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(signal!.aborted).toBe(true);
    expect(await pending).toEqual({ ok: false, text: 'api: aborted' });
    expect(vi.getTimerCount()).toBe(0);
    const done = await cmdSync([p.dir], { fetchImpl: ok(API(getOrder)) });
    expect(done.ok, done.text).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });
});
