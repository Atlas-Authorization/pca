import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { b64u, generateKeyPair, publicKeyOf, sha256, unb64u, utf8 } from '@atlasauth/pca';
import {
  ACTION_TEMPLATES, cmdActionExplain, cmdBuild, cmdConfirm, cmdDiff, cmdImport, cmdImportModel, cmdInit, cmdLint, cmdPublish, cmdSign, cmdTest, collectFiles, findConfig, parseConfig,
} from './actions';
import { cmdSchemaVerify } from './schema';
import { defsToYaml, loadActionsText, type ActionDef } from '@atlasauth/pca-actions';

const roots: string[] = [];
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'pca-actions-')); roots.push(d); return d; };
afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

const key = (): string => b64u(generateKeyPair().secretKey);
const read = (...p: string[]): string => readFileSync(join(...p), 'utf8');

/** Scaffold a project and return its paths. */
function project(template = 'minimal', ns = 'acme') {
  const root = tmp();
  const dir = join(root, 'actions');
  expect(cmdInit({ dir, ns, template }).ok).toBe(true);
  return { root, dir, out: join(root, '.pca') };
}

describe('pca actions: hello world from an empty directory to a signed pack', () => {
  it('init, lint, test, explain, build, sign, publish', async () => {
    const { dir, out } = project();
    expect(cmdInit({ dir, ns: 'acme' })).toMatchObject({ ok: false, text: expect.stringMatching(/already exists/) });
    expect(existsSync(join(dir, 'acme.yaml'))).toBe(true);
    expect(JSON.parse(read(dir, 'pca.config.json'))).toMatchObject({ ns: 'acme', stability: 'draft' });

    const lint = cmdLint([dir]);
    expect(lint).toEqual({ ok: true, text: expect.stringMatching(/note +LN-001 +.*acme\.invoice\.send: idempotency_key auto-added\n0 errors, 0 warnings, 1 note$/s) });
    expect(cmdLint([dir], { strict: true }).ok).toBe(true);

    const t = cmdTest([dir]);
    expect(t.text).toMatch(/PASS {2}acme\.invoice\.send example 1: expected allow, got allow/);
    expect(t.text).toMatch(/PASS {2}acme\.invoice\.send example 2: expected escalate, got escalate/);
    expect(t.text).toMatch(/PASS {2}acme\.invoice\.send schema round trip: \d+ mutations refused/);
    expect(t.ok, t.text).toBe(true);

    // nobody has confirmed the hello-world action: it is the most dangerous kind of action until a pinned reviewer signs it
    const ex0 = cmdActionExplain([dir], 'acme.invoice.send').text.split('\n');
    expect(ex0[0]).toMatch(/^Send an invoice\. This action has not been reviewed by a person, so it is treated as the most dangerous kind of action/);
    expect(ex0[1]).toBe('effective: risk 3, irreversible, blast 1000k, escalation: stepup');
    expect(ex0.at(-2)).toBe('review: authored, not confirmed by a signed review');
    expect(ex0.at(-1)).toMatch(/as written it would be: risk 2, escalation tier 1, traits: pca\.external_communication, pca\.irreversible, pca\.pii_access$/);
    expect(cmdActionExplain([dir], 'acme.nope').ok).toBe(false);

    const b = cmdBuild([dir], { out });
    expect(b.ok, b.text).toBe(true);
    for (const f of ['schema.json', 'pack.json', 'cards.json', 'ontology.json', 'mcp.json', 'types.d.ts']) expect(existsSync(join(out, f))).toBe(true);
    expect(read(out, 'types.d.ts')).toMatch(/export interface AcmeInvoiceSendParams \{[^}]*idempotency_key: string;[^}]*invoice: string;[^}]*note: string;[^}]*to: string;/s);
    expect(read(out, 'types.d.ts')).toMatch(/export type ActionVerb = keyof ActionParams;/);
    const schema = JSON.parse(read(out, 'schema.json'));
    expect(schema).toMatchObject({ v: 2, kind: 'pca-action-schema', site: 'https://acme.example.com', aud: 'acme-api', pack: { ns: 'acme', version: '0.1.0' } });
    expect(schema.pack.root).toBe(JSON.parse(read(out, 'pack.json')).root);
    expect(JSON.parse(read(out, 'cards.json'))[0].text).toMatch(/^Send an invoice\./);

    const s = cmdSign([dir], { out, kid: 'site-1', key: key() });
    expect(s.ok, s.text).toBe(true);
    const signed = read(out, 'pca-actions.json');
    const keys = read(out, 'keys.json');
    expect(cmdSchemaVerify(signed, keys).ok).toBe(true);

    const calls: { url: string; auth: string }[] = [];
    const fetchImpl = async (url: string, init: { headers: Record<string, string> }) => {
      calls.push({ url, auth: init.headers.authorization! });
      if (url.endsWith('/v1/pca/action-registry/packs')) return { status: 201, json: async () => ({ version: '0.1.0', status: 'active', changes: [{ verb: 'acme.invoice.send', class: 'added', reasons: [] }] }) };
      return { status: 200, json: async () => ({ digest: 'd1', anchor: { index: 7 } }) };
    };
    const p = await cmdPublish([dir], { out, api: 'https://api.example.com/', sk: 'sk_test', fetchImpl });
    expect(p.ok, p.text).toBe(true);
    expect(p.text).toMatch(/anchored d1 at log index 7/);
    expect(p.text).toMatch(/registry: acme@0\.1\.0 active/);
    expect(calls).toEqual([{ url: 'https://api.example.com/v1/pca/intent/schemas', auth: 'Bearer sk_test' }, { url: 'https://api.example.com/v1/pca/action-registry/packs', auth: 'Bearer sk_test' }]);
    expect(read(out, '.well-known', 'pca-actions.json')).toBe(signed);
    expect((await cmdPublish([dir], { out, api: 'https://api.example.com' })).text).toMatch(/--api and --sk go together/);
  });
});

describe('pca actions: every template is lint-clean (no errors) and its examples hold', () => {
  for (const tpl of Object.keys(ACTION_TEMPLATES)) {
    it(`${tpl}`, () => {
      const { dir, out } = project(tpl, 'shop');
      const l = cmdLint([dir]);
      expect(l.ok, l.text).toBe(true);
      expect(l.text).toMatch(/0 errors, 0 warnings/);
      const t = cmdTest([dir]);
      expect(t.ok, t.text).toBe(true);
      expect(cmdBuild([dir], { out }).ok).toBe(true);
    });
  }
  it('init rejects an unknown template and a bad namespace', () => {
    expect(cmdInit({ dir: join(tmp(), 'a'), ns: 'x', template: 'nope' }).text).toMatch(/unknown template/);
    expect(cmdInit({ dir: join(tmp(), 'a'), ns: 'Bad!' }).text).toMatch(/--ns must be/);
  });
});

describe('pca actions lint', () => {
  const bad = `ns: acme
actions:
  - verb: acme.invoice.remove
    title: Removing invoices
    effects: [update]
    resource: acme.invoice:*@one
    params: {invoice: id:acme.invoice}
`;
  it('reports errors with the file, exits not-ok, and emits SARIF', () => {
    const { dir } = project();
    writeFileSync(join(dir, 'bad.yaml'), bad);
    const l = cmdLint([dir]);
    expect(l.ok).toBe(false);
    expect(l.text).toMatch(/error +LD-001 +.*bad\.yaml:3:5: acme\.invoice\.remove: the verb says 'remove'/);
    expect(l.text).toMatch(/error +LD-008/);
    const s = JSON.parse(cmdLint([dir], { format: 'sarif' }).text);
    expect(s.version).toBe('2.1.0');
    const rules = s.runs[0].results.map((r: { ruleId: string }) => r.ruleId);
    expect(rules).toEqual(expect.arrayContaining(['LD-001', 'LD-008', 'LW-001']));
    const loc = s.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'LD-001').locations[0].physicalLocation;
    expect(loc.artifactLocation.uri).toMatch(/bad\.yaml$/);
    expect(loc.region).toEqual({ startLine: 3, startColumn: 5 });
    expect(l.text).toMatch(/bad\.yaml:3:5: acme\.invoice\.remove/);
    // a parameter finding points at the parameter, not the action
    const p = s.runs[0].results.find((r: { message: { text: string } }) => /\[invoice\]/.test(r.message.text));
    if (p) expect(p.locations[0].physicalLocation.region.startLine).toBe(7);
  });
  it('a load error is an LD-000 finding, not a crash', () => {
    const { dir } = project();
    writeFileSync(join(dir, 'broken.yaml'), 'ns: acme\nactions: *oops\n');
    const l = cmdLint([dir]);
    expect(l.ok).toBe(false);
    expect(l.text).toMatch(/error +LD-000 +.*broken\.yaml:\d+:\d+/);
  });
  it('--strict fails on a warning', () => {
    const { dir } = project();
    writeFileSync(join(dir, 'warn.yaml'), 'ns: acme\nactions:\n  - {verb: acme.invoice.get, title: Read an invoice, description: Reads it., effects: read, resource: "acme.invoice:inv_*", params: {invoice: "id:acme.invoice"}}\n');
    expect(cmdLint([dir]).ok).toBe(true);
    expect(cmdLint([dir], { strict: true }).ok).toBe(false);
  });
  it('build refuses a project with lint errors and writes nothing', () => {
    const { root, dir, out } = project();
    writeFileSync(join(dir, 'bad.yaml'), bad);
    const b = cmdBuild([dir], { out });
    expect(b.ok).toBe(false);
    expect(b.text).toMatch(/not building/);
    expect(existsSync(join(root, '.pca', 'pack.json'))).toBe(false);
  });
  it('a missing path and a malformed config are reported', () => {
    expect(() => collectFiles(['/no/such/dir'])).toThrow(/no such file/);
    expect(parseConfig('{')).toMatch(/not JSON/);
    expect(parseConfig('{"ns":"a","version":"1","stability":"draft","site":"s","aud":"a"}')).toMatch(/semantic version/);
    expect(parseConfig('{"ns":"a","version":"1.0.0","stability":"draft","site":"s","aud":"a","x":1}')).toMatch(/unknown member 'x'/);
    const { dir } = project();
    writeFileSync(join(dir, 'pca.config.json'), '{"ns":"acme"}');
    expect(findConfig([dir])).toMatch(/version/);
    expect(cmdLint([dir]).ok).toBe(false);
  });
});

describe('pca actions sign refuses a build that was edited', () => {
  const built = () => {
    const p = project();
    expect(cmdBuild([p.dir], { out: p.out }).ok).toBe(true);
    return p;
  };
  it('a changed schema floor', () => {
    const { dir, out } = built();
    const s = JSON.parse(read(out, 'schema.json'));
    s.verbs[0].floors.esc = 0;
    writeFileSync(join(out, 'schema.json'), JSON.stringify(s));
    const r = cmdSign([dir], { out, kid: 'k', key: key() });
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/not signing: schema.json is not what the pack derives/);
    expect(existsSync(join(out, 'pca-actions.json'))).toBe(false);
  });
  it('a changed pack def', () => {
    const { dir, out } = built();
    const pk = JSON.parse(read(out, 'pack.json'));
    pk.defs[0].title = 'Send money';
    writeFileSync(join(out, 'pack.json'), JSON.stringify(pk));
    expect(cmdSign([dir], { out, kid: 'k', key: key() }).text).toMatch(/not signing: the pack root does not match its defs/);
  });
  it('a pack with an invalid def, a missing build, and a bad key', () => {
    const { dir, out } = built();
    const pk = JSON.parse(read(out, 'pack.json'));
    pk.defs[0].bogus = 1;
    writeFileSync(join(out, 'pack.json'), JSON.stringify(pk));
    expect(cmdSign([dir], { out, kid: 'k', key: key() }).text).toMatch(/unknown member 'bogus'/);
    const q = project();
    expect(cmdSign([q.dir], { out: q.out, kid: 'k', key: key() }).text).toMatch(/run pca actions build first/);
    const r = built();
    expect(cmdSign([r.dir], { out: r.out, kid: 'k', key: 'AAAA' }).text).toMatch(/32-byte/);
  });
  it('a stable pack must be lint-clean even of warnings', () => {
    const { dir, out } = project();
    writeFileSync(join(dir, 'pca.config.json'), JSON.stringify({ ns: 'acme', version: '1.0.0', stability: 'stable', site: 'https://acme.example.com', aud: 'acme-api' }));
    writeFileSync(join(dir, 'warn.yaml'), 'ns: acme\nactions:\n  - {verb: acme.invoice.get, title: Read an invoice, effects: read, resource: "acme.invoice:inv_*", params: {invoice: "id:acme.invoice"}}\n');
    expect(cmdBuild([dir], { out }).ok).toBe(true);
    const r = cmdSign([dir], { out, kid: 'k', key: key() });
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/a stable pack must be lint-clean/);
  });
  it('publish refuses a tampered signed file and a pack signed by an unlisted key', async () => {
    const { dir, out } = built();
    expect(cmdSign([dir], { out, kid: 'k', key: key() }).ok).toBe(true);
    const signed = JSON.parse(read(out, 'pca-actions.json'));
    signed.verbs[0].floors.esc = 0;
    writeFileSync(join(out, 'pca-actions.json'), JSON.stringify(signed));
    expect((await cmdPublish([dir], { out })).text).toMatch(/not publishing: schema signature invalid/);
    expect(cmdSign([dir], { out, kid: 'k', key: key() }).ok).toBe(true);
    const keys = JSON.parse(read(out, 'keys.json'));
    writeFileSync(join(out, 'keys.json'), JSON.stringify([{ ...keys[0], pk: b64u(generateKeyPair().publicKey) }]));
    expect((await cmdPublish([dir], { out })).ok).toBe(false);
  });
  it('a separate registry key signs the pack; both keys are listed', async () => {
    const { dir, out } = built();
    expect(cmdSign([dir], { out, kid: 'site', key: key(), packKid: 'reg', packKey: key() }).ok).toBe(true);
    expect(JSON.parse(read(out, 'keys.json')).map((k: { kid: string }) => k.kid)).toEqual(['site', 'reg']);
    expect((await cmdPublish([dir], { out })).ok).toBe(true);
  });
});

describe('pca actions import', () => {
  const MCP = JSON.stringify({ tools: [
    { name: 'search_orders', description: 'Search orders', inputSchema: { type: 'object', properties: { q: { type: 'string', maxLength: 100 }, limit: { type: 'integer', minimum: 1, maximum: 50 } }, required: ['q'] }, annotations: { readOnlyHint: true } },
    { name: 'delete_order', inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] }, annotations: { destructiveHint: true, idempotentHint: true } },
    { name: 'price', inputSchema: { type: 'object', properties: { amount: { type: 'number' } } } },
  ] });
  it('MCP tools become unreviewed draft defs that lint, build and escalate', () => {
    const r = cmdImport(MCP, { from: 'mcp', ns: 'shop', uri: 'https://shop.example/mcp', licence: 'MIT' });
    expect(r.ok).toBe(true);
    expect(r.todo.join('\n')).toMatch(/amount.*fractions/);
    const { dir, out } = project();
    writeFileSync(join(dir, 'shop.yaml'), r.yaml);
    expect(cmdLint([dir]).ok, cmdLint([dir]).text).toBe(true);
    const ex = cmdActionExplain([dir], 'shop.order.delete');
    expect(ex.text).toMatch(/has not been reviewed by a person/);
    expect(ex.text).toMatch(/review: (unreviewed|suggested)/);
    expect(ex.text).toMatch(/escalation: stepup/);
    expect(cmdBuild([dir], { out }).ok).toBe(true);
    const pack = JSON.parse(read(out, 'pack.json'));
    expect(pack.defs.find((d: { verb: string }) => d.verb === 'shop.orders.search')).toMatchObject({ effects: ['read'], review: { state: 'suggested' }, source: { kind: 'mcp', licence: 'MIT' }, bindings: { mcp: { tool: 'search_orders' } } });
    // an unreviewed tool's claim of being read-only is not advertised
    expect(JSON.parse(read(out, 'mcp.json')).tools.search_orders.annotations).toMatchObject({ readOnlyHint: false });
  });
  it('a pack is inert-strict until a pinned reviewer confirms it: `confirm --origin any` signs every def, the config pins the key', () => {
    const { dir, out } = project();
    const r = cmdImport(MCP, { from: 'mcp', ns: 'shop', uri: 'https://shop.example/mcp', licence: 'MIT' });
    writeFileSync(join(dir, 'shop.yaml'), r.yaml);
    rmSync(join(dir, 'acme.yaml'));
    const sk = b64u(sha256(utf8('cli-reviewer')));
    const pk = b64u(publicKeyOf(unb64u(sk)));
    // nothing confirmed: the build says so, and every verb carries every trait
    const b0 = cmdBuild([dir], { out });
    expect(b0.ok, b0.text).toBe(true);
    expect(b0.text).toMatch(/3 of 3 actions are not confirmed by a pinned reviewer/);
    const doc0 = JSON.parse(read(out, 'schema.json'));
    expect(doc0.verbs.every((v: { traits: string[]; confirmation?: unknown }) => v.traits.length === 22 && v.confirmation === undefined)).toBe(true);
    // the preview signs nothing; --origin any with the key signs all three
    const text = readFileSync(join(dir, 'shop.yaml'), 'utf8');
    const preview = cmdConfirm(text, { verbs: [], kid: 'rev-1', yes: false, ts: 1_700_000_000, origin: 'any' });
    expect(preview.ok && preview.text).toMatch(/nothing signed/);
    const signed = cmdConfirm(text, { verbs: [], kid: 'rev-1', secret: sk, yes: true, ts: 1_700_000_000, origin: 'any' });
    expect(signed.ok, signed.text).toBe(true);
    expect(signed.text).toMatch(/^3 confirmed by rev-1/);
    writeFileSync(join(dir, 'shop.yaml'), signed.yaml);
    // a config that does not pin the key still treats them as unconfirmed; pinning the reviewer makes the traits real
    const b1 = cmdBuild([dir], { out });
    expect(b1.text).toMatch(/3 of 3 actions are not confirmed/);
    const cfg = JSON.parse(read(dir, 'pca.config.json'));
    writeFileSync(join(dir, 'pca.config.json'), JSON.stringify({ ...cfg, reviewers: { keys: [{ kid: 'rev-1', pk, roles: ['reviewer'] }] } }));
    const b2 = cmdBuild([dir], { out });
    expect(b2.ok, b2.text).toBe(true);
    expect(b2.text).not.toMatch(/not confirmed/);
    const doc2 = JSON.parse(read(out, 'schema.json'));
    expect(doc2.verbs.every((v: { traits: string[]; confirmation?: unknown }) => v.traits.length < 22 && v.confirmation !== undefined)).toBe(true);
    // the config refuses a malformed pin set
    expect(parseConfig(JSON.stringify({ ...cfg, reviewers: { keys: [{ kid: 'a', pk: 'x', roles: ['reviewer'] }] } }))).toMatch(/reviewers:/);
  });
  it('a stable pack flags the unreviewed defs (LW-004)', () => {
    const { dir } = project();
    writeFileSync(join(dir, 'shop.yaml'), cmdImport(MCP, { from: 'mcp', ns: 'shop' }).yaml);
    writeFileSync(join(dir, 'pca.config.json'), JSON.stringify({ ns: 'acme', version: '1.0.0', stability: 'stable', site: 's', aud: 'a' }));
    expect(cmdLint([dir]).text).toMatch(/LW-004/);
    expect(cmdLint([dir], { strict: true }).ok).toBe(false);
  });
  it('OpenAPI operations and a JSON Schema', () => {
    const api = JSON.stringify({ openapi: '3.0.0', paths: {
      '/orders/{id}': { parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], get: { operationId: 'getOrder', summary: 'Get an order' }, delete: { operationId: 'deleteOrder', summary: 'Delete an order' } },
      '/orders': { post: { summary: 'Create an order', requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/New' } } } } } },
    }, components: { schemas: { New: { type: 'object', required: ['sku'], properties: { sku: { type: 'string', maxLength: 40 }, qty: { type: 'integer', minimum: 1, maximum: 9 }, ship: { type: 'object', properties: { zip: { type: 'string', maxLength: 10 } } }, ext: { $ref: 'http://evil.example/x.json' } } } } } });
    const r = cmdImport(api, { from: 'openapi', ns: 'shop' });
    expect(r.ok).toBe(true);
    expect(r.todo.join('\n')).toMatch(/does not resolve|not a local reference/);
    expect(r.yaml).toMatch(/operationId: getOrder/);
    expect(r.yaml).toMatch(/ship\.zip:/);
    expect(r.yaml).toMatch(/method: POST/);
    const js = cmdImport(JSON.stringify({ title: 'Ping', properties: { host: { type: 'string', maxLength: 64 } }, required: ['host'] }), { from: 'jsonschema', ns: 'ops', verb: 'ops.host.ping' });
    expect(js.ok).toBe(true);
    expect(js.yaml).toMatch(/verb: ops.host.ping/);
    expect(cmdImport('{}', { from: 'jsonschema', ns: 'ops' }).text).toMatch(/needs --verb/);
  });
  it('GraphQL SDL and .proto are read as text, and --suggest none keeps the plain draft', () => {
    const g = cmdImport('type Query { user(id: ID!): String } type Mutation { sendEmail(to: String!): String }', { from: 'graphql', ns: 'g' });
    expect(g.ok).toBe(true);
    expect(g.yaml).toMatch(/graphql:/);
    const p = cmdImport('syntax="proto3"; message M { string a = 1; } service S { rpc Do(M) returns (M); }', { from: 'grpc', ns: 'p', suggest: 'none' });
    expect(p.ok).toBe(true);
    expect(p.yaml).toMatch(/state: unreviewed/);
    expect(cmdImport('type Query { a: Int }', { from: 'graphql', ns: 'g', suggest: 'model' }).text).toMatch(/--suggest rules\|none/);
  });
  it('--suggest model: pinned model, key from the environment, recorded fake transport, output still unreviewed', async () => {
    const calls: string[] = [];
    const fake = async (_u: string, i: { body: string; headers: Record<string, string> }) => { calls.push(i.body); return { ok: true, status: 200, json: async () => ({ content: [{ type: 'text', text: '["pca.data_export"]' }] }) }; };
    const env = { ANTHROPIC_API_KEY: 'sk-cli-SECRET' };
    const r = await cmdImportModel(MCP, { from: 'mcp', ns: 'shop', model: 'pinned-1' }, env, fake as never);
    expect(r.ok).toBe(true);
    expect(r.yaml).toMatch(/pca\.data_export/);
    expect(r.yaml).toMatch(/state: suggested/);
    expect(r.yaml + r.text + r.todo.join()).not.toContain('SECRET');
    expect(calls).toHaveLength(3);
    expect((await cmdImportModel(MCP, { from: 'mcp', ns: 'shop' }, env, fake as never)).text).toMatch(/--model/);
    expect((await cmdImportModel(MCP, { from: 'mcp', ns: 'shop', model: 'p' }, {}, fake as never)).text).toBe('ANTHROPIC_API_KEY is not set');
  });
  it('bad input is reported, never thrown', () => {
    expect(cmdImport('{', { from: 'mcp', ns: 'a' }).text).toMatch(/not JSON/);
    expect(cmdImport('{}', { from: 'mcp', ns: 'a' }).text).toMatch(/tool array/);
    expect(cmdImport('{}', { from: 'soap', ns: 'a' }).text).toMatch(/unknown source/);
    expect(cmdImport('{}', { from: 'mcp', ns: 'A!' }).text).toMatch(/--ns must be/);
    expect(cmdImport('{"paths":1}', { from: 'openapi', ns: 'a' }).text).toMatch(/not an OpenAPI/);
  });
});

describe('pca actions diff', () => {
  it('equal, narrow, widen and incomparable are told apart; added and removed are listed', () => {
    const a = project('saas');
    const b = project('saas');
    const same = cmdDiff([a.dir], [b.dir]);
    expect(same.ok).toBe(true);
    expect(same.text).toMatch(/^equal +acme\.charge\.refund/m);
    expect(same.text).toMatch(/no widening/);

    const y = read(b.dir, 'acme.yaml');
    // a higher refund ceiling widens; the removed customer.delete and an added action are listed
    writeFileSync(join(b.dir, 'acme.yaml'), y.replace('max=100000', 'max=999999'));
    const w = cmdDiff([a.dir], [b.dir]);
    expect(w.ok).toBe(false);
    expect(w.text).toMatch(/^widen +acme\.charge\.refund/m);
    expect(w.text).toMatch(/widen: param amount: max 100000 to 999999/);
    expect(w.text).toMatch(/widens authority/);

    writeFileSync(join(b.dir, 'acme.yaml'), y.replace('max=100000', 'max=1000'));
    expect(cmdDiff([a.dir], [b.dir]).text).toMatch(/^narrow +acme\.charge\.refund/m);

    writeFileSync(join(b.dir, 'acme.yaml'), y.replace('max=100000', 'max=1000').replace('Refund a charge', 'Refund a charge now').replace('effects: [pay]', 'effects: [pay, update]'));
    const n = cmdDiff([a.dir], [b.dir]);
    expect(n.text).toMatch(/^narrow +acme\.charge\.refund/m);

    writeFileSync(join(b.dir, 'acme.yaml'), y.split('  - verb: acme.customer.delete')[0]!.replace('amount: money(USD, max=100000)', 'amount: money(USD, max=100000)\n      memo: text(10)?'));
    const r = cmdDiff([a.dir], [b.dir]);
    expect(r.text).toMatch(/^removed +acme\.customer\.delete/m);
    expect(r.text).toMatch(/optional param memo added/);
    expect(r.ok).toBe(false);
  });
});

describe('actions confirm --origin union (batch review of union-added traits)', () => {
  const def = (verb: string, union: string[]): ActionDef => ({
    v: 1, kind: 'pca-action-def', verb, title: 'Create a refund', description: 'Creates a refund.', effects: ['create'],
    resource: { type: 'acme.refund', id: '*', scope: 'set' },
    params: { note: { type: 'string', max_len: 100 }, idempotency_key: { type: 'string', max_len: 64, required: false } },
    reversibility: 'irreversible', idempotency: { mode: 'key_param', param: 'idempotency_key' },
    traits: ['pca.money_moving', 'pca.destructive'].filter((t) => union.includes(t)), review: { state: 'authored', ...(union.length ? { provenance: { union } } : {}) }, since: '0.5.0',
  });
  const text = defsToYaml('acme', [def('acme.a.create', ['pca.money_moving']), def('acme.b.create', ['pca.destructive']), def('acme.c.create', [])]);
  const sk = b64u(generateKeyPair().secretKey);

  it('without --yes it lists only the defs whose union-added trait matches and signs nothing', () => {
    const r = cmdConfirm(text, { verbs: [], kid: 'rev-1', yes: false, ts: 1_700_000_000, origin: 'union', trait: 'money_moving' });
    expect(r.ok).toBe(true);
    expect(r.text).toContain('acme.a.create');
    expect(r.text).toContain('added from the suggestion rules (union): pca.money_moving');
    expect(r.text).not.toContain('acme.b.create');
    expect(r.text).not.toContain('acme.c.create');
    expect(r.yaml).toBe('');
  });
  it('keeping the trait signs an attestation; dropping it needs a reason and is recorded in the attestation', () => {
    const keep = cmdConfirm(text, { verbs: [], kid: 'rev-1', secret: sk, yes: true, ts: 1_700_000_000, origin: 'union', trait: 'pca.money_moving' });
    expect(keep.ok).toBe(true);
    const kept = loadActionsText(keep.yaml).defs.find((d) => d.verb === 'acme.a.create')!;
    expect(kept.review.state).toBe('confirmed');
    expect(kept.traits).toContain('pca.money_moving');
    const silent = cmdConfirm(text, { verbs: [], kid: 'rev-1', secret: sk, yes: true, ts: 1_700_000_000, origin: 'union', trait: 'money_moving', final: [] });
    expect(silent.ok).toBe(false);
    const drop = cmdConfirm(text, { verbs: [], kid: 'rev-1', secret: sk, yes: true, ts: 1_700_000_000, origin: 'union', trait: 'money_moving', dismiss: ['pca.money_moving=lookup only, no payment'] });
    expect(drop.ok).toBe(true);
    const dropped = loadActionsText(drop.yaml).defs.find((d) => d.verb === 'acme.a.create')!;
    expect(dropped.traits ?? []).not.toContain('pca.money_moving');
    expect(dropped.review.attestation?.dismissed).toEqual([{ trait: 'pca.money_moving', reason: 'lookup only, no payment' }]);
    expect(loadActionsText(drop.yaml).defs.find((d) => d.verb === 'acme.c.create')!.review.state).toBe('authored');
  });
  it('refuses an unknown origin, a trait without an origin, and an empty selection', () => {
    expect(cmdConfirm(text, { verbs: [], kid: 'k', yes: false, ts: 1, origin: 'pack' }).ok).toBe(false);
    expect(cmdConfirm(text, { verbs: [], kid: 'k', yes: false, ts: 1, trait: 'money_moving' }).ok).toBe(false);
    expect(cmdConfirm(text, { verbs: [], kid: 'k', yes: false, ts: 1, origin: 'union', trait: 'data_export' }).text).toMatch(/no def carries/);
  });
});

describe('pca actions lint: provenance pin and trace rules (track K9)', () => {
  const FETCH = `ns: acme
since: 0.1.0
actions:
  - verb: acme.page.fetch
    title: Fetch a page
    description: Reads a public web page.
    effects: [read]
    traits: [pca.network_egress]
    resource: acme.page:pg_*
    params:
      page: id:acme.page
`;
  const withConfig = (dir: string, extra: Record<string, unknown>) => {
    const f = join(dir, 'pca.config.json');
    writeFileSync(f, JSON.stringify({ ...JSON.parse(read(f)), ...extra }));
  };

  it('LT-001: untrusted content, private data and a send with no trace rule; a rule cutting the leg clears it', () => {
    const { dir } = project();
    writeFileSync(join(dir, 'fetch.yaml'), FETCH);
    const open = cmdLint([dir]);
    expect(open.ok).toBe(true);
    expect(open.text).toMatch(/warning LT-001 .*acme\.invoice\.send: untrusted content \(acme\.page\.fetch\) and private data \(acme\.invoice\.send\) can reach this send/);
    expect(cmdLint([dir], { strict: true }).ok).toBe(false);
    withConfig(dir, { trace: { rules: ['no_exfil: never trait:pca.external_communication after tool:acme.page.fetch within 1d'] } });
    expect(cmdLint([dir]).text).not.toMatch(/LT-001/);
    expect(cmdLint([dir], { strict: true }).ok).toBe(true);
  });

  it('LT-000: a rule that does not compile is an error, never skipped', () => {
    const { dir } = project();
    withConfig(dir, { trace: { rules: ['r: never tool:acme.nope after tool:acme.invoice.send within 1h'] } });
    const l = cmdLint([dir]);
    expect(l.ok).toBe(false);
    expect(l.text).toMatch(/error +LT-000 .*tool 'acme\.nope' is not an action/);
    withConfig(dir, { trace: { rules: ['never tool:acme.invoice.send after tool:acme.invoice.send within 1h'] } });
    expect(cmdLint([dir]).text).toMatch(/LT-000 .*must be '<id>: never/);
  });

  it('LP-001: a beta or stable pack without a pinned builder identity fails under --strict', () => {
    const { dir } = project();
    withConfig(dir, { stability: 'beta' });
    expect(cmdLint([dir]).text).toMatch(/warning LP-001 .*pin the identity that builds it/);
    expect(cmdLint([dir], { strict: true }).ok).toBe(false);
    withConfig(dir, { provenance: { oidc_issuer: 'https://token.actions.githubusercontent.com', identity_prefix: 'https://github.com/acme/actions/.github/workflows/release.yml@refs/tags/', builder_id: 'https://github.com/actions/runner/github-hosted' } });
    expect(cmdLint([dir]).text).not.toMatch(/LP-001/);
  });

  it('config validation of the new members', () => {
    const base = { ns: 'acme', version: '0.1.0', stability: 'draft', site: 'https://a.example', aud: 'a' };
    expect(parseConfig(JSON.stringify({ ...base, provenance: { oidc_issuer: 'i', builder_id: 'b' } }))).toMatch(/exactly one of identity/);
    expect(parseConfig(JSON.stringify({ ...base, provenance: { oidc_issuer: 'i', builder_id: 'b', identity_prefix: 'short' } }))).toMatch(/at least 10/);
    expect(parseConfig(JSON.stringify({ ...base, trace: { rules: 'x' } }))).toMatch(/trace must be/);
    expect(parseConfig(JSON.stringify({ ...base, trace: { rules: [], extra: 1 } }))).toMatch(/trace must be/);
    expect(typeof parseConfig(JSON.stringify({ ...base, trace: { rules: [], untrusted: ['acme.page.fetch'] } }))).toBe('object');
  });
});
