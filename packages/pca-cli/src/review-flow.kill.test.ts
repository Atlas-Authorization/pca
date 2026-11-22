import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CORE_REGISTRY, IMPORTERS, defsToYaml, explainBusinessRules, loadActionsText, prepareReview, type ActionDef, type TraitDef } from '@atlasauth/pca-actions';
import { cmdActionExplain, cmdConfirm, cmdImport, cmdInit, cmdLint, cmdSync, loadProject } from './actions';

const tmp = (): string => mkdtempSync(join(tmpdir(), 'pcacli-rf-'));
const put = (dir: string, name: string, text: string): string => { const f = join(dir, name); writeFileSync(f, text); return f; };
const project = (ns = 'acme'): string => { const dir = join(tmp(), 'actions'); expect(cmdInit({ dir, ns }).ok).toBe(true); return dir; };

const READ: ActionDef = {
  v: 1, kind: 'pca-action-def', verb: 'acme.row.get', title: 'Read a row', description: 'Reads one row by its key.', effects: ['read'],
  resource: { type: 'acme.row', id: '*', scope: 'one' },
  params: { row: { type: 'string', max_len: 64 } },
  reversibility: 'reversible',
  review: { state: 'suggested', suggested_by: { added: { traits: ['pca.data_export', 'pca.pii_access'], roles: {}, tags: {} } } },
  since: '0.5.0',
} as ActionDef;
const READ_YAML = defsToYaml('acme', [READ]);

describe('cmdConfirm', () => {
  it('a document that does not load is refused with its first load error', () => {
    const text = 'ns: acme\nactions: 5\n';
    const errs = loadActionsText(text).errors;
    expect(errs.length).toBeGreaterThan(0);
    expect(cmdConfirm(text, { verbs: [], kid: 'rev-1', yes: false, ts: 0 })).toEqual({ ok: false, yaml: '', text: errs[0]!.message });
  });
  it('the review prints - for an empty trait list and joins a list with commas', () => {
    expect(loadActionsText(READ_YAML).errors).toEqual([]);
    const v = prepareReview(loadActionsText(READ_YAML).defs[0]!, CORE_REGISTRY);
    expect(v.declared_traits).toEqual([]);
    expect(v.implied_traits).toEqual([]);
    const r = cmdConfirm(READ_YAML, { verbs: ['acme.row.get'], kid: 'rev-1', yes: false, ts: 0 });
    expect(r.ok).toBe(true);
    expect(r.text.endsWith('\n  declared: -\n  implied: -\n  suggested: pca.data_export, pca.pii_access\n(nothing signed: pass --yes with --reviewer-key to confirm)')).toBe(true);
  });
  it('--origin union skips a def that carries no provenance', () => {
    expect(cmdConfirm(READ_YAML, { verbs: [], kid: 'rev-1', yes: false, ts: 0, origin: 'union' })).toEqual({ ok: false, yaml: '', text: 'no def carries a union-added trait to review' });
  });
});

describe('cmdLint', () => {
  it('the SARIF form passes and fails exactly like the text form', () => {
    const dir = project();
    expect(cmdLint([dir]).ok).toBe(true);
    expect(cmdLint([dir], { format: 'sarif' }).ok).toBe(true);
    const bad = project();
    put(bad, 'pca.config.json', JSON.stringify({ ns: 'acme', version: '0.1.0', stability: 'draft', site: 'https://acme.example.com', aud: 'acme-api', traits: [{ id: 'pca.mine', implies: [] } as unknown as TraitDef] }));
    expect(cmdLint([bad]).ok).toBe(false);
    expect(cmdLint([bad], { format: 'sarif' }).ok).toBe(false);
  });
});

describe('cmdActionExplain', () => {
  it('each business rule is on its own line', () => {
    const dir = project();
    const f = join(dir, 'acme.yaml');
    writeFileSync(f, readFileSync(f, 'utf8').replace(/\n {4}examples:\n/, '\n    rules:\n      recipients: {param: to, domains: [b.com]}\n      required: [note]\n      rate: [{max: 10, per: hour}]\n    examples:\n'));
    const l = loadProject([dir]);
    const d = l.defs.find((x) => x.verb === 'acme.invoice.send')!;
    const lines = explainBusinessRules(d, l.rules[d.verb]!);
    expect(lines.length).toBeGreaterThan(1);
    const r = cmdActionExplain([dir], 'acme.invoice.send');
    expect(r.ok).toBe(true);
    expect(r.text.endsWith(`\nbusiness rules:\n${lines.map((x) => `  - ${x}`).join('\n')}`)).toBe(true);
  });
});

describe('cmdSync --check', () => {
  it('a check before the first sync writes no lock', async () => {
    const dir = project('shop');
    const root = join(dir, '..');
    writeFileSync(join(root, 'openapi.json'), JSON.stringify({ openapi: '3.0.0', paths: { '/orders/{id}': { parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', maxLength: 40 } }], get: { operationId: 'getOrder', summary: 'Get an order' } } } }));
    const cfg = JSON.parse(readFileSync(join(dir, 'pca.config.json'), 'utf8')) as Record<string, unknown>;
    put(dir, 'pca.config.json', JSON.stringify({ ...cfg, sources: [{ name: 'api', from: 'openapi', file: '../openapi.json' }] }));
    const r = await cmdSync([dir], { check: true });
    expect(r.ok).toBe(false);
    expect(existsSync(join(dir, 'pca.sync.json'))).toBe(false);
    expect(existsSync(join(dir, 'api.sync.yaml'))).toBe(false);
  });
});

describe('cmdImport: GraphQL and gRPC sources', () => {
  const failure = (from: string, doc: unknown): string => {
    try { IMPORTERS[from]!(doc, { ns: 'g' }); } catch (e) { return (e as Error).message; }
    throw new Error('the importer accepted it');
  };
  const verbs = (yaml: string): string[] => loadActionsText(yaml).defs.map((d) => d.verb);
  const INTROSPECTION = JSON.stringify({ data: { __schema: { queryType: { name: 'Query' }, types: [{ kind: 'OBJECT', name: 'Query', fields: [{ name: 'ping', args: [] }] }] } } });

  it('a GraphQL introspection result (JSON, leading whitespace allowed) is imported as JSON', () => {
    const sdl = cmdImport('type Query { ping: String }', { from: 'graphql', ns: 'g' });
    expect(sdl.ok, sdl.text).toBe(true);
    expect(verbs(sdl.yaml).length).toBe(1);
    for (const src of [INTROSPECTION, `  \n${INTROSPECTION}`]) {
      const r = cmdImport(src, { from: 'graphql', ns: 'g' });
      expect(r.ok, r.text).toBe(true);
      expect(verbs(r.yaml)).toEqual(verbs(sdl.yaml));
    }
  });
  it('GraphQL text that is not JSON (even when it starts with a brace or is a JSON scalar) is parsed as SDL', () => {
    for (const src of ['{ broken', '5']) expect(cmdImport(src, { from: 'graphql', ns: 'g' })).toEqual({ ok: false, yaml: '', todo: [], text: failure('graphql', src) });
    expect(failure('graphql', '{ broken')).not.toBe(failure('graphql', {}));
    expect(failure('graphql', '5')).not.toBe(failure('graphql', 5));
  });
  it('a gRPC source that looks like JSON is still read as .proto text', () => {
    expect(cmdImport('{}', { from: 'grpc', ns: 'g' }).text).not.toBe(failure('grpc', {}));
    const proto = cmdImport('syntax="proto3"; message M { string a = 1; } service S { rpc Do(M) returns (M); }', { from: 'grpc', ns: 'g' });
    expect(proto.ok, proto.text).toBe(true);
  });
});
