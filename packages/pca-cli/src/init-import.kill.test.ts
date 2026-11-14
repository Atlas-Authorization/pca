import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ACTION_TEMPLATES, CONFIG_NAME, cmdImport, cmdInit } from './actions';

const tmp = () => mkdtempSync(join(tmpdir(), 'pcacli-'));
const NS_MSG = '--ns must be a lowercase identifier (a-z, 0-9, _)';

describe('cmdInit', () => {
  it('writes the template and a draft config, and says exactly where', () => {
    const dir = join(tmp(), 'nested', 'actions');
    const r = cmdInit({ dir, ns: 'shop' });
    const yaml = join(dir, 'shop.yaml');
    const cfg = join(dir, CONFIG_NAME);
    expect(r).toEqual({ ok: true, text: `wrote ${yaml}, ${cfg}` });
    expect(readFileSync(yaml, 'utf8')).toBe(ACTION_TEMPLATES.minimal!('shop'));
    const raw = readFileSync(cfg, 'utf8');
    expect(raw.endsWith('}\n')).toBe(true);
    expect(JSON.parse(raw)).toStrictEqual({ ns: 'shop', version: '0.1.0', stability: 'draft', site: 'https://shop.example.com', aud: 'shop-api' });
    expect(raw).toBe(JSON.stringify(JSON.parse(raw), null, 2) + '\n');
  });
  it('each authoring template is selectable', () => {
    for (const t of ['minimal', 'saas', 'db', 'mcp']) {
      const dir = tmp();
      expect(cmdInit({ dir, ns: 'x1', template: t }).ok).toBe(true);
      expect(readFileSync(join(dir, 'x1.yaml'), 'utf8')).toBe(ACTION_TEMPLATES[t]!('x1'));
    }
  });
  it('a starter pack adds custom traits to the config and a review notice', () => {
    const dir = tmp();
    const r = cmdInit({ dir, ns: 'store', template: 'ecommerce' });
    expect(r.ok).toBe(true);
    expect(r.text).toMatch(/^wrote .+, .+\n.+: a starter pack to adapt\. Every action is unreviewed \(treated as the most dangerous kind\) until a reviewer confirms it \(pca actions confirm\)\.$/);
    const cfg = JSON.parse(readFileSync(join(dir, CONFIG_NAME), 'utf8')) as { traits?: unknown[] };
    expect(Array.isArray(cfg.traits)).toBe(true);
    expect(cfg.traits!.length).toBeGreaterThan(0);
    expect(cmdInit({ dir: tmp(), ns: 'pca', template: 'ecommerce' })).toEqual({ ok: false, text: NS_MSG });
    expect(cmdInit({ dir: tmp(), ns: 'pca' }).ok).toBe(true);
  });
  it('an unknown template lists the known ones', () => {
    const r = cmdInit({ dir: tmp(), ns: 'shop', template: 'zzz' });
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/^unknown template 'zzz' \(minimal, saas, db, mcp(, [a-z_]+)+\)$/);
  });
  it('the namespace must be a lowercase identifier of at most 32 characters', () => {
    for (const ns of ['', 'A', '1a', 'a-b', 'a b', 'a'.repeat(33)]) expect(cmdInit({ dir: tmp(), ns })).toEqual({ ok: false, text: NS_MSG });
    expect(cmdInit({ dir: tmp(), ns: 'a'.repeat(32) }).ok).toBe(true);
    expect(cmdInit({ dir: tmp(), ns: 'a_9' }).ok).toBe(true);
  });
  it('an existing file blocks the scaffold, naming it, unless forced', () => {
    const dir = tmp();
    cmdInit({ dir, ns: 'shop' });
    const yaml = join(dir, 'shop.yaml');
    const cfg = join(dir, CONFIG_NAME);
    expect(cmdInit({ dir, ns: 'shop' })).toEqual({ ok: false, text: `${yaml} already exists (use --force to overwrite)` });
    expect(cmdInit({ dir, ns: 'shop', force: false }).ok).toBe(false);
    expect(cmdInit({ dir, ns: 'other' })).toEqual({ ok: false, text: `${cfg} already exists (use --force to overwrite)` });
    writeFileSync(yaml, 'changed');
    expect(cmdInit({ dir, ns: 'shop', force: true }).ok).toBe(true);
    expect(readFileSync(yaml, 'utf8')).toBe(ACTION_TEMPLATES.minimal!('shop'));
    expect(existsSync(join(dir, 'other.yaml'))).toBe(false);
    mkdirSync(join(dir, 'sub'));
  });
});

describe('cmdImport', () => {
  const doc = (n: number) => JSON.stringify({
    openapi: '3.0.0',
    info: { title: 't', version: '1' },
    paths: Object.fromEntries(Array.from({ length: n }, (_, i) => [`/items${i}`, { get: { operationId: `listItems${i}`, responses: { '200': { description: 'ok' } } } }])),
  });
  it('unknown sources, bad namespaces and bad suggestion modes are refused with exact messages', () => {
    expect(cmdImport(doc(1), { from: 'zzz', ns: 'shop' })).toEqual({ ok: false, yaml: '', todo: [], text: "unknown source 'zzz' (asyncapi, graphql, grpc, jsonschema, mcp, openapi)" });
    for (const ns of ['', 'A', '1a', 'a'.repeat(33)]) expect(cmdImport(doc(1), { from: 'openapi', ns })).toEqual({ ok: false, yaml: '', todo: [], text: NS_MSG });
    for (const suggest of ['model', 'x', '']) {
      expect(cmdImport(doc(1), { from: 'openapi', ns: 'shop', suggest })).toEqual({ ok: false, yaml: '', todo: [], text: '--suggest rules|none (model assist: cmdImportModel / the CLI with --suggest model)' });
    }
  });
  it('a JSON source that is not JSON is refused', () => {
    const r = cmdImport('{nope', { from: 'openapi', ns: 'shop' });
    expect(r.ok).toBe(false);
    expect(r.yaml).toBe('');
    expect(r.todo).toEqual([]);
    expect(r.text).toMatch(/^the source is not JSON: .+/);
  });
  it('a document the importer rejects reports the importer message', () => {
    const r = cmdImport('{}', { from: 'openapi', ns: 'shop' });
    expect(r.ok).toBe(false);
    expect(r.text.length).toBeGreaterThan(0);
    expect(r.text).not.toMatch(/^the source is not JSON/);
    expect(r.yaml).toBe('');
  });
  it('a good document yields draft actions, counted with the right plural', () => {
    const one = cmdImport(doc(1), { from: 'openapi', ns: 'shop' });
    expect(one.ok).toBe(true);
    expect(one.text).toBe('1 draft action (unreviewed: every one escalates until confirmed)');
    expect(one.yaml.length).toBeGreaterThan(0);
    const two = cmdImport(doc(2), { from: 'openapi', ns: 'shop', suggest: 'rules' });
    expect(two.ok).toBe(true);
    expect(two.text).toBe('2 draft actions (unreviewed: every one escalates until confirmed)');
  });
  it('rule suggestions are applied by default and left out with suggest none', () => {
    const withRules = cmdImport(doc(2), { from: 'openapi', ns: 'shop' });
    const explicit = cmdImport(doc(2), { from: 'openapi', ns: 'shop', suggest: 'rules' });
    const none = cmdImport(doc(2), { from: 'openapi', ns: 'shop', suggest: 'none' });
    expect(withRules.yaml).toBe(explicit.yaml);
    expect(none.ok).toBe(true);
    expect(none.yaml).not.toBe(withRules.yaml);
  });
  it('GraphQL and gRPC sources are taken as text', () => {
    const r = cmdImport('type Query { a: Int }', { from: 'graphql', ns: 'shop' });
    expect(typeof r.ok).toBe('boolean');
    expect(r.text).not.toMatch(/^the source is not JSON/);
    expect(cmdImport('syntax = "proto3";', { from: 'grpc', ns: 'shop' }).text).not.toMatch(/^the source is not JSON/);
  });
});
