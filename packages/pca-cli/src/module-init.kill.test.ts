// Module-level tables (file extensions, project file names, the version pattern, source kinds, templates, the review
// options) are built when the module loads, so these tests load a fresh copy of the module inside each test.
// The directory order tests reverse what readdirSync returns, so a result that does not sort cannot pass by luck.
import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { b64u, publicKeyOf, sha256, unb64u, utf8 } from '@atlasauth/pca';
import { loadActionsText, type TraitDef } from '@atlasauth/pca-actions';

const order = vi.hoisted(() => ({ reverse: false }));
vi.mock('node:fs', async (orig) => {
  const actual = await orig<typeof import('node:fs')>();
  const readdirSync = ((...a: unknown[]) => {
    const r = (actual.readdirSync as (...x: unknown[]) => string[])(...a);
    return order.reverse ? [...r].sort().reverse() : r;
  }) as typeof actual.readdirSync;
  return { ...actual, readdirSync };
});

const fresh = async () => {
  vi.resetModules();
  return import('./actions');
};
const reversed = <T>(run: () => T): T => {
  order.reverse = true;
  try { return run(); } finally { order.reverse = false; }
};
const tmp = (): string => mkdtempSync(join(tmpdir(), 'pcacli-init-'));
const put = (dir: string, name: string, text: string): string => { const f = join(dir, name); writeFileSync(f, text); return f; };
const CONFIG = { ns: 'acme', version: '0.1.0', stability: 'draft', site: 'https://acme.example.com', aud: 'acme-api' };

describe('module tables, loaded fresh', () => {
  it('action files are .yaml, .yml and .json; the config, the sync lock and the rules reviews are not action files', async () => {
    const m = await fresh();
    const d = tmp();
    for (const f of ['a.yml', 'b.json', 'c.yaml', 'pca.config.json', 'pca.sync.json', 'pca.rules-reviews.json', 'd.txt']) put(d, f, '{}');
    expect(m.collectFiles([d])).toEqual([join(d, 'a.yml'), join(d, 'b.json'), join(d, 'c.yaml')]);
  });

  it('the version is a whole semantic version: multi-digit parts and a pre-release are accepted, a prefix or a fourth part is not', async () => {
    const m = await fresh();
    const parse = (version: string) => m.parseConfig(JSON.stringify({ ...CONFIG, version }));
    for (const version of ['10.20.30', '10.20.30-rc.1', '1.0.0-alpha-2']) expect(parse(version)).toMatchObject({ version });
    for (const version of ['v1.0.0', '1.0.0.0', 'x10.20.30', '1.0.0-']) expect(parse(version)).toBe('pca.config.json: version must be a semantic version');
  });

  it('every source kind is accepted and the refusal lists them all', async () => {
    const m = await fresh();
    const parse = (s: Record<string, unknown>) => m.parseConfig(JSON.stringify({ ...CONFIG, sources: [{ name: 's1', file: 'a.json', ...s }] }));
    expect(parse({ from: 'soap' })).toBe('pca.config.json: sources: sources[0]: from must be one of openapi, mcp, graphql, grpc, asyncapi, jsonschema');
    for (const from of ['openapi', 'mcp', 'graphql', 'grpc', 'asyncapi']) expect(parse({ from })).toMatchObject({ sources: [{ from }] });
    expect(parse({ from: 'jsonschema', verb: 'acme.thing.create' })).toMatchObject({ sources: [{ from: 'jsonschema' }] });
  });

  it('the db and mcp templates scaffold their own actions', async () => {
    const m = await fresh();
    for (const [template, needle] of [['db', 'verb: acme.row.delete'], ['mcp', 'bindings: {mcp: {tool: append_note}}']] as const) {
      const dir = join(tmp(), 'p');
      const r = m.cmdInit({ dir, ns: 'acme', template });
      expect(r).toEqual({ ok: true, text: `wrote ${join(dir, 'acme.yaml')}, ${join(dir, 'pca.config.json')}` });
      const text = readFileSync(join(dir, 'acme.yaml'), 'utf8');
      expect(text).toContain(needle);
      expect(loadActionsText(text).errors).toEqual([]);
    }
  });

  it('a pinned reviewer confirms: test is silent once every action is confirmed, and lint flags a signature by a key that is not pinned', async () => {
    const m = await fresh();
    const sk = b64u(sha256(utf8('cli-reviewer')));
    const pk = b64u(publicKeyOf(unb64u(sk)));
    const other = b64u(publicKeyOf(sha256(utf8('someone-else'))));
    const c = m.cmdConfirm(m.ACTION_TEMPLATES.minimal!('acme'), { verbs: ['acme.invoice.send'], kid: 'rev-1', secret: sk, yes: true, ts: 1_700_000_000 });
    expect(c.ok, c.text).toBe(true);
    const dir = tmp();
    put(dir, 'a.yaml', c.yaml);
    put(dir, 'pca.config.json', JSON.stringify({ ...CONFIG, reviewers: { keys: [{ kid: 'rev-1', pk, roles: ['reviewer'] }] } }));
    const t = m.cmdTest([dir]);
    expect(t.text).not.toContain('not confirmed by a pinned reviewer');
    expect(m.cmdLint([dir]).text).not.toContain('the attestation is not signed by a pinned reviewer');
    put(dir, 'pca.config.json', JSON.stringify({ ...CONFIG, reviewers: { keys: [{ kid: 'rev-1', pk: other, roles: ['reviewer'] }] } }));
    expect(m.cmdLint([dir]).text).toContain('the attestation is not signed by a pinned reviewer');
    expect(m.cmdTest([dir]).text).toContain('1 of 1 action is not confirmed by a pinned reviewer');
  });
});

describe('custom traits that do not build', () => {
  it('a confirmed action is checked against the core registry and is not flagged as signed by an unpinned key', async () => {
    const { ACTION_TEMPLATES, cmdConfirm, cmdLint } = await import('./actions');
    const sk = b64u(sha256(utf8('cli-reviewer')));
    const pk = b64u(publicKeyOf(unb64u(sk)));
    const c = cmdConfirm(ACTION_TEMPLATES.minimal!('acme'), { verbs: ['acme.invoice.send'], kid: 'rev-1', secret: sk, yes: true, ts: 1_700_000_000 });
    expect(c.ok, c.text).toBe(true);
    const dir = tmp();
    put(dir, 'a.yaml', c.yaml);
    const badTrait = { id: 'pca.mine', implies: [] } as unknown as TraitDef;
    put(dir, 'pca.config.json', JSON.stringify({ ...CONFIG, traits: [badTrait], reviewers: { keys: [{ kid: 'rev-1', pk, roles: ['reviewer'] }] } }));
    const l = cmdLint([dir]);
    expect(l.ok).toBe(false);
    expect(l.text).toContain('invalid custom traits');
    expect(l.text).not.toContain('the attestation is not signed by a pinned reviewer');
  });
});

describe('directory order does not leak into results', () => {
  it('a directory is walked in sorted order: the first entry that cannot be read is the first by name', async () => {
    const { collectFiles } = await import('./actions');
    const d = tmp();
    symlinkSync(join(d, 'missing-a'), join(d, 'a.yaml'));
    symlinkSync(join(d, 'missing-b'), join(d, 'b.yaml'));
    expect(() => reversed(() => collectFiles([d]))).toThrow(join(d, 'a.yaml'));
  });

  it('a pack name picks the highest version directory that holds a pack.json', async () => {
    const { packText } = await import('./actions');
    const packs = tmp();
    const write = (ver: string, ns: string): void => {
      const dir = join(packs, 'shop', ver);
      mkdirSync(dir, { recursive: true });
      put(dir, 'pack.json', JSON.stringify({ ns: [ns], shards: [{ file: 's.jsonl' }] }));
      put(dir, 's.jsonl', '');
    };
    write('1.0.0', 'one');
    write('2.0.0', 'two');
    mkdirSync(join(packs, 'shop', '3.0.0'));
    expect(reversed(() => packText('shop', packs))).toEqual({ ok: true, text: 'ns: two\nactions: []\n', ns: 'two' });
  });

  it('a directory without a pack.json is looked up as a name, not read as a pack', async () => {
    const { packText } = await import('./actions');
    const ref = tmp();
    const packs = tmp();
    expect(packText(ref, packs)).toEqual({ ok: false, text: `no pack '${ref}' (a pack directory, or a name under ${packs})` });
  });
});
