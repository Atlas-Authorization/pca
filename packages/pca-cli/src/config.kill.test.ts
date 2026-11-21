import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CONFIG_NAME, type Config, collectFiles, findConfig, parseConfig } from './actions';

const base = { ns: 'acme', version: '1.2.3', stability: 'draft', site: 'https://site.example', aud: 'ins_1' };
const parse = (over: Record<string, unknown>) => parseConfig(JSON.stringify({ ...base, ...over }));
const P = `${CONFIG_NAME}: `;

describe('parseConfig: exact refusals', () => {
  it('the document must be a JSON object', () => {
    expect(parseConfig('{')).toMatch(/^pca\.config\.json is not JSON: .+/);
    for (const t of ['null', '5', '"x"', '[]']) expect(parseConfig(t)).toBe(`${CONFIG_NAME} must be an object`);
  });
  it('unknown members, ns, version, stability, site and aud', () => {
    expect(parse({ extra: 1 })).toBe(`${P}unknown member 'extra'`);
    for (const ns of [5, '', 'A', '1a', 'a-b', 'a'.repeat(33)]) expect(parse({ ns })).toBe(`${P}ns must be a lowercase identifier`);
    expect(parse({ ns: 'a'.repeat(32) })).toMatchObject({ ns: 'a'.repeat(32) });
    for (const version of [5, '1', '1.0', 'v1.0.0', '1.0.0.0']) expect(parse({ version })).toBe(`${P}version must be a semantic version`);
    expect(parse({ version: '1.0.0-rc.1' })).toMatchObject({ version: '1.0.0-rc.1' });
    for (const stability of ['x', 5, undefined]) expect(parse({ stability })).toBe(`${P}stability must be draft, beta or stable`);
    for (const stability of ['draft', 'beta', 'stable']) expect(parse({ stability, provenance: undefined })).toMatchObject({ stability });
    for (const site of [5, '', 's'.repeat(257)]) expect(parse({ site })).toBe(`${P}site is required`);
    expect(parse({ site: 's'.repeat(256) })).toMatchObject({ site: 's'.repeat(256) });
    for (const aud of [5, '', 'a'.repeat(257)]) expect(parse({ aud })).toBe(`${P}aud is required`);
    expect(parse({ aud: 'a'.repeat(256) })).toMatchObject({ aud: 'a'.repeat(256) });
  });
  it('traits must be a list; reviewers are checked; sources are checked', () => {
    expect(parse({ traits: {} })).toBe(`${P}traits must be a list of trait definitions`);
    expect(parse({ traits: [] })).toMatchObject({ traits: [] });
    expect(parse({ reviewers: { keys: [{ kid: 'a', pk: 'x', roles: ['reviewer'] }] } })).toMatch(/^pca\.config\.json: reviewers: .+/);
    expect(parse({ sources: [] })).toBe(`${P}sources: must be a list of 1..32 sources`);
  });
  it('provenance: shape and the one-of identity rule', () => {
    const shape = `${P}provenance must be {oidc_issuer, identity | identity_prefix, builder_id}`;
    const needs = `${P}provenance needs oidc_issuer, builder_id and exactly one of identity / identity_prefix (at least 10 characters)`;
    const ok = { oidc_issuer: 'https://issuer', builder_id: 'b', identity: 'me' };
    for (const provenance of [null, 'x', 5, [], { ...ok, extra: 1 }]) expect(parse({ provenance })).toBe(shape);
    expect(parse({ provenance: ok })).toMatchObject({ provenance: ok });
    expect(parse({ provenance: { ...ok, identity: undefined, identity_prefix: 'abcdefghij' } })).toMatchObject({ provenance: { identity_prefix: 'abcdefghij' } });
    for (const p of [
      { ...ok, oidc_issuer: '' },
      { ...ok, oidc_issuer: 5 },
      { ...ok, oidc_issuer: 'x'.repeat(2049) },
      { ...ok, builder_id: '' },
      { ...ok, builder_id: 5 },
      { oidc_issuer: 'i', builder_id: 'b' },
      { ...ok, identity_prefix: 'abcdefghij' },
      { ...ok, identity: '' },
      { ...ok, identity: 'x'.repeat(2049) },
      { oidc_issuer: 'i', builder_id: 'b', identity_prefix: 'short' },
      { oidc_issuer: 'i', builder_id: 'b', identity_prefix: 'abcdefghi' },
      { oidc_issuer: 'i', builder_id: 'b', identity_prefix: 5 },
    ]) expect(parse({ provenance: p })).toBe(needs);
    expect(parse({ provenance: { oidc_issuer: 'i'.repeat(2048), builder_id: 'b', identity: 'x'.repeat(2048) } })).toMatchObject({ provenance: { identity: 'x'.repeat(2048) } });
  });
  it('trace: rules and untrusted must be string lists and nothing else', () => {
    const m = `${P}trace must be {rules: string[], untrusted?: string[]}`;
    for (const trace of [null, 'x', 5, [], {}, { rules: 'x' }, { rules: [5] }, { rules: [], extra: 1 }, { rules: [], untrusted: 'x' }, { rules: [], untrusted: [5] }]) expect(parse({ trace })).toBe(m);
    expect(parse({ trace: { rules: ['a: never tool:b after tool:c within 1h'], untrusted: ['v'] } })).toMatchObject({ trace: { rules: ['a: never tool:b after tool:c within 1h'], untrusted: ['v'] } });
    expect(parse({ trace: { rules: [] } })).toMatchObject({ trace: { rules: [] } });
  });
  it('a valid config carries only the members it was given', () => {
    expect(parse({})).toStrictEqual({ ns: 'acme', version: '1.2.3', stability: 'draft', site: 'https://site.example', aud: 'ins_1' });
    const full = parse({ traits: [], sources: [{ name: 's1', from: 'openapi', file: 'a.json' }], trace: { rules: [] } }) as Config;
    expect(Object.keys(full).sort()).toEqual(['aud', 'ns', 'site', 'sources', 'stability', 'trace', 'traits', 'version']);
  });
});

describe('parseConfig: sources', () => {
  const src = (s: unknown) => parse({ sources: s });
  const ok = { name: 's1', from: 'openapi', file: 'a.json' };
  const S = `${P}sources: `;
  it('a list of 1..32 objects with known members', () => {
    for (const s of [undefined, 'x', {}, [], Array.from({ length: 33 }, (_, i) => ({ ...ok, name: `s${i}` }))]) {
      if (s !== undefined) expect(src(s)).toBe(`${S}must be a list of 1..32 sources`);
    }
    expect(src(Array.from({ length: 32 }, (_, i) => ({ ...ok, name: `s${i}` })))).toHaveProperty('sources');
    for (const v of [null, 'x', 5, []]) expect(src([v])).toBe(`${S}sources[0] must be an object`);
    expect(src([ok, { ...ok, name: 's2', extra: 1 }])).toBe(`${S}sources[1]: unknown member 'extra'`);
  });
  it('names are unique lowercase identifiers', () => {
    for (const name of [5, '', 'A', '1a', 'a b', 'a'.repeat(33)]) expect(src([{ ...ok, name }])).toBe(`${S}sources[0]: name must be a unique lowercase identifier`);
    expect(src([ok, ok])).toBe(`${S}sources[1]: name must be a unique lowercase identifier`);
    expect(src([{ ...ok, name: 'a_b-1' }])).toHaveProperty('sources');
    expect(src([{ ...ok, name: 'a'.repeat(32) }])).toHaveProperty('sources');
  });
  it('from must be a known kind', () => {
    const kinds = 'openapi, mcp, graphql, grpc, asyncapi, jsonschema';
    for (const from of ['soap', 5, undefined]) expect(src([{ ...ok, from }])).toBe(`${S}sources[0]: from must be one of ${kinds}`);
    for (const from of ['openapi', 'mcp', 'graphql', 'grpc', 'asyncapi']) expect(src([{ ...ok, from }])).toHaveProperty('sources');
  });
  it('exactly one of file and url, each well-formed', () => {
    const one = `${S}sources[0]: exactly one of file / url`;
    expect(src([{ name: 's1', from: 'openapi' }])).toBe(one);
    expect(src([{ ...ok, url: 'https://x.example/a' }])).toBe(one);
    for (const file of ['', 5, 'f'.repeat(1025)]) expect(src([{ ...ok, file }])).toBe(`${S}sources[0]: file must be a path`);
    expect(src([{ ...ok, file: 'f'.repeat(1024) }])).toHaveProperty('sources');
    for (const url of ['http://x.example', 'https://', 'https://a b', 5, `https://${'u'.repeat(2041)}`]) expect(src([{ name: 's1', from: 'openapi', url }])).toBe(`${S}sources[0]: url must be an https URL`);
    expect(src([{ name: 's1', from: 'openapi', url: 'https://x.example/a' }])).toHaveProperty('sources');
    expect(src([{ name: 's1', from: 'openapi', url: `https://${'u'.repeat(2040)}` }])).toHaveProperty('sources');
  });
  it('verb is required for, and only for, a jsonschema source', () => {
    const m = `${S}sources[0]: verb is required for (and only for) a jsonschema source`;
    expect(src([{ ...ok, from: 'jsonschema' }])).toBe(m);
    expect(src([{ ...ok, verb: 'v' }])).toBe(m);
    expect(src([{ ...ok, from: 'jsonschema', verb: 5 }])).toBe(m);
    expect(src([{ ...ok, from: 'jsonschema', verb: 'v' }])).toHaveProperty('sources');
  });
});

describe('parseConfig: a value of the wrong type is refused even when its text would pass', () => {
  const S = `${P}sources: sources[0]: `;
  it('ns and version must be strings, not one-element lists', () => {
    expect(parse({ ns: ['acme'] })).toBe(`${P}ns must be a lowercase identifier`);
    expect(parse({ version: ['1.2.3'] })).toBe(`${P}version must be a semantic version`);
  });
  it('every untrusted verb must be a string', () => {
    const m = `${P}trace must be {rules: string[], untrusted?: string[]}`;
    expect(parse({ trace: { rules: [], untrusted: ['v', 5] } })).toBe(m);
    expect(parse({ trace: { rules: [], untrusted: [5, 'v'] } })).toBe(m);
    expect(parse({ trace: { rules: [], untrusted: ['v', 'w'] } })).toMatchObject({ trace: { untrusted: ['v', 'w'] } });
  });
  it('a source name and url must be strings, and the url must start with https://', () => {
    expect(parse({ sources: [{ name: ['s1'], from: 'openapi', file: 'a.json' }] })).toBe(`${S}name must be a unique lowercase identifier`);
    expect(parse({ sources: [{ name: 's1', from: 'openapi', url: ['https://x.example/a'] }] })).toBe(`${S}url must be an https URL`);
    expect(parse({ sources: [{ name: 's1', from: 'openapi', url: 'xhttps://x.example/a' }] })).toBe(`${S}url must be an https URL`);
  });
});

describe('collectFiles and findConfig', () => {
  const tree = () => {
    const d = mkdtempSync(join(tmpdir(), 'pcacli-'));
    mkdirSync(join(d, 'sub', 'deep'), { recursive: true });
    mkdirSync(join(d, '.hidden'));
    mkdirSync(join(d, 'node_modules'));
    for (const f of ['b.yaml', 'a.yml', 'c.json', 'skip.txt', CONFIG_NAME, 'pca.sync.json', 'pca.rules-reviews.json', join('sub', 'x.yaml'), join('sub', 'deep', 'y.json'), join('.hidden', 'h.yaml'), join('node_modules', 'n.yaml')]) writeFileSync(join(d, f), '{}');
    return d;
  };
  it('walks directories recursively, sorted, skipping dot-directories, node_modules, other extensions and project files', () => {
    const d = tree();
    expect(collectFiles([d])).toEqual([join(d, 'a.yml'), join(d, 'b.yaml'), join(d, 'c.json'), join(d, 'sub', 'deep', 'y.json'), join(d, 'sub', 'x.yaml')]);
    expect(collectFiles([join(d, 'b.yaml'), join(d, 'b.yaml')])).toEqual([join(d, 'b.yaml')]);
    expect(collectFiles([join(d, 'sub'), join(d, 'b.yaml'), join(d, 'a.yml')])).toEqual([join(d, 'a.yml'), join(d, 'b.yaml'), join(d, 'sub', 'deep', 'y.json'), join(d, 'sub', 'x.yaml')]);
    expect(collectFiles([join(d, 'skip.txt')])).toEqual([]);
    expect(collectFiles([join(d, CONFIG_NAME)])).toEqual([]);
  });
  it('depth is bounded at 8 levels', () => {
    const d = mkdtempSync(join(tmpdir(), 'pcacli-'));
    let cur = d;
    for (let i = 0; i < 10; i++) {
      cur = join(cur, `l${i}`);
      mkdirSync(cur);
      writeFileSync(join(cur, 'f.yaml'), '{}');
    }
    const found = collectFiles([d]);
    // the root is depth 0, so a file under l6 sits at depth 8 (kept) and one under l7 at depth 9 (dropped)
    expect(found).toHaveLength(7);
    expect(found.some((f) => f.includes(`${sep}l6${sep}`))).toBe(true);
    expect(found.some((f) => f.includes(`${sep}l7${sep}`))).toBe(false);
  });
  it('a missing path names itself', () => {
    expect(() => collectFiles(['/no/such/dir/x'])).toThrow(new Error('no such file or directory: /no/such/dir/x'));
  });
  it('the config is looked up next to a directory or a file, and a missing one is null', () => {
    const d = tree();
    const text = JSON.stringify(base);
    writeFileSync(join(d, CONFIG_NAME), text);
    expect(findConfig([d])).toMatchObject({ ns: 'acme' });
    expect(findConfig([join(d, 'b.yaml')])).toMatchObject({ ns: 'acme' });
    expect(findConfig([join(d, 'sub')])).toBeNull();
    expect(findConfig([join(d, 'sub'), d])).toMatchObject({ ns: 'acme' });
    writeFileSync(join(d, CONFIG_NAME), '{');
    expect(findConfig([d])).toMatch(/not JSON/);
    expect(findConfig([])).toBeNull();
  });
});
