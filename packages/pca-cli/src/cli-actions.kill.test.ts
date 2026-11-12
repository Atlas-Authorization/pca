import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { b64u, sha256, utf8 } from '@atlasauth/pca';
import { actionSchemaDigest, actionSchemaKeyOf } from '@atlasauth/pca/ext/intent';
import { defsToYaml, loadActionsText, packKeyOf, type ActionDef } from '@atlasauth/pca-actions';
import { ACTION_TEMPLATES, cmdBuild, cmdInit, cmdSign } from './actions';
import { cmdSchemaConform, cmdSchemaInit, cmdSchemaSign } from './schema';

const io = vi.hoisted(() => ({ stdin: '' }));
vi.mock('node:fs', async (orig) => {
  const actual = await orig<typeof import('node:fs')>();
  const readFileSync = ((p: unknown, ...rest: unknown[]) => (p === 0 ? io.stdin : (actual.readFileSync as (...a: unknown[]) => unknown)(p, ...rest))) as typeof actual.readFileSync;
  return { ...actual, readFileSync };
});

interface Run { out: string; err: string; code: number | string | undefined }

async function pca(args: string[], stdin = ''): Promise<Run> {
  const out: string[] = [];
  const err: string[] = [];
  const so = vi.spyOn(process.stdout, 'write').mockImplementation(((s: unknown) => (out.push(String(s)), true)) as never);
  const se = vi.spyOn(process.stderr, 'write').mockImplementation(((s: unknown) => (err.push(String(s)), true)) as never);
  const argv = process.argv;
  const prevCode = process.exitCode;
  process.exitCode = undefined;
  process.argv = ['node', 'pca', ...args];
  io.stdin = stdin;
  try {
    vi.resetModules();
    await import('./cli');
    let stable = 0;
    let last = '';
    for (let i = 0; i < 4000 && stable < 40; i++) {
      await new Promise<void>((r) => setImmediate(r));
      const now = out.join('') + '|' + err.join('');
      stable = now === last ? stable + 1 : 0;
      last = now;
    }
    return { out: out.join(''), err: err.join(''), code: process.exitCode };
  } finally {
    process.argv = argv;
    process.exitCode = prevCode;
    so.mockRestore();
    se.mockRestore();
  }
}

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });
const tmp = (): string => mkdtempSync(join(tmpdir(), 'pcacli-ca-'));
const put = (dir: string, name: string, text: string): string => { const f = join(dir, name); writeFileSync(f, text); return f; };
const read = (...p: string[]): string => readFileSync(join(...p), 'utf8');
// fixed keys: a random base64url secret could start with '--' and be taken for a flag
const keyBytes = (label: string): Uint8Array => sha256(utf8(label));
const sk = (label = 'reviewer'): string => b64u(keyBytes(label));
const inDir = async <T>(dir: string, run: () => Promise<T>): Promise<T> => {
  const cwd = process.cwd();
  process.chdir(dir);
  try { return await run(); } finally { process.chdir(cwd); }
};

const def = (verb: string, union: string[], traits: string[] = union): ActionDef => ({
  v: 1, kind: 'pca-action-def', verb, title: 'Create a refund', description: 'Creates a refund.', effects: ['create'],
  resource: { type: 'acme.refund', id: '*', scope: 'set' },
  params: { note: { type: 'string', max_len: 100 }, idempotency_key: { type: 'string', max_len: 64, required: false } },
  reversibility: 'irreversible', idempotency: { mode: 'key_param', param: 'idempotency_key' },
  traits: [...traits], review: { state: 'authored', ...(union.length ? { provenance: { union: [...union] } } : {}) }, since: '0.5.0',
});
const TWO = defsToYaml('acme', [def('acme.a.create', ['pca.money_moving']), def('acme.d.create', ['pca.money_moving', 'pca.destructive'])]);

describe('pca actions confirm', () => {
  it('prints the review and writes nothing without --yes', async () => {
    const dir = tmp();
    const f = put(dir, 'actions.yaml', TWO);
    const r = await pca(['actions', 'confirm', 'acme.a.create', '--file', f, '--kid', 'rev-1']);
    expect(r.code).toBeUndefined();
    expect(r.out).toMatch(/^acme\.a\.create {2}\[/);
    expect(r.out.endsWith('\n(nothing signed: pass --yes with --reviewer-key to confirm)\n')).toBe(true);
    expect(read(dir, 'actions.yaml')).toBe(TWO);
    const o = join(dir, 'out.yaml');
    await pca(['actions', 'confirm', 'acme.a.create', '--file', f, '--out', o]);
    expect(existsSync(o)).toBe(false);
  });
  it('signs in place by default, from ./actions.yaml, with a seconds timestamp, and reports the count and the reviewer', async () => {
    const dir = tmp();
    put(dir, 'actions.yaml', TWO);
    const before = Math.floor(Date.now() / 1000);
    const r = await inDir(dir, () => pca(['actions', 'confirm', 'acme.a.create', '--kid', 'rev-1', '--reviewer-key', sk(), '--yes', '--dismiss', 'pca.money_moving=lookup only']));
    const after = Math.floor(Date.now() / 1000);
    expect(r.out).toBe('1 confirmed by rev-1 (the attestation is valid only against the reviewer keys your registry pins)\n');
    expect(r.code).toBeUndefined();
    const defs = loadActionsText(read(dir, 'actions.yaml')).defs;
    const a = defs.find((d) => d.verb === 'acme.a.create')!;
    expect(a.review.state).toBe('confirmed');
    expect(a.review.attestation!.reviewer_kid).toBe('rev-1');
    expect(a.review.attestation!.ts).toBeGreaterThanOrEqual(before);
    expect(a.review.attestation!.ts).toBeLessThanOrEqual(after);
    expect(defs.find((d) => d.verb === 'acme.d.create')!.review.state).toBe('authored');
  });
  it('--out writes elsewhere and leaves the source alone', async () => {
    const dir = tmp();
    const f = put(dir, 'src.yaml', TWO);
    const o = join(dir, 'out.yaml');
    const r = await pca(['actions', 'confirm', 'acme.a.create', '--file', f, '--out', o, '--kid', 'rev-1', '--reviewer-key', sk(), '--yes', '--dismiss', 'pca.money_moving=lookup only']);
    expect(r.code).toBeUndefined();
    expect(read(dir, 'src.yaml')).toBe(TWO);
    expect(loadActionsText(readFileSync(o, 'utf8')).defs.find((d) => d.verb === 'acme.a.create')!.review.state).toBe('confirmed');
  });
  it('--final is a comma list that ignores empty entries, --dismiss a ;;-separated list of trait=reason', async () => {
    const dir = tmp();
    const f = put(dir, 'actions.yaml', TWO);
    const r = await pca(['actions', 'confirm', 'acme.d.create', '--file', f, '--kid', 'rev-1', '--reviewer-key', sk(), '--yes', '--final', 'pca.destructive,', '--dismiss', 'pca.money_moving=r1']);
    expect(r.code, r.out).toBeUndefined();
    const d = loadActionsText(read(dir, 'actions.yaml')).defs.find((x) => x.verb === 'acme.d.create')!;
    expect(d.review.attestation!.final_traits).toEqual(['pca.destructive']);
    const g = put(dir, 'both.yaml', TWO);
    const r2 = await pca(['actions', 'confirm', 'acme.d.create', '--file', g, '--kid', 'rev-1', '--reviewer-key', sk(), '--yes', '--dismiss', 'pca.money_moving=r1;;pca.destructive=r2']);
    expect(r2.code, r2.out).toBeUndefined();
    const e = loadActionsText(read(dir, 'both.yaml')).defs.find((x) => x.verb === 'acme.d.create')!;
    expect([...e.review.attestation!.dismissed].sort((x, y) => (x.trait < y.trait ? -1 : 1))).toEqual([{ trait: 'pca.destructive', reason: 'r2' }, { trait: 'pca.money_moving', reason: 'r1' }]);
  });
  it('--origin and --trait select the defs to review', async () => {
    const dir = tmp();
    const f = put(dir, 'actions.yaml', TWO);
    const r = await pca(['actions', 'confirm', '--file', f, '--origin', 'union', '--trait', 'destructive']);
    expect(r.out).toContain('acme.d.create  [');
    expect(r.out).not.toContain('acme.a.create');
    const all = await pca(['actions', 'review', '--file', f, '--origin', 'any']);
    expect(all.out).toContain('acme.a.create  [');
    expect(all.out).toContain('acme.d.create  [');
  });
  it('a refused confirmation prints the reason on stdout and exits 1', async () => {
    const dir = tmp();
    const f = put(dir, 'actions.yaml', TWO);
    expect(await pca(['actions', 'confirm', 'acme.a.create', '--file', f, '--yes'])).toEqual({ out: '--reviewer-key is required to confirm\n', err: '', code: 1 });
    expect(read(dir, 'actions.yaml')).toBe(TWO);
  });
  it('signs the business rules of what it confirms into pca.rules-reviews.json next to the written file, and only then', async () => {
    const dir = tmp();
    const other = join(dir, 'other');
    mkdirSync(other);
    const hello = ACTION_TEMPLATES.minimal!('acme').replace(/\n    examples:\n/, '\n    rules:\n      required: [note]\n    examples:\n');
    const f = put(dir, 'acme.yaml', hello);
    const key = sk();
    const r = await pca(['actions', 'confirm', 'acme.invoice.send', '--file', f, '--kid', 'rev-1', '--reviewer-key', key, '--yes']);
    expect(r.out).toBe('1 confirmed by rev-1 (and the business rules of 1) (the attestation is valid only against the reviewer keys your registry pins)\n');
    const reviews = JSON.parse(read(dir, 'pca.rules-reviews.json')) as Record<string, { reviewer_kid: string }>;
    expect(Object.keys(reviews)).toEqual(['acme.invoice.send']);
    expect(reviews['acme.invoice.send']!.reviewer_kid).toBe('rev-1');
    const g = put(dir, 'second.yaml', hello);
    const o = join(other, 'out.yaml');
    await pca(['actions', 'confirm', 'acme.invoice.send', '--file', g, '--out', o, '--kid', 'rev-2', '--reviewer-key', key, '--yes']);
    expect((JSON.parse(read(other, 'pca.rules-reviews.json')) as Record<string, { reviewer_kid: string }>)['acme.invoice.send']!.reviewer_kid).toBe('rev-2');
    expect((JSON.parse(read(dir, 'pca.rules-reviews.json')) as Record<string, { reviewer_kid: string }>)['acme.invoice.send']!.reviewer_kid).toBe('rev-1');
    const plain = tmp();
    const p = put(plain, 'acme.yaml', ACTION_TEMPLATES.minimal!('acme'));
    await pca(['actions', 'confirm', 'acme.invoice.send', '--file', p, '--kid', 'rev-1', '--reviewer-key', key, '--yes']);
    expect(existsSync(join(plain, 'pca.rules-reviews.json'))).toBe(false);
  });

  describe('--pack', () => {
    const shopDefs = loadActionsText(ACTION_TEMPLATES.db!('shop')).defs;
    const writePack = (dir: string): void => {
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, 'pack.json'), JSON.stringify({ ns: ['shop'], shards: [{ file: 's.jsonl' }] }));
      writeFileSync(join(dir, 's.jsonl'), shopDefs.map((d) => JSON.stringify(d)).join('\n') + '\n');
    };
    it('a pack under --packs-dir is reviewed whole with --origin any, and written to <name>.reviewed.yaml', async () => {
      const root = tmp();
      writePack(join(root, 'cat', 'my.pack-1', '1.0.0'));
      const work = tmp();
      const r = await inDir(work, () => pca(['actions', 'confirm', '--pack', 'my.pack-1', '--packs-dir', join(root, 'cat'), '--origin', 'any', '--kid', 'rev-1', '--reviewer-key', sk(), '--yes']));
      expect(r.out).toBe('2 confirmed by rev-1 (the attestation is valid only against the reviewer keys your registry pins)\n');
      const written = loadActionsText(read(work, 'my.pack-1.reviewed.yaml'));
      expect(written.defs.map((d) => d.review.state)).toEqual(['confirmed', 'confirmed']);
    });
    it('the file name replaces every character outside A-Za-z0-9._- with an underscore', async () => {
      const work = tmp();
      writePack(join(work, 'pk dir'));
      const r = await inDir(work, () => pca(['actions', 'confirm', '--pack', 'pk dir', '--origin', 'any', '--kid', 'rev-1', '--reviewer-key', sk(), '--yes']));
      expect(r.code, r.out + r.err).toBeUndefined();
      expect(existsSync(join(work, 'pk_dir.reviewed.yaml'))).toBe(true);
    });
    it('--packs-dir defaults to ./packs, and an unknown pack is an error', async () => {
      const work = tmp();
      writePack(join(work, 'packs', 'shop', '0.1.0'));
      const view = await inDir(work, () => pca(['actions', 'confirm', '--pack', 'shop', '--origin', 'any']));
      expect(view.out).toContain('shop.row.get  [');
      const gone = await inDir(work, () => pca(['actions', 'confirm', '--pack', 'nope', '--origin', 'any']));
      expect(gone).toEqual({ out: '', err: "pca: no pack 'nope' (a pack directory, or a name under packs)\n", code: 1 });
    });
    it('--out overrides the default name', async () => {
      const work = tmp();
      writePack(join(work, 'p'));
      const o = join(work, 'mine.yaml');
      await pca(['actions', 'confirm', '--pack', join(work, 'p'), '--origin', 'any', '--out', o, '--kid', 'rev-1', '--reviewer-key', sk(), '--yes']);
      expect(existsSync(o)).toBe(true);
    });
  });
});

// ---- sign and publish ---------------------------------------------------------------------------------------------------------------

function built(template = 'minimal', ns = 'acme') {
  const root = tmp();
  const dir = join(root, 'actions');
  const out = join(root, '.pca');
  expect(cmdInit({ dir, ns, template }).ok).toBe(true);
  expect(cmdBuild([dir], { out }).ok).toBe(true);
  return { root, dir, out };
}

describe('pca actions sign', () => {
  it('signs the build and prints what cmdSign prints', async () => {
    const { dir, out } = built();
    const s = keyBytes('site');
    const r = await pca(['actions', 'sign', dir, '--out', out, '--kid', 'site-1', '--key', b64u(s)]);
    expect(r.code).toBeUndefined();
    const root = JSON.parse(read(out, 'pack.json')).root as string;
    expect(r.out).toBe(`signed schema ${actionSchemaDigest(JSON.parse(read(out, 'pca-actions.json')))} and pack ${root}\nkeys: ${join(out, 'keys.json')} (list them under intent.schema_keys in your discovery document)\n`);
    expect(JSON.parse(read(out, 'keys.json'))).toEqual([actionSchemaKeyOf('site-1', s)]);
  });
  it('--pack-kid and --pack-key give the pack its own key, listed after the site key', async () => {
    const { dir, out } = built();
    const s = keyBytes('site');
    const p = keyBytes('registry');
    const r = await pca(['actions', 'sign', dir, '--out', out, '--kid', 'site-1', '--key', b64u(s), '--pack-kid', 'reg-1', '--pack-key', b64u(p)]);
    expect(r.code, r.out).toBeUndefined();
    expect(JSON.parse(read(out, 'keys.json'))).toEqual([actionSchemaKeyOf('site-1', s), packKeyOf('reg-1', p)]);
    const second = built();
    await pca(['actions', 'sign', second.dir, '--out', second.out, '--kid', 'site-1', '--key', b64u(s), '--pack-kid', 'reg-2']);
    expect(JSON.parse(read(second.out, 'keys.json'))).toEqual([actionSchemaKeyOf('site-1', s), packKeyOf('reg-2', s)]);
  });
  it('without a path it uses ./actions and without --out ./.pca', async () => {
    const { root } = built();
    const out = await inDir(root, () => pca(['actions', 'build']));
    expect(out.code, out.err).toBeUndefined();
    const r = await inDir(root, () => pca(['actions', 'sign', '--kid', 'k', '--key', sk()]));
    expect(r.code, r.out).toBeUndefined();
    expect(existsSync(join(root, '.pca', 'pca-actions.json'))).toBe(true);
  });
  it('a failing sign prints the reason on stdout and exits 1', async () => {
    const { dir, out } = built();
    const r = await pca(['actions', 'sign', dir, '--out', out, '--kid', 'k', '--key', 'AAAA']);
    expect(r).toEqual({ out: 'not signing: a signing key must be a base64url 32-byte Ed25519 secret\n', err: '', code: 1 });
  });
});

describe('pca actions publish', () => {
  const REG = '/v1/pca/action-registry/packs';
  const stubFetch = (calls: Array<{ url: string; auth: string }>) => vi.stubGlobal('fetch', async (url: string, init: { headers: Record<string, string> }) => {
    calls.push({ url, auth: init.headers.authorization! });
    return url.endsWith(REG)
      ? { status: 201, json: async () => ({ version: '0.1.0', status: 'active', changes: [] }) }
      : { status: 201, json: async () => ({ digest: 'd1', anchor: { index: 7 } }) };
  });
  const signed = () => {
    const b = built();
    expect(cmdSign([b.dir], { out: b.out, kid: 'k', key: sk() }).ok).toBe(true);
    return b;
  };
  const withEnv = async (value: string | undefined, run: () => Promise<void>): Promise<void> => {
    const prev = process.env.ATLAS_SECRET_KEY;
    if (value === undefined) delete process.env.ATLAS_SECRET_KEY; else process.env.ATLAS_SECRET_KEY = value;
    try { await run(); } finally { if (prev === undefined) delete process.env.ATLAS_SECRET_KEY; else process.env.ATLAS_SECRET_KEY = prev; }
  };

  it('without --api it only writes the discovery file', async () => {
    const { dir, out } = signed();
    const calls: Array<{ url: string; auth: string }> = [];
    stubFetch(calls);
    await withEnv('sk_env', async () => {
      const r = await pca(['actions', 'publish', dir, '--out', out]);
      expect(r).toEqual({ out: `wrote ${join(out, '.well-known', 'pca-actions.json')}\n`, err: '', code: undefined });
    });
    expect(calls).toEqual([]);
  });
  it('--api with --sk anchors and publishes, using the flag over the environment', async () => {
    const { dir, out } = signed();
    const calls: Array<{ url: string; auth: string }> = [];
    stubFetch(calls);
    await withEnv('sk_env', async () => {
      const r = await pca(['actions', 'publish', dir, '--out', out, '--api', 'https://api.example.com', '--sk', 'sk_flag']);
      expect(r.code, r.out).toBeUndefined();
      expect(r.out).toBe(`wrote ${join(out, '.well-known', 'pca-actions.json')}\nOK  anchored d1 at log index 7\nregistry: acme@0.1.0 active\n`);
    });
    expect(calls).toEqual([{ url: 'https://api.example.com/v1/pca/intent/schemas', auth: 'Bearer sk_flag' }, { url: `https://api.example.com${REG}`, auth: 'Bearer sk_flag' }]);
  });
  it('--api alone takes the key from ATLAS_SECRET_KEY, and fails when that is not set either', async () => {
    const { dir, out } = signed();
    const calls: Array<{ url: string; auth: string }> = [];
    stubFetch(calls);
    await withEnv('sk_env', async () => {
      const r = await pca(['actions', 'publish', dir, '--out', out, '--api', 'https://api.example.com']);
      expect(r.code, r.out).toBeUndefined();
    });
    expect(calls.map((c) => c.auth)).toEqual(['Bearer sk_env', 'Bearer sk_env']);
    await withEnv(undefined, async () => {
      expect(await pca(['actions', 'publish', dir, '--out', out, '--api', 'https://api.example.com'])).toEqual({ out: 'publish: --api and --sk go together\n', err: '', code: 1 });
    });
  });
  it('a refusal exits 1 with the reason', async () => {
    const { dir, out } = signed();
    vi.stubGlobal('fetch', async () => ({ status: 500, json: async () => ({}) }));
    expect(await pca(['actions', 'publish', dir, '--out', out, '--api', 'https://api.example.com', '--sk', 'sk_x'])).toEqual({ out: 'FAIL  HTTP 500\n', err: '', code: 1 });
  });
  it('without --out it reads ./.pca', async () => {
    const { root, dir } = signed();
    const r = await inDir(root, () => pca(['actions', 'publish', dir]));
    expect(r.out).toBe(`wrote ${join('.pca', '.well-known', 'pca-actions.json')}\n`);
  });
});

// ---- sync ---------------------------------------------------------------------------------------------------------------------

describe('pca actions sync', () => {
  const API = (n: number): string => JSON.stringify({ openapi: '3.0.0', paths: Object.fromEntries(Array.from({ length: n }, (_, i) => [`/items${i}/{id}`, { parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', maxLength: 40 } }], get: { operationId: `getItem${i}`, summary: `Get item ${i}` } }])) });
  const project = (n = 1) => {
    const root = tmp();
    const dir = join(root, 'actions');
    cmdInit({ dir, ns: 'shop' });
    writeFileSync(join(root, 'openapi.json'), API(n));
    const cfg = JSON.parse(read(dir, 'pca.config.json'));
    put(dir, 'pca.config.json', JSON.stringify({ ...cfg, sources: [{ name: 'api', from: 'openapi', file: '../openapi.json' }, { name: 'web', from: 'openapi', file: '../openapi.json' }] }));
    return { root, dir };
  };

  it('syncs every source, or only --source, and prints the result', async () => {
    const p = project();
    const one = await pca(['actions', 'sync', p.dir, '--source', 'web']);
    expect(one.code).toBeUndefined();
    expect(one.out.startsWith('web (openapi):\n')).toBe(true);
    expect(one.out.endsWith('\n')).toBe(true);
    expect(existsSync(join(p.dir, 'api.sync.yaml'))).toBe(false);
    const all = await pca(['actions', 'sync', p.dir]);
    expect(all.out.split('\n').filter((l) => /^\S/.test(l))).toEqual(['api (openapi):', 'web (openapi):']);
    expect(existsSync(join(p.dir, 'api.sync.yaml'))).toBe(true);
  });
  it('--check does not take the next argument as its value, writes nothing and exits 1 when the sources moved', async () => {
    const p = project();
    await pca(['actions', 'sync', p.dir]);
    const same = await pca(['actions', 'sync', '--check', p.dir]);
    expect(same.code).toBeUndefined();
    expect(same.out).toContain('0 added, 0 changed, 0 removed (deprecated), 1 unchanged');
    writeFileSync(join(p.root, 'openapi.json'), API(2));
    const before = read(p.dir, 'pca.sync.json');
    const moved = await pca(['actions', 'sync', '--check', p.dir]);
    expect(moved.code).toBe(1);
    expect(moved.out.endsWith('\nthe sources changed: run pca actions sync and review the added and changed actions\n')).toBe(true);
    expect(read(p.dir, 'pca.sync.json')).toBe(before);
    const real = await pca(['actions', 'sync', p.dir]);
    expect(real.code).toBeUndefined();
    expect(real.out).not.toContain('the sources changed');
  });
  it('without a path it syncs ./actions', async () => {
    const p = project();
    const r = await inDir(p.root, () => pca(['actions', 'sync']));
    expect(r.code, r.out).toBeUndefined();
    expect(existsSync(join(p.dir, 'pca.sync.json'))).toBe(true);
  });
});

// ---- schema -------------------------------------------------------------------------------------------------------------------

describe('pca schema (deprecated)', () => {
  const WARN = 'pca schema is deprecated and will be removed in the next release; use pca actions (import, sign, publish)\n';
  const OPENAPI = JSON.stringify({
    paths: { '/book': { post: { operationId: 'createBooking', 'x-pca-verb': 'air.book', 'x-pca-reversibility': 'irreversible', requestBody: { content: { 'application/json': { schema: { properties: { total: { type: 'integer', minimum: 0 } }, required: ['total'] } } } } } } },
  });
  const MCP = JSON.stringify({ tools: [{ name: 'search', inputSchema: { type: 'object', properties: { q: { type: 'string' } } }, annotations: { readOnlyHint: true } }] });
  const flagsFor = ['--site', 'https://s', '--aud', 's', '--version', '1'];

  it('init drafts from OpenAPI or MCP, from a file or stdin, with the todo list on stderr', async () => {
    const dir = tmp();
    const fo = put(dir, 'api.json', OPENAPI);
    const fm = put(dir, 'tools.json', MCP);
    const wantO = cmdSchemaInit(OPENAPI, { from: 'openapi', site: 'https://s', aud: 's', version: '1' });
    expect(wantO.todo.length).toBeGreaterThan(0);
    expect(await pca(['schema', 'init', fo, '--from', 'openapi', ...flagsFor])).toEqual({ out: wantO.schema + '\n', err: WARN + wantO.todo.map((t) => `decide: ${t}\n`).join(''), code: undefined });
    const wantM = cmdSchemaInit(MCP, { from: 'mcp', site: 'https://s', aud: 's', version: '1', verbPrefix: 'x.' });
    const m = await pca(['schema', 'init', fm, '--from', 'mcp', ...flagsFor, '--prefix', 'x.']);
    expect(m.out).toBe(wantM.schema + '\n');
    expect(m.err).toBe(WARN + wantM.todo.map((t) => `decide: ${t}\n`).join(''));
    expect(JSON.parse(m.out).verbs[0].verb).toBe('x.search');
    const plain = cmdSchemaInit(MCP, { from: 'mcp', site: 'https://s', aud: 's', version: '1' });
    expect((await pca(['schema', 'init', '-', '--from', 'mcp', ...flagsFor], MCP)).out).toBe(plain.schema + '\n');
    expect(plain.schema).not.toBe(wantM.schema);
  });
  it('sign writes the signed schema to stdout and the digest and key entry to stderr; the key may be @file', async () => {
    const dir = tmp();
    const draft = cmdSchemaInit(OPENAPI, { from: 'openapi', site: 'https://s', aud: 's', version: '1' }).schema;
    const fd = put(dir, 'draft.json', draft);
    const secret = sk();
    const want = cmdSchemaSign(draft, { kid: 'k1', secret });
    expect(await pca(['schema', 'sign', fd, '--kid', 'k1', '--key', secret])).toEqual({ out: want.schema + '\n', err: `${WARN}digest ${want.digest}\nintent.schema_keys entry: ${JSON.stringify(want.key)}\n`, code: undefined });
    const kf = put(dir, 'k.key', secret + '\n');
    const viaFile = await pca(['schema', 'sign', fd, '--kid', 'k1', '--key', `@${kf}`]);
    expect(viaFile.out).toBe(want.schema + '\n');
    expect(viaFile.err).toBe(`${WARN}digest ${want.digest}\nintent.schema_keys entry: ${JSON.stringify(want.key)}\n`);
    expect((await pca(['schema', 'sign', '-', '--kid', 'k1', '--key', secret], draft)).out).toBe(want.schema + '\n');
  });
  it('verify and conform print their result and exit 1 on failure', async () => {
    const dir = tmp();
    const draft = cmdSchemaInit(OPENAPI, { from: 'openapi', site: 'https://s', aud: 's', version: '1' }).schema;
    const signed = cmdSchemaSign(draft, { kid: 'k1', secret: sk() });
    const fs = put(dir, 'schema.json', signed.schema);
    const fk = put(dir, 'keys.json', JSON.stringify([signed.key]));
    expect(await pca(['schema', 'verify', fs, fk])).toEqual({ out: `OK  digest ${signed.digest}\n`, err: WARN, code: undefined });
    const bad = put(dir, 'badkeys.json', JSON.stringify([{ ...signed.key, kid: 'other' }]));
    const v = await pca(['schema', 'verify', fs, bad]);
    expect(v.code).toBe(1);
    expect(v.out).toMatch(/^FAIL {2}.+\n$/);
    expect((await pca(['schema', 'verify', '-', fk], signed.schema)).out).toBe(`OK  digest ${signed.digest}\n`);
    const good = put(dir, 'good.json', '{"total": 5}');
    const bad2 = put(dir, 'bad.json', '{"total": 5, "x": 1}');
    expect(await pca(['schema', 'conform', fs, 'air.book', good])).toEqual({ out: "OK  'air.book' conforms\n", err: WARN, code: undefined });
    const d = await pca(['schema', 'conform', fs, 'air.book', bad2]);
    expect(d.out).toBe(cmdSchemaConform(signed.schema, 'air.book', '{"total": 5, "x": 1}').text + '\n');
    expect(d.code).toBe(1);
    expect((await pca(['schema', 'conform', fs, 'air.book', '-'], '{"total": 5}')).out).toBe("OK  'air.book' conforms\n");
  });
  it('publish anchors the schema and exits 1 when the instance refuses', async () => {
    const dir = tmp();
    const draft = cmdSchemaInit(OPENAPI, { from: 'openapi', site: 'https://s', aud: 's', version: '1' }).schema;
    const signed = cmdSchemaSign(draft, { kid: 'k1', secret: sk() });
    const fs = put(dir, 'schema.json', signed.schema);
    const fk = put(dir, 'keys.json', JSON.stringify([signed.key]));
    const calls: Array<{ url: string; auth: string }> = [];
    vi.stubGlobal('fetch', async (url: string, init: { headers: Record<string, string> }) => { calls.push({ url, auth: init.headers.authorization! }); return { status: 201, json: async () => ({ digest: signed.digest, anchor: { index: 4 } }) }; });
    expect(await pca(['schema', 'publish', fs, fk, '--api', 'https://inst.example', '--sk', 'sk_x'])).toEqual({ out: `OK  anchored ${signed.digest} at log index 4\n`, err: WARN, code: undefined });
    expect(calls).toEqual([{ url: 'https://inst.example/v1/pca/intent/schemas', auth: 'Bearer sk_x' }]);
    vi.stubGlobal('fetch', async () => ({ status: 500, json: async () => ({}) }));
    expect(await pca(['schema', 'publish', fs, fk, '--api', 'https://inst.example', '--sk', 'sk_x'])).toEqual({ out: 'FAIL  HTTP 500\n', err: WARN, code: 1 });
  });
});

describe('top-level failures', () => {
  it('an unknown schema or actions sub-command, and an unknown command, name themselves and carry the usage', async () => {
    const s = await pca(['schema', 'zzz']);
    expect(s.err.startsWith("pca schema is deprecated")).toBe(true);
    expect(s.err).toContain("pca: schema: unknown sub-command 'zzz'\n\npca — Proof-Carrying Authority dev CLI\n");
    const a = await pca(['actions', 'zzz']);
    expect(a.err.startsWith("pca: actions: unknown sub-command 'zzz'\n\npca — Proof-Carrying Authority dev CLI\n")).toBe(true);
    expect(a.err.endsWith('\n')).toBe(true);
    expect(a.code).toBe(1);
  });
});
