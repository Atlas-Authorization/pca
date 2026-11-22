import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { agent, b64u, generateKeyPair, sha256, utf8 } from '@atlasauth/pca';
import { ACTION_TEMPLATES, cmdConfirm, cmdImport, cmdImportModel, cmdInit, cmdLint } from './actions';
import { inCwd } from './cwd-fixture';
import { cmdDecode } from './index';
import { defsToYaml, loadActionsText, type ActionDef } from '@atlasauth/pca-actions';

// STDIN is read like the real readFileSync(0, encoding): a string only when an encoding is given, else a Buffer.
const io = vi.hoisted(() => ({ stdin: '' }));
vi.mock('node:fs', async (orig) => {
  const actual = await orig<typeof import('node:fs')>();
  const wrapped = (await import('./cwd-fixture')).withVirtualCwd(actual);
  const readFileSync = ((p: unknown, ...rest: unknown[]) => {
    if (p !== 0) return (wrapped.readFileSync as (...a: unknown[]) => unknown)(p, ...rest);
    return rest[0] === 'utf8' ? io.stdin : Buffer.from(io.stdin, 'utf8');
  }) as typeof actual.readFileSync;
  return { ...wrapped, readFileSync };
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

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); });
const tmp = (): string => mkdtempSync(join(tmpdir(), 'pcacli-args-'));
const put = (dir: string, name: string, text: string): string => { const f = join(dir, name); writeFileSync(f, text); return f; };
const sk = b64u(sha256(utf8('reviewer')));
const WARN = 'pca schema is deprecated and will be removed in the next release; use pca actions (import, sign, publish)\n';
const project = (): string => { const dir = join(tmp(), 'actions'); expect(cmdInit({ dir, ns: 'acme' }).ok).toBe(true); return dir; };

describe('STDIN', () => {
  it('is read as UTF-8 text', async () => {
    const { encoded } = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: 'ins_test' }).act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' }, { counter: 1 });
    expect(await pca(['decode', '-'], encoded)).toEqual({ out: cmdDecode(encoded) + '\n', err: '', code: undefined });
  });
});

describe('argument parsing', () => {
  it('--force takes no value, and --=value is a flag with an empty name: neither swallows the path after it', async () => {
    const dir = project();
    const want = cmdLint([dir], { strict: false, format: 'text' });
    const empty = tmp();
    for (const flag of ['--force', '--=x']) {
      expect(await inCwd(empty, () => pca(['actions', 'lint', flag, dir]))).toEqual({ out: want.text + '\n', err: '', code: want.ok ? undefined : 1 });
    }
  });
  it('--strict fails a lint that has only warnings', async () => {
    const dir = project();
    const cfg = JSON.parse(readFileSync(join(dir, 'pca.config.json'), 'utf8')) as Record<string, unknown>;
    put(dir, 'pca.config.json', JSON.stringify({ ...cfg, stability: 'beta' }));
    expect(cmdLint([dir]).ok).toBe(true);
    const strict = cmdLint([dir], { strict: true });
    expect(strict.ok).toBe(false);
    expect(await pca(['actions', 'lint', '--strict', dir])).toEqual({ out: strict.text + '\n', err: '', code: 1 });
  });
});

describe('pca actions init', () => {
  it('defaults to --dir actions and --ns acme', async () => {
    const root = tmp();
    const r = await inCwd(root, () => pca(['actions', 'init']));
    expect(r).toEqual({ out: `wrote ${join('actions', 'acme.yaml')}, ${join('actions', 'pca.config.json')}\n`, err: '', code: undefined });
    expect(readFileSync(join(root, 'actions', 'acme.yaml'), 'utf8')).toBe(ACTION_TEMPLATES.minimal!('acme'));
  });
  it('--template picks the template', async () => {
    const dir = join(tmp(), 'p');
    const r = await pca(['actions', 'init', '--dir', dir, '--ns', 'shop', '--template', 'db']);
    expect(r.code).toBeUndefined();
    expect(readFileSync(join(dir, 'shop.yaml'), 'utf8')).toBe(ACTION_TEMPLATES.db!('shop'));
  });
});

describe('pca actions import', () => {
  const MCP = JSON.stringify({ tools: [
    { name: 'search_orders', description: 'Search orders', inputSchema: { type: 'object', properties: { q: { type: 'string', maxLength: 100 } }, required: ['q'] }, annotations: { readOnlyHint: true } },
    { name: 'delete_order', inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] }, annotations: { destructiveHint: true, idempotentHint: true } },
    { name: 'price', inputSchema: { type: 'object', properties: { amount: { type: 'number' } } } },
  ] });
  const ONE_TOOL = JSON.stringify({ tools: [{ name: 'search_orders', description: 'Search orders', inputSchema: { type: 'object', properties: { q: { type: 'string', maxLength: 100 } }, required: ['q'] } }] });
  const printed = (r: ReturnType<typeof cmdImport>): Run => ({ out: r.yaml, err: r.todo.map((t) => `todo: ${t}\n`).join('') + r.text + '\n', code: undefined });

  it('a missing source is an argument error even with --from and --ns', async () => {
    expect((await pca(['actions', 'import', '--from', 'openapi', '--ns', 'shop'])).err).toBe('pca: actions import: <file|-> --from --ns are required\n');
  });
  it('prints each todo on its own line on stderr', async () => {
    const f = put(tmp(), 'tools.json', MCP);
    const want = cmdImport(MCP, { from: 'mcp', ns: 'shop' });
    expect(want.ok).toBe(true);
    expect(want.todo.length).toBeGreaterThan(0);
    expect(await pca(['actions', 'import', f, '--from', 'mcp', '--ns', 'shop'])).toEqual(printed(want));
  });
  it('--uri, --licence and --suggest reach the import', async () => {
    const f = put(tmp(), 'tools.json', ONE_TOOL);
    const opts = { from: 'mcp', ns: 'shop', uri: 'https://shop.example.com/mcp', licence: 'MIT', suggest: 'none' };
    const want = cmdImport(ONE_TOOL, opts);
    expect(want.ok).toBe(true);
    expect(want.yaml).not.toBe(cmdImport(ONE_TOOL, { from: 'mcp', ns: 'shop', suggest: 'none' }).yaml);
    expect(await pca(['actions', 'import', f, '--from', 'mcp', '--ns', 'shop', '--uri', opts.uri, '--licence', 'MIT', '--suggest', 'none'])).toEqual(printed(want));
  });
  it('--verb reaches a JSON Schema import', async () => {
    const schema = JSON.stringify({ title: 'Ping', properties: { host: { type: 'string', maxLength: 64 } }, required: ['host'] });
    const f = put(tmp(), 'ping.json', schema);
    const want = cmdImport(schema, { from: 'jsonschema', ns: 'ops', verb: 'ops.host.ping' });
    expect(want.ok, want.text).toBe(true);
    expect(await pca(['actions', 'import', f, '--from', 'jsonschema', '--ns', 'ops', '--verb', 'ops.host.ping'])).toEqual(printed(want));
  });
  it('--suggest model asks the provider named by --provider with the pinned --model, through fetch', async () => {
    const f = put(tmp(), 'tools.json', ONE_TOOL);
    vi.stubEnv('OPENAI_API_KEY', 'key-o');
    vi.stubEnv('ANTHROPIC_API_KEY', '');
    vi.stubEnv('ATLAS_PCA_SUGGEST_MODEL', '');
    vi.stubEnv('ATLAS_PCA_SUGGEST_PROVIDER', '');
    const urls: string[] = [];
    const fake = async (url: string) => { urls.push(url); return { ok: true, status: 200, json: async () => ({ choices: [{ message: { content: '["pca.data_export"]' } }] }) }; };
    vi.stubGlobal('fetch', fake);
    const want = await cmdImportModel(ONE_TOOL, { from: 'mcp', ns: 'shop', model: 'pinned-2', provider: 'openai' }, { OPENAI_API_KEY: 'key-o' }, fake as never);
    expect(want.ok, want.text).toBe(true);
    expect(want.text).toContain('rules and openai:pinned-2;');
    urls.length = 0;
    expect(await pca(['actions', 'import', f, '--from', 'mcp', '--ns', 'shop', '--suggest', 'model', '--model', 'pinned-2', '--provider', 'openai'])).toEqual(printed(want));
    expect(urls).toEqual(['https://api.openai.com/v1/chat/completions']);
  });
});

describe('pca actions confirm', () => {
  const def = (verb: string): ActionDef => ({
    v: 1, kind: 'pca-action-def', verb, title: 'Create a refund', description: 'Creates a refund.', effects: ['create'],
    resource: { type: 'acme.refund', id: '*', scope: 'set' },
    params: { note: { type: 'string', max_len: 100 }, idempotency_key: { type: 'string', max_len: 64, required: false } },
    reversibility: 'irreversible', idempotency: { mode: 'key_param', param: 'idempotency_key' },
    traits: ['pca.money_moving'], review: { state: 'authored', provenance: { union: ['pca.money_moving'] } }, since: '0.5.0',
  } as ActionDef);
  const ONE = defsToYaml('acme', [def('acme.a.create')]);

  it('--pack with verbs reviews those verbs without --origin', async () => {
    const pack = join(tmp(), 'p');
    mkdirSync(pack);
    writeFileSync(join(pack, 'pack.json'), JSON.stringify({ ns: ['shop'], shards: [{ file: 's.jsonl' }] }));
    writeFileSync(join(pack, 's.jsonl'), loadActionsText(ACTION_TEMPLATES.db!('shop')).defs.map((d) => JSON.stringify(d)).join('\n') + '\n');
    const r = await pca(['actions', 'confirm', 'shop.row.get', '--pack', pack]);
    expect(r.code, r.err).toBeUndefined();
    expect(r.out).toMatch(/^shop\.row\.get {2}\[/);
    expect(r.out).not.toContain('shop.row.delete');
  });
  it('--final sets the final traits, which may add to the declared ones', async () => {
    const f = put(tmp(), 'actions.yaml', ONE);
    const r = await pca(['actions', 'confirm', 'acme.a.create', '--file', f, '--kid', 'rev-1', '--reviewer-key', sk, '--yes', '--final', 'pca.money_moving,pca.destructive']);
    expect(r.code, r.out).toBeUndefined();
    const d = loadActionsText(readFileSync(f, 'utf8')).defs[0]!;
    expect(d.review.attestation!.final_traits).toEqual(['pca.destructive', 'pca.money_moving']);
  });
  it('without --kid the reviewer id is empty', async () => {
    const f = put(tmp(), 'actions.yaml', ONE);
    const want = cmdConfirm(ONE, { verbs: ['acme.a.create'], kid: '', secret: sk, yes: true, ts: 1_700_000_000 });
    const r = await pca(['actions', 'confirm', 'acme.a.create', '--file', f, '--reviewer-key', sk, '--yes']);
    expect(r.out).toBe(want.text + '\n');
    expect(r.code).toBe(want.ok ? undefined : 1);
  });
});

describe('pca schema: a missing positional is an argument error even with every flag', () => {
  it('init, sign and publish', async () => {
    expect((await pca(['schema', 'init', '--from', 'openapi', '--site', 's', '--aud', 'a', '--version', '1'])).err).toBe(`${WARN}pca: schema init: --from openapi|mcp <file|-> --site --aud --version are required\n`);
    expect((await pca(['schema', 'sign', '--kid', 'k', '--key', sk])).err).toBe(`${WARN}pca: schema sign: <draft.json> --kid --key are required\n`);
    expect((await pca(['schema', 'publish', 'a.json', '--api', 'https://i.example', '--sk', 'sk_x'])).err).toBe(`${WARN}pca: schema publish: <schema.json> <keys.json> --api --sk are required\n`);
  });
});

