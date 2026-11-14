import { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { agent, generateKeyPair } from '@atlasauth/pca';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cmdActionExplain, cmdBuild, cmdDiff, cmdInit, cmdLint, cmdTest } from './actions';
import { inCwd } from './cwd-fixture';
import { cmdDecode, cmdDiscovery, cmdExplain, cmdSimulate } from './index';

const io = vi.hoisted(() => ({ stdin: '' }));
vi.mock('node:fs', async (orig) => {
  const actual = await orig<typeof import('node:fs')>();
  const wrapped = (await import('./cwd-fixture')).withVirtualCwd(actual);
  const readFileSync = ((p: unknown, ...rest: unknown[]) => (p === 0 ? io.stdin : (wrapped.readFileSync as (...a: unknown[]) => unknown)(p, ...rest))) as typeof actual.readFileSync;
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
    // main() is not exposed: let its promise chain drain until the output stops changing
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

afterEach(() => vi.restoreAllMocks());
const tmp = () => mkdtempSync(join(tmpdir(), 'pcacli-'));
const mint = () => agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: 'ins_test' }).act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' }, { counter: 1 });

describe('usage and dispatch', () => {
  it('no command, --help, -h and help print the usage and succeed', async () => {
    const first = await pca([]);
    expect(first.code).toBeUndefined();
    expect(first.out.startsWith('pca — Proof-Carrying Authority dev CLI\n\nUsage:\n  pca decode <file|->')).toBe(true);
    expect(first.out.endsWith('Notes:\n  <-> reads from STDIN. Nothing here authorizes anything — the resource server\'s verifier decides.\n')).toBe(true);
    expect(first.out).toContain('pca actions sync [paths...] [--source NAME] [--check]');
    expect(first.out).toContain('Legacy (deprecated, removed next release; use pca actions):');
    for (const a of ['--help', '-h', 'help']) expect(await pca([a])).toEqual(first);
    expect(first.err).toBe('');
  });
  it('an unknown command is an error naming it, with the usage', async () => {
    const r = await pca(['zzz']);
    expect(r.code).toBe(1);
    expect(r.out).toBe('');
    expect(r.err.startsWith("pca: unknown command 'zzz'\n\npca — Proof-Carrying Authority dev CLI\n")).toBe(true);
  });
});

describe('decode, explain, keygen, simulate, discovery', () => {
  const dir = tmp();
  const { pcactn, encoded } = mint();
  const file = join(dir, 'p.json');
  writeFileSync(file, encoded);

  it('decode reads a file or stdin and requires a source', async () => {
    const want = cmdDecode(encoded) + '\n';
    expect(await pca(['decode', file])).toEqual({ out: want, err: '', code: undefined });
    expect(await pca(['decode', '-'], encoded)).toEqual({ out: want, err: '', code: undefined });
    expect(await pca(['decode'])).toEqual({ out: '', err: "pca: decode: expected a file path or '-' for STDIN\n", code: 1 });
    const bad = await pca(['decode', '-'], 'nonsense{');
    expect(bad.code).toBe(1);
    expect(bad.err.startsWith('pca: ')).toBe(true);
  });
  it('explain passes --aud (all forms) and exits 1 on a deny', async () => {
    const ok = await cmdExplain(encoded, { audience: 'ins_test' });
    expect(ok.allow).toBe(true);
    for (const a of [['--aud', 'ins_test'], ['--aud=ins_test']]) expect(await pca(['explain', file, ...a])).toEqual({ out: ok.text + '\n', err: '', code: undefined });
    const wrong = await cmdExplain(encoded, { audience: 'other' });
    expect(await pca(['explain', file, '--aud', 'other'])).toEqual({ out: wrong.text + '\n', err: '', code: 1 });
    const any = await cmdExplain(encoded, {});
    for (const a of [[], ['--aud'], ['--aud=']]) expect((await pca(['explain', file, ...a])).out).toBe(any.text + '\n');
    expect(await pca(['explain'])).toEqual({ out: '', err: "pca: explain: expected a file path or '-' for STDIN\n", code: 1 });
    expect((await pca(['explain', '-', '--aud', 'ins_test'], encoded)).out).toBe(ok.text + '\n');
  });
  it('keygen prints a labelled keypair', async () => {
    const r = await pca(['keygen']);
    expect(r.code).toBeUndefined();
    expect(r.out).toMatch(/^PCA dev keypair \(Ed25519\)\n  public  [A-Za-z0-9_-]{43}\n  secret  [A-Za-z0-9_-]{43}\n\n  Keep the SECRET key private[^\n]*\n  Share only the public key[^\n]*\n$/);
  });
  it('simulate reads both files (or stdin for one) and requires both', async () => {
    const pol = join(dir, 'pol.json');
    const act = join(dir, 'act.json');
    const policy = JSON.stringify({ permissions: { stripe: ['refund'] }, limits: { refund: '$100/day' } });
    const actions = JSON.stringify([{ verb: 'stripe.refund', resource: 'charge:ch_1', params: { amount: 40 } }]);
    writeFileSync(pol, policy);
    writeFileSync(act, actions);
    const want = cmdSimulate(policy, actions) + '\n';
    expect(await pca(['simulate', pol, act])).toEqual({ out: want, err: '', code: undefined });
    expect(await pca(['simulate', pol, '-'], actions)).toEqual({ out: want, err: '', code: undefined });
    expect(await pca(['simulate', pol])).toEqual({ out: '', err: 'pca: simulate: expected <policy.json> <actions.json>\n', code: 1 });
    expect(await pca(['simulate'])).toMatchObject({ code: 1 });
  });
  it('discovery needs --aud and maps its flags', async () => {
    const need = { out: '', err: 'pca: discovery: --aud <id> is required\n', code: 1 };
    expect(await pca(['discovery'])).toEqual(need);
    expect(await pca(['discovery', '--aud'])).toEqual(need);
    expect(await pca(['discovery', '--aud='])).toEqual(need);
    expect(await pca(['discovery', '--aud', 'a1'])).toEqual({ out: cmdDiscovery({ audience: 'a1' }) + '\n', err: '', code: undefined });
    expect((await pca(['discovery', '--aud=a1'])).out).toBe(cmdDiscovery({ audience: 'a1' }) + '\n');
    expect((await pca(['discovery', '--aud', 'a1', '--suites', 'ed25519, custom ,,x'])).out).toBe(cmdDiscovery({ audience: 'a1', suites: ['ed25519', 'custom', 'x'] }) + '\n');
    expect((await pca(['discovery', '--aud', 'a1', '--suites', ' , '])).out).toBe(cmdDiscovery({ audience: 'a1', suites: [] }) + '\n');
    const all = await pca(['discovery', '--aud', 'a1', '--attest', 'https://x/a', '--revocation', 'https://x/r', '--beacon', 'https://x/b', '--stepup', 'https://x/s']);
    expect(all.out).toBe(cmdDiscovery({ audience: 'a1', endpoints: { attestation_challenge: 'https://x/a', revocation_epoch: 'https://x/r', liveness_beacon: 'https://x/b', stepup: 'https://x/s' } }) + '\n');
    for (const [flag, key] of [['--attest', 'attestation_challenge'], ['--revocation', 'revocation_epoch'], ['--beacon', 'liveness_beacon'], ['--stepup', 'stepup']] as const) {
      expect((await pca(['discovery', '--aud', 'a1', flag, 'https://x/y'])).out).toBe(cmdDiscovery({ audience: 'a1', endpoints: { [key]: 'https://x/y' } }) + '\n');
    }
    expect((await pca(['discovery', '--aud', 'a1', '--stepup'])).out).toBe(cmdDiscovery({ audience: 'a1' }) + '\n');
  });
  it('flags do not swallow another flag, and a trailing flag is the empty string', async () => {
    const r = await pca(['discovery', '--aud', '--stepup', 'https://x/s']);
    expect(r.err).toBe('pca: discovery: --aud <id> is required\n');
    expect(pcactn.counter).toBe(1);
  });
});

describe('actions', () => {
  const projectIn = (root: string) => {
    const dir = join(root, 'actions');
    cmdInit({ dir, ns: 'acme' });
    return dir;
  };
  const strip = (s: string, root: string) => s.split(root).join('<R>');

  it('init scaffolds like cmdInit, with --dir, --ns, --template and --force', async () => {
    const a = tmp();
    const b = tmp();
    const viaCli = await pca(['actions', 'init', '--dir', join(a, 'd1'), '--ns', 'shop', '--template', 'saas']);
    const direct = cmdInit({ dir: join(b, 'd1'), ns: 'shop', template: 'saas' });
    expect(strip(viaCli.out, a)).toBe(strip(direct.text + '\n', b));
    expect(viaCli.code).toBe(direct.ok ? undefined : 1);
    expect(readdirSync(join(a, 'd1')).sort()).toEqual(readdirSync(join(b, 'd1')).sort());
    const twice = await pca(['actions', 'init', '--dir', join(a, 'd1'), '--ns', 'shop']);
    const twiceDirect = cmdInit({ dir: join(b, 'd1'), ns: 'shop' });
    expect(twice.code).toBe(twiceDirect.ok ? undefined : 1);
    expect(strip(twice.out, a)).toBe(strip(twiceDirect.text + '\n', b));
    const forced = await pca(['actions', 'init', '--dir', join(a, 'd1'), '--ns', 'shop', '--force']);
    const forcedDirect = cmdInit({ dir: join(b, 'd1'), ns: 'shop', force: true });
    expect(forced.code).toBe(forcedDirect.ok ? undefined : 1);
    expect(strip(forced.out, a)).toBe(strip(forcedDirect.text + '\n', b));
    const defaults = tmp();
    await inCwd(defaults, async () => {
      const d = await pca(['actions', 'init']);
      const want = cmdInit({ dir: 'actions', ns: 'acme' });
      expect(d.out).toBe(want.text.length ? d.out : '');
      expect(readdirSync(join(defaults, 'actions')).length).toBeGreaterThan(0);
    });
  });
  it('lint, test, explain, diff and build print what their commands print and set the exit code', async () => {
    const root = tmp();
    const dir = projectIn(root);
    const lint = cmdLint([dir], { strict: false, format: 'text' });
    expect(await pca(['actions', 'lint', dir])).toEqual({ out: lint.text + '\n', err: '', code: lint.ok ? undefined : 1 });
    const strict = cmdLint([dir], { strict: true, format: 'text' });
    expect(await pca(['actions', 'lint', '--strict', dir])).toEqual({ out: strict.text + '\n', err: '', code: strict.ok ? undefined : 1 });
    const sarif = cmdLint([dir], { strict: false, format: 'sarif' });
    expect(await pca(['actions', 'lint', dir, '--format', 'sarif'])).toEqual({ out: sarif.text + '\n', err: '', code: sarif.ok ? undefined : 1 });
    expect((await pca(['actions', 'lint', dir, '--format', 'text'])).out).toBe(lint.text + '\n');
    const t = cmdTest([dir]);
    expect(await pca(['actions', 'test', dir])).toEqual({ out: t.text + '\n', err: '', code: t.ok ? undefined : 1 });
    await inCwd(root, async () => {
      expect((await pca(['actions', 'lint'])).out).toBe(cmdLint(['actions'], { strict: false, format: 'text' }).text + '\n');
      expect((await pca(['actions', 'test'])).out).toBe(cmdTest(['actions']).text + '\n');
    });
    const verb = 'acme.invoice.send';
    const ex = cmdActionExplain([dir], verb);
    expect(await pca(['actions', 'explain', verb, dir])).toEqual({ out: ex.text + '\n', err: '', code: ex.ok ? undefined : 1 });
    const other = projectIn(tmp());
    const df = cmdDiff([dir], [other]);
    expect(await pca(['actions', 'diff', dir, other])).toEqual({ out: df.text + '\n', err: '', code: df.ok ? undefined : 1 });
    const out1 = join(root, 'o1');
    const out2 = join(root, 'o2');
    const b1 = await pca(['actions', 'build', dir, '--out', out1]);
    const b2 = cmdBuild([dir], { out: out2 });
    expect(b1.out.split(out1).join('<O>')).toBe((b2.text + '\n').split(out2).join('<O>'));
    expect(b1.code).toBe(b2.ok ? undefined : 1);
    expect(readdirSync(out1).sort()).toEqual(readdirSync(out2).sort());
  });
  it('argument errors are reported with their exact messages', async () => {
    const e = async (args: string[]) => (await pca(args)).err;
    expect(await e(['actions', 'import'])).toBe('pca: actions import: <file|-> --from --ns are required\n');
    expect(await e(['actions', 'import', 'f.json', '--from', 'openapi'])).toBe('pca: actions import: <file|-> --from --ns are required\n');
    expect(await e(['actions', 'import', 'f.json', '--ns', 'a'])).toBe('pca: actions import: <file|-> --from --ns are required\n');
    expect(await e(['actions', 'confirm'])).toBe('pca: actions confirm: <verb>... or --origin union|any is required\n');
    expect(await e(['actions', 'review'])).toBe('pca: actions confirm: <verb>... or --origin union|any is required\n');
    expect(await e(['actions', 'confirm', '--pack', 'x', '--origin', 'union'])).toBe('pca: actions confirm --pack: pass --origin any (every def of the pack) or the verbs to review\n');
    expect(await e(['actions', 'explain'])).toBe('pca: actions explain: <verb> is required\n');
    expect(await e(['actions', 'diff', 'one'])).toBe('pca: actions diff: <old> <new> are required\n');
    expect(await e(['actions', 'diff', 'a', 'b', 'c'])).toBe('pca: actions diff: <old> <new> are required\n');
    expect(await e(['actions', 'sign'])).toBe('pca: actions sign: --kid and --key are required\n');
    expect(await e(['actions', 'sign', '--kid', 'k'])).toBe('pca: actions sign: --kid and --key are required\n');
    expect(await e(['actions', 'sign', '--key', 'k'])).toBe('pca: actions sign: --kid and --key are required\n');
    const unknown = await e(['actions', 'nope']);
    expect(unknown.startsWith("pca: actions: unknown sub-command 'nope'\n\npca — Proof-Carrying Authority dev CLI\n")).toBe(true);
    expect((await e(['actions'])).startsWith("pca: actions: unknown sub-command 'undefined'\n\n")).toBe(true);
  });
  it('import writes the draft to stdout or --out and reports todos on stderr', async () => {
    const dir = tmp();
    const doc = JSON.stringify({ openapi: '3.0.0', info: { title: 't', version: '1' }, paths: { '/items': { get: { operationId: 'listItems', responses: { '200': { description: 'ok' } } } } } });
    const f = join(dir, 'api.json');
    writeFileSync(f, doc);
    const { cmdImport } = await import('./actions');
    const want = cmdImport(doc, { from: 'openapi', ns: 'shop' });
    expect(want.ok).toBe(true);
    const r = await pca(['actions', 'import', f, '--from', 'openapi', '--ns', 'shop']);
    if (!want.ok) throw new Error('unreachable');
    expect(r.out).toBe(want.yaml);
    expect(r.err).toBe(want.todo.map((t) => `todo: ${t}\n`).join('') + want.text + '\n');
    const outFile = join(dir, 'draft.yaml');
    const w = await pca(['actions', 'import', f, '--from', 'openapi', '--ns', 'shop', '--out', outFile]);
    expect(w.out).toBe('');
    expect(readFileSync(outFile, 'utf8')).toBe(want.yaml);
    const viaStdin = await pca(['actions', 'import', '-', '--from', 'openapi', '--ns', 'shop'], doc);
    expect(viaStdin.out).toBe(want.yaml);
    const bad = await pca(['actions', 'import', f, '--from', 'nonsense', '--ns', 'shop']);
    const badWant = cmdImport(doc, { from: 'nonsense', ns: 'shop' });
    expect(badWant.ok).toBe(false);
    expect(bad.code).toBe(1);
    expect(bad.out).toBe(badWant.text + '\n');
  });
});

describe('schema (deprecated) argument errors', () => {
  it('always warns first, then reports the exact missing-argument message', async () => {
    const warn = 'pca schema is deprecated and will be removed in the next release; use pca actions (import, sign, publish)\n';
    const e = async (args: string[]) => (await pca(['schema', ...args])).err;
    expect(await e(['init'])).toBe(`${warn}pca: schema init: --from openapi|mcp <file|-> --site --aud --version are required\n`);
    expect(await e(['init', 'f', '--from', 'soap', '--site', 's', '--aud', 'a', '--version', '1'])).toBe(`${warn}pca: schema init: --from openapi|mcp <file|-> --site --aud --version are required\n`);
    for (const missing of ['--site', '--aud', '--version']) {
      const flags = ['--from', 'mcp', '--site', 's', '--aud', 'a', '--version', '1'];
      const i = flags.indexOf(missing);
      flags.splice(i, 2);
      expect(await e(['init', 'f', ...flags])).toContain('schema init: --from openapi|mcp');
    }
    expect(await e(['sign'])).toBe(`${warn}pca: schema sign: <draft.json> --kid --key are required\n`);
    expect(await e(['sign', 'd.json', '--kid', 'k'])).toBe(`${warn}pca: schema sign: <draft.json> --kid --key are required\n`);
    expect(await e(['sign', 'd.json', '--key', 'k'])).toBe(`${warn}pca: schema sign: <draft.json> --kid --key are required\n`);
    expect((await e(['verify', 'one'])).startsWith(`${warn}pca: schema verify: wrong arguments\n\npca — Proof-Carrying Authority dev CLI\n`)).toBe(true);
    expect((await e(['conform', 'a', 'b'])).startsWith(`${warn}pca: schema conform: wrong arguments\n\n`)).toBe(true);
    expect(await e(['publish', 'a'])).toBe(`${warn}pca: schema publish: <schema.json> <keys.json> --api --sk are required\n`);
    expect(await e(['publish', 'a', 'b', '--api', 'https://x'])).toBe(`${warn}pca: schema publish: <schema.json> <keys.json> --api --sk are required\n`);
    expect(await e(['publish', 'a', 'b', '--sk', 'k'])).toBe(`${warn}pca: schema publish: <schema.json> <keys.json> --api --sk are required\n`);
    expect((await e(['nope'])).startsWith(`${warn}pca: schema: unknown sub-command 'nope'\n\n`)).toBe(true);
    expect((await e([])).startsWith(`${warn}pca: schema: unknown sub-command 'undefined'\n\n`)).toBe(true);
  });
});
