/**
 * party-main.ts as real OS processes (the compiled entry point), small runs only: keygen, the test-hook gate, the dealer / party /
 * OT roles, the pass-through of every config field that changes behaviour, and the exact shape of the one-line verdict.
 *
 * The package is compiled once per source state (cached by a hash of src/), so a mutation run (where only the active-mutant id
 * changes) does not rebuild per mutant; the active mutant id is forwarded to the child processes through the environment.
 */
import { execFileSync, spawn } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { composeClear } from '../compose';
import { generateIdentity } from './certs';
import { launchLocal, launchOtLocal, type LaunchOptions } from './launch-local';
import type { NodeConfig } from './party-main';
import { T, reservePorts } from './test-timing';

const pkg = resolve(__dirname, '../..');
const underStryker = (): boolean => (globalThis as { __stryker__?: unknown }).__stryker__ !== undefined;
let buildDir = '';
let mainJs = '';
let work = '';

function srcHash(): string {
  const h = createHash('sha256');
  const walk = (d: string): string[] =>
    readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(d, e.name)) : e.name.endsWith('.ts') && !e.name.endsWith('.test.ts') ? [join(d, e.name)] : []));
  for (const f of walk(join(pkg, 'src')).sort()) h.update(relative(pkg, f)).update('\0').update(readFileSync(f)).update('\0');
  h.update(readFileSync(join(pkg, 'tsconfig.json'))).update(readFileSync(join(pkg, 'tsconfig.build.json')));
  return h.digest('hex').slice(0, 16);
}

beforeAll(() => {
  buildDir = join(pkg, `.nettest-build-pm-${srcHash()}`);
  mainJs = join(buildDir, 'net', 'party-main.js');
  if (!existsSync(mainJs)) {
    const tmp = mkdtempSync(join(pkg, '.nettest-build-tmp-'));
    execFileSync(process.execPath, [require.resolve('typescript/bin/tsc'), '-p', join(pkg, 'tsconfig.build.json'), '--outDir', tmp], { stdio: 'pipe' });
    try {
      renameSync(tmp, buildDir);
    } catch {
      rmSync(tmp, { recursive: true, force: true }); // a concurrent worker won the race
    }
  }
  work = mkdtempSync(join(tmpdir(), 'pca-pm-kill-'));
}, T(240_000));
afterAll(() => {
  rmSync(work, { recursive: true, force: true });
  if (!underStryker()) rmSync(buildDir, { recursive: true, force: true });
});
beforeEach(() => {
  const am = (globalThis as { __stryker__?: { activeMutant?: unknown } }).__stryker__?.activeMutant;
  if (am === undefined) delete process.env.__STRYKER_ACTIVE_MUTANT__;
  else process.env.__STRYKER_ACTIVE_MUTANT__ = String(am);
});

interface Ran {
  code: number | null;
  json: any; // eslint-disable-line @typescript-eslint/no-explicit-any
  lines: string[];
  raw: string;
  stderr: string;
}
function runMain(args: string[], env: Record<string, string | undefined> = {}): Promise<Ran> {
  return new Promise((res) => {
    const child = spawn(process.execPath, [mainJs, ...args], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, PCA_MPC_UNSAFE_TEST_HOOKS: undefined, ...env } });
    let so = '';
    let se = '';
    child.stdout.on('data', (d) => (so += d));
    child.stderr.on('data', (d) => (se += d));
    const killer = setTimeout(() => child.kill('SIGKILL'), T(120_000));
    child.on('close', (code) => {
      clearTimeout(killer);
      const lines = so.split('\n').filter(Boolean);
      let json = null;
      try {
        json = lines.length === 1 ? JSON.parse(lines[0]!) : null;
      } catch {
        /* leave null */
      }
      res({ code, json, lines, raw: so, stderr: se });
    });
  });
}

/** A config for a lone party (n = 1, dealer-free): it connects to nobody and finishes on its own. */
async function soloCfg(over: Partial<NodeConfig> = {}): Promise<string> {
  const d = mkdtempSync(join(work, 'solo-'));
  const id = generateIdentity(join(d, 'n0'), 'n0');
  const [port] = await reservePorts(1);
  const cfg: NodeConfig = {
    role: 'party', id: 0, n: 1, Q: 2, offline: 'no-dealer', sessionId: 'solo', input: { allow: 1, t: 2, rQuant: 1 }, listenHost: '127.0.0.1',
    nodes: [{ id: 0, host: '127.0.0.1', port: port!, certPath: id.certPath }], keyPath: id.keyPath, certPath: id.certPath, ...over,
  };
  const p = join(d, 'cfg.json');
  writeFileSync(p, JSON.stringify(cfg));
  return p;
}
const refused = (role: string, id: number) => ({
  ok: false, role, id,
  error: { kind: 'local', blamed: null, reporter: id, message: 'refusing to start: test hooks (behavior/frameFault) are not enabled in this environment' },
});

describe('keygen', () => {
  it('writes key.pem and cert.pem for the given common name and prints their paths', async () => {
    const d = join(work, 'kg');
    const r = await runMain(['keygen', d, 'node-x']);
    expect(r.code).toBe(0);
    expect(r.json).toEqual({ keyPath: join(d, 'key.pem'), certPath: join(d, 'cert.pem') });
    expect(r.raw).toBe(JSON.stringify(r.json) + '\n');
    expect(new X509Certificate(readFileSync(join(d, 'cert.pem'))).subject).toBe('CN=node-x');
  });
  it('the common name defaults to mpc-node', async () => {
    const d = join(work, 'kg2');
    await runMain(['keygen', d]);
    expect(new X509Certificate(readFileSync(join(d, 'cert.pem'))).subject).toBe('CN=mpc-node');
  });
});

describe('the test-hook gate', () => {
  it('a hook in the config is refused unless BOTH unsafeTestHooks and the environment flag are set', async () => {
    const cases: Array<[Partial<NodeConfig>, Record<string, string | undefined>]> = [
      [{ behavior: { kind: 'crash', round: 'nope' }, unsafeTestHooks: true }, {}],
      [{ behavior: { kind: 'crash', round: 'nope' } }, { PCA_MPC_UNSAFE_TEST_HOOKS: '1' }],
      [{ behavior: { kind: 'crash', round: 'nope' }, unsafeTestHooks: true }, { PCA_MPC_UNSAFE_TEST_HOOKS: 'yes' }],
      [{ frameFault: { kind: 'drop', round: 'nope' }, unsafeTestHooks: true }, {}],
      [{ dealerFault: { macFaultAtInput: 0 }, unsafeTestHooks: true }, {}],
    ];
    for (const [over, env] of cases) {
      const r = await runMain([await soloCfg(over)], env);
      expect(r.code).toBe(3);
      expect(r.json).toEqual(refused('party', 0));
    }
  });
  it('with both set, the hooked node runs', async () => {
    const r = await runMain([await soloCfg({ behavior: { kind: 'crash', round: 'nope' }, frameFault: { kind: 'drop', round: 'nope' }, unsafeTestHooks: true })], { PCA_MPC_UNSAFE_TEST_HOOKS: '1' });
    expect(r.code).toBe(0);
    expect(r.json.ok).toBe(true);
  });
});

describe('a lone party', () => {
  it('prints one verdict line: ok, role, connect time, its result, link stats and events; exits 0', async () => {
    const r = await runMain([await soloCfg()]);
    expect(r.code).toBe(0);
    expect(r.lines.length).toBe(1);
    expect(Object.keys(r.json).sort()).toEqual(['connectMs', 'events', 'links', 'ok', 'result', 'role']);
    expect(r.json.ok).toBe(true);
    expect(r.json.role).toBe('party');
    expect(typeof r.json.connectMs).toBe('number');
    expect(r.json.connectMs).toBeGreaterThanOrEqual(0);
    expect(r.json.connectMs).toBeLessThan(60_000);
    expect(r.raw.endsWith('}\n')).toBe(true);
    expect(r.json.links).toEqual([]);
    expect(r.json.events).toEqual([]);
    expect(r.json.result.composed).toEqual({ allow: 1, t: 2, rQuant: 1 });
    expect(r.json.result.Q).toBe(2);
    expect(r.json.result.offlineMode).toBe('no-dealer');
  });
  it('an exception that is not a NetAbort becomes a local error naming the node, exit code 3', async () => {
    const r = await runMain([await soloCfg({ input: undefined })]);
    expect(r.code).toBe(3);
    expect(r.json.ok).toBe(false);
    expect(r.json.role).toBe('party');
    expect(r.json.id).toBe(0);
    expect(r.json.error.kind).toBe('local');
    expect(r.json.error.blamed).toBeNull();
    expect(r.json.error.reporter).toBe(0);
    expect(r.json.error.message).toMatch(/^\[local\] blamed=none reporter=0: .*allow/);
    expect(r.json.error.reason).toMatch(/^unattributable/);
    expect(r.json.links).toEqual([]);
    expect(r.json.events).toEqual([]);
  });
  it('a NetAbort is reported with every field (a connect timeout honours connectTimeoutMs)', async () => {
    const d = mkdtempSync(join(work, 'ct-'));
    const a = generateIdentity(join(d, 'a'), 'a');
    const b = generateIdentity(join(d, 'b'), 'b');
    const ports = await reservePorts(2);
    const cfg: NodeConfig = {
      role: 'party', id: 0, n: 2, Q: 1, offline: 'no-dealer', sessionId: 's', input: { allow: 1, t: 1, rQuant: 0 }, listenHost: '127.0.0.1',
      nodes: [{ id: 0, host: '127.0.0.1', port: ports[0]!, certPath: a.certPath }, { id: 1, host: '127.0.0.1', port: ports[1]!, certPath: b.certPath }],
      keyPath: a.keyPath, certPath: a.certPath, connectTimeoutMs: 1500,
    };
    const p = join(d, 'cfg.json');
    writeFileSync(p, JSON.stringify(cfg));
    const t0 = Date.now();
    const r = await runMain([p]);
    expect(Date.now() - t0).toBeLessThan(15_000);
    expect(r.code).toBe(3);
    expect(Object.keys(r.json.error).sort()).toEqual(['blamed', 'kind', 'message', 'reason', 'reporter']);
    expect(r.json.error).toMatchObject({ kind: 'timeout', blamed: 1, reporter: 0, reason: null });
    expect(r.json.error.message).toContain('connect: no authenticated link from 1');
    expect(r.json.links.map((l: { peer: number }) => l.peer)).toEqual([1]);
    expect(Array.isArray(r.json.events)).toBe(true);
  });
});

const V2 = [
  { allow: 1, t: 1, rQuant: 1 },
  { allow: 1, t: 2, rQuant: 0 },
] as const;
const run2 = (o: Partial<LaunchOptions> = {}) => launchLocal({ n: 2, Q: 1, vectors: [...V2], mainJs, recvTimeoutMs: 20_000, killAfterMs: 90_000, ...o });

describe('dealer and parties (n = 2, Q = 1)', () => {
  it('honest run: both parties output the clear composition, the dealer reports its links to the parties only', async () => {
    const r = await run2({ dealerSeed: '7' });
    const [p0, p1, d] = r.outputs;
    for (const p of [p0!, p1!]) {
      expect(p.exitCode).toBe(0);
      expect(p.json.ok).toBe(true);
      expect(p.json.role).toBe('party');
      expect(p.json.result.composed).toEqual(composeClear([...V2], 1));
      expect(p.json.result.offlineMode).toBe('trusted-dealer');
      expect(p.json.links.map((l: { peer: number }) => l.peer)).toEqual(p.id === 0 ? [1, 2] : [0, 2]);
    }
    expect(d!.exitCode).toBe(0);
    expect(Object.keys(d!.json).sort()).toEqual(['connectMs', 'events', 'id', 'links', 'ok', 'role']);
    expect(d!.json).toMatchObject({ ok: true, role: 'dealer', id: 2 });
    expect(d!.json.links.map((l: { peer: number }) => l.peer)).toEqual([0, 1]);
  });
  it('a dealer seed that is not an integer is a local error of the dealer', async () => {
    const r = await run2({ dealerSeed: 'not-a-number', recvTimeoutMs: 5000 });
    const d = r.outputs[2]!;
    expect(d.exitCode).toBe(3);
    expect(d.json).toMatchObject({ ok: false, role: 'dealer', id: 2 });
    expect(d.json.error.kind).toBe('local');
    expect(d.json.error.message).toMatch(/BigInt/);
  });
  it('a lying dealer (kept product, partner product, MAC of an input mask) is caught and named by the parties', async () => {
    const keep = await run2({ overrides: { 2: { dealerFault: { keepCDelta: '1' } } } });
    const partner = await run2({ overrides: { 2: { dealerFault: { partnerCDelta: [null, '5'] } } } });
    const mac = await run2({ overrides: { 2: { dealerFault: { macFaultAtInput: 0 } } } });
    const direct = (r: Awaited<ReturnType<typeof run2>>) => r.outputs.slice(0, 2).map((o) => o.json.error).find((e: { kind: string }) => e.kind === 'dealer');
    expect(direct(keep)).toMatchObject({ kind: 'dealer', blamed: 2 });
    expect(direct(keep).message).toContain('triple sacrifice FAILED at triple 0 (partner 0)');
    expect(direct(partner).message).toContain('(partner 1)');
    expect(direct(mac).message).toContain("the trusted dealer's MACs are inconsistent with its values");
    for (const r of [keep, partner, mac]) for (const o of r.outputs.slice(0, 2)) expect(o.exitCode).toBe(3);
  });
  it('a frame fault on a party and a behaviour on a party reach the protocol', async () => {
    const ff = await run2({ overrides: { 0: { frameFault: { kind: 'wrong-session', round: 'mul0' } } } });
    expect(ff.outputs[1]!.json.error).toMatchObject({ kind: 'wrong-session', blamed: 0 });
    const beh = await run2({ overrides: { 1: { behavior: { kind: 'open-lie', round: 'mul0' } } } });
    expect(beh.outputs[0]!.json.error).toMatchObject({ kind: 'mac-check', blamed: 1 });
  });
  it('recvTimeoutMs reaches the mesh: a party that falls silent is blamed at that deadline; the peer reports the claim fields', async () => {
    const r = await run2({ recvTimeoutMs: 1500, overrides: { 1: { frameFault: { kind: 'silent-from', round: 'coin1-c' }, recvTimeoutMs: T(60_000) } } });
    expect(r.outputs[0]!.json.error).toMatchObject({ kind: 'timeout', blamed: 1, reporter: 0, deadlineMs: T(1500) });
    expect(r.outputs[1]!.json.error).toMatchObject({ kind: 'peer-abort', blamed: 0, claimedKind: 'timeout', claimedBlame: 1 });
  });
});

describe('OT roles', () => {
  it('sender and receiver complete an EC base OT of the requested count', async () => {
    const r = await launchOtLocal({ kind: 'ec', count: 4, mainJs });
    expect(r.outputs.map((o) => o.exitCode)).toEqual([0, 0]);
    expect(r.outputs[0]!.json).toMatchObject({ ok: true, role: 'ot-sender', result: { kind: 'ec', role: 'sender', count: 4, matched: true } });
    expect(r.outputs[1]!.json).toMatchObject({ ok: true, role: 'ot-receiver', result: { kind: 'ec', role: 'receiver', count: 4, matched: true } });
    expect(Object.keys(r.outputs[0]!.json).sort()).toEqual(['connectMs', 'events', 'links', 'ok', 'result', 'role']);
  });
  it('without an ot section the roles default to 128 EC transfers', async () => {
    const d = mkdtempSync(join(work, 'ot-'));
    const ids = [0, 1].map((i) => generateIdentity(join(d, `n${i}`), `n${i}`));
    const ports = await reservePorts(2);
    const nodes = ids.map((x, j) => ({ id: j, host: '127.0.0.1', port: ports[j]!, certPath: x.certPath }));
    const paths = [0, 1].map((id) => {
      const cfg: NodeConfig = { role: id === 0 ? 'ot-sender' : 'ot-receiver', id, n: 2, sessionId: 'ot', listenHost: '127.0.0.1', nodes, keyPath: ids[id]!.keyPath, certPath: ids[id]!.certPath };
      const p = join(d, `cfg${id}.json`);
      writeFileSync(p, JSON.stringify(cfg));
      return p;
    });
    const [a, b] = await Promise.all(paths.map((p) => runMain([p])));
    expect(a!.json.result).toMatchObject({ kind: 'ec', count: 128, matched: true, role: 'sender' });
    expect(b!.json.result).toMatchObject({ kind: 'ec', count: 128, matched: true, role: 'receiver' });
  });
});

