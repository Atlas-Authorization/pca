import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { confineArgs, policyFromNeeds } from './index';

/**
 * Real enforcement of the GENERATED seccomp and Landlock profiles: the reference helper applies them to a child process and the
 * child tries things. On Linux in CI (PCA_REQUIRE_LINUX=1) the suite must run: a missing platform, compiler, libseccomp or
 * Landlock FAILS instead of skipping. Elsewhere (a Mac) it is skipped explicitly.
 */
const REQUIRED = process.env.PCA_REQUIRE_LINUX === '1';
const MUTATING = process.env.PCA_MUTATION_RUN === '1'; // Stryker re-runs tests per mutant: the compile-and-apply suite is not run per mutant
const LINUX = process.platform === 'linux' && !MUTATING;

describe('linux enforcement is required in CI', () => {
  it('runs on Linux when PCA_REQUIRE_LINUX=1', () => {
    if (REQUIRED) expect(process.platform).toBe('linux');
  });
});

describe.runIf(LINUX)('seccomp + Landlock enforcement (Linux)', () => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'pca-lin-')));
  const bin = path.join(dir, 'bin');
  const data = path.join(dir, 'data');
  const secret = path.join(dir, 'secret.txt');
  const granted = path.join(data, 'granted.txt');
  const writable = path.join(data, 'out.txt');
  let ready: string | null = null;

  beforeAll(() => {
    fs.mkdirSync(bin);
    fs.mkdirSync(data);
    fs.writeFileSync(granted, 'granted');
    fs.writeFileSync(writable, '');
    fs.writeFileSync(secret, 'nope');
    const src = path.join(__dirname, '../linux');
    try {
      execFileSync('gcc', ['-O2', '-o', path.join(bin, 'pca-confine'), path.join(src, 'pca-confine.c'), '-lseccomp'], { stdio: 'pipe' });
      execFileSync('gcc', ['-O2', '-static', '-o', path.join(bin, 'pca-probe'), path.join(src, 'pca-probe.c')], { stdio: 'pipe' });
      const abi = Number(execFileSync(path.join(bin, 'pca-confine'), ['--landlock-abi'], { encoding: 'utf8' }).trim());
      if (abi < 4) throw new Error(`Landlock ABI ${abi} on this kernel (need 4 for the network rule)`);
    } catch (e) {
      ready = e instanceof Error ? `${e.message}${(e as unknown as { stderr?: Buffer }).stderr ? `: ${(e as unknown as { stderr: Buffer }).stderr.toString().slice(0, 400)}` : ''}` : String(e);
      if (REQUIRED) throw new Error(`Linux enforcement cannot run in CI: ${ready}`);
    }
  });

  const probePath = () => path.join(bin, 'pca-probe');
  /** Run the probe under the helper with the profiles generated for `policy`. */
  function probe(policy: ReturnType<typeof policyFromNeeds>, ...args: string[]): string {
    const r = spawnSync(path.join(bin, 'pca-confine'), [...confineArgs(policy), '--', probePath(), ...args], { encoding: 'utf8' });
    return r.status === 0 ? r.stdout.trim() : `helper:${r.status}:${r.stderr.trim()}`;
  }
  const skipUnlessReady = (ctx: { skip: () => void }) => { if (ready) ctx.skip(); };

  const base = policyFromNeeds([{ fs: [{ path: probePath(), mode: 'x' }, { path: granted, mode: 'r' }, { path: writable, mode: 'rw' }] }]);

  it('without the profile the probe can do everything (so the refusals below are the profile)', (ctx) => {
    skipUnlessReady(ctx);
    const run = (...a: string[]) => spawnSync(probePath(), a, { encoding: 'utf8' }).stdout.trim();
    expect(run('read', secret)).toBe('ok');
    expect(run('unixsock')).toBe('ok');
    expect(run('ptrace')).toBe('ok');
  });

  it('Landlock: the granted path reads, the writable path writes, everything else is refused', (ctx) => {
    skipUnlessReady(ctx);
    expect(probe(base, 'read', granted)).toBe('ok');
    expect(probe(base, 'write', writable)).toBe('ok');
    expect(probe(base, 'write', granted)).toBe('err:open:13'); // read-only grant: EACCES
    expect(probe(base, 'read', secret)).toBe('err:open:13');
    expect(probe(base, 'read', '/etc/passwd')).toBe('err:open:13');
  });

  it('Landlock: exec is refused outside the granted binary', (ctx) => {
    skipUnlessReady(ctx);
    expect(probe(base, 'exec', '/bin/true')).toMatch(/^err:exec:(13|1)$/); // EACCES (Landlock) or EPERM (seccomp)
  });

  it('seccomp: syscalls outside the allowlist fail with EPERM, and no network without a proxy', (ctx) => {
    skipUnlessReady(ctx);
    expect(probe(base, 'ptrace')).toBe('err:ptrace:1');
    expect(probe(base, 'unixsock')).toBe('err:socket:1');
    expect(probe(base, 'connect', '9')).toBe('err:socket:1');
  });

  it('egress only via the proxy: connect to the proxy port works, any other port is refused', async (ctx) => {
    skipUnlessReady(ctx);
    const listen = (s: net.Server) => new Promise<number>((r) => s.listen(0, '127.0.0.1', () => r((s.address() as net.AddressInfo).port)));
    const proxy = http.createServer((_q, res) => res.end('p'));
    const origin = http.createServer((_q, res) => res.end('o'));
    const [proxyPort, originPort] = [await listen(proxy), await listen(origin)];
    try {
      const policy = policyFromNeeds([{ fs: [{ path: probePath(), mode: 'x' }], net: [{ host: 'api.example.com', port: 443 }] }], proxyPort);
      // the child blocks on connect only briefly; run it async so the listeners in this process answer
      const run = (port: number) =>
        new Promise<string>((resolve) => {
          const c = require('node:child_process').execFile(path.join(bin, 'pca-confine'), [...confineArgs(policy), '--', probePath(), 'connect', String(port)], { encoding: 'utf8' }, (_e: unknown, out: string) => resolve(out.trim()));
          void c;
        });
      expect(await run(proxyPort)).toBe('ok');
      expect(await run(originPort)).toBe('err:connect:13'); // Landlock network rule: EACCES
      expect(await run(1)).toBe('err:connect:13');
      // AF_UNIX stays refused by seccomp even with a proxy
      expect(probe(policy, 'unixsock')).toBe('err:socket:1');
    } finally {
      proxy.close();
      origin.close();
    }
  });

  it('the helper fails closed: an unknown access name or a missing path is a setup failure, never an unconfined exec', (ctx) => {
    skipUnlessReady(ctx);
    const r = spawnSync(path.join(bin, 'pca-confine'), ['--fs-handled', 'FS_NOPE', '--', probePath(), 'read', granted], { encoding: 'utf8' });
    expect(r.status).toBe(72);
    expect(r.stdout).toBe('');
    const m = spawnSync(path.join(bin, 'pca-confine'), ['--fs-handled', 'FS_READ_FILE', '--fs', `${dir}/missing:FS_READ_FILE`, '--', probePath(), 'read', granted], { encoding: 'utf8' });
    expect(m.status).toBe(72);
    expect(m.stdout).toBe('');
  });
});
