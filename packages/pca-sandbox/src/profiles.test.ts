import { execFile } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { authFixture } from './test-auth';
import { EgressPolicy, ReceiptLog, compilePolicy, createEgressProxy, landlockRuleset, macosProfile, policyFromNeeds, seccompProfile, type Needs } from './index';

const VECTORS = path.join(__dirname, '../vectors/sandbox-vectors.json');

const CASES: { name: string; needs: Needs[]; proxy_port: number | null }[] = [
  { name: 'empty', needs: [], proxy_port: null },
  { name: 'read_one_file', needs: [{ fs: [{ path: '/srv/data/notes.txt', mode: 'r' }] }], proxy_port: null },
  { name: 'write_implies_read_and_merges_duplicates', needs: [{ fs: [{ path: '/srv/out', mode: 'rw' }, { path: '/srv/out', mode: 'r' }] }, { fs: [{ path: '/srv/data', mode: 'r' }] }], proxy_port: null },
  { name: 'exec_binary', needs: [{ fs: [{ path: '/usr/local/bin/convert', mode: 'x' }, { path: '/srv/in', mode: 'r' }] }], proxy_port: null },
  { name: 'net_via_proxy', needs: [{ net: [{ host: 'api.example.com', port: 443 }, { host: 'api.example.com', port: 443 }] }, { net: [{ host: 'cdn.example.com', port: 80 }] }], proxy_port: 3128 },
  { name: 'everything', needs: [{ fs: [{ path: '/srv/work dir', mode: 'rw' }, { path: '/opt/tool/bin/run', mode: 'x' }], net: [{ host: 'api.example.com', port: 443 }] }], proxy_port: 8080 },
];

const generate = () =>
  CASES.map((c) => {
    const policy = policyFromNeeds(c.needs, c.proxy_port);
    return { name: c.name, needs: c.needs, proxy_port: c.proxy_port, policy, seccomp: seccompProfile(policy), landlock: landlockRuleset(policy), macos: macosProfile(policy) };
  });

describe('shared vectors', () => {
  it('sandbox-vectors.json is a fresh generation (UPDATE_VECTORS=1 rewrites it)', () => {
    const fresh = `${JSON.stringify({ about: 'Policy compiler and profile generator vectors for @atlasauth/pca-sandbox: needs in, policy and the seccomp, Landlock and macOS profiles out.', cases: generate() }, null, 1)}\n`;
    if (process.env.UPDATE_VECTORS === '1') fs.writeFileSync(VECTORS, fresh);
    expect(fs.readFileSync(VECTORS, 'utf8')).toBe(fresh);
  });
});

describe('policyFromNeeds', () => {
  it('is deterministic whatever the order of the needs', () => {
    const a: Needs[] = [{ fs: [{ path: '/b', mode: 'r' }, { path: '/a', mode: 'rw' }] }];
    const b: Needs[] = [{ fs: [{ path: '/a', mode: 'rw' }] }, { fs: [{ path: '/b', mode: 'r' }] }];
    expect(policyFromNeeds(a)).toEqual(policyFromNeeds(b));
    expect(policyFromNeeds(a).fs).toEqual({ read: ['/a', '/b'], write: ['/a'], exec: [] });
  });

  it('refuses every unsafe path rather than escaping it', () => {
    const bad = ['relative/path', '', '/', '/a//b', '/a/', '/a/./b', '/a/../b', '/a"b', '/a\\b', '/a(b', '/a)b', '/a;b', '/a*b', '/a\nb', '/a\u0000b', '/ä', '/a b"', "/a'b", '/a$b', '/a`b'];
    for (const p of bad.filter((x) => x !== '/')) expect(() => policyFromNeeds([{ fs: [{ path: p, mode: 'r' }] }]), JSON.stringify(p)).toThrow(/bad_path/);
    expect(policyFromNeeds([{ fs: [{ path: '/', mode: 'r' }] }]).fs.read).toEqual(['/']);
  });

  it('refuses bad modes, hosts and ports, and network without a proxy', () => {
    expect(() => policyFromNeeds([{ fs: [{ path: '/a', mode: 'w' as never }] }])).toThrow('bad_mode');
    for (const host of ['', 'A.com', 'a b', 'a"b', '-a', 'a-', 'a/b']) expect(() => policyFromNeeds([{ net: [{ host, port: 443 }] }], 1), host).toThrow('bad_net_need');
    for (const port of [0, 70000, 1.5, -1]) expect(() => policyFromNeeds([{ net: [{ host: 'a.com', port }] }], 1)).toThrow('bad_net_need');
    expect(() => policyFromNeeds([{ net: [{ host: 'a.com', port: 443 }] }])).toThrow(/net_needs_proxy/);
    for (const p of [0, 70000, 1.5]) expect(() => policyFromNeeds([], p)).toThrow('bad_proxy_port');
  });
});

describe('compilePolicy: only what the verifier allowed contributes', () => {
  it('compiles authorized operations and refuses an unauthorized one', async () => {
    const f = authFixture(['notes']);
    const op = { verb: 'fs.read', resource: 'notes', params: { path: '/srv/notes/a.txt' } };
    const ok = await f.allow(op);
    const needsOf = (o: { params?: Record<string, unknown> }) => ({ fs: [{ path: String(o.params?.path), mode: 'r' as const }] });
    expect(compilePolicy([{ result: ok, operation: op }], needsOf).fs.read).toEqual(['/srv/notes/a.txt']);
    const denied = await f.allow(op, { ...op, params: { path: '/etc/shadow' } });
    expect(() => compilePolicy([{ result: denied, operation: op }], needsOf)).toThrow(/not_authorized/);
    expect(() => compilePolicy([{ result: ok, operation: { ...op, params: { path: '/etc/shadow' } } }], needsOf)).toThrow(/not_authorized/);
    expect(compilePolicy([{ result: ok, operation: op }], () => null).fs.read).toEqual([]);
  });
});

describe('generated profiles', () => {
  const tight = policyFromNeeds([{ fs: [{ path: '/srv/data', mode: 'r' }] }]);
  const full = policyFromNeeds([{ fs: [{ path: '/srv/out', mode: 'rw' }, { path: '/opt/t/run', mode: 'x' }], net: [{ host: 'a.com', port: 443 }] }], 3128);

  it('seccomp: default deny; no network or exec syscalls unless the grant needs them; socket limited to inet families', () => {
    const names = (p: ReturnType<typeof seccompProfile>) => p.syscalls.flatMap((s) => s.names);
    const t = seccompProfile(tight);
    expect(t.defaultAction).toBe('SCMP_ACT_ERRNO');
    for (const n of ['socket', 'connect', 'execve', 'execveat', 'ptrace', 'mount', 'bpf']) expect(names(t)).not.toContain(n);
    const f = seccompProfile(full);
    expect(names(f)).toEqual(expect.arrayContaining(['connect', 'socket', 'execve']));
    expect(f.syscalls.filter((s) => s.names[0] === 'socket').map((s) => s.args![0]!.value).sort((a, b) => a - b)).toEqual([2, 10]);
    for (const n of ['ptrace', 'mount', 'bpf', 'unshare', 'setns']) expect(names(f)).not.toContain(n);
  });

  it('landlock: handles every right, grants only the named paths and the proxy port', () => {
    const l = landlockRuleset(full);
    expect(l.handled_access_fs).toContain('LANDLOCK_ACCESS_FS_REFER');
    expect(l.rules.fs.map((r) => r.path)).toEqual(['/opt/t/run', '/srv/out']);
    expect(l.rules.fs.find((r) => r.path === '/opt/t/run')!.access).toEqual(['LANDLOCK_ACCESS_FS_EXECUTE', 'LANDLOCK_ACCESS_FS_READ_FILE']);
    expect(l.rules.fs.find((r) => r.path === '/srv/out')!.access).toContain('LANDLOCK_ACCESS_FS_WRITE_FILE');
    expect(l.rules.net).toEqual([{ port: 3128, access: ['LANDLOCK_ACCESS_NET_CONNECT_TCP'] }]);
    expect(landlockRuleset(tight).rules.net).toEqual([]);
    expect(landlockRuleset(tight).rules.fs[0]!.access).not.toContain('LANDLOCK_ACCESS_FS_WRITE_FILE');
  });

  it('macOS: deny default; network only to the proxy port', () => {
    const m = macosProfile(full);
    expect(m.split('\n')[1]).toBe('(deny default)');
    expect(m).toContain('(allow network-outbound (remote tcp "localhost:3128"))');
    expect(m).not.toMatch(/network\*|network-inbound|network-bind/);
    expect(macosProfile(tight)).not.toContain('network');
    expect(macosProfile(tight)).not.toContain('file-write');
  });
});

// The profile is only worth anything if the OS enforces it: run real processes under sandbox-exec(1) on macOS.
describe.runIf(process.platform === 'darwin' && fs.existsSync('/usr/bin/sandbox-exec'))('macOS sandbox-exec enforces the generated profile', () => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'pca-sbx-')));
  const allowed = path.join(dir, 'allowed');
  fs.mkdirSync(allowed);
  fs.writeFileSync(path.join(allowed, 'a.txt'), 'granted');
  fs.writeFileSync(path.join(dir, 'secret.txt'), 'nope');
  const run = (profile: string, args: string[]) => {
    const pf = path.join(dir, `p${Math.random().toString(36).slice(2)}.sb`);
    fs.writeFileSync(pf, profile);
    // async: the egress proxy under test runs in this process and must keep serving while the child runs
    return new Promise<{ status: number | null; stdout: string }>((resolve) => {
      execFile('/usr/bin/sandbox-exec', ['-f', pf, ...args], { encoding: 'utf8' }, (err, stdout) => resolve({ status: err ? (typeof err.code === 'number' ? err.code : 1) : 0, stdout }));
    });
  };

  it('reads the granted path and nothing else', async () => {
    const profile = macosProfile(policyFromNeeds([{ fs: [{ path: '/bin/cat', mode: 'x' }, { path: allowed, mode: 'r' }] }]));
    const ok = await run(profile, ['/bin/cat', path.join(allowed, 'a.txt')]);
    expect([ok.status, ok.stdout]).toEqual([0, 'granted']);
    const no = await run(profile, ['/bin/cat', path.join(dir, 'secret.txt')]);
    expect(no.status).not.toBe(0);
    expect(no.stdout).toBe('');
    expect((await run(profile, ['/bin/cat', '/etc/hosts'])).stdout).toBe('');
  });

  it('a tool in the sandbox can reach the egress proxy and the admitted request, and nothing else', async () => {
    const hits: string[] = [];
    const listen = (s: http.Server) => new Promise<number>((r) => s.listen(0, '127.0.0.1', () => r((s.address() as { port: number }).port)));
    const origin = http.createServer((req, res) => { hits.push(req.url!); res.end('data'); });
    const originPort = await listen(origin);
    const other = http.createServer((req, res) => { hits.push(`other${req.url}`); res.end('data'); });
    const otherPort = await listen(other);
    const f = authFixture(['api']);
    const get = { verb: 'http.get', resource: 'api', params: { path: '/v1/items' } };
    const policy = new EgressPolicy();
    policy.admit(await f.allow(get), get, () => ({ method: 'GET', scheme: 'http', host: '127.0.0.1', port: originPort, path: '/v1/items' }));
    const log = new ReceiptLog();
    const proxy = createEgressProxy({ policy, log, allowPrivate: true });
    const proxyPort = await listen(proxy);
    const profile = macosProfile(policyFromNeeds([{ fs: [{ path: '/usr/bin/curl', mode: 'x' }, { path: '/private/etc/ssl', mode: 'r' }] }], proxyPort));
    const curl = (args: string[]) => run(profile, ['/usr/bin/curl', '-s', '--max-time', '5', '-o', '-', '-w', '|%{http_code}', ...args]);
    try {
      // direct to the origin: the OS refuses before any packet leaves
      const direct = await curl([`http://127.0.0.1:${originPort}/v1/items`]);
      expect(direct.stdout).not.toContain('data');
      // via the proxy: the admitted request goes through once
      const via = await curl(['-x', `http://127.0.0.1:${proxyPort}`, `http://127.0.0.1:${originPort}/v1/items`]);
      expect(via.stdout).toBe('data|200');
      // via the proxy to an unlisted host: refused by the proxy
      const unlisted = await curl(['-x', `http://127.0.0.1:${proxyPort}`, `http://127.0.0.1:${otherPort}/v1/items`]);
      expect(unlisted.stdout).toContain('|403');
      // the same admitted request again: spent
      expect((await curl(['-x', `http://127.0.0.1:${proxyPort}`, `http://127.0.0.1:${originPort}/v1/items`])).stdout).toContain('|403');
      expect(hits).toEqual(['/v1/items']);
    } finally {
      origin.close(); other.close(); proxy.close();
    }
  });
});
