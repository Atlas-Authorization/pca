import { describe, expect, it } from 'vitest';
import { authFixture, claimFixture } from './test-auth';
import {
  HandleTable, ReceiptLog, USE_ERR, buildProbeTool, buildTool, confineArgs, createSandbox, EgressPolicy, isPrivateAddress, policyFromNeeds,
  satisfiesRuntimeClass, signRuntimeClaim, verifiedRuntimeClass, verifyReceiptChain, landlockRuleset, seccompProfile, macosProfile,
} from './index';

// Exact-outcome tests: each pins a boundary or a literal so a mutated comparison, constant or branch changes an observable result.
const enc = (s: string) => new TextEncoder().encode(s);
const op = { verb: 'notes.read', resource: 'notes', params: { id: 'n-7' } };

describe('receipts: the exact record', () => {
  it('pins every field of a receipt and its digest', () => {
    const log = new ReceiptLog({ now: () => 1234 });
    const r = log.append('os_confined', { kind: 'handle_use', subject: { op_id: 'o', verb: 'v', resource: 'r', params_digest: 'p' }, outcome: 'ok', reason: 'used' });
    expect(r).toEqual({ v: 1, seq: 0, prev: 'genesis', at: 1234, runtime_class: 'os_confined', kind: 'handle_use', subject: { op_id: 'o', verb: 'v', resource: 'r', params_digest: 'p' }, outcome: 'ok', reason: 'used', digest: r.digest });
    const r2 = log.append('none', { kind: 'egress', subject: { op_id: '', verb: '', resource: '', params_digest: '' }, outcome: 'refused', reason: 'x' });
    expect([r2.seq, r2.prev]).toEqual([1, r.digest]);
    expect(r.digest).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(r2.digest).not.toBe(r.digest);
  });
  it('class order: equal satisfies, one below does not, every pair', () => {
    const C = ['none', 'os_confined', 'egress_default_deny', 'wasi_no_ambient'];
    for (const [i, a] of C.entries()) for (const [j, b] of C.entries()) expect(satisfiesRuntimeClass(a, b), `${a}>=${b}`).toBe(i >= j);
  });
});

describe('handles: boundaries', () => {
  const mk = async (now = () => 1000) => {
    const f = authFixture(['notes']);
    const t = new HandleTable('none', new ReceiptLog(), { 'notes.read': () => enc('x') }, now);
    return { t, ok: await f.allow(op) };
  };
  it('uses: 1 and 1_000_000 mint, 0 and 1_000_001 do not', async () => {
    const { t, ok } = await mk();
    expect(t.mint(ok, op, { uses: 1 })).toBe(1);
    expect(t.mint(ok, op, { uses: 1_000_000 })).toBe(2);
    expect(() => t.mint(ok, op, { uses: 0 })).toThrow('bad_uses');
    expect(() => t.mint(ok, op, { uses: 1_000_001 })).toThrow('bad_uses');
  });
  it('expiry is exclusive: usable at expiresAt-1, spent at expiresAt', async () => {
    let now = 99;
    const { t, ok } = await mk(() => now);
    const h = t.mint(ok, op, { uses: 2, expiresAt: 100 });
    expect(t.use(h).ok).toBe(true);
    now = 100;
    expect(t.use(h)).toEqual({ ok: false, reason: 'spent' });
  });
  it('attenuate: exactly the parent uses and exactly the parent expiry are allowed, one more is not', async () => {
    const { t, ok } = await mk();
    const p = t.mint(ok, op, { uses: 3, expiresAt: 5000 });
    expect(() => t.attenuate(p, { uses: 4 })).toThrow('attenuate_widens');
    expect(() => t.attenuate(p, { expiresAt: 5001 })).toThrow('attenuate_widens');
    const c = t.attenuate(p, { uses: 3, expiresAt: 5000 });
    expect(t.use(p)).toEqual({ ok: false, reason: 'spent' }); // the parent gave everything up
    expect(t.use(c).ok).toBe(true);
    expect(() => t.attenuate(p)).toThrow('unknown_handle'); // a spent parent cannot derive
  });
  it('verbOf: the verb of a real handle, null for handle 0, past the end and negative', async () => {
    const { t, ok } = await mk();
    t.mint(ok, op);
    expect([t.verbOf(1), t.verbOf(0), t.verbOf(2), t.verbOf(-1)]).toEqual(['notes.read', null, null, null]);
    expect(t.size).toBe(1);
  });
  it('a use is spent before the executor runs: the executor sees the handle already spent', async () => {
    const f = authFixture(['notes']);
    let inner: unknown;
    const t = new HandleTable('none', new ReceiptLog(), { 'notes.read': () => { inner = t.use(1); return enc('x'); } });
    t.mint(await f.allow(op), op);
    expect(t.use(1).ok).toBe(true);
    expect(inner).toEqual({ ok: false, reason: 'spent' });
  });
  it('the frozen copy: the signed params the executor sees are deep-equal to the mint, nested and frozen', async () => {
    const f = authFixture(['notes']);
    const o = { verb: 'notes.read', resource: 'notes', params: { id: 'n', nested: { a: [1, 2] } } };
    let seen: { params: { nested: { a: number[] } } } | undefined;
    const t = new HandleTable('none', new ReceiptLog(), { 'notes.read': (x) => { seen = x as never; return enc('x'); } });
    t.mint(await f.allow(o), o);
    t.use(1);
    expect(seen!.params.nested.a).toEqual([1, 2]);
    expect(Object.isFrozen(seen!.params.nested.a)).toBe(true);
    expect(Object.isFrozen(seen)).toBe(true);
  });
});

describe('host: boundaries', () => {
  const tool = buildTool({ calls: [{ handle: 1, ptr: 0, cap: 8 }] });
  it('module size: exactly the cap runs, one byte over is refused', () => {
    expect(createSandbox({ executors: {}, maxModuleBytes: tool.length }).run(tool).ok).toBe(true);
    expect(createSandbox({ executors: {}, maxModuleBytes: tool.length - 1 }).run(tool)).toEqual({ ok: false, reason: 'module_size' });
  });
  it('memory pages: max == cap and min == cap run; max cap+1 and min cap+1 are refused', () => {
    const sb = createSandbox({ executors: {}, maxMemoryPages: 4 });
    expect(sb.run(buildTool({ calls: [], memory: { min: 4, max: 4 } })).ok).toBe(true);
    expect(sb.run(buildTool({ calls: [], memory: { min: 1, max: 5 } }))).toEqual({ ok: false, reason: 'memory_limits' });
    expect(sb.run(buildTool({ calls: [], memory: { min: 5, max: 5 } }))).toEqual({ ok: false, reason: 'memory_limits' });
  });
  it('result window: exactly the result length fits, one byte less is out_too_small; result cap likewise', async () => {
    const f = authFixture(['notes']);
    const mkSb = async (maxResultBytes: number) => {
      const sb = createSandbox({ executors: { 'notes.read': () => new Uint8Array(10) }, runtimeClaim: claimFixture().runtimeClaim, maxResultBytes });
      sb.table.mint(await f.allow(op), op);
      return sb;
    };
    expect((await mkSb(1024)).run(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 10 }] }))).toEqual({ ok: true, value: 10 });
    expect((await mkSb(1024)).run(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 9 }] }))).toEqual({ ok: true, value: USE_ERR.out_too_small });
    expect((await mkSb(10)).run(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 100 }] }))).toEqual({ ok: true, value: 10 });
    expect((await mkSb(9)).run(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 100 }] }))).toEqual({ ok: true, value: USE_ERR.out_too_small });
  });
  it('memory window: the last byte of memory is writable, one past it is bad_memory', async () => {
    const f = authFixture(['notes']);
    const mkSb = async () => {
      const sb = createSandbox({ executors: { 'notes.read': () => new Uint8Array(4) }, runtimeClaim: claimFixture().runtimeClaim });
      sb.table.mint(await f.allow(op), op);
      return sb;
    };
    expect((await mkSb()).run(buildTool({ calls: [{ handle: 1, ptr: 65532, cap: 4 }] }))).toEqual({ ok: true, value: 4 });
    expect((await mkSb()).run(buildTool({ calls: [{ handle: 1, ptr: 65533, cap: 4 }] }))).toEqual({ ok: true, value: USE_ERR.bad_memory });
  });
  it('handle_verb: writes the verb into guest memory; the window must fit it exactly', async () => {
    const f = authFixture(['notes']);
    const mkSb = async () => {
      const sb = createSandbox({ executors: {}, runtimeClaim: claimFixture().runtimeClaim });
      sb.table.mint(await f.allow(op), op);
      return sb;
    };
    const first = 'n'.charCodeAt(0);
    expect((await mkSb()).run(buildProbeTool(10))).toEqual({ ok: true, value: 256 + first }); // 'notes.read' is 10 bytes
    expect((await mkSb()).run(buildProbeTool(9))).toEqual({ ok: true, value: 256 + 0 }); // too small: nothing written, byte0 stays 0
    expect(await (await mkSb()).runAsync(buildProbeTool(10))).toEqual({ ok: true, value: 256 + first });
    expect(await (await mkSb()).runAsync(buildProbeTool(9))).toEqual({ ok: true, value: 256 });
  });
  it('the timeout is honoured to the millisecond scale: a quick tool finishes well inside it', async () => {
    const sb = createSandbox({ executors: {} });
    const t0 = Date.now();
    expect(await sb.runAsync(buildTool({ calls: [] }), 'run', 5000)).toEqual({ ok: true, value: 0 });
    expect(Date.now() - t0).toBeLessThan(4000);
  });
});

describe('runtime claim: time and shape boundaries', () => {
  it('valid at iat, valid at exp-1, none at iat-1 and at exp', () => {
    const f = claimFixture('wasi_no_ambient', { iat: 10, exp: 20 });
    const at = (now: number) => verifiedRuntimeClass(f.claim, { ...f.trust, now });
    expect([at(9), at(10), at(19), at(20)]).toEqual(['none', 'wasi_no_ambient', 'wasi_no_ambient', 'none']);
  });
  it('a negative or fractional now is none (as in every native)', () => {
    const f = claimFixture();
    expect(verifiedRuntimeClass(f.claim, { ...f.trust, now: -1 })).toBe('none');
    expect(verifiedRuntimeClass(f.claim, { ...f.trust, now: 0.5 })).toBe('none'); // the natives require an integer time too
  });
  it('a wrong-length attestor key is none even if pinned', () => {
    const f = claimFixture();
    const short = signRuntimeClaim(f.kp.secretKey, f.kp.publicKey, { class: 'wasi_no_ambient', passport_digest: f.trust.passportDigest, evidence_digest: 'ev1', iat: 0, exp: 10 });
    expect(verifiedRuntimeClass({ ...short, attestor: 'AAAA' }, { ...f.trust, pinnedAttestors: ['AAAA'] })).toBe('none');
  });
});

describe('egress: numeric boundaries', () => {
  const admit = async (over: object) => {
    const f = authFixture(['api']);
    const get = { verb: 'http.get', resource: 'api', params: {} };
    new EgressPolicy().admit(await f.allow(get), get, () => ({ method: 'GET', scheme: 'https', host: 'a.com', path: '/', ...over }));
  };
  it('port 1 and 65535 are admitted, 0 and 65536 are not', async () => {
    await admit({ port: 1 });
    await admit({ port: 65535 });
    await expect(admit({ port: 0 })).rejects.toThrow('bad_template_port');
    await expect(admit({ port: 65536 })).rejects.toThrow('bad_template_port');
  });
  it('private ranges: the exact edges', () => {
    const t = ['9.255.255.255', '11.0.0.0', '126.255.255.255', '128.0.0.0', '169.253.255.255', '169.255.0.0', '172.15.255.255', '172.32.0.0', '192.167.255.255', '192.169.0.0', '100.63.255.255', '100.128.0.0', '223.255.255.255'];
    for (const ip of t) expect(isPrivateAddress(ip), ip).toBe(false);
    for (const ip of ['0.0.0.1', '10.0.0.0', '127.255.255.255', '169.254.0.0', '172.16.0.0', '172.31.255.255', '192.168.0.0', '100.64.0.0', '100.127.255.255', '224.0.0.0', '255.255.255.255']) expect(isPrivateAddress(ip), ip).toBe(true);
    for (const ip of ['fc00::', 'fdff::1', 'fe80::', 'febf::1', 'ff00::']) expect(isPrivateAddress(ip), ip).toBe(true);
    for (const ip of ['fbff::1', 'fec0::1', '2001:db8::1']) expect(isPrivateAddress(ip), ip).toBe(false);
  });
});

describe('confineArgs: the exact flags for a known policy', () => {
  it('flattens the generated profiles with nothing added', () => {
    const p = policyFromNeeds([{ fs: [{ path: '/opt/t/run', mode: 'x' }, { path: '/srv/in', mode: 'r' }, { path: '/srv/out', mode: 'rw' }] }], 3128);
    const a = confineArgs(p);
    const ll = landlockRuleset(p);
    expect(a.slice(0, 2)).toEqual(['--fs-handled', ll.handled_access_fs.map((x) => x.replace('LANDLOCK_ACCESS_', '')).join(',')]);
    expect(a.slice(2, 4)).toEqual(['--net-handled', 'NET_BIND_TCP,NET_CONNECT_TCP']);
    expect(a).toContain('--fs');
    expect(a.filter((x, i) => a[i - 1] === '--fs')).toEqual(['/opt/t/run:FS_EXECUTE,FS_READ_FILE', '/srv/in:FS_READ_FILE,FS_READ_DIR', '/srv/out:FS_READ_FILE,FS_READ_DIR,FS_WRITE_FILE,FS_TRUNCATE,FS_MAKE_REG,FS_MAKE_DIR,FS_REMOVE_FILE,FS_REMOVE_DIR']);
    expect(a.filter((x, i) => a[i - 1] === '--net')).toEqual(['3128:NET_CONNECT_TCP']);
    expect(a.filter((x, i) => a[i - 1] === '--allow-arg')).toEqual(['socket:0:2', 'socket:0:10']);
    const allowed = a.filter((x, i) => a[i - 1] === '--allow');
    const sc = seccompProfile(p);
    expect(allowed).toEqual(sc.syscalls.filter((s) => !s.args).flatMap((s) => s.names));
    expect(allowed).toContain('execve');
    expect(allowed).toContain('connect');
  });
  it('no proxy: no net flags; no exec path: no execve', () => {
    const a = confineArgs(policyFromNeeds([{ fs: [{ path: '/srv/in', mode: 'r' }] }]));
    expect(a).not.toContain('--net-handled');
    expect(a).not.toContain('--net');
    expect(a).not.toContain('execve');
    expect(a).not.toContain('--allow-arg');
  });
});

describe('macOS profile: exact lines', () => {
  it('pins the whole profile for a known policy', () => {
    const p = policyFromNeeds([{ fs: [{ path: '/opt/t/run', mode: 'x' }, { path: '/srv/in', mode: 'r' }, { path: '/srv/out', mode: 'rw' }] }], 8080);
    expect(macosProfile(p).split('\n')).toEqual([
      '(version 1)', '(deny default)', '(allow sysctl-read)', '(allow process-fork)', '(allow mach-lookup)', '(allow file-read-metadata)',
      '(allow file-read* (literal "/") (literal "/dev/null") (literal "/dev/urandom") (subpath "/usr/lib") (subpath "/System/Library") (subpath "/private/var/db/dyld") (subpath "/System/Volumes/Preboot/Cryptexes"))',
      '(allow process-exec (literal "/opt/t/run"))', '(allow file-read* (literal "/opt/t/run"))',
      '(allow file-read* (subpath "/srv/in"))', '(allow file-read* (subpath "/srv/out"))', '(allow file-write* (subpath "/srv/out"))',
      '(allow network-outbound (remote tcp "localhost:8080"))', '',
    ]);
  });
});
