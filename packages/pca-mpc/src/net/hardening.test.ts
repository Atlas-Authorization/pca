/**
 * Hardening regressions for the networked MPC transport: forged abort frames, linear framing, bounded
 * observation log, inbox cap, test-hook gating and the multi-host runner's input validation.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import * as tls from 'node:tls';
import { describe, expect, it } from 'vitest';
import { ManualClock, T, until, waitListening, reservePorts } from './test-timing';
import { generateIdentity, readPem } from './certs';
import { MAX_MESH_EVENTS, Mesh } from './mesh';
import { FrameSplitter, MAX_FRAME_BYTES, NetAbort, WIRE_VERSION, encodeFrame, type Frame } from './wire';

/** A scripted raw peer (node 1) that dials node 0 and speaks the framing by hand. */
async function rawPeer(opts: { meshCfg?: Partial<ConstructorParameters<typeof Mesh>[0]>; ids?: number }) {
  const dir = mkdtempSync(join(tmpdir(), 'pca-mpc-hard-'));
  const a = generateIdentity(join(dir, 'a'), 'a');
  const b = generateIdentity(join(dir, 'b'), 'b');
  const c = generateIdentity(join(dir, 'c'), 'c');
  const [pa, pb, pc] = (await reservePorts(3)) as [number, number, number];
  const nodes = [
    { id: 0, host: '127.0.0.1', port: pa, certPem: readPem(a.certPath) },
    { id: 1, host: '127.0.0.1', port: pb, certPem: readPem(b.certPath) },
    { id: 2, host: '127.0.0.1', port: pc, certPem: readPem(c.certPath) },
  ];
  const mesh = new Mesh({
    selfId: 0, nodes, linkTo: [1], keyPem: readPem(a.keyPath), certPem: readPem(a.certPath),
    sessionId: 's', listenHost: '127.0.0.1', connectTimeoutMs: T(30_000), recvTimeoutMs: T(10_000), ...opts.meshCfg,
  });
  const connected = mesh.connect().catch((e) => e);
  await waitListening(pa);
  const sock = tls.connect({ host: '127.0.0.1', port: pa, key: readPem(b.keyPath), cert: readPem(b.certPath), ca: [nodes[0]!.certPem], checkServerIdentity: () => undefined });
  sock.on('error', () => undefined);
  let seq = 0;
  const send = (ty: Frame['ty'], rd: string, d: unknown): void => {
    sock.write(encodeFrame({ v: WIRE_VERSION, ty, sid: 's', seq: seq++, rd, d }));
  };
  await new Promise<void>((r) => sock.once('secureConnect', () => r()));
  send('hello', 'hello', { id: 1 });
  await connected;
  const done = (): void => {
    sock.destroy();
    mesh.fail(mesh.failed ?? new NetAbort('local', null, 0, 'test done'));
    rmSync(dir, { recursive: true, force: true });
  };
  return { mesh, send, sock, done, pa, certs: { a, b, c } };
}

describe('abort frames are claims, validated before use', () => {
  it('blames the party that SENT the abort, keeps the accusation separate', async () => {
    const p = await rawPeer({});
    p.send('abort', 'abort', { kind: 'timeout', blamed: 2, detail: 'it was node 2' });
    const e = (await p.mesh.recv(1, 'x').catch((x) => x)) as NetAbort;
    expect(e).toBeInstanceOf(NetAbort);
    expect(e.kind).toBe('peer-abort');
    expect(e.blamed).toBe(1);
    expect(e.claimedBlame).toBe(2);
    expect(e.claimedKind).toBe('timeout');
    p.done();
  }, T(20_000));

  it.each([[999], [-1], [1.5], ['2'], [1e308], [null]])('ignores an out-of-range or non-integer accusation (%s)', async (blamed) => {
    const p = await rawPeer({});
    p.send('abort', 'abort', { kind: 'bogus-kind', blamed, detail: 'x'.repeat(100000) + '\u0000\n[forged] blamed=2' });
    const e = (await p.mesh.recv(1, 'x').catch((x) => x)) as NetAbort;
    expect(e.blamed).toBe(1);
    expect(e.claimedBlame).toBeNull();
    expect(e.claimedKind).toBeUndefined();
    expect(e.message.length).toBeLessThan(400);
    expect(e.message.includes('\u0000') || e.message.includes('\n')).toBe(false);
    p.done();
  }, T(20_000));
});

describe('framing is linear and bounded', () => {
  it('reassembles a maximum-size frame delivered in tiny chunks in linear time', () => {
    const body = Buffer.alloc(MAX_FRAME_BYTES, 0x61);
    const raw = Buffer.allocUnsafe(4 + body.length);
    raw.writeUInt32BE(body.length, 0);
    body.copy(raw, 4);
    const sp = new FrameSplitter();
    let got: Buffer[] = [];
    for (let i = 0; i < raw.length; i += 64) got = got.concat(sp.push(raw.subarray(i, Math.min(raw.length, i + 64))));
    expect(got).toHaveLength(1);
    expect(got[0]!.equals(body)).toBe(true);
  }, T(20_000));

  it('splits back-to-back frames across arbitrary chunk boundaries', () => {
    const mk = (n: number) => encodeFrame({ v: WIRE_VERSION, ty: 'msg', sid: 's', seq: n, rd: 'r', d: 'x'.repeat(n) });
    const all = Buffer.concat([mk(1), mk(50), mk(0), mk(300)]);
    for (const step of [1, 3, 7, 4096]) {
      const sp = new FrameSplitter();
      const out: Buffer[] = [];
      for (let i = 0; i < all.length; i += step) out.push(...sp.push(all.subarray(i, i + step)));
      expect(out.map((b) => JSON.parse(b.toString()).seq)).toEqual([1, 50, 0, 300]);
    }
  });

  it('bounds the observation log', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pca-mpc-ev-'));
    try {
      const a = generateIdentity(join(dir, 'a'), 'a');
      const b = generateIdentity(join(dir, 'b'), 'b');
      const evil = generateIdentity(join(dir, 'e'), 'e');
      const [pa, pb2] = (await reservePorts(2)) as [number, number];
      const nodes = [
        { id: 0, host: '127.0.0.1', port: pa, certPem: readPem(a.certPath) },
        { id: 1, host: '127.0.0.1', port: pb2, certPem: readPem(b.certPath) },
      ];
      const m = new Mesh({ selfId: 0, nodes, keyPem: readPem(a.keyPath), certPem: readPem(a.certPath), sessionId: 's', listenHost: '127.0.0.1', connectTimeoutMs: T(30_000) });
      const c = m.connect().catch((e) => e);
      await waitListening(pa);
      const n = MAX_MESH_EVENTS * 3;
      await Promise.all(
        Array.from({ length: n }, () => new Promise<void>((r) => {
          const s = tls.connect({ host: '127.0.0.1', port: pa, key: readPem(evil.keyPath), cert: readPem(evil.certPath), rejectUnauthorized: false });
          s.on('error', () => r());
          s.on('close', () => r());
          setTimeout(r, T(1500)); // fallback only; the normal path is the error/close event
        })),
      );
      await until(() => m.events.length + m.eventsDropped > MAX_MESH_EVENTS, 'the rejected clients to be recorded');
      expect(m.events.length).toBeLessThanOrEqual(MAX_MESH_EVENTS);
      expect(m.events.length + m.eventsDropped).toBeGreaterThan(MAX_MESH_EVENTS);
      m.fail(m.failed ?? new NetAbort('local', null, 0, 'done'));
      await c;
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, T(30_000));

  it('caps the inbox: a peer that floods unread frames is blamed with flood', async () => {
    const p = await rawPeer({ meshCfg: { maxInboxFrames: 20 } });
    for (let i = 0; i < 200; i++) p.send('msg', 'r', i);
    await until(() => p.mesh.failed, 'the flood to be detected');
    expect(p.mesh.failed?.kind).toBe('flood');
    expect(p.mesh.failed?.blamed).toBe(1);
    p.done();
  }, T(20_000));

  it('caps the inbox by bytes', async () => {
    const p = await rawPeer({ meshCfg: { maxInboxBytes: 5000 } });
    for (let i = 0; i < 20; i++) p.send('msg', 'r', 'y'.repeat(1000));
    await until(() => p.mesh.failed, 'the flood to be detected');
    expect(p.mesh.failed?.kind).toBe('flood');
    p.done();
  }, T(20_000));
});

describe('test hooks are not reachable from the production path', () => {
  it('Mesh refuses a tamper hook without the explicit unsafeTestHooks flag', () => {
    const mk = (extra: object) =>
      new Mesh({ selfId: 0, nodes: [{ id: 0, host: '127.0.0.1', port: 1, certPem: '' }], keyPem: '', certPem: '', sessionId: 's', tamper: () => [], ...extra });
    expect(() => mk({})).toThrow(/unsafeTestHooks/);
    expect(() => mk({ unsafeTestHooks: true })).not.toThrow();
  });
});

// Under a Stryker sandbox (packages/pca-mpc/.stryker-tmp-*/sandbox-*/src/net) the repo root is two levels deeper. The runner is
// repository tooling (scripts/): absent from trees that ship this package without it (the public package repository), where
// this suite skips instead of failing.
const MULTIHOST = [resolve(__dirname, '../../../../scripts/pca-mpc-multihost.mjs'), resolve(__dirname, '../../../../../../scripts/pca-mpc-multihost.mjs')].find(existsSync);

describe.skipIf(!MULTIHOST)('multi-host runner validates host entries before running anything', () => {
  const script = MULTIHOST!;
  const runWith = (host: object, extra: string[] = []) => {
    const dir = mkdtempSync(join(tmpdir(), 'pca-mpc-mh-test-'));
    const f = join(dir, 'hosts.json');
    writeFileSync(f, JSON.stringify({ hosts: [{ name: 'a', addr: '203.0.113.5', user: 'mpcuser', key: '/dev/null', dir: '/home/mpcuser/mpc', node: '/usr/bin/node', main: '/home/mpcuser/m.js', hostKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl', ...host }], assign: { '0': 'a', dealer: 'a' } }));
    const r = spawnSync(process.execPath, [script, '--hosts', f, '--vectors', '[{"allow":1,"t":1,"rQuant":1}]', ...extra], { encoding: 'utf8', timeout: 15000 });
    rmSync(dir, { recursive: true, force: true });
    return r;
  };

  it.each([
    ['addr with shell metacharacters', { addr: '203.0.113.5; touch /tmp/pwned-mpc' }],
    ['addr that looks like an ssh option', { addr: '-oProxyCommand=touch' }],
    ['user that looks like an ssh option', { user: '-oProxyCommand=x' }],
    ['dir with a quote', { dir: "/home/x'; touch /tmp/pwned-mpc; '" }],
    ['node path with spaces and $()', { node: '/usr/bin/$(id)' }],
    ['relative dir', { dir: 'relative/dir' }],
  ])('rejects %s', (_n, host) => {
    const r = runWith(host);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/invalid host entry/);
    expect(existsSync('/tmp/pwned-mpc')).toBe(false);
  });

  it('refuses unpinned host keys unless explicitly told to accept new ones', () => {
    const r = runWith({ hostKey: undefined });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/hostKey/);
  });

  it('refuses behavior / frame-fault flags without the unsafe-test-hooks flag', () => {
    const r = runWith({}, ['--behavior', '{"party":0,"kind":"crash","round":"mul0"}']);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/unsafe-test-hooks/);
  });
});

describe('deadlines run on the injected clock (no wall-clock decision)', () => {
  it('a silent peer is blamed exactly when virtual time passes the deadline, and the deadline is recorded', async () => {
    const clock = new ManualClock();
    const p = await rawPeer({ meshCfg: { clock, recvTimeoutMs: 5000 } });
    const pending = p.mesh.recv(1, 'never').catch((x) => x as NetAbort);
    let settled = false;
    void pending.then(() => (settled = true));
    clock.advance(4999);
    await new Promise((r) => setImmediate(r));
    expect(settled).toBe(false); // however much real time passed, virtual time has not reached the deadline
    clock.advance(1);
    const e = (await pending) as NetAbort;
    expect(e.kind).toBe('timeout');
    expect(e.blamed).toBe(1);
    expect(e.deadlineMs).toBe(5000);
    p.done();
  }, T(20_000));
});
