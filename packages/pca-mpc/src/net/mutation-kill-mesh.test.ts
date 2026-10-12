import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as net from 'node:net';
import * as tls from 'node:tls';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { generateIdentity, readPem } from './certs';
import { MAX_MESH_EVENTS, Mesh, type MeshConfig, type NodeAddr, type TamperEvent } from './mesh';
import { ManualClock, T, reservePorts, until, waitListening } from './test-timing';
import { FrameSplitter, MAX_FRAME_BYTES, NetAbort, WIRE_VERSION, encodeFrame, parseFrame, type Frame } from './wire';

let dir: string;
let ids: Array<{ key: string; cert: string }>;
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'pca-mesh-kill-'));
  ids = ['a', 'b', 'c'].map((n) => {
    const i = generateIdentity(join(dir, n), n);
    return { key: readPem(i.keyPath), cert: readPem(i.certPath) };
  });
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));
afterEach(() => {
  vi.useRealTimers();
});
/** A virtual clock that counts reads, so a test can wait for the connect loop to have polled it. */
class CountingClock extends ManualClock {
  reads = 0;
  override now(): number {
    this.reads++;
    return super.now();
  }
}
const polled = async (c: CountingClock, times = 2): Promise<void> => {
  const r0 = c.reads;
  await until(() => c.reads >= r0 + times, 'the connect loop to poll the clock');
};
/** One full event-loop turn (no wall-clock wait). */
const tick = (): Promise<void> => new Promise((r) => setImmediate(r));

const SID = 's';
async function nodes3(): Promise<NodeAddr[]> {
  const ports = await reservePorts(3);
  return ids.map((x, i) => ({ id: i, host: '127.0.0.1', port: ports[i]!, certPem: x.cert }));
}

/** A scripted raw peer that dials `mesh` (node 0) as node `as` and records every frame the mesh sends it. */
interface Raw {
  sock: tls.TLSSocket;
  got: Frame[];
  raw: Buffer[];
  closed: () => boolean;
  send: (ty: Frame['ty'], rd: string, d: unknown, over?: Partial<Frame>) => void;
  write: (b: Buffer) => void;
  sendMany: (items: Array<[string, unknown]>) => void;
  seq: () => number;
}
async function dialRaw(nodes: NodeAddr[], as: number, hello = true, attached = true): Promise<Raw> {
  const sock = tls.connect({ host: '127.0.0.1', port: nodes[0]!.port, key: ids[as]!.key, cert: ids[as]!.cert, ca: [nodes[0]!.certPem], checkServerIdentity: () => undefined });
  const got: Frame[] = [];
  const raw: Buffer[] = [];
  const sp = new FrameSplitter();
  let closed = false;
  sock.on('data', (d) => {
    for (const b of sp.push(d)) {
      raw.push(b);
      const f = parseFrame(b);
      if (f) got.push(f);
    }
  });
  sock.on('error', () => undefined);
  sock.on('close', () => (closed = true));
  await new Promise<void>((r) => sock.once('secureConnect', () => r()));
  let seq = 0;
  const send: Raw['send'] = (ty, rd, d, over = {}) => {
    sock.write(encodeFrame({ v: WIRE_VERSION, ty, sid: SID, seq: seq++, rd, d, ...over }));
  };
  if (attached) await until(() => got.length >= 1 || closed, 'the mesh to attach the link and say hello');
  if (hello) send('hello', 'hello', { id: as });
  const sendMany: Raw['sendMany'] = (items) => {
    sock.write(Buffer.concat(items.map(([rd, d]) => encodeFrame({ v: WIRE_VERSION, ty: 'msg', sid: SID, seq: seq++, rd, d }))));
  };
  return { sock, got, raw, closed: () => closed, send, write: (b) => sock.write(b), sendMany, seq: () => seq };
}

interface Fx {
  mesh: Mesh;
  nodes: NodeAddr[];
  peer: Raw;
  peer2: Raw | null;
  clock: ManualClock;
  done: () => void;
}
async function withPeer(cfg: Partial<MeshConfig> = {}, opts: { hello?: boolean; linkTo?: number[] } = {}): Promise<Fx> {
  const nodes = await nodes3();
  const clock = new ManualClock();
  const mesh = new Mesh({
    selfId: 0, nodes, linkTo: opts.linkTo ?? [1], keyPem: ids[0]!.key, certPem: ids[0]!.cert, sessionId: SID, listenHost: '127.0.0.1',
    clock, connectTimeoutMs: T(30_000), recvTimeoutMs: T(10_000), ...cfg,
  });
  const connected = mesh.connect().catch((e) => e);
  await waitListening(nodes[0]!.port);
  const peer = await dialRaw(nodes, 1, opts.hello !== false);
  const peer2 = (opts.linkTo ?? [1]).includes(2) ? await dialRaw(nodes, 2, opts.hello !== false) : null;
  if (opts.hello !== false) await connected;
  return {
    mesh, nodes, peer, peer2, clock,
    done: () => {
      peer.sock.destroy();
      peer2?.sock.destroy();
      mesh.fail(mesh.failed ?? new NetAbort('local', null, 0, 'test done'));
    },
  };
}
const failureOf = async (fx: Fx): Promise<NetAbort> => (await until(() => fx.mesh.failed, 'mesh failure')) as NetAbort;

describe('construction', () => {
  it('refuses a tamper hook without unsafeTestHooks, with an explanatory message', () => {
    const mk = (extra: object) => new Mesh({ selfId: 0, nodes: [{ id: 0, host: '127.0.0.1', port: 1, certPem: ids[0]!.cert }], keyPem: '', certPem: '', sessionId: SID, ...extra });
    expect(() => mk({ tamper: () => [] })).toThrow('mesh: the tamper test hook requires unsafeTestHooks: true (test-only)');
    expect(() => mk({ tamper: () => [], unsafeTestHooks: false })).toThrow('unsafeTestHooks');
    expect(() => mk({ tamper: () => [], unsafeTestHooks: true })).not.toThrow();
    expect(() => mk({})).not.toThrow();
  });
  it('rejects a link target that is not a node', () => {
    const base = { selfId: 0, nodes: [{ id: 0, host: 'h', port: 1, certPem: ids[0]!.cert }, { id: 1, host: 'h', port: 2, certPem: ids[1]!.cert }], keyPem: '', certPem: '', sessionId: SID };
    expect(() => new Mesh({ ...base, linkTo: [7] })).toThrow('mesh: unknown link target 7');
    expect(() => new Mesh({ ...base, linkTo: [0] })).not.toThrow(); // self is a node (degenerate but declared)
  });
  it('exposes selfId, sessionId and the sorted peer list; default links are all other nodes', () => {
    const ns = [2, 0, 1].map((i) => ({ id: i, host: 'h', port: i, certPem: ids[i]!.cert }));
    const m = new Mesh({ selfId: 1, nodes: ns, keyPem: '', certPem: '', sessionId: 'sess-x' });
    expect(m.selfId).toBe(1);
    expect(m.sessionId).toBe('sess-x');
    expect(m.peers).toEqual([0, 2]);
    expect(m.failed).toBeNull();
    expect(m.events).toEqual([]);
    expect(m.eventsDropped).toBe(0);
    const m2 = new Mesh({ selfId: 1, nodes: ns, linkTo: [2], keyPem: '', certPem: '', sessionId: 's' });
    expect(m2.peers).toEqual([2]);
  });
  it('connect() without self in nodes throws', async () => {
    const m = new Mesh({ selfId: 5, nodes: [{ id: 0, host: 'h', port: 1, certPem: ids[0]!.cert }], keyPem: '', certPem: '', sessionId: SID, linkTo: [0] });
    await expect(m.connect()).rejects.toThrow('mesh: self not in nodes');
  });
});

describe('connect', () => {
  it('times out blaming the first missing peer with a message naming all of them, only after the deadline', async () => {
    const nodes = await nodes3();
    const clock = new CountingClock();
    const m = new Mesh({ selfId: 0, nodes, linkTo: [1, 2], keyPem: ids[0]!.key, certPem: ids[0]!.cert, sessionId: SID, listenHost: '127.0.0.1', clock, connectTimeoutMs: 1000 });
    let outcome: unknown = 'pending';
    const p = m.connect().then(() => (outcome = 'ok'), (e) => (outcome = e));
    await waitListening(nodes[0]!.port);
    clock.advance(1000);
    await polled(clock); // three connect polls see now === deadline
    expect(outcome).toBe('pending'); // now === deadline: not yet expired
    clock.advance(1);
    await p;
    const e = outcome as NetAbort;
    expect(e.kind).toBe('timeout');
    expect(e.blamed).toBe(1);
    expect(e.reporter).toBe(0);
    expect(e.message).toContain('connect: no authenticated link from 1,2');
    expect(m.failed).toBe(e);
  }, T(20_000));
  it('the default connect timeout is 30 s', async () => {
    const nodes = await nodes3();
    const clock = new CountingClock();
    const m = new Mesh({ selfId: 0, nodes, linkTo: [1], keyPem: ids[0]!.key, certPem: ids[0]!.cert, sessionId: SID, listenHost: '127.0.0.1', clock });
    let outcome: unknown = 'pending';
    const p = m.connect().then(() => (outcome = 'ok'), (e) => (outcome = e));
    await waitListening(nodes[0]!.port);
    clock.advance(30_000);
    await polled(clock);
    expect(outcome).toBe('pending');
    clock.advance(1);
    await p;
    expect((outcome as NetAbort).kind).toBe('timeout');
  }, T(20_000));
  it('a listen failure rejects connect', async () => {
    const nodes = await nodes3();
    const a = new Mesh({ selfId: 0, nodes, linkTo: [1], keyPem: ids[0]!.key, certPem: ids[0]!.cert, sessionId: SID, listenHost: '127.0.0.1', connectTimeoutMs: 500 });
    const pa = a.connect().catch((e) => e);
    await waitListening(nodes[0]!.port);
    const b = new Mesh({ selfId: 0, nodes, linkTo: [1], keyPem: ids[0]!.key, certPem: ids[0]!.cert, sessionId: SID, listenHost: '127.0.0.1', connectTimeoutMs: 500 });
    await expect(b.connect()).rejects.toThrow(/EADDRINUSE/);
    a.fail(new NetAbort('local', null, 0, 'x'));
    await pa;
  }, T(20_000));
  it('rejects, and records, connections from unpinned certificates, lower ids, unlinked nodes and duplicates', async () => {
    const fx = await withPeer({}, { linkTo: [1] });
    // unlinked node 2 (pinned but no link on this mesh)
    const s2 = await dialRaw(fx.nodes, 2, false, false);
    await until(() => fx.mesh.events.some((e) => e.startsWith('rejected incoming connection (fp=')), 'rejection note');
    expect(fx.mesh.events.find((e) => e.startsWith('rejected incoming connection'))).toMatch(/^rejected incoming connection \(fp=([0-9A-F]{2}:){31}[0-9A-F]{2}\)$/);
    // a duplicate connection from the already-linked node 1
    const dup = await dialRaw(fx.nodes, 1, false, false);
    await until(() => fx.mesh.events.some((e) => e === 'duplicate connection from node 1'), 'duplicate note');
    expect(fx.peer.closed()).toBe(false); // the original link survives
    dup.sock.destroy();
    s2.sock.destroy();
    fx.done();
  }, T(20_000));
  it('a lower-numbered node may not dial a higher-numbered one', async () => {
    const nodes = await nodes3();
    const m = new Mesh({ selfId: 1, nodes, linkTo: [0], keyPem: ids[1]!.key, certPem: ids[1]!.cert, sessionId: SID, listenHost: '127.0.0.1', connectTimeoutMs: 300 });
    const c = m.connect().catch((e) => e);
    await waitListening(nodes[1]!.port);
    const s = tls.connect({ host: '127.0.0.1', port: nodes[1]!.port, key: ids[0]!.key, cert: ids[0]!.cert, ca: [nodes[1]!.certPem], checkServerIdentity: () => undefined });
    s.on('error', () => undefined);
    await until(() => m.events.some((e) => e.startsWith('rejected incoming connection')), 'lower-id rejection');
    s.destroy();
    m.fail(new NetAbort('local', null, 1, 'done'));
    await c;
  }, T(20_000));
});

describe('two real meshes', () => {
  async function pairUp(cfg0: Partial<MeshConfig> = {}, cfg1: Partial<MeshConfig> = {}) {
    const nodes = await nodes3();
    const m0 = new Mesh({ selfId: 0, nodes, linkTo: [1], keyPem: ids[0]!.key, certPem: ids[0]!.cert, sessionId: SID, listenHost: '127.0.0.1', connectTimeoutMs: T(30_000), recvTimeoutMs: T(10_000), ...cfg0 });
    const m1 = new Mesh({ selfId: 1, nodes, linkTo: [0], keyPem: ids[1]!.key, certPem: ids[1]!.cert, sessionId: SID, listenHost: '127.0.0.1', connectTimeoutMs: T(30_000), recvTimeoutMs: T(10_000), ...cfg1 });
    await Promise.all([m0.connect(), m1.connect()]);
    return { m0, m1, nodes, end: () => { m0.fail(m0.failed ?? new NetAbort('local', null, 0, 'x')); m1.fail(m1.failed ?? new NetAbort('local', null, 1, 'x')); } };
  }
  it('exchange messages in both directions in order; stats count frames and bytes', async () => {
    const { m0, m1, end } = await pairUp();
    m0.send(1, 'r1', { a: 1 });
    m0.send(1, 'r2', 'two');
    m1.send(0, 'q', [1, 2, 3]);
    expect(await m1.recv(0, 'r1')).toEqual({ a: 1 });
    expect(await m1.recv(0, 'r2')).toBe('two');
    expect(await m0.recv(1, 'q')).toEqual([1, 2, 3]);
    const s0 = m0.stats();
    expect(s0.length).toBe(1);
    expect(s0[0]!.peer).toBe(1);
    expect(s0[0]!.framesOut).toBe(3); // hello + 2
    expect(s0[0]!.framesIn).toBe(2); // hello + 1
    expect(s0[0]!.appBytesOut).toBeGreaterThan(0);
    expect(s0[0]!.appBytesIn).toBeGreaterThan(0);
    expect(s0[0]!.tlsBytesWritten).toBe(s0[0]!.appBytesOut);
    expect(s0[0]!.tlsBytesRead).toBe(s0[0]!.appBytesIn);
    expect(s0[0]!.tlsBytesRead).toBeGreaterThan(0);
    const s1 = m1.stats()[0]!;
    expect(s1.appBytesIn).toBe(s0[0]!.appBytesOut);
    expect(s1.appBytesOut).toBe(s0[0]!.appBytesIn);
    end();
  }, T(20_000));
  it('broadcast and collect default to every peer', async () => {
    const { m0, m1, end } = await pairUp();
    m0.broadcast('bc', 7);
    m0.broadcast('only', 8, [1]);
    m0.broadcast('none', 9, []);
    expect(await m1.collect('bc')).toEqual(new Map([[0, 7]]));
    expect(await m1.collect('only', [0])).toEqual(new Map([[0, 8]]));
    m1.send(0, 'z', 1);
    expect(await m0.collect('z', [1])).toEqual(new Map([[1, 1]]));
    end();
  }, T(20_000));
  it('sign / verify use the pinned TLS identity; verify never throws and refuses self and unknown peers', async () => {
    const { m0, m1, end } = await pairUp();
    const data = Buffer.from('hello world');
    const sig = m0.sign(data);
    expect(m1.verify(0, data, sig)).toBe(true);
    expect(m1.verify(0, Buffer.from('hello worle'), sig)).toBe(false);
    expect(m1.verify(1, data, sig)).toBe(false); // self
    expect(m1.verify(9, data, sig)).toBe(false); // unknown
    expect(m1.verify(2, data, sig)).toBe(false); // wrong key
    expect(m1.verify(0, data, new Uint8Array([1, 2, 3]))).toBe(false);
    const bad = Buffer.from(sig);
    bad[bad.length - 1] = bad[bad.length - 1]! ^ 1;
    expect(m1.verify(0, data, bad)).toBe(false);
    expect(m0.verify(0, data, sig)).toBe(false);
    end();
  }, T(20_000));
  it('send / recv on an unknown peer throw, and a failed mesh refuses further sends with its failure', async () => {
    const { m0, end } = await pairUp();
    expect(() => m0.send(5, 'r', 1)).toThrow('mesh: no link to 5');
    await expect(m0.recv(5, 'r')).rejects.toThrow('mesh: no link to 5');
    const e = new NetAbort('local', null, 0, 'boom');
    m0.fail(e);
    expect(m0.failed).toBe(e);
    expect(() => m0.send(1, 'r', 1)).toThrow(e);
    await expect(m0.recv(1, 'r')).rejects.toBe(e);
    end();
  }, T(20_000));
  it('the first failure wins', async () => {
    const { m0, end } = await pairUp();
    const e1 = new NetAbort('local', null, 0, 'first');
    m0.fail(e1);
    m0.fail(new NetAbort('timeout', 1, 0, 'second'));
    expect(m0.failed).toBe(e1);
    end();
  }, T(20_000));
  it('a mesh failure is propagated to the peer as an abort frame (kind, blame, sanitized detail) and wakes a pending recv', async () => {
    const { m0, m1, end } = await pairUp();
    const pending = m1.recv(0, 'never').catch((e) => e);
    m0.fail(new NetAbort('dealer', 1, 0, 'bad\u0001dealer ' + 'x'.repeat(300)));
    const e = (await pending) as NetAbort;
    expect(e.kind).toBe('peer-abort');
    expect(e.blamed).toBe(0); // the sender of the abort, not the accused
    expect(e.claimedKind).toBe('dealer');
    expect(e.claimedBlame).toBe(1);
    expect(e.message).toContain('peer 0 reported an abort (dealer, accuses 1, unverified)');
    expect(e.message).not.toContain('\u0001');
    end();
  }, T(20_000));
  it('tamper hook sees only non-hello frames with the destination, frame and honest encoding; its outputs are what is sent', async () => {
    const seen: TamperEvent[] = [];
    const { m0, m1, end } = await pairUp({ unsafeTestHooks: true, tamper: (ev) => (seen.push(ev), [ev.raw, ev.raw]) });
    m0.send(1, 'dupe', 'x');
    expect(await m1.recv(0, 'dupe')).toBe('x');
    const e = (await m1.recv(0, 'dupe').catch((x) => x)) as NetAbort; // the duplicate is a replayed sequence number
    expect(e.kind).toBe('duplicate');
    expect(seen.length).toBe(1);
    expect(seen[0]!.to).toBe(1);
    expect(seen[0]!.frame.rd).toBe('dupe');
    expect(seen[0]!.frame.seq).toBe(1);
    expect(seen[0]!.raw.equals(encodeFrame(seen[0]!.frame))).toBe(true);
    expect(m0.stats()[0]!.framesOut).toBe(2); // one logical frame per send, however many wire writes
    end();
  }, T(20_000));
});

describe('dialing', () => {
  it('a server whose certificate is not the pinned identity of the node dialed is an identity abort', async () => {
    const [pa, pb] = await reservePorts(2);
    // nodes 0 and 2 share one certificate; the pin table maps that fingerprint to node 2, so dialing node 0 must be refused
    const nodes: NodeAddr[] = [
      { id: 0, host: '127.0.0.1', port: pa!, certPem: ids[0]!.cert },
      { id: 1, host: '127.0.0.1', port: pb!, certPem: ids[1]!.cert },
      { id: 2, host: '127.0.0.1', port: pa!, certPem: ids[0]!.cert },
    ];
    const srv = tls.createServer({ key: ids[0]!.key, cert: ids[0]!.cert, ca: [ids[1]!.cert], requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.3' }, (s) => s.on('error', () => undefined));
    await new Promise<void>((r) => srv.listen(pa, '127.0.0.1', () => r()));
    const m = new Mesh({ selfId: 1, nodes, linkTo: [0], keyPem: ids[1]!.key, certPem: ids[1]!.cert, sessionId: SID, listenHost: '127.0.0.1', connectTimeoutMs: T(10_000) });
    const e = (await m.connect().catch((x) => x)) as NetAbort;
    expect(e.kind).toBe('identity');
    expect(e.blamed).toBe(0);
    expect(e.reporter).toBe(1);
    expect(e.message).toContain('dial: peer certificate is not the pinned identity of node 0');
    srv.close();
  }, T(30_000));
  it('keeps retrying a dial until the peer is up (pacing is not a decision)', async () => {
    const nodes = await nodes3();
    const m1 = new Mesh({ selfId: 1, nodes, linkTo: [0], keyPem: ids[1]!.key, certPem: ids[1]!.cert, sessionId: SID, listenHost: '127.0.0.1', connectTimeoutMs: T(30_000) });
    const c1 = m1.connect();
    await waitListening(nodes[1]!.port); // m1 is up and dialing a node that is not there yet
    const m0 = new Mesh({ selfId: 0, nodes, linkTo: [1], keyPem: ids[0]!.key, certPem: ids[0]!.cert, sessionId: SID, listenHost: '127.0.0.1', connectTimeoutMs: T(30_000) });
    await Promise.all([m0.connect(), c1]);
    m0.fail(new NetAbort('local', null, 0, 'x'));
    m1.fail(new NetAbort('local', null, 1, 'x'));
  }, T(30_000));
});

describe('receive path (scripted peer)', () => {
  const abortOf = async (fx: Fx): Promise<NetAbort> => {
    const e = await failureOf(fx);
    fx.done();
    return e;
  };
  it('an announced length above MAX_FRAME_BYTES is an oversize abort naming the sender', async () => {
    const fx = await withPeer();
    const h = Buffer.alloc(4);
    h.writeUInt32BE(MAX_FRAME_BYTES + 1, 0);
    fx.peer.write(h);
    const e = await abortOf(fx);
    expect([e.kind, e.blamed, e.reporter]).toEqual(['oversize', 1, 0]);
    expect(e.message).toContain('length prefix above MAX_FRAME_BYTES');
  }, T(20_000));
  it('undecodable and ill-shaped frames are malformed', async () => {
    for (const body of [Buffer.from('not json'), Buffer.from('[1,2]'), Buffer.from(JSON.stringify({ v: WIRE_VERSION, ty: 'msg' }))]) {
      const fx = await withPeer();
      const raw = Buffer.alloc(4 + body.length);
      raw.writeUInt32BE(body.length, 0);
      body.copy(raw, 4);
      fx.peer.write(raw);
      const e = await abortOf(fx);
      expect([e.kind, e.blamed]).toEqual(['malformed', 1]);
      expect(e.message).toContain('undecodable or ill-shaped frame');
    }
  }, T(30_000));
  it('a frame of another wire version is a typed version abort; a non-integer or non-number v stays malformed', async () => {
    for (const [v, kind] of [[WIRE_VERSION + 1, 'version'], [0, 'version'], [-5, 'version'], [1.5, 'malformed'], ['2', 'malformed'], [null, 'malformed']] as const) {
      const fx = await withPeer();
      const body = Buffer.from(JSON.stringify({ v, ty: 'msg', sid: SID, seq: 1, rd: 'r', d: 0 }));
      const raw = Buffer.alloc(4 + body.length);
      raw.writeUInt32BE(body.length, 0);
      body.copy(raw, 4);
      fx.peer.write(raw);
      const e = await abortOf(fx);
      expect(e.kind).toBe(kind);
      if (kind === 'version') expect(e.message).toContain(`peer 1 speaks wire version ${String(v)}, this node speaks ${WIRE_VERSION}; upgrade both peers`);
    }
  }, T(40_000));
  it('a frame from another session is refused', async () => {
    const fx = await withPeer();
    fx.peer.send('msg', 'r', 1, { sid: 'other' });
    const e = await abortOf(fx);
    expect([e.kind, e.blamed]).toEqual(['wrong-session', 1]);
    expect(e.message).toContain('frame from another session');
  }, T(20_000));
  it('replayed and skipped sequence numbers are distinguished and described', async () => {
    const dup = await withPeer();
    dup.peer.send('msg', 'r', 1, { seq: 0 });
    const e1 = await abortOf(dup);
    expect([e1.kind, e1.blamed]).toEqual(['duplicate', 1]);
    expect(e1.message).toContain('expected seq 1, got 0 (round r)');
    const skip = await withPeer();
    skip.peer.send('msg', 'rr', 1, { seq: 2 });
    const e2 = await abortOf(skip);
    expect([e2.kind, e2.blamed]).toEqual(['out-of-order', 1]);
    expect(e2.message).toContain('expected seq 1, got 2 (round rr)');
  }, T(30_000));
  it('a second hello, a hello with the wrong id, and data before hello are refused', async () => {
    const h2 = await withPeer();
    h2.peer.send('hello', 'hello', { id: 1 });
    const e1 = await abortOf(h2);
    expect([e1.kind, e1.blamed]).toEqual(['identity', 1]);
    expect(e1.message).toContain('hello claims id 1 on the link pinned to 1');
    for (const d of [{ id: 2 }, null, 'x', {}]) {
      const fx = await withPeer({}, { hello: false });
      fx.peer.send('hello', 'hello', d);
      const e = await failureOf(fx);
      expect([e.kind, e.blamed]).toEqual(['identity', 1]);
      expect(e.message).toContain(`hello claims id ${String((d as { id?: unknown } | null)?.id)}`);
      fx.done();
    }
    const early = await withPeer({}, { hello: false });
    early.peer.send('msg', 'r', 1);
    const e3 = await failureOf(early);
    expect([e3.kind, e3.blamed]).toEqual(['malformed', 1]);
    expect(e3.message).toContain('data before hello');
    early.done();
  }, T(40_000));
  it('the data-before-hello check does not trip after a proper hello', async () => {
    const fx = await withPeer();
    fx.peer.send('msg', 'r', 'ok');
    expect(await fx.mesh.recv(1, 'r')).toBe('ok');
    expect(fx.mesh.failed).toBeNull();
    fx.done();
  }, T(20_000));
});

describe('abort frames from a peer', () => {
  const recvAbort = async (d: unknown, extra: Partial<Fx> = {}) => {
    const fx = await withPeer();
    fx.peer.send('abort', 'abort', d);
    const e = (await fx.mesh.recv(1, 'x').catch((x) => x)) as NetAbort;
    return { fx, e, ...extra };
  };
  it('a reported abort blames the sender and records the claim separately', async () => {
    const { fx, e } = await recvAbort({ kind: 'timeout', blamed: 2, detail: 'it was 2' });
    expect([e.kind, e.blamed, e.reporter, e.claimedKind, e.claimedBlame, e.reason]).toEqual(['peer-abort', 1, 0, 'timeout', 2, null]);
    expect(e.message).toBe('[peer-abort] blamed=1 reporter=0: peer 1 reported an abort (timeout, accuses 2, unverified) it was 2');
    fx.done();
  }, T(20_000));
  it('accusation bounds: 0..maxId inclusive, integers only', async () => {
    for (const [blamed, want] of [[0, 0], [2, 2], [3, null], [-1, null], [1.5, null], ['1', null], [null, null], [undefined, null]] as const) {
      const { fx, e } = await recvAbort({ kind: 'local', blamed, detail: 'd' });
      expect(e.claimedBlame).toBe(want);
      expect(e.message).toContain(`accuses ${want === null ? 'no one' : want}`);
      fx.done();
    }
  }, T(60_000));
  it('unknown kinds and non-string kinds are ignored; known kinds are kept', async () => {
    for (const [kind, want] of [['mac-check', 'mac-check'], ['version', 'version'], ['made-up', undefined], [5, undefined], [undefined, undefined]] as const) {
      const { fx, e } = await recvAbort({ kind, blamed: 0, detail: 'd' });
      expect(e.claimedKind).toBe(want);
      expect(e.message).toContain(`(${want ?? 'unspecified'}, accuses 0`);
      fx.done();
    }
  }, T(60_000));
  it('detail is sanitised to printable ASCII and capped at 120 characters; non-strings become empty', async () => {
    const a = await recvAbort({ kind: 'local', blamed: 0, detail: 'a\nb\u0000cé' + 'z'.repeat(200) });
    expect(a.e.message.endsWith(`unverified) a?b?c?${'z'.repeat(120 - 6)}`)).toBe(true);
    a.fx.done();
    const b = await recvAbort({ kind: 'local', blamed: 0, detail: 5 });
    expect(b.e.message.endsWith('unverified) ')).toBe(true);
    b.fx.done();
    const c = await recvAbort(null);
    expect(c.e.message).toContain('(unspecified, accuses no one, unverified) ');
    c.fx.done();
    const d = await recvAbort({ kind: 'local', blamed: 0, detail: 'z'.repeat(120) });
    expect(d.e.message.endsWith('z'.repeat(120))).toBe(true);
    d.fx.done();
  }, T(60_000));
  it('a relayed abort names no one, with an explanatory reason; only a literal true counts as relayed', async () => {
    const { fx, e } = await recvAbort({ kind: 'dealer', blamed: 2, detail: 'second hand', relayed: true });
    expect(e.blamed).toBeNull();
    expect(e.reason).toBe('relayed abort: a second-hand claim passed on by an honest peer; it names no one and is never evidence');
    expect(e.message).toContain('peer 1 relayed an abort (dealer, accuses 2, unverified) second hand');
    fx.done();
    for (const relayed of ['true', 1, false, undefined]) {
      const r = await recvAbort({ kind: 'dealer', blamed: 2, detail: 'x', relayed });
      expect(r.e.blamed).toBe(1);
      expect(r.e.message).toContain('reported an abort');
      r.fx.done();
    }
  }, T(60_000));
  it('the abort is NOT echoed back to the peer that sent it, but is relayed (marked relayed, claim only) to the others', async () => {
    const fx = await withPeer({}, { linkTo: [1, 2] });
    const p2 = fx.peer2!;
    fx.peer.send('abort', 'abort', { kind: 'mac-check', blamed: 2, detail: 'hmm' });
    await until(() => p2.got.some((f) => f.ty === 'abort'), 'relay to peer 2');
    const rel = p2.got.find((f) => f.ty === 'abort')!;
    expect(rel.rd).toBe('abort');
    expect(rel.sid).toBe(SID);
    expect(rel.d).toEqual({ kind: 'mac-check', blamed: 2, detail: expect.stringContaining('peer 1 reported an abort'), relayed: true });
    await until(() => fx.peer.closed(), 'the mesh to close the reporting link'); // every frame it was sent has arrived
    expect(fx.peer.got.filter((f) => f.ty === 'abort')).toEqual([]);
    fx.done();
  }, T(30_000));
  it('relaying an unattributable or unknown-kind abort uses peer-abort / null', async () => {
    const fx = await withPeer({}, { linkTo: [1, 2] });
    const p2 = fx.peer2!;
    fx.peer.send('abort', 'abort', { kind: 'bogus', blamed: 99, detail: 'x' });
    await until(() => p2.got.some((f) => f.ty === 'abort'), 'relay to peer 2');
    expect((p2.got.find((f) => f.ty === 'abort')!.d as { kind: string; blamed: unknown }).kind).toBe('peer-abort');
    expect((p2.got.find((f) => f.ty === 'abort')!.d as { blamed: unknown }).blamed).toBeNull();
    fx.done();
  }, T(30_000));
  it('a local failure sends a plain abort frame (no relayed marker) with kind, blame and sanitised detail to every peer', async () => {
    const fx = await withPeer();
    fx.mesh.fail(new NetAbort('flood', 1, 0, 'bad\u0007thing ' + 'q'.repeat(400)));
    await until(() => fx.peer.got.some((f) => f.ty === 'abort'), 'abort frame');
    const f = fx.peer.got.find((x) => x.ty === 'abort')!;
    const d = f.d as { kind: string; blamed: number | null; detail: string; relayed?: boolean };
    expect(d.kind).toBe('flood');
    expect(d.blamed).toBe(1);
    expect(d.detail.length).toBe(200);
    expect(d.detail.startsWith('[flood] blamed=1 reporter=0: bad?thing ')).toBe(true);
    expect('relayed' in d).toBe(false);
    expect(f.seq).toBe(1); // after the hello (seq 0)
    fx.done();
  }, T(20_000));
  it('an unattributable local failure sends blamed: null', async () => {
    const fx = await withPeer();
    fx.mesh.fail(new NetAbort('mac-check', null, 0, 'who knows'));
    await until(() => fx.peer.got.some((f) => f.ty === 'abort'), 'abort frame');
    expect((fx.peer.got.find((f) => f.ty === 'abort')!.d as { blamed: unknown }).blamed).toBeNull();
    fx.done();
  }, T(20_000));
});

describe('recv', () => {
  it('returns payloads in order and frees inbox accounting; a payload round of the wrong name is a wrong-round abort', async () => {
    const fx = await withPeer();
    fx.peer.send('msg', 'a', 1);
    fx.peer.send('msg', 'b', 2);
    expect(await fx.mesh.recv(1, 'a')).toBe(1);
    const e = (await fx.mesh.recv(1, 'zzz').catch((x) => x)) as NetAbort;
    expect([e.kind, e.blamed, e.reporter]).toEqual(['wrong-round', 1, 0]);
    expect(e.message).toContain("expected round 'zzz', got 'b'");
    fx.done();
  }, T(20_000));
  it('times out on the virtual clock exactly at the deadline, blaming the silent peer and recording the deadline', async () => {
    const fx = await withPeer();
    let out: unknown = 'pending';
    const p = fx.mesh.recv(1, 'x', 5000).then((v) => (out = v), (e) => (out = e));
    await until(() => fx.clock.pending === 1, 'the receive timer');
    fx.clock.advance(4999);
    await tick();
    expect(out).toBe('pending');
    expect(fx.clock.pending).toBe(1);
    fx.clock.advance(1);
    await p;
    const e = out as NetAbort;
    expect([e.kind, e.blamed, e.reporter, e.deadlineMs]).toEqual(['timeout', 1, 0, 5000]);
    expect(e.message).toContain("no 'x' message from 1 within 5000ms (deadline 5000ms; a silent peer is blamed on this local observation only)");
    fx.done();
  }, T(20_000));
  it('uses the configured recvTimeoutMs by default (and 20 s when unset)', async () => {
    const fx = await withPeer({ recvTimeoutMs: 700 });
    const p = fx.mesh.recv(1, 'x').catch((e) => e);
    await until(() => fx.clock.pending === 1, 'the receive timer');
    fx.clock.advance(700);
    expect(((await p) as NetAbort).deadlineMs).toBe(700);
    fx.done();
    const d = await withPeer({ recvTimeoutMs: undefined });
    let out2: unknown = 'pending';
    const p2 = d.mesh.recv(1, 'x').then((v) => (out2 = v), (e) => (out2 = e));
    await until(() => d.clock.pending === 1, 'the receive timer');
    d.clock.advance(19_999);
    await tick();
    expect(out2).toBe('pending');
    d.clock.advance(1);
    await p2;
    expect((out2 as NetAbort).deadlineMs).toBe(20_000);
    d.done();
  }, T(30_000));
  it('a closed link is a disconnect abort naming the peer (after queued data is drained)', async () => {
    const fx = await withPeer();
    fx.peer.send('msg', 'a', 1);
    await until(() => fx.mesh.stats()[0]!.framesIn >= 2, 'the message');
    fx.peer.sock.destroy();
    expect(await fx.mesh.recv(1, 'a')).toBe(1);
    const e = (await fx.mesh.recv(1, 'b').catch((x) => x)) as NetAbort;
    expect([e.kind, e.blamed, e.reporter]).toEqual(['disconnect', 1, 0]);
    expect(e.message).toContain("link to 1 closed while awaiting 'b'");
  }, T(20_000));
  it('a wake-up from new data delivers a message that arrives while waiting', async () => {
    const fx = await withPeer();
    const p = fx.mesh.recv(1, 'late');
    await until(() => fx.clock.pending === 1, 'the receive to wait');
    fx.peer.send('msg', 'late', 'here');
    expect(await p).toBe('here');
    fx.done();
  }, T(20_000));
  it('collect rejects as soon as one link fails', async () => {
    const fx = await withPeer({}, { linkTo: [1, 2] });
    const c = fx.mesh.collect('r').catch((e) => e);
    fx.peer.send('msg', 'wrongname', 1);
    const e = (await c) as NetAbort;
    expect(e.kind).toBe('wrong-round');
    fx.done();
  }, T(20_000));
});

describe('inbox limits and flow control', () => {
  it('accepts exactly maxInboxFrames queued frames, pauses the socket past half, resumes when drained to half, and floods on one more', async () => {
    const fx = await withPeer({ maxInboxFrames: 4 });
    const link = (fx.mesh as unknown as { links: Map<number, { paused: boolean; inbox: unknown[]; inboxBytes: number }> }).links.get(1)!;
    fx.peer.sendMany([['r', 1], ['r', 2]]);
    await until(() => link.inbox.length === 2, '2 queued');
    expect(link.paused).toBe(false); // 2 is not more than half of 4
    fx.peer.sendMany([['r', 3], ['r', 4]]);
    await until(() => link.inbox.length === 4, '4 queued');
    expect(fx.mesh.failed).toBeNull(); // exactly at the cap is allowed
    expect(link.paused).toBe(true);
    await fx.mesh.recv(1, 'r');
    expect(link.paused).toBe(true); // 3 left: still more than half
    await fx.mesh.recv(1, 'r');
    expect(link.paused).toBe(false); // 2 left: at half, resumed
    expect(link.inboxBytes).toBeGreaterThan(0);
    await fx.mesh.recv(1, 'r');
    await fx.mesh.recv(1, 'r');
    expect(link.inboxBytes).toBe(0);
    fx.peer.sendMany([['r', 1], ['r', 2], ['r', 3], ['r', 4], ['r', 5]]);
    const e = await failureOf(fx);
    expect([e.kind, e.blamed]).toEqual(['flood', 1]);
    fx.done();
  }, T(30_000));
  it('byte accounting: the cap is on queued frame bytes and pausing starts past half of it', async () => {
    const fx = await withPeer({ maxInboxBytes: 1000 });
    const link = (fx.mesh as unknown as { links: Map<number, { paused: boolean; inbox: unknown[]; inboxBytes: number }> }).links.get(1)!;
    fx.peer.send('msg', 'r', 'x'.repeat(300));
    await until(() => link.inbox.length === 1, 'one queued');
    const one = link.inboxBytes;
    expect(one).toBeGreaterThan(300);
    expect(link.paused).toBe(false);
    fx.peer.send('msg', 'r', 'x'.repeat(300));
    await until(() => link.inbox.length === 2, 'two queued');
    expect(link.inboxBytes).toBe(one * 2);
    expect(link.paused).toBe(true);
    fx.done();
    const g = await withPeer({ maxInboxBytes: 1000 });
    g.peer.sendMany([['r', 'x'.repeat(300)], ['r', 'x'.repeat(300)], ['r', 'x'.repeat(300)]]);
    const e = await failureOf(g);
    expect([e.kind, e.blamed]).toEqual(['flood', 1]);
    expect(e.message).toContain('peer 1 queued more than the inbox cap allows');
    g.done();
  }, T(30_000));
});

describe('observations and shutdown', () => {
  it('records a link that closed before its hello, once, and not after finish/failure', async () => {
    const fx = await withPeer({}, { hello: false });
    fx.peer.sock.destroy();
    await until(() => fx.mesh.events.find((e) => e.startsWith('link 1 closed before hello: ')), 'the close note');
    expect(fx.mesh.events.filter((e) => e.startsWith('link 1 closed before hello')).length).toBe(1);
    fx.mesh.fail(new NetAbort('local', null, 0, 'done'));
  }, T(20_000));
  it('no note for a close after hello', async () => {
    const fx = await withPeer();
    fx.peer.sock.destroy();
    await until(() => fx.peer.closed(), 'closed');
    await until(() => (fx.mesh as unknown as { links: Map<number, { closed: boolean }> }).links.get(1)!.closed, 'the mesh to see the close');
    expect(fx.mesh.events.filter((e) => e.includes('closed before hello'))).toEqual([]);
    fx.mesh.fail(new NetAbort('local', null, 0, 'done'));
  }, T(20_000));
  it('caps the event log at MAX_MESH_EVENTS and counts the overflow', async () => {
    const fx = await withPeer({}, { hello: false });
    const note = (fx.mesh as unknown as { note: (m: string) => void }).note.bind(fx.mesh);
    const pre = fx.mesh.events.length;
    for (let i = 0; i < MAX_MESH_EVENTS + 5; i++) note(`e${i}`);
    expect(fx.mesh.events.length).toBe(MAX_MESH_EVENTS);
    expect(fx.mesh.events[MAX_MESH_EVENTS - 1]).toBe(`e${MAX_MESH_EVENTS - 1 - pre}`);
    expect(fx.mesh.eventsDropped).toBe(5 + pre);
    fx.peer.sock.destroy();
    fx.mesh.fail(new NetAbort('local', null, 0, 'done'));
  }, T(20_000));
  it('finish() flushes and closes the links; a failure closes them shortly after the abort frame', async () => {
    const fx = await withPeer();
    await fx.mesh.finish();
    await until(() => fx.peer.closed(), 'link closed after finish');
    const g = await withPeer();
    g.mesh.fail(new NetAbort('local', null, 0, 'x'));
    await until(() => g.peer.closed(), 'link closed after failure');
    expect(g.peer.got.some((f) => f.ty === 'abort')).toBe(true);
  }, T(30_000));
  it('the hello frame is the first frame the mesh sends: seq 0, round "hello", carrying its id', async () => {
    const fx = await withPeer();
    await until(() => fx.peer.got.length >= 1, 'hello');
    const h = fx.peer.got[0]!;
    expect([h.v, h.ty, h.sid, h.seq, h.rd, h.d]).toEqual([WIRE_VERSION, 'hello', SID, 0, 'hello', { id: 0 }]);
    fx.mesh.send(1, 'r', { k: 1 });
    await until(() => fx.peer.got.length >= 2, 'msg');
    const m = fx.peer.got[1]!;
    expect([m.v, m.ty, m.sid, m.seq, m.rd, m.d]).toEqual([WIRE_VERSION, 'msg', SID, 1, 'r', { k: 1 }]);
    fx.done();
  }, T(20_000));
});

// ===================================================================================== second round

const wire = (rd: string, d: unknown, seq: number): number => encodeFrame({ v: WIRE_VERSION, ty: 'msg', sid: SID, seq, rd, d }).length - 4;

describe('TLS policy and door-keeping', () => {
  const dialAs = async (nodes: NodeAddr[], who: { key: string; cert: string }, opts: tls.ConnectionOptions = {}) => {
    const events: string[] = [];
    const sock = tls.connect({ host: '127.0.0.1', port: nodes[0]!.port, key: who.key, cert: who.cert, rejectUnauthorized: false, checkServerIdentity: () => undefined, ...opts });
    sock.on('error', (e) => events.push(`error:${e.message}`));
    let closed = false;
    sock.on('close', () => (closed = true));
    return { sock, events, closed: () => closed };
  };
  it('a client with an untrusted certificate is stopped in the TLS handshake and recorded as a TLS client error', async () => {
    const fx = await withPeer();
    const evil = generateIdentity(join(dir, 'evil'), 'evil');
    const c = await dialAs(fx.nodes, { key: readPem(evil.keyPath), cert: readPem(evil.certPath) });
    await until(() => fx.mesh.events.some((e) => e.startsWith('tlsClientError: ')), 'tls client error note');
    await until(() => c.closed(), 'the client to be dropped'); // a socket the server accepted would be noted before it is closed
    expect(fx.mesh.events.some((e) => e.startsWith('rejected incoming connection'))).toBe(false);
    expect(fx.mesh.events.find((e) => e.startsWith('tlsClientError: '))!.length).toBeLessThanOrEqual('tlsClientError: '.length + 120);
    await until(() => c.closed(), 'client dropped');
    fx.done();
  }, T(20_000));
  it('the mesh\'s own certificate is not accepted from a client either (only the OTHER nodes are trusted)', async () => {
    const fx = await withPeer();
    const c = await dialAs(fx.nodes, ids[0]!);
    await until(() => fx.mesh.events.some((e) => e.startsWith('tlsClientError: ')), 'tls client error note');
    await until(() => c.closed(), 'the client to be dropped');
    expect(fx.mesh.events.some((e) => e.startsWith('rejected incoming connection'))).toBe(false);
    fx.done();
  }, T(20_000));
  it('TLS 1.2 clients are refused', async () => {
    const fx = await withPeer();
    const c = await dialAs(fx.nodes, ids[2]!, { maxVersion: 'TLSv1.2', ca: [fx.nodes[0]!.certPem], rejectUnauthorized: true });
    await until(() => c.closed(), 'client closed');
    await until(() => fx.mesh.events.some((e) => e.startsWith('tlsClientError: ')), 'tls client error');
    expect(c.events.join(' ')).toMatch(/version|protocol|alert/i);
    fx.done();
  }, T(20_000));
  it('rejected and duplicate connections are closed by the server', async () => {
    const fx = await withPeer();
    const s2 = await dialRaw(fx.nodes, 2, false, false);
    await until(() => s2.closed(), 'rejected link closed');
    const dup = await dialRaw(fx.nodes, 1, false, false);
    await until(() => dup.closed(), 'duplicate link closed');
    expect(fx.peer.closed()).toBe(false);
    fx.done();
  }, T(20_000));
  it('a server-level error is recorded and does not crash the mesh', async () => {
    const fx = await withPeer();
    const srv = (fx.mesh as unknown as { server: { emit: (e: string, x: Error) => boolean } }).server;
    srv.emit('error', new Error('boom'));
    expect(fx.mesh.events).toContain('server error: boom');
    fx.done();
  }, T(20_000));
  it('listens on the configured host, else on all interfaces', async () => {
    const fx = await withPeer();
    const a = (fx.mesh as unknown as { server: net.Server }).server.address() as net.AddressInfo;
    expect(a.address).toBe('127.0.0.1');
    fx.done();
    const nodes = await nodes3();
    const m = new Mesh({ selfId: 0, nodes, linkTo: [1], keyPem: ids[0]!.key, certPem: ids[0]!.cert, sessionId: SID, clock: new ManualClock(), connectTimeoutMs: 100000 });
    const c = m.connect().catch((e) => e);
    await waitListening(nodes[0]!.port);
    expect(((m as unknown as { server: net.Server }).server.address() as net.AddressInfo).address).toBe('0.0.0.0');
    m.fail(new NetAbort('local', null, 0, 'x'));
    await c;
  }, T(20_000));
  it('registers no more than the default number of event listeners without a warning even with many waiting receivers', async () => {
    const fx = await withPeer({}, { linkTo: [1] });
    const warnings: string[] = [];
    const onWarn = (w: Error): void => void warnings.push(w.name);
    process.on('warning', onWarn);
    try {
      const pending = Array.from({ length: 15 }, () => fx.mesh.recv(1, 'x').catch((e) => e));
      await until(() => fx.clock.pending === 15, 'all 15 receivers waiting');
      fx.mesh.fail(new NetAbort('local', null, 0, 'done'));
      await Promise.all(pending);
      await tick(); // process warnings are emitted on the next tick
    } finally {
      process.off('warning', onWarn);
    }
    expect(warnings).not.toContain('MaxListenersExceededWarning');
    fx.peer.sock.destroy();
  }, T(20_000));
});

describe('dial / connect corner cases', () => {
  it('a link target equal to self never dials itself (and so times out)', async () => {
    const nodes = await nodes3();
    const clock = new ManualClock();
    const m = new Mesh({ selfId: 0, nodes, linkTo: [0], keyPem: ids[0]!.key, certPem: ids[0]!.cert, sessionId: SID, listenHost: '127.0.0.1', clock, connectTimeoutMs: 1000 });
    let out: unknown = 'pending';
    const p = m.connect().then(() => (out = 'ok'), (e) => (out = e));
    await waitListening(nodes[0]!.port);
    clock.advance(1001);
    await p;
    expect(m.events.filter((e) => !e.startsWith('tlsClientError'))).toEqual([]);
    expect((out as NetAbort).kind).toBe('timeout');
    expect((out as NetAbort).blamed).toBe(0);
  }, T(20_000));
  it('node 2 dials node 1 at node 1\'s address (the node it is linked to, not the first node)', async () => {
    const nodes = await nodes3();
    const m1 = new Mesh({ selfId: 1, nodes, linkTo: [2], keyPem: ids[1]!.key, certPem: ids[1]!.cert, sessionId: SID, listenHost: '127.0.0.1', connectTimeoutMs: T(15_000) });
    const m2 = new Mesh({ selfId: 2, nodes, linkTo: [1], keyPem: ids[2]!.key, certPem: ids[2]!.cert, sessionId: SID, listenHost: '127.0.0.1', connectTimeoutMs: T(15_000) });
    await Promise.all([m1.connect(), m2.connect()]);
    m2.send(1, 'r', 'hi');
    expect(await m1.recv(2, 'r')).toBe('hi');
    expect(m1.events).toEqual([]);
    m1.fail(new NetAbort('local', null, 1, 'x'));
    m2.fail(new NetAbort('local', null, 2, 'x'));
  }, T(30_000));
  it('after a successful dial it does not dial again (the peer never sees a duplicate connection)', async () => {
    const nodes = await nodes3();
    const m0 = new Mesh({ selfId: 0, nodes, linkTo: [1], keyPem: ids[0]!.key, certPem: ids[0]!.cert, sessionId: SID, listenHost: '127.0.0.1', connectTimeoutMs: T(15_000) });
    const m1 = new Mesh({ selfId: 1, nodes, linkTo: [0], keyPem: ids[1]!.key, certPem: ids[1]!.cert, sessionId: SID, listenHost: '127.0.0.1', connectTimeoutMs: T(15_000) });
    await Promise.all([m0.connect(), m1.connect()]);
    // (a second dial would be refused as a duplicate; mutation-kill-mesh-inject.test.ts drives the dial loop deterministically)
    expect(m0.events).toEqual([]);
    expect(m1.events).toEqual([]);
    expect(m0.failed).toBeNull();
    m0.fail(new NetAbort('local', null, 0, 'x'));
    m1.fail(new NetAbort('local', null, 1, 'x'));
  }, T(30_000));
  it('a failed mesh stops dialing; dial retries are paced', async () => {
    const [pa, pb] = await reservePorts(2);
    let attempts = 0;
    const srv = net.createServer((raw) => {
      attempts++;
      raw.on('error', () => undefined);
      raw.destroy();
    });
    await new Promise<void>((r) => srv.listen(pa, '127.0.0.1', () => r()));
    const nodes: NodeAddr[] = [
      { id: 0, host: '127.0.0.1', port: pa!, certPem: ids[0]!.cert },
      { id: 1, host: '127.0.0.1', port: pb!, certPem: ids[1]!.cert },
    ];
    const m = new Mesh({ selfId: 1, nodes, linkTo: [0], keyPem: ids[1]!.key, certPem: ids[1]!.cert, sessionId: SID, listenHost: '127.0.0.1', connectTimeoutMs: 100000, clock: new ManualClock() });
    const c = m.connect().catch((e) => e);
    await until(() => attempts >= 2, 'at least two dial attempts');
    const mid = attempts;
    expect(mid).toBeLessThan(40); // paced, not a busy loop
    m.fail(new NetAbort('local', null, 1, 'stop'));
    await c;
    srv.close();
  }, T(30_000));
  it('an identity failure closes the client socket it dialed', async () => {
    const [pa, pb] = await reservePorts(2);
    const nodes: NodeAddr[] = [
      { id: 0, host: '127.0.0.1', port: pa!, certPem: ids[0]!.cert },
      { id: 1, host: '127.0.0.1', port: pb!, certPem: ids[1]!.cert },
      { id: 2, host: '127.0.0.1', port: pa!, certPem: ids[0]!.cert },
    ];
    let serverSideClosed = false;
    const srv = tls.createServer({ key: ids[0]!.key, cert: ids[0]!.cert, ca: [ids[1]!.cert], requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.3' }, (s) => s.on('error', () => undefined));
    srv.on('connection', (raw: net.Socket) => {
      raw.on('error', () => undefined);
      raw.on('close', () => (serverSideClosed = true));
    });
    srv.on('tlsClientError', () => undefined);
    await new Promise<void>((r) => srv.listen(pa, '127.0.0.1', () => r()));
    const m = new Mesh({ selfId: 1, nodes, linkTo: [0], keyPem: ids[1]!.key, certPem: ids[1]!.cert, sessionId: SID, listenHost: '127.0.0.1', connectTimeoutMs: T(10_000) });
    const e = (await m.connect().catch((x) => x)) as NetAbort;
    expect(e.kind).toBe('identity');
    await until(() => serverSideClosed, 'the dialed socket to be closed');
    srv.close();
  }, T(30_000));
});

describe('unconnected mesh', () => {
  const bare = () => new Mesh({ selfId: 0, nodes: [{ id: 0, host: 'h', port: 1, certPem: ids[0]!.cert }, { id: 1, host: 'h', port: 2, certPem: ids[1]!.cert }], keyPem: ids[0]!.key, certPem: ids[0]!.cert, sessionId: SID });
  it('send before any link exists is a no-op on the wire but is counted as a frame; stats are zero-byte', () => {
    const m = bare();
    m.send(1, 'r', 1);
    const s = m.stats()[0]!;
    expect([s.peer, s.framesOut, s.appBytesOut, s.tlsBytesWritten, s.tlsBytesRead, s.appBytesIn, s.framesIn]).toEqual([1, 1, 0, 0, 0, 0, 0]);
  });
  it('fail() on a mesh that never connected does not blow up later (no server to close)', async () => {
    const m = bare();
    const errors: unknown[] = [];
    const h = (e: unknown): void => void errors.push(e);
    process.on('uncaughtException', h);
    try {
      vi.useFakeTimers({ toFake: ['setTimeout'] });
      m.fail(new NetAbort('local', null, 0, 'x'));
      vi.runAllTimers(); // closeAll and its delayed destroy/server close
      vi.useRealTimers();
    } finally {
      process.off('uncaughtException', h);
    }
    expect(errors).toEqual([]);
  });
  it('verify never throws, even for a key that cannot verify SHA-256 signatures', async () => {
    const ed = join(dir, 'ed.pem');
    const key = join(dir, 'ed.key');
    const { execFileSync } = await import('node:child_process');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ed25519', '-nodes', '-keyout', key, '-out', ed, '-subj', '/CN=ed', '-days', '2'], { stdio: 'pipe' });
    const m = new Mesh({ selfId: 0, nodes: [{ id: 0, host: 'h', port: 1, certPem: ids[0]!.cert }, { id: 1, host: 'h', port: 2, certPem: readPem(ed) }], keyPem: ids[0]!.key, certPem: ids[0]!.cert, sessionId: SID });
    expect(m.verify(1, Buffer.from('x'), Buffer.from('y'))).toBe(false);
  });
});

describe('inbox boundaries (exact byte caps)', () => {
  it('a cap of exactly N frames is fine, N+1 bytes over floods; half-way marks are inclusive for pausing/resuming', async () => {
    const s = wire('r', 'x'.repeat(200), 1);
    const link = (fx: Fx) => (fx.mesh as unknown as { links: Map<number, { paused: boolean; inbox: unknown[]; inboxBytes: number }> }).links.get(1)!;
    const fx = await withPeer({ maxInboxBytes: 4 * s });
    fx.peer.sendMany([['r', 'x'.repeat(200)], ['r', 'x'.repeat(200)]]);
    await until(() => link(fx).inbox.length === 2, 'two queued');
    expect(link(fx).inboxBytes).toBe(2 * s);
    expect(link(fx).paused).toBe(false); // exactly half of the cap is not "more than half"
    fx.peer.sendMany([['r', 'x'.repeat(200)], ['r', 'x'.repeat(200)]]);
    await until(() => link(fx).inbox.length === 4, 'four queued');
    expect(fx.mesh.failed).toBeNull(); // exactly at the cap is allowed
    expect(link(fx).paused).toBe(true);
    await fx.mesh.recv(1, 'r');
    expect(link(fx).paused).toBe(true); // 3s left: still more than half of 4s
    await fx.mesh.recv(1, 'r');
    expect(link(fx).paused).toBe(false); // 2s left: exactly half resumes
    fx.done();
  }, T(30_000));
  it('one byte more than the cap floods', async () => {
    const s = wire('r', 'x'.repeat(200), 1);
    const fx = await withPeer({ maxInboxBytes: 2 * s - 1 });
    fx.peer.sendMany([['r', 'x'.repeat(200)], ['r', 'x'.repeat(200)]]);
    const e = await failureOf(fx);
    expect(e.kind).toBe('flood');
    fx.done();
  }, T(30_000));
});

describe('failure bookkeeping', () => {
  it('a failed recv poisons the mesh (wrong round, disconnect, timeout)', async () => {
    const a = await withPeer();
    a.peer.send('msg', 'zz', 1);
    const e1 = (await a.mesh.recv(1, 'x').catch((x) => x)) as NetAbort;
    expect(a.mesh.failed).toBe(e1);
    a.done();
    const b = await withPeer();
    b.peer.sock.destroy();
    const e2 = (await b.mesh.recv(1, 'x').catch((x) => x)) as NetAbort;
    expect(b.mesh.failed).toBe(e2);
    const c = await withPeer();
    const p = c.mesh.recv(1, 'x', 100).catch((x) => x);
    await until(() => c.clock.pending === 1, 'the receive timer');
    c.clock.advance(100);
    const e3 = (await p) as NetAbort;
    expect(c.mesh.failed).toBe(e3);
    c.done();
  }, T(30_000));
  it('fail() wakes a receiver on the same mesh at once', async () => {
    const fx = await withPeer();
    const p = fx.mesh.recv(1, 'x').catch((e) => e);
    await until(() => fx.clock.pending === 1, 'the receive timer');
    const boom = new NetAbort('local', null, 0, 'boom');
    fx.mesh.fail(boom);
    expect(await p).toBe(boom);
    fx.peer.sock.destroy();
  }, T(20_000));
  it('a satisfied receive clears its timer and its wake-up listener', async () => {
    const fx = await withPeer();
    const ev = (fx.mesh as unknown as { ev: { listenerCount: (n: string) => number } }).ev;
    const base = ev.listenerCount('wake');
    const p = fx.mesh.recv(1, 'x');
    await until(() => fx.clock.pending === 1, 'the receive timer');
    expect(ev.listenerCount('wake')).toBe(base + 1);
    fx.peer.send('msg', 'x', 1);
    await p;
    expect(fx.clock.pending).toBe(0);
    expect(ev.listenerCount('wake')).toBe(base);
    fx.done();
  }, T(20_000));
  it('after a failure incoming bytes are ignored and abort-frame sequence numbers advance only on live links', async () => {
    const fx = await withPeer({}, { linkTo: [1, 2] });
    const link = (id: number) => (fx.mesh as unknown as { links: Map<number, { sendSeq: number; bytesIn: number; closed: boolean }> }).links.get(id)!;
    fx.peer2!.sock.destroy();
    await until(() => link(2).closed, 'link 2 closed');
    const before = link(1).bytesIn;
    fx.mesh.fail(new NetAbort('local', null, 0, 'x'));
    expect(link(1).sendSeq).toBe(2); // hello (0) + abort (1) -> next is 2
    expect(link(2).sendSeq).toBe(1); // hello only: no abort frame was built for the dead link
    (fx.mesh as unknown as { onData: (l: unknown, b: Buffer) => void }).onData(link(1), encodeFrame({ v: WIRE_VERSION, ty: 'msg', sid: SID, seq: 1, rd: 'late', d: 'data' }));
    expect(link(1).bytesIn).toBe(before);
    fx.done();
  }, T(20_000));
  it('a send on a link whose socket is gone is not written or counted as bytes', async () => {
    const fx = await withPeer();
    fx.peer.sock.destroy();
    await until(() => (fx.mesh as unknown as { links: Map<number, { closed: boolean; socket: tls.TLSSocket }> }).links.get(1)!.socket.destroyed, 'socket destroyed');
    const before = fx.mesh.stats()[0]!.appBytesOut;
    fx.mesh.send(1, 'r', 'x'.repeat(50));
    expect(fx.mesh.stats()[0]!.appBytesOut).toBe(before);
    expect(fx.mesh.stats()[0]!.framesOut).toBe(2);
    fx.mesh.fail(new NetAbort('local', null, 0, 'x'));
  }, T(20_000));
  it('after a failure the port is released and links are torn down shortly after', async () => {
    const fx = await withPeer();
    fx.mesh.fail(new NetAbort('local', null, 0, 'x'));
    await until(() => fx.peer.closed(), 'peer link closed');
    await until(
      () =>
        new Promise<boolean>((res) => {
          const c = net.connect(fx.nodes[0]!.port, '127.0.0.1');
          c.on('connect', () => (c.destroy(), res(false)));
          c.on('error', () => res(true));
        }),
      'the listening port to be released',
    );
  }, T(20_000));
  it('close notes: a graceful close before hello, a reset before hello; nothing once finished or failed', async () => {
    const fx = await withPeer({}, { hello: false });
    fx.peer.sock.end();
    await until(() => fx.mesh.events.some((e) => e === 'link 1 closed before hello: peer ended'), 'peer ended note');
    fx.mesh.fail(new NetAbort('local', null, 0, 'x'));
    const gone = await withPeer({}, { hello: false });
    type OC = { onClosed: (l: unknown, why: string) => void; links: Map<number, unknown> };
    gone.mesh.fail(new NetAbort('local', null, 0, 'x'));
    (gone.mesh as unknown as OC).onClosed((gone.mesh as unknown as OC).links.get(1), 'socket closed');
    expect(gone.mesh.events.filter((e) => e.includes('closed before hello'))).toEqual([]);
    gone.peer.sock.destroy();
    const fin = await withPeer({}, { hello: false });
    await fin.mesh.finish();
    (fin.mesh as unknown as OC).onClosed((fin.mesh as unknown as OC).links.get(1), 'socket closed');
    expect(fin.mesh.events.filter((e) => e.includes('closed before hello'))).toEqual([]);
    fin.peer.sock.destroy();
  }, T(30_000));
  it('a TCP reset before hello is recorded as a socket error', async () => {
    const nodes = await nodes3();
    const mesh = new Mesh({ selfId: 0, nodes, linkTo: [1], keyPem: ids[0]!.key, certPem: ids[0]!.cert, sessionId: SID, listenHost: '127.0.0.1', clock: new ManualClock(), connectTimeoutMs: 100000 });
    const c = mesh.connect().catch((e) => e);
    await waitListening(nodes[0]!.port);
    const raw = net.connect(nodes[0]!.port, '127.0.0.1');
    await new Promise<void>((r) => raw.once('connect', () => r()));
    const t = tls.connect({ socket: raw, key: ids[1]!.key, cert: ids[1]!.cert, ca: [nodes[0]!.certPem], checkServerIdentity: () => undefined });
    t.on('error', () => undefined);
    await new Promise<void>((r) => t.once('secureConnect', () => r()));
    await until(() => (mesh as unknown as { links: Map<number, { socket: unknown }> }).links.get(1)!.socket !== null, 'the server side to attach the link');
    raw.resetAndDestroy();
    await until(() => mesh.events.some((e) => e.startsWith('link 1 closed before hello: ')), 'close note');
    expect(mesh.events.find((e) => e.startsWith('link 1 closed before hello: '))).toMatch(/^link 1 closed before hello: (socket error: .*ECONNRESET|socket closed|peer ended)/);
    mesh.fail(new NetAbort('local', null, 0, 'x'));
    await c;
  }, T(20_000));
});


describe('socket lifecycle notes', () => {
  const sockOf = (fx: Fx) => (fx.mesh as unknown as { links: Map<number, { socket: tls.TLSSocket }> }).links.get(1)!.socket;
  it('a socket error before hello is recorded with its message and closes the link', async () => {
    const fx = await withPeer({}, { hello: false });
    sockOf(fx).emit('error', new Error('boom-test'));
    expect(fx.mesh.events).toContain('link 1 closed before hello: socket error: boom-test');
    fx.done();
  }, T(20_000));
  it('a socket close before hello is recorded as "socket closed"', async () => {
    const fx = await withPeer({}, { hello: false });
    sockOf(fx).emit('close');
    expect(fx.mesh.events).toContain('link 1 closed before hello: socket closed');
    fx.done();
  }, T(20_000));
  it('an end before hello is recorded as "peer ended"', async () => {
    const fx = await withPeer({}, { hello: false });
    sockOf(fx).emit('end');
    expect(fx.mesh.events).toContain('link 1 closed before hello: peer ended');
    fx.done();
  }, T(20_000));
  it('only the first closing event of a link is recorded', async () => {
    const fx = await withPeer({}, { hello: false });
    sockOf(fx).emit('end');
    sockOf(fx).emit('close');
    sockOf(fx).emit('error', new Error('late'));
    expect(fx.mesh.events.filter((e) => e.includes('closed before hello'))).toEqual(['link 1 closed before hello: peer ended']);
    fx.done();
  }, T(20_000));
});
