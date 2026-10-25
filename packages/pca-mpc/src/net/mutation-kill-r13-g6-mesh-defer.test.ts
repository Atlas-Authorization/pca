/**
 * The mesh's deferred abort claims (setDeferAborts): with deferral on, a peer's abort frame is queued behind the frames it
 * sent before, so the blame round can collect every party's blame data even when a fast party (the cheater in particular)
 * has already aborted. Scripted raw peers against a real TLS mesh.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as tls from 'node:tls';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { generateIdentity, readPem } from './certs';
import { Mesh, type MeshConfig, type NodeAddr } from './mesh';
import { ManualClock, T, reservePorts, until, waitListening } from './test-timing';
import { FrameSplitter, NetAbort, WIRE_VERSION, encodeFrame, parseFrame, type Frame } from './wire';

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
const inboxLen = (fx: Fx): number => (fx.mesh as unknown as { links: Map<number, { inbox: unknown[] }> }).links.get(1)!.inbox.length;
/** Wait until the two frames sent were either acted on (mesh failed) or both queued, whichever this mesh does; never hangs. */
const settled = (fx: Fx): Promise<unknown> => until(() => fx.mesh.failed !== null || inboxLen(fx) === 2, 'the abort frame to be acted on or queued');


describe('deferred abort claims (Mesh.setDeferAborts, used by the blame round)', () => {
  it('off (default): an abort frame poisons the mesh on arrival, even with an earlier message still unread', async () => {
    const fx = await withPeer();
    fx.peer.send('msg', 'blame', 'data');
    fx.peer.send('abort', 'abort', { kind: 'dealer', blamed: 2, detail: 'not me' });
    await settled(fx);
    const e = fx.mesh.failed;
    expect([e?.kind, e?.blamed, e?.claimedKind, e?.claimedBlame]).toEqual(['peer-abort', 1, 'dealer', 2]);
    expect(((await fx.mesh.recv(1, 'blame').catch((x) => x)) as NetAbort).kind).toBe('peer-abort');
    fx.done();
  }, T(20_000));
  it('on: the claim is read in link order, after the message the peer sent first; it then takes effect', async () => {
    const fx = await withPeer();
    fx.mesh.setDeferAborts(true);
    fx.peer.send('msg', 'blame', 'data');
    fx.peer.send('abort', 'abort', { kind: 'dealer', blamed: 2, detail: 'not me' });
    await settled(fx);
    expect(fx.mesh.failed).toBeNull();
    expect(inboxLen(fx)).toBe(2);
    expect(await fx.mesh.recv(1, 'blame')).toBe('data');
    expect(fx.mesh.failed).toBeNull();
    const e = (await fx.mesh.recv(1, 'next').catch((x) => x)) as NetAbort;
    expect([e.kind, e.blamed, e.reporter, e.claimedKind, e.claimedBlame]).toEqual(['peer-abort', 1, 0, 'dealer', 2]);
    expect(fx.mesh.failed).toBe(e);
    fx.done();
  }, T(20_000));
  it('on: an abort that arrives BEFORE the awaited message ends the receive at once (no wait for a message that never comes)', async () => {
    const fx = await withPeer();
    fx.mesh.setDeferAborts(true);
    fx.peer.send('abort', 'abort', { kind: 'dealer', blamed: 2, detail: '' });
    const e = (await fx.mesh.recv(1, 'blame').catch((x) => x)) as NetAbort;
    expect([e.kind, e.blamed, e.claimedBlame]).toEqual(['peer-abort', 1, 2]);
    fx.done();
  }, T(20_000));
  it('turning it off again restores immediate aborts for later frames', async () => {
    const fx = await withPeer();
    fx.mesh.setDeferAborts(true);
    fx.mesh.setDeferAborts(false);
    fx.peer.send('msg', 'blame', 'data');
    fx.peer.send('abort', 'abort', { kind: 'dealer', blamed: 2, detail: '' });
    await settled(fx);
    expect(fx.mesh.failed?.kind).toBe('peer-abort');
    fx.done();
  }, T(20_000));
});
