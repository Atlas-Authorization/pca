/**
 * Mesh behaviour that a real TLS network cannot provoke on demand (dial races, a late socket error, a link without a socket),
 * driven by injecting fake sockets into the mesh's own handlers. `node:tls` is mocked only so `connect` can be scripted.
 */
import { X509Certificate } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

const tlsHook = vi.hoisted(() => ({ connect: null as null | ((...a: unknown[]) => unknown) }));
vi.mock('node:tls', async (orig) => {
  const real = (await orig()) as typeof import('node:tls');
  return { ...real, default: real, connect: ((...a: unknown[]) => (tlsHook.connect ? tlsHook.connect(...a) : (real.connect as (...x: unknown[]) => unknown)(...a))) as typeof real.connect };
});

import { generateIdentity, readPem } from './certs';
import { Mesh, type NodeAddr } from './mesh';
import { ManualClock, reservePorts, until } from './test-timing';
import { NetAbort, WIRE_VERSION, encodeFrame } from './wire';

let dir: string;
let ids: Array<{ key: string; cert: string; fp: string }>;
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'pca-mesh-inject-'));
  ids = ['a', 'b', 'c'].map((n) => {
    const i = generateIdentity(join(dir, n), n);
    const cert = readPem(i.certPath);
    return { key: readPem(i.keyPath), cert, fp: new X509Certificate(cert).fingerprint256 };
  });
});
afterAll(() => {
  tlsHook.connect = null;
  rmSync(dir, { recursive: true, force: true });
});

const SID = 's';
const nodes = (ports = [1, 2, 3]): NodeAddr[] => ids.map((x, i) => ({ id: i, host: '127.0.0.1', port: ports[i]!, certPem: x.cert }));

/** A scriptable stand-in for a TLSSocket: records writes, destroys, pauses and resumes. */
class FakeSock extends EventEmitter {
  authorized = true;
  destroyed = false;
  writes: Buffer[] = [];
  calls: string[] = [];
  bytesWritten = 0;
  bytesRead = 0;
  constructor(private fp: string | undefined) {
    super();
  }
  getPeerCertificate(): { fingerprint256?: string } {
    return this.fp === undefined ? {} : { fingerprint256: this.fp };
  }
  setNoDelay(v: boolean): void {
    this.calls.push(`noDelay:${v}`);
  }
  write(b: Buffer): boolean {
    this.writes.push(b);
    return true;
  }
  destroy(): void {
    this.calls.push('destroy');
    this.destroyed = true;
  }
  end(): void {
    this.calls.push('end');
  }
  pause(): void {
    this.calls.push('pause');
  }
  resume(): void {
    this.calls.push('resume');
  }
}

type Priv = {
  dial: (id: number, deadline: number) => Promise<void>;
  onIncoming: (s: unknown) => void;
  attach: (id: number, s: unknown) => void;
  onData: (l: unknown, chunk: Buffer) => void;
  links: Map<number, { id: number; socket: unknown; paused: boolean; inbox: unknown[]; inboxBytes: number; helloSeen: boolean; closed: boolean; sendSeq: number }>;
  server: EventEmitter | null;
};
const priv = (m: Mesh): Priv => m as unknown as Priv;
const mk = (selfId: number, linkTo: number[], extra: Partial<ConstructorParameters<typeof Mesh>[0]> = {}) =>
  new Mesh({ selfId, nodes: nodes(), linkTo, keyPem: ids[selfId]!.key, certPem: ids[selfId]!.cert, sessionId: SID, clock: new ManualClock(), ...extra });
const frame = (ty: 'hello' | 'msg', seq: number, rd: string, d: unknown): Buffer => encodeFrame({ v: WIRE_VERSION, ty, sid: SID, seq, rd, d });

describe('TLS client errors are recorded capped at 120 characters', () => {
  it('a long error message is cut to its first 120 characters', async () => {
    const [p] = await reservePorts(1);
    const m = new Mesh({ selfId: 0, nodes: [{ id: 0, host: '127.0.0.1', port: p!, certPem: ids[0]!.cert }], linkTo: [], keyPem: ids[0]!.key, certPem: ids[0]!.cert, sessionId: SID, listenHost: '127.0.0.1' });
    await m.connect();
    const long = 'E'.repeat(119) + 'XYZ' + 'F'.repeat(200);
    priv(m).server!.emit('tlsClientError', new Error(long));
    expect(m.events).toEqual([`tlsClientError: ${long.slice(0, 120)}`]);
    expect(m.events[0]!.endsWith('EX')).toBe(true);
    m.fail(new NetAbort('local', null, 0, 'done'));
  });
});

describe('dial loop (scripted tls.connect)', () => {
  afterAll(() => {
    tlsHook.connect = null;
  });
  it('does not dial at all once the deadline has been reached (now === deadline included)', async () => {
    const m = mk(1, [0]);
    const clock = new ManualClock();
    (m as unknown as { clock: ManualClock }).clock = clock;
    clock.advance(1000);
    let calls = 0;
    tlsHook.connect = () => {
      calls++;
      if (calls >= 2) m.fail(new NetAbort('local', null, 1, 'stop'));
      const s = new FakeSock(undefined);
      queueMicrotask(() => s.emit('error', new Error('refused')));
      return s;
    };
    await priv(m).dial(0, 1000);
    expect(calls).toBe(0);
  });
  it('a connect error before the handshake destroys that socket and retries (paced)', async () => {
    const m = mk(1, [0]);
    const socks: FakeSock[] = [];
    tlsHook.connect = () => {
      const s = new FakeSock(undefined);
      socks.push(s);
      if (socks.length >= 2) m.fail(new NetAbort('local', null, 1, 'stop'));
      queueMicrotask(() => s.emit('error', new Error('refused')));
      return s;
    };
    await priv(m).dial(0, Number.MAX_SAFE_INTEGER);
    expect(socks.length).toBe(2);
    for (const s of socks) expect(s.calls).toEqual(['destroy']);
  });
  it('after a successful handshake the dial returns at once and a later socket error does not destroy from the dial handler', async () => {
    const m = mk(1, [0]);
    const socks: FakeSock[] = [];
    tlsHook.connect = () => {
      const s = new FakeSock(ids[0]!.fp);
      socks.push(s);
      if (socks.length >= 2) {
        m.fail(new NetAbort('local', null, 1, 'stop'));
        queueMicrotask(() => s.emit('error', new Error('again')));
      } else {
        queueMicrotask(() => s.emit('secureConnect'));
      }
      return s;
    };
    await priv(m).dial(0, Number.MAX_SAFE_INTEGER);
    expect(socks.length).toBe(1);
    const s = socks[0]!;
    expect(priv(m).links.get(0)!.socket).toBe(s);
    expect(s.calls).toEqual(['noDelay:true']);
    expect(s.writes.length).toBe(1); // the hello frame
    s.emit('error', new Error('late'));
    expect(s.calls).toEqual(['noDelay:true']);
    expect(priv(m).links.get(0)!.closed).toBe(true);
  });
});

describe('incoming / attach handlers', () => {
  it('a rejected incoming socket swallows a later error event', () => {
    const m = mk(0, [1]);
    const s = new FakeSock(undefined);
    s.authorized = false;
    priv(m).onIncoming(s);
    expect(s.destroyed).toBe(true);
    expect(() => s.emit('error', new Error('reset'))).not.toThrow();
    expect(m.events).toEqual(['rejected incoming connection (fp=none)']);
  });
  it('attach turns Nagle off and refuses a second socket for the same link', () => {
    const m = mk(0, [1]);
    const a = new FakeSock(ids[1]!.fp);
    const b = new FakeSock(ids[1]!.fp);
    priv(m).attach(1, a);
    expect(a.calls).toEqual(['noDelay:true']);
    priv(m).attach(1, b);
    expect(b.calls).toEqual(['destroy']);
    expect(priv(m).links.get(1)!.socket).toBe(a);
  });
});

describe('a link without a socket', () => {
  it('flow control tolerates a missing socket when pausing and resuming', async () => {
    const m = mk(0, [1], { maxInboxFrames: 2 });
    const l = priv(m).links.get(1)!;
    expect(l.socket).toBeNull();
    priv(m).onData(l, Buffer.concat([frame('hello', 0, 'hello', { id: 1 }), frame('msg', 1, 'r', 1), frame('msg', 2, 'r', 2)]));
    expect(l.inbox.length).toBe(2);
    expect(l.paused).toBe(true);
    expect(m.failed).toBeNull();
    expect(await m.recv(1, 'r')).toBe(1);
    expect(l.paused).toBe(false);
    expect(await m.recv(1, 'r')).toBe(2);
  });
  it('fail() sends abort frames only on live links: not to a link without a socket, nor to a destroyed socket', () => {
    const m = mk(0, [1, 2]);
    const l1 = priv(m).links.get(1)!;
    const l2 = priv(m).links.get(2)!;
    const dead = new FakeSock(ids[2]!.fp);
    dead.destroyed = true;
    l2.socket = dead;
    const live = mk(0, [1]);
    const ls = new FakeSock(ids[1]!.fp);
    priv(live).links.get(1)!.socket = ls;
    m.fail(new NetAbort('local', null, 0, 'x'));
    live.fail(new NetAbort('local', null, 0, 'x'));
    expect(l1.sendSeq).toBe(0);
    expect(l2.sendSeq).toBe(0);
    expect(dead.writes).toEqual([]);
    expect(ls.writes.length).toBe(1);
    expect(priv(live).links.get(1)!.sendSeq).toBe(1);
  });
  it('fail() wakes a pending receive immediately (nothing else would: there is no socket to close)', async () => {
    const m = mk(0, [1]);
    const clock = (m as unknown as { clock: ManualClock }).clock;
    const p = m.recv(1, 'x');
    await until(() => clock.pending === 1, 'the receive to register its timer');
    const e = new NetAbort('local', null, 0, 'boom');
    m.fail(e);
    await expect(p).rejects.toBe(e);
  }, 5000);
});
