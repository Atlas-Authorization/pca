import { EventEmitter } from 'node:events';
import { afterEach, describe, expect, it, vi } from 'vitest';

const netHook = vi.hoisted(() => ({ connect: null as null | ((...a: unknown[]) => unknown) }));
vi.mock('node:net', async (orig) => {
  const real = (await orig()) as typeof import('node:net');
  return { ...real, default: real, connect: ((...a: unknown[]) => (netHook.connect ? netHook.connect(...a) : (real.connect as (...x: unknown[]) => unknown)(...a))) as typeof real.connect };
});
import * as net from 'node:net';
import { FaultProxy, type FrameFault, type WireFault, tamperFor } from './faults';
import type { TamperEvent } from './mesh';
import { type Frame, FrameSplitter, encodeFrame, parseFrame } from './wire';
import { reservePorts, until } from './test-timing';

const fr = (over: Partial<Frame> = {}): Frame => ({ v: 2, ty: 'msg', sid: 'sess', seq: 5, rd: 'mul0', d: { a: 1 }, ...over });
const ev = (to = 1, f: Frame = fr()): TamperEvent => ({ to, frame: f, raw: encodeFrame(f) });
const decode = (b: Buffer): Frame => {
  const s = new FrameSplitter();
  const [body] = s.push(b);
  return JSON.parse(body!.toString('utf8')) as Frame;
};

describe('tamperFor', () => {
  const kinds: FrameFault['kind'][] = ['duplicate', 'reorder', 'skip-seq', 'garbage', 'truncate', 'bitflip', 'wrong-round', 'wrong-session', 'oversize', 'drop', 'silent-from', 'extra-field', 'false-accuse'];
  it('frames of other rounds pass through untouched, for every kind', () => {
    for (const kind of kinds) {
      const t = tamperFor({ kind, round: 'mul0' });
      const e = ev(1, fr({ rd: 'other' }));
      const out = t(e);
      expect(out.length).toBe(1);
      expect(out[0]).toBe(e.raw);
    }
  });
  it('frames to other recipients pass through when the fault is restricted with `to`', () => {
    for (const kind of kinds) {
      const t = tamperFor({ kind, round: 'mul0', to: 2 });
      const e = ev(1);
      const out = t(e);
      expect(out).toEqual([e.raw]);
      expect(out[0]).toBe(e.raw);
    }
  });
  it('a matching `to` (including 0) applies the fault', () => {
    expect(tamperFor({ kind: 'drop', round: 'mul0', to: 0 })(ev(0))).toEqual([]);
    expect(tamperFor({ kind: 'drop', round: 'mul0', to: 3 })(ev(3))).toEqual([]);
    expect(tamperFor({ kind: 'drop', round: 'mul0', to: 3 })(ev(2)).length).toBe(1);
  });
  it('duplicate sends the same bytes twice', () => {
    const e = ev();
    const out = tamperFor({ kind: 'duplicate', round: 'mul0' })(e);
    expect(out.length).toBe(2);
    expect(out[0]).toBe(e.raw);
    expect(out[1]).toBe(e.raw);
  });
  it('skip-seq re-encodes with seq + 1', () => {
    const out = tamperFor({ kind: 'skip-seq', round: 'mul0' })(ev(1, fr({ seq: 9 })));
    expect(out.length).toBe(1);
    expect(decode(out[0]!)).toEqual(fr({ seq: 10 }));
  });
  it('garbage has the honest length and prefix but every body byte 0x5a', () => {
    const e = ev();
    const [g] = tamperFor({ kind: 'garbage', round: 'mul0' })(e);
    expect(g!.length).toBe(e.raw.length);
    expect(g!.readUInt32BE(0)).toBe(e.raw.length - 4);
    expect(g!.subarray(4).every((b) => b === 0x5a)).toBe(true);
    expect(parseFrame(g!.subarray(4))).toBeNull();
  });
  it('truncate keeps max(5, floor(len/2)) leading bytes', () => {
    const e = ev();
    const [t] = tamperFor({ kind: 'truncate', round: 'mul0' })(e);
    expect(t!.length).toBe(Math.floor(e.raw.length / 2));
    expect(t!.equals(e.raw.subarray(0, t!.length))).toBe(true);
    const tiny = Buffer.from([0, 0, 0, 2, 1, 2, 3]);
    const [s] = tamperFor({ kind: 'truncate', round: 'mul0' })({ to: 1, frame: fr(), raw: tiny });
    expect(s!.length).toBe(5);
    const [m] = tamperFor({ kind: 'truncate', round: 'mul0' })({ to: 1, frame: fr(), raw: Buffer.alloc(30, 7) });
    expect(m!.length).toBe(15);
    const [m2] = tamperFor({ kind: 'truncate', round: 'mul0' })({ to: 1, frame: fr(), raw: Buffer.alloc(31, 7) });
    expect(m2!.length).toBe(15);
  });
  it('bitflip flips exactly bit 2 of the byte at floor(0.6 * len), on a copy', () => {
    const e = ev();
    const orig = Buffer.from(e.raw);
    const [b] = tamperFor({ kind: 'bitflip', round: 'mul0' })(e);
    expect(e.raw.equals(orig)).toBe(true);
    const i = Math.floor(orig.length * 0.6);
    const diff = [...b!].map((x, k) => (x ^ orig[k]!) | 0).map((x, k) => [k, x]).filter(([, x]) => x !== 0);
    expect(diff).toEqual([[i, 0x04]]);
    expect(b!.length).toBe(orig.length);
  });
  it('wrong-round / wrong-session rewrite only that field', () => {
    const [r] = tamperFor({ kind: 'wrong-round', round: 'mul0' })(ev());
    expect(decode(r!)).toEqual(fr({ rd: 'zzz-mul0' }));
    const [s] = tamperFor({ kind: 'wrong-session', round: 'mul0' })(ev());
    expect(decode(s!)).toEqual(fr({ sid: 'not-this-session' }));
  });
  it('oversize is just a 4-byte prefix announcing 0x7fffffff bytes', () => {
    const out = tamperFor({ kind: 'oversize', round: 'mul0' })(ev());
    expect(out.length).toBe(1);
    expect(out[0]!.length).toBe(4);
    expect(out[0]!.readUInt32BE(0)).toBe(0x7fffffff);
  });
  it('drop returns nothing for each matching frame but stays per-frame', () => {
    const t = tamperFor({ kind: 'drop', round: 'mul0' });
    expect(t(ev())).toEqual([]);
    expect(t(ev(1, fr({ rd: 'x' }))).length).toBe(1);
    expect(t(ev())).toEqual([]);
  });
  it('silent-from drops the first hit and then EVERYTHING afterwards, whatever the round or recipient', () => {
    const t = tamperFor({ kind: 'silent-from', round: 'mul0', to: 1 });
    expect(t(ev(2, fr({ rd: 'a' }))).length).toBe(1);
    expect(t(ev(1, fr({ rd: 'a' }))).length).toBe(1);
    expect(t(ev(1))).toEqual([]);
    expect(t(ev(2, fr({ rd: 'a' })))).toEqual([]);
    expect(t(ev(1, fr({ rd: 'b' })))).toEqual([]);
    const fresh = tamperFor({ kind: 'silent-from', round: 'mul0' });
    expect(fresh(ev(1, fr({ rd: 'a' }))).length).toBe(1); // silence state is per tamperer
  });
  it('false-accuse replaces the frame with an abort frame naming `accuse` (default 0)', () => {
    const [a] = tamperFor({ kind: 'false-accuse', round: 'mul0', accuse: 3 })(ev());
    expect(decode(a!)).toEqual(fr({ ty: 'abort', rd: 'abort', d: { kind: 'timeout', blamed: 3, detail: 'forged accusation' } }));
    const [b] = tamperFor({ kind: 'false-accuse', round: 'mul0' })(ev());
    expect((decode(b!).d as { blamed: number }).blamed).toBe(0);
    const [c] = tamperFor({ kind: 'false-accuse', round: 'mul0', accuse: 0 })(ev());
    expect((decode(c!).d as { blamed: number }).blamed).toBe(0);
  });
  it('extra-field adds one unknown key to the envelope', () => {
    const [x] = tamperFor({ kind: 'extra-field', round: 'mul0' })(ev());
    expect(decode(x!)).toEqual({ ...fr(), x: 1 });
    expect(Object.keys(decode(x!)).length).toBe(7);
  });
  it('reorder holds the first matching frame per recipient and releases it AFTER the next frame to that recipient', () => {
    const t = tamperFor({ kind: 'reorder', round: 'mul0' });
    const a1 = ev(1, fr({ seq: 1 })), a2 = ev(1, fr({ seq: 2, rd: 'next' })), b1 = ev(2, fr({ seq: 1 })), b2 = ev(2, fr({ seq: 2, rd: 'next' }));
    expect(t(a1)).toEqual([]);
    expect(t(b1)).toEqual([]); // separate stash per recipient
    expect(t(ev(3, fr({ rd: 'other' })))[0]).toBeDefined(); // non-hit with nothing held passes
    const o1 = t(a2);
    expect(o1.length).toBe(2);
    expect(o1[0]).toBe(a2.raw);
    expect(o1[1]).toBe(a1.raw);
    const o2 = t(b2);
    expect(o2).toEqual([b2.raw, b1.raw]);
    const a3 = ev(1, fr({ seq: 3, rd: 'next' }));
    expect(t(a3)).toEqual([a3.raw]); // stash was emptied
    const h = ev(1, fr({ seq: 4 }));
    expect(t(h)).toEqual([]); // hit again: held again
  });
  it('reorder with a `to` restriction only holds frames to that recipient', () => {
    const t = tamperFor({ kind: 'reorder', round: 'mul0', to: 2 });
    const x = ev(1);
    expect(t(x)).toEqual([x.raw]);
    expect(t(ev(2))).toEqual([]);
  });
});

// ----------------------------------------------------------------------------- FaultProxy

const B = (...n: number[]): Buffer => Buffer.from(n);

/** Source side of a pipe: the test emits 'data' and 'end' by hand. */
class Src extends EventEmitter {}
/** Destination side of a pipe: records what the proxy writes and whether it ends it. */
class Dst extends EventEmitter {
  destroyed = false;
  writes: number[][] = [];
  ended = 0;
  destroys = 0;
  write(b: Buffer): boolean {
    this.writes.push([...b]);
    return true;
  }
  end(): void {
    this.ended++;
  }
  destroy(): void {
    this.destroys++;
    this.destroyed = true;
  }
}
type Pipe = (from: Src, to: Dst, dir: 'c2s' | 's2c') => void;
const piped = (fault: WireFault, dir: 'c2s' | 's2c' = fault.dir) => {
  const proxy = new FaultProxy(0, { host: '127.0.0.1', port: 1 }, fault);
  const src = new Src();
  const dst = new Dst();
  ((proxy as unknown as { pipe: Pipe }).pipe).call(proxy, src, dst, dir);
  return { proxy, src, dst, send: (...chunks: Buffer[]) => chunks.forEach((c) => src.emit('data', c)) };
};

afterEach(() => {
  vi.useRealTimers();
  netHook.connect = null;
});

describe('FaultProxy byte-level faults (driven through the pipe)', () => {
  it('kind none passes everything through and logs nothing', () => {
    const { dst, send, proxy } = piped({ kind: 'none', dir: 'c2s', afterBytes: 0 });
    send(B(1, 2, 3), B(4));
    expect(dst.writes).toEqual([[1, 2, 3], [4]]);
    expect(proxy.log).toEqual([]);
  });
  it('a fault configured for one direction leaves the other direction alone', () => {
    const { dst, send, proxy } = piped({ kind: 'drop', dir: 'c2s', afterBytes: 0 }, 's2c');
    send(B(7, 7));
    expect(dst.writes).toEqual([[7, 7]]);
    expect(proxy.log).toEqual([]);
  });
  it('drop: bytes up to afterBytes pass (a chunk ending exactly at afterBytes too), then a black hole forever', () => {
    vi.useFakeTimers();
    const a = piped({ kind: 'drop', dir: 'c2s', afterBytes: 3 });
    a.send(B(1, 2, 3), B(4, 5), B(6, 7));
    vi.advanceTimersByTime(10_000);
    expect(a.dst.writes).toEqual([[1, 2, 3]]);
    expect(a.proxy.log).toEqual(['fault drop c2s after 3B']);
    const b = piped({ kind: 'drop', dir: 's2c', afterBytes: 2 });
    b.send(B(1, 2, 3), B(4));
    vi.advanceTimersByTime(10_000);
    expect(b.dst.writes).toEqual([]); // the straddling chunk is faulted whole
    expect(b.proxy.log).toEqual(['fault drop s2c after 2B']);
  });
  it('delay: the faulted chunks arrive after exactly ms, in order; earlier ones at once', () => {
    vi.useFakeTimers();
    const { dst, send, proxy } = piped({ kind: 'delay', dir: 'c2s', afterBytes: 2, ms: 300 });
    send(B(1, 2), B(3, 4), B(5));
    expect(dst.writes).toEqual([[1, 2]]);
    vi.advanceTimersByTime(299);
    expect(dst.writes).toEqual([[1, 2]]);
    vi.advanceTimersByTime(1);
    expect(dst.writes).toEqual([[1, 2], [3, 4], [5]]);
    expect(proxy.log).toEqual(['fault delay c2s after 2B']);
    expect(dst.ended).toBe(0); // the source has not ended: the destination stays open
  });
  it('delay defaults to one second', () => {
    vi.useFakeTimers();
    const { dst, send } = piped({ kind: 'delay', dir: 'c2s', afterBytes: 0 });
    send(B(9));
    vi.advanceTimersByTime(999);
    expect(dst.writes).toEqual([]);
    vi.advanceTimersByTime(1);
    expect(dst.writes).toEqual([[9]]);
  });
  it('delay: a source end while writes are pending ends the destination only after the last delayed write', () => {
    vi.useFakeTimers();
    const { dst, send, src } = piped({ kind: 'delay', dir: 'c2s', afterBytes: 0, ms: 100 });
    send(B(1));
    vi.advanceTimersByTime(50);
    send(B(2));
    src.emit('end');
    expect(dst.ended).toBe(0);
    vi.advanceTimersByTime(50);
    expect(dst.writes).toEqual([[1]]);
    expect(dst.ended).toBe(0);
    vi.advanceTimersByTime(50);
    expect(dst.writes).toEqual([[1], [2]]);
    expect(dst.ended).toBe(1);
  });
  it('delay: nothing is written to a destination destroyed in the meantime', () => {
    vi.useFakeTimers();
    const { dst, send } = piped({ kind: 'delay', dir: 'c2s', afterBytes: 0, ms: 100 });
    send(B(1));
    dst.destroyed = true;
    vi.advanceTimersByTime(100);
    expect(dst.writes).toEqual([]);
  });
  it('a source end with nothing pending ends the destination at once', () => {
    const { dst, src } = piped({ kind: 'delay', dir: 'c2s', afterBytes: 0, ms: 100 });
    src.emit('end');
    expect(dst.ended).toBe(1);
  });
  it('truncate: the straddling chunk is cut to floor(len/2) and the destination ended once; later chunks pass unfaulted', () => {
    const { dst, send, proxy } = piped({ kind: 'truncate', dir: 'c2s', afterBytes: 2 });
    send(B(1, 2), B(3, 4, 5, 6, 7), B(8, 9));
    expect(dst.writes).toEqual([[1, 2], [3, 4], [8, 9]]);
    expect(dst.ended).toBe(1);
    expect(proxy.log).toEqual(['fault truncate c2s after 2B']);
  });
  it('bitflip: bit 0 of the middle byte of the straddling chunk, once, on a copy', () => {
    const { dst, send } = piped({ kind: 'bitflip', dir: 'c2s', afterBytes: 1 });
    const c = B(10, 20, 30, 40);
    send(B(0), c, B(50, 60));
    expect(dst.writes).toEqual([[0], [10, 20, 31, 40], [50, 60]]);
    expect([...c]).toEqual([10, 20, 30, 40]);
    const odd = piped({ kind: 'bitflip', dir: 'c2s', afterBytes: 0 });
    odd.send(B(4, 4, 4, 4, 4));
    expect(odd.dst.writes).toEqual([[4, 4, 5, 4, 4]]);
  });
  it('duplicate: the straddling chunk twice, once only', () => {
    const { dst, send } = piped({ kind: 'duplicate', dir: 'c2s', afterBytes: 1 });
    send(B(0), B(1, 2), B(3));
    expect(dst.writes).toEqual([[0], [1, 2], [1, 2], [3]]);
  });
  it('reorder: one swap, then everything passes in order; a chunk still held is flushed when the source ends', () => {
    const a = piped({ kind: 'reorder', dir: 'c2s', afterBytes: 1 });
    a.send(B(0), B(1, 2), B(3, 4), B(5), B(6));
    expect(a.dst.writes).toEqual([[0], [3, 4], [1, 2], [5], [6]]);
    const b = piped({ kind: 'reorder', dir: 'c2s', afterBytes: 1 });
    b.send(B(0), B(1, 2));
    expect(b.dst.writes).toEqual([[0]]);
    b.src.emit('end');
    expect(b.dst.writes).toEqual([[0], [1, 2]]);
    expect(b.dst.ended).toBe(1);
  });
  it('an unknown fault kind just forwards the chunk', () => {
    const { dst, send } = piped({ kind: 'bogus' as never, dir: 'c2s', afterBytes: 0 });
    send(B(1, 2));
    expect(dst.writes).toEqual([[1, 2]]);
  });
});

describe('FaultProxy connection lifecycle (scripted upstream)', () => {
  const wire = (fault: WireFault = { kind: 'none', dir: 'c2s', afterBytes: 0 }) => {
    let up: Dst | null = null;
    netHook.connect = () => (up = new Dst());
    const proxy = new FaultProxy(0, { host: '127.0.0.1', port: 1 }, fault);
    const c = new Dst();
    (proxy as unknown as { onClient: (c: unknown) => void }).onClient(c);
    return { c, up: up! };
  };
  it('a client error or close destroys the upstream at once', () => {
    const a = wire();
    a.c.emit('error', new Error('reset'));
    expect(a.up.destroys).toBe(1);
    const b = wire();
    b.c.emit('close');
    expect(b.up.destroys).toBe(1);
  });
  it('client bytes travel c2s to the upstream and upstream bytes s2c to the client', () => {
    const a = wire({ kind: 'drop', dir: 'c2s', afterBytes: 0 });
    a.c.emit('data', B(1));
    a.up.emit('data', B(2));
    expect(a.up.writes).toEqual([]);
    expect(a.c.writes).toEqual([[2]]);
    const b = wire({ kind: 'drop', dir: 's2c', afterBytes: 0 });
    b.c.emit('data', B(1));
    b.up.emit('data', B(2));
    expect(b.up.writes).toEqual([[1]]);
    expect(b.c.writes).toEqual([]);
  });
  it('an upstream error or close destroys the client at once', () => {
    const a = wire();
    a.up.emit('error', new Error('refused'));
    expect(a.c.destroys).toBe(1);
    const b = wire();
    b.up.emit('close');
    expect(b.c.destroys).toBe(1);
  });
});

describe('FaultProxy over real sockets', () => {
  it('kind none relays both directions', async () => {
    const [pp, tp] = await reservePorts(2);
    const got: number[] = [];
    const back: number[] = [];
    const server = net.createServer((s) => {
      s.on('data', (d) => got.push(...d));
      s.write(B(9, 8));
    });
    await new Promise<void>((r) => server.listen(tp, '127.0.0.1', () => r()));
    const proxy = new FaultProxy(pp!, { host: '127.0.0.1', port: tp! }, { kind: 'none', dir: 'c2s', afterBytes: 0 });
    await proxy.listen();
    const client = net.connect(pp!, '127.0.0.1');
    client.on('data', (d) => back.push(...d));
    client.write(B(1, 2, 3));
    await until(() => got.length === 3 && back.length === 2, 'both directions relayed');
    expect(got).toEqual([1, 2, 3]);
    expect(back).toEqual([9, 8]);
    client.destroy();
    proxy.close();
    server.close();
  });
  it('listen() rejects when the port is taken; close() stops accepting; it listens on loopback only', async () => {
    const [pp, tp] = await reservePorts(2);
    const p = new FaultProxy(pp!, { host: '127.0.0.1', port: tp! }, { kind: 'none', dir: 'c2s', afterBytes: 0 });
    await p.listen();
    expect(((p as unknown as { server: net.Server }).server.address() as net.AddressInfo).address).toBe('127.0.0.1');
    const p2 = new FaultProxy(pp!, { host: '127.0.0.1', port: tp! }, { kind: 'none', dir: 'c2s', afterBytes: 0 });
    await expect(p2.listen()).rejects.toThrow(/EADDRINUSE/);
    const closed = new Promise<void>((r) => (p as unknown as { server: net.Server }).server.once('close', () => r()));
    p.close();
    await closed;
    await expect(
      new Promise((res, rej) => {
        const c = net.connect(pp!, '127.0.0.1');
        c.on('connect', () => res('connected'));
        c.on('error', rej);
      }),
    ).rejects.toThrow(/ECONNREFUSED/);
  });
  it('an upstream that refuses the connection closes the client side', async () => {
    const [pp, tp] = await reservePorts(2);
    const p = new FaultProxy(pp!, { host: '127.0.0.1', port: tp! }, { kind: 'none', dir: 'c2s', afterBytes: 0 });
    await p.listen();
    await new Promise<void>((res) => {
      const c = net.connect(pp!, '127.0.0.1');
      c.on('error', () => undefined);
      c.on('close', () => res());
    });
    p.close();
  });
});
