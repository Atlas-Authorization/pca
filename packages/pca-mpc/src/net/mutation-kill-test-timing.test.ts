import * as net from 'node:net';
import { describe, expect, it, vi } from 'vitest';
import { ManualClock, T, TIMEOUT_SCALE, reservePorts, until, waitListening } from './test-timing';

describe('T / TIMEOUT_SCALE', () => {
  it('scales and rounds up; scale defaults to a positive finite number', () => {
    expect(Number.isFinite(TIMEOUT_SCALE)).toBe(true);
    expect(TIMEOUT_SCALE).toBeGreaterThan(0);
    expect(T(0)).toBe(0);
    expect(T(1000)).toBe(Math.ceil(1000 * TIMEOUT_SCALE));
    expect(T(3)).toBe(Math.ceil(3 * TIMEOUT_SCALE));
  });
  it('honours MPC_TEST_TIMEOUT_SCALE when set to a positive finite number, else 1', async () => {
    const name = 'PCA_MPC_TEST_TIMEOUT_SCALE';
    const old = process.env[name];
    try {
      for (const [val, want] of [['2.5', 2.5], ['0', 1], ['-3', 1], ['abc', 1], ['Infinity', 1], ['', 1], ['0.5', 0.5]] as const) {
        process.env[name] = val;
        vi.resetModules();
        const mod = await import('./test-timing');
        expect(mod.TIMEOUT_SCALE).toBe(want);
        expect(mod.T(10)).toBe(Math.ceil(10 * want));
      }
      delete process.env[name];
      vi.resetModules();
      expect((await import('./test-timing')).TIMEOUT_SCALE).toBe(1);
    } finally {
      if (old === undefined) delete process.env[name];
      else process.env[name] = old;
      vi.resetModules();
    }
  });
});

describe('until', () => {
  it('resolves with the truthy value, polling a sync or async condition', async () => {
    let n = 0;
    expect(await until(() => (++n >= 3 ? 'ok' : ''), 'x')).toBe('ok');
    expect(n).toBe(3);
    let m = 0;
    expect(await until(async () => (++m >= 2 ? 42 : 0), 'x')).toBe(42);
    expect(await until(() => [] as unknown[], 'x')).toEqual([]);
  });
  it('rejects with the description after the (scaled) deadline', async () => {
    const t0 = Date.now();
    await expect(until(() => false, 'the thing', 120)).rejects.toThrow('timed out waiting for: the thing');
    const dt = Date.now() - t0;
    expect(dt).toBeGreaterThanOrEqual(100);
    expect(dt).toBeLessThan(2000);
  });
  it('checks the condition at least once even when it is already true, and does not wait', async () => {
    const t0 = Date.now();
    expect(await until(() => 1, 'x', 5000)).toBe(1);
    expect(Date.now() - t0).toBeLessThan(500);
  });
});

describe('reservePorts / waitListening', () => {
  it('returns the requested number of distinct, free loopback ports', async () => {
    const ports = await reservePorts(4);
    expect(ports.length).toBe(4);
    expect(new Set(ports).size).toBe(4);
    for (const p of ports) {
      expect(Number.isInteger(p)).toBe(true);
      expect(p).toBeGreaterThan(0);
      await new Promise<void>((res, rej) => {
        const s = net.createServer();
        s.once('error', rej);
        s.listen(p, '127.0.0.1', () => s.close(() => res()));
      });
    }
    expect(await reservePorts(0)).toEqual([]);
  });
  it('waitListening resolves true once something accepts, and rejects otherwise', async () => {
    const [p] = await reservePorts(1);
    const pending = waitListening(p!, '127.0.0.1', 5000);
    await new Promise((r) => setTimeout(r, 120));
    const srv = net.createServer();
    await new Promise<void>((r) => srv.listen(p!, '127.0.0.1', () => r()));
    expect(await pending).toBe(true);
    srv.close();
    const [q] = await reservePorts(1);
    await expect(waitListening(q!, '127.0.0.1', 300)).rejects.toThrow();
    const [r] = await reservePorts(1);
    const srv2 = net.createServer();
    await new Promise<void>((res) => srv2.listen(r!, '127.0.0.1', () => res()));
    expect(await waitListening(r!)).toBe(true); // default host is loopback
    srv2.close();
  });
});

describe('ManualClock', () => {
  it('time stands still until advanced', () => {
    const c = new ManualClock();
    expect(c.now()).toBe(0);
    c.advance(0);
    expect(c.now()).toBe(0);
    c.advance(250);
    expect(c.now()).toBe(250);
    c.advance(1);
    expect(c.now()).toBe(251);
  });
  it('fires timers whose due time falls inside the advance, earliest first, with now() set to the due time', () => {
    const c = new ManualClock();
    const log: Array<[string, number]> = [];
    c.setTimer(() => log.push(['b', c.now()]), 200);
    c.setTimer(() => log.push(['a', c.now()]), 100);
    c.setTimer(() => log.push(['late', c.now()]), 1001);
    expect(c.pending).toBe(3);
    c.advance(1000);
    expect(log).toEqual([['a', 100], ['b', 200]]);
    expect(c.now()).toBe(1000);
    expect(c.pending).toBe(1);
    c.advance(1);
    expect(log[2]).toEqual(['late', 1001]);
    expect(c.pending).toBe(0);
  });
  it('timers fire in due order whatever the insertion order, and equal due times fire in insertion order', () => {
    const c = new ManualClock();
    const log: string[] = [];
    c.setTimer(() => log.push('a100'), 100);
    c.setTimer(() => log.push('b200'), 200);
    c.setTimer(() => log.push('c150'), 150);
    c.setTimer(() => log.push('d150'), 150);
    c.setTimer(() => log.push('e50'), 50);
    c.advance(1000);
    expect(log).toEqual(['e50', 'a100', 'c150', 'd150', 'b200']);
  });
  it('a timer due exactly at the target fires; one due after does not; zero-delay timers fire on the next advance', () => {
    const c = new ManualClock();
    let hit = 0;
    c.setTimer(() => hit++, 10);
    c.advance(9);
    expect(hit).toBe(0);
    c.advance(1);
    expect(hit).toBe(1);
    c.setTimer(() => hit++, 0);
    expect(hit).toBe(1);
    c.advance(0);
    expect(hit).toBe(2);
  });
  it('timers are relative to the current virtual time and a cleared timer never fires', () => {
    const c = new ManualClock();
    c.advance(500);
    let a = 0, b = 0;
    c.setTimer(() => a++, 100);
    const h = c.setTimer(() => b++, 100);
    c.clearTimer(h);
    expect(c.pending).toBe(1);
    c.advance(99);
    expect(a).toBe(0);
    c.advance(1);
    expect(a).toBe(1);
    expect(b).toBe(0);
    c.clearTimer(12345); // unknown handles are ignored
  });
  it('a timer set by a firing timer inside the same advance also fires if due; time never goes backwards', () => {
    const c = new ManualClock();
    const log: number[] = [];
    c.setTimer(() => {
      log.push(c.now());
      c.setTimer(() => log.push(c.now()), 50);
    }, 100);
    c.advance(200);
    expect(log).toEqual([100, 150]);
    expect(c.now()).toBe(200);
    const d = new ManualClock();
    d.advance(100);
    d.setTimer(() => undefined, 0); // due now (== 100), earlier than target
    d.advance(10);
    expect(d.now()).toBe(110);
  });
  it('handles are distinct and increasing', () => {
    const c = new ManualClock();
    const a = c.setTimer(() => undefined, 1) as number;
    const b = c.setTimer(() => undefined, 1) as number;
    expect(b).toBeGreaterThan(a);
    expect(a).toBeGreaterThan(0);
  });
});
