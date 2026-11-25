/** test-timing helpers with `node:net` scripted, so host defaults, listen failures and the exact deadline are observable. */
import { EventEmitter } from 'node:events';
import { afterEach, describe, expect, it, vi } from 'vitest';

const netHook = vi.hoisted(() => ({
  connects: [] as unknown[][],
  listens: [] as unknown[][],
  failListen: false,
}));
vi.mock('node:net', async (orig) => {
  const real = (await orig()) as typeof import('node:net');
  return {
    ...real,
    default: real,
    connect: ((...a: unknown[]) => {
      netHook.connects.push(a);
      return (real.connect as (...x: unknown[]) => unknown)(...a);
    }) as typeof real.connect,
    createServer: ((...a: unknown[]) => {
      const s = (real.createServer as (...x: unknown[]) => import('node:net').Server)(...a);
      const listen = s.listen.bind(s) as (...x: unknown[]) => unknown;
      (s as unknown as { listen: (...x: unknown[]) => unknown }).listen = (...x: unknown[]) => {
        netHook.listens.push(x);
        if (netHook.failListen) {
          queueMicrotask(() => (s as unknown as EventEmitter).emit('error', new Error('EACCES: scripted listen failure')));
          return s;
        }
        return listen(...x);
      };
      return s;
    }) as typeof real.createServer,
  };
});
import * as net from 'node:net';
import { T, until, waitListening } from './test-timing';

afterEach(() => {
  netHook.connects.length = 0;
  netHook.listens.length = 0;
  netHook.failListen = false;
  vi.restoreAllMocks();
});

describe('loopback defaults', () => {
  it('waitListening connects to 127.0.0.1 by default', async () => {
    const srv = net.createServer();
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
    const port = (srv.address() as net.AddressInfo).port;
    expect(await waitListening(port)).toBe(true);
    expect(netHook.connects.some((a) => JSON.stringify(a[0]) === JSON.stringify({ port, host: '127.0.0.1' }))).toBe(true);
    srv.close();
  });
});

describe('until deadline (scripted clock)', () => {
  it('a poll that lands exactly on the deadline polls once more before giving up', async () => {
    const times = [1000, 1000 + T(120), 1000 + T(120) + 1];
    vi.spyOn(Date, 'now').mockImplementation(() => times.shift() ?? 99_999);
    let calls = 0;
    await expect(until(() => (calls++, false), 'never', 120)).rejects.toThrow('timed out waiting for: never');
    expect(calls).toBe(2);
  });
});
