/**
 * In-process kills for the delaying FaultProxy's close handling (faults.ts): bytes the sender wrote before it closed are
 * delivered after their delay, in order, and only then is the destination torn down (ended AND destroyed, so a half-open
 * target still sees the connection close). Everything runs in this process: a local target server, the proxy, a client.
 */
import * as net from 'node:net';
import { describe, expect, it } from 'vitest';
import { FaultProxy } from './faults';
import { freePort } from './launch-local';
import { until } from './test-timing';

describe('FaultProxy delay: a sender close waits for the delayed bytes', () => {
  it('two delayed chunks arrive in order before the close, and the destination is then destroyed', async () => {
    const events: string[] = [];
    let got = '';
    // allowHalfOpen: the target does not end its side by itself, so it only sees 'close' if the proxy DESTROYS the upstream
    // (its probe writes are then reset)
    const target = net.createServer({ allowHalfOpen: true }, (s) => {
      s.on('data', (d) => {
        got += d.toString();
        events.push(`data:${got}`);
      });
      s.on('end', () => {
        events.push('end');
        // probe the upstream: writing to a destroyed peer resets the connection (error + close); a merely half-closed
        // (ended, not destroyed) upstream keeps accepting, so the target never closes
        s.write('x');
        setTimeout(() => s.writable && s.write('y'), 100);
        setTimeout(() => s.writable && s.write('z'), 300);
      });
      s.on('close', () => events.push('close'));
      s.on('error', () => events.push('error'));
    });
    await new Promise<void>((r) => target.listen(0, '127.0.0.1', () => r()));
    const tport = (target.address() as net.AddressInfo).port;
    const proxy = new FaultProxy(await freePort(), { host: '127.0.0.1', port: tport }, { kind: 'delay', dir: 'c2s', afterBytes: 0, ms: 300 });
    await proxy.listen();
    try {
      const client = net.connect(proxy.listenPort, '127.0.0.1');
      client.on('error', () => undefined);
      await new Promise<void>((r) => client.once('connect', () => r()));
      client.write('a');
      await new Promise((r) => setTimeout(r, 60)); // a separate chunk (and a separate delay timer)
      client.write('b');
      await new Promise((r) => setTimeout(r, 60));
      client.end();
      // without a destroy the half-open target never closes: wait a bounded time, then let the assertion report it
      await until(() => events.includes('close'), 'the target connection to close', 3_000).catch(() => undefined);
      expect(got).toBe('ab');
      expect(events.slice(0, 3)).toEqual(['data:a', 'data:ab', 'end']);
      expect(events.includes('close')).toBe(true);
    } finally {
      proxy.close();
      target.close();
    }
  }, 30_000);
});
