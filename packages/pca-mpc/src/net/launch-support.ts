/**
 * Small helpers the local multi-process launcher (`launch-local.ts`) shares with the tests: the one timeout-scale knob and
 * distinct free loopback ports.
 */
import * as net from 'node:net';

const parsed = Number(process.env['PCA_MPC_TEST_TIMEOUT_SCALE'] ?? '1');
/** Multiplier for every launcher/test timeout, from `PCA_MPC_TEST_TIMEOUT_SCALE` (default 1; raise it on a slow machine). */
export const TIMEOUT_SCALE = Number.isFinite(parsed) && parsed > 0 ? parsed : 1;

/** Scale a duration (ms) by the one timeout knob. */
export const T = (ms: number): number => Math.ceil(ms * TIMEOUT_SCALE);

/** `count` DISTINCT free ephemeral ports, all held open at the same time (so they cannot collide with each other) and released together. */
export async function reservePorts(count: number): Promise<number[]> {
  const servers: net.Server[] = [];
  const ports: number[] = [];
  for (let i = 0; i < count; i++) {
    const s = net.createServer();
    await new Promise<void>((res, rej) => {
      s.once('error', rej);
      s.listen(0, '127.0.0.1', () => res());
    });
    servers.push(s);
    ports.push((s.address() as net.AddressInfo).port);
  }
  await Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r()))));
  return ports;
}
