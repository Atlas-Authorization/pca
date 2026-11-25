/** The Envoy harness never probes a port and releases it: every port is bound by its owner (port 0) and read back. */
import { readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { bootstrap, startDeadService } from '../test-support/envoy-harness';

// assembled so this file does not itself contain the names it forbids
const PROBE = new RegExp(`\\b(${['free', 'Port'].join('')}s?|${['reserve', 'Ports'].join('')})\\b`);

describe('envoy harness binds first', () => {
  it('the dead check service holds the port it reports', async () => {
    const dead = await startDeadService();
    expect(dead.port).toBeGreaterThan(0);
    await expect(new Promise((res, rej) => { const s = createServer(); s.once('error', rej); s.listen(dead.port, '127.0.0.1', () => res(true)); })).rejects.toThrow(/EADDRINUSE/);
    await dead.close();
  });

  it('the bootstrap asks Envoy to bind the admin and every listener on port 0', () => {
    const b = bootstrap({ upstreamPort: 1, listeners: [{ name: 'h', mode: 'http', authzPort: 2 }] }) as {
      admin: { address: { socket_address: { port_value: number } } };
      static_resources: { listeners: Array<{ address: { socket_address: { port_value: number } } }> };
    };
    expect(b.admin.address.socket_address.port_value).toBe(0);
    expect(b.static_resources.listeners.map((l) => l.address.socket_address.port_value)).toEqual([0]);
  });

  it('no probe-and-release port helper remains in the harness or its tests', () => {
    for (const f of [join(__dirname, '../test-support/envoy-harness.ts'), join(__dirname, 'envoy.integration.test.ts')]) {
      expect(readFileSync(f, 'utf8')).not.toMatch(PROBE);
    }
  });
});
