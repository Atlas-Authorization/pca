/**
 * Bound-first ports and bounded dial attempts.
 *
 *  - every node binds port 0 itself and reports the port it really holds; the launcher hands everyone the full map before any
 *    node dials. No helper probes a port and releases it (that races with every other process on the machine).
 *  - a dial attempt whose TCP connect succeeds but whose TLS handshake never completes is destroyed at its own deadline and
 *    retried; a peer that closes before the handshake is retried too. Driven by an injected clock, no sleeps.
 *  - a launch that exceeds its cap fails with each node's stage and output instead of waiting for the kill timer.
 */
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import * as net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateIdentity, readPem } from './certs';
import { launchLocal } from './launch-local';
import { Mesh } from './mesh';
import type { DecisionVector } from '../party';
import { ManualClock, T, until } from './test-timing';
import { NetAbort } from './wire';

let dir = '';
let holdJs = '';
let stuckAfterPortJs = '';
let silentJs = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'pca-bind-first-'));
  // binds a real server on port 0, reports it, takes the map, then proves it still holds the port (a second bind must fail)
  holdJs = join(dir, 'hold.js');
  writeFileSync(
    holdJs,
    `const net = require('net');
const cfg = JSON.parse(require('fs').readFileSync(process.argv[2], 'utf8'));
const srv = net.createServer();
srv.listen(0, '127.0.0.1', () => {
  const bound = srv.address().port;
  process.stdout.write(JSON.stringify({ listening: bound }) + '\\n');
  let b = '';
  process.stdin.on('data', (d) => {
    b += d;
    const i = b.indexOf('\\n');
    if (i < 0) return;
    process.stdin.pause();
    const ports = JSON.parse(b.slice(0, i)).ports;
    const again = net.createServer();
    again.once('error', (e) => { process.stdout.write(JSON.stringify({ id: cfg.id, bound, ports, secondBind: e.code }) + '\\n'); srv.close(); });
    again.listen(bound, '127.0.0.1', () => { process.stdout.write(JSON.stringify({ id: cfg.id, bound, ports, secondBind: 'succeeded' }) + '\\n'); again.close(); srv.close(); });
  });
});
`,
  );
  stuckAfterPortJs = join(dir, 'stuck.js');
  writeFileSync(stuckAfterPortJs, `process.stdout.write('{"listening":7}\\n'); process.stdin.resume(); setInterval(() => {}, 1000);\n`);
  silentJs = join(dir, 'silent.js');
  writeFileSync(silentJs, `process.stderr.write('never bound'); setInterval(() => {}, 1000);\n`);
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

// assembled so this file does not itself contain the names it forbids
const PROBE = new RegExp(`\\b(${['reserve', 'Ports'].join('')}|${['free', 'Port'].join('')})\\b`);

describe('the launcher binds first', () => {
  it('the advertised ports are the bound ports, and every node still holds its port', async () => {
    const r = await launchLocal({ n: 2, vectors: [{ allow: 1, t: 1, rQuant: 0 }, { allow: 1, t: 1, rQuant: 0 }], mainJs: holdJs, offline: 'trusted-dealer', insecureTrustedDealer: true, capMs: T(30_000) });
    expect(r.outputs.length).toBe(3);
    const bound = r.outputs.map((o) => o.json.bound as number);
    expect(new Set(bound).size).toBe(3);
    for (const o of r.outputs) {
      expect(o.json.ports).toEqual(Object.fromEntries(bound.map((p, j) => [j, p]))); // every node was told exactly what the nodes bound
      expect(o.json.secondBind).toBe('EADDRINUSE'); // the node held its port the whole time
    }
  }, T(60_000));

  it('no probe-and-release port helper remains in the package sources', () => {
    const here = __dirname;
    const offenders: string[] = [];
    for (const f of readdirSync(here).filter((x) => x.endsWith('.ts') && x !== 'launch-bind-first.test.ts')) {
      const txt = readFileSync(join(here, f), 'utf8');
      if (PROBE.test(txt)) offenders.push(f);
    }
    expect(offenders).toEqual([]);
  });

  it('a Mesh bound to port 0 holds the port it reports and writes it back to its own address', async () => {
    const a = generateIdentity(join(dir, 'ma'), 'ma');
    const nodes = [{ id: 0, host: '127.0.0.1', port: 0, certPem: readPem(a.certPath) }];
    const m = new Mesh({ selfId: 0, nodes, linkTo: [], keyPem: readPem(a.keyPath), certPem: readPem(a.certPath), sessionId: 's', listenHost: '127.0.0.1' });
    const p = await m.listen();
    expect(p).toBeGreaterThan(0);
    expect(nodes[0]!.port).toBe(p);
    expect(await m.listen()).toBe(p); // idempotent
    const again = net.createServer();
    await expect(new Promise((res, rej) => { again.once('error', rej); again.listen(p, '127.0.0.1', () => res(true)); })).rejects.toThrow(/EADDRINUSE/);
    await m.connect(); // no links: connect after listen completes at once
    m.fail(new NetAbort('local', null, 0, 'done'));
  });
});

describe('a launch that hangs says where', () => {
  const two: { n: number; vectors: DecisionVector[] } = { n: 1, vectors: [{ allow: 1, t: 1, rQuant: 0 }] };
  it('a node that got the port map and then stalled is reported with its stage, stdout and stderr', async () => {
    const e = (await launchLocal({ ...two, mainJs: stuckAfterPortJs, offline: 'no-dealer', capMs: 1500 }).catch((x) => x)) as Error;
    expect(e).toBeInstanceOf(Error);
    expect(e.message).toMatch(/exceeded its 1500ms cap/);
    expect(e.message).toMatch(/node 0 \(party\) stage=ports-sent/);
    expect(e.message).toContain('listening');
  }, T(30_000));
  it('a node that never bound is reported as spawned, with what it wrote to stderr', async () => {
    const e = (await launchLocal({ ...two, mainJs: silentJs, offline: 'no-dealer', capMs: 1500 }).catch((x) => x)) as Error;
    expect(e.message).toMatch(/node 0 \(party\) stage=spawned/);
    expect(e.message).toContain('never bound');
  }, T(30_000));
});

describe('a dial attempt is bounded by its own handshake deadline', () => {
  const setup = async (onConn: (s: net.Socket) => void) => {
    const a = generateIdentity(join(dir, 'da'), 'da');
    const b = generateIdentity(join(dir, 'db'), 'db');
    const srv = net.createServer((s) => {
      s.on('error', () => undefined);
      onConn(s);
    });
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
    const port = (srv.address() as net.AddressInfo).port;
    const nodes = [
      { id: 0, host: '127.0.0.1', port, certPem: readPem(a.certPath) },
      { id: 1, host: '127.0.0.1', port: 0, certPem: readPem(b.certPath) },
    ];
    const clock = new ManualClock();
    const m = new Mesh({ selfId: 1, nodes, linkTo: [0], keyPem: readPem(b.keyPath), certPem: readPem(b.certPath), sessionId: 's', listenHost: '127.0.0.1', clock, connectTimeoutMs: 100_000, handshakeTimeoutMs: 5_000 });
    return { srv, m, clock };
  };

  it('a peer that accepts TCP and never speaks is destroyed at the handshake deadline and dialed again', async () => {
    const seen: { s: net.Socket; closed: boolean }[] = [];
    const { srv, m, clock } = await setup((s) => {
      const rec = { s, closed: false };
      s.resume(); // read (and discard) the ClientHello: an unread socket never sees the client's close, so it would never emit 'close'
      s.on('close', () => (rec.closed = true));
      seen.push(rec);
    });
    const c = m.connect().catch((e) => e);
    await until(() => seen.length >= 1, 'the first dial to reach the peer');
    expect(seen[0]!.closed).toBe(false); // nothing but the deadline can end this attempt
    clock.advance(4_999);
    await new Promise((r) => setImmediate(r));
    expect(seen[0]!.closed).toBe(false);
    clock.advance(1); // the attempt's own deadline
    await until(() => seen[0]!.closed, 'the stalled attempt to be destroyed');
    await until(() => seen.length >= 2, 'the dial to be retried'); // retry pacing is real time, a fixed 150 ms
    clock.advance(100_001); // past the connect deadline (now === deadline is not yet expired) // the connect deadline: the whole connect fails, bounded
    const e = (await c) as NetAbort;
    expect(e.kind).toBe('timeout');
    expect(e.blamed).toBe(0);
    srv.close();
    for (const x of seen) x.s.destroy();
  }, T(30_000));

  it('a peer that closes before the handshake is retried without waiting for any deadline', async () => {
    let n = 0;
    const { srv, m, clock } = await setup((s) => {
      n++;
      s.end();
    });
    const c = m.connect().catch((e) => e);
    await until(() => n >= 3, 'repeated dials of a peer that hangs up'); // the clock never moves: only the close can end an attempt
    clock.advance(100_001); // past the connect deadline (now === deadline is not yet expired)
    expect(((await c) as NetAbort).kind).toBe('timeout');
    srv.close();
  }, T(30_000));
});
