/**
 * Mutation kills for the reference mutual-TLS DKG channel (frost-dkg-tls.ts). Everything runs on loopback or in-process.
 *
 * Pinned here:
 *  - start-up validation (duplicate certificates, a peer that is this node), the exact refusal text, ascending peer order;
 *  - the listen address: default host 127.0.0.1 and port 0, an explicit port and host are honoured, a busy port rejects,
 *    a missing listening address is refused with its own message, and the server keeps handlers for stray errors;
 *  - framing: a frame of exactly the cap is delivered and keeps the link, a frame one byte over is refused with `oversize`
 *    and the socket is destroyed, a frame split across TCP chunks is reassembled;
 *  - authentication: a client with an unpinned certificate is refused at the handshake, a certificate that chains to a pinned
 *    peer but is not that peer's certificate never becomes a link (inbound and outbound);
 *  - link lifecycle: a dropped link fails the awaited message with `closed` and the peer, later sends see no link, a link
 *    that was replaced is not removed by the old socket's close, sockets leave the tracking set when they close, close()
 *    destroys every socket and closes the inbox;
 *  - connect(): exact timeout text naming only the missing peers, the pinned-peer check on addresses, dial retry after a
 *    refused attempt, no redial once linked, no further dialling after the deadline or close(), the deadline timer and link
 *    waiter are released on success and on timeout.
 */
import * as nodeNet from 'node:net';
import * as nodeTls from 'node:tls';
import { createPrivateKey } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { utf8 } from './hash';
import { DKG_MAX_MESSAGE_BYTES, DkgChannelError, encodeDkgMessage, type DkgChannel } from './frost-dkg-channel';
import { startTlsDkgNode, type TlsDkgNode } from './frost-dkg-tls';
import { ext, forgeCert, forgeKey } from './test-support/forge-x509';
import { tlsIdentity } from './test-support/tls-identity';

const SID = utf8('gate3-frost-tls-session-0001-xxxxxx');
const HOST = '127.0.0.1';
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

type Ident = { keyPem: string; certPem: string };
const ident = (id: number | string): Ident => tlsIdentity(`p${id}`);

/** A certificate that chains to peer `issuerId` (so TLS accepts it) but is not that peer's own pinned certificate. */
function leafIssuedBy(issuerId: number): Ident {
  const issuer = forgeKey(`tls-identity/p${issuerId}`, 'P-256');
  const key = forgeKey(`tls-identity/leaf-of-${issuerId}`, 'P-256');
  const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64url');
  const keyPem = createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d: b64(key.priv), x: b64(key.pub.subarray(1, 33)), y: b64(key.pub.subarray(33, 65)) }, format: 'jwk' })
    .export({ type: 'pkcs8', format: 'pem' })
    .toString();
  const cert = forgeCert({
    subject: [['CN', `leaf-of-${issuerId}`]],
    issuer: [['CN', `p${issuerId}`]],
    subjectKey: key,
    signer: issuer,
    serial: 7n,
    notBefore: new Date('2020-01-01T00:00:00Z'),
    notAfter: new Date('2049-12-31T00:00:00Z'),
    extensions: [ext.basicConstraints(false)],
  });
  return { keyPem, certPem: cert.pem };
}

const closers: (() => Promise<void> | void)[] = [];
afterEach(async () => {
  for (const c of closers.splice(0).reverse()) await c();
});

async function node(self: number, peerIds: number[], extra: Partial<Parameters<typeof startTlsDkgNode>[0]> = {}): Promise<TlsDkgNode> {
  const me = ident(self);
  const n = await startTlsDkgNode({
    self,
    sessionId: SID,
    ...me,
    peerCerts: peerIds.map((p) => ({ id: p, certPem: ident(p).certPem })),
    ...extra,
  });
  closers.push(() => n.close());
  return n;
}

/** A raw TLS 1.3 client, presenting `me`, trusting `server`. Resolves once the handshake completed on its side. */
async function rawClient(port: number, me: Ident, server: Ident): Promise<nodeTls.TLSSocket> {
  const s = nodeTls.connect({ host: HOST, port, key: me.keyPem, cert: me.certPem, ca: [server.certPem], minVersion: 'TLSv1.3', checkServerIdentity: () => undefined });
  s.on('error', () => undefined);
  closers.push(() => void s.destroy());
  await new Promise<void>((res, rej) => {
    s.once('secureConnect', () => res());
    s.once('close', () => rej(new Error('closed before the handshake')));
  });
  return s;
}

const header = (len: number): Buffer => {
  const h = Buffer.alloc(4);
  h.writeUInt32BE(len, 0);
  return h;
};
const framed = (payload: Uint8Array): Buffer => Buffer.concat([header(payload.length), payload]);
const closedOf = (s: nodeNet.Socket): Promise<void> => new Promise<void>((r) => (s.destroyed ? r() : s.once('close', () => r())));
const settle = async (p: Promise<unknown>): Promise<unknown> => p.then(() => undefined, (e: unknown) => e);

async function until(cond: () => boolean, ms = 3000): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error('condition not reached');
    await sleep(10);
  }
}

async function freePort(): Promise<number> {
  const s = nodeNet.createServer();
  await new Promise<void>((r) => s.listen(0, HOST, () => r()));
  const port = (s.address() as nodeNet.AddressInfo).port;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}

/** Observe, without changing behaviour, every TLS socket added to a Set and every net listen / setNoDelay call. */
function observe() {
  const socks: { set: Set<unknown>; sock: nodeTls.TLSSocket }[] = [];
  const listens: { server: nodeNet.Server; args: unknown[] }[] = [];
  const noDelay: unknown[] = [];
  const add = Set.prototype.add;
  const listen = nodeNet.Server.prototype.listen;
  const nd = nodeNet.Socket.prototype.setNoDelay;
  Set.prototype.add = function (this: Set<unknown>, v: unknown) {
    if (v instanceof nodeTls.TLSSocket) socks.push({ set: this, sock: v });
    return add.call(this, v);
  };
  nodeNet.Server.prototype.listen = function (this: nodeNet.Server, ...args: unknown[]) {
    listens.push({ server: this, args });
    return (listen as (...a: unknown[]) => nodeNet.Server).apply(this, args);
  } as typeof listen;
  nodeNet.Socket.prototype.setNoDelay = function (this: nodeNet.Socket, ...args: unknown[]) {
    noDelay.push(args[0]);
    return (nd as (...a: unknown[]) => nodeNet.Socket).apply(this, args);
  } as typeof nd;
  const restore = (): void => {
    Set.prototype.add = add;
    nodeNet.Server.prototype.listen = listen;
    nodeNet.Socket.prototype.setNoDelay = nd;
  };
  closers.push(restore);
  return { socks, listens, noDelay, restore };
}

/** Count calls of the global clearTimeout (the deadline timer of connect() is released through it). */
function countClears() {
  const orig = globalThis.clearTimeout;
  const c = { n: 0, restore: () => void (globalThis.clearTimeout = orig) };
  globalThis.clearTimeout = ((h?: Parameters<typeof clearTimeout>[0]) => {
    c.n++;
    orig(h);
  }) as typeof clearTimeout;
  closers.push(c.restore);
  return c;
}

/** A raw mutually-authenticated TLS server presenting peer `id`'s identity that keeps every accepted socket. */
async function rawServer(id: number, trust: Ident, certOverride?: Ident) {
  const me = certOverride ?? ident(id);
  const accepted: nodeTls.TLSSocket[] = [];
  const received: Buffer[] = [];
  const conns: nodeNet.Socket[] = [];
  const server = nodeTls.createServer({ key: me.keyPem, cert: me.certPem, ca: [trust.certPem], requestCert: true, rejectUnauthorized: false, minVersion: 'TLSv1.3' }, (s) => {
    s.on('error', () => undefined);
    s.on('data', (d: Buffer) => received.push(d));
    accepted.push(s);
  });
  server.on('tlsClientError', () => undefined);
  server.on('connection', (c: nodeNet.Socket) => conns.push(c));
  await new Promise<void>((r) => server.listen(0, HOST, () => r()));
  closers.push(async () => {
    for (const s of conns) s.destroy();
    await new Promise<void>((r) => server.close(() => r()));
  });
  return { port: (server.address() as nodeNet.AddressInfo).port, accepted, conns, received };
}

/** Node 1 (listens) with a raw peer 2 linked to it. */
async function linkedPair(timeoutMs = 3000) {
  const n1 = await node(1, [2]);
  const raw = await rawClient(n1.port, ident(2), ident(1));
  const chan = await n1.connect([{ id: 2, host: HOST, port: 1 }], timeoutMs);
  return { n1, raw, chan };
}

// ---- start-up ---------------------------------------------------------------------------------------------

describe('startTlsDkgNode: peer certificate validation', () => {
  const MSG = 'startTlsDkgNode: peer certificates must be distinct and none may be this node';
  const messageOf = async (p: Promise<unknown>): Promise<string | undefined> => {
    const e = await settle(p);
    return e instanceof Error ? e.message : undefined;
  };

  it('two peers pinned with the same certificate are refused with the exact text', async () => {
    const cert = ident(2).certPem;
    const p = startTlsDkgNode({ self: 1, sessionId: SID, ...ident(1), peerCerts: [{ id: 2, certPem: cert }, { id: 3, certPem: cert }] });
    expect(await messageOf(p)).toBe(MSG);
  });

  it('a peer entry carrying this node id is refused with the exact text', async () => {
    const p = startTlsDkgNode({ self: 1, sessionId: SID, ...ident(1), peerCerts: [{ id: 1, certPem: ident(2).certPem }, { id: 3, certPem: ident(3).certPem }] });
    expect(await messageOf(p)).toBe(MSG);
  });

  it('a single peer entry carrying this node id is refused too', async () => {
    const p = startTlsDkgNode({ self: 4, sessionId: SID, ...ident(4), peerCerts: [{ id: 4, certPem: ident(5).certPem }] });
    expect(await messageOf(p)).toBe(MSG);
  });

  it('peers are reported in ascending order whatever the order they were pinned in', async () => {
    const n = await node(1, [5, 2, 4, 3]);
    const raws = await Promise.all([2, 3, 4, 5].map((p) => rawClient(n.port, ident(p), ident(1))));
    expect(raws.length).toBe(4);
    const chan = await n.connect([], 3000);
    expect(chan.peers).toEqual([2, 3, 4, 5]);
    expect(chan.self).toBe(1);
  });
});

describe('startTlsDkgNode: listening address', () => {
  it('listens on port 0 and 127.0.0.1 by default', async () => {
    const o = observe();
    const n = await node(1, [2]);
    o.restore();
    const first = o.listens.find((l) => l.args.length === 3 && typeof l.args[2] === 'function');
    expect(first!.args[0]).toBe(0);
    expect(first!.args[1]).toBe(HOST);
    expect(n.port > 0).toBe(true);
  });

  it('honours an explicit port and host', async () => {
    const port = await freePort();
    const o = observe();
    const n = await node(1, [2], { listenPort: port, listenHost: 'localhost' });
    o.restore();
    expect(n.port).toBe(port);
    const first = o.listens.find((l) => l.args.length === 3 && typeof l.args[2] === 'function');
    expect(first!.args[0]).toBe(port);
    expect(first!.args[1]).toBe('localhost');
  });

  it('a port that is already taken rejects instead of hanging', async () => {
    const blocker = nodeNet.createServer();
    await new Promise<void>((r) => blocker.listen(0, HOST, () => r()));
    closers.push(() => new Promise<void>((r) => blocker.close(() => r())));
    const port = (blocker.address() as nodeNet.AddressInfo).port;
    const e = await settle(startTlsDkgNode({ self: 1, sessionId: SID, ...ident(1), peerCerts: [{ id: 2, certPem: ident(2).certPem }], listenPort: port }));
    expect((e as { code?: string }).code).toBe('EADDRINUSE');
  }, 5000);

  it.each([
    ['no address at all', null],
    ['a pipe (string) address', '/tmp/pipe'],
  ])('%s is refused with `no listening address`', async (_name, fake) => {
    const orig = nodeNet.Server.prototype.address;
    nodeNet.Server.prototype.address = function (this: nodeNet.Server) {
      nodeNet.Server.prototype.address = orig;
      this.close();
      return fake as never;
    };
    closers.push(() => void (nodeNet.Server.prototype.address = orig));
    const e = await settle(startTlsDkgNode({ self: 1, sessionId: SID, ...ident(1), peerCerts: [{ id: 2, certPem: ident(2).certPem }] }));
    nodeNet.Server.prototype.address = orig;
    expect(e instanceof Error ? e.message : e).toBe('startTlsDkgNode: no listening address');
  });

  it('the server keeps handlers for client handshake failures and for later errors', async () => {
    const o = observe();
    await node(1, [2]);
    o.restore();
    const server = o.listens.find((l) => l.args.length === 3)!.server;
    expect(server.emit('tlsClientError', new Error('probe'), {})).toBe(true);
    // two emissions: the one-shot start-up listener may absorb only the first
    expect(() => server.emit('error', new Error('late one'))).not.toThrow();
    expect(() => server.emit('error', new Error('late two'))).not.toThrow();
  });

  it('a client without a pinned certificate is refused at the handshake and never reaches the connection handler', async () => {
    const o = observe();
    const n = await node(1, [2]);
    o.restore();
    const server = o.listens.find((l) => l.args.length === 3)!.server;
    let accepted = 0;
    let refused = 0;
    server.on('secureConnection', () => accepted++);
    server.on('tlsClientError', () => refused++);
    const rogue = nodeTls.connect({ host: HOST, port: n.port, key: ident('rogue').keyPem, cert: ident('rogue').certPem, ca: [ident(1).certPem], minVersion: 'TLSv1.3', checkServerIdentity: () => undefined });
    rogue.on('error', () => undefined);
    closers.push(() => void rogue.destroy());
    await closedOf(rogue);
    await until(() => refused > 0);
    expect(accepted).toBe(0);
    expect(refused).toBe(1);
  });
});

// ---- framing ----------------------------------------------------------------------------------------------

/** A valid wire message of exactly `n` bytes (an echo envelope padded in its body). */
function messageOfSize(n: number): Uint8Array {
  const base = encodeDkgMessage(SID, 'echo', { pad: '' }).length;
  const m = encodeDkgMessage(SID, 'echo', { pad: 'x'.repeat(n - base) });
  expect(m.length).toBe(n);
  return m;
}

describe('inbound framing', () => {
  it('a frame of exactly the cap is delivered and the link stays up', async () => {
    const { raw, chan } = await linkedPair();
    raw.write(framed(messageOfSize(DKG_MAX_MESSAGE_BYTES)));
    const got = await chan.collect('echo', [2], 5000);
    expect((got.get(2) as { pad: string }).pad.length > DKG_MAX_MESSAGE_BYTES - 100).toBe(true);
    expect(raw.destroyed).toBe(false);
    await chan.send(2, 'echo', { still: 'linked' });
  }, 15_000);

  it('a frame one byte over the cap fails the peer with `oversize`, the exact text, and destroys the socket', async () => {
    const { raw, chan } = await linkedPair();
    raw.write(header(DKG_MAX_MESSAGE_BYTES + 1));
    const e = (await settle(chan.collect('round1', [2], 3000))) as DkgChannelError;
    expect(e instanceof DkgChannelError).toBe(true);
    expect(e.code).toBe('oversize');
    expect(e.peer).toBe(2);
    expect(e.message).toBe(`dkg channel (oversize, peer 2): frame of ${DKG_MAX_MESSAGE_BYTES + 1} bytes exceeds the cap`);
    await Promise.race([closedOf(raw), sleep(2000).then(() => Promise.reject(new Error('socket was not destroyed')))]);
  }, 15_000);

  it('a frame split across TCP chunks (inside the header and inside the body) is reassembled', async () => {
    const { raw, chan } = await linkedPair();
    const bytes = framed(encodeDkgMessage(SID, 'echo', { split: 'across chunks' }));
    raw.write(bytes.subarray(0, 2));
    await sleep(40);
    raw.write(bytes.subarray(2, 9));
    await sleep(40);
    const early = await settle(chan.collect('echo', [2], 60));
    expect((early as DkgChannelError).code).toBe('timeout');
    raw.write(bytes.subarray(9));
    const got = await chan.collect('echo', [2], 3000);
    expect(got.get(2)).toEqual({ split: 'across chunks' });
  }, 15_000);

  it('sets TCP_NODELAY on every link', async () => {
    const o = observe();
    await linkedPair();
    o.restore();
    expect(o.noDelay.includes(true)).toBe(true);
    expect(o.noDelay.includes(false)).toBe(false);
  });
});

// ---- authentication -----------------------------------------------------------------------------------------

describe('pinned-certificate authentication', () => {
  it('a certificate that chains to a pinned peer but is not its pinned certificate never becomes an inbound link', async () => {
    const n1 = await node(1, [2]);
    const leaf = leafIssuedBy(2);
    const s = nodeTls.connect({ host: HOST, port: n1.port, key: leaf.keyPem, cert: leaf.certPem, ca: [ident(1).certPem], minVersion: 'TLSv1.3', checkServerIdentity: () => undefined });
    s.on('error', () => undefined);
    closers.push(() => void s.destroy());
    const e = (await settle(n1.connect([{ id: 2, host: HOST, port: 1 }], 500))) as DkgChannelError;
    expect(e.message).toBe('dkg channel (timeout, peer 2): no authenticated link to 2');
    await closedOf(s);
  }, 10_000);

  it('a server whose certificate chains to the dialled peer but is not its pinned certificate is dropped and redialled', async () => {
    const rogue = await rawServer(1, ident(2), leafIssuedBy(1));
    const n2 = await node(2, [1]);
    const p = settle(n2.connect([{ id: 1, host: HOST, port: rogue.port }], 1500));
    // refused: the dialler closes the socket itself (long before the deadline) and then tries again
    await until(() => rogue.conns.length >= 1);
    await Promise.race([closedOf(rogue.conns[0]!), sleep(1000).then(() => Promise.reject(new Error('refused socket stayed open')))]);
    await until(() => rogue.conns.length >= 2, 1000);
    const e = (await p) as DkgChannelError;
    expect(e.message).toBe('dkg channel (timeout, peer 1): no authenticated link to 1');
  }, 15_000);

  it('a pinned peer that is supposed to be dialled by this node cannot dial in', async () => {
    const n2 = await node(2, [1]);
    const s = nodeTls.connect({ host: HOST, port: n2.port, key: ident(1).keyPem, cert: ident(1).certPem, ca: [ident(2).certPem], minVersion: 'TLSv1.3', checkServerIdentity: () => undefined });
    s.on('error', () => undefined);
    closers.push(() => void s.destroy());
    const e = (await settle(n2.connect([{ id: 1, host: HOST, port: 1 }], 400))) as DkgChannelError;
    expect(e.message).toBe('dkg channel (timeout, peer 1): no authenticated link to 1');
    await closedOf(s);
  }, 10_000);
});

// ---- link lifecycle -----------------------------------------------------------------------------------------

describe('link lifecycle', () => {
  it('a dropped link fails the awaited message with `closed` and the peer, and later sends find no link', async () => {
    const { raw, chan } = await linkedPair();
    const pending = settle(chan.collect('round1', [2], 3000));
    await sleep(30);
    raw.destroy();
    const e = (await pending) as DkgChannelError;
    expect(e.code).toBe('closed');
    expect(e.peer).toBe(2);
    expect(e.message).toBe('dkg channel (closed, peer 2): link ended before its round1 message arrived');
    const s = (await settle(chan.send(2, 'echo', { x: 1 }))) as DkgChannelError;
    expect(s.code).toBe('closed');
    expect(s.peer).toBe(2);
    expect(s.message).toBe('dkg channel (closed, peer 2): no authenticated link');
    const b = (await settle(chan.broadcast('echo', { x: 1 }))) as DkgChannelError;
    expect(b.message).toBe('dkg channel (closed, peer 2): no authenticated link');
  }, 15_000);

  it('a write to a socket that is already destroyed fails with `write failed`', async () => {
    const o = observe();
    const { raw, chan } = await linkedPair();
    o.restore();
    const serverSide = o.socks.find((s) => (s.sock as unknown as { _tlsOptions?: { isServer?: boolean } })._tlsOptions?.isServer)!.sock;
    serverSide.destroy();
    const e = (await settle(chan.send(2, 'echo', { x: 1 }))) as DkgChannelError;
    expect(e.code).toBe('closed');
    expect(e.peer).toBe(2);
    expect(e.message).toBe('dkg channel (closed, peer 2): write failed');
    raw.destroy();
  }, 15_000);

  it('send to a participant that is not a pinned peer is refused with `identity`', async () => {
    const { chan } = await linkedPair();
    const e = (await settle(chan.send(9, 'echo', {}))) as DkgChannelError;
    expect(e.code).toBe('identity');
    expect(e.peer).toBe(9);
    expect(e.message).toBe('dkg channel (identity, peer 9): not a connected peer');
  });

  it('connect refuses an address for a participant that is not a pinned peer', async () => {
    const n1 = await node(1, [2]);
    const e = (await settle(n1.connect([{ id: 9, host: HOST, port: 1 }], 300))) as DkgChannelError;
    expect(e.code).toBe('identity');
    expect(e.peer).toBe(9);
    expect(e.message).toBe('dkg channel (identity, peer 9): address for a participant that is not a pinned peer');
  });

  it('a link replaced by a newer one is not removed when the old socket closes', async () => {
    const srv = await rawServer(1, ident(2));
    const n2 = await node(2, [1]);
    const addrs = [{ id: 1, host: HOST, port: srv.port }];
    const chan = await n2.connect(addrs, 3000);
    await n2.connect(addrs, 3000); // dials again: the new socket replaces the link
    await until(() => srv.accepted.length >= 2);
    await sleep(100);
    srv.accepted[0]!.destroy();
    await sleep(200);
    await chan.send(1, 'echo', { via: 'the newer link' });
    await until(() => Buffer.concat(srv.received).length > 0);
    expect(Buffer.concat(srv.received).toString('utf8').includes('the newer link')).toBe(true);
  }, 15_000);

  it('sockets leave the tracking set when they close (accepting and dialling side)', async () => {
    const o = observe();
    const { raw, n1 } = await linkedPair();
    const srv = await rawServer(1, ident(2));
    const n2 = await node(2, [1]);
    await n2.connect([{ id: 1, host: HOST, port: srv.port }], 3000);
    await until(() => srv.accepted.length >= 1);
    o.restore();
    const tracked = o.socks.filter((s) => s.sock instanceof nodeTls.TLSSocket);
    expect(tracked.length >= 2).toBe(true);
    const serverSide = tracked.find((s) => (s.sock as unknown as { _tlsOptions?: { isServer?: boolean } })._tlsOptions?.isServer && s.set.has(s.sock))!;
    const dialSide = tracked.find((s) => (s.sock as unknown as { _tlsOptions?: { isServer?: boolean } })._tlsOptions?.isServer === false)!;
    expect(serverSide.set.has(serverSide.sock)).toBe(true);
    expect(dialSide.set.has(dialSide.sock)).toBe(true);
    raw.destroy();
    srv.accepted[0]!.destroy();
    await until(() => !serverSide.set.has(serverSide.sock) && !dialSide.set.has(dialSide.sock));
    expect(n1.port > 0).toBe(true);
  }, 15_000);

  it('a late socket error on an established dialled link does not tear it down, and stray errors are absorbed', async () => {
    const o = observe();
    const srv = await rawServer(1, ident(2));
    const n2 = await node(2, [1]);
    const chan = await n2.connect([{ id: 1, host: HOST, port: srv.port }], 3000);
    o.restore();
    const dial = o.socks.find((s) => (s.sock as unknown as { _tlsOptions?: { isServer?: boolean } })._tlsOptions?.isServer === false)!.sock;
    expect(() => dial.emit('error', new Error('late'))).not.toThrow();
    await sleep(50);
    expect(dial.destroyed).toBe(false);
    await chan.send(1, 'echo', { ok: true });
  }, 15_000);

  it('a linked dialled socket keeps its own error handler after the dial attempt one is spent', async () => {
    const o = observe();
    const srv = await rawServer(1, ident(2));
    const n2 = await node(2, [1]);
    await n2.connect([{ id: 1, host: HOST, port: srv.port }], 3000);
    o.restore();
    const dial = o.socks.find((s) => (s.sock as unknown as { _tlsOptions?: { isServer?: boolean } })._tlsOptions?.isServer === false)!.sock;
    // the first error consumes the dial attempt's once() handler; only the link's handler is left for the second
    expect(() => dial.emit('error', new Error('first'))).not.toThrow();
    expect(dial.listenerCount('error')).toBe(1);
    expect(() => dial.emit('error', new Error('second'))).not.toThrow();
  }, 15_000);

  it('a socket error before the handshake completes destroys the attempt and the dial is retried', async () => {
    const real = await node(1, [2]);
    const n2 = await node(2, [1]);
    const o = observe();
    let injected: nodeTls.TLSSocket | undefined;
    let destroyedRightAfter: boolean | undefined;
    const add = Set.prototype.add; // the observer's wrapper; wrap once more to inject into the first dialled socket
    Set.prototype.add = function (this: Set<unknown>, v: unknown) {
      const r = add.call(this, v);
      if (v instanceof nodeTls.TLSSocket && injected === undefined) {
        injected = v;
        queueMicrotask(() => {
          v.emit('error', new Error('injected'));
          destroyedRightAfter = v.destroyed;
        });
      }
      return r;
    };
    const p1 = real.connect([{ id: 2, host: HOST, port: n2.port }], 5000);
    const p2 = n2.connect([{ id: 1, host: HOST, port: real.port }], 5000);
    await Promise.all([p1, p2]);
    Set.prototype.add = add;
    o.restore();
    expect(injected).toBeDefined();
    expect(destroyedRightAfter).toBe(true);
  }, 15_000);

  it('a refused first attempt is retried until the peer comes up (dial retry, port honoured)', async () => {
    const port = await freePort();
    const n2 = await node(2, [1]);
    const p2 = n2.connect([{ id: 1, host: HOST, port }], 6000);
    await sleep(250);
    const n1 = await node(1, [2], { listenPort: port });
    expect(n1.port).toBe(port);
    const [c1, c2] = await Promise.all([n1.connect([{ id: 2, host: HOST, port: n2.port }], 6000), p2]);
    await c2.send(1, 'echo', { hello: 1 });
    expect((await c1.collect('echo', [2], 3000)).get(2)).toEqual({ hello: 1 });
  }, 20_000);
});

// ---- connect() ------------------------------------------------------------------------------------------------

describe('connect', () => {
  it('names exactly the missing peers, ascending, and reports the first as the peer', async () => {
    const n1 = await node(1, [3, 2]);
    const none = (await settle(n1.connect([], 200))) as DkgChannelError;
    expect(none.code).toBe('timeout');
    expect(none.peer).toBe(2);
    expect(none.message).toBe('dkg channel (timeout, peer 2): no authenticated link to 2,3');
  });

  it('after the deadline only the peers without a link are named', async () => {
    const n1 = await node(1, [2, 3]);
    await rawClient(n1.port, ident(3), ident(1));
    const e = (await settle(n1.connect([], 400))) as DkgChannelError;
    expect(e.peer).toBe(2);
    expect(e.message).toBe('dkg channel (timeout, peer 2): no authenticated link to 2');
  });

  it('links that were established before connect() was called complete it at once', async () => {
    const n1 = await node(1, [2]);
    await rawClient(n1.port, ident(2), ident(1));
    await sleep(150);
    const started = Date.now();
    const chan = await n1.connect([], 5000);
    expect(chan.peers).toEqual([2]);
    expect(Date.now() - started < 1500).toBe(true);
  }, 15_000);

  it('the deadline timer is released once connect() succeeds', async () => {
    const n1 = await node(1, [2]);
    const [chan] = await Promise.all([n1.connect([], 1500), rawClient(n1.port, ident(2), ident(1))]);
    await sleep(1800); // past the old deadline: the node must not have been closed behind our back
    await chan.send(2, 'echo', { alive: true });
  }, 15_000);

  it('a finished connect() leaves no link waiter behind: a later link wakes only the current connect()', async () => {
    const srv = await rawServer(1, ident(2));
    const n2 = await node(2, [1]);
    const addrs = [{ id: 1, host: HOST, port: srv.port }];
    await n2.connect(addrs, 3000);
    const clears = countClears();
    await n2.connect(addrs, 3000); // the old link still counts, so this resolves at once and clears its own deadline
    await until(() => srv.accepted.length >= 2); // the redialled link attaches afterwards and wakes every waiter left
    await sleep(100);
    clears.restore();
    expect(clears.n).toBe(1);
  }, 15_000);

  it('a timed-out connect() releases its deadline and its link waiter', async () => {
    const n1 = await node(1, [2]);
    const clears = countClears();
    await settle(n1.connect([], 150));
    clears.restore();
    expect(clears.n).toBe(1);
  });

  it('once linked, a second address for the same peer is no longer dialled', async () => {
    const o = observe();
    const srv = await rawServer(1, ident(2));
    const dead = await freePort();
    const n2 = await node(2, [1]);
    await n2.connect([{ id: 1, host: HOST, port: srv.port }, { id: 1, host: HOST, port: dead }], 3000);
    const before = o.socks.length;
    await sleep(500);
    o.restore();
    expect(o.socks.length).toBe(before);
  }, 15_000);

  it('a linked peer is not redialled while another peer is still awaited', async () => {
    const o = observe();
    const n1 = await node(1, [2, 3]);
    const n2 = await node(2, [1, 3]);
    const dialled = (): number => o.socks.filter((s) => (s.sock as unknown as { _tlsOptions?: { isServer?: boolean } })._tlsOptions?.isServer === false).length;
    // node 1's deadline is well after node 2's: a timed-out node closes itself, and node 1 closing first would drop the
    // 1-2 link while node 2 still waits (node 2 would then report peer 1 missing and redial it)
    const a = settle(n1.connect([{ id: 2, host: HOST, port: n2.port }, { id: 3, host: HOST, port: 1 }], 9000));
    const b = (await settle(n2.connect([{ id: 1, host: HOST, port: n1.port }, { id: 3, host: HOST, port: 1 }], 4000))) as DkgChannelError;
    await a;
    o.restore();
    expect(b.message).toBe('dkg channel (timeout, peer 3): no authenticated link to 3');
    expect(dialled()).toBe(1);
  }, 30_000);

  it('dialling stops when the node is closed', async () => {
    const o = observe();
    const dead = await freePort();
    const n2 = await node(2, [1]);
    const p = settle(n2.connect([{ id: 1, host: HOST, port: dead }], 1500));
    await sleep(200);
    await n2.close();
    await sleep(100);
    const atClose = o.socks.length;
    await sleep(400);
    o.restore();
    expect(o.socks.length).toBe(atClose);
    const e = (await p) as DkgChannelError;
    expect(e.code).toBe('timeout');
  }, 15_000);
});

// ---- close ------------------------------------------------------------------------------------------------------

describe('close', () => {
  it('channel.close() closes the node: links are destroyed and a waiting collect rejects `closed`', async () => {
    const { raw, chan } = await linkedPair();
    const pending = settle(chan.collect('echo', [2], 5000));
    await sleep(30);
    await Promise.race([chan.close(), sleep(3000).then(() => Promise.reject(new Error('close did not finish')))]);
    const e = (await pending) as DkgChannelError;
    expect(e.code).toBe('closed');
    expect(e.peer).toBeUndefined();
    expect(e.message).toBe('dkg channel (closed): channel closed before all messages arrived');
    await Promise.race([closedOf(raw), sleep(2000).then(() => Promise.reject(new Error('link was not destroyed')))]);
    const later = (await settle(chan.collect('round1', [2], 2000))) as DkgChannelError;
    expect(later.code).toBe('closed');
  }, 15_000);

  it('node.close() resolves with a live link, destroys dialled sockets too, and is repeatable', async () => {
    const srv = await rawServer(1, ident(2));
    const n2 = await node(2, [1]);
    const chan: DkgChannel = await n2.connect([{ id: 1, host: HOST, port: srv.port }], 3000);
    expect(chan.peers).toEqual([1]);
    await until(() => srv.accepted.length >= 1);
    await n2.close();
    await Promise.race([closedOf(srv.accepted[0]!), sleep(2000).then(() => Promise.reject(new Error('dialled socket survived close')))]);
    await n2.close();
  }, 15_000);
});
