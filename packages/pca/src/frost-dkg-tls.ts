import type { Server, TLSSocket } from 'node:tls';
import type { ParticipantId } from './frost';
import { DKG_MAX_MESSAGE_BYTES, DkgChannelError, DkgInbox, encodeDkgMessage, type DkgChannel, type DkgMessageKind } from './frost-dkg-channel';

/**
 * REFERENCE MUTUAL-TLS CHANNEL FOR THE FROST DKG (Node only; `node:tls` is imported lazily).
 *
 * One TLS 1.3 connection per pair of participants, mutually authenticated by pinned certificate: each side trusts exactly
 * the other participants' certificates, and the peer's SHA-256 certificate fingerprint maps to its participant id, so the
 * sender identity the DKG driver sees comes from the handshake and never from message content. The higher-numbered party
 * dials the lower-numbered one. A peer without a pinned certificate, a plaintext client, a TLS 1.2 client, a second
 * connection for an already linked identity and a connection from a party that should have been dialled are all refused
 * before any DKG byte is read. Frames are a 4-byte big-endian length then the message; the length is checked against
 * {@link DKG_MAX_MESSAGE_BYTES} before any allocation.
 *
 * This is a reference: certificate issuance, rotation and revocation are the deployer's.
 */

export interface TlsDkgNodeOpts {
  self: ParticipantId;
  sessionId: Uint8Array;
  /** This node's PEM private key and certificate. */
  keyPem: string;
  certPem: string;
  /** Pinned identities of every OTHER participant (certificate only). */
  peerCerts: { id: ParticipantId; certPem: string }[];
  /** Port to listen on (0 = ephemeral; read {@link TlsDkgNode.port}). Default host 127.0.0.1. */
  listenPort?: number;
  listenHost?: string;
}

export interface TlsDkgNode {
  readonly port: number;
  /** Dial the lower-numbered peers, wait for the higher-numbered ones, and return the channel once every link is authenticated. */
  connect(addresses: { id: ParticipantId; host: string; port: number }[], connectTimeoutMs?: number): Promise<DkgChannel>;
  close(): Promise<void>;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export async function startTlsDkgNode(opts: TlsDkgNodeOpts): Promise<TlsDkgNode> {
  const tls = await import('node:tls');
  const { X509Certificate } = await import('node:crypto');
  const pinned = new Map<string, ParticipantId>(opts.peerCerts.map((p) => [new X509Certificate(p.certPem).fingerprint256, p.id]));
  if (pinned.size !== opts.peerCerts.length || opts.peerCerts.some((p) => p.id === opts.self)) {
    throw new Error('startTlsDkgNode: peer certificates must be distinct and none may be this node');
  }
  const peers = opts.peerCerts.map((p) => p.id).sort((a, b) => a - b);
  const inbox = new DkgInbox(opts.sessionId, peers);
  const links = new Map<ParticipantId, TLSSocket>();
  const sockets = new Set<TLSSocket>();
  const linkWaiters = new Set<() => void>(); // woken by every new link: connect() waits on events, not on a polling loop
  let closed = false;

  const attach = (id: ParticipantId, sock: TLSSocket): void => {
    links.set(id, sock);
    for (const w of [...linkWaiters]) w();
    sock.setNoDelay(true);
    let buf: Buffer = Buffer.alloc(0);
    sock.on('data', (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        if (buf.length < 4) return;
        const len = buf.readUInt32BE(0);
        if (len > DKG_MAX_MESSAGE_BYTES) {
          inbox.fail(id, new DkgChannelError('oversize', id, `frame of ${len} bytes exceeds the cap`));
          sock.destroy();
          return;
        }
        if (buf.length < 4 + len) return;
        inbox.accept(id, new Uint8Array(buf.subarray(4, 4 + len)));
        buf = buf.subarray(4 + len);
      }
    });
    sock.on('error', () => undefined);
    sock.on('close', () => {
      if (links.get(id) === sock) links.delete(id);
      inbox.peerGone(id);
    });
  };

  const server: Server = tls.createServer(
    {
      key: opts.keyPem,
      cert: opts.certPem,
      ca: opts.peerCerts.map((p) => p.certPem),
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.3',
    },
    (sock) => {
      sockets.add(sock);
      sock.on('error', () => undefined);
      sock.on('close', () => sockets.delete(sock));
      const fp = sock.getPeerCertificate().fingerprint256;
      const id = fp ? pinned.get(fp) : undefined;
      // Only a pinned, authorized peer that is supposed to dial us (higher id), once.
      if (!sock.authorized || id === undefined || id < opts.self || links.has(id)) return void sock.destroy();
      attach(id, sock);
    },
  );
  server.on('tlsClientError', () => undefined);
  server.on('error', () => undefined);
  await new Promise<void>((res, rej) => {
    server.once('error', rej);
    server.listen(opts.listenPort ?? 0, opts.listenHost ?? '127.0.0.1', () => res());
  });
  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('startTlsDkgNode: no listening address');

  const dial = async (id: ParticipantId, host: string, port: number, stopped: () => boolean): Promise<void> => {
    const cert = opts.peerCerts.find((p) => p.id === id)!.certPem;
    while (!stopped() && !closed) {
      const done = await new Promise<boolean>((resolve) => {
        const sock = tls.connect({
          host,
          port,
          key: opts.keyPem,
          cert: opts.certPem,
          ca: [cert],
          minVersion: 'TLSv1.3',
          checkServerIdentity: () => undefined, // pinned by certificate, not by host name
        });
        sockets.add(sock);
        sock.once('close', () => sockets.delete(sock));
        let settled = false;
        sock.once('secureConnect', () => {
          settled = true;
          if (!sock.authorized || pinned.get(sock.getPeerCertificate().fingerprint256) !== id) {
            sock.destroy();
            return resolve(false);
          }
          attach(id, sock);
          resolve(true);
        });
        sock.once('error', () => {
          if (!settled) {
            sock.destroy();
            resolve(false);
          }
        });
      });
      if (done) return;
      await sleep(50);
    }
  };

  const node: TlsDkgNode = {
    port: addr.port,
    async connect(addresses, connectTimeoutMs = 15_000) {
      let stop = false;
      for (const a of addresses) {
        if (!peers.includes(a.id)) throw new DkgChannelError('identity', a.id, 'address for a participant that is not a pinned peer');
        if (a.id < opts.self) void dial(a.id, a.host, a.port, () => stop);
      }
      // The only timer is the overall deadline; completion is signalled by the link event itself.
      await new Promise<void>((resolve, reject) => {
        const finish = (): void => {
          stop = true;
          clearTimeout(timer);
          linkWaiters.delete(check);
        };
        const check = (): void => {
          if (links.size >= peers.length) {
            finish();
            resolve();
          }
        };
        const timer = setTimeout(() => {
          finish();
          const missing = peers.filter((p) => !links.has(p));
          void node.close().then(() => reject(new DkgChannelError('timeout', missing[0], `no authenticated link to ${missing.join(',')}`)));
        }, connectTimeoutMs);
        linkWaiters.add(check);
        check();
      });
      const write = (to: ParticipantId, kind: DkgMessageKind, body: unknown): Promise<void> => {
        const sock = links.get(to);
        if (!sock) return Promise.reject(new DkgChannelError('closed', to, 'no authenticated link'));
        const payload = encodeDkgMessage(opts.sessionId, kind, body);
        const frame = Buffer.alloc(4 + payload.length);
        frame.writeUInt32BE(payload.length, 0);
        frame.set(payload, 4);
        return new Promise((res, rej) => sock.write(frame, (e) => (e ? rej(new DkgChannelError('closed', to, 'write failed')) : res())));
      };
      return {
        self: opts.self,
        peers,
        broadcast: async (kind, body) => void (await Promise.all(peers.map((p) => write(p, kind, body)))),
        send: (to, kind, body) => (peers.includes(to) ? write(to, kind, body) : Promise.reject(new DkgChannelError('identity', to, 'not a connected peer'))),
        collect: (kind, from, timeoutMs) => inbox.collect(kind, from, timeoutMs),
        close: () => node.close(),
      };
    },
    async close() {
      closed = true;
      inbox.close();
      for (const s of sockets) s.destroy();
      await new Promise<void>((res) => server.close(() => res()));
    },
  };
  return node;
}
