/**
 * Authenticated, confidential, fail-closed point-to-point mesh over TLS 1.3 (research prototype).
 *
 *  - MUTUAL TLS with PINNED self-signed certificates (generated per run by `certs.ts`). A peer is
 *    identified by the SHA-256 fingerprint of its certificate, never by anything it claims; the claimed
 *    id in the hello frame must agree with the pinned fingerprint.
 *  - Strict framing + per-link sequence numbers. A malformed frame, a duplicate / replayed frame, a
 *    skipped (out-of-order) frame, a frame for the wrong round or session, or an oversize length
 *    prefix aborts the whole run with an ATTRIBUTABLE `NetAbort` naming the sender.
 *  - Timeouts on every receive (no hangs); a silent peer is blamed after `recvTimeoutMs`.
 *  - ABORT PROPAGATION: the first failure poisons the mesh, wakes every pending receive, best-effort
 *    sends an `abort` frame to every peer (so they stop immediately and learn who we blame), then
 *    closes the sockets. Once failed, nothing further is sent as protocol data (fail closed).
 *
 * Network faults (drop, truncate, bit-flip, reorder, duplicate at the TCP level) are all caught by TLS
 * record authentication and surface as `disconnect` on that link. Application-level misbehaviour
 * (replay, skipped sequence, garbage, wrong round) is caught by the framing checks here. See the tests.
 */

import { X509Certificate, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { EventEmitter } from 'node:events';
import * as tls from 'node:tls';
import { createServer as createTlsServer, type TLSSocket } from 'node:tls';
import {
  encodeFrame,
  type Frame,
  type FrameType,
  FrameSplitter,
  NetAbort,
  type AbortKind,
  parseFrame,
  ABORT_KINDS,
  WIRE_VERSION,
  versionMismatch,
} from './wire';
import { fingerprintOf } from './certs';

export interface NodeAddr {
  id: number;
  host: string;
  port: number;
  /** The node's PUBLIC certificate (PEM): pinned trust anchor + identity. */
  certPem: string;
}

/**
 * Time source for every DECISION the mesh makes by time (receive deadlines, connect deadline, dial retry). The default is the
 * wall clock; tests inject a virtual clock so an outcome never depends on how loaded the machine is. A deadline is always a
 * parameter (`timeoutMs`) and is recorded on the resulting `NetAbort` (`deadlineMs`).
 */
export interface MeshClock {
  now(): number;
  /** Schedule `fn` after `ms` of clock time; returns a handle for `clearTimer`. */
  setTimer(fn: () => void, ms: number): unknown;
  clearTimer(handle: unknown): void;
}

export const wallClock: MeshClock = {
  now: () => Date.now(),
  setTimer: (fn, ms) => setTimeout(fn, ms),
  clearTimer: (h) => clearTimeout(h as ReturnType<typeof setTimeout>),
};

export interface MeshConfig {
  /** Time source for deadlines (default: wall clock). */
  clock?: MeshClock;
  selfId: number;
  /** Every node in the session (including self). Only nodes in `linkTo` get a connection. */
  nodes: NodeAddr[];
  /** Node ids this node maintains a link to (default: all others). */
  linkTo?: number[];
  keyPem: string;
  certPem: string;
  sessionId: string;
  listenHost?: string;
  connectTimeoutMs?: number;
  recvTimeoutMs?: number;
  /**
   * TEST HOOK: a (malicious) sender rewriting its own outgoing frames. Refused unless `unsafeTestHooks` is
   * also `true`; the production entry point (`party-main`) only sets that from an explicit test environment.
   */
  tamper?: (ev: TamperEvent) => Buffer[];
  /** Explicit opt-in required for `tamper`. Leave unset in production. */
  unsafeTestHooks?: boolean;
  /** Most unread frames queued per link before the sender is blamed with `flood` (default 1024). */
  maxInboxFrames?: number;
  /** Most unread frame bytes queued per link before the sender is blamed with `flood` (default 32 MiB). */
  maxInboxBytes?: number;
}

/** Most non-fatal observations kept in `Mesh.events`; further ones are only counted. */
export const MAX_MESH_EVENTS = 64;

export interface TamperEvent {
  to: number;
  frame: Frame;
  /** The honest encoding of the frame. */
  raw: Buffer;
}

interface Link {
  id: number;
  socket: TLSSocket | null;
  splitter: FrameSplitter;
  /** Queued frames; `abort` marks a peer's abort claim deferred behind its earlier frames (see `deferAborts`). */
  inbox: { f: Frame; size: number; abort?: NetAbort }[];
  inboxBytes: number;
  paused: boolean;
  sendSeq: number;
  recvSeq: number;
  closed: boolean;
  helloSeen: boolean;
  bytesIn: number;
  bytesOut: number;
  framesIn: number;
  framesOut: number;
}

export interface LinkStats {
  peer: number;
  appBytesOut: number;
  appBytesIn: number;
  framesOut: number;
  framesIn: number;
  tlsBytesWritten: number;
  tlsBytesRead: number;
}

export class Mesh {
  readonly selfId: number;
  private readonly cfg: MeshConfig;
  private readonly links = new Map<number, Link>();
  private readonly pinned = new Map<string, number>(); // fingerprint -> node id
  private readonly ev = new EventEmitter();
  private server: tls.Server | null = null;
  private failure: NetAbort | null = null;
  private finished = false;
  private deferAborts = false;
  private readonly clock: MeshClock;
  private readonly recvTimeoutMs: number;
  private readonly connectTimeoutMs: number;
  /** Non-fatal observations (e.g. a TLS client rejected at the door) for evidence logs. */
  readonly events: string[] = [];
  /** Observations beyond `MAX_MESH_EVENTS` that were counted but not stored. */
  eventsDropped = 0;
  private readonly maxInboxFrames: number;
  private readonly maxInboxBytes: number;

  constructor(cfg: MeshConfig) {
    this.cfg = cfg;
    this.selfId = cfg.selfId;
    this.clock = cfg.clock ?? wallClock;
    this.recvTimeoutMs = cfg.recvTimeoutMs ?? 20_000;
    this.connectTimeoutMs = cfg.connectTimeoutMs ?? 30_000;
    if (cfg.tamper && cfg.unsafeTestHooks !== true) {
      throw new Error('mesh: the tamper test hook requires unsafeTestHooks: true (test-only)');
    }
    this.maxInboxFrames = cfg.maxInboxFrames ?? 1024;
    this.maxInboxBytes = cfg.maxInboxBytes ?? 32 * 1024 * 1024;
    this.ev.setMaxListeners(0);
    const want = cfg.linkTo ?? cfg.nodes.map((n) => n.id).filter((i) => i !== cfg.selfId);
    for (const n of cfg.nodes) {
      if (n.id !== cfg.selfId) this.pinned.set(fingerprintOf(n.certPem), n.id);
    }
    for (const id of want) {
      if (!cfg.nodes.some((n) => n.id === id)) throw new Error(`mesh: unknown link target ${id}`);
      this.links.set(id, newLink(id));
    }
  }

  private note(msg: string): void {
    if (this.events.length < MAX_MESH_EVENTS) this.events.push(msg);
    else this.eventsDropped++;
  }

  /** The session id every frame on this mesh carries (used to bind sub-protocols to this session). */
  get sessionId(): string {
    return this.cfg.sessionId;
  }

  get peers(): number[] {
    return [...this.links.keys()].sort((a, b) => a - b);
  }

  get failed(): NetAbort | null {
    return this.failure;
  }

  // ------------------------------------------------------------------ connect

  /** Listen, dial every lower-numbered link target, and wait until all links are authenticated. */
  async connect(): Promise<void> {
    const self = this.cfg.nodes.find((n) => n.id === this.selfId);
    if (!self) throw new Error('mesh: self not in nodes');
    const others = this.cfg.nodes.filter((n) => n.id !== this.selfId);
    this.server = createTlsServer(
      {
        key: this.cfg.keyPem,
        cert: this.cfg.certPem,
        ca: others.map((n) => n.certPem),
        requestCert: true,
        rejectUnauthorized: true,
        minVersion: 'TLSv1.3',
      },
      (sock) => this.onIncoming(sock),
    );
    this.server.on('tlsClientError', (e) => this.note(`tlsClientError: ${(e as Error).message.slice(0, 120)}`));
    this.server.on('error', (e) => this.note(`server error: ${e.message}`));
    await new Promise<void>((res, rej) => {
      this.server!.once('error', rej);
      this.server!.listen(self.port, this.cfg.listenHost ?? '0.0.0.0', () => res());
    });

    const deadline = this.clock.now() + this.connectTimeoutMs;
    for (const id of this.peers) {
      if (id < this.selfId) void this.dial(id, deadline);
    }
    // wait for all links to complete the authenticated hello exchange (poll; bounded by the deadline)
    for (;;) {
      if (this.failure) throw this.failure;
      const missing = this.peers.filter((i) => !this.links.get(i)!.helloSeen);
      if (missing.length === 0) return;
      if (this.clock.now() > deadline) {
        const e = new NetAbort('timeout', missing[0]!, this.selfId, `connect: no authenticated link from ${missing.join(',')}`);
        this.fail(e);
        throw e;
      }
      await new Promise<void>((r) => setTimeout(r, 20)); // a poll interval, not a decision: real time
    }
  }

  private async dial(id: number, deadline: number): Promise<void> {
    const node = this.cfg.nodes.find((n) => n.id === id)!;
    while (!this.failure && this.clock.now() < deadline) {
      const ok = await new Promise<boolean>((resolve) => {
        const sock = tls.connect({
          host: node.host,
          port: node.port,
          key: this.cfg.keyPem,
          cert: this.cfg.certPem,
          ca: [node.certPem],
          minVersion: 'TLSv1.3',
          // We pin by certificate (ca = exactly that cert + fingerprint check below), not by hostname.
          checkServerIdentity: () => undefined,
        });
        let settled = false;
        sock.once('secureConnect', () => {
          settled = true;
          const fp = sock.getPeerCertificate().fingerprint256;
          if (!sock.authorized || this.pinned.get(fp) !== id) {
            sock.destroy();
            this.fail(new NetAbort('identity', id, this.selfId, `dial: peer certificate is not the pinned identity of node ${id}`));
            return resolve(true);
          }
          this.attach(id, sock);
          resolve(true);
        });
        sock.once('error', () => {
          if (!settled) {
            sock.destroy();
            resolve(false);
          }
        });
      });
      if (ok) return;
      await new Promise<void>((r) => setTimeout(r, 150)); // retry pacing, not a decision: real time
    }
  }

  private onIncoming(sock: TLSSocket): void {
    sock.on('error', () => undefined);
    const fp = sock.getPeerCertificate().fingerprint256;
    const id = fp ? this.pinned.get(fp) : undefined;
    if (!sock.authorized || id === undefined || !this.links.has(id) || id < this.selfId) {
      this.note(`rejected incoming connection (fp=${fp ?? 'none'})`);
      sock.destroy();
      return;
    }
    const l = this.links.get(id)!;
    if (l.socket) {
      // a second connection claiming an already-linked identity
      this.note(`duplicate connection from node ${id}`);
      sock.destroy();
      return;
    }
    this.attach(id, sock);
  }

  private attach(id: number, sock: TLSSocket): void {
    const l = this.links.get(id)!;
    if (l.socket) {
      sock.destroy();
      return;
    }
    l.socket = sock;
    sock.setNoDelay(true);
    sock.on('data', (chunk: Buffer) => this.onData(l, chunk));
    sock.on('error', (e) => this.onClosed(l, `socket error: ${e.message}`));
    sock.on('close', () => this.onClosed(l, 'socket closed'));
    sock.on('end', () => this.onClosed(l, 'peer ended'));
    // hello: first frame on every link (seq 0); carries our id so the peer can cross-check the pin.
    this.sendFrame(l, 'hello', 'hello', { id: this.selfId });
  }

  // ------------------------------------------------------------------ receive path

  private onData(l: Link, chunk: Buffer): void {
    if (this.failure) return;
    l.bytesIn += chunk.length;
    let bodies: Buffer[];
    try {
      bodies = l.splitter.push(chunk);
    } catch {
      return this.fail(new NetAbort('oversize', l.id, this.selfId, 'length prefix above MAX_FRAME_BYTES'));
    }
    for (const b of bodies) {
      const f = parseFrame(b);
      if (!f) {
        const pv = versionMismatch(b);
        if (pv !== null) {
          return this.fail(new NetAbort('version', l.id, this.selfId, `peer ${l.id} speaks wire version ${pv}, this node speaks ${WIRE_VERSION}; upgrade both peers`));
        }
      }
      if (!f) return this.fail(new NetAbort('malformed', l.id, this.selfId, 'undecodable or ill-shaped frame'));
      if (f.sid !== this.cfg.sessionId) {
        return this.fail(new NetAbort('wrong-session', l.id, this.selfId, 'frame from another session'));
      }
      if (f.ty === 'abort') {
        // An abort frame is only a CLAIM by the peer that sent it. We blame that peer (the authenticated
        // sender), never the party it names: otherwise any peer could frame an honest one.
        const d = f.d as { kind?: unknown; blamed?: unknown; detail?: unknown; relayed?: unknown } | null;
        // a relayed abort is second-hand (an honest peer passing on what ITS peer said): it names no one
        const relayed = d?.relayed === true;
        const claimedKind = typeof d?.kind === 'string' && ABORT_KINDS.has(d.kind) ? (d.kind as AbortKind) : undefined;
        const maxId = Math.max(...this.cfg.nodes.map((x) => x.id));
        const claimedBlame =
          typeof d?.blamed === 'number' && Number.isInteger(d.blamed) && d.blamed >= 0 && d.blamed <= maxId ? d.blamed : null;
        const detail = typeof d?.detail === 'string' ? sanitize(d.detail, 120) : '';
        const claim =
          new NetAbort(
            'peer-abort',
            relayed ? null : l.id,
            this.selfId,
            `peer ${l.id} ${relayed ? 'relayed' : 'reported'} an abort (${claimedKind ?? 'unspecified'}, accuses ${claimedBlame === null ? 'no one' : claimedBlame}, unverified) ${detail}`,
            claimedKind,
            claimedBlame,
            relayed ? { reason: 'relayed abort: a second-hand claim passed on by an honest peer; it names no one and is never evidence' } : {},
          );
        if (this.deferAborts) {
          // Order-preserving: the claim takes effect when it is READ, i.e. only after every frame this peer sent before
          // it (an honest peer always sends its round data before it aborts, on this same in-order link).
          l.inbox.push({ f, size: b.length, abort: claim });
          continue;
        }
        return this.fail(claim, l.id);
      }
      if (f.seq !== l.recvSeq) {
        const kind: AbortKind = f.seq < l.recvSeq ? 'duplicate' : 'out-of-order';
        return this.fail(new NetAbort(kind, l.id, this.selfId, `expected seq ${l.recvSeq}, got ${f.seq} (round ${f.rd})`));
      }
      l.recvSeq++;
      l.framesIn++;
      if (f.ty === 'hello') {
        const d = f.d as { id?: unknown } | null;
        if (l.helloSeen || d?.id !== l.id) {
          return this.fail(new NetAbort('identity', l.id, this.selfId, `hello claims id ${String(d?.id)} on the link pinned to ${l.id}`));
        }
        l.helloSeen = true;
      } else {
        if (!l.helloSeen) return this.fail(new NetAbort('malformed', l.id, this.selfId, 'data before hello'));
        l.inbox.push({ f, size: b.length });
        l.inboxBytes += b.length;
        if (l.inbox.length > this.maxInboxFrames || l.inboxBytes > this.maxInboxBytes) {
          return this.fail(new NetAbort('flood', l.id, this.selfId, `peer ${l.id} queued more than the inbox cap allows`));
        }
        if (!l.paused && (l.inbox.length > this.maxInboxFrames / 2 || l.inboxBytes > this.maxInboxBytes / 2)) {
          l.paused = true;
          l.socket?.pause();
        }
      }
    }
    this.ev.emit('wake');
  }

  private onClosed(l: Link, why: string): void {
    if (l.closed) return;
    l.closed = true;
    if (!this.finished && !this.failure && !l.helloSeen) {
      this.note(`link ${l.id} closed before hello: ${why}`);
    }
    this.ev.emit('wake');
  }

  // ------------------------------------------------------------------ send path

  private sendFrame(l: Link, ty: FrameType, rd: string, d: unknown): void {
    const frame: Frame = { v: WIRE_VERSION, ty, sid: this.cfg.sessionId, seq: l.sendSeq++, rd, d };
    const raw = encodeFrame(frame);
    const outs = this.cfg.tamper && ty !== 'hello' ? this.cfg.tamper({ to: l.id, frame, raw }) : [raw];
    for (const b of outs) {
      if (l.socket && !l.socket.destroyed) {
        l.socket.write(b);
        l.bytesOut += b.length;
      }
    }
    l.framesOut++;
  }

  /** Send a protocol message to one peer. Throws the mesh failure if already aborted (fail closed). */
  send(to: number, round: string, payload: unknown): void {
    if (this.failure) throw this.failure;
    const l = this.links.get(to);
    if (!l) throw new Error(`mesh: no link to ${to}`);
    this.sendFrame(l, 'msg', round, payload);
  }

  broadcast(round: string, payload: unknown, to: readonly number[] = this.peers): void {
    for (const p of to) this.send(p, round, payload);
  }

  /** ECDSA-P256/SHA-256 signature over `data` with this node's TLS identity key (transferable: verifiable against the pinned certificate). */
  sign(data: Uint8Array): Buffer {
    return cryptoSign('sha256', Buffer.from(data), this.cfg.keyPem);
  }

  /** Verify `sig` over `data` against the PINNED certificate of node `peer`. False on any failure (never throws). */
  verify(peer: number, data: Uint8Array, sig: Uint8Array): boolean {
    const n = this.cfg.nodes.find((x) => x.id === peer);
    if (!n || peer === this.selfId) return false;
    try {
      return cryptoVerify('sha256', Buffer.from(data), new X509Certificate(n.certPem).publicKey, Buffer.from(sig));
    } catch {
      return false;
    }
  }

  /** Receive the next message from `from`, which must belong to `round`. Times out; never hangs. */
  async recv(from: number, round: string, timeoutMs = this.recvTimeoutMs): Promise<unknown> {
    const l = this.links.get(from);
    if (!l) throw new Error(`mesh: no link to ${from}`);
    const deadline = this.clock.now() + timeoutMs;
    for (;;) {
      if (this.failure) throw this.failure;
      const it = l.inbox.shift();
      if (it?.abort) {
        this.fail(it.abort, from);
        throw it.abort;
      }
      if (it) {
        const f = it.f;
        l.inboxBytes -= it.size;
        if (l.paused && l.inbox.length <= this.maxInboxFrames / 2 && l.inboxBytes <= this.maxInboxBytes / 2) {
          l.paused = false;
          l.socket?.resume();
        }
        if (f.rd !== round) {
          const e = new NetAbort('wrong-round', from, this.selfId, `expected round '${round}', got '${f.rd}'`);
          this.fail(e);
          throw e;
        }
        return f.d;
      }
      if (l.closed) {
        const e = new NetAbort('disconnect', from, this.selfId, `link to ${from} closed while awaiting '${round}'`);
        this.fail(e);
        throw e;
      }
      const left = deadline - this.clock.now();
      if (left <= 0) {
        const e = new NetAbort('timeout', from, this.selfId, `no '${round}' message from ${from} within ${timeoutMs}ms (deadline ${timeoutMs}ms; a silent peer is blamed on this local observation only)`, undefined, undefined, { deadlineMs: timeoutMs });
        this.fail(e);
        throw e;
      }
      await new Promise<void>((res) => {
        const done = (): void => {
          this.clock.clearTimer(t);
          this.ev.off('wake', done);
          res();
        };
        const t = this.clock.setTimer(done, left);
        this.ev.on('wake', done);
      });
    }
  }

  /**
   * While on, a peer's abort frame does not poison the mesh on arrival: it is queued behind that peer's earlier frames and
   * only takes effect when a receive from that peer reaches it. Used for the blame round, where every party (the honest ones
   * always, before any abort) sends its blame data first: a fast party's abort, in particular a cheater's own claim, then
   * cannot pre-empt an honest party that is still collecting the blame data it needs to name the culprit itself. Turning it
   * off affects only frames that arrive later: an abort already queued still takes effect at the next receive from that peer.
   */
  setDeferAborts(on: boolean): void {
    this.deferAborts = on;
  }

  /** Receive `round` from every peer in `from` concurrently. A failure on any link rejects the whole call. */
  async collect(round: string, from: readonly number[] = this.peers, timeoutMs?: number): Promise<Map<number, unknown>> {
    const got = await Promise.all(from.map(async (p) => [p, await this.recv(p, round, timeoutMs)] as const));
    return new Map(got);
  }

  // ------------------------------------------------------------------ failure / shutdown

  /**
   * Poison the mesh: record the first failure, tell EVERY peer except `skipPeer` (the one that just told us;
   * forwarding the original accusation so an innocent bystander is never blamed for merely closing), close all.
   */
  fail(err: NetAbort, skipPeer?: number): void {
    if (this.failure) return;
    this.failure = err;
    {
      for (const l of this.links.values()) {
        if (l.id === skipPeer) continue;
        if (l.socket && !l.socket.destroyed && !l.closed) {
          try {
            // a forwarded peer-abort stays a claim: we pass on what was claimed, receivers re-attribute to us
            const kind = err.kind === 'peer-abort' ? (err.claimedKind ?? 'peer-abort') : err.kind;
            const blamed = err.kind === 'peer-abort' ? (err.claimedBlame ?? null) : err.blamed;
            this.sendFrameRaw(l, { kind, blamed, detail: sanitize(err.message, 200), ...(err.kind === 'peer-abort' ? { relayed: true } : {}) });
          } catch {
            /* best effort */
          }
        }
      }
    }
    this.ev.emit('wake');
    setTimeout(() => this.closeAll(), 50).unref();
  }

  private sendFrameRaw(l: Link, d: unknown): void {
    const frame: Frame = { v: WIRE_VERSION, ty: 'abort', sid: this.cfg.sessionId, seq: l.sendSeq++, rd: 'abort', d };
    l.socket!.write(encodeFrame(frame));
  }

  /** Normal completion: flush and close. Peers that are still reading will see EOF only after our data. */
  async finish(): Promise<void> {
    this.finished = true;
    await new Promise((r) => setTimeout(r, 100));
    this.closeAll();
  }

  private closeAll(): void {
    for (const l of this.links.values()) l.socket?.end();
    setTimeout(() => {
      for (const l of this.links.values()) l.socket?.destroy();
      this.server?.close();
    }, 100).unref();
  }

  stats(): LinkStats[] {
    return this.peers.map((p) => {
      const l = this.links.get(p)!;
      return {
        peer: p,
        appBytesOut: l.bytesOut,
        appBytesIn: l.bytesIn,
        framesOut: l.framesOut,
        framesIn: l.framesIn,
        tlsBytesWritten: l.socket?.bytesWritten ?? 0,
        tlsBytesRead: l.socket?.bytesRead ?? 0,
      };
    });
  }
}

function newLink(id: number): Link {
  return {
    id,
    socket: null,
    splitter: new FrameSplitter(),
    inbox: [],
    inboxBytes: 0,
    paused: false,
    sendSeq: 0,
    recvSeq: 0,
    closed: false,
    helloSeen: false,
    bytesIn: 0,
    bytesOut: 0,
    framesIn: 0,
    framesOut: 0,
  };
}

/** Printable-ASCII, length-capped copy of untrusted text (no control characters, no log forging). */
function sanitize(x: string, max: number): string {
  return x.replace(/[^\x20-\x7e]/g, '?').slice(0, max);
}
