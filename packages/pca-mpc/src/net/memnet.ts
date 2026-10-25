/**
 * TEST SUPPORT: an in-memory stand-in for `Mesh` that lets `runParty` / `runDealer` / the OT rounds run inside one process.
 * It mirrors the parts of the Mesh contract the protocol relies on: per-pair FIFO delivery, a round name on every message,
 * wrong-round / timeout / disconnect aborts, fail-closed after a failure, abort propagation to the peers, and byte stats.
 */
import { createHash, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { NetAbort, type AbortKind } from './wire';

export interface MemTap {
  /** Return the payload to deliver (possibly modified), or `undefined` to drop the message. */
  (from: number, to: number, rd: string, payload: unknown): unknown | undefined;
}

export class MemNet {
  readonly nodes = new Map<number, MemMesh>();
  readonly keys = new Map<number, { priv: KeyObject; pub: KeyObject }>();
  constructor(
    readonly ids: number[],
    readonly sessionId: string,
    readonly recvTimeoutMs = 20_000,
    public tap: MemTap | null = null,
  ) {
    for (const id of ids) {
      const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      this.keys.set(id, { priv: privateKey, pub: publicKey });
    }
    for (const id of ids) this.nodes.set(id, new MemMesh(this, id, ids.filter((i) => i !== id)));
  }
  mesh(id: number): MemMesh {
    return this.nodes.get(id)!;
  }
}

interface Q {
  /** `abort` marks a peer's abort claim queued behind that peer's earlier messages (see `setDeferAborts`). */
  items: Array<{ rd: string; d: unknown; size: number; abort?: NetAbort }>;
  closed: boolean;
}

/** Same public surface as `Mesh` for everything the protocol layers use. */
export class MemMesh {
  failure: NetAbort | null = null;
  finished = false;
  readonly events: string[] = [];
  readonly sent: Array<{ to: number; rd: string; d: unknown }> = [];
  private readonly inbox = new Map<number, Q>();
  private bytesOut = new Map<number, number>();
  private bytesIn = new Map<number, number>();
  private waiters: Array<() => void> = [];
  private deferAborts = false;
  constructor(
    private readonly net: MemNet,
    readonly selfId: number,
    readonly peers: number[],
  ) {
    for (const p of peers) {
      this.inbox.set(p, { items: [], closed: false });
      this.bytesOut.set(p, 0);
      this.bytesIn.set(p, 0);
    }
  }
  get sessionId(): string {
    return this.net.sessionId;
  }
  get failed(): NetAbort | null {
    return this.failure;
  }
  private wake(): void {
    for (const w of this.waiters.splice(0)) w();
  }
  send(to: number, rd: string, payload: unknown): void {
    if (this.failure) throw this.failure;
    const dst = this.net.nodes.get(to);
    if (!dst || !this.inbox.has(to)) throw new Error(`mesh: no link to ${to}`);
    const wire = JSON.parse(JSON.stringify(payload ?? null)) as unknown;
    this.sent.push({ to, rd, d: wire });
    const size = JSON.stringify(wire ?? null).length + rd.length;
    this.bytesOut.set(to, this.bytesOut.get(to)! + size);
    const d = this.net.tap ? this.net.tap(this.selfId, to, rd, wire) : wire;
    if (d === undefined) return;
    if (dst.failure) return;
    dst.inbox.get(this.selfId)!.items.push({ rd, d, size });
    dst.bytesIn.set(this.selfId, dst.bytesIn.get(this.selfId)! + size);
    dst.wake();
  }
  broadcast(rd: string, payload: unknown, to: readonly number[] = this.peers): void {
    for (const p of to) this.send(p, rd, payload);
  }
  async recv(from: number, rd: string, timeoutMs = this.net.recvTimeoutMs): Promise<unknown> {
    const q = this.inbox.get(from);
    if (!q) throw new Error(`mesh: no link to ${from}`);
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      if (this.failure) throw this.failure;
      const it = q.items.shift();
      if (it?.abort) {
        this.fail(it.abort, from);
        throw it.abort;
      }
      if (it) {
        if (it.rd !== rd) {
          const e = new NetAbort('wrong-round', from, this.selfId, `expected round '${rd}', got '${it.rd}'`);
          this.fail(e);
          throw e;
        }
        return it.d;
      }
      if (q.closed) {
        const e = new NetAbort('disconnect', from, this.selfId, `link to ${from} closed while awaiting '${rd}'`);
        this.fail(e);
        throw e;
      }
      const left = deadline - Date.now();
      if (left <= 0) {
        const e = new NetAbort('timeout', from, this.selfId, `no '${rd}' message from ${from} within ${timeoutMs}ms`, undefined, undefined, { deadlineMs: timeoutMs });
        this.fail(e);
        throw e;
      }
      await new Promise<void>((res) => {
        const t = setTimeout(done, left);
        function done(): void {
          clearTimeout(t);
          res();
        }
        this.waiters.push(done);
      });
    }
  }
  async collect(rd: string, from: readonly number[] = this.peers, timeoutMs?: number): Promise<Map<number, unknown>> {
    const got = await Promise.all(from.map(async (p) => [p, await this.recv(p, rd, timeoutMs)] as const));
    return new Map(got);
  }
  sign(data: Uint8Array): Buffer {
    return cryptoSign('sha256', Buffer.from(data), this.net.keys.get(this.selfId)!.priv);
  }
  verify(peer: number, data: Uint8Array, sig: Uint8Array): boolean {
    const k = this.net.keys.get(peer);
    if (!k || peer === this.selfId) return false;
    try {
      return cryptoVerify('sha256', Buffer.from(data), k.pub, Buffer.from(sig));
    } catch {
      return false;
    }
  }
  /** As `Mesh.setDeferAborts`: while on, a peer's abort claim is queued behind its earlier messages instead of poisoning this node. */
  setDeferAborts(on: boolean): void {
    this.deferAborts = on;
  }
  /** Poison this node and tell every peer (they stop with a `peer-abort` naming this node as the authenticated sender). */
  fail(err: NetAbort, skipPeer?: number): void {
    if (this.failure) return;
    this.failure = err;
    for (const p of this.peers) {
      if (p === skipPeer) continue;
      const peer = this.net.nodes.get(p)!;
      if (peer.failure) continue;
      const kind: AbortKind = err.kind === 'peer-abort' ? (err.claimedKind ?? 'peer-abort') : err.kind;
      const blamed = err.kind === 'peer-abort' ? (err.claimedBlame ?? null) : err.blamed;
      const claim = new NetAbort('peer-abort', this.selfId, p, `peer ${this.selfId} reported an abort (${kind}, accuses ${blamed === null ? 'no one' : blamed}, unverified) ${err.message.slice(0, 120)}`, kind, blamed);
      // As `Mesh`: a deferring peer reads the claim in order, behind the messages this node sent it before.
      if (peer.deferAborts) peer.inbox.get(this.selfId)!.items.push({ rd: 'abort', d: null, size: 0, abort: claim });
      else peer.failure = claim;
    }
    for (const p of this.peers) this.net.nodes.get(p)!.wake();
    this.wake();
  }
  /** Simulate this node's process dying: peers see a closed link. */
  kill(): void {
    for (const p of this.peers) {
      const peer = this.net.nodes.get(p)!;
      peer.inbox.get(this.selfId)!.closed = true;
      peer.wake();
    }
  }
  async finish(): Promise<void> {
    this.finished = true;
    await new Promise((r) => setTimeout(r, 0));
  }
  stats(): Array<{ peer: number; appBytesOut: number; appBytesIn: number; framesOut: number; framesIn: number; tlsBytesWritten: number; tlsBytesRead: number }> {
    return this.peers.map((p) => ({
      peer: p,
      appBytesOut: this.bytesOut.get(p)!,
      appBytesIn: this.bytesIn.get(p)!,
      framesOut: 0,
      framesIn: 0,
      tlsBytesWritten: 0,
      tlsBytesRead: 0,
    }));
  }
}

export const digestOf = (x: unknown): string => createHash('sha256').update(JSON.stringify(x)).digest('hex');
