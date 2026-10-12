/**
 * TEST-ONLY fault injection for the networked MPC.
 *
 * Two layers, deliberately separate:
 *  - `tamperFor(spec)`: a MALICIOUS SENDER rewriting its own outgoing frames at the application layer
 *    (duplicate, reorder, skipped sequence, garbage, truncation, wrong round/session, oversize length,
 *    drop, silence). The bytes still travel inside valid TLS, so the receiver's framing checks decide.
 *  - `FaultProxy`: a NETWORK adversary on the wire (TCP middlebox): drop / delay / truncate / bit-flip /
 *    duplicate / reorder at the byte level. TLS 1.3 record authentication rejects tampering, so the
 *    expected outcome is an attributable-to-the-link `disconnect`, never a silently corrupted value.
 */

import * as net from 'node:net';
import { encodeFrame, type Frame } from './wire';
import type { TamperEvent } from './mesh';

export type FrameFaultKind =
  | 'duplicate'
  | 'reorder'
  | 'skip-seq'
  | 'garbage'
  | 'truncate'
  | 'bitflip'
  | 'wrong-round'
  | 'wrong-session'
  | 'oversize'
  | 'drop'
  | 'silent-from'
  | 'extra-field'
  | 'false-accuse'; // replace the frame with an abort frame that accuses `accuse`

export interface FrameFault {
  kind: FrameFaultKind;
  /** Protocol round to attack (e.g. 'mul0'). */
  round: string;
  /** Restrict to one recipient; default: all recipients. */
  to?: number;
  /** For `false-accuse`: the (honest) party the malicious sender names in its forged abort frame. */
  accuse?: number;
}

export function tamperFor(spec: FrameFault): (ev: TamperEvent) => Buffer[] {
  const stash = new Map<number, Buffer>();
  let silent = false;
  return (ev: TamperEvent): Buffer[] => {
    if (silent) return [];
    const hit = ev.frame.rd === spec.round && (spec.to === undefined || spec.to === ev.to);
    if (spec.kind === 'reorder') {
      const held = stash.get(ev.to);
      if (held) {
        stash.delete(ev.to);
        return [ev.raw, held]; // later frame first, then the held-back one
      }
      if (hit) {
        stash.set(ev.to, ev.raw);
        return [];
      }
      return [ev.raw];
    }
    if (!hit) return [ev.raw];
    switch (spec.kind) {
      case 'duplicate':
        return [ev.raw, ev.raw];
      case 'skip-seq':
        return [encodeFrame({ ...ev.frame, seq: ev.frame.seq + 1 })];
      case 'garbage': {
        const g = Buffer.alloc(ev.raw.length, 0x5a);
        g.writeUInt32BE(ev.raw.length - 4, 0);
        return [g];
      }
      case 'truncate':
        return [ev.raw.subarray(0, Math.max(5, Math.floor(ev.raw.length / 2)))];
      case 'bitflip': {
        const b = Buffer.from(ev.raw);
        const i = Math.floor(b.length * 0.6);
        b[i] = b[i]! ^ 0x04;
        return [b];
      }
      case 'wrong-round':
        return [encodeFrame({ ...ev.frame, rd: 'zzz-' + ev.frame.rd })];
      case 'wrong-session':
        return [encodeFrame({ ...ev.frame, sid: 'not-this-session' })];
      case 'oversize': {
        const h = Buffer.alloc(4);
        h.writeUInt32BE(0x7fffffff, 0);
        return [h];
      }
      case 'drop':
        return [];
      case 'silent-from':
        silent = true;
        return [];
      case 'false-accuse':
        return [
          encodeFrame({ ...ev.frame, ty: 'abort', rd: 'abort', d: { kind: 'timeout', blamed: spec.accuse ?? 0, detail: 'forged accusation' } }),
        ];
      case 'extra-field':
        return [encodeFrame({ ...(ev.frame as Frame), x: 1 } as unknown as Frame)];
    }
  };
}

// ----------------------------------------------------------------------------- TCP fault proxy

export type WireFaultKind = 'none' | 'drop' | 'delay' | 'truncate' | 'bitflip' | 'duplicate' | 'reorder';

export interface WireFault {
  kind: WireFaultKind;
  /** Which direction through the proxy: client->server ('c2s') or server->client ('s2c'). */
  dir: 'c2s' | 's2c';
  /** Fault starts after this many bytes have passed in that direction (skips the TLS handshake). */
  afterBytes: number;
  /** delay milliseconds (kind=delay). */
  ms?: number;
}

/** A transparent TCP proxy that misbehaves once, after `afterBytes` bytes, in one direction. */
export class FaultProxy {
  private server: net.Server;
  readonly log: string[] = [];

  constructor(
    readonly listenPort: number,
    private readonly target: { host: string; port: number },
    private readonly fault: WireFault,
  ) {
    this.server = net.createServer((c) => this.onClient(c));
  }

  listen(): Promise<void> {
    return new Promise((res, rej) => {
      this.server.once('error', rej);
      this.server.listen(this.listenPort, '127.0.0.1', () => res());
    });
  }

  close(): void {
    this.server.close();
  }

  private onClient(c: net.Socket): void {
    const up = net.connect(this.target.port, this.target.host);
    c.on('error', () => up.destroy());
    up.on('error', () => c.destroy());
    c.on('close', () => up.destroy());
    up.on('close', () => c.destroy());
    this.pipe(c, up, 'c2s');
    this.pipe(up, c, 's2c');
  }

  private pipe(from: net.Socket, to: net.Socket, dir: 'c2s' | 's2c'): void {
    const f = this.fault;
    const active = f.kind !== 'none' && f.dir === dir;
    let seen = 0;
    let fired = false;
    let done = false;
    let held: Buffer | null = null;
    let pending = 0; // delayed writes in flight: a half-close must not overtake them
    let ended = false;
    from.on('data', (chunk: Buffer) => {
      const before = seen;
      seen += chunk.length;
      if (!active || done || before + chunk.length <= f.afterBytes) {
        if (active && f.kind === 'drop' && fired) return; // black hole stays black
        to.write(chunk);
        return;
      }
      if (!fired) {
        fired = true;
        this.log.push(`fault ${f.kind} ${dir} after ${f.afterBytes}B`);
      }
      switch (f.kind) {
        case 'drop':
          return;
        case 'delay':
          pending++;
          setTimeout(() => {
            if (!to.destroyed) to.write(chunk);
            pending--;
            if (pending === 0 && ended) to.end();
          }, f.ms ?? 1000);
          return;
        case 'truncate':
          done = true;
          to.write(chunk.subarray(0, Math.floor(chunk.length / 2)));
          to.end();
          return;
        case 'bitflip': {
          done = true;
          const b = Buffer.from(chunk);
          const i = Math.floor(b.length / 2);
          b[i] = b[i]! ^ 0x01;
          to.write(b);
          return;
        }
        case 'duplicate':
          done = true;
          to.write(chunk);
          to.write(chunk);
          return;
        case 'reorder':
          if (!held) {
            held = chunk;
          } else {
            done = true;
            to.write(chunk);
            to.write(held);
            held = null;
          }
          return;
        default:
          to.write(chunk);
      }
    });
    from.on('end', () => {
      if (held) to.write(held);
      ended = true;
      if (pending === 0) to.end();
    });
  }
}
