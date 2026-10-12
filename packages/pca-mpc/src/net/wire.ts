/**
 * Wire format + error taxonomy for the networked MPC transport (research prototype).
 *
 * A frame is `uint32_be length || utf8 JSON`. The JSON is a strict envelope
 * `{ v:2, ty, sid, seq, rd, d }`. Field elements travel as lowercase hex strings and are validated
 * to be canonical (< p) on receipt. Nothing here is cryptography: confidentiality, integrity and peer
 * authentication come from TLS 1.3 with pinned certificates (`mesh.ts`).
 */

import { PRIME } from '../field';

/**
 * Wire/protocol version. 2 = the R4-12 OT-extension tweak (128-bit tweak, session domain from the binding). A peer
 * that sends any other integer `v` is refused with a typed `version` abort (never a silent OT divergence).
 */
export const WIRE_VERSION = 2;
/** Hard cap on a single frame (bytes). A bigger length prefix is treated as hostile and aborts. */
export const MAX_FRAME_BYTES = 4 * 1024 * 1024;

export type FrameType = 'hello' | 'msg' | 'abort';

export interface Frame {
  v: number;
  ty: FrameType;
  sid: string;
  seq: number;
  rd: string;
  d: unknown;
}

/** Why a protocol run aborted. Every abort carries a kind and, when the evidence supports it, a culprit. */
export type AbortKind =
  | 'timeout' //        an expected message never arrived (blames the silent peer)
  | 'disconnect' //     the link closed / reset / failed TLS mid-protocol
  | 'version' //       the peer speaks a different wire/protocol version (e.g. pre-R4-12 OT tweak); upgrade both peers
  | 'malformed' //      undecodable frame, bad schema, bad field element, wrong shape
  | 'oversize' //       length prefix above MAX_FRAME_BYTES
  | 'duplicate' //      a sequence number was replayed
  | 'out-of-order' //   a sequence number skipped ahead
  | 'wrong-round' //    a well-formed frame for a different protocol round
  | 'wrong-session' //  frame from another session (replay across runs)
  | 'identity' //       TLS peer is not the pinned identity for the claimed party
  | 'commitment' //     a commit-then-open value did not open to its commitment
  | 'ot-check' //       an oblivious-transfer consistency check (base-OT proof/commitment, KOS correlation) failed
  | 'mac-check' //      SPDZ MAC-check or a pairwise tag failed (detected cheating; blames a party only when the evidence names one)
  | 'dealer' //        the trusted dealer's preprocessing was wrong or inconsistent (a lying dealer; blames the dealer)
  | 'equivocation' //   two parties' transcripts disagree (a broadcast was inconsistent)
  | 'flood' //          a peer queued more unread frames / bytes than the inbox cap allows
  | 'peer-abort' //     another party told us it aborted; `blamed` is that PEER (its accusation is only a claim)
  | 'local'; //         local invariant / configuration error

export class NetAbort extends Error {
  readonly kind: AbortKind;
  /**
   * The party we blame, or null when the evidence cannot attribute (e.g. a MAC-check failure).
   * For `peer-abort` this is the peer that SENT the abort frame; whom that peer accuses is `claimedBlame`.
   */
  readonly blamed: number | null;
  /** Node that detected / reported it. */
  readonly reporter: number;
  /** For `peer-abort`: the kind the reporting peer gave (an unauthenticated claim by that peer). */
  readonly claimedKind?: AbortKind;
  /** For `peer-abort`: whom the reporting peer accuses. An unverified claim; never used as attribution. */
  readonly claimedBlame?: number | null;
  /**
   * Why `blamed` is null (R3-16/17): attribution is impossible from this party's evidence and the abort says so
   * explicitly. `null` when a party IS blamed. Never empty when `blamed` is null.
   */
  readonly reason: string | null;
  /**
   * What the blame rests on, when it is transferable: for an `equivocation` the two statements the culprit SIGNED
   * (a third party can verify both against the culprit's pinned certificate). Absent for first-hand observations
   * (a timeout, a failed commitment opening, a bad share), which convince only the observer.
   */
  readonly evidence?: unknown;
  /** For a `timeout`: the deadline (ms) that elapsed. A silent peer is indistinguishable from a slow or partitioned honest one. */
  readonly deadlineMs?: number;

  constructor(
    kind: AbortKind,
    blamed: number | null,
    reporter: number,
    detail: string,
    claimedKind?: AbortKind,
    claimedBlame?: number | null,
    opts: { reason?: string; evidence?: unknown; deadlineMs?: number } = {},
  ) {
    super(`[${kind}] blamed=${blamed === null ? 'none' : blamed} reporter=${reporter}: ${detail}`);
    this.name = 'NetAbort';
    this.kind = kind;
    this.blamed = blamed;
    this.reporter = reporter;
    this.claimedKind = claimedKind;
    this.claimedBlame = claimedBlame;
    this.reason = blamed === null ? (opts.reason !== undefined && opts.reason.length > 0 ? opts.reason : 'unattributable: the evidence available to this party does not identify a culprit') : null;
    if (opts.evidence !== undefined) this.evidence = opts.evidence;
    if (opts.deadlineMs !== undefined) this.deadlineMs = opts.deadlineMs;
  }
}

export function encodeFrame(f: Frame): Buffer {
  const body = Buffer.from(JSON.stringify(f), 'utf8');
  if (body.length > MAX_FRAME_BYTES) throw new Error('frame too large');
  const out = Buffer.allocUnsafe(4 + body.length);
  out.writeUInt32BE(body.length, 0);
  body.copy(out, 4);
  return out;
}

/** All abort kinds, for validating a kind claimed by a peer. */
export const ABORT_KINDS: ReadonlySet<string> = new Set<AbortKind>([
  'timeout', 'disconnect', 'version', 'malformed', 'oversize', 'duplicate', 'out-of-order', 'wrong-round', 'wrong-session',
  'identity', 'commitment', 'ot-check', 'mac-check', 'dealer', 'equivocation', 'flood', 'peer-abort', 'local',
]);

/**
 * Incremental length-prefixed frame splitter in linear time: incoming chunks are queued and a frame body is
 * materialised once, when it is complete (never by re-concatenating the whole buffer per chunk).
 * `push` throws a plain Error('oversize') on a hostile length.
 */
export class FrameSplitter {
  private chunks: Buffer[] = [];
  private head = 0; // read offset inside chunks[0]
  private have = 0; // unread bytes queued

  push(chunk: Buffer): Buffer[] {
    if (chunk.length > 0) {
      this.chunks.push(chunk);
      this.have += chunk.length;
    }
    const out: Buffer[] = [];
    for (;;) {
      if (this.have < 4) break;
      const len = this.peekLen();
      if (len > MAX_FRAME_BYTES) throw new Error('oversize');
      if (this.have < 4 + len) break;
      this.take(4);
      out.push(this.take(len));
    }
    return out;
  }

  private peekLen(): number {
    let v = 0;
    let need = 4;
    let ci = 0;
    let off = this.head;
    while (need > 0) {
      const c = this.chunks[ci]!;
      while (off < c.length && need > 0) {
        v = v * 256 + c[off++]!;
        need--;
      }
      ci++;
      off = 0;
    }
    return v;
  }

  private take(len: number): Buffer {
    if (len === 0) return Buffer.alloc(0);
    const first = this.chunks[0]!;
    let out: Buffer;
    let ci = 0;
    if (first.length - this.head >= len) {
      out = first.subarray(this.head, this.head + len);
      this.head += len;
    } else {
      out = Buffer.allocUnsafe(len);
      let w = 0;
      while (w < len) {
        const c = this.chunks[ci]!;
        const n = Math.min(c.length - this.head, len - w);
        c.copy(out, w, this.head, this.head + n);
        w += n;
        this.head += n;
        if (this.head === c.length && w < len) {
          ci++;
          this.head = 0;
        }
      }
    }
    this.have -= len;
    if (this.head === this.chunks[ci]!.length) {
      ci++;
      this.head = 0;
    }
    if (ci > 0) this.chunks = this.chunks.slice(ci);
    return out;
  }
}

const FRAME_TYPES: ReadonlySet<string> = new Set(['hello', 'msg', 'abort']);

/** The integer `v` of a frame body, or null when the body is not a JSON object carrying one. Used only to type a version-mismatch abort. */
export function peekVersion(body: Buffer): number | null {
  try {
    const j = JSON.parse(body.toString('utf8')) as unknown;
    if (typeof j !== 'object' || j === null || Array.isArray(j)) return null;
    const v = (j as Record<string, unknown>).v;
    return typeof v === 'number' && Number.isSafeInteger(v) ? v : null;
  } catch {
    return null;
  }
}

function parseObject(body: Buffer): Record<string, unknown> | null {
  let j: unknown;
  try {
    j = JSON.parse(body.toString('utf8'));
  } catch {
    return null;
  }
  if (typeof j !== 'object' || j === null || Array.isArray(j)) return null;
  return j as Record<string, unknown>;
}

/** Every envelope rule except the version: exactly the six keys, known type, string sid/rd, non-negative safe seq. */
function envelopeShapeOk(o: Record<string, unknown>): boolean {
  if (Object.keys(o).length !== 6 || !('v' in o)) return false;
  if (typeof o.ty !== 'string' || !FRAME_TYPES.has(o.ty)) return false;
  if (typeof o.sid !== 'string' || typeof o.rd !== 'string') return false;
  if (typeof o.seq !== 'number' || !Number.isSafeInteger(o.seq) || o.seq < 0) return false;
  return 'd' in o;
}

/** Strict envelope parse. Returns null on ANY deviation (the caller aborts blaming the sender). */
export function parseFrame(body: Buffer): Frame | null {
  const o = parseObject(body);
  if (o === null || o.v !== WIRE_VERSION || !envelopeShapeOk(o)) return null;
  return o as unknown as Frame;
}

/**
 * The peer's version when `body` is a well-formed frame in every respect except an integer `v` other than
 * {@link WIRE_VERSION}; null otherwise. R6-CORE-06: only such a frame earns a `version` abort; garbage that merely
 * carries some integer `v` is `malformed`.
 */
export function versionMismatch(body: Buffer): number | null {
  const o = parseObject(body);
  if (o === null || typeof o.v !== 'number' || !Number.isSafeInteger(o.v) || o.v === WIRE_VERSION) return null;
  return envelopeShapeOk(o) ? o.v : null;
}

// ---- field-element codec (canonical lowercase hex, strictly < p) ----

export const hx = (x: bigint): string => x.toString(16);

const HEX61 = /^(0|[1-9a-f][0-9a-f]{0,15})$/;

/** Decode a canonical field element; returns null if not a canonical hex string < p. */
export function unhx(s: unknown): bigint | null {
  if (typeof s !== 'string' || !HEX61.test(s)) return null;
  const v = BigInt('0x' + s);
  return v < PRIME ? v : null;
}

/** Decode an array of exactly `len` canonical field elements, or null. */
export function unhxArray(a: unknown, len: number): bigint[] | null {
  if (!Array.isArray(a) || a.length !== len) return null;
  const out: bigint[] = [];
  for (const s of a) {
    const v = unhx(s);
    if (v === null) return null;
    out.push(v);
  }
  return out;
}
