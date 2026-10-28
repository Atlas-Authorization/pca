import { b64u, decodeB64uStrict, utf8 } from './hash';
import { strictParseBytes } from './strict-json';
import type { ParticipantId } from './frost';
import {
  dkgCheckEchoes,
  dkgEcho,
  dkgFileComplaint,
  dkgFinalize,
  dkgQualifiedSet,
  dkgRebut,
  dkgRound1,
  dkgRound2,
  dkgVerifyComplaint,
  dkgVerifyRound1,
  dkgVerifyShare,
  type DkgComplaint,
  type DkgEcho,
  type DkgKeyPackage,
  type DkgReceivedShare,
  type DkgRebuttal,
  type DkgRound1Package,
  type DkgShareToSend,
} from './frost-dkg';

/**
 * AUTHENTICATED-CHANNEL INTERFACE FOR THE FROST DKG.
 *
 * `frost-dkg.ts` produces and verifies the protocol messages but, by its own header, assumes an authenticated broadcast
 * and private authenticated point-to-point links. This module states that assumption as an interface and enforces what
 * the protocol can enforce on top of it:
 *
 *  - The CHANNEL supplies the sender's identity (for a TLS channel, the pinned certificate); the message never does.
 *    Every driver check compares the channel-authenticated sender with the identifier inside the message.
 *  - A message names one session; a message for another session is refused.
 *  - A second message of the same kind from the same sender is refused (identical = `duplicate`, different =
 *    `equivocation`), and the refusal is sticky for that peer.
 *  - Every message is size-capped before it is parsed, parsed with the strict JSON profile, and shape-checked with
 *    exact member sets. Nothing malformed is repaired.
 *  - A missing message at the timeout aborts the run (fail closed); nothing is finalized on a partial view.
 *  - Transcript equivocation (a dealer showing different parties different packages) is caught by the existing echo
 *    round, which the driver always runs.
 *
 * What the channel must provide (the interface cannot check it): confidentiality and integrity of every message, and
 * that `collect` reports a message under the identity of the party that really sent it. {@link createMemoryDkgNetwork}
 * is the in-process reference; `frost-dkg-tls.ts` is the reference mutual-TLS implementation.
 */

export const DKG_WIRE_VERSION = 1 as const;
/** Largest wire message a channel accepts, checked before parsing. */
export const DKG_MAX_MESSAGE_BYTES = 256 * 1024;
/** Largest participant set the driver accepts. */
export const DKG_MAX_PARTICIPANTS = 256;

export const DKG_MESSAGE_KINDS = ['round1', 'share', 'complaints', 'rebuttals', 'echo'] as const;
export type DkgMessageKind = (typeof DKG_MESSAGE_KINDS)[number];

export type DkgChannelErrorCode =
  | 'timeout'
  | 'identity'
  | 'wrong-session'
  | 'duplicate'
  | 'equivocation'
  | 'malformed'
  | 'oversize'
  | 'closed'
  | 'protocol'
  | 'disqualified';

/** Every channel and driver refusal. `peer` is the authenticated party the refusal is about, when known. */
export class DkgChannelError extends Error {
  readonly code: DkgChannelErrorCode;
  readonly peer: ParticipantId | undefined;
  constructor(code: DkgChannelErrorCode, peer: ParticipantId | undefined, message: string) {
    super(`dkg channel (${code}${peer === undefined ? '' : `, peer ${peer}`}): ${message}`);
    this.name = 'DkgChannelError';
    this.code = code;
    this.peer = peer;
  }
}

/** One participant's end of the authenticated channel. */
export interface DkgChannel {
  readonly self: ParticipantId;
  /** Every other participant this channel is connected to, ascending. */
  readonly peers: readonly ParticipantId[];
  /** Authenticated broadcast of `body` to every peer. */
  broadcast(kind: DkgMessageKind, body: unknown): Promise<void>;
  /** Private, authenticated delivery of `body` to one peer. */
  send(to: ParticipantId, kind: DkgMessageKind, body: unknown): Promise<void>;
  /**
   * Wait for exactly one `kind` message from each of `from` and return the bodies keyed by the AUTHENTICATED sender.
   * Rejects with {@link DkgChannelError} on timeout, a duplicate or divergent second message, a malformed, oversize or
   * wrong-session message from any of `from`, or a closed channel.
   */
  collect(kind: DkgMessageKind, from: readonly ParticipantId[], timeoutMs: number): Promise<Map<ParticipantId, unknown>>;
  close(): Promise<void>;
}

// ---- wire envelope ------------------------------------------------------------------------------

/** Encode one wire message. */
export function encodeDkgMessage(sessionId: Uint8Array, kind: DkgMessageKind, body: unknown): Uint8Array {
  const bytes = utf8(JSON.stringify({ v: DKG_WIRE_VERSION, sid: b64u(sessionId), kind, body }));
  if (bytes.length > DKG_MAX_MESSAGE_BYTES) throw new DkgChannelError('oversize', undefined, `message of ${bytes.length} bytes exceeds the cap`);
  return bytes;
}

/** Strictly decode one wire message for `sessionId`. Typed {@link DkgChannelError} on every deviation. */
export function decodeDkgMessage(bytes: Uint8Array, sessionId: Uint8Array): { kind: DkgMessageKind; body: unknown } {
  if (!(bytes instanceof Uint8Array)) throw new DkgChannelError('malformed', undefined, 'message is not bytes');
  if (bytes.length > DKG_MAX_MESSAGE_BYTES) throw new DkgChannelError('oversize', undefined, `message of ${bytes.length} bytes exceeds the cap`);
  let msg: unknown;
  try {
    msg = strictParseBytes(bytes);
  } catch {
    throw new DkgChannelError('malformed', undefined, 'message is not strict JSON');
  }
  const o = asRecord(msg, ['v', 'sid', 'kind', 'body'], 'envelope');
  if (o.v !== DKG_WIRE_VERSION) throw new DkgChannelError('malformed', undefined, 'unsupported wire version');
  if (typeof o.kind !== 'string' || !(DKG_MESSAGE_KINDS as readonly string[]).includes(o.kind)) {
    throw new DkgChannelError('malformed', undefined, 'unknown message kind');
  }
  if (o.sid !== b64u(sessionId)) throw new DkgChannelError('wrong-session', undefined, 'message names another session');
  return { kind: o.kind as DkgMessageKind, body: o.body };
}

function asRecord(x: unknown, keys: readonly string[], what: string): Record<string, unknown> {
  if (x === null || typeof x !== 'object' || Array.isArray(x)) throw new DkgChannelError('malformed', undefined, `${what} is not an object`);
  const got = Object.keys(x);
  if (got.length !== keys.length || !keys.every((k) => got.includes(k))) {
    throw new DkgChannelError('malformed', undefined, `${what} has unexpected or missing members`);
  }
  return x as Record<string, unknown>;
}

function posInt(x: unknown, what: string): number {
  if (typeof x !== 'number' || !Number.isSafeInteger(x) || x <= 0) throw new DkgChannelError('malformed', undefined, `${what} is not a positive integer`);
  return x;
}

function b64Field(x: unknown, what: string, len?: number): string {
  if (decodeB64uStrict(x, len) === null) throw new DkgChannelError('malformed', undefined, `${what} is not canonical base64url`);
  return x as string;
}

// ---- message-body decoders (exported: fuzzed) -------------------------------------------------------

/** Decode a round-1 package body. `t` is the threshold the package must commit to. */
export function decodeDkgRound1Package(x: unknown, t: number): DkgRound1Package {
  const o = asRecord(x, ['identifier', 'sessionId', 'coefficientCommitments', 'proofOfKnowledge'], 'round-1 package');
  const pok = asRecord(o.proofOfKnowledge, ['R', 'mu'], 'proof of knowledge');
  const cc = o.coefficientCommitments;
  if (!Array.isArray(cc) || cc.length !== t) throw new DkgChannelError('malformed', undefined, `round-1 package must commit to exactly t=${t} coefficients`);
  return {
    identifier: posInt(o.identifier, 'identifier'),
    sessionId: b64Field(o.sessionId, 'sessionId'),
    coefficientCommitments: cc.map((c) => b64Field(c, 'coefficient commitment', 32)),
    proofOfKnowledge: { R: b64Field(pok.R, 'PoP R', 32), mu: b64Field(pok.mu, 'PoP mu', 32) },
  };
}

/** Decode a private share body into the wire form (`share` as bytes). */
export function decodeDkgShareMessage(x: unknown): DkgShareToSend {
  const o = asRecord(x, ['from', 'to', 'sessionId', 'share', 'sig'], 'share message');
  return {
    from: posInt(o.from, 'from'),
    to: posInt(o.to, 'to'),
    sessionId: b64Field(o.sessionId, 'sessionId'),
    share: decodeB64uStrict(b64Field(o.share, 'share', 32))!,
    sig: b64Field(o.sig, 'share signature', 64),
  };
}

function complaintOf(x: unknown): DkgComplaint {
  const o = asRecord(x, ['accused', 'accuser', 'sessionId', 'revealedShare', 'shareSig'], 'complaint');
  return {
    accused: posInt(o.accused, 'accused'),
    accuser: posInt(o.accuser, 'accuser'),
    sessionId: b64Field(o.sessionId, 'sessionId'),
    revealedShare: b64Field(o.revealedShare, 'revealed share', 32),
    shareSig: b64Field(o.shareSig, 'share signature', 64),
  };
}

function rebuttalOf(x: unknown): DkgRebuttal {
  const o = asRecord(x, ['accused', 'accuser', 'sessionId', 'presentedShare', 'shareSig'], 'rebuttal');
  return {
    accused: posInt(o.accused, 'accused'),
    accuser: posInt(o.accuser, 'accuser'),
    sessionId: b64Field(o.sessionId, 'sessionId'),
    presentedShare: b64Field(o.presentedShare, 'presented share', 32),
    shareSig: b64Field(o.shareSig, 'share signature', 64),
  };
}

function listOf<T>(x: unknown, key: string, one: (v: unknown) => T): T[] {
  const o = asRecord(x, [key], key);
  const l = o[key];
  if (!Array.isArray(l) || l.length > DKG_MAX_PARTICIPANTS) throw new DkgChannelError('malformed', undefined, `${key} is not a bounded list`);
  return l.map(one);
}

/** Decode a complaints body (`{ complaints: [...] }`, possibly empty). */
export const decodeDkgComplaints = (x: unknown): DkgComplaint[] => listOf(x, 'complaints', complaintOf);
/** Decode a rebuttals body (`{ rebuttals: [...] }`, possibly empty). */
export const decodeDkgRebuttals = (x: unknown): DkgRebuttal[] => listOf(x, 'rebuttals', rebuttalOf);

/** Decode an echo body. */
export function decodeDkgEcho(x: unknown): DkgEcho {
  const o = asRecord(x, ['identifier', 'sessionId', 'transcriptDigest'], 'echo');
  return {
    identifier: posInt(o.identifier, 'identifier'),
    sessionId: b64Field(o.sessionId, 'sessionId'),
    transcriptDigest: b64Field(o.transcriptDigest, 'transcript digest', 32),
  };
}

// ---- shared inbox (used by every channel implementation) ----------------------------------------------

/**
 * Receive side shared by channel implementations: holds at most one message per (kind, authenticated sender), records a
 * sticky error per peer, and implements `collect`. A channel calls {@link DkgInbox.accept} with the AUTHENTICATED sender.
 */
export class DkgInbox {
  readonly #seen = new Map<string, { digest: string; body: unknown }>();
  readonly #errors = new Map<ParticipantId, DkgChannelError>();
  readonly #waiters = new Set<() => void>();
  readonly #gone = new Set<ParticipantId>();
  #closed = false;

  readonly sessionId: Uint8Array;
  readonly peers: readonly ParticipantId[];

  constructor(sessionId: Uint8Array, peers: readonly ParticipantId[]) {
    this.sessionId = sessionId;
    this.peers = peers;
  }

  /** Record a peer failure (first one wins). */
  fail(peer: ParticipantId, err: DkgChannelError): void {
    if (!this.#errors.has(peer)) this.#errors.set(peer, new DkgChannelError(err.code, peer, err.message.replace(/^dkg channel \([^)]*\): /, '')));
    this.#wake();
  }

  /** Accept one wire message from the authenticated `sender`. Never throws; a bad message becomes a sticky peer error. */
  accept(sender: ParticipantId, bytes: Uint8Array): void {
    if (!this.peers.includes(sender)) return; // not a participant: nothing to attribute to
    try {
      const { kind, body } = decodeDkgMessage(bytes, this.sessionId);
      const key = `${kind}\u0000${sender}`;
      const digest = b64u(bytes);
      const prev = this.#seen.get(key);
      if (prev) {
        throw new DkgChannelError(prev.digest === digest ? 'duplicate' : 'equivocation', sender, `second ${kind} message`);
      }
      this.#seen.set(key, { digest, body });
      this.#wake();
    } catch (e) {
      this.fail(sender, e instanceof DkgChannelError ? e : new DkgChannelError('malformed', sender, 'undecodable message'));
    }
  }

  /** The link to `peer` ended. Soft: only matters if a message that peer owed is still missing. */
  peerGone(peer: ParticipantId): void {
    this.#gone.add(peer);
    this.#wake();
  }

  close(): void {
    this.#closed = true;
    this.#wake();
  }

  #wake(): void {
    for (const w of [...this.#waiters]) w();
  }

  async collect(kind: DkgMessageKind, from: readonly ParticipantId[], timeoutMs: number): Promise<Map<ParticipantId, unknown>> {
    const want = [...from].sort((a, b) => a - b);
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      for (const id of want) {
        const e = this.#errors.get(id);
        if (e) throw e;
      }
      const out = new Map<ParticipantId, unknown>();
      for (const id of want) {
        const m = this.#seen.get(`${kind}\u0000${id}`);
        if (m) out.set(id, m.body);
      }
      if (out.size === want.length) return out;
      if (this.#closed) throw new DkgChannelError('closed', undefined, 'channel closed before all messages arrived');
      const gone = want.find((id) => !out.has(id) && this.#gone.has(id));
      if (gone !== undefined) throw new DkgChannelError('closed', gone, `link ended before its ${kind} message arrived`);
      const left = deadline - Date.now();
      if (left <= 0) {
        const missing = want.filter((id) => !out.has(id));
        throw new DkgChannelError('timeout', missing[0], `no ${kind} message from ${missing.join(',')}`);
      }
      await new Promise<void>((resolve) => {
        let timer: ReturnType<typeof setTimeout>;
        const done = (): void => {
          clearTimeout(timer);
          this.#waiters.delete(done);
          resolve();
        };
        timer = setTimeout(done, left);
        this.#waiters.add(done);
      });
    }
  }
}

// ---- in-memory reference channel -----------------------------------------------------------------------

export interface MemoryDkgDelivery {
  from: ParticipantId;
  to: ParticipantId;
  bytes: Uint8Array;
}

export interface MemoryDkgNetwork {
  channels: Map<ParticipantId, DkgChannel>;
  /** Adversary hook: deliver raw `bytes` to `to` as if sent by `from` (the adversary controls `from`'s link). */
  deliver(from: ParticipantId, to: ParticipantId, bytes: Uint8Array): void;
}

/**
 * In-process reference network. `intercept` sees every delivery and returns the bytes to deliver, or `null` to drop it,
 * so tests model a network or a corrupted peer without any private API.
 */
export function createMemoryDkgNetwork(
  ids: readonly ParticipantId[],
  sessionId: Uint8Array,
  intercept?: (d: MemoryDkgDelivery & { kind: DkgMessageKind }) => Uint8Array | null,
): MemoryDkgNetwork {
  const sorted = [...ids].sort((a, b) => a - b);
  const inboxes = new Map(sorted.map((id) => [id, new DkgInbox(sessionId, sorted.filter((p) => p !== id))]));
  const deliver = (from: ParticipantId, to: ParticipantId, bytes: Uint8Array): void => inboxes.get(to)?.accept(from, bytes);
  const channels = new Map<ParticipantId, DkgChannel>();
  for (const self of sorted) {
    const peers = sorted.filter((p) => p !== self);
    const route = (to: ParticipantId, kind: DkgMessageKind, body: unknown): void => {
      const bytes = encodeDkgMessage(sessionId, kind, body);
      const out = intercept ? intercept({ from: self, to, kind, bytes }) : bytes;
      if (out !== null) deliver(self, to, out);
    };
    channels.set(self, {
      self,
      peers,
      broadcast: (kind, body) => {
        for (const p of peers) route(p, kind, body);
        return Promise.resolve();
      },
      send: (to, kind, body) => {
        if (!peers.includes(to)) return Promise.reject(new DkgChannelError('identity', to, 'not a connected peer'));
        route(to, kind, body);
        return Promise.resolve();
      },
      collect: (kind, from, timeoutMs) => inboxes.get(self)!.collect(kind, from, timeoutMs),
      close: () => {
        inboxes.get(self)!.close();
        return Promise.resolve();
      },
    });
  }
  return { channels, deliver };
}

// ---- the driver ----------------------------------------------------------------------------------------

export interface RunDkgOpts {
  t: number;
  /** Every participant including this one. */
  participants: readonly ParticipantId[];
  /** The ceremony id, identical for all participants and unique per run. */
  sessionId: Uint8Array;
  /** Per-phase wait for the other parties; a missing message after this aborts the run. Default 30 s. */
  timeoutMs?: number;
  /** Fixed polynomial coefficients (tests). */
  coefficients?: Uint8Array[];
}

export interface RunDkgResult {
  keyPackage: DkgKeyPackage;
  qualified: ParticipantId[];
  complaints: DkgComplaint[];
}

function bind<T>(peer: ParticipantId, f: () => T): T {
  try {
    return f();
  } catch (e) {
    if (e instanceof DkgChannelError) throw new DkgChannelError(e.code, peer, e.message.replace(/^dkg channel \([^)]*\): /, ''));
    throw e;
  }
}

/**
 * Run ONE participant's whole DKG over `ch`: round 1, proof-of-possession checks, round 2 with signed shares, share
 * verification, complaints, rebuttals, the qualified set, the echo round and finalize. Resolves with this participant's
 * key package; rejects with {@link DkgChannelError} on any channel or protocol violation (nothing partial is returned).
 */
export async function runDkgOverChannel(ch: DkgChannel, opts: RunDkgOpts): Promise<RunDkgResult> {
  const self = ch.self;
  const ids = [...opts.participants].sort((a, b) => a - b);
  if (ids.length > DKG_MAX_PARTICIPANTS || ids.some((i, k) => !Number.isSafeInteger(i) || i <= 0 || (k > 0 && ids[k - 1] === i))) {
    throw new DkgChannelError('protocol', undefined, 'participants must be distinct positive integers within the cap');
  }
  if (!ids.includes(self)) throw new DkgChannelError('protocol', undefined, 'this participant is not in the participant list');
  if (!Number.isSafeInteger(opts.t) || opts.t < 1 || opts.t > ids.length) throw new DkgChannelError('protocol', undefined, 'need 1 <= t <= n');
  const others = ids.filter((i) => i !== self);
  if (ch.peers.length !== others.length || !others.every((o, k) => ch.peers[k] === o)) {
    throw new DkgChannelError('protocol', undefined, 'the channel peers are not exactly the other participants');
  }
  const sid = opts.sessionId;
  const sidB64 = b64u(sid);
  const tmo = opts.timeoutMs ?? 30_000;
  const n = ids.length;

  // Round 1: broadcast, collect, bind each package to its authenticated sender.
  const r1 = dkgRound1(self, opts.t, n, sid, { coefficients: opts.coefficients });
  await ch.broadcast('round1', r1.package);
  const pkgs: DkgRound1Package[] = [r1.package];
  for (const [from, body] of await ch.collect('round1', others, tmo)) {
    const p = bind(from, () => decodeDkgRound1Package(body, opts.t));
    if (p.identifier !== from) throw new DkgChannelError('identity', from, `package claims identifier ${p.identifier}`);
    if (p.sessionId !== sidB64) throw new DkgChannelError('wrong-session', from, 'package names another session');
    pkgs.push(p);
  }
  const byId = new Map(pkgs.map((p) => [p.identifier, p]));
  // A package whose proof of possession fails is dropped by the qualified set; it gets and gives no shares.
  const pok = pkgs.filter((p) => dkgVerifyRound1(p.identifier, p, sid));
  const okPeers = others.filter((o) => pok.some((p) => p.identifier === o));

  // Round 2: signed shares out (private), signed shares in.
  for (const s of dkgRound2(r1.state, pok)) {
    await ch.send(s.to, 'share', { from: s.from, to: s.to, sessionId: s.sessionId, share: b64u(s.share), sig: s.sig });
  }
  const inbox: DkgReceivedShare[] = [];
  const mine: DkgComplaint[] = [];
  for (const [from, body] of await ch.collect('share', okPeers, tmo)) {
    const m = bind(from, () => decodeDkgShareMessage(body));
    if (m.from !== from) throw new DkgChannelError('identity', from, `share claims sender ${m.from}`);
    if (m.to !== self) throw new DkgChannelError('identity', from, `share is addressed to ${m.to}`);
    if (m.sessionId !== sidB64) throw new DkgChannelError('wrong-session', from, 'share names another session');
    const received: DkgReceivedShare = { from, sessionId: m.sessionId, share: m.share, sig: m.sig };
    const sender = byId.get(from)!;
    if (dkgVerifyShare(received, sender, self, sid)) {
      inbox.push(received);
      continue;
    }
    const c = dkgFileComplaint({ accused: from, accuser: self, receivedShare: m.share, shareSig: m.sig, senderCommitments: sender.coefficientCommitments, sessionId: sid });
    // Only a share the sender really signed is attributable blame; anything else aborts the run instead of accusing.
    if (!dkgVerifyComplaint(c, pkgs).justified) throw new DkgChannelError('protocol', from, 'share failed verification and is not admissible blame');
    mine.push(c);
  }

  // Complaints (broadcast, possibly empty), then rebuttals by the accused.
  await ch.broadcast('complaints', { complaints: mine });
  const complaints: DkgComplaint[] = [...mine];
  for (const [from, body] of await ch.collect('complaints', others, tmo)) {
    const list = bind(from, () => decodeDkgComplaints(body));
    const pairs = new Set<string>();
    for (const c of list) {
      if (c.accuser !== from) throw new DkgChannelError('identity', from, `complaint filed as ${c.accuser}`);
      if (c.sessionId !== sidB64) throw new DkgChannelError('wrong-session', from, 'complaint names another session');
      if (c.accused === from || !ids.includes(c.accused)) throw new DkgChannelError('protocol', from, 'complaint names an invalid accused');
      if (pairs.has(String(c.accused))) throw new DkgChannelError('duplicate', from, 'two complaints against one accused');
      pairs.add(String(c.accused));
      complaints.push(c);
    }
  }
  const rebuttals: DkgRebuttal[] = complaints.filter((c) => c.accused === self).map((c) => dkgRebut(self, c, r1.state));
  await ch.broadcast('rebuttals', { rebuttals });
  const allRebuttals: DkgRebuttal[] = [...rebuttals];
  for (const [from, body] of await ch.collect('rebuttals', others, tmo)) {
    for (const r of bind(from, () => decodeDkgRebuttals(body))) {
      if (r.accused !== from) throw new DkgChannelError('identity', from, `rebuttal made as ${r.accused}`);
      if (r.sessionId !== sidB64) throw new DkgChannelError('wrong-session', from, 'rebuttal names another session');
      allRebuttals.push(r);
    }
  }

  const qualified = dkgQualifiedSet(ids, complaints, pkgs, allRebuttals);
  if (!qualified.includes(self)) throw new DkgChannelError('disqualified', self, 'this participant was disqualified by the blame round');
  if (qualified.length < opts.t) throw new DkgChannelError('protocol', undefined, 'fewer than t participants remain qualified');

  // Echo round: every qualified party must have seen the identical transcript.
  const echo = dkgEcho({ identifier: self, round1Packages: pkgs, complaints, qualified, sessionId: sid });
  await ch.broadcast('echo', echo);
  const echoes: DkgEcho[] = [echo];
  for (const [from, body] of await ch.collect('echo', qualified.filter((q) => q !== self), tmo)) {
    const e = bind(from, () => decodeDkgEcho(body));
    if (e.identifier !== from) throw new DkgChannelError('identity', from, `echo claims identifier ${e.identifier}`);
    echoes.push(e);
  }
  const agreement = dkgCheckEchoes(qualified, echoes, sid);
  if (!agreement.agreed) throw new DkgChannelError('equivocation', undefined, agreement.reason ?? 'echo disagreement');

  const keyPackage = dkgFinalize(self, r1.state, inbox, pkgs, qualified, { echoes, complaints });
  return { keyPackage, qualified, complaints };
}
