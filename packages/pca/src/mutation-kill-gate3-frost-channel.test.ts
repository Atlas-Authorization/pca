/**
 * Mutation kills for the 0.5.0 flagship gate survivors in frost-dkg-channel.ts: the exact code, peer and message of
 * every channel refusal (envelope, body decoders, inbox, memory network, driver), the size and list caps at their
 * boundaries, the inbox's wake-up, first-error-wins, sorting and timer bookkeeping, and the driver's participant
 * checks, proof-of-possession filtering, complaint / rebuttal handling and qualified-set outcomes. The driver is run
 * for participant 1 over a scripted channel whose peers are simulated from fixed polynomial coefficients, so every
 * expected message is computed independently.
 */
import { describe, expect, it } from 'vitest';
import { b64u, utf8 } from './hash';
import type { ParticipantId } from './frost';
import {
  DKG_MAX_MESSAGE_BYTES,
  DKG_MAX_PARTICIPANTS,
  DkgChannelError,
  DkgInbox,
  createMemoryDkgNetwork,
  decodeDkgComplaints,
  decodeDkgEcho,
  decodeDkgMessage,
  decodeDkgRebuttals,
  decodeDkgRound1Package,
  decodeDkgShareMessage,
  encodeDkgMessage,
  runDkgOverChannel,
  type DkgChannel,
  type DkgMessageKind,
} from './frost-dkg-channel';
import { dkgEcho, dkgRebut, dkgRound1, dkgRound2, dkgSignShare, type DkgComplaint, type DkgRebuttal, type DkgRound1Package, type DkgRound1Result } from './frost-dkg';

const SID = utf8('gate3-dkg-channel-session-000001');
const SIDB = b64u(SID);
const OTHER = b64u(utf8('gate3-another-session-0000000001'));
const B32 = b64u(new Uint8Array(32));
const B64 = b64u(new Uint8Array(64));
const enc = (o: unknown): Uint8Array => utf8(JSON.stringify(o));
const wire = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const msg = (code: string, peer: number | undefined, text: string) => `dkg channel (${code}${peer === undefined ? '' : `, peer ${peer}`}): ${text}`;
const err = (code: string, peer: number | undefined, text: string) => ({ name: 'DkgChannelError', code, peer, message: msg(code, peer, text) });
const settle = <T>(p: Promise<T>, ms = 150): Promise<{ v: T } | { e: unknown } | 'pending'> =>
  Promise.race([p.then((v) => ({ v }), (e: unknown) => ({ e })), new Promise<'pending'>((r) => setTimeout(() => r('pending'), ms))]);

// ---- envelope and error shape ------------------------------------------------------------------------------

describe('DkgChannelError and the wire envelope', () => {
  it('formats the code, the optional peer and the text, and names itself', () => {
    const a = new DkgChannelError('malformed', undefined, 'x y');
    expect(a.message).toBe('dkg channel (malformed): x y');
    expect(a.name).toBe('DkgChannelError');
    expect(a.peer).toBeUndefined();
    const b = new DkgChannelError('timeout', 7, 'z');
    expect(b.message).toBe('dkg channel (timeout, peer 7): z');
    expect(b.peer).toBe(7);
  });

  it('encode accepts a message of exactly the cap and refuses one byte more with `oversize`', () => {
    const base = encodeDkgMessage(SID, 'round1', '').length;
    const fill = DKG_MAX_MESSAGE_BYTES - base;
    expect(encodeDkgMessage(SID, 'round1', 'x'.repeat(fill)).length).toBe(DKG_MAX_MESSAGE_BYTES);
    expect(() => encodeDkgMessage(SID, 'round1', 'x'.repeat(fill + 1))).toThrow(
      expect.objectContaining(err('oversize', undefined, `message of ${DKG_MAX_MESSAGE_BYTES + 1} bytes exceeds the cap`)),
    );
  });

  it('decode accepts exactly the cap and refuses one byte more with `oversize` and the length', () => {
    const big = encodeDkgMessage(SID, 'echo', 'x'.repeat(DKG_MAX_MESSAGE_BYTES - encodeDkgMessage(SID, 'echo', '').length));
    expect(decodeDkgMessage(big, SID).kind).toBe('echo');
    expect(() => decodeDkgMessage(new Uint8Array(DKG_MAX_MESSAGE_BYTES + 1), SID)).toThrow(
      expect.objectContaining(err('oversize', undefined, `message of ${DKG_MAX_MESSAGE_BYTES + 1} bytes exceeds the cap`)),
    );
  });

  it.each([
    ['not bytes', 'abc', 'message is not bytes'],
    ['not JSON', utf8('{{'), 'message is not strict JSON'],
    ['a number', utf8('5'), 'envelope is not an object'],
    ['an array', utf8('[]'), 'envelope is not an object'],
    ['a wrong member', enc({ v: 1, sid: SIDB, kind: 'round1', bodyX: 1 }), 'envelope has unexpected or missing members'],
    ['a missing member', enc({ v: 1, sid: SIDB, kind: 'round1' }), 'envelope has unexpected or missing members'],
    ['version 2', enc({ v: 2, sid: SIDB, kind: 'round1', body: 1 }), 'unsupported wire version'],
    ['an unknown kind', enc({ v: 1, sid: SIDB, kind: 'nope', body: 1 }), 'unknown message kind'],
    ['a numeric kind', enc({ v: 1, sid: SIDB, kind: 5, body: 1 }), 'unknown message kind'],
  ] as const)('an envelope that is %s is `malformed` with its own text', (_n, bytes, text) => {
    expect(() => decodeDkgMessage(bytes as never, SID)).toThrow(expect.objectContaining(err('malformed', undefined, text)));
  });

  it('another session is `wrong-session`', () => {
    expect(() => decodeDkgMessage(enc({ v: 1, sid: OTHER, kind: 'round1', body: 1 }), SID)).toThrow(
      expect.objectContaining(err('wrong-session', undefined, 'message names another session')),
    );
    expect(decodeDkgMessage(enc({ v: 1, sid: SIDB, kind: 'share', body: { a: 1 } }), SID)).toEqual({ kind: 'share', body: { a: 1 } });
  });
});

// ---- body decoders ---------------------------------------------------------------------------------------------

const bad = (text: string) => expect.objectContaining(err('malformed', undefined, text));
const echoBody = (o: Record<string, unknown> = {}) => ({ identifier: 1, sessionId: SIDB, transcriptDigest: B32, ...o });

describe('body decoders refuse with the exact field name', () => {
  it.each([[0], [-1], [1.5], ['1'], [2 ** 53], [null]])('identifier %j is not a positive integer', (v) => {
    expect(() => decodeDkgEcho(echoBody({ identifier: v }))).toThrow(bad('identifier is not a positive integer'));
  });

  it('echo: shape, every field and the decoded value', () => {
    expect(() => decodeDkgEcho(5)).toThrow(bad('echo is not an object'));
    expect(() => decodeDkgEcho(undefined)).toThrow(bad('echo is not an object'));
    expect(() => decodeDkgEcho([1, 2, 3])).toThrow(bad('echo is not an object'));
    expect(() => decodeDkgEcho({ identifier: 1, sessionId: SIDB, digest: B32 })).toThrow(bad('echo has unexpected or missing members'));
    expect(() => decodeDkgEcho(echoBody({ sessionId: '*' }))).toThrow(bad('sessionId is not canonical base64url'));
    expect(() => decodeDkgEcho(echoBody({ transcriptDigest: B64 }))).toThrow(bad('transcript digest is not canonical base64url'));
    expect(decodeDkgEcho(echoBody({ identifier: 1 }))).toEqual(echoBody());
  });

  const r1 = { identifier: 2, sessionId: SIDB, coefficientCommitments: [B32, B32], proofOfKnowledge: { R: B32, mu: B32 } };
  it('round-1 package: shape, commitment count and every field', () => {
    expect(() => decodeDkgRound1Package('x', 2)).toThrow(bad('round-1 package is not an object'));
    expect(() => decodeDkgRound1Package({ ...r1, proofOfKnowledge: 1 }, 2)).toThrow(bad('proof of knowledge is not an object'));
    for (const cc of ['ab', { length: 2 }, [B32], [B32, B32, B32]]) {
      expect(() => decodeDkgRound1Package({ ...r1, coefficientCommitments: cc }, 2)).toThrow(bad('round-1 package must commit to exactly t=2 coefficients'));
    }
    expect(() => decodeDkgRound1Package({ ...r1, identifier: 0 }, 2)).toThrow(bad('identifier is not a positive integer'));
    expect(() => decodeDkgRound1Package({ ...r1, sessionId: '=' }, 2)).toThrow(bad('sessionId is not canonical base64url'));
    expect(() => decodeDkgRound1Package({ ...r1, coefficientCommitments: [B32, B64] }, 2)).toThrow(bad('coefficient commitment is not canonical base64url'));
    expect(() => decodeDkgRound1Package({ ...r1, proofOfKnowledge: { R: B64, mu: B32 } }, 2)).toThrow(bad('PoP R is not canonical base64url'));
    expect(() => decodeDkgRound1Package({ ...r1, proofOfKnowledge: { R: B32, mu: B64 } }, 2)).toThrow(bad('PoP mu is not canonical base64url'));
    expect(decodeDkgRound1Package(r1, 2)).toEqual(r1);
  });

  const sh = { from: 2, to: 1, sessionId: SIDB, share: B32, sig: B64 };
  it('share message: shape and every field, with the share as bytes', () => {
    expect(() => decodeDkgShareMessage(null)).toThrow(bad('share message is not an object'));
    expect(() => decodeDkgShareMessage({ ...sh, from: 'a' })).toThrow(bad('from is not a positive integer'));
    expect(() => decodeDkgShareMessage({ ...sh, to: -2 })).toThrow(bad('to is not a positive integer'));
    expect(() => decodeDkgShareMessage({ ...sh, sessionId: 5 })).toThrow(bad('sessionId is not canonical base64url'));
    expect(() => decodeDkgShareMessage({ ...sh, share: B64 })).toThrow(bad('share is not canonical base64url'));
    expect(() => decodeDkgShareMessage({ ...sh, sig: B32 })).toThrow(bad('share signature is not canonical base64url'));
    expect(decodeDkgShareMessage(sh)).toEqual({ ...sh, share: new Uint8Array(32) });
  });

  const cmp = { accused: 3, accuser: 2, sessionId: SIDB, revealedShare: B32, shareSig: B64 };
  it('complaints: list shape, cap and every field', () => {
    expect(() => decodeDkgComplaints({ complaints: 'x' })).toThrow(bad('complaints is not a bounded list'));
    expect(() => decodeDkgComplaints({ complaints: {} })).toThrow(bad('complaints is not a bounded list'));
    expect(() => decodeDkgComplaints({ list: [] })).toThrow(bad('complaints has unexpected or missing members'));
    expect(decodeDkgComplaints({ complaints: Array.from({ length: DKG_MAX_PARTICIPANTS }, () => cmp) })).toHaveLength(DKG_MAX_PARTICIPANTS);
    expect(() => decodeDkgComplaints({ complaints: Array.from({ length: DKG_MAX_PARTICIPANTS + 1 }, () => cmp) })).toThrow(bad('complaints is not a bounded list'));
    expect(() => decodeDkgComplaints({ complaints: [7] })).toThrow(bad('complaint is not an object'));
    expect(() => decodeDkgComplaints({ complaints: [{ ...cmp, accused: 0 }] })).toThrow(bad('accused is not a positive integer'));
    expect(() => decodeDkgComplaints({ complaints: [{ ...cmp, accuser: 0 }] })).toThrow(bad('accuser is not a positive integer'));
    expect(() => decodeDkgComplaints({ complaints: [{ ...cmp, sessionId: '*' }] })).toThrow(bad('sessionId is not canonical base64url'));
    expect(() => decodeDkgComplaints({ complaints: [{ ...cmp, revealedShare: B64 }] })).toThrow(bad('revealed share is not canonical base64url'));
    expect(() => decodeDkgComplaints({ complaints: [{ ...cmp, shareSig: B32 }] })).toThrow(bad('share signature is not canonical base64url'));
    expect(decodeDkgComplaints({ complaints: [cmp] })).toEqual([cmp]);
  });

  const reb = { accused: 3, accuser: 2, sessionId: SIDB, presentedShare: B32, shareSig: B64 };
  it('rebuttals: list shape and every field', () => {
    expect(() => decodeDkgRebuttals({ rebuttals: 1 })).toThrow(bad('rebuttals is not a bounded list'));
    expect(() => decodeDkgRebuttals({ rebuttals: ['r'] })).toThrow(bad('rebuttal is not an object'));
    const { shareSig: _s, ...noSig } = reb;
    expect(() => decodeDkgRebuttals({ rebuttals: [{ ...noSig, sig: B64 }] })).toThrow(bad('rebuttal has unexpected or missing members'));
    expect(() => decodeDkgRebuttals({ rebuttals: [{ ...reb, accused: 'x' }] })).toThrow(bad('accused is not a positive integer'));
    expect(() => decodeDkgRebuttals({ rebuttals: [{ ...reb, accuser: 1.5 }] })).toThrow(bad('accuser is not a positive integer'));
    expect(() => decodeDkgRebuttals({ rebuttals: [{ ...reb, sessionId: '!' }] })).toThrow(bad('sessionId is not canonical base64url'));
    expect(() => decodeDkgRebuttals({ rebuttals: [{ ...reb, presentedShare: B64 }] })).toThrow(bad('presented share is not canonical base64url'));
    expect(() => decodeDkgRebuttals({ rebuttals: [{ ...reb, shareSig: B32 }] })).toThrow(bad('share signature is not canonical base64url'));
    expect(decodeDkgRebuttals({ rebuttals: [reb] })).toEqual([reb]);
    for (const k of ['accused', 'accuser', 'sessionId', 'presentedShare', 'shareSig'] as const) {
      const { [k]: _drop, ...rest } = reb;
      expect(() => decodeDkgRebuttals({ rebuttals: [{ ...rest, other: 1 }] })).toThrow(bad('rebuttal has unexpected or missing members'));
    }
  });
});

// ---- inbox ---------------------------------------------------------------------------------------------------------

const r1msg = (n = 1) => encodeDkgMessage(SID, 'round1', { n });

describe('DkgInbox', () => {
  it('a peer error is re-attributed to the peer with the prefix stripped once, and the first one wins', async () => {
    const box = new DkgInbox(SID, [2, 3]);
    box.fail(2, new DkgChannelError('timeout', undefined, 'first'));
    box.fail(2, new DkgChannelError('oversize', undefined, 'second'));
    const odd = new DkgChannelError('malformed', undefined, 'x');
    odd.message = 'zz dkg channel (q): y';
    box.fail(3, odd);
    await expect(box.collect('round1', [2], 50)).rejects.toMatchObject(err('timeout', 2, 'first'));
    await expect(box.collect('round1', [3], 50)).rejects.toMatchObject(err('malformed', 3, 'zz dkg channel (q): y'));
  });

  it('errors are checked in ascending peer order whatever order `from` has', async () => {
    const box = new DkgInbox(SID, [2, 3, 4, 5, 6]);
    box.fail(6, new DkgChannelError('timeout', undefined, 'six'));
    box.fail(3, new DkgChannelError('timeout', undefined, 'three'));
    box.fail(5, new DkgChannelError('timeout', undefined, 'five'));
    await expect(box.collect('round1', [6, 5, 4, 3, 2], 50)).rejects.toMatchObject({ peer: 3 });
    await expect(box.collect('round1', [6, 5, 4], 50)).rejects.toMatchObject({ peer: 5 });
  });

  it('a timeout names the missing peers ascending, the first as the peer', async () => {
    const box = new DkgInbox(SID, [2, 3, 4, 5, 6]);
    box.accept(4, r1msg());
    await expect(box.collect('round1', [6, 4, 5, 3, 2], 30)).rejects.toMatchObject(err('timeout', 2, 'no round1 message from 2,3,5,6'));
    await expect(box.collect('round1', [6, 3], 30)).rejects.toMatchObject(err('timeout', 3, 'no round1 message from 3,6'));
  });

  it('a second message is `duplicate` or `equivocation` with its exact text', async () => {
    const box = new DkgInbox(SID, [2, 3]);
    box.accept(2, r1msg(1));
    box.accept(2, r1msg(1));
    box.accept(3, r1msg(1));
    box.accept(3, r1msg(2));
    await expect(box.collect('round1', [2], 30)).rejects.toMatchObject(err('duplicate', 2, 'second round1 message'));
    await expect(box.collect('round1', [3], 30)).rejects.toMatchObject(err('equivocation', 3, 'second round1 message'));
  });

  it('a decode failure that is not a channel error is `malformed: undecodable message`', async () => {
    const evil = Object.defineProperty(new Uint8Array(4), 'length', {
      get() {
        throw new Error('boom');
      },
    });
    const box = new DkgInbox(SID, [2]);
    box.accept(2, evil);
    await expect(box.collect('round1', [2], 30)).rejects.toMatchObject(err('malformed', 2, 'undecodable message'));
  });

  it('a message from a non-peer is ignored', async () => {
    const box = new DkgInbox(SID, [2]);
    box.accept(9, r1msg());
    box.accept(9, utf8('garbage'));
    await expect(box.collect('round1', [9], 30)).rejects.toMatchObject(err('timeout', 9, 'no round1 message from 9'));
  });

  it('an arriving message wakes a waiting collect at once', async () => {
    const box = new DkgInbox(SID, [2]);
    const p = box.collect('round1', [2], 10_000);
    box.accept(2, r1msg(4));
    const out = await settle(p);
    expect(out).toEqual({ v: new Map([[2, { n: 4 }]]) });
  });

  it('a peer failure wakes a waiting collect at once', async () => {
    const box = new DkgInbox(SID, [2]);
    const p = box.collect('round1', [2], 10_000);
    box.fail(2, new DkgChannelError('identity', undefined, 'nope'));
    expect(await settle(p)).toEqual({ e: expect.objectContaining(err('identity', 2, 'nope')) });
  });

  it('close wakes a waiting collect at once with `closed`', async () => {
    const box = new DkgInbox(SID, [2]);
    const p = box.collect('round1', [2], 10_000);
    box.close();
    expect(await settle(p)).toEqual({ e: expect.objectContaining(err('closed', undefined, 'channel closed before all messages arrived')) });
  });

  it('a link that ended wakes a waiting collect at once and names that peer', async () => {
    const box = new DkgInbox(SID, [2, 3]);
    const p = box.collect('round1', [2, 3], 10_000);
    box.peerGone(3);
    expect(await settle(p)).toEqual({ e: expect.objectContaining(err('closed', 3, 'link ended before its round1 message arrived')) });
  });

  it('a link that ended only matters while its message is missing', async () => {
    const box = new DkgInbox(SID, [2, 3]);
    box.accept(2, r1msg());
    box.peerGone(2);
    await expect(box.collect('round1', [2, 3], 30)).rejects.toMatchObject(err('timeout', 3, 'no round1 message from 3'));
    await expect(box.collect('round1', [2], 30)).resolves.toEqual(new Map([[2, { n: 1 }]]));
  });

  it('a zero timeout refuses on the first pass even if a message would arrive right after', async () => {
    const now = Date.now;
    Date.now = () => 1_000_000;
    try {
      const box = new DkgInbox(SID, [2]);
      const p = box.collect('round1', [2], 0);
      queueMicrotask(() => box.accept(2, r1msg()));
      await expect(p).rejects.toMatchObject(err('timeout', 2, 'no round1 message from 2'));
    } finally {
      Date.now = now;
    }
  });

  it('a woken waiter clears its timer and leaves the waiter set', async () => {
    const orig = globalThis.clearTimeout;
    let cleared = 0;
    globalThis.clearTimeout = ((h?: Parameters<typeof clearTimeout>[0]) => {
      cleared++;
      orig(h);
    }) as typeof clearTimeout;
    try {
      const box = new DkgInbox(SID, [2]);
      const p = box.collect('round1', [2], 10_000);
      box.accept(2, r1msg());
      await p;
      expect(cleared).toBe(1);
      box.close();
      box.fail(2, new DkgChannelError('timeout', undefined, 'later'));
      expect(cleared).toBe(1);
    } finally {
      globalThis.clearTimeout = orig;
    }
  });
});

// ---- memory network --------------------------------------------------------------------------------------------------

describe('createMemoryDkgNetwork', () => {
  it.each([[[3, 1, 2]], [[5, 2, 4, 1, 3]], [[2, 1]]])('sorts the participants %j and gives each channel the others, ascending', (ids) => {
    const net = createMemoryDkgNetwork(ids, SID);
    const sorted = [...ids].sort((a, b) => a - b);
    expect([...net.channels.keys()]).toEqual(sorted);
    for (const id of sorted) expect(net.channels.get(id)!.peers).toEqual(sorted.filter((p) => p !== id));
  });

  it('a channel never accepts a message from itself, and delivery to a non-member is a no-op', async () => {
    const net = createMemoryDkgNetwork([1, 2], SID);
    net.deliver(1, 1, r1msg());
    expect(() => net.deliver(1, 99, r1msg())).not.toThrow();
    await expect(net.channels.get(1)!.collect('round1', [1], 30)).rejects.toMatchObject({ code: 'timeout' });
  });

  it('send to a participant that is not a connected peer is `identity`', async () => {
    const net = createMemoryDkgNetwork([1, 2], SID);
    await expect(net.channels.get(1)!.send(9, 'share', {})).rejects.toMatchObject(err('identity', 9, 'not a connected peer'));
    await expect(net.channels.get(1)!.send(1, 'share', {})).rejects.toMatchObject(err('identity', 1, 'not a connected peer'));
  });
});

// ---- the driver over a scripted channel ------------------------------------------------------------------------------

const scalar = (n: number): Uint8Array => {
  const b = new Uint8Array(32);
  b[0] = n;
  return b;
};
const coeffsFor = (id: number, t: number): Uint8Array[] => Array.from({ length: t }, (_, j) => scalar(id * 16 + j + 1));

type Body = (id: ParticipantId, w: World) => unknown;
interface World {
  t: number;
  ids: ParticipantId[];
  states: Map<ParticipantId, DkgRound1Result>;
  /** party 1's view of every round-1 package: its own broadcast and what it was delivered. */
  pkgs: () => DkgRound1Package[];
  ch: ScriptedChannel;
}

class ScriptedChannel implements DkgChannel {
  readonly broadcasts = new Map<DkgMessageKind, unknown>();
  readonly sent: { to: ParticipantId; kind: DkgMessageKind; body: unknown }[] = [];
  readonly collected: { kind: DkgMessageKind; from: ParticipantId[] }[] = [];
  readonly delivered = new Map<DkgMessageKind, Map<ParticipantId, unknown>>();
  world!: World;
  constructor(
    readonly self: ParticipantId,
    readonly peers: ParticipantId[],
    readonly bodies: Partial<Record<DkgMessageKind, Body>>,
    readonly raw: Partial<Record<DkgMessageKind, boolean>> = {},
  ) {}
  broadcast(kind: DkgMessageKind, body: unknown): Promise<void> {
    this.broadcasts.set(kind, wire(body));
    return Promise.resolve();
  }
  send(to: ParticipantId, kind: DkgMessageKind, body: unknown): Promise<void> {
    this.sent.push({ to, kind, body: wire(body) });
    return Promise.resolve();
  }
  collect(kind: DkgMessageKind, from: readonly ParticipantId[]): Promise<Map<ParticipantId, unknown>> {
    this.collected.push({ kind, from: [...from] });
    const f = this.bodies[kind]!;
    const out = new Map(from.map((id) => [id, this.raw[kind] ? f(id, this.world) : wire(f(id, this.world))]));
    this.delivered.set(kind, out);
    return Promise.resolve(out);
  }
  close(): Promise<void> {
    return Promise.resolve();
  }
}

const honestShare: Body = (id, w) => {
  const s = dkgRound2(w.states.get(id)!.state, w.pkgs()).find((x) => x.to === 1)!;
  return { from: s.from, to: s.to, sessionId: s.sessionId, share: b64u(s.share), sig: s.sig };
};

/** Run participant 1 against simulated peers. `view` is the transcript every peer echoes (the expected outcome). */
function scenario(opts: {
  ids?: ParticipantId[];
  t?: number;
  bodies?: Partial<Record<DkgMessageKind, Body>>;
  raw?: Partial<Record<DkgMessageKind, boolean>>;
  view?: { complaints: DkgComplaint[]; qualified: ParticipantId[] };
  participants?: ParticipantId[];
}) {
  const ids = opts.ids ?? [1, 2, 3];
  const t = opts.t ?? 2;
  const states = new Map(ids.filter((i) => i !== 1).map((i) => [i, dkgRound1(i, t, ids.length, SID, { coefficients: coeffsFor(i, t) })]));
  const view = () => opts.view ?? { complaints: [], qualified: ids };
  const bodies: Partial<Record<DkgMessageKind, Body>> = {
    round1: (id, w) => w.states.get(id)!.package,
    share: honestShare,
    complaints: () => ({ complaints: [] }),
    rebuttals: () => ({ rebuttals: [] }),
    echo: (id, w) => dkgEcho({ identifier: id, round1Packages: w.pkgs(), complaints: view().complaints, qualified: view().qualified, sessionId: SID }),
    ...opts.bodies,
  };
  const ch = new ScriptedChannel(1, ids.filter((i) => i !== 1), bodies, opts.raw);
  const world: World = { t, ids, states, ch, pkgs: () => [ch.broadcasts.get('round1'), ...ch.delivered.get('round1')!.values()] as DkgRound1Package[] };
  ch.world = world;
  const run = () => runDkgOverChannel(ch, { t, participants: opts.participants ?? ids, sessionId: SID, timeoutMs: 1000, coefficients: coeffsFor(1, t) });
  return { ch, world, run, states };
}

/** Party 1's own round-1 state (fixed coefficients, so its commitments and share signatures can be recomputed). */
const myState = (t = 2, n = 3) => dkgRound1(1, t, n, SID, { coefficients: coeffsFor(1, t) }).state;
const badShareFrom = (w: World, dealer: ParticipantId, to: ParticipantId) => {
  const s = dkgRound2(w.states.get(dealer)!.state, w.pkgs()).find((x) => x.to === to)!;
  const bad = Uint8Array.from(s.share);
  bad[0] = bad[0]! ^ 1;
  return { s, bad, sig: dkgSignShare(w.states.get(dealer)!.state, to, bad) };
};

describe('runDkgOverChannel: honest scripted run', () => {
  it('finalizes, uses the fixed coefficients and talks to exactly the right parties', async () => {
    const a = scenario({});
    const ra = await a.run();
    const b = scenario({});
    const rb = await b.run();
    expect(ra.qualified).toEqual([1, 2, 3]);
    expect(ra.complaints).toEqual([]);
    expect(b64u(ra.keyPackage.groupPublicKey)).toBe(b64u(rb.keyPackage.groupPublicKey));
    expect(b64u(ra.keyPackage.signingShare)).toBe(b64u(rb.keyPackage.signingShare));
    expect((a.ch.broadcasts.get('round1') as DkgRound1Package).coefficientCommitments).toEqual(myState().package.coefficientCommitments);
    expect(a.ch.sent.map((s) => [s.to, s.kind])).toEqual([
      [2, 'share'],
      [3, 'share'],
    ]);
    expect(a.ch.collected).toEqual([
      { kind: 'round1', from: [2, 3] },
      { kind: 'share', from: [2, 3] },
      { kind: 'complaints', from: [2, 3] },
      { kind: 'rebuttals', from: [2, 3] },
      { kind: 'echo', from: [2, 3] },
    ]);
    expect(a.ch.broadcasts.get('complaints')).toEqual({ complaints: [] });
    expect(a.ch.broadcasts.get('rebuttals')).toEqual({ rebuttals: [] });
  });

  it('an unsorted participant list is sorted before use', async () => {
    const r = await scenario({ participants: [3, 1, 2] }).run();
    expect(r.qualified).toEqual([1, 2, 3]);
  });
});

describe('runDkgOverChannel: participant and threshold checks', () => {
  const stub = (peers: ParticipantId[]): DkgChannel => ({
    self: 1,
    peers,
    broadcast: () => Promise.reject(new Error('unused')),
    send: () => Promise.reject(new Error('unused')),
    collect: () => Promise.reject(new Error('unused')),
    close: () => Promise.resolve(),
  });
  const go = (participants: number[], t = 1, peers: ParticipantId[] = []) => runDkgOverChannel(stub(peers), { t, participants, sessionId: SID });
  const PART = err('protocol', undefined, 'participants must be distinct positive integers within the cap');
  const PEERS = err('protocol', undefined, 'the channel peers are not exactly the other participants');
  const many = (n: number) => Array.from({ length: n }, (_, i) => i + 1);

  it.each([[[1, 1, 2]], [[1, 2, 1]], [[2, 1, 2]], [[3, 1, 2, 3, 4]], [[0, 1, 2]], [[1, 1.5, 2]], [[-1, 1]], [[1, 2, 2 ** 53]]])('%j is refused', async (p) => {
    await expect(go(p)).rejects.toMatchObject(PART);
  });

  it('the participant cap is inclusive', async () => {
    await expect(go(many(DKG_MAX_PARTICIPANTS + 1))).rejects.toMatchObject(PART);
    await expect(go(many(DKG_MAX_PARTICIPANTS))).rejects.toMatchObject(PEERS);
  });

  it('self must be listed', async () => {
    await expect(go([2, 3])).rejects.toMatchObject(err('protocol', undefined, 'this participant is not in the participant list'));
  });

  it('t must be an integer in 1..n, both ends inclusive', async () => {
    const T = err('protocol', undefined, 'need 1 <= t <= n');
    for (const t of [0, -1, Number.NaN, 1.5, 4]) await expect(go([1, 2, 3], t)).rejects.toMatchObject(T);
    for (const t of [1, 3]) await expect(go([1, 2, 3], t)).rejects.toMatchObject(PEERS);
  });

  it('the channel peers must be exactly the other participants, in order', async () => {
    await expect(go([1, 2, 3], 2, [2, 4])).rejects.toMatchObject(PEERS);
    await expect(go([1, 2, 3], 2, [3, 2])).rejects.toMatchObject(PEERS);
    await expect(go([1, 2, 3], 2, [2])).rejects.toMatchObject(PEERS);
  });
});

describe('runDkgOverChannel: round 1 and round 2 refusals', () => {
  it('a body that is not a package is `malformed`, attributed to its sender', async () => {
    const { run } = scenario({ bodies: { round1: (id, w) => (id === 2 ? 'nope' : w.states.get(id)!.package) } });
    await expect(run()).rejects.toMatchObject(err('malformed', 2, 'round-1 package is not an object'));
  });

  it('a decoder fault that is not a channel error propagates unchanged', async () => {
    const trap = new Proxy({}, { ownKeys: () => { throw new RangeError('trap'); } });
    const { run } = scenario({ raw: { round1: true }, bodies: { round1: (id, w) => (id === 2 ? trap : wire(w.states.get(id)!.package)) } });
    const e = await run().catch((x: unknown) => x);
    expect(e).toBeInstanceOf(RangeError);
    expect(e).not.toBeInstanceOf(DkgChannelError);
  });

  it('a package with another identifier or session is refused with the exact text', async () => {
    const a = scenario({ bodies: { round1: (id, w) => ({ ...w.states.get(id)!.package, identifier: id === 2 ? 3 : id }) } });
    await expect(a.run()).rejects.toMatchObject(err('identity', 2, 'package claims identifier 3'));
    const b = scenario({ bodies: { round1: (id, w) => ({ ...w.states.get(id)!.package, sessionId: id === 3 ? OTHER : SIDB }) } });
    await expect(b.run()).rejects.toMatchObject(err('wrong-session', 3, 'package names another session'));
  });

  it('a package whose proof of possession fails gets no share and is not waited for', async () => {
    const s = scenario({
      bodies: { round1: (id, w) => (id === 3 ? { ...w.states.get(3)!.package, proofOfKnowledge: { ...w.states.get(3)!.package.proofOfKnowledge, mu: b64u(scalar(9)) } } : w.states.get(id)!.package) },
      view: { complaints: [], qualified: [1, 2] },
    });
    const r = await s.run();
    expect(r.qualified).toEqual([1, 2]);
    expect(s.ch.sent.map((x) => x.to)).toEqual([2]);
    expect(s.ch.collected.find((c) => c.kind === 'share')!.from).toEqual([2]);
    expect(s.ch.collected.find((c) => c.kind === 'echo')!.from).toEqual([2]);
  });

  it.each([
    ['from', { from: 3 }, err('identity', 2, 'share claims sender 3')],
    ['to', { to: 3 }, err('identity', 2, 'share is addressed to 3')],
    ['sessionId', { sessionId: OTHER }, err('wrong-session', 2, 'share names another session')],
  ] as const)('a share with another %s is refused with the exact text', async (_k, patch, want) => {
    const { run } = scenario({ bodies: { share: (id, w) => ({ ...(honestShare(id, w) as object), ...(id === 2 ? patch : {}) }) } });
    await expect(run()).rejects.toMatchObject(want);
  });
});

describe('runDkgOverChannel: blame round', () => {
  it('a share that fails verification without the sender signature aborts with `protocol` and the exact text', async () => {
    const { run } = scenario({ bodies: { share: (id, w) => ({ ...(honestShare(id, w) as object), ...(id === 2 ? { sig: b64u(new Uint8Array(64).fill(1)) } : {}) }) } });
    await expect(run()).rejects.toMatchObject(err('protocol', 2, 'share failed verification and is not admissible blame'));
  });

  it('a signed bad share from 2 becomes our complaint, is broadcast, and removes 2', async () => {
    let complaint: DkgComplaint | undefined;
    const s = scenario({
      bodies: {
        share: (id, w) => {
          if (id !== 2) return honestShare(id, w);
          const { s: sh, bad, sig } = badShareFrom(w, 2, 1);
          complaint = { accused: 2, accuser: 1, sessionId: SIDB, revealedShare: b64u(bad), shareSig: sig };
          return { from: 2, to: 1, sessionId: sh.sessionId, share: b64u(bad), sig };
        },
        rebuttals: (id, w) => ({ rebuttals: id === 2 ? [dkgRebut(2, complaint!, w.states.get(2)!.state)] : [] }),
      },
      get view() {
        return { complaints: [complaint!], qualified: [1, 3] };
      },
    });
    const r = await s.run();
    expect(r.complaints).toEqual([complaint]);
    expect(r.qualified).toEqual([1, 3]);
    expect(s.ch.broadcasts.get('complaints')).toEqual({ complaints: [complaint] });
    expect(s.ch.broadcasts.get('rebuttals')).toEqual({ rebuttals: [] });
  });

  /** An inadmissible accusation (no accused signature) filed by 2 against `accused`. */
  const fake = (accused: ParticipantId, o: Partial<DkgComplaint> = {}): DkgComplaint => ({ accused, accuser: 2, sessionId: SIDB, revealedShare: B32, shareSig: b64u(new Uint8Array(64).fill(1)), ...o });

  it('a complaint against us is answered with our rebuttal and removes nobody', async () => {
    const c = fake(1);
    const s = scenario({ bodies: { complaints: (id) => ({ complaints: id === 2 ? [c] : [] }) }, view: { complaints: [c], qualified: [1, 2, 3] } });
    const r = await s.run();
    expect(r.complaints).toEqual([c]);
    expect(r.qualified).toEqual([1, 2, 3]);
    const expected = dkgRebut(1, c, myState());
    const { shareSig: _sig, ...fields } = expected;
    const sent = s.ch.broadcasts.get('rebuttals') as { rebuttals: DkgRebuttal[] };
    expect(sent.rebuttals).toHaveLength(1);
    expect(sent.rebuttals[0]).toMatchObject(fields);
  });

  it('peer complaints are kept, and an invalid rebuttal by the accused removes it', async () => {
    const c = fake(3);
    const badReb: DkgRebuttal = { accused: 3, accuser: 2, sessionId: SIDB, presentedShare: B32, shareSig: B64 };
    const s = scenario({
      bodies: { complaints: (id) => ({ complaints: id === 2 ? [c] : [] }), rebuttals: (id) => ({ rebuttals: id === 3 ? [badReb] : [] }) },
      view: { complaints: [c], qualified: [1, 2] },
    });
    const r = await s.run();
    expect(r.complaints).toEqual([c]);
    expect(r.qualified).toEqual([1, 2]);
  });

  it('a valid rebuttal by the accused keeps it', async () => {
    const c = fake(3);
    const s = scenario({
      bodies: { complaints: (id) => ({ complaints: id === 2 ? [c] : [] }), rebuttals: (id, w) => ({ rebuttals: id === 3 ? [dkgRebut(3, c, w.states.get(3)!.state)] : [] }) },
      view: { complaints: [c], qualified: [1, 2, 3] },
    });
    expect((await s.run()).qualified).toEqual([1, 2, 3]);
  });

  it.each([
    ['filed as another accuser', [{ accuser: 3 }], err('identity', 2, 'complaint filed as 3')],
    ['for another session', [{ sessionId: OTHER }], err('wrong-session', 2, 'complaint names another session')],
    ['against its own filer', [{ accused: 2 }], err('protocol', 2, 'complaint names an invalid accused')],
    ['against a non-participant', [{ accused: 9 }], err('protocol', 2, 'complaint names an invalid accused')],
    ['twice against one accused', [{}, {}], err('duplicate', 2, 'two complaints against one accused')],
  ] as const)('a complaint %s is refused with the exact text', async (_n, patches, want) => {
    const list = patches.map((p) => fake(3, p));
    const { run } = scenario({ bodies: { complaints: (id) => ({ complaints: id === 2 ? list : [] }) } });
    await expect(run()).rejects.toMatchObject(want);
  });

  it('complaints from one filer against two accused are both kept', async () => {
    const s = scenario({ ids: [1, 2, 3, 4], bodies: { complaints: (id) => ({ complaints: id === 2 ? [fake(3), fake(4)] : [] }) }, view: { complaints: [fake(3), fake(4)], qualified: [1, 2, 3, 4] } });
    expect((await s.run()).complaints).toEqual([fake(3), fake(4)]);
  });

  it.each([
    ['made as another accused', { accused: 2 }, err('identity', 3, 'rebuttal made as 2')],
    ['for another session', { sessionId: OTHER }, err('wrong-session', 3, 'rebuttal names another session')],
  ] as const)('a rebuttal %s is refused with the exact text', async (_n, patch, want) => {
    const c = fake(3);
    const reb = { accused: 3, accuser: 2, sessionId: SIDB, presentedShare: B32, shareSig: B64, ...patch };
    const { run } = scenario({ bodies: { complaints: (id) => ({ complaints: id === 2 ? [c] : [] }), rebuttals: (id) => ({ rebuttals: id === 3 ? [reb] : [] }) } });
    await expect(run()).rejects.toMatchObject(want);
  });

  it('a justified complaint against us is `disqualified`', async () => {
    const st = myState();
    const bad = scalar(77);
    const c: DkgComplaint = { accused: 1, accuser: 2, sessionId: SIDB, revealedShare: b64u(bad), shareSig: dkgSignShare(st, 2, bad) };
    const { run } = scenario({ bodies: { complaints: (id) => ({ complaints: id === 2 ? [c] : [] }) } });
    await expect(run()).rejects.toMatchObject(err('disqualified', 1, 'this participant was disqualified by the blame round'));
  });

  it('fewer than t qualified is `protocol`', async () => {
    let c: DkgComplaint | undefined;
    const { run } = scenario({
      t: 3,
      bodies: {
        complaints: (id, w) => {
          if (id !== 2) return { complaints: [] };
          const { bad, sig } = badShareFrom(w, 3, 2);
          c = { accused: 3, accuser: 2, sessionId: SIDB, revealedShare: b64u(bad), shareSig: sig };
          return { complaints: [c] };
        },
      },
    });
    await expect(run()).rejects.toMatchObject(err('protocol', undefined, 'fewer than t participants remain qualified'));
  });
});

describe('runDkgOverChannel: echo round', () => {
  it('an echo with another identifier is refused with the exact text', async () => {
    const s = scenario({});
    const base = s.ch.bodies.echo!;
    (s.ch.bodies as Record<string, unknown>).echo = (id: ParticipantId, w: World) => ({ ...(base(id, w) as object), identifier: id === 2 ? 3 : id });
    await expect(s.run()).rejects.toMatchObject(err('identity', 2, 'echo claims identifier 3'));
  });

  it('a divergent echo is `equivocation` with the agreement reason', async () => {
    const s = scenario({});
    const base = s.ch.bodies.echo!;
    (s.ch.bodies as Record<string, unknown>).echo = (id: ParticipantId, w: World) => ({ ...(base(id, w) as object), transcriptDigest: id === 3 ? B32 : (base(id, w) as { transcriptDigest: string }).transcriptDigest });
    await expect(s.run()).rejects.toMatchObject(err('equivocation', undefined, 'qualified participant 3 echoed a DIFFERENT transcript (equivocation detected)'));
  });
});
