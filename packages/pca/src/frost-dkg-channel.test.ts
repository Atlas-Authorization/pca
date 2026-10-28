import * as nodeTls from 'node:tls';
import * as nodeNet from 'node:net';
import { describe, expect, it } from 'vitest';
import { tlsIdentity } from './test-support/tls-identity';
import { b64u, utf8 } from './hash';
import { verify } from './keys';
import { frostAggregate, frostCommit, frostSign, type FrostParticipantShare, type ParticipantId } from './frost';
import {
  DKG_MAX_MESSAGE_BYTES,
  DkgChannelError,
  createMemoryDkgNetwork,
  decodeDkgComplaints,
  decodeDkgEcho,
  decodeDkgMessage,
  decodeDkgRound1Package,
  decodeDkgShareMessage,
  encodeDkgMessage,
  runDkgOverChannel,
  type DkgChannel,
  type RunDkgResult,
} from './frost-dkg-channel';
import { startTlsDkgNode } from './frost-dkg-tls';
import { dkgRound1 } from './frost-dkg';

const SID = utf8('dkg-channel-test-session-0001-xxxxx');
const enc = (o: unknown): Uint8Array => utf8(JSON.stringify(o));
const dec = (b: Uint8Array): { v: number; sid: string; kind: string; body: Record<string, unknown> } => JSON.parse(new TextDecoder().decode(b));

function signWith(results: RunDkgResult[], ids: ParticipantId[], message: Uint8Array): Uint8Array {
  const pk = results[0]!.keyPackage.groupPublicKey;
  const mk = (id: ParticipantId): FrostParticipantShare => {
    const kp = results.find((r) => r.keyPackage.identifier === id)!.keyPackage;
    return { identifier: id, share: kp.signingShare, publicKey: kp.verifyingShare };
  };
  const commits = ids.map((id) => ({ id, c: frostCommit(mk(id)) }));
  const list = commits.map((x) => x.c.commitment);
  const sigShares = commits.map((x) => frostSign(x.id, mk(x.id).share, pk, { hiding: x.c.hidingNonce, binding: x.c.bindingNonce }, message, list));
  const verificationShares = ids.map((id) => ({ identifier: id, publicKey: mk(id).publicKey }));
  return frostAggregate(message, list, sigShares, pk, { verificationShares });
}

async function runAll(channels: Map<ParticipantId, DkgChannel>, t: number, timeoutMs = 5000) {
  const ids = [...channels.keys()];
  return Promise.allSettled(ids.map((id) => runDkgOverChannel(channels.get(id)!, { t, participants: ids, sessionId: SID, timeoutMs })));
}

const codeOf = (r: PromiseSettledResult<unknown>): string | undefined =>
  r.status === 'rejected' ? (r.reason instanceof DkgChannelError ? r.reason.code : `other:${String(r.reason)}`) : undefined;

describe('DKG over the in-memory reference channel', () => {
  it.each([
    [2, [1, 2, 3]],
    [3, [1, 2, 3, 4, 5]],
  ])('honest %i-of-%i run produces one group key that signs', async (t, ids) => {
    const net = createMemoryDkgNetwork(ids, SID);
    const out = await runAll(net.channels, t);
    expect(out.every((o) => o.status === 'fulfilled')).toBe(true);
    const results = out.map((o) => (o as PromiseFulfilledResult<RunDkgResult>).value);
    expect(new Set(results.map((r) => b64u(r.keyPackage.groupPublicKey))).size).toBe(1);
    expect(results.every((r) => r.qualified.join() === ids.join() && r.complaints.length === 0)).toBe(true);
    const msg = utf8('signed by a channel-DKG key');
    const sig = signWith(results, ids.slice(0, t), msg);
    expect(verify(results[0]!.keyPackage.groupPublicKey, msg, sig)).toBe(true);
  });

  it('a package that claims another identifier than its authenticated sender is refused with `identity`', async () => {
    const net = createMemoryDkgNetwork([1, 2, 3], SID, (d) => {
      if (d.kind !== 'round1' || d.from !== 2 || d.to !== 1) return d.bytes;
      const m = dec(d.bytes);
      m.body.identifier = 3;
      return enc(m);
    });
    const out = await runAll(net.channels, 2, 1000);
    expect(codeOf(out[0]!)).toBe('identity');
  });

  it('a share addressed to someone else is refused with `identity`', async () => {
    const net = createMemoryDkgNetwork([1, 2, 3], SID, (d) => {
      if (d.kind !== 'share' || d.from !== 2 || d.to !== 1) return d.bytes;
      const m = dec(d.bytes);
      m.body.to = 3;
      return enc(m);
    });
    const out = await runAll(net.channels, 2, 1000);
    expect(codeOf(out[0]!)).toBe('identity');
  });

  it('a complaint filed under another accuser identity is refused with `identity`', async () => {
    const net = createMemoryDkgNetwork([1, 2, 3], SID, (d) => {
      if (d.kind !== 'complaints' || d.from !== 2 || d.to !== 1) return d.bytes;
      const m = dec(d.bytes);
      m.body.complaints = [{ accused: 3, accuser: 3, sessionId: b64u(SID), revealedShare: b64u(new Uint8Array(32)), shareSig: b64u(new Uint8Array(64)) }];
      return enc(m);
    });
    const out = await runAll(net.channels, 2, 1000);
    expect(codeOf(out[0]!)).toBe('identity');
  });

  it('a message stamped with another session is refused with `wrong-session`', async () => {
    const net = createMemoryDkgNetwork([1, 2, 3], SID, (d) => {
      if (d.kind !== 'round1' || d.from !== 2 || d.to !== 1) return d.bytes;
      const m = dec(d.bytes);
      m.sid = b64u(utf8('another-session-0000000000000000'));
      return enc(m);
    });
    const out = await runAll(net.channels, 2, 1000);
    expect(codeOf(out[0]!)).toBe('wrong-session');
  });

  it('a package whose inner session differs is refused with `wrong-session`', async () => {
    const net = createMemoryDkgNetwork([1, 2, 3], SID, (d) => {
      if (d.kind !== 'round1' || d.from !== 2 || d.to !== 1) return d.bytes;
      const m = dec(d.bytes);
      m.body.sessionId = b64u(utf8('another-session-0000000000000000'));
      return enc(m);
    });
    const out = await runAll(net.channels, 2, 1000);
    expect(codeOf(out[0]!)).toBe('wrong-session');
  });

  it('the same message twice is `duplicate`; a different second message is `equivocation`', async () => {
    for (const [mutate, code] of [
      [false, 'duplicate'],
      [true, 'equivocation'],
    ] as const) {
      const net = createMemoryDkgNetwork([1, 2, 3], SID);
      const r1 = dkgRound1(2, 2, 3, SID).package;
      const first = encodeDkgMessage(SID, 'round1', r1);
      const second = mutate ? encodeDkgMessage(SID, 'round1', dkgRound1(2, 2, 3, SID).package) : first;
      net.deliver(2, 1, first);
      net.deliver(2, 1, second);
      await expect(net.channels.get(1)!.collect('round1', [2], 500)).rejects.toMatchObject({ code, peer: 2 });
    }
  });

  it('a broadcast echo that differs per recipient aborts with `equivocation`', async () => {
    const net = createMemoryDkgNetwork([1, 2, 3], SID, (d) => {
      if (d.kind !== 'echo' || d.from !== 3 || d.to !== 2) return d.bytes;
      const m = dec(d.bytes);
      m.body.transcriptDigest = b64u(new Uint8Array(32).fill(7));
      return enc(m);
    });
    const out = await runAll(net.channels, 2, 2000);
    expect(codeOf(out[1]!)).toBe('equivocation');
  });

  it('a missing message at the timeout aborts the run with `timeout` and no key', async () => {
    const net = createMemoryDkgNetwork([1, 2, 3], SID, (d) => (d.kind === 'round1' && d.from === 2 && d.to === 1 ? null : d.bytes));
    const out = await runAll(net.channels, 2, 300);
    expect(out[0]!.status).toBe('rejected');
    expect(codeOf(out[0]!)).toBe('timeout');
    expect((out[0] as PromiseRejectedResult).reason.peer).toBe(2);
  });

  it('an oversize message is refused with `oversize` before it is parsed', async () => {
    const net = createMemoryDkgNetwork([1, 2], SID);
    net.deliver(2, 1, new Uint8Array(DKG_MAX_MESSAGE_BYTES + 1));
    await expect(net.channels.get(1)!.collect('round1', [2], 500)).rejects.toMatchObject({ code: 'oversize', peer: 2 });
  });

  it.each([
    ['not json', utf8('{{{')],
    ['duplicate key', utf8('{"v":1,"v":1,"sid":"x","kind":"round1","body":{}}')],
    ['extra member', enc({ v: 1, sid: b64u(SID), kind: 'round1', body: {}, extra: 1 })],
    ['unknown kind', enc({ v: 1, sid: b64u(SID), kind: 'nope', body: {} })],
    ['unknown version', enc({ v: 2, sid: b64u(SID), kind: 'round1', body: {} })],
  ])('a malformed envelope (%s) is `malformed`', async (_n, bytes) => {
    const net = createMemoryDkgNetwork([1, 2], SID);
    net.deliver(2, 1, bytes);
    await expect(net.channels.get(1)!.collect('round1', [2], 500)).rejects.toMatchObject({ code: 'malformed', peer: 2 });
  });

  it('a share with a bad signature (unsigned blame) aborts with `protocol`, not an accusation', async () => {
    const net = createMemoryDkgNetwork([1, 2, 3], SID, (d) => {
      if (d.kind !== 'share' || d.from !== 2 || d.to !== 1) return d.bytes;
      const m = dec(d.bytes);
      m.body.sig = b64u(new Uint8Array(64).fill(1));
      return enc(m);
    });
    const out = await runAll(net.channels, 2, 1000);
    expect(codeOf(out[0]!)).toBe('protocol');
  });

  it('a closed channel before the messages arrive is `closed`', async () => {
    const net = createMemoryDkgNetwork([1, 2], SID);
    const p = net.channels.get(1)!.collect('round1', [2], 5000);
    await net.channels.get(1)!.close();
    await expect(p).rejects.toMatchObject({ code: 'closed' });
  });

  it('the driver refuses a participant list that does not match the channel peers', async () => {
    const net = createMemoryDkgNetwork([1, 2, 3], SID);
    await expect(runDkgOverChannel(net.channels.get(1)!, { t: 2, participants: [1, 2], sessionId: SID })).rejects.toMatchObject({ code: 'protocol' });
    await expect(runDkgOverChannel(net.channels.get(1)!, { t: 4, participants: [1, 2, 3], sessionId: SID })).rejects.toMatchObject({ code: 'protocol' });
  });
});

describe('wire decoders are total', () => {
  it.each([null, 1, 'x', [], {}, { identifier: 1 }])('reject %j with a typed error', (x) => {
    for (const f of [() => decodeDkgRound1Package(x, 2), () => decodeDkgShareMessage(x), () => decodeDkgComplaints(x), () => decodeDkgEcho(x)]) {
      expect(f).toThrow(DkgChannelError);
    }
  });
  it('decodeDkgMessage rejects non-bytes', () => {
    expect(() => decodeDkgMessage('x' as never, SID)).toThrow(DkgChannelError);
  });
});

// ---- mutual TLS ------------------------------------------------------------------------------------

const identity = tlsIdentity;

async function tlsMesh(ids: ParticipantId[]) {
  const idents = new Map(ids.map((id) => [id, identity(`p${id}`)]));
  const nodes = new Map<ParticipantId, Awaited<ReturnType<typeof startTlsDkgNode>>>();
  for (const id of ids) {
    nodes.set(
      id,
      await startTlsDkgNode({
        self: id,
        sessionId: SID,
        ...idents.get(id)!,
        peerCerts: ids.filter((p) => p !== id).map((p) => ({ id: p, certPem: idents.get(p)!.certPem })),
      }),
    );
  }
  const addrs = ids.map((id) => ({ id, host: '127.0.0.1', port: nodes.get(id)!.port }));
  return { idents, nodes, addrs };
}

describe('DKG over reference mutual TLS (loopback)', () => {
  it.each([
    [2, [1, 2, 3]],
    [3, [1, 2, 3, 4, 5]],
  ])('%i-of-%i over pinned TLS 1.3 yields a key that signs', async (t, ids) => {
    const { nodes, addrs } = await tlsMesh(ids);
    const chans = await Promise.all(ids.map((id) => nodes.get(id)!.connect(addrs.filter((a) => a.id !== id))));
    const out = await runAll(new Map(ids.map((id, i) => [id, chans[i]!])), t, 15_000);
    await Promise.all(chans.map((c) => c.close()));
    expect(out.map((o) => o.status)).toEqual(ids.map(() => 'fulfilled'));
    const results = out.map((o) => (o as PromiseFulfilledResult<RunDkgResult>).value);
    const msg = utf8('tls dkg');
    expect(verify(results[0]!.keyPackage.groupPublicKey, msg, signWith(results, ids.slice(0, t), msg))).toBe(true);
  }, 60_000);

  it('a peer with an unpinned certificate gets no link: connect times out with `timeout`', async () => {
    const { nodes, addrs, idents } = await tlsMesh([1, 2]);
    const rogue = identity('rogue');
    const target = nodes.get(1)!;
    const sock = nodeTls.connect({ host: '127.0.0.1', port: target.port, key: rogue.keyPem, cert: rogue.certPem, ca: [idents.get(1)!.certPem], minVersion: 'TLSv1.3', checkServerIdentity: () => undefined });
    const closed = new Promise<void>((r) => {
      sock.on('error', () => undefined);
      sock.on('close', () => r());
    });
    await expect(target.connect(addrs.filter((a) => a.id !== 1), 600)).rejects.toMatchObject({ code: 'timeout', peer: 2 });
    await closed;
    await nodes.get(2)!.close();
  }, 20_000);

  it('a plaintext client is dropped and never becomes a link', async () => {
    const { nodes, addrs } = await tlsMesh([1, 2]);
    const target = nodes.get(1)!;
    const raw = nodeNet.connect({ host: '127.0.0.1', port: target.port });
    raw.on('error', () => undefined);
    const closed = new Promise<void>((r) => raw.on('close', () => r()));
    raw.write(encodeDkgMessage(SID, 'round1', { x: 1 }));
    await expect(target.connect(addrs.filter((a) => a.id !== 1), 600)).rejects.toMatchObject({ code: 'timeout' });
    await closed;
    await nodes.get(2)!.close();
  }, 20_000);

  it('a TLS 1.2 client is refused', async () => {
    const { nodes, idents } = await tlsMesh([1, 2]);
    const sock = nodeTls.connect({ host: '127.0.0.1', port: nodes.get(1)!.port, key: idents.get(2)!.keyPem, cert: idents.get(2)!.certPem, ca: [idents.get(1)!.certPem], maxVersion: 'TLSv1.2', checkServerIdentity: () => undefined });
    const outcome = await new Promise<string>((r) => {
      sock.on('secureConnect', () => r('connected'));
      sock.on('error', () => r('refused'));
    });
    expect(outcome).toBe('refused');
    await nodes.get(1)!.close();
    await nodes.get(2)!.close();
  }, 20_000);

  it('a pinned peer cannot claim another identity: a lower-numbered peer dialling in is dropped', async () => {
    const { nodes, idents } = await tlsMesh([1, 2]);
    // node 2 expects node 1 to be dialled BY it; node 1 dialling node 2 is the wrong direction and is refused
    const sock = nodeTls.connect({ host: '127.0.0.1', port: nodes.get(2)!.port, key: idents.get(1)!.keyPem, cert: idents.get(1)!.certPem, ca: [idents.get(2)!.certPem], minVersion: 'TLSv1.3', checkServerIdentity: () => undefined });
    sock.on('error', () => undefined);
    await new Promise<void>((r) => sock.on('close', () => r()));
    await nodes.get(1)!.close();
    await nodes.get(2)!.close();
  }, 20_000);

  it('an oversize frame length closes the link and fails the peer with `oversize`', async () => {
    const { nodes, addrs, idents } = await tlsMesh([1, 2]);
    const c1p = nodes.get(1)!.connect(addrs.filter((a) => a.id !== 1));
    const sock = nodeTls.connect({ host: '127.0.0.1', port: nodes.get(1)!.port, key: idents.get(2)!.keyPem, cert: idents.get(2)!.certPem, ca: [idents.get(1)!.certPem], minVersion: 'TLSv1.3', checkServerIdentity: () => undefined });
    sock.on('error', () => undefined);
    await new Promise<void>((r) => sock.once('secureConnect', () => r()));
    const c1 = await c1p;
    const len = Buffer.alloc(4);
    len.writeUInt32BE(DKG_MAX_MESSAGE_BYTES + 1, 0);
    sock.write(len);
    await expect(c1.collect('round1', [2], 3000)).rejects.toMatchObject({ code: 'oversize', peer: 2 });
    sock.destroy();
    await c1.close();
    await nodes.get(2)!.close();
  }, 20_000);
});
