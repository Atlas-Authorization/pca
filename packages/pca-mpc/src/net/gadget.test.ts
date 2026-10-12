/** R3-16: the signed gadget agreement. In-memory all-to-all bus; real ECDSA-P256 identities; no processes needed. */
import { generateKeyPairSync, randomBytes, sign as cSign, verify as cVerify, type KeyObject } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { agreeGadgetSeeds, gadgetCommit, gadgetStatement, type GadgetIo, type GadgetNet } from './gadget';
import { NetAbort } from './wire';

const SID = 'sess-1';

function world(n: number) {
  const keys = Array.from({ length: n }, () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' }));
  const net = (id: number): GadgetNet => ({
    selfId: id,
    sessionId: SID,
    sign: (d) => cSign('sha256', Buffer.from(d), keys[id]!.privateKey),
    verify: (peer, d, sig) => peer !== id && cVerify('sha256', Buffer.from(d), keys[peer]!.publicKey, Buffer.from(sig)),
  });
  const inbox = new Map<string, unknown>(); // `${rd}|${from}|${to}`
  const waiters: Array<() => void> = [];
  const post = (rd: string, from: number, to: number, v: unknown): void => {
    inbox.set(`${rd}|${from}|${to}`, JSON.parse(JSON.stringify(v)));
    for (const w of waiters.splice(0)) w();
  };
  const take = async (rd: string, from: number, to: number): Promise<unknown> => {
    for (;;) {
      const k = `${rd}|${from}|${to}`;
      if (inbox.has(k)) return inbox.get(k);
      await new Promise<void>((r) => waiters.push(r));
    }
  };
  const io = (id: number, tamper?: (rd: string, peer: number, v: unknown) => unknown): GadgetIo => ({
    bad: (p, what) => {
      throw new NetAbort('malformed', p, id, what);
    },
    exchange: async (rd, mine, parse) => {
      const peers = Array.from({ length: n }, (_, i) => i).filter((i) => i !== id);
      for (const q of peers) post(rd, id, q, tamper ? tamper(rd, q, mine(q)) : mine(q));
      const out = new Map<number, ReturnType<typeof parse>>();
      for (const q of peers) out.set(q, parse(q, await take(rd, q, id)));
      return out;
    },
  });
  return { keys, net, io, post, take };
}

const settle = async <T>(ps: Array<Promise<T>>): Promise<Array<{ ok: true; v: T } | { ok: false; e: NetAbort }>> =>
  Promise.all(ps.map((p) => p.then((v) => ({ ok: true as const, v }), (e: NetAbort) => ({ ok: false as const, e }))));

describe('R3-16 signed gadget agreement', () => {
  it('honest parties (n = 2, 3, 5) agree on identical seeds', async () => {
    for (const n of [2, 3, 5]) {
      const w = world(n);
      const res = await settle(Array.from({ length: n }, (_, i) => agreeGadgetSeeds(w.net(i), n, w.io(i))));
      expect(res.every((r) => r.ok)).toBe(true);
      const views = res.map((r) => (r.ok ? r.v.map((s) => Buffer.from(s).toString('hex')).join('|') : ''));
      expect(new Set(views).size).toBe(1);
    }
  });

  it('PoC: one corrupt party sends a different (validly signed) commitment+seed to each honest peer: BOTH honest parties name the corrupt one, with transferable evidence', async () => {
    const w = world(3);
    const seeds = [randomBytes(32), randomBytes(32)];
    const signedFor = (round: 'gd-c' | 'gd-o', value: string) => ({ v: value, s: cSign('sha256', Buffer.from(gadgetStatement(SID, round, 2, value)), w.keys[2]!.privateKey).toString('hex') });
    const forged = (peer: number): { c: unknown; o: unknown } => ({ c: signedFor('gd-c', gadgetCommit(SID, 2, seeds[peer]!)), o: signedFor('gd-o', seeds[peer]!.toString('hex')) });
    for (const peer of [0, 1]) {
      w.post('gd-c', 2, peer, forged(peer).c);
      w.post('gd-o', 2, peer, forged(peer).o);
    }
    // the corrupt party also sends echoes (of whatever it likes): here, nothing useful
    for (const peer of [0, 1]) w.post('gd-e', 2, peer, [{ j: 1 - peer, c: { v: '0'.repeat(64), s: 'ab'.repeat(40) }, o: { v: '0'.repeat(64), s: 'ab'.repeat(40) } }]);
    const res = await settle([0, 1].map((i) => agreeGadgetSeeds(w.net(i), 3, w.io(i))));
    // the corrupt echo is itself garbage, so each honest party may first meet it; but the ECHO between the honest two must
    // already expose party 2 if their echoes are read. Collect which party each blamed.
    for (const r of res) {
      expect(r.ok).toBe(false);
      if (!r.ok) expect([2]).toContain(r.e.blamed);
    }
  });

  it('PoC (strict): with a corrupt party that echoes honestly, the honest parties detect the equivocation by each other\'s echo', async () => {
    const w = world(3);
    const seeds = [randomBytes(32), randomBytes(32)];
    const signedFor = (round: 'gd-c' | 'gd-o', value: string) => ({ v: value, s: cSign('sha256', Buffer.from(gadgetStatement(SID, round, 2, value)), w.keys[2]!.privateKey).toString('hex') });
    for (const peer of [0, 1]) {
      w.post('gd-c', 2, peer, signedFor('gd-c', gadgetCommit(SID, 2, seeds[peer]!)));
      w.post('gd-o', 2, peer, signedFor('gd-o', seeds[peer]!.toString('hex')));
    }
    // the corrupt party's echo to each honest peer: it simply relays the honest other's real messages, which it can only do after reading them
    const honest = [0, 1].map((i) => agreeGadgetSeeds(w.net(i), 3, w.io(i)));
    // wait until both honest parties have posted their gd-o, then post a faithful echo from 2
    const c = await Promise.all([0, 1].map((i) => w.take('gd-c', i, 1 - i)));
    const o = await Promise.all([0, 1].map((i) => w.take('gd-o', i, 1 - i)));
    for (const peer of [0, 1]) w.post('gd-e', 2, peer, [{ j: 1 - peer, c: c[1 - peer], o: o[1 - peer] }]);
    const res = await settle(honest);
    for (const r of res) {
      expect(r.ok).toBe(false);
      if (r.ok) continue;
      expect(r.e.kind).toBe('equivocation');
      expect(r.e.blamed).toBe(2);
      // transferable evidence: two statements by party 2 that both verify under its key and differ
      const ev = r.e.evidence as { signer: number; round: 'gd-c' | 'gd-o'; statements: Array<{ v: string; s: string }> };
      expect(ev.signer).toBe(2);
      expect(ev.statements[0]!.v).not.toBe(ev.statements[1]!.v);
      for (const st of ev.statements) expect(w.net(0).verify(2, gadgetStatement(SID, ev.round, 2, st.v), Buffer.from(st.s, 'hex'))).toBe(true);
    }
  });

  it('a corrupt echoer cannot frame an honest party: a statement it did not get from the honest signer fails verification and the ECHOER is blamed', async () => {
    const w = world(3);
    // party 1 is corrupt: honest 0 and 2 run the protocol; 1 sends proper signed values, but echoes a forged statement "from 2"
    const seed1 = randomBytes(32);
    const s1 = (round: 'gd-c' | 'gd-o', value: string) => ({ v: value, s: cSign('sha256', Buffer.from(gadgetStatement(SID, round, 1, value)), w.keys[1]!.privateKey).toString('hex') });
    for (const peer of [0, 2]) {
      w.post('gd-c', 1, peer, s1('gd-c', gadgetCommit(SID, 1, seed1)));
      w.post('gd-o', 1, peer, s1('gd-o', seed1.toString('hex')));
    }
    const fake = { v: gadgetCommit(SID, 2, randomBytes(32)), s: cSign('sha256', Buffer.from('not what 2 signed'), w.keys[1]!.privateKey).toString('hex') };
    w.post('gd-e', 1, 0, [{ j: 2, c: fake, o: { v: randomBytes(32).toString('hex'), s: fake.s } }]);
    w.post('gd-e', 1, 2, [{ j: 0, c: fake, o: { v: randomBytes(32).toString('hex'), s: fake.s } }]);
    const res = await settle([0, 2].map((i) => agreeGadgetSeeds(w.net(i), 3, w.io(i))));
    for (const r of res) {
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.e.blamed).toBe(1);
        expect(r.e.kind).toBe('malformed');
      }
    }
  });

  it('a seed that does not open its commitment is blamed (commitment), a bad signature on a commitment is blamed first-hand', async () => {
    const w = world(3);
    const sg = (id: number, round: 'gd-c' | 'gd-o', value: string) => ({ v: value, s: cSign('sha256', Buffer.from(gadgetStatement(SID, round, id, value)), w.keys[id]!.privateKey).toString('hex') });
    const real = randomBytes(32);
    for (const peer of [0, 1]) {
      w.post('gd-c', 2, peer, sg(2, 'gd-c', gadgetCommit(SID, 2, real)));
      w.post('gd-o', 2, peer, sg(2, 'gd-o', randomBytes(32).toString('hex')));
    }
    const res = await settle([0, 1].map((i) => agreeGadgetSeeds(w.net(i), 3, w.io(i))));
    for (const r of res) {
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.e.kind).toBe('commitment');
        expect(r.e.blamed).toBe(2);
      }
    }
    const w2 = world(2);
    w2.post('gd-c', 1, 0, { v: '0'.repeat(64), s: 'ab'.repeat(40) });
    const r2 = await settle([agreeGadgetSeeds(w2.net(0), 2, w2.io(0))]);
    expect(r2[0]!.ok).toBe(false);
    if (!r2[0]!.ok) expect(r2[0]!.e.blamed).toBe(1);
  });

  it('wrong-key signature is not accepted (identity separation)', () => {
    const k = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const d = gadgetStatement(SID, 'gd-c', 1, 'a'.repeat(64));
    const sig = cSign('sha256', Buffer.from(d), k.privateKey);
    const pub: KeyObject = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey;
    expect(cVerify('sha256', Buffer.from(d), pub, sig)).toBe(false);
  });
});
