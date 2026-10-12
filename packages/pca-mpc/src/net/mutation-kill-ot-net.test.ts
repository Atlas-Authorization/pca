import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

// Deterministic randomness so pad digests are reproducible and can be pinned.
vi.mock('../csprng', async (orig) => {
  const real = (await orig()) as Record<string, unknown>;
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  return {
    ...real,
    secureOtRandom: () => {
      let ctr = 0;
      const block = (): Buffer => createHash('sha256').update('ot-net-kill').update(String(ctr++)).digest();
      return {
        scalar(): bigint {
          let acc = 0n;
          for (const b of block()) acc = (acc << 8n) | BigInt(b);
          return (acc % (L - 1n)) + 1n;
        },
        bytes(n: number): Uint8Array {
          const out = new Uint8Array(n);
          let w = 0;
          while (w < n) {
            const b = block();
            const k = Math.min(32, n - w);
            out.set(b.subarray(0, k), w);
            w += k;
          }
          return out;
        },
      };
    },
  };
});


const hooks: { derive?: () => never; respond?: () => never } = {};
vi.mock('../ot', async (orig) => {
  const real = (await orig()) as Record<string, (...a: unknown[]) => unknown>;
  return {
    ...real,
    malBaseOtSenderDerive: (...a: unknown[]) => (hooks.derive ? hooks.derive() : real.malBaseOtSenderDerive!(...a)),
    malBaseOtReceiverRespond: (...a: unknown[]) => (hooks.respond ? hooks.respond() : real.malBaseOtReceiverRespond!(...a)),
  };
});

import { BaseOtAbort } from '../ot';
import { BASE, Q, isWasmCurveActive, mulBase, toAffine } from '../ec';
import { NetAbort, hx } from './wire';
import { J, b64, hexBig, jPt, netBinding, ptJ, runOtReceiver, runOtSender, unb64, type OtKind } from './ot-net';

type Tap = (from: number, rd: string, d: unknown) => unknown;
class FakeMesh {
  readonly sessionId: string;
  readonly sent: Array<{ to: number; rd: string; d: unknown }> = [];
  readonly failures: NetAbort[] = [];
  finished = 0;
  peer: FakeMesh | null = null;
  private q: Array<{ rd: string; d: unknown }> = [];
  private waiter: (() => void) | null = null;
  scripted: Record<string, unknown> = {};
  constructor(readonly selfId: number, sid: string, private tap: Tap = (_f, _r, d) => d) {
    this.sessionId = sid;
  }
  send(to: number, rd: string, d: unknown): void {
    const copy = this.tap(this.selfId, rd, structuredClone(d));
    this.sent.push({ to, rd, d: copy });
    if (this.peer) {
      this.peer.q.push({ rd, d: copy });
      this.peer.waiter?.();
    }
  }
  async recv(_from: number, rd: string): Promise<unknown> {
    if (rd in this.scripted) return this.scripted[rd];
    for (;;) {
      const it = this.q.shift();
      if (it) {
        if (it.rd !== rd) throw new Error(`fake mesh: expected ${rd} got ${it.rd}`);
        return it.d;
      }
      await new Promise<void>((r) => {
        this.waiter = r;
      });
    }
  }
  fail(e: NetAbort): void {
    this.failures.push(e);
  }
  async finish(): Promise<void> {
    this.finished++;
  }
}
const pair = (tap?: Tap, sid = 'sess-1'): [FakeMesh, FakeMesh] => {
  const a = new FakeMesh(0, sid, tap), b = new FakeMesh(1, sid, tap);
  a.peer = b;
  b.peer = a;
  return [a, b];
};
const sha = (...p: Uint8Array[]): string => {
  const h = createHash('sha256');
  for (const x of p) h.update(x);
  return h.digest('hex');
};

describe('codec helpers', () => {
  it('b64 is standard base64', () => {
    expect(b64(new Uint8Array([251, 255, 0]))).toBe('+/8A');
    expect(b64(new Uint8Array([1]))).toBe('AQ==');
  });
  it('unb64 accepts only canonical base64 of the right length', () => {
    expect(Array.from(unb64('+/8A'))).toEqual([251, 255, 0]);
    expect(Array.from(unb64('AQ=='))).toEqual([1]);
    expect(Array.from(unb64('AQ==', 1))).toEqual([1]);
    expect(Array.from(unb64(''))).toEqual([]);
    expect(() => unb64(5)).toThrow('bad base64');
    expect(() => unb64('AQ=')).toThrow(); // padding alias / invalid
    expect(() => unb64('A*==')).toThrow('bad base64');
    expect(() => unb64('AQ==\n')).toThrow('bad base64');
    expect(() => unb64('AR==')).toThrow('non-canonical base64'); // trailing bits set
    expect(() => unb64('AQ==', 2)).toThrow('bad length');
    expect(() => unb64('AQ==', 0)).toThrow('bad length');
    expect(() => unb64('-_8A')).toThrow('bad base64');
  });
  it('J is "plain object"', () => {
    expect(J({})).toBe(true);
    expect(J({ a: 1 })).toBe(true);
    expect(J(null)).toBe(false);
    expect(J([])).toBe(false);
    expect(J('x')).toBe(false);
    expect(J(1)).toBe(false);
    expect(J(undefined)).toBe(false);
  });
  it('hexBig is canonical lowercase hex strictly below the curve field prime', () => {
    expect(hexBig('0')).toBe(0n);
    expect(hexBig('ff')).toBe(255n);
    expect(hexBig(hx(Q - 1n))).toBe(Q - 1n);
    expect(() => hexBig(hx(Q))).toThrow('non-canonical field element');
    expect(hexBig('1'.repeat(64))).toBe(BigInt('0x' + '1'.repeat(64)));
    expect(() => hexBig('1'.repeat(65))).toThrow('bad field element');
    expect(() => hexBig('00')).toThrow('bad field element');
    expect(() => hexBig('0f')).toThrow('bad field element');
    expect(() => hexBig('FF')).toThrow('bad field element');
    expect(() => hexBig('')).toThrow('bad field element');
    expect(() => hexBig('xyz')).toThrow('bad field element');
    expect(() => hexBig(7)).toThrow('bad field element');
    expect(() => hexBig('f'.repeat(64))).toThrow('non-canonical field element');
  });
  it('ptJ/jPt roundtrip a subgroup point and jPt validates', () => {
    const P = mulBase(5n);
    const j = ptJ(P);
    const a = toAffine(P);
    expect(j).toEqual({ x: hx(a.x), y: hx(a.y) });
    const back = jPt(j);
    expect(toAffine(back)).toEqual(a);
    expect(back.Z).toBe(1n);
    expect(() => jPt(null)).toThrow('bad point');
    expect(() => jPt([])).toThrow('bad point');
    expect(() => jPt({ x: j.x })).toThrow('bad field element');
    expect(() => jPt({ y: j.y })).toThrow('bad field element');
    expect(() => jPt({ x: '1', y: '1' })).toThrow('received point: not on curve');
    expect(() => jPt({ x: '0', y: '1' })).toThrow(/received point: identity/);
    expect(() => jPt({ x: '0', y: hx(Q - 1n) })).toThrow(/received point: not in the prime-order/);
    expect(toAffine(jPt(ptJ(BASE)))).toEqual(toAffine(BASE));
  });
  it('netBinding hashes the session under a fixed domain and carries sender/receiver/round', () => {
    const m = new FakeMesh(0, 'abc');
    const b = netBinding(m as never, 3, 4, 'rr');
    expect(Buffer.from(b.sessionId).toString('hex')).toBe(createHash('sha256').update('atlas-pca-mpc/net-session/v2').update('abc').digest('hex'));
    expect(b.sessionId).toBeInstanceOf(Uint8Array);
    expect(b.senderIndex).toBe(3);
    expect(b.receiverIndex).toBe(4);
    expect(b.round).toBe('rr');
    const b2 = netBinding(new FakeMesh(0, 'abd') as never, 3, 4, 'rr');
    expect(Buffer.from(b2.sessionId).equals(Buffer.from(b.sessionId))).toBe(false);
  });
});

async function run(kind: OtKind, count: number, tap?: Tap) {
  const [s, r] = pair(tap);
  const [rs, rr] = await Promise.all([runOtSender(s as never, 1, kind, count), runOtReceiver(r as never, 0, kind, count)]);
  return { s, r, rs, rr };
}

describe.each(['ec', 'lwe'] as const)('honest %s OT over the in-memory mesh', (kind) => {
  it('completes, both sides agree, results are well-formed', async () => {
    const { s, r, rs, rr } = await run(kind, 4);
    expect(rs).toMatchObject({ kind, role: 'sender', count: 4, matched: true, wasmCurveActive: isWasmCurveActive() });
    expect(rr).toMatchObject({ kind, role: 'receiver', count: 4, matched: true, wasmCurveActive: isWasmCurveActive() });
    expect(typeof rs.ms).toBe('number');
    expect(rs.ms).toBeGreaterThanOrEqual(0);
    expect(rr.ms).toBeGreaterThanOrEqual(0);
    expect(rs.padDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(rr.padDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(rs.padDigest).not.toBe(rr.padDigest);
    expect(rs.padDigest).not.toBe(sha());
    expect(rr.padDigest).not.toBe(sha());
    expect(s.finished).toBe(1);
    expect(r.finished).toBe(1);
    expect(s.failures).toEqual([]);
    expect(r.failures).toEqual([]);
  });
  it('wire rounds and shapes', async () => {
    const { s, r } = await run(kind, 3);
    if (kind === 'ec') {
      expect(s.sent.map((m) => [m.to, m.rd])).toEqual([[1, 'ot-S'], [1, 'ot-done']]);
      expect(Object.keys(s.sent[0]!.d as object).sort()).toEqual(['S', 'U', 'z']);
      expect(r.sent.map((m) => [m.to, m.rd])).toEqual([[0, 'ot-R'], [0, 'ot-verify']]);
      expect((r.sent[0]!.d as unknown[]).length).toBe(3);
    } else {
      expect(s.sent.map((m) => [m.to, m.rd])).toEqual([[1, 'ot-ct'], [1, 'ot-done']]);
      expect(r.sent.map((m) => [m.to, m.rd])).toEqual([[0, 'ot-recv'], [0, 'ot-verify']]);
      const rm = r.sent[0]!.d as { rn: string; points: string[][]; rhos: string[] };
      expect(Object.keys(rm).sort()).toEqual(['points', 'rhos', 'rn']);
      expect(rm.points.length).toBe(3);
      expect(rm.rhos.length).toBe(3);
      expect(unb64(rm.rn, 32).length).toBe(32);
      expect((s.sent[0]!.d as unknown[]).length).toBe(3);
    }
    expect(s.sent[1]!.d).toEqual({ matched: true });
    const v = r.sent[1]!.d as { choices: number[]; padHashes: string[] };
    expect(v.choices.length).toBe(3);
    expect(v.choices.every((c) => c === 0 || c === 1)).toBe(true);
    expect(v.padHashes.every((h) => /^[0-9a-f]{64}$/.test(h))).toBe(true);
  });
  it('pads are deterministic under a deterministic rng (pinned digests)', async () => {
    const a = await run(kind, 2);
    const b = await run(kind, 2);
    expect(a.rs.padDigest).toBe(b.rs.padDigest);
    expect(a.rr.padDigest).toBe(b.rr.padDigest);
    expect(a.rs.padDigest).toBe(GOLD[kind].s);
    expect(a.rr.padDigest).toBe(GOLD[kind].r);
  });
  it('sender reports matched=false when a pad hash is wrong or a choice is not a bit', async () => {
    const flip = (mut: (v: { choices: unknown[]; padHashes: unknown[] }) => unknown): Tap => (from, rd, d) => (from === 1 && rd === 'ot-verify' ? mut(d as never) : d);
    const wrongHash = await run(kind, 3, flip((v) => ({ ...v, padHashes: [v.padHashes[0], '0'.repeat(64), v.padHashes[2]] })));
    expect(wrongHash.rs.matched).toBe(false);
    expect(wrongHash.rr.matched).toBe(false);
    expect(wrongHash.s.sent[1]!.d).toEqual({ matched: false });
    for (const bad of [2, '1', null, -1, 0.5]) {
      const r = await run(kind, 3, flip((v) => ({ ...v, choices: [bad, v.choices[1], v.choices[2]] })));
      expect(r.rs.matched).toBe(false);
    }
    const flipped = await run(kind, 3, flip((v) => ({ ...v, choices: v.choices.map((c) => 1 - (c as number)) })));
    expect(flipped.rs.matched).toBe(false);
  });
  it('sender: malformed verify message aborts blaming the receiver', async () => {
    const bad: unknown[] = [null, 'x', [], { choices: [0, 1, 0] }, { padHashes: ['a', 'b', 'c'] }, { choices: [0, 1], padHashes: ['a', 'b', 'c'] }, { choices: [0, 1, 0], padHashes: ['a', 'b'] }, { choices: 'abc', padHashes: ['a', 'b', 'c'] }, { choices: [0, 1, 0], padHashes: 'abc' }];
    for (const v of bad) {
      const [s, r] = pair();
      s.scripted['ot-verify'] = v;
      // drive the sender only against a real receiver's first message
      const rp = runOtReceiver(r as never, 0, kind, 3).catch(() => null);
      await expect(runOtSender(s as never, 1, kind, 3)).rejects.toMatchObject({ kind: 'malformed', blamed: 1, reporter: 0 });
      expect(s.failures.length).toBe(1);
      expect(s.failures[0]!.message).toContain("round 'ot-verify': bad verify message");
      expect(s.finished).toBe(0);
      void rp;
    }
  });
  it('receiver: matched must be exactly boolean true', async () => {
    for (const [d, want] of [[{ matched: true }, true], [{ matched: false }, false], [{ matched: 'true' }, false], [{ matched: 1 }, false], [{}, false], [null, false], [[], false], ['x', false]] as const) {
      const [s, r] = pair();
      s.scripted = {};
      r.scripted['ot-done'] = d;
      const sp = runOtSender(s as never, 1, kind, 2).catch(() => null);
      const res = await runOtReceiver(r as never, 0, kind, 2);
      expect(res.matched).toBe(want);
      void sp;
    }
  });
});

const GOLD: Record<OtKind, { s: string; r: string }> = {
  ec: { s: 'f5109bdfd0cbb3210acf37ee7fcce82e6320456378481111408d2b20a50273c6', r: 'cc8dcc3ffbf0cf77cc02bc706067c948860bfea4c9f42f76a3666ce7dc793e9a' },
  lwe: { s: 'abd7af29911ffdc9fcc385e89caf80eae2b86c7d484e298b3734ac2312a8a938', r: 'bf6d351193a1dc6cdb4e622bcc3cd2eaacbe123c3b6be17bc0bb220ac026fdac' },
};

describe('ec sender rejects a bad receiver message', () => {
  const runS = async (R: unknown) => {
    const [s] = pair();
    s.scripted['ot-R'] = R;
    return { s, p: runOtSender(s as never, 1, 'ec', 2) };
  };
  it('wrong-size / non-array R aborts with malformed naming the peer', async () => {
    for (const R of [null, {}, 'x', [], [ptJ(mulBase(3n))], [ptJ(mulBase(3n)), ptJ(mulBase(4n)), ptJ(mulBase(5n))]]) {
      const { s, p } = await runS(R);
      await expect(p).rejects.toMatchObject({ kind: 'malformed', blamed: 1, reporter: 0 });
      expect(s.failures[0]!.message).toContain("round 'ot-R': bad R array");
    }
  });
  it('an invalid point in R aborts with malformed', async () => {
    const { s, p } = await runS([ptJ(mulBase(3n)), { x: '1', y: '1' }]);
    await expect(p).rejects.toMatchObject({ kind: 'malformed', blamed: 1 });
    expect(s.failures[0]!.message).toContain("round 'ot-R'");
    expect(s.failures[0]!.message).toMatch(/not on curve/);
  });
});

describe('ec receiver rejects a bad sender message', () => {
  const runR = async (S: unknown) => {
    const [, r] = pair();
    r.scripted['ot-S'] = S;
    return { r, p: runOtReceiver(r as never, 0, 'ec', 2) };
  };
  it('non-object S', async () => {
    for (const S of [null, [], 'x', 4]) {
      const { r, p } = await runR(S);
      await expect(p).rejects.toMatchObject({ kind: 'malformed', blamed: 0, reporter: 1 });
      expect(r.failures[0]!.message).toContain("round 'ot-S': bad S message");
    }
  });
  it('missing / invalid fields', async () => {
    const good = { S: ptJ(mulBase(7n)), U: ptJ(mulBase(8n)), z: '5' };
    for (const S of [{ ...good, U: undefined }, { ...good, S: undefined }, { ...good, z: undefined }, { ...good, z: hx(Q) }, { ...good, S: { x: '1', y: '1' } }, { ...good, U: { x: '0', y: '1' } }]) {
      const { r, p } = await runR(S);
      await expect(p).rejects.toMatchObject({ kind: 'malformed', blamed: 0, reporter: 1 });
      expect(r.failures.length).toBe(1);
      expect(r.failures[0]!.message).toContain("round 'ot-S'");
    }
  });
  it('a Schnorr proof that does not verify aborts as a commitment failure blaming the sender', async () => {
    const { r, p } = await runR({ S: ptJ(mulBase(7n)), U: ptJ(mulBase(8n)), z: '5' });
    await expect(p).rejects.toMatchObject({ kind: 'commitment', blamed: 0, reporter: 1 });
    expect(r.failures.length).toBe(1);
  });
});

describe('lwe sender rejects a bad receiver message', () => {
  const good = async () => {
    const [s, r] = pair();
    s.scripted = {};
    const rp = runOtReceiver(r as never, 0, 'lwe', 2).catch(() => null);
    await new Promise((x) => setTimeout(x, 20));
    const captured: unknown = r.sent.find((m) => m.rd === 'ot-recv')!.d;
    void rp;
    return captured as { rn: string; points: string[][]; rhos: string[] };
  };
  const tryS = async (m: unknown) => {
    const [s] = pair();
    s.scripted['ot-recv'] = m;
    return { s, p: runOtSender(s as never, 1, 'lwe', 2) };
  };
  it('structurally bad messages', async () => {
    const g = await good();
    const cases: unknown[] = [
      null, [], 'x',
      { ...g, points: undefined }, { ...g, rhos: undefined }, { ...g, points: 'x' }, { ...g, rhos: 'x' },
      { ...g, points: g.points.slice(1) }, { ...g, rhos: g.rhos.slice(1) },
      { ...g, points: [...g.points, g.points[0]] }, { ...g, rhos: [...g.rhos, g.rhos[0]] },
    ];
    for (const m of cases) {
      const { s, p } = await tryS(m);
      await expect(p).rejects.toMatchObject({ kind: 'malformed', blamed: 1, reporter: 0 });
      expect(s.failures[0]!.message).toContain("round 'ot-recv': bad receiver message");
    }
  });
  it('bad field encodings', async () => {
    const g = await good();
    const cases: Array<[unknown, string]> = [
      [{ ...g, rn: undefined }, 'bad base64'],
      [{ ...g, rn: b64(new Uint8Array(31)) }, 'bad length'],
      [{ ...g, rn: b64(new Uint8Array(33)) }, 'bad length'],
      [{ ...g, points: [g.points[0], 'x'] }, 'bad point pair'],
      [{ ...g, points: [g.points[0], [g.points[1]![0]]] }, 'bad point pair'],
      [{ ...g, points: [g.points[0], [g.points[1]![0], g.points[1]![1], g.points[1]![1]]] }, 'bad point pair'],
      [{ ...g, points: [g.points[0], [5, g.points[1]![1]]] }, 'bad base64'],
      [{ ...g, points: [g.points[0], [g.points[1]![0], 5]] }, 'bad base64'],
      [{ ...g, rhos: [g.rhos[0], b64(new Uint8Array(31))] }, 'bad length'],
      [{ ...g, rhos: [g.rhos[0], 5] }, 'bad base64'],
    ];
    for (const [m, why] of cases) {
      const { s, p } = await tryS(m);
      await expect(p).rejects.toMatchObject({ kind: 'malformed', blamed: 1 });
      expect(s.failures[0]!.message).toContain(why);
    }
  });
  it('a message the LWE sender itself refuses is reported with the lwe sender prefix', async () => {
    const g = await good();
    const { s, p } = await tryS({ ...g, points: [[b64(new Uint8Array(3)), b64(new Uint8Array(3))], [b64(new Uint8Array(3)), b64(new Uint8Array(3))]] });
    await expect(p).rejects.toMatchObject({ kind: 'malformed', blamed: 1, reporter: 0 });
    expect(s.failures[0]!.message).toContain('lwe sender: ');
  });
});

describe('lwe receiver rejects a bad ciphertext message', () => {
  const tryR = async (ct: unknown) => {
    const [, r] = pair();
    r.scripted['ot-ct'] = ct;
    return { r, p: runOtReceiver(r as never, 0, 'lwe', 2) };
  };
  it('non-array / wrong length / bad pairs', async () => {
    const z = b64(new Uint8Array(4));
    for (const [ct, why] of [[null, 'bad ciphertext array'], ['x', 'bad ciphertext array'], [[[z, z]], 'bad ciphertext array'], [[[z, z], [z, z], [z, z]], 'bad ciphertext array'], [[[z, z], 'x'], 'bad ct pair'], [[[z, z], [z]], 'bad ct pair'], [[[z, z], [z, z, z]], 'bad ct pair'], [[[z, z], [5, z]], 'bad base64']] as const) {
      const { r, p } = await tryR(ct);
      await expect(p).rejects.toMatchObject({ kind: 'malformed', blamed: 0, reporter: 1 });
      expect(r.failures[0]!.message).toContain("round 'ot-ct'");
      expect(r.failures[0]!.message).toContain(why);
    }
  });
  it('ciphertexts the LWE receiver cannot recover from abort with malformed in round ot-ct', async () => {
    const z = b64(new Uint8Array(4));
    const { r, p } = await tryR([[z, z], [z, z]]);
    await expect(p).rejects.toMatchObject({ kind: 'malformed', blamed: 0, reporter: 1 });
    expect(r.failures[0]!.message).toContain("round 'ot-ct'");
  });
});

describe('hooks on the underlying OT primitives', () => {
  it('a sender-derive failure aborts as malformed naming the peer, with the primitive\'s message', async () => {
    hooks.derive = () => {
      throw new Error('derive boom');
    };
    try {
      const [s] = pair();
      s.scripted['ot-R'] = [ptJ(mulBase(3n)), ptJ(mulBase(4n))];
      await expect(runOtSender(s as never, 1, 'ec', 2)).rejects.toMatchObject({ kind: 'malformed', blamed: 1, reporter: 0 });
      expect(s.failures.length).toBe(1);
      expect(s.failures[0]!.message).toBe('[malformed] blamed=1 reporter=0: derive boom');
    } finally {
      delete hooks.derive;
    }
  });
  it('a receiver-respond failure is a commitment abort only for BaseOtAbort, otherwise malformed', async () => {
    const S = { S: ptJ(mulBase(7n)), U: ptJ(mulBase(8n)), z: '5' };
    for (const [err, kind] of [[new BaseOtAbort('proof failed'), 'commitment'], [new Error('other'), 'malformed'], [new RangeError('range'), 'malformed']] as const) {
      hooks.respond = () => {
        throw err;
      };
      try {
        const [, r] = pair();
        r.scripted['ot-S'] = S;
        await expect(runOtReceiver(r as never, 0, 'ec', 2)).rejects.toMatchObject({ kind, blamed: 0, reporter: 1 });
        expect(r.failures[0]!.message).toBe(`[${kind}] blamed=0 reporter=1: ${err.message}`);
      } finally {
        delete hooks.respond;
      }
    }
  });
});

describe('timing', () => {
  it('ms is the elapsed performance.now() between start and the result', async () => {
    const [s, r] = pair();
    let t = 5000;
    const spy = vi.spyOn(performance, 'now').mockImplementation(() => (t += 7));
    try {
      const [rs, rr] = await Promise.all([runOtSender(s as never, 1, 'lwe', 1), runOtReceiver(r as never, 0, 'lwe', 1)]);
      expect(Number.isInteger(rs.ms / 7)).toBe(true);
      expect(Number.isInteger(rr.ms / 7)).toBe(true);
      expect(rs.ms).toBeGreaterThan(0);
      expect(rs.ms).toBeLessThan(7 * 20);
      expect(rr.ms).toBeGreaterThan(0);
      expect(rr.ms).toBeLessThan(7 * 20);
    } finally {
      spy.mockRestore();
    }
  });
});
