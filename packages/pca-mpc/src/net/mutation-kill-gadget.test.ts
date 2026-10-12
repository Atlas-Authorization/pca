import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { type GadgetNet, agreeGadgetSeeds, gadgetCommit, gadgetStatement } from './gadget';
import { NetAbort } from './wire';

const sigOf = (signer: number, data: Uint8Array): Buffer => createHash('sha256').update('test-sig').update(String(signer)).update(data).digest();
const mkNet = (id: number, sid = 'S'): GadgetNet => ({
  selfId: id,
  sessionId: sid,
  sign: (d) => sigOf(id, d),
  verify: (peer, d, sig) => Buffer.from(sig).equals(sigOf(peer, d)),
});
const seedOf = (p: number): Uint8Array => new Uint8Array(32).fill(0xa0 + p);
const hex = (u: Uint8Array): string => Buffer.from(u).toString('hex');
const signed = (signer: number, round: 'gd-c' | 'gd-o', value: string, sid = 'S') => ({ v: value, s: sigOf(signer, gadgetStatement(sid, round, signer, value)).toString('hex') });
const commitMsg = (p: number, seed = seedOf(p)) => signed(p, 'gd-c', gadgetCommit('S', p, seed));
const openMsg = (p: number, seed = seedOf(p)) => signed(p, 'gd-o', hex(seed));

type Script = Partial<Record<'gd-c' | 'gd-o' | 'gd-e', (p: number) => unknown>>;
async function run(n: number, script: Script = {}, id = 0, mySeed: Uint8Array = seedOf(id)) {
  const rounds: string[] = [];
  const mine: Record<string, unknown[]> = {};
  const bads: Array<[number, string]> = [];
  const others = Array.from({ length: n }, (_, i) => i).filter((i) => i !== id);
  const honestEcho = (p: number): unknown => others.filter((j) => j !== p).map((j) => ({ j, c: commitMsg(j), o: openMsg(j) }));
  const io = {
    bad: (p: number, what: string): never => {
      bads.push([p, what]);
      throw new NetAbort('malformed', p, id, what);
    },
    exchange: async <T>(rd: string, m: (peer: number) => unknown, parse: (p: number, raw: unknown) => T): Promise<Map<number, T>> => {
      rounds.push(rd);
      mine[rd] = others.map((q) => m(q));
      const out = new Map<number, T>();
      for (const p of others) {
        const raw = script[rd as 'gd-c'] ? script[rd as 'gd-c']!(p) : rd === 'gd-c' ? commitMsg(p) : rd === 'gd-o' ? openMsg(p) : honestEcho(p);
        out.set(p, parse(p, raw));
      }
      return out;
    },
  };
  const res = await agreeGadgetSeeds(mkNet(id), n, io, mySeed).then((v) => ({ ok: true as const, v }), (e: unknown) => ({ ok: false as const, e: e as NetAbort }));
  return { res, rounds, mine, bads };
}

describe('shape anchors (run first: module-level regexes)', () => {
  it('commitment and signature shapes are anchored at both ends', async () => {
    const v = commitMsg(1);
    for (const c of [{ v: 'x' + v.v, s: v.s }, { v: v.v + 'x', s: v.s }, { v: v.v, s: 'x' + v.s }, { v: v.v, s: v.s + 'x' }, { v: v.v, s: 'g'.repeat(40) }, { v: 'f'.repeat(63), s: v.s }]) {
      const { res, bads } = await run(2, { 'gd-c': () => c });
      expect(res.ok).toBe(false);
      expect(bads).toEqual([[1, 'bad gadget commitment']]);
    }
    const o = openMsg(1);
    for (const c of [{ v: 'x' + o.v, s: o.s }, { v: o.v + 'x', s: o.s }]) {
      const { res, bads } = await run(2, { 'gd-o': () => c });
      expect(res.ok).toBe(false);
      expect(bads).toEqual([[1, 'bad gadget seed']]);
    }
  });
});

describe('gadgetCommit / gadgetStatement', () => {
  it('commitment is SHA-256 over a fixed domain, session, party and seed (pinned)', () => {
    const c = gadgetCommit('sess', 3, new Uint8Array([1, 2, 3]));
    expect(c).toBe(createHash('sha256').update('atlas-pca-mpc/gadget-commit').update('sess').update('3').update(Buffer.from([1, 2, 3])).digest('hex'));
    expect(c).toMatch(/^[0-9a-f]{64}$/);
    expect(gadgetCommit('sess', 4, new Uint8Array([1, 2, 3]))).not.toBe(c);
    expect(gadgetCommit('sesu', 3, new Uint8Array([1, 2, 3]))).not.toBe(c);
    expect(gadgetCommit('sess', 3, new Uint8Array([1, 2, 4]))).not.toBe(c);
  });
  it('statement bytes are the JSON of [domain, session, round, signer, value]', () => {
    expect(Buffer.from(gadgetStatement('s', 'gd-c', 2, 'v')).toString('utf8')).toBe('["atlas-pca-mpc/gadget-sig/v1","s","gd-c",2,"v"]');
    expect(Buffer.from(gadgetStatement('s"x', 'gd-o', 0, 'a,b')).toString('utf8')).toBe('["atlas-pca-mpc/gadget-sig/v1","s\\"x","gd-o",0,"a,b"]');
  });
});

describe('agreeGadgetSeeds (honest)', () => {
  it('two parties: commit and open only (no echo), seeds returned in party order', async () => {
    for (const id of [0, 1]) {
      const { res, rounds, mine } = await run(2, {}, id);
      expect(rounds).toEqual(['gd-c', 'gd-o']);
      expect(res.ok).toBe(true);
      if (!res.ok) return;
      expect(res.v.map(hex)).toEqual([hex(seedOf(0)), hex(seedOf(1))]);
      expect(res.v[id]).toBeInstanceOf(Uint8Array);
      // my own messages are signed under my identity for the right round
      expect(mine['gd-c']![0]).toEqual(signed(id, 'gd-c', gadgetCommit('S', id, seedOf(id))));
      expect(mine['gd-o']![0]).toEqual(signed(id, 'gd-o', hex(seedOf(id))));
    }
  });
  it('three and four parties add the echo round, and every party gets every seed', async () => {
    for (const n of [3, 4]) {
      for (let id = 0; id < n; id++) {
        const { res, rounds, mine } = await run(n, {}, id);
        expect(rounds).toEqual(['gd-c', 'gd-o', 'gd-e']);
        expect(res.ok).toBe(true);
        if (!res.ok) return;
        expect(res.v.map(hex)).toEqual(Array.from({ length: n }, (_, p) => hex(seedOf(p))));
        // echo to peer q carries every OTHER party (not q, not me) in ascending order with the exact signed statements
        const others = Array.from({ length: n }, (_, i) => i).filter((i) => i !== id);
        others.forEach((q, qi) => {
          const echo = mine['gd-e']![qi] as Array<{ j: number; c: unknown; o: unknown }>;
          const want = others.filter((j) => j !== q);
          expect(echo.map((e) => e.j)).toEqual(want);
          for (const e of echo) {
            expect(e.c).toEqual(commitMsg(e.j));
            expect(e.o).toEqual(openMsg(e.j));
          }
        });
      }
    }
  });
  it('mySeed defaults to 32 random bytes', async () => {
    const io = {
      bad: (p: number, w: string): never => {
        throw new Error(`${p}${w}`);
      },
      exchange: async <T>(rd: string, m: (peer: number) => unknown, parse: (p: number, raw: unknown) => T): Promise<Map<number, T>> => {
        const raw = m(1) as { v: string };
        const out = new Map<number, T>();
        out.set(1, parse(1, rd === 'gd-c' ? commitMsg(1) : openMsg(1)));
        void raw;
        return out;
      },
    };
    const r1 = await agreeGadgetSeeds(mkNet(0), 2, io);
    const r2 = await agreeGadgetSeeds(mkNet(0), 2, io);
    expect(r1[0]!.length).toBe(32);
    expect(hex(r1[0]!)).not.toBe(hex(r2[0]!));
    expect(hex(r1[1]!)).toBe(hex(seedOf(1)));
  });
  it('the returned own seed is a copy, not the caller\'s array', async () => {
    const mine = seedOf(0);
    const { res } = await run(2, {}, 0, mine);
    if (!res.ok) throw res.e;
    expect(res.v[0]).not.toBe(mine);
    expect(hex(res.v[0]!)).toBe(hex(mine));
  });
});

describe('commit / open message validation', () => {
  const validC = commitMsg(1);
  const cases = (valid: { v: string; s: string }) => [
    null, undefined, 'x', 5, [], {},
    { s: valid.s }, { v: valid.v }, { v: 5, s: valid.s }, { v: valid.v, s: 5 },
    { v: valid.v.slice(1), s: valid.s }, { v: valid.v + '0', s: valid.s }, { v: valid.v.toUpperCase().replace(/^/, ''), s: valid.s },
    { v: 'x' + valid.v, s: valid.s }, { v: valid.v + 'x', s: valid.s }, { v: `${valid.v}\n`, s: valid.s },
    { v: [valid.v], s: valid.s }, { v: valid.v, s: [valid.s] },
    { v: valid.v, s: 'a'.repeat(15) }, { v: valid.v, s: 'a'.repeat(201) }, { v: valid.v, s: 'g'.repeat(32) }, { v: valid.v, s: `${'a'.repeat(32)}\n` }, { v: valid.v, s: 'A'.repeat(32).replace(/A/g, 'F') },
  ];
  it('bad commitment shapes are refused naming the peer', async () => {
    for (const c of cases(validC)) {
      const { res, bads } = await run(2, { 'gd-c': () => c });
      expect(res.ok).toBe(false);
      expect(bads).toEqual([[1, 'bad gadget commitment']]);
    }
  });
  it('signature length bounds are 16..200 hex characters', async () => {
    // the signature check itself will fail (wrong value), but the shape check must pass first
    for (const len of [16, 200]) {
      const { bads } = await run(2, { 'gd-c': () => ({ v: validC.v, s: 'a'.repeat(len) }) });
      expect(bads).toEqual([[1, 'gadget commitment signature does not verify']]);
    }
    for (const len of [15, 201]) {
      const { bads } = await run(2, { 'gd-c': () => ({ v: validC.v, s: 'a'.repeat(len) }) });
      expect(bads).toEqual([[1, 'bad gadget commitment']]);
    }
  });
  it('a commitment signed by someone else, for another round, session or value does not verify', async () => {
    const wrong = [
      signed(2, 'gd-c', validC.v),
      signed(1, 'gd-o', validC.v),
      signed(1, 'gd-c', validC.v, 'other-session'),
      { v: validC.v, s: signed(1, 'gd-c', 'ab'.repeat(32)).s },
    ];
    for (const c of wrong) {
      const { res, bads } = await run(2, { 'gd-c': () => c });
      expect(res.ok).toBe(false);
      expect(bads).toEqual([[1, 'gadget commitment signature does not verify']]);
    }
  });
  it('bad opening shapes and signatures are refused naming the peer', async () => {
    for (const o of cases(openMsg(1))) {
      const { res, bads } = await run(2, { 'gd-o': () => o });
      expect(res.ok).toBe(false);
      expect(bads).toEqual([[1, 'bad gadget seed']]);
    }
    for (const o of [signed(2, 'gd-o', hex(seedOf(1))), signed(1, 'gd-c', hex(seedOf(1))), signed(1, 'gd-o', hex(seedOf(1)), 'other')]) {
      const { res, bads } = await run(2, { 'gd-o': () => o });
      expect(res.ok).toBe(false);
      expect(bads).toEqual([[1, 'gadget seed signature does not verify']]);
    }
  });
  it('an opening that does not match the earlier commitment is a commitment abort blaming the opener', async () => {
    const other = new Uint8Array(32).fill(0x77);
    const { res } = await run(3, { 'gd-o': (p) => (p === 2 ? openMsg(2, other) : openMsg(p)) });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.e.kind).toBe('commitment');
    expect(res.e.blamed).toBe(2);
    expect(res.e.reporter).toBe(0);
    expect(res.e.message).toContain('party 2 opened a gadget seed that does not match its commitment');
  });
  it('the commitment binds the party index', async () => {
    // party 1 reveals the seed whose commitment was made under index 2
    const { res } = await run(2, { 'gd-c': (p) => signed(p, 'gd-c', gadgetCommit('S', 2, seedOf(1))) });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.e.kind).toBe('commitment');
  });
});

describe('echo round', () => {
  it('malformed echoes name the echoer', async () => {
    const good = (p: number) => [0, 1, 2].filter((j) => j !== 0 && j !== p).map((j) => ({ j, c: commitMsg(j), o: openMsg(j) }));
    const e1 = good(1)[0]!;
    for (const [raw, msg] of [
      [null, 'bad gadget echo'], ['x', 'bad gadget echo'], [{}, 'bad gadget echo'], [[], 'bad gadget echo'], [[e1, e1], 'bad gadget echo'],
      [[null], 'bad gadget echo entry'], [['x'], 'bad gadget echo entry'], [[5], 'bad gadget echo entry'], [[{ ...e1, j: 1 }], 'bad gadget echo entry'], [[{ ...e1, j: undefined }], 'bad gadget echo entry'],
      [[{ j: e1.j, o: e1.o }], 'bad gadget echo entry'], [[{ j: e1.j, c: e1.c }], 'bad gadget echo entry'], [[{ ...e1, c: 'x' }], 'bad gadget echo entry'], [[{ ...e1, o: { v: 'x', s: 'y' } }], 'bad gadget echo entry'],
    ] as const) {
      const { res, bads } = await run(3, { 'gd-e': (p) => (p === 1 ? raw : good(p)) });
      expect(res.ok).toBe(false);
      expect(bads).toEqual([[1, msg]]);
    }
  });
  it('an echoed statement that party j did not sign is a forgery by the echoer', async () => {
    const forged = (which: 'c' | 'o') => (p: number) => {
      const j = [1, 2].find((x) => x !== p)!;
      const e = { j, c: commitMsg(j), o: openMsg(j) };
      if (p === 1) return [{ ...e, [which]: { v: e[which].v, s: signed(0, which === 'c' ? 'gd-c' : 'gd-o', e[which].v).s } }];
      return [e];
    };
    for (const which of ['c', 'o'] as const) {
      const { res, bads } = await run(3, { 'gd-e': forged(which) });
      expect(res.ok).toBe(false);
      expect(bads).toEqual([[1, 'gadget echo carries a statement that party 2 did not sign']]);
    }
  });
  it('two validly signed but different statements for one round is equivocation by the signer, with both as evidence', async () => {
    const otherSeed = new Uint8Array(32).fill(0x55);
    // party 2 told me seed A but told party 1 seed B; party 1 echoes B's signed opening
    const { res } = await run(3, { 'gd-e': (p) => (p === 1 ? [{ j: 2, c: commitMsg(2), o: openMsg(2, otherSeed) }] : [{ j: 1, c: commitMsg(1), o: openMsg(1) }]) });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.e.kind).toBe('equivocation');
    expect(res.e.blamed).toBe(2);
    expect(res.e.reporter).toBe(0);
    expect(res.e.message).toContain("party 2 signed different gadget seeds for different parties (shown by party 1's echo)");
    expect(res.e.evidence).toEqual({ signer: 2, round: 'gd-o', statements: [openMsg(2), openMsg(2, otherSeed)] });
    const { res: r2 } = await run(3, { 'gd-e': (p) => (p === 1 ? [{ j: 2, c: commitMsg(2, otherSeed), o: openMsg(2) }] : [{ j: 1, c: commitMsg(1), o: openMsg(1) }]) });
    expect(r2.ok).toBe(false);
    if (r2.ok) return;
    expect(r2.e.kind).toBe('equivocation');
    expect(r2.e.message).toContain('signed different gadget commitments for different parties');
    expect(r2.e.evidence).toEqual({ signer: 2, round: 'gd-c', statements: [commitMsg(2), commitMsg(2, otherSeed)] });
  });
  it('a commitment mismatch takes precedence in the report over the seed mismatch', async () => {
    const o2 = new Uint8Array(32).fill(0x55);
    const { res } = await run(3, { 'gd-e': (p) => (p === 1 ? [{ j: 2, c: commitMsg(2, o2), o: openMsg(2, o2) }] : [{ j: 1, c: commitMsg(1), o: openMsg(1) }]) });
    if (res.ok) throw new Error('expected abort');
    expect((res.e.evidence as { round: string }).round).toBe('gd-c');
  });
  it('the first failing entry decides, and all entries of a valid echo are checked (4 parties)', async () => {
    const o2 = new Uint8Array(32).fill(0x55);
    const echo = (p: number, bad3: boolean) => [1, 2, 3].filter((j) => j !== p).map((j) => (bad3 && j === 3 ? { j, c: commitMsg(j), o: openMsg(j, o2) } : { j, c: commitMsg(j), o: openMsg(j) }));
    const { res } = await run(4, { 'gd-e': (p) => echo(p, p === 1) });
    if (res.ok) throw new Error('expected abort');
    expect(res.e.kind).toBe('equivocation');
    expect(res.e.blamed).toBe(3);
    const ok = await run(4, { 'gd-e': (p) => echo(p, false) });
    expect(ok.res.ok).toBe(true);
  });
});
