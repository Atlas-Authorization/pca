import { describe, expect, it } from 'vitest';
import { FieldRng, fadd, fmul } from '../field';
import { makeGadget, sampleEnc } from '../enc';
import { DEFAULT_FORENSIC_DEADLINE_MS, type AuditResult, type Disclosure, auditDisclosures, blameFrom, disclosureCommit, exchangeDisclosures, parseDisclosure, slotsFor, wireDisclosure } from './forensics';
import { NetAbort, hx } from './wire';

const bigs = (xs: number[]): bigint[] => xs.map(BigInt);

describe('slotsFor / defaults', () => {
  it('one product slot plus one per partner', () => {
    expect(slotsFor(0)).toBe(1);
    expect(slotsFor(1)).toBe(2);
    expect(slotsFor(3)).toBe(4);
  });
  it('default deadline is 30 s', () => {
    expect(DEFAULT_FORENSIC_DEADLINE_MS).toBe(30_000);
  });
});

describe('wireDisclosure', () => {
  it('serialises bits as a 0/1 string, field elements as hex, peer tables as [peer, [hex...]] pairs', () => {
    const d: Disclosure = [{ bits: [1, 0, 1], y: 255n, z: 16n, recv: new Map([[2, bigs([10, 11, 12])], [1, bigs([0, 1, 2])]]), rho: new Map([[1, bigs([15, 16, 17])]]) }];
    expect(wireDisclosure(d)).toEqual([
      { bits: '101', y: 'ff', z: '10', recv: [[2, ['a', 'b', 'c']], [1, ['0', '1', '2']]], rho: [[1, ['f', '10', '11']]] },
    ]);
  });
});

describe('parseDisclosure', () => {
  const rows = 3;
  const peers = [1, 2];
  const goodSlot = () => ({ bits: '101', y: 'a', z: 'b', recv: [[1, ['1', '2', '3']], [2, ['4', '5', '6']]], rho: [[1, ['7', '8', '9']], [2, ['a', 'b', 'c']]] });
  const parse = (slot: unknown, slots = 1) => parseDisclosure(Array.from({ length: slots }, () => slot), slots, rows, peers);
  const mut = (f: (s: ReturnType<typeof goodSlot>) => void) => {
    const s = goodSlot();
    f(s);
    return s;
  };

  it('parses a good disclosure into typed values', () => {
    const d = parse(goodSlot());
    expect(d.length).toBe(1);
    expect(d[0]!.bits).toEqual([1, 0, 1]);
    expect(d[0]!.y).toBe(10n);
    expect(d[0]!.z).toBe(11n);
    expect(d[0]!.recv.get(1)).toEqual([1n, 2n, 3n]);
    expect(d[0]!.recv.get(2)).toEqual([4n, 5n, 6n]);
    expect(d[0]!.rho.get(1)).toEqual([7n, 8n, 9n]);
    expect(d[0]!.rho.get(2)).toEqual([10n, 11n, 12n]);
    expect(parse(goodSlot(), 2).length).toBe(2);
  });
  it('rejects a wrong slot count or non-array', () => {
    for (const raw of [null, 'x', {}, [], [goodSlot(), goodSlot()]]) expect(() => parseDisclosure(raw, 1, rows, peers)).toThrow('bad forensic disclosure');
    expect(() => parseDisclosure([goodSlot()], 2, rows, peers)).toThrow('bad forensic disclosure');
  });
  it('rejects bad choice bits', () => {
    for (const bits of [undefined, 5, null, '10', '1010', '102', '10a', ' 10', '10 ', '']) expect(() => parse(mut((s) => ((s as { bits: unknown }).bits = bits)))).toThrow('bad choice bits');
    expect(() => parseDisclosure([null], 1, rows, peers)).toThrow('bad choice bits');
    expect(() => parseDisclosure([undefined], 1, rows, peers)).toThrow('bad choice bits');
    expect(() => parseDisclosure([goodSlot()], 1, 4, peers)).toThrow('bad choice bits');
    expect(parseDisclosure([mut((s) => ((s.bits = '1'), (s.recv = []), (s.rho = []), (s.recv as unknown[]).length))], 1, 1, [])[0]!.bits).toEqual([1]);
  });
  it('rejects non-canonical field elements in y, z and the tables', () => {
    for (const v of [undefined, 5, '00', '0A', 'g', '', 'f'.repeat(17), hx(2n ** 61n - 1n)]) {
      expect(() => parse(mut((s) => ((s as { y: unknown }).y = v)))).toThrow('bad field element');
      expect(() => parse(mut((s) => ((s as { z: unknown }).z = v)))).toThrow('bad field element');
      expect(() => parse(mut((s) => (s.recv[0]![1] = [v as string, '2', '3'])))).toThrow('bad field element');
      expect(() => parse(mut((s) => (s.rho[1]![1] = ['1', '2', v as string])))).toThrow('bad field element');
    }
  });
  it('rejects malformed peer tables', () => {
    for (const side of ['recv', 'rho'] as const) {
      const set = (v: unknown) => mut((s) => ((s as unknown as Record<string, unknown>)[side] = v));
      for (const t of [undefined, null, 'ab', {}, 5]) expect(() => parse(set(t))).toThrow('bad peer table');
      expect(() => parse(set([[1, ['1', '2', '3']]]))).toThrow('bad peer table'); // too short
      expect(() => parse(set([[1, ['1', '2', '3']], [2, ['1', '2', '3']], [1, ['1', '2', '3']]]))).toThrow('bad peer table'); // too long
      const entry = (e: unknown) => set([[1, ['1', '2', '3']], e]);
      for (const e of [5, 'ab', null, [2], [2, ['1', '2', '3'], 'x'], ['2', ['1', '2', '3']], [3, ['1', '2', '3']], [1, ['1', '2', '3']], { 0: 2, 1: [], length: 2 }]) expect(() => parse(entry(e))).toThrow('bad peer entry');
      for (const rowsBad of [undefined, 'abc', null, ['1', '2'], ['1', '2', '3', '4'], { length: 3 }]) expect(() => parse(entry([2, rowsBad]))).toThrow('bad row table');
    }
  });
  it('accepts the peer table in any order', () => {
    const d = parse(mut((s) => (s.recv = [s.recv[1]!, s.recv[0]!])));
    expect([...d[0]!.recv.keys()]).toEqual([2, 1]);
  });
});

/** Honest OT product among n parties for one slot (as the disclosures would record it). */
function honest(n: number, seed: bigint, s = 8): { all: Map<number, Disclosure>; g: bigint[] } {
  const rng = new FieldRng(seed);
  const g = makeGadget(s, () => rng.next(), true);
  const xs = Array.from({ length: n }, () => sampleEnc(g, rng));
  const ys = Array.from({ length: n }, () => rng.next());
  const rho = new Map<string, bigint[]>();
  const recv = new Map<string, bigint[]>();
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      if (i === j) continue;
      const r = g.map(() => rng.next());
      rho.set(`${j}>${i}`, r);
      recv.set(`${i}<${j}`, r.map((v, k) => (xs[i]!.bits[k] === 1 ? fadd(v, fmul(g[k]!, ys[j]!)) : v)));
    }
  }
  const all = new Map<number, Disclosure>();
  for (let i = 0; i < n; i++) {
    let z = fmul(xs[i]!.value, ys[i]!);
    const rc = new Map<number, bigint[]>();
    const ro = new Map<number, bigint[]>();
    for (let p = 0; p < n; p++) {
      if (p === i) continue;
      rc.set(p, recv.get(`${i}<${p}`)!);
      ro.set(p, rho.get(`${i}>${p}`)!);
      for (const v of rc.get(p)!) z = fadd(z, v);
      for (const v of ro.get(p)!) z = (z - v + (2n ** 61n - 1n)) % (2n ** 61n - 1n);
    }
    all.set(i, [{ bits: xs[i]!.bits, y: ys[i]!, z, recv: rc, rho: ro }]);
  }
  return { all, g };
}

describe('auditDisclosures', () => {
  it('honest transcripts: no selfBad, no pairBad, independent of Map insertion order', () => {
    const { all, g } = honest(4, 21n);
    const rev = new Map([...all.entries()].reverse());
    for (const m of [all, rev]) {
      const r = auditDisclosures(m, g);
      expect(r.selfBad.size).toBe(0);
      expect(r.pairBad).toEqual([]);
    }
  });
  it('pairBad lists failing [receiver, sender] pairs in ascending party order regardless of Map insertion order', () => {
    const { all, g } = honest(4, 22n);
    // corrupt every receiver's view of every sender at a position where its bit is 1 (so the check bites)
    for (const [, d] of all) for (const [p, v] of d[0]!.recv) d[0]!.recv.set(p, v.map((x, k) => (d[0]!.bits[k] === 1 ? fadd(x, 1n) : x)));
    const expected: Array<[number, number]> = [];
    for (let i = 0; i < 4; i++) for (let p = 0; p < 4; p++) if (i !== p) expected.push([i, p]);
    for (const order of [[0, 1, 2, 3], [3, 2, 1, 0], [2, 0, 3, 1]]) {
      const m = new Map(order.map((k) => [k, all.get(k)!] as const));
      expect(auditDisclosures(m, g).pairBad).toEqual(expected);
    }
  });
  it('a single wrong gadget position in a received value flags exactly that pair, in both bit cases', () => {
    const { all, g } = honest(3, 23n);
    const d = all.get(0)![0]!;
    const k1 = d.bits.findIndex((b) => b === 1);
    const k0 = d.bits.findIndex((b) => b === 0);
    expect(k1).toBeGreaterThanOrEqual(0);
    expect(k0).toBeGreaterThanOrEqual(0);
    for (const k of [k0, k1, g.length - 1]) {
      const { all: a2 } = honest(3, 23n);
      const dd = a2.get(0)![0]!;
      const v = dd.recv.get(1)!.slice();
      v[k] = fadd(v[k]!, 1n);
      dd.recv.set(1, v);
      expect(auditDisclosures(a2, g).pairBad).toEqual([[0, 1]]);
    }
  });
  it('the gadget is applied only where the choice bit is 1 (a claimed 0-bit position carries no y term)', () => {
    const { all, g } = honest(3, 24n);
    const d = all.get(1)![0]!;
    const k0 = d.bits.findIndex((b) => b === 0);
    // pretend the receiver chose 1 at k0 but received the 0-bit value: pair (1,p) must fail
    d.bits = d.bits.map((b, k) => (k === k0 ? 1 : b));
    const r = auditDisclosures(all, g);
    expect(r.pairBad.some(([i]) => i === 1)).toBe(true);
  });
  it('selfBad: a claimed product share that does not follow from the disclosure, only for that party', () => {
    const { all, g } = honest(3, 25n);
    all.get(2)![0]!.z = fadd(all.get(2)![0]!.z, 1n);
    const r = auditDisclosures(all, g);
    expect(r.selfBad).toEqual(new Set([2]));
    expect(r.pairBad).toEqual([]);
  });
  it('selfBad detects a wrong y, a wrong recv entry and a wrong rho entry in the party\'s own disclosure', () => {
    for (const tweak of [
      (d: Disclosure) => (d[0]!.y = fadd(d[0]!.y, 1n)),
      (d: Disclosure) => d[0]!.recv.set(1, d[0]!.recv.get(1)!.map((x, k) => (k === 0 ? fadd(x, 1n) : x))),
      (d: Disclosure) => d[0]!.rho.set(2, d[0]!.rho.get(2)!.map((x, k) => (k === 0 ? fadd(x, 1n) : x))),
    ]) {
      const { all, g } = honest(3, 26n);
      tweak(all.get(0)!);
      expect(auditDisclosures(all, g).selfBad.has(0)).toBe(true);
    }
  });
  it('ignores choice bits beyond the gadget length', () => {
    const { all, g } = honest(2, 27n);
    for (const d of all.values()) d[0]!.bits = [...d[0]!.bits, 1];
    const r = auditDisclosures(all, g);
    expect(r.selfBad.size).toBe(0);
    expect(r.pairBad).toEqual([]);
  });
  it('audits every slot, not just the first', () => {
    const { all, g } = honest(3, 28n);
    for (const [, d] of all) d.push({ ...d[0]!, recv: new Map(d[0]!.recv), rho: new Map(d[0]!.rho) });
    const bad = all.get(1)![1]!;
    bad.z = fadd(bad.z, 1n);
    expect(auditDisclosures(all, g).selfBad).toEqual(new Set([1]));
  });
});

describe('blameFrom', () => {
  const R = (selfBad: number[], pairBad: Array<[number, number]>): AuditResult => ({ selfBad: new Set(selfBad), pairBad });
  it('names the lowest-numbered self-inconsistent party other than me', () => {
    expect(blameFrom(0, R([5, 3, 4, 1], []))).toBe(1);
    expect(blameFrom(0, R([10, 2], []))).toBe(2);
    expect(blameFrom(0, R([2, 10], []))).toBe(2);
    expect(blameFrom(1, R([1, 3], []))).toBe(3);
    expect(blameFrom(1, R([3, 1, 2], []))).toBe(2);
  });
  it('my own inconsistency does not blame me; falls through to the pair check', () => {
    expect(blameFrom(1, R([1], []))).toBeNull();
    expect(blameFrom(1, R([1], [[1, 2]]))).toBe(2);
  });
  it('blames the counterpart of the first failing pair I belong to', () => {
    expect(blameFrom(0, R([], [[0, 3]]))).toBe(3);
    expect(blameFrom(0, R([], [[3, 0]]))).toBe(3);
    expect(blameFrom(0, R([], [[1, 2], [2, 0], [0, 4]]))).toBe(2);
    expect(blameFrom(0, R([], [[1, 2], [0, 4], [2, 0]]))).toBe(4);
    expect(blameFrom(2, R([], [[1, 3]]))).toBeNull();
    expect(blameFrom(2, R([], []))).toBeNull();
  });
  it('a self-inconsistent party outranks a failing pair', () => {
    expect(blameFrom(0, R([4], [[0, 1]]))).toBe(4);
  });
});

describe('disclosureCommit', () => {
  it('is a domain-separated SHA-256 over [session, party, triple, deadline, nonce, wire] (pinned)', () => {
    const c = disclosureCommit('sess', 2, 3, 5000, 'ab'.repeat(32), [{ bits: '1' }]);
    expect(c).toBe('5fea3e16959dd52246562f7afc65ee2b6d9e0a55e30a40f257eaac99646e6e44');
  });
  it('every input changes the commitment', () => {
    const base = ['sess', 2, 3, 5000, 'ab'.repeat(32), [{ bits: '1' }]] as const;
    const c0 = disclosureCommit(...base);
    expect(disclosureCommit('sesT', 2, 3, 5000, base[4], base[5])).not.toBe(c0);
    expect(disclosureCommit('sess', 1, 3, 5000, base[4], base[5])).not.toBe(c0);
    expect(disclosureCommit('sess', 2, 4, 5000, base[4], base[5])).not.toBe(c0);
    expect(disclosureCommit('sess', 2, 3, 5001, base[4], base[5])).not.toBe(c0);
    expect(disclosureCommit('sess', 2, 3, 5000, 'cd'.repeat(32), base[5])).not.toBe(c0);
    expect(disclosureCommit('sess', 2, 3, 5000, base[4], [{ bits: '0' }])).not.toBe(c0);
    expect(c0).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('exchangeDisclosures (scripted peers)', () => {
  const SID = 'sess';
  const DL = 7000;
  const TRIPLE = 4;
  const { all } = honest(3, 31n);
  const rows = all.get(0)![0]!.bits.length;
  const nonceOf = (p: number): string => ('a' + p.toString(16)).repeat(32);
  const commitOf = (p: number, d = all.get(p)!, o: Partial<{ sid: string; triple: number; dl: number; nonce: string }> = {}): string =>
    disclosureCommit(o.sid ?? SID, p, o.triple ?? TRIPLE, o.dl ?? DL, o.nonce ?? nonceOf(p), wireDisclosure(d));
  type Script = { c?: (p: number) => unknown; o?: (p: number) => unknown };
  const run = async (script: Script = {}) => {
    const calls: Array<{ rd: string; timeoutMs: number; mineC?: unknown; mineO?: unknown }> = [];
    const bads: Array<[number, string]> = [];
    const mineOf = all.get(0)!;
    const args = {
      sessionId: SID, id: 0, n: 3, tripleIndex: TRIPLE, mine: mineOf, slots: 1, rows, deadlineMs: DL,
      bad: (p: number, what: string): never => {
        bads.push([p, what]);
        throw new NetAbort('malformed', p, 0, what);
      },
      exchange: async <T>(rd: string, mine: (peer: number) => unknown, parse: (p: number, raw: unknown) => T, timeoutMs: number): Promise<Map<number, T>> => {
        calls.push({ rd, timeoutMs, ...(rd === 'forensic-c' ? { mineC: mine(1) } : { mineO: mine(1) }) });
        const out = new Map<number, T>();
        for (const p of [1, 2]) {
          const raw = rd === 'forensic-c' ? (script.c ? script.c(p) : { c: commitOf(p), d: DL }) : script.o ? script.o(p) : { w: JSON.parse(JSON.stringify(wireDisclosure(all.get(p)!))), nonce: nonceOf(p) };
          out.set(p, parse(p, raw));
        }
        return out;
      },
    };
    const res = await exchangeDisclosures(args).then((v) => ({ ok: true as const, v }), (e: unknown) => ({ ok: false as const, e: e as NetAbort }));
    return { res, calls, bads };
  };

  it('commits first with its own deadline, then opens; returns the verified disclosures of the others', async () => {
    const { res, calls, bads } = await run();
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect([...res.v.keys()].sort()).toEqual([1, 2]);
    expect(wireDisclosure(res.v.get(1)!)).toEqual(wireDisclosure(all.get(1)!));
    expect(wireDisclosure(res.v.get(2)!)).toEqual(wireDisclosure(all.get(2)!));
    expect(bads).toEqual([]);
    expect(calls.map((c) => c.rd)).toEqual(['forensic-c', 'forensic-o']);
    expect(calls.map((c) => c.timeoutMs)).toEqual([DL, DL]);
    const mc = calls[0]!.mineC as { c: string; d: number };
    expect(Object.keys(mc).sort()).toEqual(['c', 'd']);
    expect(mc.d).toBe(DL);
    const mo = calls[1]!.mineO as { w: unknown; nonce: string };
    expect(Object.keys(mo).sort()).toEqual(['nonce', 'w']);
    expect(mo.nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(mo.w).toEqual(wireDisclosure(all.get(0)!));
    expect(mc.c).toBe(disclosureCommit(SID, 0, TRIPLE, DL, mo.nonce, mo.w));
  });
  it('commitment must be exactly 64 lowercase hex characters', async () => {
    const good = commitOf(1);
    for (const c of [undefined, 5, null, good.slice(1), good + '0', good.toUpperCase(), 'x' + good, good + 'x', good.slice(0, 63) + 'g', `${good}\n`, `\n${good}`]) {
      const { res, bads } = await run({ c: (p) => (p === 1 ? { c, d: DL } : { c: commitOf(2), d: DL }) });
      expect(res.ok).toBe(false);
      expect(bads).toEqual([[1, 'bad forensic commitment']]);
    }
    for (const raw of [null, undefined, 'x', 5]) {
      const { res, bads } = await run({ c: (p) => (p === 1 ? raw : { c: commitOf(2), d: DL }) });
      expect(res.ok).toBe(false);
      expect(bads).toEqual([[1, 'bad forensic commitment']]);
    }
  });
  it('a commitment advertising another deadline is refused with a message naming both deadlines', async () => {
    for (const d of [DL + 1, DL - 1, undefined, String(DL)]) {
      const { res, bads } = await run({ c: (p) => ({ c: commitOf(p), d: p === 2 ? d : DL }) });
      expect(res.ok).toBe(false);
      expect(bads).toEqual([[2, `forensic deadline ${String(d)} differs from the agreed ${DL}`]]);
    }
  });
  it('the opening nonce must be exactly 64 lowercase hex characters', async () => {
    const good = nonceOf(1);
    for (const nonce of [undefined, 5, null, good.slice(1), good + '0', good.toUpperCase(), 'x' + good, good + 'x', `${good}\n`, `\n${good}`]) {
      const { res, bads } = await run({ o: (p) => ({ w: wireDisclosure(all.get(p)!), nonce: p === 1 ? nonce : nonceOf(2) }) });
      expect(res.ok).toBe(false);
      expect(bads).toEqual([[1, 'bad forensic opening']]);
    }
    for (const raw of [null, undefined, 'x', 5]) {
      const { res, bads } = await run({ o: (p) => (p === 1 ? raw : { w: wireDisclosure(all.get(p)!), nonce: nonceOf(2) }) });
      expect(res.ok).toBe(false);
      expect(bads).toEqual([[1, 'bad forensic opening']]);
    }
  });
  it('an opening that does not match the commitment aborts with a commitment NetAbort blaming the opener', async () => {
    const tuned = JSON.parse(JSON.stringify(wireDisclosure(all.get(2)!)));
    tuned[0].y = '1';
    const { res } = await run({ o: (p) => ({ w: p === 2 ? tuned : wireDisclosure(all.get(p)!), nonce: nonceOf(p) }) });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.e).toBeInstanceOf(NetAbort);
    expect(res.e.kind).toBe('commitment');
    expect(res.e.blamed).toBe(2);
    expect(res.e.reporter).toBe(0);
    expect(res.e.message).toContain('party 2 opened a forensic disclosure that does not match its commitment');
  });
  it('the commitment binds session, party, triple index and deadline', async () => {
    const wrongs: Array<Partial<{ sid: string; triple: number; dl: number }>> = [{ sid: 'other' }, { triple: TRIPLE + 1 }, { dl: DL + 1 }];
    for (const w of wrongs) {
      const { res } = await run({ c: (p) => ({ c: commitOf(p, all.get(p)!, w), d: DL }) });
      expect(res.ok).toBe(false);
      if (!res.ok) expect(res.e.kind).toBe('commitment');
    }
    // a commitment made for another party's identity does not open for me
    const { res } = await run({ c: (p) => ({ c: commitOf(p === 1 ? 2 : 1, all.get(p)!), d: DL }) });
    expect(res.ok).toBe(false);
  });
  it('a committed but malformed disclosure is rejected by the strict parser (peer table excludes the opener)', async () => {
    // party 1's disclosure lists a peer entry for party 1 itself: valid peers for opener 1 are {0, 2}
    const w = JSON.parse(JSON.stringify(wireDisclosure(all.get(1)!)));
    w[0].recv = w[0].recv.map(([p, v]: [number, string[]]) => [p === 0 ? 1 : p, v]);
    const nonce = nonceOf(1);
    const c = disclosureCommit(SID, 1, TRIPLE, DL, nonce, w);
    const { res } = await run({
      c: (p) => ({ c: p === 1 ? c : commitOf(2), d: DL }),
      o: (p) => ({ w: p === 1 ? w : wireDisclosure(all.get(p)!), nonce: p === 1 ? nonce : nonceOf(2) }),
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.e.message).toContain('bad peer entry');
  });
  it('expects slots rows and n parties from the arguments', async () => {
    const calls = { slots: 2 };
    const args = {
      sessionId: SID, id: 0, n: 3, tripleIndex: TRIPLE, mine: all.get(0)!, slots: calls.slots, rows, deadlineMs: DL,
      bad: (p: number, what: string): never => {
        throw new NetAbort('malformed', p, 0, what);
      },
      exchange: async <T>(rd: string, _m: (peer: number) => unknown, parse: (p: number, raw: unknown) => T): Promise<Map<number, T>> => {
        const out = new Map<number, T>();
        for (const p of [1, 2]) out.set(p, parse(p, rd === 'forensic-c' ? { c: commitOf(p), d: DL } : { w: wireDisclosure(all.get(p)!), nonce: nonceOf(p) }));
        return out;
      },
    };
    await expect(exchangeDisclosures(args)).rejects.toThrow('bad forensic disclosure');
  });
});
