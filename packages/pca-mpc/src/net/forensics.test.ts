import { describe, expect, it } from 'vitest';
import { FieldRng, fadd, fmul, fsub, mod } from '../field';
import { makeGadget, sampleEnc } from '../enc';
import { type Disclosure, auditDisclosures, blameFrom, disclosureCommit, exchangeDisclosures, parseDisclosure, wireDisclosure } from './forensics';
import { NetAbort } from './wire';

/** Honest OT product among n parties for one slot, as the disclosures would record it. */
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
      rho.set(`${j}>${i}`, r); // rho offered by j toward i
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
      for (const v of ro.get(p)!) z = fsub(z, v);
    }
    all.set(i, [{ bits: xs[i]!.bits, y: ys[i]!, z, recv: rc, rho: ro }]);
  }
  return { all, g };
}

describe('forensic audit of a discarded triple', () => {
  it('honest transcripts are consistent', () => {
    for (const n of [2, 3, 4]) {
      const { all, g } = honest(n, BigInt(n));
      const r = auditDisclosures(all, g);
      expect(r.selfBad.size).toBe(0);
      expect(r.pairBad).toEqual([]);
      expect(blameFrom(0, r)).toBeNull();
    }
  });

  it('a sender whose OT messages differ from its disclosed operand is named by its honest receivers', () => {
    const { all, g } = honest(3, 7n);
    // party 2 offered y+1 to everyone but discloses its true y: receivers hold values that do not match
    for (const rcv of [0, 1]) {
      const d = all.get(rcv)![0]!;
      const v = d.recv.get(2)!;
      d.recv.set(2, v.map((x, k) => (d.bits[k] === 1 ? fadd(x, g[k]!) : x)));
    }
    // their claimed shares follow from what they received, so only the pair check fires
    for (const rcv of [0, 1]) {
      const d = all.get(rcv)![0]!;
      let z = fmul(mod(d.bits.reduce((a, b, k) => (b ? a + g[k]! : a), 0n)), d.y);
      for (const [p, v] of d.recv) {
        for (const x of v) z = fadd(z, x);
        for (const x of d.rho.get(p)!) z = fsub(z, x);
      }
      d.z = z;
    }
    const r = auditDisclosures(all, g);
    expect(r.selfBad.size).toBe(0);
    expect(blameFrom(0, r)).toBe(2);
    expect(blameFrom(1, r)).toBe(2);
    expect(blameFrom(2, r)).not.toBeNull(); // the liar sees the mismatch from its own data too
  });

  it('a party whose claimed product share does not follow from its own transcript is named by everyone', () => {
    const { all, g } = honest(3, 9n);
    const d = all.get(1)![0]!;
    d.z = fadd(d.z, 5n);
    const r = auditDisclosures(all, g);
    expect(r.selfBad).toEqual(new Set([1]));
    expect(blameFrom(0, r)).toBe(1);
    expect(blameFrom(2, r)).toBe(1);
  });

  it('wire round-trip and strict parsing', () => {
    const { all } = honest(3, 11n);
    const d = all.get(0)![0]!;
    const rows = d.bits.length;
    const wire = JSON.parse(JSON.stringify(wireDisclosure(all.get(0)!)));
    const back = parseDisclosure(wire, 1, rows, [1, 2]);
    expect(back[0]!.z).toBe(d.z);
    expect(back[0]!.recv.get(1)).toEqual(d.recv.get(1));
    expect(() => parseDisclosure(wire, 2, rows, [1, 2])).toThrow();
    expect(() => parseDisclosure(wire, 1, rows + 1, [1, 2])).toThrow();
    expect(() => parseDisclosure(wire, 1, rows, [1, 3])).toThrow();
    const bad = JSON.parse(JSON.stringify(wire));
    bad[0].bits = '2'.repeat(rows);
    expect(() => parseDisclosure(bad, 1, rows, [1, 2])).toThrow();
  });
});


describe('R3-17: forensic disclosures are commit-first', () => {
  const SID = 'sess';
  const DL = 5000;
  /** In-memory all-to-all bus with a per-round receive deadline; logs every post in order. */
  function bus(n: number) {
    const box = new Map<string, unknown>();
    const log: string[] = [];
    const wake: Array<() => void> = [];
    const post = (rd: string, from: number, to: number, v: unknown): void => {
      log.push(`${rd}:${from}->${to}`);
      box.set(`${rd}|${from}|${to}`, JSON.parse(JSON.stringify(v)));
      for (const w of wake.splice(0)) w();
    };
    const io = (id: number, hold?: (rd: string) => boolean) => ({
      bad: (p: number, what: string): never => {
        throw new NetAbort('malformed', p, id, what);
      },
      exchange: async <T>(rd: string, mine: (peer: number) => unknown, parse: (p: number, raw: unknown) => T, timeoutMs: number): Promise<Map<number, T>> => {
        const peers = Array.from({ length: n }, (_, i) => i).filter((i) => i !== id);
        if (!hold?.(rd)) for (const q of peers) post(rd, id, q, mine(q));
        const out = new Map<number, T>();
        for (const q of peers) {
          const key = `${rd}|${q}|${id}`;
          // simulated receive deadline: a message that is not posted by the time everyone else has finished never arrives
          let waited = 0;
          while (!box.has(key)) {
            if (waited++ > 50) throw new NetAbort('timeout', q, id, `no '${rd}' message from ${q} within ${timeoutMs}ms`, undefined, undefined, { deadlineMs: timeoutMs });
            await new Promise<void>((r) => {
              wake.push(r);
              setTimeout(r, 2);
            });
          }
          out.set(q, parse(q, box.get(key)));
        }
        return out;
      },
    });
    return { post, io, log, box };
  }
  const args = (b: ReturnType<typeof bus>, n: number, id: number, d: Disclosure, hold?: (rd: string) => boolean) => ({
    sessionId: SID, id, n, tripleIndex: 3, mine: d, slots: 1, rows: d[0]!.bits.length, deadlineMs: DL, ...b.io(id, hold),
  });

  it('honest parties receive each other\'s disclosures intact, and nobody opens before all commitments are posted', async () => {
    const { all } = honest(3, 11n);
    const b = bus(3);
    const res = await Promise.all([0, 1, 2].map((i) => exchangeDisclosures(args(b, 3, i, all.get(i)!))));
    for (let i = 0; i < 3; i++) for (const [p, d] of res[i]!) expect(wireDisclosure(d)).toEqual(wireDisclosure(all.get(p)!));
    const firstOpen = b.log.findIndex((l) => l.startsWith('forensic-o'));
    const lastCommit = b.log.map((l) => l.startsWith('forensic-c')).lastIndexOf(true);
    expect(firstOpen).toBeGreaterThan(lastCommit);
  });

  it('a rushing corrupt sender that opens a disclosure tuned after seeing the others is caught: it must have committed first', async () => {
    const { all } = honest(3, 12n);
    const b = bus(3);
    const tuned = JSON.parse(JSON.stringify(wireDisclosure(all.get(2)!)));
    tuned[0].y = '1'; // a different disclosure than the one committed
    // party 2 commits to its real disclosure (it has not seen anyone else yet) ...
    const nonce = 'ab'.repeat(32);
    const c = disclosureCommit(SID, 2, 3, DL, nonce, wireDisclosure(all.get(2)!));
    for (const q of [0, 1]) b.post('forensic-c', 2, q, { c, d: DL });
    // ... and, only after the honest openings arrive, opens something else
    const honestRuns = [0, 1].map((i) => exchangeDisclosures(args(b, 3, i, all.get(i)!)).then((v) => ({ ok: true as const, v }), (e: NetAbort) => ({ ok: false as const, e })));
    while (!(b.log.includes('forensic-o:0->2') && b.log.includes('forensic-o:1->2'))) await new Promise((r) => setTimeout(r, 2)); // the honest openings are now visible to the rusher
    for (const q of [0, 1]) b.post('forensic-o', 2, q, { w: tuned, nonce });
    for (const r of await Promise.all(honestRuns)) {
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.e.kind).toBe('commitment');
        expect(r.e.blamed).toBe(2);
      }
    }
  });

  it('a party that never commits is blamed by timeout and the abort records the deadline', async () => {
    const { all } = honest(3, 13n);
    const b = bus(3);
    const res = await Promise.allSettled([0, 1].map((i) => exchangeDisclosures(args(b, 3, i, all.get(i)!))).flat());
    for (const r of res) {
      expect(r.status).toBe('rejected');
      if (r.status === 'rejected') {
        const e = r.reason as NetAbort;
        expect(e.kind).toBe('timeout');
        expect(e.blamed).toBe(2);
        expect(e.deadlineMs).toBe(DL);
      }
    }
  });

  it('a different advertised deadline is refused (the deadline is part of the agreed transcript)', async () => {
    const { all } = honest(3, 14n);
    const b = bus(3);
    for (const q of [0, 1]) b.post('forensic-c', 2, q, { c: 'a'.repeat(64), d: DL + 1 });
    const res = await Promise.allSettled([0, 1].map((i) => exchangeDisclosures(args(b, 3, i, all.get(i)!))));
    for (const r of res) {
      expect(r.status).toBe('rejected');
      if (r.status === 'rejected') expect((r.reason as NetAbort).blamed).toBe(2);
    }
  });

  it('NetAbort states why nobody is blamed', () => {
    const e = new NetAbort('mac-check', null, 0, 'x');
    expect(e.blamed).toBeNull();
    expect(e.reason).toMatch(/unattributable/);
    expect(new NetAbort('mac-check', 1, 0, 'x').reason).toBeNull();
    expect(new NetAbort('mac-check', null, 0, 'x', undefined, undefined, { reason: 'because' }).reason).toBe('because');
  });
});
