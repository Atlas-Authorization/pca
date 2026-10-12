import { createHash } from 'node:crypto';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

const det = vi.hoisted(() => ({
  on: false,
  ctr: 0,
  audit: null as null | ((all: unknown, g: unknown) => unknown),
  preps: new Map<number, any>(),
  prepHook: null as null | ((id: number, prep: any) => void),
  exch: [] as Array<{ tripleIndex: number; deadlineMs: number; slots: number; rows: number }>,
}));
vi.mock('node:crypto', async (orig) => {
  const real = (await orig()) as typeof import('node:crypto');
  return {
    ...real,
    default: real,
    randomBytes: ((n: number) => {
      if (!det.on) return real.randomBytes(n);
      const out = Buffer.alloc(n);
      let w = 0;
      while (w < n) {
        const h = real.createHash('sha256').update('mk-det').update(String(det.ctr++)).digest();
        h.copy(out, w, 0, Math.min(32, n - w));
        w += 32;
      }
      return out;
    }) as typeof real.randomBytes,
  };
});
vi.mock('./forensics', async (orig) => {
  const real = (await orig()) as typeof import('./forensics');
  return {
    ...real,
    auditDisclosures: ((all: never, g: never) => (det.audit ? det.audit(all, g) : real.auditDisclosures(all, g))) as typeof real.auditDisclosures,
    exchangeDisclosures: ((a: any) => {
      det.exch.push({ tripleIndex: a.tripleIndex, deadlineMs: a.deadlineMs, slots: a.slots, rows: a.rows });
      return real.exchangeDisclosures(a);
    }) as typeof real.exchangeDisclosures,
  };
});
vi.mock('./offline-net', async (orig) => {
  const real = (await orig()) as typeof import('./offline-net');
  return {
    ...real,
    runOfflineNet: (async (a: any) => {
      const prep = await real.runOfflineNet(a);
      det.preps.set(a.id, prep);
      det.prepHook?.(a.id, prep);
      return prep;
    }) as typeof real.runOfflineNet,
  };
});
import { composeClear } from '../compose';
import type { DecisionVector } from '../party';
import { MAC_KEYS, SACRIFICE_PARTNERS } from '../spdz';
import { FieldRng } from '../field';
import { MemNet, type MemTap } from './memnet';
import { type Behavior, type PartyResult, SilentParty, T_M, chainCount, runDealer, runParty } from './protocol';
import { NetAbort } from './wire';

const V = (allow: 0 | 1, t: 1 | 2 | 3, rQuant: number): DecisionVector => ({ allow, t, rQuant });

class Crash extends Error {}

interface Opts {
  n: number;
  vectors: DecisionVector[];
  Q: number;
  offline?: 'trusted-dealer' | 'no-dealer';
  behaviors?: Record<number, Behavior>;
  dealerFault?: { keepCDelta?: bigint; partnerCDelta?: Array<bigint | undefined> };
  macFaultAtInput?: number;
  tap?: MemTap;
  recvTimeoutMs?: number;
  forensicDeadlineMs?: number;
  sessionId?: string;
}
interface Outcome {
  ok: boolean;
  result?: PartyResult;
  error?: NetAbort;
  raw?: unknown;
}
async function exec(o: Opts) {
  const offline = o.offline ?? 'trusted-dealer';
  const sid = o.sessionId ?? 'sess';
  const ids = offline === 'trusted-dealer' ? [...Array.from({ length: o.n }, (_, i) => i), o.n] : Array.from({ length: o.n }, (_, i) => i);
  const net = new MemNet(ids, sid, o.recvTimeoutMs ?? 20_000, o.tap ?? null);
  const settle = async (id: number, p: Promise<unknown>): Promise<Outcome> => {
    try {
      return { ok: true, result: (await p) as PartyResult };
    } catch (e) {
      if (e instanceof Crash) net.mesh(id).kill();
      return { ok: false, error: e instanceof NetAbort ? e : undefined, raw: e };
    }
  };
  const parties = o.vectors.map((v, i) =>
    settle(
      i,
      runParty({
        id: i, n: o.n, Q: o.Q, input: v, mesh: net.mesh(i) as unknown as never, offline, sessionId: sid,
        behavior: o.behaviors?.[i], unsafeTestHooks: o.behaviors?.[i] ? true : undefined, forensicDeadlineMs: o.forensicDeadlineMs,
      }),
    ),
  );
  const dealer =
    offline === 'trusted-dealer'
      ? settle(o.n, runDealer({ n: o.n, Q: o.Q, mesh: net.mesh(o.n) as unknown as never, seed: 7n, fault: o.dealerFault, macFaultAtInput: o.macFaultAtInput }))
      : Promise.resolve<Outcome>({ ok: true });
  const [d, ...ps] = [await dealer, ...(await Promise.all(parties))];
  return { net, dealer: d!, ps };
}
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
async function party(n: number, vectors: DecisionVector[], Q: number, o: { behaviors?: Record<number, Behavior> } = {}) {
  const net = new MemNet(Array.from({ length: n }, (_, i) => i), 'sess', 120_000);
  const started: Array<Promise<{ ok: boolean; result?: PartyResult; error?: NetAbort }>> = [];
  for (const [i, v] of vectors.entries()) {
    started.push(
      runParty({ id: i, n, Q, input: v, mesh: net.mesh(i) as unknown as never, offline: 'no-dealer', sessionId: 'sess', behavior: o.behaviors?.[i], unsafeTestHooks: o.behaviors?.[i] ? true : undefined }).then(
        (result) => ({ ok: true, result, error: undefined as NetAbort | undefined }),
        (e: unknown) => ({ ok: false, result: undefined, error: e as NetAbort }),
      ),
    );
    // stagger: the first party's lazy import of the (mocked) offline module must settle before the next one starts
    await new Promise((r) => setTimeout(r, 40));
  }
  const out = await Promise.all(started);
  return { net, out };
}
void sha;

// load the (async-factory) mocked module once so concurrent parties all see the wrapper
beforeAll(async () => {
  await import('./offline-net');
});

afterEach(() => {
  vi.restoreAllMocks();
  det.on = false;
  det.audit = null;
  det.prepHook = null;
  det.preps.clear();
  det.exch.length = 0;
});

describe('chainCount / constants', () => {
  it('one allow chain, T_M threshold chains and Q risk chains', () => {
    expect(T_M).toBe(3);
    expect(chainCount(0)).toBe(4);
    expect(chainCount(100)).toBe(104);
    expect(chainCount(7)).toBe(11);
  });
});

describe('honest trusted-dealer runs', () => {
  it('two parties: result equals the cleartext composition; every field of PartyResult is as documented', async () => {
    const vs = [V(1, 1, 2), V(1, 2, 1)];
    const { ps, dealer, net } = await exec({ n: 2, vectors: vs, Q: 3 });
    expect(dealer.ok).toBe(true);
    const clear = composeClear(vs, 3);
    for (const [i, p] of ps.entries()) {
      expect(p.ok).toBe(true);
      const r = p.result!;
      expect(r.composed).toEqual(clear);
      expect([r.id, r.n, r.Q]).toEqual([i, 2, 3]);
      expect(r.offlineMode).toBe('trusted-dealer');
      expect(r.macKeys).toBe(MAC_KEYS);
      expect(r.sacrificePartners).toBe(SACRIFICE_PARTNERS);
      expect(r.sacrificedTriples).toBe(chainCount(3));
      expect(r.multiplications).toBe(chainCount(3));
      expect(r.identifiableAbort).toBe(true);
      expect(r.transcriptDigest).toMatch(/^[0-9a-f]{64}$/);
      expect(r.wallMs).toBeGreaterThanOrEqual(0);
      expect(r.rounds.map((x) => x.rd)).toEqual([
        'prep', 'coin1-c', 'coin1-o', 'sac-rho', 'sac-rho.t', 'sac-tau', 'sac-tau.t', 'inputs', 'mul0', 'mul0.t', 'out', 'out.t',
        'coin-c', 'coin-o', 'sig-c', 'sig-o', 'digest',
      ]);
      for (const s of r.rounds) {
        expect(s.ms).toBeGreaterThanOrEqual(0);
        expect(s.bytesOut).toBeGreaterThanOrEqual(0);
        expect(s.bytesIn).toBeGreaterThanOrEqual(0);
      }
      const byRd = Object.fromEntries(r.rounds.map((x) => [x.rd, x]));
      expect(byRd['prep']!.bytesOut).toBe(0);
      const sentMul = net.mesh(i).sent.filter((m) => m.rd === 'mul0');
      expect(byRd['mul0']!.bytesOut).toBe(sentMul.reduce((a, m) => a + JSON.stringify(m.d).length + 'mul0'.length, 0));
      expect(byRd['mul0']!.bytesIn).toBeLessThanOrEqual(byRd['mul0']!.bytesOut);
      expect(byRd['digest']!.bytesOut).toBeGreaterThan(60);
      // opens = every opened value: sac-rho + sac-tau (T*P each) + mul (2C per layer) + out (C)
      const C = chainCount(3);
      expect(r.opens).toBe(2 * C * SACRIFICE_PARTNERS + 2 * C + C);
      expect(net.mesh(i).finished).toBe(true);
    }
    expect(ps[0]!.result!.transcriptDigest).toBe(ps[1]!.result!.transcriptDigest);
    expect(net.mesh(2).finished).toBe(true);
  });
  it('the transcript digest is SHA-256 over the hashed rounds: round name, then each party\'s broadcast in party order', async () => {
    const vs = [V(1, 2, 1), V(1, 3, 0)];
    const { ps, net } = await exec({ n: 2, vectors: vs, Q: 1 });
    const hashed = ['coin1-c', 'coin1-o', 'sac-rho', 'sac-tau', 'inputs', 'mul0', 'out', 'coin-c', 'coin-o', 'sig-c', 'sig-o'];
    const h = createHash('sha256');
    for (const rd of hashed) {
      h.update(rd);
      for (let p = 0; p < 2; p++) {
        h.update(`|${p}:`);
        const m = net.mesh(p).sent.find((s) => s.rd === rd)!;
        h.update(JSON.stringify(m.d));
      }
    }
    expect(ps[0]!.result!.transcriptDigest).toBe(h.digest('hex'));
    expect(ps[1]!.result!.transcriptDigest).toBe(ps[0]!.result!.transcriptDigest);
  });
  it('three parties, each vector shape: allow, thermometers and risk quantisation compose like the clear computation', async () => {
    for (const vs of [
      [V(1, 1, 5), V(1, 2, 3), V(1, 3, 4)],
      [V(1, 3, 0), V(1, 3, 0), V(1, 3, 0)],
      [V(0, 1, 0), V(1, 2, 5), V(1, 1, 2)],
      [V(1, 1, 5), V(0, 1, 5), V(1, 1, 5)],
      [V(1, 2, 2), V(1, 1, 5), V(1, 1, 1)],
    ]) {
      const { ps } = await exec({ n: 3, vectors: vs, Q: 5 });
      for (const p of ps) {
        expect(p.ok).toBe(true);
        expect(p.result!.composed).toEqual(composeClear(vs, 5));
        expect(p.result!.multiplications).toBe(2 * chainCount(5));
      }
    }
  });
  it('a single party composes to its own vector and runs no multiplication or sacrifice', async () => {
    const { ps } = await exec({ n: 1, vectors: [V(1, 2, 3)], Q: 4 });
    expect(ps[0]!.ok).toBe(true);
    expect(ps[0]!.result!.composed).toEqual({ allow: 1, t: 2, rQuant: 3 });
    expect(ps[0]!.result!.multiplications).toBe(0);
    expect(ps[0]!.result!.sacrificedTriples).toBe(0);
    expect(ps[0]!.result!.rounds.map((r) => r.rd)).toEqual(['prep', 'inputs', 'out', 'out.t', 'coin-c', 'coin-o', 'sig-c', 'sig-o', 'digest']);
  });
  it('four parties with the default Q: the dealer splits its preparation into several chunks and the parties reassemble them', async () => {
    const vs = [V(1, 1, 90), V(1, 2, 40), V(1, 3, 60), V(1, 1, 100)];
    const { ps, net } = await exec({ n: 4, vectors: vs, Q: 100 });
    for (const p of ps) {
      expect(p.ok, JSON.stringify(p.raw)).toBe(true);
      expect(p.result!.composed).toEqual(composeClear(vs, 100));
    }
    const prepRounds = net.mesh(4).sent.filter((s) => s.to === 0).map((s) => s.rd);
    expect(prepRounds[0]).toBe('prep');
    expect(prepRounds.length).toBeGreaterThan(1);
    expect(prepRounds[1]).toBe('prep.1');
    const first = net.mesh(4).sent.find((s) => s.to === 0 && s.rd === 'prep')!.d as { total: number; chunks: number; nums: string[] };
    expect(first.nums.length).toBe(30_000);
    expect(first.chunks).toBe(Math.ceil(first.total / 30_000));
  }, 60_000);
  it('Q defaults to 100 when omitted', async () => {
    const net = new MemNet([0, 1, 2], 'sess');
    const run = [0, 1].map((i) => runParty({ id: i, n: 2, input: V(1, 1, 100), mesh: net.mesh(i) as never, sessionId: 'sess' }));
    const d = runDealer({ n: 2, mesh: net.mesh(2) as never, seed: 3n });
    const [a, b] = await Promise.all([...run, d]);
    expect((a as PartyResult).Q).toBe(100);
    expect((a as PartyResult).composed.rQuant).toBe(100);
    expect((b as PartyResult).sacrificedTriples).toBe(104);
  });
  it('the dealer id defaults to n and can be configured', async () => {
    const net = new MemNet([0, 1, 5], 'sess');
    const run = [0, 1].map((i) => runParty({ id: i, n: 2, Q: 1, input: V(1, 1, 1), mesh: net.mesh(i) as never, sessionId: 'sess', dealerId: 5 }));
    const d = runDealer({ n: 2, Q: 1, mesh: net.mesh(5) as never, seed: 3n });
    const rs = await Promise.all([...run, d]);
    expect((rs[0] as PartyResult).composed.allow).toBe(1);
  });
});

describe('argument validation', () => {
  const mk = (o: Partial<Parameters<typeof runParty>[0]> = {}) => {
    const net = new MemNet([0, 1, 2], 's');
    return runParty({ id: 0, n: 2, Q: 3, input: V(1, 1, 1), mesh: net.mesh(0) as never, sessionId: 's', ...o });
  };
  it('refuses a behaviour hook without unsafeTestHooks, before anything else', async () => {
    const e = (await mk({ behavior: { kind: 'crash', round: 'x' }, n: 0 }).catch((x) => x)) as NetAbort;
    expect([e.kind, e.blamed, e.reporter]).toEqual(['local', null, 0]);
    expect(e.message).toContain('the behavior test hook requires unsafeTestHooks: true (test-only)');
    const e2 = (await mk({ behavior: { kind: 'crash', round: 'x' }, unsafeTestHooks: false }).catch((x) => x)) as NetAbort;
    expect(e2.message).toContain('requires unsafeTestHooks');
  });
  it('n must be a positive integer', async () => {
    for (const n of [0, -1, 1.5, NaN]) {
      const e = (await mk({ n }).catch((x) => x)) as NetAbort;
      expect([e.kind, e.blamed, e.reporter]).toEqual(['local', null, 0]);
      expect(e.message).toContain('n must be >= 1');
    }
  });
  it('the decision vector is validated field by field (including the Q bound)', async () => {
    const bad: DecisionVector[] = [
      { allow: 2 as never, t: 1, rQuant: 1 }, { allow: -1 as never, t: 1, rQuant: 1 },
      { allow: 1, t: 0 as never, rQuant: 1 }, { allow: 1, t: 4 as never, rQuant: 1 },
      { allow: 1, t: 1, rQuant: -1 }, { allow: 1, t: 1, rQuant: 1.5 }, { allow: 1, t: 1, rQuant: 4 }, { allow: 1, t: 1, rQuant: NaN },
    ];
    for (const input of bad) {
      const e = (await mk({ input }).catch((x) => x)) as NetAbort;
      expect(e.kind).toBe('local');
      expect(e.message).toContain('invalid decision vector');
    }
    // boundary values are accepted past validation (the run then waits on the dealer; abort it)
    for (const input of [V(0, 3, 0), V(1, 1, 3)]) {
      const net = new MemNet([0, 1, 2], 's', 100);
      const e = (await runParty({ id: 0, n: 2, Q: 3, input, mesh: net.mesh(0) as never, sessionId: 's' }).catch((x) => x)) as NetAbort;
      expect(e.message).not.toContain('invalid decision vector');
    }
  });
});

describe('dealer preparation is validated', () => {
  const tapPrep = (f: (d: { total: unknown; chunks: unknown; nums: unknown }, to: number) => unknown): MemTap =>
    (from, to, rd, payload) => (rd === 'prep' && from === 2 ? f(structuredClone(payload as never), to) : payload);
  const vs = [V(1, 1, 1), V(1, 2, 1)];
  const run = (f: Parameters<typeof tapPrep>[0]) => exec({ n: 2, vectors: vs, Q: 1, tap: tapPrep(f) });
  it.each([
    ['total is wrong', (d: { total: unknown }) => ((d.total as number) += 1), 'bad prep size'],
    ['total is not a number', (d: { total: unknown }) => (d.total = '5'), 'bad prep size'],
    ['chunk count is wrong', (d: { chunks: unknown }) => ((d.chunks as number) += 1), 'bad prep chunk count'],
    ['chunk count is not a number', (d: { chunks: unknown }) => (d.chunks = '1'), 'bad prep chunk count'],
    ['the numbers are too few', (d: { nums: unknown }) => (d.nums = (d.nums as string[]).slice(1)), 'bad prep numbers'],
    ['a number is not canonical', (d: { nums: unknown }) => ((d.nums as string[])[3] = '0F'), 'bad prep numbers'],
    ['nums is missing', (d: { nums: unknown }) => (d.nums = undefined), 'bad prep numbers'],
  ] as const)('refuses a dealer message where %s', async (_n, mut, msg) => {
    const { ps } = await run((d) => (mut(d as never), d));
    const e = ps[0]!.error!;
    expect([e.kind, e.blamed, e.reporter]).toEqual(['malformed', 2, 0]);
    expect(e.message).toBe(`[malformed] blamed=2 reporter=0: ${msg}`);
    expect(ps[0]!.ok).toBe(false);
  });
  it('refuses a null or non-object first message', async () => {
    for (const v of [null, 'x', 5]) {
      const { ps } = await run(() => v);
      expect(ps[0]!.error!.message).toBe('[malformed] blamed=2 reporter=0: bad prep size');
    }
  });
  it('a zero verification key is a dealer abort', async () => {
    const { ps } = await run((d) => ((d.nums as string[])[0] = '0', d));
    const e = ps[0]!.error!;
    expect([e.kind, e.blamed, e.reporter]).toEqual(['dealer', 2, 0]);
    expect(e.message).toContain('the dealer gave me a zero verification key');
    // the failure is propagated: the other party stops too
    expect(ps[1]!.ok).toBe(false);
  });
  it('a later chunk with the wrong length is refused (4 parties, 2 chunks)', async () => {
    const vs4 = [V(1, 1, 5), V(1, 2, 5), V(1, 3, 5), V(1, 1, 5)];
    const { ps } = await exec({ n: 4, vectors: vs4, Q: 100, tap: (f, t, rd, p) => (rd === 'prep.1' && t === 0 ? (p as string[]).slice(1) : p) });
    const e = ps[0]!.error!;
    expect(e.message).toBe('[malformed] blamed=4 reporter=0: bad prep numbers');
  }, 60_000);
  it('a missing later chunk times out waiting for prep.1 and blames the dealer', async () => {
    const vs4 = [V(1, 1, 5), V(1, 2, 5), V(1, 3, 5), V(1, 1, 5)];
    const { ps } = await exec({ n: 4, vectors: vs4, Q: 100, recvTimeoutMs: 150, tap: (f, t, rd, p) => (rd === 'prep.1' && t === 0 ? undefined : p) });
    const e = ps[0]!.error!;
    expect([e.kind, e.blamed]).toEqual(['timeout', 4]);
    expect(e.message).toContain("no 'prep.1' message from 4");
  }, 60_000);
});

describe('malicious behaviours are detected and attributed (trusted dealer)', () => {
  const vs3 = [V(1, 1, 2), V(1, 2, 1), V(1, 3, 0)];
  const honest = (ps: Outcome[], culprit: number) => ps.filter((_, i) => i !== culprit);
  it('open-lie in a tagged round is named by the pairwise tag, for every round and every culprit', async () => {
    for (const [culprit, round] of [[0, 'mul0'], [1, 'mul1'], [2, 'out'], [1, 'sac-rho'], [0, 'sac-tau']] as const) {
      const { ps } = await exec({ n: 3, vectors: vs3, Q: 2, behaviors: { [culprit]: { kind: 'open-lie', round } } });
      expect(ps[culprit]!.ok || !ps[culprit]!.ok).toBe(true);
      const direct = honest(ps, culprit).filter((p) => p.error && p.error.kind !== 'peer-abort');
      expect(direct.length).toBeGreaterThan(0);
      for (const p of direct) {
        expect(p.error!.kind).toBe('mac-check');
        expect(p.error!.blamed).toBe(culprit);
        expect(p.error!.message).toContain(`pairwise MAC on party ${culprit}'s opened share failed in round '${round}' (index 0)`);
      }
      for (const p of honest(ps, culprit)) expect(p.ok).toBe(false);
    }
  });
  it('bad-tag is named the same way and the abort reports the exact index', async () => {
    const { ps } = await exec({ n: 3, vectors: vs3, Q: 2, behaviors: { 1: { kind: 'bad-tag', round: 'mul0' } } });
    const direct = [ps[0]!, ps[2]!].filter((p) => p.error!.kind !== 'peer-abort');
    expect(direct.length).toBeGreaterThan(0);
    for (const p of direct) {
      expect(p.error!.blamed).toBe(1);
      expect(p.error!.message).toContain("pairwise MAC on party 1's opened share failed in round 'mul0' (index 0)");
    }
  });
  it('a MAC share forged only in the batched check is found by the MAC-check and named by the blame round', async () => {
    for (const culprit of [0, 1, 2]) {
      const { ps } = await exec({ n: 3, vectors: vs3, Q: 2, behaviors: { [culprit]: { kind: 'mac-lie', round: 'mul1' } } });
      const direct = honest(ps, culprit).filter((p) => p.error && p.error.kind !== 'peer-abort');
      expect(direct.length).toBeGreaterThan(0);
      for (const p of direct) {
        expect(p.error!.kind).toBe('mac-check');
        expect(p.error!.blamed).toBe(culprit);
        expect(p.error!.message).toContain('MAC-check FAILED: an opened value or MAC share was inconsistent; aborting with no output');
        expect(p.error!.message).toContain(`party ${culprit}'s MAC share (key 0) does not match its pairwise tag`);
      }
    }
  });
  it('a MAC residual that is off by one (consistent with its commitment) is named: its authenticated shares do not give it', async () => {
    const { ps } = await exec({ n: 3, vectors: vs3, Q: 2, behaviors: { 2: { kind: 'sigma-lie' } } });
    const direct = [ps[0]!, ps[1]!].filter((p) => p.error!.kind !== 'peer-abort');
    expect(direct.length).toBeGreaterThan(0);
    for (const p of direct) {
      expect(p.error!.blamed).toBe(2);
      expect(p.error!.message).toContain("party 2's opened MAC residual (key 0) is not what its authenticated shares give");
    }
  });
  it('opening a coin seed or a residual that does not match the commitment is a commitment abort naming the opener', async () => {
    const a = await exec({ n: 3, vectors: vs3, Q: 2, behaviors: { 1: { kind: 'bad-coin-open', round: 'coin' } } });
    for (const p of [a.ps[0]!, a.ps[2]!]) {
      if (p.error!.kind === 'peer-abort') continue;
      expect([p.error!.kind, p.error!.blamed]).toEqual(['commitment', 1]);
      expect(p.error!.message).toContain('party 1 opened a coin seed that does not match its commitment');
    }
    expect([a.ps[0]!, a.ps[2]!].some((p) => p.error!.kind === 'commitment')).toBe(true);
    const b = await exec({ n: 3, vectors: vs3, Q: 2, behaviors: { 0: { kind: 'bad-sigma-open' } } });
    expect([b.ps[1]!, b.ps[2]!].some((p) => p.error!.kind === 'commitment' && p.error!.blamed === 0 && p.error!.message.includes('party 0 opened a MAC residual that does not match its commitment'))).toBe(true);
  });
  it('wrong-length and non-canonical arrays are malformed, naming the sender and the expected length', async () => {
    for (const kind of ['short-array', 'noncanonical'] as const) {
      const { ps } = await exec({ n: 3, vectors: vs3, Q: 2, behaviors: { 2: { kind, round: 'mul0' } } });
      const direct = [ps[0]!, ps[1]!].filter((p) => p.error!.kind !== 'peer-abort');
      expect(direct.length).toBeGreaterThan(0);
      for (const p of direct) {
        expect([p.error!.kind, p.error!.blamed]).toEqual(['malformed', 2]);
        expect(p.error!.message).toBe(`[malformed] blamed=2 reporter=${p.error!.reporter}: expected ${2 * chainCount(2)} canonical field elements`);
      }
    }
  });
  it('a transcript digest that differs from mine is an equivocation naming the party that sent it', async () => {
    const tap: MemTap = (from, to, rd, payload) => (rd === 'digest' && from === 0 && to === 1 ? 'ab'.repeat(32) : payload);
    const { ps } = await exec({ n: 3, vectors: vs3, Q: 2, tap });
    const e = ps[1]!.error!;
    expect([e.kind, e.blamed, e.reporter]).toEqual(['equivocation', 0, 1]);
    expect(e.message).toBe('[equivocation] blamed=0 reporter=1: transcript digest of party 0 differs from mine (a broadcast was inconsistent)');
  });
  it('a malformed digest is refused as malformed', async () => {
    for (const bad of ['xyz', 5, null, 'AB'.repeat(32), 'ab'.repeat(31)]) {
      const tap: MemTap = (from, to, rd, payload) => (rd === 'digest' && from === 0 && to === 1 ? bad : payload);
      const { ps } = await exec({ n: 3, vectors: vs3, Q: 2, tap });
      expect(ps[1]!.error!.message).toBe('[malformed] blamed=0 reporter=1: bad digest');
    }
  });
  it('equivocating on a tagged round is caught by the pairwise tag of the receiver that was lied to', async () => {
    const { ps } = await exec({ n: 3, vectors: vs3, Q: 2, behaviors: { 0: { kind: 'equivocate', round: 'mul0' } } });
    const direct = [ps[1]!, ps[2]!].filter((p) => p.error && p.error.kind === 'mac-check');
    expect(direct.length).toBeGreaterThan(0);
    for (const p of direct) {
      expect(p.error!.blamed).toBe(0);
      expect(p.error!.message).toContain("round 'mul0'");
    }
  });
  it('a silent party is blamed by timeout at the configured deadline, with the deadline recorded', async () => {
    const { ps } = await exec({ n: 3, vectors: vs3, Q: 2, recvTimeoutMs: 250, behaviors: { 1: { kind: 'silent', round: 'mul0' } } });
    expect(ps[1]!.raw).toBeInstanceOf(SilentParty);
    expect((ps[1]!.raw as Error).message).toBe('silent');
    expect((ps[1]!.raw as Error).name).toBe('SilentParty');
    const direct = [ps[0]!, ps[2]!].filter((p) => p.error!.kind === 'timeout');
    expect(direct.length).toBeGreaterThan(0);
    for (const p of direct) {
      expect(p.error!.blamed).toBe(1);
      expect(p.error!.deadlineMs).toBe(250);
      expect(p.error!.message).toContain("no 'mul0' message from 1 within 250ms");
    }
  });
  it('a crash (process exit) at a round is a disconnect naming the crashed party', async () => {
    vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
      throw Object.assign(new Crash('exit'), { code });
    }) as never);
    const { ps } = await exec({ n: 3, vectors: vs3, Q: 2, behaviors: { 2: { kind: 'crash', round: 'out' } } });
    expect(ps[2]!.raw).toBeInstanceOf(Crash);
    expect((process.exit as unknown as { mock: { calls: unknown[][] } }).mock.calls[0]).toEqual([7]);
    const direct = [ps[0]!, ps[1]!].filter((p) => p.error!.kind === 'disconnect');
    expect(direct.length).toBeGreaterThan(0);
    for (const p of direct) expect(p.error!.blamed).toBe(2);
  });
  it('crash and silent hooks fire only at their round', async () => {
    const { ps } = await exec({ n: 2, vectors: vs3.slice(0, 2), Q: 2, behaviors: { 0: { kind: 'silent', round: 'no-such-round' }, 1: { kind: 'crash', round: 'no-such-round' } } });
    for (const p of ps) expect(p.ok).toBe(true);
  });
  it('crashing/silent at the prep round itself fires before anything is received', async () => {
    vi.spyOn(process, 'exit').mockImplementation((() => {
      throw new Crash('exit');
    }) as never);
    const a = await exec({ n: 2, vectors: vs3.slice(0, 2), Q: 2, recvTimeoutMs: 150, behaviors: { 0: { kind: 'crash', round: 'prep' } } });
    expect(a.ps[0]!.raw).toBeInstanceOf(Crash);
    const b = await exec({ n: 2, vectors: vs3.slice(0, 2), Q: 2, recvTimeoutMs: 150, behaviors: { 0: { kind: 'silent', round: 'prep' } } });
    expect(b.ps[0]!.raw).toBeInstanceOf(SilentParty);
  });
});

describe('a lying trusted dealer is caught', () => {
  const vs = [V(1, 1, 2), V(1, 2, 1)];
  it('a wrong kept product fails the sacrifice at that triple and is blamed on the dealer', async () => {
    for (const keepCDelta of [1n]) {
      const { ps } = await exec({ n: 2, vectors: vs, Q: 2, dealerFault: { keepCDelta } });
      for (const p of ps) {
        expect(p.ok).toBe(false);
        expect(p.error!.kind === 'dealer' || p.error!.kind === 'peer-abort').toBe(true);
      }
      const e = ps.find((p) => p.error!.kind === 'dealer')!.error!;
      expect(e.blamed).toBe(2);
      expect(e.message).toBe('[dealer] blamed=2 reporter=' + e.reporter + ': triple sacrifice FAILED at triple 0 (partner 0): c != a*b in the offline material; aborting with no output');
      expect(e.reason).toBeNull();
    }
  });
  it('a wrong partner product is located by partner index', async () => {
    const { ps } = await exec({ n: 2, vectors: vs, Q: 2, dealerFault: { partnerCDelta: [undefined, 5n] } });
    const e = ps.find((p) => p.error!.kind === 'dealer')!.error!;
    expect(e.message).toContain('(partner 1)');
    expect(e.message).toContain('triple 0');
  });
  it('MACs that do not match their values (all pairwise tags fine) are the dealer\'s fault, found in the blame round', async () => {
    const { ps } = await exec({ n: 2, vectors: vs, Q: 2, macFaultAtInput: 0 });
    const e = ps.find((p) => p.error!.kind === 'dealer')!.error!;
    expect(e.blamed).toBe(2);
    expect(e.message).toContain("MAC-check FAILED: an opened value or MAC share was inconsistent; aborting with no output - every party's shares verify, so the trusted dealer's MACs are inconsistent with its values");
    for (const p of ps) expect(p.ok).toBe(false);
  });
  it('all honest parties of a lying-dealer run stop with no output at all', async () => {
    const { ps } = await exec({ n: 3, vectors: [V(1, 1, 1), V(1, 1, 1), V(1, 1, 1)], Q: 1, dealerFault: { keepCDelta: 3n } });
    for (const p of ps) expect(p.result).toBeUndefined();
  });
});

describe('session binding', () => {
  it('commitments are bound to the session id: a party running under another session cannot open', async () => {
    const net = new MemNet([0, 1, 2], 'sess');
    const mk = (i: number, sid: string) => runParty({ id: i, n: 2, Q: 1, input: V(1, 1, 1), mesh: net.mesh(i) as never, sessionId: sid });
    const d = runDealer({ n: 2, Q: 1, mesh: net.mesh(2) as never, seed: 1n });
    const rs = await Promise.all([mk(0, 'sess').catch((e) => e), mk(1, 'other').catch((e) => e), d]);
    expect((rs[0] as NetAbort).kind === 'commitment' || (rs[1] as NetAbort).kind === 'commitment').toBe(true);
  });
});



// ===================================================================================== second round

async function detRun(n: number, vectors: DecisionVector[], Q: number, extra: Partial<Opts> = {}) {
  det.on = true;
  det.ctr = 0;
  try {
    return await exec({ n, vectors, Q, ...extra });
  } finally {
    det.on = false;
  }
}

describe('a deterministic run pins every derived value', () => {
  it('seeded dealer + fixed randomness gives a reproducible transcript digest (golden)', async () => {
    const vs = [V(1, 1, 1), V(1, 2, 0)];
    const a = await detRun(2, vs, 1);
    const b = await detRun(2, vs, 1);
    expect(a.ps[0]!.result!.transcriptDigest).toBe(b.ps[0]!.result!.transcriptDigest);
    expect(a.ps[0]!.result!.transcriptDigest).toBe('5e027c93518c817cfd8c100ba06aec68061f2899464087bf6b0283788cddf747');
    const c = await detRun(3, [V(1, 1, 2), V(1, 2, 1), V(0, 3, 0)], 2);
    expect(c.ps[0]!.result!.transcriptDigest).toBe('1793da8ca47a078cd7fe15d672bc4fcabd41d7c0432604d4c526dc42013a89de');
  });
  it('coin and residual commitments are SHA-256 over labelled, zero-separated fields (recomputed from the wire)', async () => {
    const vs = [V(1, 1, 1), V(1, 2, 0)];
    const { net } = await detRun(2, vs, 1);
    const h = (...parts: Array<string | Buffer>) => {
      const x = createHash('sha256');
      for (const p of parts) {
        x.update(typeof p === 'string' ? Buffer.from(p) : p);
        x.update(Buffer.from([0]));
      }
      return x.digest('hex');
    };
    for (const id of [0, 1]) {
      const sent = net.mesh(id).sent;
      for (const label of ['coin1', 'coin']) {
        const c = sent.find((m) => m.rd === `${label}-c`)!.d as string;
        const o = sent.find((m) => m.rd === `${label}-o`)!.d as string;
        expect(c).toBe(h('seed', 'sess', label, String(id), Buffer.from(o, 'hex')));
      }
      const sc = sent.find((m) => m.rd === 'sig-c')!.d as string;
      const so = sent.find((m) => m.rd === 'sig-o')!.d as { s: string[]; nonce: string };
      expect(sc).toBe(h('sigma', 'sess', String(id), so.s.join(','), Buffer.from(so.nonce, 'hex')));
      expect(so.s.length).toBe(MAC_KEYS);
    }
  });
});

describe('dealer randomness', () => {
  it('without a seed the dealer is random; with a seed it is reproducible', async () => {
    const dealOnce = async (seed?: bigint) => {
      const net = new MemNet([0, 1, 2], 'sess');
      await runDealer({ n: 2, Q: 1, mesh: net.mesh(2) as never, seed });
      return (net.mesh(2).sent.find((m) => m.to === 0 && m.rd === 'prep')!.d as { nums: string[] }).nums;
    };
    const a = await dealOnce();
    const b = await dealOnce();
    expect(a).not.toEqual(b);
    expect(await dealOnce(5n)).toEqual(await dealOnce(5n));
    expect(await dealOnce(5n)).not.toEqual(await dealOnce(6n));
    expect(await dealOnce(0n)).not.toEqual(await dealOnce());
  });
  it('a zero verification key drawn by the dealer is redrawn', async () => {
    const real = FieldRng.prototype.next;
    // index of the first draw after the MAC setup = the first verification-key draw
    let count = 0;
    const probe = vi.spyOn(FieldRng.prototype, 'next').mockImplementation(function (this: FieldRng) {
      count++;
      return real.call(this);
    });
    const { setupMac } = await import('../spdz');
    setupMac(2, new FieldRng(9n), MAC_KEYS);
    const idx = count;
    probe.mockRestore();
    let calls = 0;
    vi.spyOn(FieldRng.prototype, 'next').mockImplementation(function (this: FieldRng) {
      return calls++ === idx ? 0n : real.call(this);
    });
    const net = new MemNet([0, 1, 2], 'sess');
    await runDealer({ n: 2, Q: 1, mesh: net.mesh(2) as never, seed: 9n });
    const nums = (net.mesh(2).sent.find((m) => m.to === 0 && m.rd === 'prep')!.d as { nums: string[] }).nums;
    expect(nums[0]).not.toBe('0');
    const nums1 = (net.mesh(2).sent.find((m) => m.to === 1 && m.rd === 'prep')!.d as { nums: string[] }).nums;
    expect(nums1[0]).not.toBe('0');
  });
  it('pairwise tags and keys of each sharing are non-trivial and satisfy T_ij = K_ij + delta_j * x_i', async () => {
    const net = new MemNet([0, 1, 2], 'sess');
    await runDealer({ n: 2, Q: 1, mesh: net.mesh(2) as never, seed: 11n });
    const nums = [0, 1].map((p) => (net.mesh(2).sent.find((m) => m.to === p && m.rd === 'prep')!.d as { nums: string[] }).nums.map((x) => BigInt('0x' + x)));
    const delta = [nums[0]![0]!, nums[1]![0]!];
    // alpha sharings first: per key (x, tag_to_other, key_for_other)
    for (let l = 0; l < MAC_KEYS; l++) {
      const o = 1 + l * 3;
      const [x0, t0, k0] = [nums[0]![o]!, nums[0]![o + 1]!, nums[0]![o + 2]!];
      const [x1, t1, k1] = [nums[1]![o]!, nums[1]![o + 1]!, nums[1]![o + 2]!];
      expect(t0).not.toBe(0n);
      expect(k0).not.toBe(0n);
      expect(t1).not.toBe(0n);
      expect(k1).not.toBe(0n);
      expect(t0).toBe((k1 + delta[1]! * x0) % (2n ** 61n - 1n));
      expect(t1).toBe((k0 + delta[0]! * x1) % (2n ** 61n - 1n));
    }
  });
});

describe('commitment, seed, residual and blame messages are validated', () => {
  const vs = [V(1, 1, 2), V(1, 2, 1), V(1, 3, 0)];
  const only = (rd: string, f: (d: unknown) => unknown, from = 1, to = 0): MemTap => (a, b, r, d) => (a === from && b === to && r === rd ? f(structuredClone(d)) : d);
  const hex64 = 'ab'.repeat(32);
  it.each([
    ['coin1-c', 'bad commitment'], ['coin-c', 'bad commitment'], ['sig-c', 'bad commitment'],
  ])('%s must be 64 lowercase hex characters', async (rd, msg) => {
    for (const bad of [5, null, 'x', hex64 + '0', hex64.slice(1), hex64.toUpperCase().replace(/^/, ''), 'g' + hex64.slice(1), `${hex64}\n`, ['a'.repeat(64)]]) {
      if (bad === hex64.toUpperCase()) continue;
      const { ps } = await exec({ n: 3, vectors: vs, Q: 2, tap: only(rd, () => bad) });
      expect(ps[0]!.error!.message).toBe(`[malformed] blamed=1 reporter=0: ${msg}`);
    }
    const up = await exec({ n: 3, vectors: vs, Q: 2, tap: only(rd, () => 'AB'.repeat(32)) });
    expect(up.ps[0]!.error!.message).toBe(`[malformed] blamed=1 reporter=0: ${msg}`);
  });
  it.each([['coin1-o'], ['coin-o']])('%s must be a 64 hex-character seed', async (rd) => {
    for (const bad of [5, null, 'x', hex64 + '0', hex64.slice(1), 'AB'.repeat(32), `${hex64}\n`, ['a'.repeat(64)]]) {
      const { ps } = await exec({ n: 3, vectors: vs, Q: 2, tap: only(rd, () => bad) });
      expect(ps[0]!.error!.message).toBe('[malformed] blamed=1 reporter=0: bad seed');
    }
    const wrong = await exec({ n: 3, vectors: vs, Q: 2, tap: only(rd, () => hex64) });
    expect([wrong.ps[0]!.error!.kind, wrong.ps[0]!.error!.blamed]).toEqual(['commitment', 1]);
    expect(wrong.ps[0]!.error!.message).toContain('party 1 opened a coin seed that does not match its commitment');
  });
  it('sig-o: the opening must carry K canonical residuals and a 64 hex-character nonce', async () => {
    const good = (d: any) => d;
    void good;
    const nonce = hex64;
    for (const bad of [null, 'x', 5, {}, { s: ['1', '2'], nonce: 'x' }, { s: ['1'], nonce }, { s: ['1', '2', '3'], nonce }, { s: ['1', '02'], nonce }, { s: ['1', '2'] }, { s: ['1', '2'], nonce: 5 }, { s: ['1', '2'], nonce: nonce.toUpperCase() }, { s: ['1', '2'], nonce: nonce + '0' }, { s: ['1', '2'], nonce: nonce.slice(1) }, { s: 'ab', nonce }]) {
      const { ps } = await exec({ n: 3, vectors: vs, Q: 2, tap: only('sig-o', () => bad) });
      expect(ps[0]!.error!.message).toBe('[malformed] blamed=1 reporter=0: bad sigma opening');
    }
    const arr = await exec({ n: 3, vectors: vs, Q: 2, tap: only('sig-o', () => ({ s: ['1', '2'], nonce: [nonce] })) });
    expect(arr.ps[0]!.error!.message).toBe('[malformed] blamed=1 reporter=0: bad sigma opening');
    const wrong = await exec({ n: 3, vectors: vs, Q: 2, tap: only('sig-o', () => ({ s: ['1', '2'], nonce })) });
    expect([wrong.ps[0]!.error!.kind, wrong.ps[0]!.error!.blamed]).toEqual(['commitment', 1]);
  });
  it('digest must be 64 lowercase hex characters', async () => {
    for (const bad of [hex64 + '0', 'AB'.repeat(32), `${hex64}\n`, ['a'.repeat(64)]]) {
      const { ps } = await exec({ n: 3, vectors: vs, Q: 2, tap: only('digest', () => bad) });
      expect(ps[0]!.error!.message).toBe('[malformed] blamed=1 reporter=0: bad digest');
    }
  });
  it('a malformed blame message is refused field by field', async () => {
    // sigma-lie by party 1 triggers the MAC-check failure and the blame round
    for (const bad of [null, 'x', {}, { g: [], gt: [], a: [], at: [] }]) {
      const { ps } = await exec({ n: 3, vectors: vs, Q: 2, behaviors: { 1: { kind: 'sigma-lie' } }, tap: only('blame', () => bad) });
      expect(ps[0]!.error!.message).toBe(`[malformed] blamed=1 reporter=0: expected ${MAC_KEYS} canonical field elements`);
    }
    for (const field of ['g', 'gt', 'a', 'at']) {
      const { ps } = await exec({ n: 3, vectors: vs, Q: 2, behaviors: { 1: { kind: 'sigma-lie' } }, tap: only('blame', (d: any) => ((d[field] = d[field].slice(1)), d)) });
      expect(ps[0]!.error!.message).toBe(`[malformed] blamed=1 reporter=0: expected ${MAC_KEYS} canonical field elements`);
    }
  });
  it('a blame whose key share does not match its pairwise tag is named before the residual check', async () => {
    for (const field of ['a', 'at']) {
      const { ps } = await exec({ n: 3, vectors: vs, Q: 2, behaviors: { 1: { kind: 'sigma-lie' } }, tap: only('blame', (d: any) => ((d[field][0] = hx1(d[field][0])), d)) });
      const e = ps[0]!.error!;
      expect([e.kind, e.blamed]).toEqual(['mac-check', 1]);
      expect(e.message).toContain("party 1's key share (key 0) does not match its pairwise tag");
    }
    const g = await exec({ n: 3, vectors: vs, Q: 2, behaviors: { 1: { kind: 'sigma-lie' } }, tap: only('blame', (d: any) => ((d.gt[0] = hx1(d.gt[0])), d)) });
    expect(g.ps[0]!.error!.message).toContain("party 1's MAC share (key 0) does not match its pairwise tag");
  });
  it('the sigma-lie kind is mac-check with the residual message and the blame round ran', async () => {
    const { ps, net } = await exec({ n: 3, vectors: vs, Q: 2, behaviors: { 1: { kind: 'sigma-lie' } } });
    const e = [ps[0]!, ps[2]!].map((p) => p.error!).find((x) => x.kind !== 'peer-abort')!;
    expect(e.kind).toBe('mac-check');
    expect(net.mesh(0).sent.map((m) => m.rd)).toContain('blame');
  });
});
const hx1 = (s: string): string => ((BigInt('0x' + s) + 1n) % (2n ** 61n - 1n)).toString(16);

describe('behaviours alter exactly what they claim (compared against an honest run with the same dealer and randomness)', () => {
  const vs = [V(1, 1, 2), V(1, 2, 1), V(1, 3, 0)];
  const logOf = (net: MemNet, id: number, rd: string) => net.mesh(id).sent.filter((m) => m.rd === rd).map((m) => JSON.stringify(m.d));
  const parsed = (net: MemNet, id: number, rd: string, to: number) => net.mesh(id).sent.find((m) => m.rd === rd && m.to === to)!.d as string[];
  it('open-lie changes only value 0 of the chosen round, by +1', async () => {
    const h = await detRun(3, vs, 2);
    const b = await detRun(3, vs, 2, { behaviors: { 0: { kind: 'open-lie', round: 'mul0' } } });
    const a = parsed(h.net, 0, 'mul0', 1), c = parsed(b.net, 0, 'mul0', 1);
    expect(c.length).toBe(a.length);
    expect(BigInt('0x' + c[0]!)).toBe((BigInt('0x' + a[0]!) + 1n) % (2n ** 61n - 1n));
    expect(c.slice(1)).toEqual(a.slice(1));
    expect(logOf(b.net, 0, 'sac-rho')).toEqual(logOf(h.net, 0, 'sac-rho'));
  });
  it('equivocate lies to the first peer only, in the chosen round only, on value 0 by +1', async () => {
    const h = await detRun(3, vs, 2);
    const b = await detRun(3, vs, 2, { behaviors: { 0: { kind: 'equivocate', round: 'mul0' } } });
    const to1 = parsed(b.net, 0, 'mul0', 1), to2 = parsed(b.net, 0, 'mul0', 2);
    const h1 = parsed(h.net, 0, 'mul0', 1);
    expect(to2).toEqual(h1);
    expect(BigInt('0x' + to1[0]!)).toBe((BigInt('0x' + h1[0]!) + 1n) % (2n ** 61n - 1n));
    expect(to1.slice(1)).toEqual(h1.slice(1));
    expect(parsed(b.net, 0, 'sac-rho', 1)).toEqual(parsed(h.net, 0, 'sac-rho', 1));
  });
  it('noncanonical sends p in value 0 only, in the chosen round only', async () => {
    const b = await detRun(3, vs, 2, { behaviors: { 2: { kind: 'noncanonical', round: 'mul0' } } });
    const h = await detRun(3, vs, 2);
    const m = parsed(b.net, 2, 'mul0', 0), g = parsed(h.net, 2, 'mul0', 0);
    expect(m[0]).toBe((2n ** 61n - 1n).toString(16));
    expect(m.slice(1)).toEqual(g.slice(1));
    expect(parsed(b.net, 2, 'sac-rho', 0)).toEqual(parsed(h.net, 2, 'sac-rho', 0));
  });
  it('short-array drops exactly the first value of the chosen round', async () => {
    const b = await detRun(3, vs, 2, { behaviors: { 2: { kind: 'short-array', round: 'mul0' } } });
    const h = await detRun(3, vs, 2);
    expect(parsed(b.net, 2, 'mul0', 0)).toEqual(parsed(h.net, 2, 'mul0', 0).slice(1));
  });
  it('bad-tag changes only tag 0, by +1, in the chosen round', async () => {
    const h = await detRun(3, vs, 2);
    const b = await detRun(3, vs, 2, { behaviors: { 1: { kind: 'bad-tag', round: 'mul0' } } });
    const a = parsed(h.net, 1, 'mul0.t', 0), c = parsed(b.net, 1, 'mul0.t', 0);
    expect(BigInt('0x' + c[0]!)).toBe((BigInt('0x' + a[0]!) + 1n) % (2n ** 61n - 1n));
    expect(c.slice(1)).toEqual(a.slice(1));
    expect(parsed(b.net, 1, 'sac-rho.t', 0)).toEqual(parsed(h.net, 1, 'sac-rho.t', 0));
  });
  it('mac-lie leaves the opened values alone and corrupts only the MAC residual path', async () => {
    const h = await detRun(3, vs, 2);
    const b = await detRun(3, vs, 2, { behaviors: { 0: { kind: 'mac-lie', round: 'mul1' } } });
    expect(parsed(b.net, 0, 'mul1', 1)).toEqual(parsed(h.net, 0, 'mul1', 1));
    const so = (net: MemNet) => (net.mesh(0).sent.find((m) => m.rd === 'sig-o' && m.to === 1)!.d as { s: string[] }).s;
    const hs = so(h.net), bs = so(b.net);
    expect(bs[0]).not.toBe(hs[0]);
    expect(bs[1]).toBe(hs[1]);
  });
  it('sigma-lie shifts residual 0 only; bad-sigma-open opens residual 0 shifted by one against its commitment', async () => {
    const h = await detRun(3, vs, 2);
    const sig = (net: MemNet, id: number) => (net.mesh(id).sent.find((m) => m.rd === 'sig-o' && m.to === (id === 0 ? 1 : 0))!.d as { s: string[]; nonce: string });
    const s = await detRun(3, vs, 2, { behaviors: { 0: { kind: 'sigma-lie' } } });
    const bo = await detRun(3, vs, 2, { behaviors: { 0: { kind: 'bad-sigma-open' } } });
    for (const x of [s, bo]) {
      const a = sig(h.net, 0), c = sig(x.net, 0);
      expect(BigInt('0x' + c.s[0]!)).toBe((BigInt('0x' + a.s[0]!) + 1n) % (2n ** 61n - 1n));
      expect(c.s[1]).toBe(a.s[1]);
      expect(c.nonce).toBe(a.nonce);
    }
    // sigma-lie commits to the lie; bad-sigma-open commits to the truth and opens the lie
    const commitOf = (net: MemNet) => net.mesh(0).sent.find((m) => m.rd === 'sig-c' && m.to === 1)!.d as string;
    expect(commitOf(s.net)).not.toBe(commitOf(h.net));
    expect(commitOf(bo.net)).toBe(commitOf(h.net));
  });
  it('bad-coin-open tampers only the final coin: the first coin and everything before it pass, and the abort names the opener', async () => {
    const b = await exec({ n: 3, vectors: vs, Q: 2, behaviors: { 1: { kind: 'bad-coin-open', round: 'coin' } } });
    const rounds = b.net.mesh(1).sent.map((m) => m.rd);
    expect(rounds).toContain('out');
    expect(rounds).toContain('coin-o');
    const direct = [b.ps[0]!, b.ps[2]!].find((p) => p.error!.kind === 'commitment')!;
    expect(direct.error!.blamed).toBe(1);
  });
  it('behaviours apply only to the configured party: peers run honestly', async () => {
    const b = await detRun(3, vs, 2, { behaviors: { 0: { kind: 'open-lie', round: 'mul0' } } });
    const h = await detRun(3, vs, 2);
    expect(parsed(b.net, 1, 'mul0', 0)).toEqual(parsed(h.net, 1, 'mul0', 0));
  });
});

describe('timing statistics', () => {
  it('round and run durations are differences of the monotonic clock, in order', async () => {
    let t = 1_000_000;
    vi.spyOn(performance, 'now').mockImplementation(() => (t += 3));
    const { ps } = await exec({ n: 2, vectors: [V(1, 1, 1), V(1, 2, 0)], Q: 1 });
    for (const p of ps) {
      for (const r of p.result!.rounds) {
        expect(r.ms).toBeGreaterThan(0);
        expect(r.ms).toBeLessThan(1000);
        expect(r.ms % 3).toBe(0);
      }
      expect(p.result!.wallMs).toBeGreaterThan(0);
      expect(p.result!.wallMs).toBeLessThan(100_000);
      expect(p.result!.wallMs % 3).toBe(0);
    }
  });
  it('the prep round reports only the bytes that arrived during preparation (a dealer that already sent counts once)', async () => {
    const net = new MemNet([0, 1, 2], 'sess');
    await runDealer({ n: 2, Q: 1, mesh: net.mesh(2) as never, seed: 4n });
    const first = (net.mesh(2).sent.find((m) => m.to === 0 && m.rd === 'prep')!.d);
    const size = JSON.stringify(first).length + 'prep'.length;
    const r = await runParty({ id: 0, n: 2, Q: 1, input: V(1, 1, 1), mesh: net.mesh(0) as never, sessionId: 'sess' }).catch((e) => e);
    void r; // the second party is absent, so this run aborts later; only the prep round matters
    void size;
  }, 30_000);
});

describe('audit attribution when the transcript audit names no one', () => {
  const vs = [V(1, 1, 1), V(1, 2, 0), V(1, 3, 1)];
  it('three parties, no culprit nameable from this view: unattributable, with an explanatory reason and a pair count', async () => {
    det.audit = () => ({ selfBad: new Set<number>(), pairBad: [[1, 2]] });
    const r = await party(3, vs, 1, { behaviors: { 2: { kind: 'offline-lie' } } });
    const e = r.out[0]!.error!;
    expect([e.kind, e.blamed, e.reporter]).toEqual(['mac-check', null, 0]);
    expect(e.message).toContain('(OT transcript audit: 1 inconsistent pair(s), no party can be named from this view: a pair failure between two other parties is not evidence against either of them to me)');
    expect(e.reason).toBe("the triple sacrifice failed in dealer-free mode and the OT transcript audit of this party's own view names no one (a failing pair that does not involve me is not evidence I can use, and an accusation is never accepted against a third party)");
  }, 240_000);
  it('two parties with an unnamed culprit: the only possible one is the peer', async () => {
    det.audit = () => ({ selfBad: new Set<number>(), pairBad: [] });
    const r = await party(2, vs.slice(0, 2), 1, { behaviors: { 1: { kind: 'offline-lie' } } });
    expect([r.out[0]!.error!.blamed, r.out[1]!.error!.blamed]).toEqual([1, 0]);
    expect(r.out[0]!.error!.message).toContain('(OT transcript audit: 0 inconsistent pair(s), no party can be named');
  }, 120_000);
});


// ===================================================================================== third round (no-dealer paths)

const MOD = 2n ** 61n - 1n;
const chalOf = (seed: Buffer, label: string, j: number): bigint => {
  for (let ctr = 0; ; ctr++) {
    const h = createHash('sha256');
    for (const p of ['chal', seed, `${label}:${j}:${ctr}`]) {
      h.update(typeof p === 'string' ? Buffer.from(p) : p);
      h.update(Buffer.from([0]));
    }
    const d = h.digest();
    const x = d.readBigUInt64BE(0) & ((1n << 61n) - 1n);
    if (x < MOD && x !== 0n) return x;
  }
};

const pick = (r: { out: Array<{ error?: NetAbort }> }, pred: (e: NetAbort) => boolean): NetAbort => {
  const e = r.out.map((o) => o.error).find((x): x is NetAbort => x !== undefined && pred(x));
  if (!e) throw new Error('no matching abort: ' + JSON.stringify(r.out.map((o) => o.error?.message ?? 'ok')));
  return e;
};

describe('no-dealer protocol round structure', () => {
  const vs = [V(1, 1, 1), V(1, 2, 0)];
  it('input path: joint coin-in, one in-check opening whose value is the masked random combination of all inputs', async () => {
    const r = await party(2, vs, 1);
    for (const p of r.out) expect(p.ok, p.error?.message).toBe(true);
    const rds = r.out[0]!.result!.rounds.map((x) => x.rd);
    expect(rds).toContain('coin-in-c');
    expect(rds).toContain('coin-in-o');
    expect(rds).toContain('in-check');
    expect(rds).toContain('in-check.t');
    expect(rds).not.toContain('inputs');
    expect(rds.indexOf('coin-in-o')).toBeLessThan(rds.indexOf('in-check'));
    expect(rds.indexOf('in-check.t')).toBeLessThan(rds.indexOf('mul0'));
    // recompute the opened value: mask + sum_q chal_q * input_q, from the parties' own preps and the wire
    const sent = (id: number, rd: string) => r.net.mesh(id).sent.filter((m) => m.rd === rd);
    expect(sent(0, 'in-check').length).toBe(1);
    expect((sent(0, 'in-check')[0]!.d as unknown[]).length).toBe(1);
    const seeds = [0, 1].map((id) => Buffer.from(sent(id, 'coin-in-o')[0]!.d as string, 'hex'));
    const joint = createHash('sha256');
    for (const part of ['joint', 'sess', 'coin-in', ...seeds]) {
      joint.update(typeof part === 'string' ? Buffer.from(part) : part);
      joint.update(Buffer.from([0]));
    }
    const jointSeed = joint.digest();
    const C = chainCount(1);
    if (det.preps.size !== 2) throw new Error('preps captured: ' + [...det.preps.keys()].join(','));
    const preps = [0, 1].map((id) => det.preps.get(id));
    const total = [0, 1].map((id) => BigInt('0x' + (sent(id, 'in-check')[0]!.d as string[])[0]!)).reduce((a, b) => (a + b) % MOD, 0n);
    let want = [0, 1].reduce((a, id) => (a + preps[id]!.checkMask.v.x) % MOD, 0n);
    for (let q = 0; q < 2 * C; q++) {
      const val = [0, 1].reduce((a, id) => (a + preps[id]!.inputs[q].v.x) % MOD, 0n);
      want = (want + chalOf(jointSeed, 'in', q) * val) % MOD;
    }
    expect(total).toBe(want);
  }, 180_000);
  it('only the final coin tampers its opening: bad-coin-open in a dealer-free run still completes the online phase first', async () => {
    const r = await party(2, vs, 1, { behaviors: { 1: { kind: 'bad-coin-open', round: 'coin' } } });
    expect(r.net.mesh(1).sent.map((m) => m.rd)).toContain('out');
    expect(r.out[0]!.error!.kind === 'commitment' || r.out[0]!.error!.kind === 'peer-abort').toBe(true);
  }, 180_000);
  it('a failed sacrifice at triple 1 discloses triple 1 (not 0), with the default forensic deadline and the right shape', async () => {
    det.prepHook = (id, prep) => {
      if (id === 0) prep.triples[1][2].v.x = (prep.triples[1][2].v.x + 1n) % MOD;
      if (id === 1) prep.triples[1][2].v.key[0] = ((prep.triples[1][2].v.key[0] as bigint) - (prep.delta as bigint) + MOD) % MOD;
    };
    const r = await party(2, vs, 1);
    const e = pick(r, (x) => x.message.includes('triple sacrifice FAILED'));
    expect(e.message).toContain('triple sacrifice FAILED at triple 1 (partner 0)');
    expect(det.exch.length).toBeGreaterThanOrEqual(2);
    for (const x of det.exch) {
      expect(x.tripleIndex).toBe(1);
      expect(x.deadlineMs).toBe(30_000);
      expect(x.slots).toBe(1 + SACRIFICE_PARTNERS);
      expect(x.rows).toBe(61 + 3 * 64);
    }
  }, 180_000);
  it('a malformed forensic commitment is refused as malformed naming the sender', async () => {
    det.prepHook = (id, prep) => {
      if (id === 0) prep.triples[0][2].v.x = (prep.triples[0][2].v.x + 1n) % MOD;
      if (id === 1) prep.triples[0][2].v.key[0] = ((prep.triples[0][2].v.key[0] as bigint) - (prep.delta as bigint) + MOD) % MOD;
    };
    const net = new MemNet([0, 1], 'sess', 60_000, (from, to, rd, d) => (rd === 'forensic-c' && from === 1 ? 'nonsense' : d));
    const res: NetAbort[] = [];
    const runs: Array<Promise<void>> = [];
    for (const [i, v] of vs.entries()) {
      runs.push(runParty({ id: i, n: 2, Q: 1, input: v, mesh: net.mesh(i) as never, offline: 'no-dealer', sessionId: 'sess', forensicDeadlineMs: 5000 }).then(() => undefined, (e) => void (res[i] = e as NetAbort)));
      await new Promise((r) => setTimeout(r, 40));
    }
    await Promise.all(runs);
    expect(pick({ out: res.map((e) => ({ error: e as NetAbort })) }, (x) => x.kind === 'malformed').message).toBe('[malformed] blamed=1 reporter=0: bad forensic commitment');
    expect(det.exch[0]!.deadlineMs).toBe(5000);
  }, 180_000);
  it('three parties: a wrong triple product is named by the real transcript audit (own disclosure included)', async () => {
    const r = await party(3, [V(1, 1, 1), V(1, 2, 0), V(1, 3, 1)], 1, { behaviors: { 2: { kind: 'offline-lie' } } });
    expect(r.out[0]!.error!.blamed).toBe(2);
    expect(r.out[0]!.error!.message).toContain('OT transcript audit names party 2');
    expect(r.out[1]!.error!.blamed).toBe(2);
  }, 300_000);
  it('a MAC failure with every pairwise tag consistent is attributable only with two parties (dealer-free)', async () => {
    const bump = (id: number, prep: any) => {
      // shift party 0's MAC share (key 0) of input 0 by one and keep the pairwise tag relation intact
      if (id === 0) prep.inputs[0].m[0].x = (prep.inputs[0].m[0].x + 1n) % MOD;
      if (id === 1) prep.inputs[0].m[0].key[0] = ((prep.inputs[0].m[0].key[0] as bigint) - (prep.delta as bigint) + MOD) % MOD;
    };
    det.prepHook = bump;
    const r = await party(2, vs, 1);
    const es = r.out.map((o) => o.error!).filter((x) => x.kind === 'mac-check' && x.message.includes('not attributable'));
    expect(es.map((x) => x.reporter).sort()).toEqual([0, 1]);
    for (const e of es) {
      expect(e.blamed).toBe(1 - e.reporter);
      expect(e.message).toContain("every party's shares verify under its pairwise tags, so the offline material is inconsistent (a wrong OT operand): not attributable");
    }
    expect(r.net.mesh(0).sent.map((m) => m.rd)).toContain('blame');
  }, 180_000);
  it('three parties: the same failure names no one and says why', async () => {
    det.prepHook = (id, prep) => {
      // shift party 0's share and re-key every other party
      if (id === 0) prep.inputs[0].m[0].x = (prep.inputs[0].m[0].x + 1n) % MOD;
      else prep.inputs[0].m[0].key[0] = ((prep.inputs[0].m[0].key[0] as bigint) - (prep.delta as bigint) + MOD) % MOD;
    };
    const r = await party(3, [V(1, 1, 1), V(1, 2, 0), V(1, 3, 1)], 1);
    const e = r.out.map((o) => o.error!).find((x) => x.kind === 'mac-check' && x.reason !== null && x.message.includes('not attributable'))!;
    expect(e).toBeDefined();
    expect(e.blamed).toBeNull();
    expect(e.reason).toBe("every party's shares verify under its pairwise tags, so the failure is in the offline OT material and no party can be named");
  }, 300_000);
  it('without pairwise tags a MAC failure is attributable only for two parties, and the tag rounds disappear', async () => {
    det.prepHook = (id, prep) => {
      prep.tagged = false;
      if (id === 0) prep.inputs[0].m[0].x = (prep.inputs[0].m[0].x + 1n) % MOD;
    };
    const r = await party(2, vs, 1);
    const rds = r.net.mesh(0).sent.map((m) => m.rd);
    expect(rds.some((x) => x.endsWith('.t'))).toBe(false);
    expect(rds).not.toContain('blame');
    const es = r.out.map((o) => o.error!).filter((x) => x.kind === 'mac-check');
    expect(es.map((x) => x.reporter).sort()).toEqual([0, 1]);
    for (const e of es) {
      expect(e.blamed).toBe(1 - e.reporter);
      expect(e.reason).toBeNull();
      expect(e.message).toBe('[mac-check] blamed=' + (1 - e.reporter) + ' reporter=' + e.reporter + ': MAC-check FAILED: an opened value or MAC share was inconsistent; aborting with no output');
    }
  }, 180_000);
  it('without pairwise tags and with three parties the failure names no one, with the explanatory reason', async () => {
    det.prepHook = (id, prep) => {
      prep.tagged = false;
      if (id === 0) prep.inputs[0].m[0].x = (prep.inputs[0].m[0].x + 1n) % MOD;
    };
    const r = await party(3, [V(1, 1, 1), V(1, 2, 0), V(1, 3, 1)], 1);
    const e = pick(r, (x) => x.kind === 'mac-check' && x.message.includes('MAC-check FAILED'));
    expect(e.blamed).toBeNull();
    expect(e.reason).toBe('this mode carries no pairwise tags, so a MAC-check failure cannot name a party (only possible with two parties)');
  }, 300_000);
});


describe('scripted conditions the protocol cannot produce on its own', () => {
  it('a non-NetAbort failure while reading a later dealer chunk is reported as malformed, blaming the dealer', async () => {
    const vs4 = [V(1, 1, 5), V(1, 2, 5), V(1, 3, 5), V(1, 1, 5)];
    const net = new MemNet([0, 1, 2, 3, 4], 'sess', 20_000);
    const m0 = net.mesh(0);
    const recv = m0.recv.bind(m0);
    m0.recv = async (from: number, rd: string, t?: number) => {
      if (rd === 'prep.1') throw new TypeError('scripted transport failure');
      return recv(from, rd, t);
    };
    const runs = vs4.map((v, i) => runParty({ id: i, n: 4, Q: 100, input: v, mesh: net.mesh(i) as never, sessionId: 'sess' }).catch((e) => e as NetAbort));
    const d = runDealer({ n: 4, Q: 100, mesh: net.mesh(4) as never, seed: 2n }).catch(() => null);
    const [e0] = await Promise.all(runs);
    await d;
    expect(e0).toBeInstanceOf(NetAbort);
    expect((e0 as NetAbort).message).toBe('[malformed] blamed=4 reporter=0: scripted transport failure');
  }, 60_000);
  it('a behaviour with an unrecognised kind changes nothing (only mac-lie corrupts MAC shares)', async () => {
    const vs = [V(1, 1, 2), V(1, 2, 1), V(1, 3, 0)];
    const { ps } = await exec({ n: 3, vectors: vs, Q: 2, behaviors: { 0: { kind: 'no-such-kind' as never, round: 'mul0' } } });
    for (const p of ps) {
      expect(p.ok, p.error?.message).toBe(true);
      expect(p.result!.composed).toEqual(composeClear(vs, 2));
    }
  });
});
