import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

const seen = vi.hoisted(() => ({ sids: [] as string[], deriveThrow: null as unknown }));
vi.mock('../ot', async (orig) => {
  const real = (await orig()) as typeof import('../ot');
  return {
    ...real,
    bindingBytes: ((b: { sessionId: Uint8Array }) => {
      seen.sids.push(Buffer.from(b.sessionId).toString('hex'));
      return real.bindingBytes(b as never);
    }) as typeof real.bindingBytes,
    malBaseOtSenderDerive: ((...a: unknown[]) => {
      if (seen.deriveThrow) throw seen.deriveThrow;
      return (real.malBaseOtSenderDerive as (...x: unknown[]) => unknown)(...a);
    }) as typeof real.malBaseOtSenderDerive,
  };
});
import { SecureFieldRng } from '../csprng';
import { STAT_SEC, makeGadget } from '../enc';
import { composeClear } from '../compose';
import { PRIME, fadd, fmul } from '../field';
import { KAPPA, OtExtReceiver } from '../ot';
import type { DecisionVector } from '../party';
import { SACRIFICE_PARTNERS, MAC_KEYS } from '../spdz';
import { auditDisclosures } from './forensics';
import { type MemMesh, MemNet, type MemTap } from './memnet';
import { type PA } from './pa';
import { runOfflineNet } from './offline-net';
import { chainCount, runParty, type Behavior, type PartyResult } from './protocol';
import { sharingsPerTriple } from './prep';
import { NetAbort, hx, unhxArray } from './wire';

const V = (allow: 0 | 1, t: 1 | 2 | 3, rQuant: number): DecisionVector => ({ allow, t, rQuant });
const P = SACRIFICE_PARTNERS;
const K = MAC_KEYS;

interface Run {
  net: MemNet;
  out: Array<{ ok: boolean; result?: PartyResult; error?: NetAbort }>;
}
async function party(n: number, vs: DecisionVector[], Q: number, o: { behaviors?: Record<number, Behavior>; tap?: MemTap; recvTimeoutMs?: number } = {}): Promise<Run> {
  const net = new MemNet(Array.from({ length: n }, (_, i) => i), 'sess', o.recvTimeoutMs ?? 120_000, o.tap ?? null);
  const out = await Promise.all(
    vs.map((v, i) =>
      runParty({ id: i, n, Q, input: v, mesh: net.mesh(i) as unknown as never, offline: 'no-dealer', sessionId: 'sess', behavior: o.behaviors?.[i], unsafeTestHooks: o.behaviors?.[i] ? true : undefined }).then(
        (result) => ({ ok: true, result }),
        (e: unknown) => ({ ok: false, error: e as NetAbort }),
      ),
    ),
  );
  return { net, out };
}

/** Drive runOfflineNet directly (same wrappers as protocol.ts) so the dealt-equivalent material can be inspected. */
async function offlineOnly(n: number, vs: DecisionVector[], Q: number) {
  const net = new MemNet(Array.from({ length: n }, (_, i) => i), 'sess', 120_000);
  const C = chainCount(Q);
  const preps = await Promise.all(
    vs.map((v, id) => {
      const mesh = net.mesh(id) as MemMesh;
      const others = Array.from({ length: n }, (_, i) => i).filter((i) => i !== id);
      const bad = (p: number, what: string): never => {
        throw new NetAbort('malformed', p, id, what);
      };
      return runOfflineNet({
        mesh: mesh as unknown as never, id, n, C, keys: K, partners: P, sessionId: 'sess', input: v, Q,
        exchange: async (rd, mine, parse) => {
          for (const p of others) mesh.send(p, rd, mine(p));
          const raw = await mesh.collect(rd, others);
          const m = new Map<number, ReturnType<typeof parse>>();
          for (const p of others) {
            try {
              m.set(p, parse(p, raw.get(p)));
            } catch (e) {
              if (e instanceof NetAbort) throw e;
              throw new NetAbort('malformed', p, id, `round '${rd}': ${(e as Error).message}`);
            }
          }
          return m;
        },
        crashIf: () => undefined,
        bad,
        arr: (p, raw, len) => unhxArray(raw, len) ?? bad(p, `expected ${len} canonical field elements`),
      });
    }),
  );
  return { net, preps, C };
}

const sumField = (xs: bigint[]): bigint => xs.reduce((a, b) => fadd(a, b), 0n);

describe('dealer-free offline material (2 parties, Q = 1)', () => {
  const vs = [V(1, 1, 1), V(1, 2, 0)];
  it('is a correct authenticated sharing: triples, MACs, inputs, check mask and pairwise tags all verify', async () => {
    const { net, preps, C } = await offlineOnly(2, vs, 1);
    const n = 2;
    // global MAC keys
    const alpha = Array.from({ length: K }, (_, l) => sumField(preps.map((p) => p.alpha[l]!.x)));
    for (const p of preps) {
      expect(p.mode).toBe('no-dealer');
      expect(p.tagged).toBe(true);
      expect(p.delta).not.toBe(0n);
      expect(p.alpha.length).toBe(K);
      expect(p.triples.length).toBe((n - 1) * C);
      expect(p.inputs.length).toBe(n * C);
    }
    expect(preps[0]!.delta).not.toBe(preps[1]!.delta);
    expect(preps[0]!.alpha[0]!.x).not.toBe(preps[1]!.alpha[0]!.x);
    // every sharing: macs sum to alpha * value, for all parties' shares
    const val = (get: (i: number) => { v: PA; m: PA[] }): { v: bigint; macs: bigint[] } => ({
      v: sumField(preps.map((_, i) => get(i).v.x)),
      macs: Array.from({ length: K }, (_, l) => sumField(preps.map((_, i) => get(i).m[l]!.x))),
    });
    const checkAW = (get: (i: number) => { v: PA; m: PA[] }): bigint => {
      const s = val(get);
      expect(s.macs.length).toBe(K);
      for (let l = 0; l < K; l++) expect(s.macs[l]).toBe(fmul(alpha[l]!, s.v));
      return s.v;
    };
    for (let t = 0; t < (n - 1) * C; t++) {
      expect(preps[0]!.triples[t]!.length).toBe(sharingsPerTriple(P));
      const sh = (k: number) => checkAW((i) => preps[i]!.triples[t]![k]!);
      const a = sh(0), b = sh(1), c = sh(2);
      expect(c).toBe(fmul(a, b));
      for (let r = 0; r < P; r++) {
        const ah = sh(3 + 2 * r), ch = sh(4 + 2 * r);
        expect(ch).toBe(fmul(ah, b));
      }
      expect(a).not.toBe(0n);
    }
    // inputs: the sum of the shares of (owner o, chain c) is owner o's input bit
    const bitsOf = (v: DecisionVector): number[] => [v.allow, ...[1, 2, 3].map((k) => (v.t >= k ? 1 : 0)), ...[1].map((k) => (v.rQuant >= k ? 1 : 0))];
    for (let o = 0; o < n; o++) {
      const bits = bitsOf(vs[o]!);
      for (let c = 0; c < C; c++) expect(checkAW((i) => preps[i]!.inputs[o * C + c]!)).toBe(BigInt(bits[c]!));
      expect(preps[o]!.myPlain).toEqual(bits.map(BigInt));
    }
    const mask = checkAW((i) => preps[i]!.checkMask!);
    expect(mask).not.toBe(0n);
    // pairwise tags: T_ij = K_ij + delta_j * x_i for every PA of every kind (value, mac, alpha)
    const allPA = (p: (typeof preps)[number]): PA[] => [...p.alpha, ...[...p.triples.flat(), ...p.inputs, p.checkMask!].flatMap((w) => [w.v, ...w.m])];
    const A = allPA(preps[0]!), B = allPA(preps[1]!);
    expect(A.length).toBe(B.length);
    expect(A.length).toBe(K + ((n - 1) * C * sharingsPerTriple(P) + n * C + 1) * (1 + K));
    for (let u = 0; u < A.length; u++) {
      expect(A[u]!.tag[0]).toBe(0n);
      expect(A[u]!.key[0]).toBe(0n);
      expect(A[u]!.tag.length).toBe(n);
      expect(fadd(B[u]!.key[0]!, fmul(preps[1]!.delta, A[u]!.x))).toBe(A[u]!.tag[1]);
      expect(fadd(A[u]!.key[1]!, fmul(preps[0]!.delta, B[u]!.x))).toBe(B[u]!.tag[0]);
    }
    // forensic disclosures cover the kept products and audit clean
    const f = preps[0]!.forensics!;
    expect(f.slots).toBe(1 + P);
    expect(f.rows).toBe(f.gadget.length);
    expect(f.gadget.length).toBe(61 + 3 * 64);
    expect(f.gadget.every((g) => g >= 0n && g < PRIME)).toBe(true);
    expect(preps[1]!.forensics!.gadget).toEqual(f.gadget);
    for (let t = 0; t < (n - 1) * C; t += 1) {
      const all = new Map(preps.map((p, i) => [i, p.forensics!.disclose(t)]));
      const d0 = all.get(0)!;
      expect(d0.length).toBe(1 + P);
      expect(d0[0]!.bits.length).toBe(f.rows);
      expect(d0[0]!.recv.size).toBe(n - 1);
      expect(d0[0]!.rho.get(1)!.length).toBe(f.rows);
      const res = auditDisclosures(all, f.gadget);
      expect(res.selfBad.size).toBe(0);
      expect(res.pairBad).toEqual([]);
      expect(d0[0]!.z).toBe(preps[0]!.triples[t]![2]!.v.x);
      expect(d0[1]!.z).toBe(preps[0]!.triples[t]![4]!.v.x);
    }
    // the protocol rounds, in order, with their wire shapes
    const rounds = net.mesh(0).sent.map((s) => s.rd);
    expect(rounds).toEqual([
      'ob-S', 'ob-R', 'ob-C', 'gd-c', 'gd-o', 'in-share', 'ox1.0.u', 'ox1.0.y', 'ox1.1.u', 'ox1.1.y', 'ox1.2.u', 'ox1.2.y',
      'ox2.0.u', 'ox2.0.y', 'ox3.0.u', 'ox3.0.y', 'ox3.1.u', 'ox3.1.y', 'ox3.2.u', 'ox3.2.y', 'ox3.3.u', 'ox3.3.y', 'ox3.4.u', 'ox3.4.y', 'ox3.5.u', 'ox3.5.y',
    ].filter((r) => rounds.includes(r)));
    expect(rounds.slice(0, 6)).toEqual(['ob-S', 'ob-R', 'ob-C', 'gd-c', 'gd-o', 'in-share']);
    expect(rounds.slice(6).every((r, i) => (i % 2 === 0 ? r.endsWith('.u') : r.endsWith('.y')))).toBe(true);
    const layers = rounds.slice(6).filter((r) => r.endsWith('.u')).map((r) => r.slice(2, 3));
    expect(layers).toEqual([...layers].sort());
    expect(new Set(layers)).toEqual(new Set(['1', '2', '3']));
    const S = net.mesh(0).sent.find((s) => s.rd === 'ob-S')!.d as Record<string, Record<string, string>>;
    expect(Object.keys(S).sort()).toEqual(['S', 'U', 'z']);
    expect(Object.keys(S['S']!).sort()).toEqual(['x', 'y']);
    const R = net.mesh(0).sent.find((s) => s.rd === 'ob-R')!.d as unknown[];
    expect(R.length).toBe(KAPPA);
    const Cm = net.mesh(0).sent.find((s) => s.rd === 'ob-C')!.d as { ct: string[][]; com: string[][] };
    expect(Cm.ct.length).toBe(KAPPA);
    expect(Cm.com.length).toBe(KAPPA);
    expect(Buffer.from(Cm.ct[0]![0]!, 'base64').length).toBe(16);
    expect(Buffer.from(Cm.com[0]![0]!, 'base64').length).toBe(32);
    const ins = net.mesh(0).sent.find((s) => s.rd === 'in-share')!.d as string[];
    expect(ins.length).toBe(C);
    const u0 = net.mesh(0).sent.find((s) => s.rd === 'ox1.0.u')!.d as { u: string; x: string; t: string };
    expect(Object.keys(u0).sort()).toEqual(['t', 'u', 'x']);
    const mExt = 128 * 61 + KAPPA + 128;
    expect(Buffer.from(u0.u, 'base64').length).toBe(KAPPA * Math.ceil(mExt / 8));
    const y0 = net.mesh(0).sent.find((s) => s.rd === 'ox1.0.y')!.d as { y0: string; y1: string };
    expect(Buffer.from(y0.y0, 'base64').length).toBe(128 * 61 * 8);
    expect(Buffer.from(y0.y1, 'base64').length).toBe(128 * 61 * 8);
  }, 120_000);

  it('the MPC result through the dealer-free offline phase equals the cleartext composition (and all transcripts agree)', async () => {
    const r = await party(2, vs, 1);
    for (const p of r.out) {
      expect(p.ok, p.error?.message).toBe(true);
      expect(p.result!.composed).toEqual(composeClear(vs, 1));
      expect(p.result!.offlineMode).toBe('no-dealer');
      expect(p.result!.identifiableAbort).toBe(true);
      expect(p.result!.macKeys).toBe(K);
      expect(p.result!.rounds[0]!.rd).toBe('ob-S');
      expect(p.result!.rounds.find((x) => x.rd === 'prep')!.bytesOut).toBeGreaterThan(0);
    }
    expect(r.out[0]!.result!.transcriptDigest).toBe(r.out[1]!.result!.transcriptDigest);
  }, 120_000);
});

describe('three parties (Q = 1)', () => {
  it('compose correctly, the gadget echo round runs, and every party holds consistent shares', async () => {
    const vs = [V(1, 1, 1), V(1, 2, 0), V(0, 3, 1)];
    const r = await party(3, vs, 1);
    for (const p of r.out) {
      expect(p.ok, p.error?.message).toBe(true);
      expect(p.result!.composed).toEqual(composeClear(vs, 1));
      expect(p.result!.multiplications).toBe(2 * chainCount(1));
    }
    expect(r.net.mesh(0).sent.some((s) => s.rd === 'gd-e')).toBe(true);
    const peer = (rd: string) => r.net.mesh(0).sent.filter((s) => s.rd === rd).length;
    expect(peer('ob-S')).toBe(2);
    expect(peer('ox1.0.u')).toBe(2);
  }, 240_000);
});

describe('one party and degenerate inputs', () => {
  it('a single party has no peers: no OT rounds, empty triple set, its own input as the only sharing', async () => {
    const { preps } = await offlineOnly(1, [V(1, 2, 3)], 3);
    const p = preps[0]!;
    expect(p.triples).toEqual([]);
    expect(p.inputs.length).toBe(chainCount(3));
    expect(p.mode).toBe('no-dealer');
    expect(p.myPlain).toEqual([1n, 1n, 1n, 0n, 1n, 1n, 1n]);
    for (const w of p.inputs) {
      expect(w.v.tag).toEqual([0n]);
      expect(w.v.key).toEqual([0n]);
    }
  });
  it('rejects an inconsistent chain count', async () => {
    const net = new MemNet([0], 'sess', 1000);
    const mesh = net.mesh(0) as unknown as never;
    const e = (await runOfflineNet({
      mesh, id: 0, n: 1, C: 6, keys: K, partners: P, sessionId: 'sess', input: V(1, 1, 1), Q: 1,
      exchange: async () => new Map(), crashIf: () => undefined, bad: (p, w) => { throw new Error(`${p}${w}`); }, arr: () => [],
    }).catch((x) => x)) as NetAbort;
    expect([e.kind, e.blamed, e.reporter]).toEqual(['local', null, 0]);
    expect(e.message).toContain('input chain count mismatch');
  });
});

describe('malicious peers in the dealer-free offline phase', { timeout: 300_000 }, () => {
  const vs = [V(1, 1, 1), V(1, 2, 0)];
  const only = (rd: string, f: (d: unknown) => unknown): MemTap => (from, to, r, d) => (from === 1 && to === 0 && r === rd ? f(structuredClone(d)) : d);
  const abortOf = async (tap: MemTap) => {
    const r = await party(2, vs, 1, { tap, recvTimeoutMs: 20_000 });
    return r.out[0]!.error!;
  };
  it('ot-proof-lie: the receiver rejects the Schnorr proof, naming the prover', async () => {
    const r = await party(2, vs, 1, { behaviors: { 1: { kind: 'ot-proof-lie' } } });
    const e = r.out[0]!.error!;
    expect([e.kind, e.blamed, e.reporter]).toEqual(['ot-check', 1, 0]);
    expect(e.message).toContain('base OT (receiver): base OT: sender Schnorr proof-of-knowledge of S=y·B failed');
    expect(r.out[1]!.ok).toBe(false);
  });
  it('ot-u-lie: the KOS check fails and names the cheating extension receiver and the OT layer/chunk', async () => {
    const r = await party(2, vs, 1, { behaviors: { 1: { kind: 'ot-u-lie' } } });
    const e = r.out[0]!.error!;
    expect([e.kind, e.blamed, e.reporter]).toEqual(['ot-check', 1, 0]);
    expect(e.message).toContain('OT extension (ox1.0): KOS correlation check FAILED (round 0)');
  });
  it('offline-lie (2 parties): the sacrifice fails and the audit names the counterpart of each reporter', async () => {
    const r = await party(2, vs, 1, { behaviors: { 1: { kind: 'offline-lie' } } });
    const e0 = r.out[0]!.error!;
    expect([e0.kind, e0.blamed, e0.reporter]).toEqual(['mac-check', 1, 0]);
    expect(e0.message).toContain('triple sacrifice FAILED at triple 0 (partner 0): c != a*b in the offline material; aborting with no output (OT transcript audit names party 1)');
    const e1 = r.out[1]!.error!;
    expect([e1.kind, e1.blamed, e1.reporter]).toEqual(['mac-check', 0, 1]);
    expect(r.net.mesh(0).sent.some((s) => s.rd === 'forensic-c')).toBe(true);
    expect(r.net.mesh(0).sent.some((s) => s.rd === 'forensic-o')).toBe(true);
  }, 120_000);
  it('ob-S: malformed messages are refused naming the sender', async () => {
    const good = async () => {
      const r = await party(2, vs, 1, { tap: only('ob-S', () => 'x'), recvTimeoutMs: 20_000 });
      return r.out[0]!.error!;
    };
    const e = await good();
    expect([e.kind, e.blamed, e.reporter, e.message]).toEqual(['malformed', 1, 0, '[malformed] blamed=1 reporter=0: bad S message']);
    for (const f of [(d: any) => (delete d.U, d), (d: any) => (delete d.S, d), (d: any) => (delete d.z, d), (d: any) => ((d.z = 'zz'), d), (d: any) => ((d.U = { x: '1', y: '1' }), d), (d: any) => ((d.S = null), d)]) {
      const e2 = await abortOf(only('ob-S', f));
      expect([e2.kind, e2.blamed, e2.reporter]).toEqual(['malformed', 1, 0]);
      expect(e2.message).toContain("round 'ob-S': ");
    }
  });
  it('ob-R: a wrong count or an invalid point is malformed', async () => {
    const e1 = await abortOf(only('ob-R', () => 'nope'));
    expect(e1.message).toBe('[malformed] blamed=1 reporter=0: bad R array');
    const e2 = await abortOf(only('ob-R', (d: any) => d.slice(1)));
    expect(e2.message).toBe('[malformed] blamed=1 reporter=0: bad R array');
    const e3 = await abortOf(only('ob-R', (d: any) => ((d[3] = { x: '1', y: '1' }), d)));
    expect(e3.kind).toBe('malformed');
    expect(e3.message).toContain("round 'ob-R': ");
  });
  it('ob-C: a non-object, wrong pair counts or byte lengths are malformed; a corrupted commitment is an ot-check failure', async () => {
    const e1 = await abortOf(only('ob-C', () => null));
    expect(e1.message).toBe('[malformed] blamed=1 reporter=0: bad ciphertext message');
    const cases: Array<[(d: any) => unknown, string]> = [
      [(d) => ((d.ct = d.ct.slice(1)), d), 'bad pair array'],
      [(d) => ((d.com = 'x'), d), 'bad pair array'],
      [(d) => ((d.ct[0] = 'x'), d), 'bad pair'],
      [(d) => ((d.com[5] = [d.com[5][0]]), d), 'bad pair'],
      [(d) => ((d.ct[0][1] = Buffer.alloc(15).toString('base64')), d), 'bad length'],
      [(d) => ((d.com[0][0] = Buffer.alloc(31).toString('base64')), d), 'bad length'],
      [(d) => ((d.ct[0][0] = 5), d), 'bad base64'],
    ];
    for (const [f, why] of cases) {
      const e = await abortOf(only('ob-C', f));
      expect([e.kind, e.blamed]).toEqual(['malformed', 1]);
      expect(e.message).toContain(`round 'ob-C': ${why}`);
    }
    const e3 = await abortOf(only('ob-C', (d: any) => ((d.com[7] = [Buffer.alloc(32, 1).toString('base64'), Buffer.alloc(32, 2).toString('base64')]), d)));
    expect([e3.kind, e3.blamed]).toEqual(['ot-check', 1]);
    expect(e3.message).toContain('base OT (receiver): ');
  });
  it('in-share: a wrong-length or non-canonical share vector is refused', async () => {
    for (const f of [(d: any) => d.slice(1), () => 'x', (d: any) => ((d[0] = '0F'), d)]) {
      const e = await abortOf(only('in-share', f));
      expect([e.kind, e.blamed, e.message]).toEqual(['malformed', 1, `[malformed] blamed=1 reporter=0: expected ${chainCount(1)} canonical field elements`]);
    }
  });
  it('OT extension messages: shape, base64 length, and 128-bit hex fields are checked', async () => {
    const cases: Array<[string, (d: any) => unknown, string]> = [
      ['ox1.0.u', () => 5, 'bad extension message'],
      ['ox1.0.u', (d) => ((d.u = 5), d), 'bad base64'],
      ['ox1.0.u', (d) => ((d.u = d.u.slice(4)), d), 'bad'],
      ['ox1.0.u', (d) => ((d.x = 'G'), d), 'bad 128-bit value'],
      ['ox1.0.u', (d) => ((d.x = '0' + d.x), d), 'bad 128-bit value'],
      ['ox1.0.u', (d) => ((d.t = 'f'.repeat(33)), d), 'bad 128-bit value'],
      ['ox1.0.u', (d) => ((d.t = 7), d), 'bad 128-bit value'],
      ['ox1.0.y', () => null, 'bad ciphertext message'],
      ['ox1.0.y', (d) => ((d.y0 = d.y0.slice(4)), d), 'bad'],
      ['ox1.0.y', (d) => ((d.y1 = 5), d), 'bad base64'],
    ];
    for (const [rd, f, why] of cases) {
      const e = await abortOf(only(rd, f));
      expect([e.kind, e.blamed, e.reporter]).toEqual(['malformed', 1, 0]);
      expect(e.message).toContain(`round '${rd}': `);
      expect(e.message).toContain(why);
    }
  }, 240_000);
  it('a KOS-inconsistent extension message from a peer is an ot-check abort naming it', async () => {
    const e = await abortOf(only('ox1.0.u', (d: any) => ((d.t = hx(1n)), d)));
    expect([e.kind, e.blamed]).toEqual(['ot-check', 1]);
    expect(e.message).toContain('OT extension (ox1.0): ');
  });
});

void hx;


describe('derived constants and local state', () => {
  const vs2 = [V(1, 1, 1), V(1, 2, 0)];
  it('the base-OT channel binding hashes the net-session domain with the session id', async () => {
    seen.sids.length = 0;
    await offlineOnly(2, vs2, 1);
    const want = createHash('sha256').update('atlas-pca-mpc/net-session/v2').update('sess').digest('hex');
    expect(seen.sids.length).toBeGreaterThan(0);
    for (const x of seen.sids) expect(x).toBe(want);
  }, 120_000);
  it('the choice-bit gadget is the documented hash-chain expansion of all contributed seeds in party order', async () => {
    const { net, preps } = await offlineOnly(2, vs2, 1);
    const seeds = [0, 1].map((id) => Buffer.from((net.mesh(id).sent.find((m) => m.rd === 'gd-o')!.d as { v: string }).v, 'hex'));
    const h0 = createHash('sha256').update('atlas-pca-mpc/enc-gadget').update('sess');
    for (const sd of seeds) h0.update(sd);
    const seed = h0.digest();
    let ctr = 0;
    const want = makeGadget(STAT_SEC, () => {
      for (;;) {
        const le = Buffer.alloc(8);
        le.writeBigUInt64LE(BigInt(ctr++));
        const h = createHash('sha256').update(seed).update(le).digest();
        const v = h.readBigUInt64LE(0) & ((1n << 61n) - 1n);
        if (v < PRIME) return v;
      }
    });
    expect(preps[0]!.forensics!.gadget).toEqual(want);
    expect(preps[1]!.forensics!.gadget).toEqual(want);
    expect(new Set(want).size).toBe(want.length);
  }, 120_000);
  it('a zero verification key drawn at random is redrawn', async () => {
    const real = SecureFieldRng.prototype.next;
    let n = 0;
    vi.spyOn(SecureFieldRng.prototype, 'next').mockImplementation(function (this: SecureFieldRng) {
      return n++ === 0 ? 0n : real.call(this);
    });
    try {
      const { preps } = await offlineOnly(1, [V(1, 2, 3)], 3);
      expect(preps[0]!.delta).not.toBe(0n);
    } finally {
      vi.restoreAllMocks();
    }
  });
  it('disclosures copy the choice bits: editing a returned disclosure does not alter later ones', async () => {
    const { preps } = await offlineOnly(2, vs2, 1);
    const f = preps[0]!.forensics!;
    const before = f.disclose(0)[0]!.bits.slice();
    const d1 = f.disclose(0);
    d1[0]!.bits[0] = 1 - d1[0]!.bits[0]!;
    expect(f.disclose(0)[0]!.bits).toEqual(before);
  }, 120_000);
});


describe('OT failures that honest peers cannot cause are still classified (scripted primitives)', () => {
  const vs2 = [V(1, 1, 1), V(1, 2, 0)];
  it('a non-OT error in the base-OT sender step is malformed and labelled', async () => {
    seen.deriveThrow = new Error('scripted derive failure');
    try {
      await expect(offlineOnly(2, vs2, 1)).rejects.toMatchObject({ kind: 'malformed', blamed: 1, reporter: 0, message: '[malformed] blamed=1 reporter=0: base OT (sender): scripted derive failure' });
    } finally {
      seen.deriveThrow = null;
    }
  });
  it('an OT abort in the base-OT sender step is an ot-check', async () => {
    const { BaseOtAbort } = await import('../ot');
    seen.deriveThrow = new BaseOtAbort('scripted ot abort');
    try {
      await expect(offlineOnly(2, vs2, 1)).rejects.toMatchObject({ kind: 'ot-check', blamed: 1, reporter: 0 });
    } finally {
      seen.deriveThrow = null;
    }
  });
  it('a NetAbort raised inside a guarded step passes through unchanged', async () => {
    const inner = new NetAbort('local', null, 0, 'scripted inner abort');
    seen.deriveThrow = inner;
    try {
      await expect(offlineOnly(2, vs2, 1)).rejects.toBe(inner);
    } finally {
      seen.deriveThrow = null;
    }
  });
  it('a failure while finishing an OT extension is labelled with the extension round', async () => {
    const spy = vi.spyOn(OtExtReceiver.prototype, 'finish').mockImplementation(() => {
      throw new Error('scripted finish failure');
    });
    try {
      await expect(offlineOnly(2, vs2, 1)).rejects.toMatchObject({ kind: 'malformed', blamed: 1, reporter: 0, message: '[malformed] blamed=1 reporter=0: OT extension (ox1.0): scripted finish failure' });
    } finally {
      spy.mockRestore();
    }
  }, 120_000);
});
