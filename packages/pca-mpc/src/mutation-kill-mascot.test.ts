/**
 * Mutation-kill suite for mascot.ts (the no-dealer offline phase): constructor bounds and reasons, the
 * distributed MAC context, OT share multiplication, triple generation with and without the sacrifice, the
 * test-only product deviation (index counting), attribution on abort, authenticated inputs and the
 * input-consistency check. Kept small (n = 2, mostly the legacy 61-bit choice encoding) so it is fast.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SecureFieldRng } from './csprng';
import { STAT_SEC, sampleEnc } from './enc';
import { fadd, FieldRng, fmul, mod, PRIME } from './field';
import { makeNoDealerOffline, NoDealerOffline, OfflineCheatingAbort } from './mascot';
import { OtChannel } from './ot';
import { MacCheckAbort, type AuthSV, type MacContext } from './spdz';

afterEach(() => vi.restoreAllMocks());

const sum = (xs: readonly bigint[]): bigint => xs.reduce((a, b) => fadd(a, b), 0n);
const FAST = { statSec: 0, unsafeStatSec: true } as const;
const errOf = (f: () => unknown): Error => {
  try {
    f();
  } catch (e) {
    return e as Error;
  }
  throw new Error('did not throw');
};
/** Every MAC of x (all keys) is α_l · value. */
function macOk(x: AuthSV, ctx: MacContext): boolean {
  const v = sum(x.value);
  if (sum(x.mac) !== fmul(ctx.alpha, v)) return false;
  if (x.extraMac.length !== ctx.extraKeys.length) return false;
  return x.extraMac.every((row, l) => sum(row) === fmul(ctx.extraKeys[l]!.alpha, v));
}

describe('OfflineCheatingAbort', () => {
  it('is a named MacCheckAbort carrying the blamed parties', () => {
    const a = new OfflineCheatingAbort('sacrifice failed', [0, 2]);
    expect(a).toBeInstanceOf(MacCheckAbort);
    expect(a.name).toBe('OfflineCheatingAbort');
    expect(a.blamed).toEqual([0, 2]);
    expect(a.message).toBe('sacrifice failed; offline OT transcript names party 0, 2');
    const b = new OfflineCheatingAbort('x', []);
    expect(b.message).toBe('x');
    expect(b.blamed).toEqual([]);
  });
});

describe('constructor', () => {
  it('rejects a bad party count', () => {
    for (const n of [0, -1, 1.5, Number.NaN]) {
      expect(errOf(() => new NoDealerOffline(n, 1n)).message).toBe('NoDealerOffline: n must be a positive integer');
    }
    expect(new NoDealerOffline(1, 1n).n).toBe(1);
  });
  it('macKeys must be an integer in [1, 16]', () => {
    for (const k of [0, 17, 1.5]) {
      expect(errOf(() => new NoDealerOffline(2, 1n, { ...FAST, macKeys: k })).message).toBe('NoDealerOffline: macKeys must be an integer in [1, 16]');
    }
    expect(new NoDealerOffline(2, 1n, { ...FAST, macKeys: 1 }).macContext.extraKeys).toHaveLength(0);
    expect(new NoDealerOffline(2, 1n, { ...FAST, macKeys: 16 }).macContext.extraKeys).toHaveLength(15);
    expect(new NoDealerOffline(2, 1n, FAST).macContext.extraKeys).toHaveLength(1);
  });
  it('sacrificePartners must be an integer in [1, 8]', () => {
    for (const p of [0, 9, 1.5]) {
      expect(errOf(() => new NoDealerOffline(2, 1n, { ...FAST, sacrificePartners: p })).message).toBe('NoDealerOffline: sacrificePartners must be an integer in [1, 8]');
    }
    expect(() => new NoDealerOffline(2, 1n, { ...FAST, sacrificePartners: 1 })).not.toThrow();
    expect(() => new NoDealerOffline(2, 1n, { ...FAST, sacrificePartners: 8 })).not.toThrow();
  });
  it('statSec defaults to STAT_SEC; below 40 needs the explicit unsafe flag', () => {
    expect(new NoDealerOffline(2, 1n).statSec).toBe(STAT_SEC);
    expect(new NoDealerOffline(2, 1n, { statSec: 40 }).statSec).toBe(40);
    expect(() => new NoDealerOffline(2, 1n, { statSec: 39 })).toThrow(/below 40/);
    expect(() => new NoDealerOffline(2, 1n, { statSec: 39, unsafeStatSec: false })).toThrow(/below 40/);
    expect(new NoDealerOffline(2, 1n, { statSec: 0, unsafeStatSec: true }).statSec).toBe(0);
  });
  it('makeNoDealerOffline forwards n, seed and options', () => {
    const a = makeNoDealerOffline(3, 7n, { ...FAST, macKeys: 3 });
    expect(a).toBeInstanceOf(NoDealerOffline);
    expect(a.n).toBe(3);
    expect(a.macContext.extraKeys).toHaveLength(2);
    expect(a.macContext).toEqual(new NoDealerOffline(3, 7n, { ...FAST, macKeys: 3 }).macContext);
  });
});

describe('randomness source', () => {
  it('a seed selects the deterministic stream (reproducible, seed-dependent)', () => {
    const secure = vi.spyOn(SecureFieldRng.prototype, 'next');
    const a = new NoDealerOffline(2, 5n, FAST);
    const b = new NoDealerOffline(2, 5n, FAST);
    const c = new NoDealerOffline(2, 6n, FAST);
    expect(a.macContext).toEqual(b.macContext);
    expect(a.macContext.alpha).not.toBe(c.macContext.alpha);
    expect(a.genAuthTriple()).toEqual(b.genAuthTriple());
    expect(secure).not.toHaveBeenCalled();
  });
  it('no seed draws from the CSPRNG', () => {
    const secure = vi.spyOn(SecureFieldRng.prototype, 'next');
    const a = new NoDealerOffline(2, undefined, FAST);
    expect(secure).toHaveBeenCalled();
    const t = a.genAuthTriple();
    expect(sum(t.c.value)).toBe(fmul(sum(t.a.value), sum(t.b.value)));
  });
  it('seed 0 is still a deterministic seed', () => {
    const secure = vi.spyOn(SecureFieldRng.prototype, 'next');
    const a = new NoDealerOffline(2, 0n, FAST);
    expect(a.macContext).toEqual(new NoDealerOffline(2, 0n, FAST).macContext);
    expect(secure).not.toHaveBeenCalled();
  });
});

describe('distributed MAC context', () => {
  it('alpha is the sum of the shares, per key; extra keys are independent; the context is a copy', () => {
    const o = new NoDealerOffline(3, 11n, { ...FAST, macKeys: 3 });
    const ctx = o.macContext;
    expect(ctx.n).toBe(3);
    expect(ctx.alphaShares).toHaveLength(3);
    expect(ctx.alphaShares).toEqual(o.alphaShares);
    expect(ctx.alpha).toBe(sum(o.alphaShares));
    for (const k of ctx.extraKeys) {
      expect(k.alphaShares).toHaveLength(3);
      expect(k.alpha).toBe(sum(k.alphaShares));
      expect(k.alpha).not.toBe(ctx.alpha);
    }
    expect(ctx.extraKeys[0]!.alpha).not.toBe(ctx.extraKeys[1]!.alpha);
    ctx.alphaShares[0] = 0n;
    expect(o.macContext.alphaShares[0]).toBe(o.alphaShares[0]);
    expect(o.alphaShares[0]).not.toBe(0n);
  });
});

describe('otShareMultiply', () => {
  it('sum z = (sum x)(sum y) for bigint and encoded operands, n = 2 and 3', () => {
    for (const n of [2, 3]) {
      const o = new NoDealerOffline(n, 21n + BigInt(n), FAST);
      const r = new FieldRng(99n);
      const x = Array.from({ length: n }, () => r.next());
      const y = Array.from({ length: n }, () => r.next());
      expect(sum(o.otShareMultiply(x, y))).toBe(fmul(sum(x), sum(y)));
      const xe = Array.from({ length: n }, () => sampleEnc(Array.from({ length: 61 }, (_, k) => (1n << BigInt(k)) % PRIME), r));
      expect(sum(o.otShareMultiply(xe, y))).toBe(fmul(sum(xe.map((e) => e.value)), sum(y)));
    }
  });
  it('reduces unreduced and negative bigint operands', () => {
    const o = new NoDealerOffline(2, 3n, FAST);
    const x = [PRIME + 5n, -3n];
    const y = [7n, PRIME - 1n];
    expect(sum(o.otShareMultiply(x, y))).toBe(fmul(mod(2n), mod(6n)));
    expect(sum(o.otShareMultiply([5n, 0n], [-1n, 0n]))).toBe(mod(-5n));
  });
  it('a cross term only: party 0 holds x, party 1 holds y', () => {
    const o = new NoDealerOffline(2, 4n, FAST);
    const z = o.otShareMultiply([6n, 0n], [0n, 9n]);
    expect(sum(z)).toBe(54n);
    expect(z[0]).not.toBe(54n);
  });
  it('one party: purely local', () => {
    const o = new NoDealerOffline(1, 4n, FAST);
    expect(o.otShareMultiply([6n], [9n])).toEqual([54n]);
  });
  it('length mismatches are refused', () => {
    const o = new NoDealerOffline(2, 4n, FAST);
    expect(errOf(() => o.otShareMultiply([1n], [1n, 2n])).message).toBe('otShareMultiply: wrong length');
    expect(errOf(() => o.otShareMultiply([1n, 2n], [1n])).message).toBe('otShareMultiply: wrong length');
  });
});

describe('triples', () => {
  it('honest triples: c = a*b and every component MAC-valid under every key (n = 2, 3; default encoding too)', () => {
    for (const [n, opts] of [[2, FAST], [3, FAST], [2, {}]] as const) {
      const o = new NoDealerOffline(n, 31n, { ...opts, macKeys: 3 });
      const ctx = o.macContext;
      const t = o.genAuthTriple();
      expect(sum(t.c.value)).toBe(fmul(sum(t.a.value), sum(t.b.value)));
      for (const s of [t.a, t.b, t.c]) {
        expect(s.value).toHaveLength(n);
        expect(s.extraMac).toHaveLength(2);
        expect(macOk(s, ctx)).toBe(true);
      }
    }
  });
  it('without the sacrifice a triple is still correct and MAC-valid', () => {
    const o = new NoDealerOffline(2, 32n, { ...FAST, sacrifice: false });
    const t = o.genAuthTriple();
    expect(sum(t.c.value)).toBe(fmul(sum(t.a.value), sum(t.b.value)));
    for (const s of [t.a, t.b, t.c]) expect(macOk(s, o.macContext)).toBe(true);
  });
  it('genAuthTriples returns count fresh triples', () => {
    const o = new NoDealerOffline(2, 33n, { ...FAST, sacrifice: false });
    expect(o.genAuthTriples(0)).toEqual([]);
    const ts = o.genAuthTriples(3);
    expect(ts).toHaveLength(3);
    expect(sum(ts[0]!.a.value)).not.toBe(sum(ts[1]!.a.value));
    for (const t of ts) expect(sum(t.c.value)).toBe(fmul(sum(t.a.value), sum(t.b.value)));
  });
});

describe('product deviation (test hook) and the sacrifice', () => {
  it('without the sacrifice the corrupted product slips through, MAC-consistently (c = a*b + delta)', () => {
    const o = new NoDealerOffline(2, 41n, { ...FAST, sacrifice: false, deviation: { productMul: 0, delta: 5n } });
    const t = o.genAuthTriple();
    expect(sum(t.c.value)).toBe(fadd(fmul(sum(t.a.value), sum(t.b.value)), 5n));
    expect(macOk(t.c, o.macContext)).toBe(true);
    expect(t.c.value[1]).not.toBe(undefined);
  });
  it('the index counts products across triples (no sacrifice: one product per triple)', () => {
    const o = new NoDealerOffline(2, 42n, { ...FAST, sacrifice: false, deviation: { productMul: 1, delta: 1n } });
    const [t0, t1, t2] = o.genAuthTriples(3);
    expect(sum(t0!.c.value)).toBe(fmul(sum(t0!.a.value), sum(t0!.b.value)));
    expect(sum(t1!.c.value)).toBe(fadd(fmul(sum(t1!.a.value), sum(t1!.b.value)), 1n));
    expect(sum(t2!.c.value)).toBe(fmul(sum(t2!.a.value), sum(t2!.b.value)));
  });
  it('with the sacrifice a corrupted kept product aborts and names party 0', () => {
    const o = new NoDealerOffline(2, 43n, { ...FAST, deviation: { productMul: 0, delta: 3n } });
    const e = errOf(() => o.genAuthTriple());
    expect(e).toBeInstanceOf(OfflineCheatingAbort);
    expect((e as OfflineCheatingAbort).blamed).toEqual([0]);
    expect(e.message).toMatch(/sacrifice FAILED/);
    expect(e.message).toMatch(/; offline OT transcript names party 0$/);
  });
  it('the sacrifice counts the kept product and then one per partner (partners = 2 by default)', () => {
    // productMul 2 = the second partner of the first triple: caught.
    const o2 = new NoDealerOffline(2, 44n, { ...FAST, deviation: { productMul: 2, delta: 3n } });
    expect(() => o2.genAuthTriple()).toThrow(OfflineCheatingAbort);
    // with a single partner, productMul 2 is the KEPT product of the second triple.
    const o1 = new NoDealerOffline(2, 44n, { ...FAST, sacrificePartners: 1, deviation: { productMul: 2, delta: 3n } });
    expect(() => o1.genAuthTriple()).not.toThrow();
    expect(() => o1.genAuthTriple()).toThrow(OfflineCheatingAbort);
    // a corrupted partner (productMul 1) is caught too
    const op = new NoDealerOffline(2, 45n, { ...FAST, sacrificePartners: 1, deviation: { productMul: 1, delta: 9n } });
    const e = errOf(() => op.genAuthTriple());
    expect((e as OfflineCheatingAbort).blamed).toEqual([0]);
  });
  it('after an abort the recorder is reset: the next triple is fine and a later abort blames afresh', () => {
    const o = new NoDealerOffline(2, 46n, { ...FAST, sacrificePartners: 1, deviation: { productMul: 0, delta: 3n } });
    expect(() => o.genAuthTriple()).toThrow(OfflineCheatingAbort);
    const t = o.genAuthTriple();
    expect(sum(t.c.value)).toBe(fmul(sum(t.a.value), sum(t.b.value)));
  });
  it('a non-MacCheckAbort error is rethrown unchanged (not attributed)', () => {
    const o = new NoDealerOffline(2, 47n, FAST);
    const boom = new Error('boom');
    vi.spyOn(FieldRng.prototype, 'next').mockImplementation(() => {
      throw boom;
    });
    const e = errOf(() => o.genAuthTriple());
    expect(e).toBe(boom);
    vi.restoreAllMocks();
    // and the recorder was reset, so an honest triple follows
    const t = o.genAuthTriple();
    expect(sum(t.c.value)).toBe(fmul(sum(t.a.value), sum(t.b.value)));
  });
});

describe('authenticated inputs and the input-consistency check', () => {
  it('authInput: value shares sum to the reduced value, MACs valid under every key; owner range', () => {
    const o = new NoDealerOffline(3, 51n, { ...FAST, macKeys: 2 });
    const x = o.authInput(PRIME + 4n, 2);
    expect(x.value).toHaveLength(3);
    expect(sum(x.value)).toBe(4n);
    expect(macOk(x, o.macContext)).toBe(true);
    expect(sum(o.authInput(-1n, 0).value)).toBe(PRIME - 1n);
    expect(errOf(() => o.authInput(1n, -1)).message).toBe('authInput: owner out of range');
    expect(errOf(() => o.authInput(1n, 3)).message).toBe('authInput: owner out of range');
  });
  it('honest inputs pass; an empty batch is a no-op', () => {
    const o = new NoDealerOffline(2, 52n, FAST);
    const xs = [o.authInput(1n, 0), o.authInput(0n, 1), o.authInput(7n, 0)];
    expect(() => o.checkInputConsistency(xs)).not.toThrow();
    expect(() => o.checkInputConsistency([])).not.toThrow();
  });
  it('an input whose key-0 MAC or extra-key MAC is off by one aborts, wherever it sits in the batch', () => {
    const o = new NoDealerOffline(2, 53n, FAST);
    for (const pos of [0, 1, 2]) {
      const xs = [o.authInput(1n, 0), o.authInput(2n, 1), o.authInput(3n, 0)];
      const bad = xs[pos]!;
      xs[pos] = { ...bad, mac: [fadd(bad.mac[0]!, 1n), bad.mac[1]!] };
      expect(() => o.checkInputConsistency(xs)).toThrow(MacCheckAbort);
      const ys = [o.authInput(1n, 0), o.authInput(2n, 1), o.authInput(3n, 0)];
      const b2 = ys[pos]!;
      ys[pos] = { ...b2, extraMac: [[b2.extraMac[0]![0]!, fadd(b2.extraMac[0]![1]!, 1n)]] };
      expect(() => o.checkInputConsistency(ys)).toThrow(MacCheckAbort);
    }
  });
  it('a value share inconsistent with its MAC aborts', () => {
    const o = new NoDealerOffline(2, 54n, FAST);
    const x = o.authInput(5n, 0);
    expect(() => o.checkInputConsistency([{ ...x, value: [fadd(x.value[0]!, 1n), x.value[1]!] }])).toThrow(MacCheckAbort);
  });
  it('a party-count mismatch (value or MAC) is refused before any OT', () => {
    const o = new NoDealerOffline(2, 55n, FAST);
    const x = o.authInput(5n, 0);
    expect(errOf(() => o.checkInputConsistency([{ ...x, value: [1n] }])).message).toBe('checkInputConsistency: input party count mismatch');
    expect(errOf(() => o.checkInputConsistency([x, { ...x, mac: [1n, 2n, 3n] }])).message).toBe('checkInputConsistency: input party count mismatch');
  });
});

describe('attribution from the OT transcript', () => {
  /** Make the FIRST OT extension of the next triple hand the receiver a value its sender never offered. */
  function tamperFirstExtend(): void {
    const orig = OtChannel.prototype.extend;
    let done = false;
    vi.spyOn(OtChannel.prototype, 'extend').mockImplementation(function (this: OtChannel, bits, m0, m1) {
      const out = orig.call(this, bits, m0, m1);
      if (done) return out;
      done = true;
      const received = out.received.slice();
      received[0] = fadd(received[0]!, 1n);
      return { ...out, received };
    });
  }
  it('a receiver output outside the offered pair blames that pair\'s sender', () => {
    const o = new NoDealerOffline(2, 61n, { ...FAST, sacrificePartners: 1 });
    tamperFirstExtend();
    const e = errOf(() => o.genAuthTriple());
    expect(e).toBeInstanceOf(OfflineCheatingAbort);
    // the first extension is receiver 0 <- sender 1
    expect((e as OfflineCheatingAbort).blamed).toEqual([1]);
  });
  it('blame from the transcript and from a wrong product claim is merged and sorted', () => {
    const o = new NoDealerOffline(2, 62n, { ...FAST, sacrificePartners: 1, deviation: { productMul: 0, delta: 2n } });
    tamperFirstExtend();
    const e = errOf(() => o.genAuthTriple()) as OfflineCheatingAbort;
    expect(e.blamed).toEqual([0, 1]);
    expect(e.message).toMatch(/names party 0, 1$/);
  });
});

describe('input check details', () => {
  it('an empty batch runs no OT and draws no randomness', () => {
    const o = new NoDealerOffline(2, 63n, FAST);
    o.authInput(1n, 0); // make sure the channels exist already
    const ext = vi.spyOn(OtChannel.prototype, 'extend');
    const next = vi.spyOn(FieldRng.prototype, 'next');
    o.checkInputConsistency([]);
    expect(ext).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });
  it('MAC errors that cancel under equal weights are still caught (the weights are random)', () => {
    for (const seed of [64n, 65n, 66n]) {
      const o = new NoDealerOffline(2, seed, FAST);
      const a = o.authInput(1n, 0);
      const b = o.authInput(2n, 1);
      const a2 = { ...a, mac: [fadd(a.mac[0]!, 1n), a.mac[1]!] };
      const b2 = { ...b, mac: [fadd(b.mac[0]!, PRIME - 1n), b.mac[1]!] };
      expect(() => o.checkInputConsistency([a2, b2])).toThrow(MacCheckAbort);
    }
  });
});
