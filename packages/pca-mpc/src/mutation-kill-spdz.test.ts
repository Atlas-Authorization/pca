/**
 * Mutation-kill suite for spdz.ts: argument validation and its reasons, the authenticated linear ops (no
 * aliasing of inputs, party-count / key-count agreement), the public-constant rule, deviation targeting,
 * the sacrifice (partner sharing b, the non-zero challenge), the MAC-check's randomness consumption and the
 * exact residual core.
 */
import { describe, expect, it } from 'vitest';
import { fadd, FieldRng, fmul, PRIME } from './field';
import {
  addAuth,
  addPublicAuth,
  authConstant,
  authShare,
  authValue,
  beaverMulAuth,
  genAuthTriple,
  genTripleWithPartners,
  MacCheckAbort,
  macResiduals,
  negAuth,
  notBitAuth,
  sacrificeVerify,
  scaleAuth,
  setupMac,
  SpdzEngine,
  subAuth,
  type AuthSV,
  type MacContext,
} from './spdz';

const sum = (xs: readonly bigint[]): bigint => xs.reduce((a, b) => fadd(a, b), 0n);
const errOf = (f: () => unknown): Error => {
  try {
    f();
  } catch (e) {
    return e as Error;
  }
  throw new Error('did not throw');
};
const macOk = (x: AuthSV, ctx: MacContext): boolean =>
  sum(x.mac) === fmul(ctx.alpha, authValue(x)) && x.extraMac.every((r, l) => sum(r) === fmul(ctx.extraKeys[l]!.alpha, authValue(x)));
const clone = (x: AuthSV): AuthSV => JSON.parse(JSON.stringify(x, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v)), (_k, v) =>
  typeof v === 'string' && /^\d+n$/.test(v) ? BigInt(v.slice(0, -1)) : v);
/** A scripted RNG: returns the given values first, then a seeded stream; counts draws. */
class Scripted extends FieldRng {
  draws = 0;
  constructor(private readonly head: bigint[], seed = 77n) {
    super(seed);
  }
  override next(): bigint {
    this.draws++;
    return this.head.length ? this.head.shift()! : super.next();
  }
}

describe('MacCheckAbort and setupMac', () => {
  it('MacCheckAbort is a named Error', () => {
    const e = new MacCheckAbort('m');
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe('MacCheckAbort');
    expect(e.message).toBe('m');
  });
  it('setupMac validates n and keys with exact reasons', () => {
    const r = new FieldRng(1n);
    for (const n of [0, -2, 1.5]) expect(errOf(() => setupMac(n, r)).message).toBe('setupMac: n must be a positive integer');
    for (const k of [0, 17, 2.5]) expect(errOf(() => setupMac(2, r, k)).message).toBe('setupMac: keys must be an integer in [1, 16]');
    expect(setupMac(1, r).alphaShares).toHaveLength(1);
    expect(setupMac(2, r, 16).extraKeys).toHaveLength(15);
    expect(setupMac(2, r, 1).extraKeys).toHaveLength(0);
  });
});

describe('authConstant and the public-constant rule', () => {
  const ctx = setupMac(3, new FieldRng(2n));
  it('authConstant puts c in party 0 and MACs alpha_i * c under every key', () => {
    const c = authConstant(PRIME + 9n, ctx);
    expect(c.value).toEqual([9n, 0n, 0n]);
    expect(c.mac).toEqual(ctx.alphaShares.map((a) => fmul(a, 9n)));
    expect(c.extraMac).toEqual([ctx.extraKeys[0]!.alphaShares.map((a) => fmul(a, 9n))]);
    expect(macOk(c, ctx)).toBe(true);
  });
  it('addPublicAuth adds c to party 0 only, keeps MACs valid and never mutates its input', () => {
    const r = new FieldRng(3n);
    const x = authShare(5n, ctx, r);
    const before = clone(x);
    const y = addPublicAuth(x, 4n, ctx);
    expect(x).toEqual(before);
    expect(authValue(y)).toBe(9n);
    expect(y.value[1]).toBe(x.value[1]);
    expect(y.value[0]).toBe(fadd(x.value[0]!, 4n));
    expect(macOk(y, ctx)).toBe(true);
    expect(authValue(notBitAuth(authShare(1n, ctx, r), ctx))).toBe(0n);
    expect(authValue(notBitAuth(authShare(0n, ctx, r), ctx))).toBe(1n);
  });
  it('addPublicAuth refuses party-count and key-count disagreement, each on its own', () => {
    const r = new FieldRng(4n);
    const x = authShare(5n, ctx, r);
    const party = 'addPublicAuth: shared value and MAC context disagree on the party count';
    expect(errOf(() => addPublicAuth({ ...x, value: x.value.slice(0, 2) }, 1n, ctx)).message).toBe(party);
    expect(errOf(() => addPublicAuth({ ...x, mac: x.mac.slice(0, 2) }, 1n, ctx)).message).toBe(party);
    expect(errOf(() => addPublicAuth(x, 1n, { ...ctx, alphaShares: ctx.alphaShares.slice(0, 2) })).message).toBe(party);
    expect(errOf(() => addPublicAuth({ ...x, extraMac: [] }, 1n, ctx)).message).toBe('addPublicAuth: shared value and MAC context disagree on the key count');
    const extra = 'addPublicAuth: extra MAC party count mismatch';
    expect(errOf(() => addPublicAuth({ ...x, extraMac: [x.extraMac[0]!.slice(0, 2)] }, 1n, ctx)).message).toBe(extra);
    const k = ctx.extraKeys[0]!;
    expect(errOf(() => addPublicAuth(x, 1n, { ...ctx, extraKeys: [{ ...k, alphaShares: k.alphaShares.slice(0, 2) }] })).message).toBe(extra);
  });
});

describe('linear ops and the shape check', () => {
  const ctx = setupMac(2, new FieldRng(5n));
  const r = new FieldRng(6n);
  const x = authShare(10n, ctx, r);
  const y = authShare(3n, ctx, r);
  it('add, sub, neg and scale are exact and MAC-valid', () => {
    expect(authValue(addAuth(x, y))).toBe(13n);
    expect(authValue(subAuth(x, y))).toBe(7n);
    expect(authValue(negAuth(x))).toBe(PRIME - 10n);
    expect(authValue(scaleAuth(x, -2n))).toBe(PRIME - 20n);
    for (const z of [addAuth(x, y), subAuth(x, y), negAuth(x), scaleAuth(x, 7n)]) expect(macOk(z, ctx)).toBe(true);
  });
  it('mismatched shapes are refused by add, sub and Beaver multiplication', () => {
    const party = 'authenticated shared values must have the same party count';
    const keys = 'authenticated shared values must carry the same number of MAC keys';
    const short = { ...y, value: y.value.slice(0, 1) };
    const shortMac = { ...y, mac: y.mac.slice(0, 1) };
    const noKeys = { ...y, extraMac: [] };
    const shortExtra = { ...y, extraMac: [y.extraMac[0]!.slice(0, 1)] };
    for (const f of [addAuth, subAuth]) {
      expect(errOf(() => f(x, short)).message).toBe(party);
      expect(errOf(() => f(x, shortMac)).message).toBe(party);
      expect(errOf(() => f(x, noKeys)).message).toBe(keys);
      expect(errOf(() => f(x, shortExtra)).message).toBe(party);
    }
    const t = genAuthTriple(ctx, r);
    const eng = new SpdzEngine(ctx);
    expect(errOf(() => beaverMulAuth(x, short, t, ctx, eng)).message).toBe(party);
    expect(errOf(() => beaverMulAuth(x, y, { ...t, a: short }, ctx, eng)).message).toBe(party);
    expect(errOf(() => beaverMulAuth(x, y, { ...t, b: noKeys }, ctx, eng)).message).toBe(keys);
    expect(errOf(() => beaverMulAuth(x, y, { ...t, c: shortExtra }, ctx, eng)).message).toBe(party);
    expect(eng.openCount).toBe(0); // refused before any opening
  });
  it('beaverMulAuth multiplies and stays MAC-valid', () => {
    const eng = new SpdzEngine(ctx);
    const z = beaverMulAuth(x, y, genAuthTriple(ctx, r), ctx, eng, 'm');
    expect(authValue(z)).toBe(30n);
    expect(macOk(z, ctx)).toBe(true);
    expect(eng.openCount).toBe(2);
    expect(() => eng.macCheck(r)).not.toThrow();
  });
});

describe('genTripleWithPartners and the sacrifice', () => {
  const ctx = setupMac(2, new FieldRng(7n));
  it('partners must be an integer in [1, 8]', () => {
    const r = new FieldRng(8n);
    for (const p of [0, 9, 1.5]) expect(errOf(() => genTripleWithPartners(ctx, r, p)).message).toBe('genTripleWithPartners: partners must be in [1, 8]');
    expect(genTripleWithPartners(ctx, r, 8).partners).toHaveLength(8);
    expect(genTripleWithPartners(ctx, r, 1).partners).toHaveLength(1);
  });
  it('a partner must share b exactly: one differing share, or a different length, is refused with its reason', () => {
    const r = new FieldRng(9n);
    const t = genTripleWithPartners(ctx, r, 1);
    const p = t.partners[0]!;
    const oneOff = { ...p, b: { ...p.b, value: [p.b.value[0]!, fadd(p.b.value[1]!, 1n)] } };
    const e = errOf(() => sacrificeVerify([{ keep: t.keep, partners: [oneOff] }], ctx, r));
    expect(e).toBeInstanceOf(MacCheckAbort);
    expect(e.message).toBe('sacrifice: partner does not share b with the triple');
    const longer = { ...p, b: { ...p.b, value: [...p.b.value, 0n] } };
    expect(errOf(() => sacrificeVerify([{ keep: t.keep, partners: [longer] }], ctx, r)).message).toBe('sacrifice: partner does not share b with the triple');
    // a SHORTER b whose shares all match the kept b's prefix: only the length test refuses it
    const shorter = { ...p, b: { ...p.b, value: p.b.value.slice(0, 1) } };
    expect(errOf(() => sacrificeVerify([{ keep: t.keep, partners: [shorter] }], ctx, r)).message).toBe('sacrifice: partner does not share b with the triple');
    const e2 = errOf(() => sacrificeVerify([{ keep: t.keep, partners: [] }], ctx, r));
    expect(e2).toBeInstanceOf(MacCheckAbort);
    expect(e2.message).toBe('sacrifice: a triple without partners cannot be certified');
  });
  it('a lie repeated identically in the partner is caught because the challenge is random, not fixed', () => {
    // c = ab + 5 and c^ = a^b + 5: with e = 1 the residual would be 5 - 5 = 0.
    for (let s = 0n; s < 4n; s++) {
      const r = new FieldRng(100n + s);
      const t = genTripleWithPartners(ctx, r, 1, { keepCDelta: 5n, partnerCDelta: [5n] });
      expect(() => sacrificeVerify([t], ctx, r)).toThrow(/sacrifice FAILED/);
    }
  });
  it('a drawn challenge of 0 is replaced by 1 (so a bad kept triple cannot hide behind e = 0)', () => {
    const r = new FieldRng(11n);
    const t = genTripleWithPartners(ctx, r, 1, { keepCDelta: 3n });
    expect(() => sacrificeVerify([t], ctx, new Scripted([0n]))).toThrow(/sacrifice FAILED/);
    const good = genTripleWithPartners(ctx, r, 1);
    expect(sacrificeVerify([good], ctx, new Scripted([0n]))).toEqual([good.keep]);
  });
});

describe('SpdzEngine.open and deviations', () => {
  const ctx = setupMac(2, new FieldRng(12n));
  it('the default context gives >= 100 bits; a 1-key context is refused', () => {
    expect(() => new SpdzEngine(ctx)).not.toThrow();
    expect(() => new SpdzEngine(setupMac(2, new FieldRng(1n), 1))).toThrow(/bits of statistical soundness/);
  });
  it('a deviation only touches its own open index, and never mutates the caller\'s sharing', () => {
    const r = new FieldRng(13n);
    const x = authShare(6n, ctx, r);
    const before = clone(x);
    const eng = new SpdzEngine(ctx, [{ openIndex: 1, party: 1, valueDelta: 2n, macDelta: 3n }, { openIndex: 2, party: 0, macDelta: 1n, macKey: 1 }]);
    expect(eng.open(x)).toBe(6n);
    expect(eng.open(x)).toBe(8n);
    expect(eng.open(x)).toBe(6n);
    expect(x).toEqual(before);
    expect(eng.openCount).toBe(3);
  });
  it('a key-count mismatch and out-of-range deviations are refused with exact reasons', () => {
    const r = new FieldRng(14n);
    const x = authShare(6n, ctx, r);
    expect(errOf(() => new SpdzEngine(ctx).open({ ...x, extraMac: [] })).message).toBe('open: value and MAC context disagree on the key count');
    for (const party of [-1, 2]) {
      expect(errOf(() => new SpdzEngine(ctx, [{ openIndex: 0, party, valueDelta: 1n }]).open(x)).message).toBe('Deviation.party out of range');
    }
    expect(new SpdzEngine(ctx, [{ openIndex: 0, party: 1, valueDelta: 1n }]).open(x)).toBe(7n);
    for (const macKey of [-1, 2]) {
      expect(errOf(() => new SpdzEngine(ctx, [{ openIndex: 0, party: 0, macDelta: 1n, macKey }]).open(x)).message).toBe('Deviation.macKey out of range');
    }
    expect(() => new SpdzEngine(ctx, [{ openIndex: 0, party: 0, macDelta: 1n, macKey: 1 }]).open(x)).not.toThrow();
  });
  it('a forged extra-key MAC share is caught by the MAC-check', () => {
    const r = new FieldRng(15n);
    const eng = new SpdzEngine(ctx, [{ openIndex: 0, party: 0, macDelta: 1n, macKey: 1 }]);
    eng.open(authShare(6n, ctx, r));
    expect(() => eng.macCheck(r)).toThrow(/MAC-check FAILED \(key 1\)/);
  });
});

describe('macCheck randomness and the residual core', () => {
  it('no opens: a no-op that draws no randomness', () => {
    const ctx = setupMac(2, new FieldRng(16n));
    const rng = new Scripted([]);
    new SpdzEngine(ctx).macCheck(rng);
    expect(rng.draws).toBe(0);
  });
  it('draws one challenge per key per open and one commitment nonce per key per party', () => {
    for (const [n, keys, opens] of [[2, 2, 1], [3, 3, 2]] as const) {
      const ctx = setupMac(n, new FieldRng(17n), keys);
      const r = new FieldRng(18n);
      const eng = new SpdzEngine(ctx);
      for (let j = 0; j < opens; j++) eng.open(authShare(BigInt(j), ctx, r));
      const rng = new Scripted([]);
      eng.macCheck(rng);
      expect(rng.draws).toBe(keys * opens + keys * n);
    }
  });
  it('macResiduals returns canonical residues in [0, p), exactly', () => {
    const p = 101n;
    // one key, two parties, one opening of value 3 with MAC shares (10, 20); alpha shares (2, 5); challenge 7
    const s = macResiduals(p, [[2n, 5n]], [{ value: 3n, macShares: [[10n, 20n]] }], [[7n]]);
    // a = 21; sigma_0 = 70 - 42 = 28; sigma_1 = 140 - 105 = 35 (mod 101)
    expect(s).toEqual([[28n, 35n]]);
    const neg = macResiduals(p, [[50n, 0n]], [{ value: 1n, macShares: [[0n, 0n]] }], [[1n]]);
    expect(neg).toEqual([[51n, 0n]]); // -50 mod 101
  });
});
