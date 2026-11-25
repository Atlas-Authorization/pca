import { describe, expect, it } from 'vitest';
import { mintRoot, delegate, type Caveat } from './capability';
import { encodeKey, publicKeyOf } from './keys';
import { MeshDomain, MeshWitness, buildMeshExample, checkCosignedHead, translateCapability, verifyMeshProof, verifyTranslatedCapability } from './mesh';

const BAD = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY];
const pub = (s: Uint8Array) => encodeKey(publicKeyOf(s));
const seed = (n: number) => new Uint8Array(32).fill(n);

// every old check here was `a > b` or `a < b`, which is false when either side is NaN: the proof was admitted.
describe('a non-finite clock never admits (mesh)', () => {
  it('an unbounded maxClockSkewMs never admits a mesh proof (an infinite skew admits any action time)', () => {
    const ex = buildMeshExample();
    expect(verifyMeshProof(ex.proof, { ...ex.trust, maxClockSkewMs: Number.POSITIVE_INFINITY }).ok).toBe(false);
  });
  it.each(BAD)('verifyMeshProof refuses a trust clock of %s', (now) => {
    const ex = buildMeshExample();
    expect(verifyMeshProof(ex.proof, { ...ex.trust, now }).ok).toBe(false);
  });

  it.each(BAD)('verifyTranslatedCapability refuses an expiring capability at a clock of %s', (now) => {
    const human = seed(100);
    const agent = seed(101);
    const B = seed(111);
    const A = pub(seed(110));
    const root = mintRoot({
      principalSecret: human,
      principalPublic: pub(human),
      holder: pub(agent),
      caveats: [{ type: 'scope', actions: ['payments.refund'] }, { type: 'max_amount', max: 500 }, { type: 'expires', at: 1_800_003_600_000 }] as Caveat[],
    });
    const chain = [root, delegate(root, pub(seed(102)), [{ type: 'max_amount', max: 100 }], agent)];
    const tc = translateCapability(chain, { fromGuardian: A, toGuardian: pub(B), additionalCaveats: [{ type: 'max_amount', max: 50 }], bridgeSecret: B, issued_at: 1_800_000_000_000 });
    const trust = { fromGuardian: A, toGuardian: pub(B), bridge: pub(B), rootIssuer: pub(human) };
    expect(verifyTranslatedCapability(tc, trust).ok).toBe(true);
    // old check `now > expiresAt` was false for NaN, so the expired-or-not question was never asked
    expect(verifyTranslatedCapability(tc, { ...trust, now }).ok).toBe(false);
  });

  // a +Infinity witness clock made `timestamp <= clock + skew` true for every head
  it.each(BAD)('a witness whose own clock is %s refuses to cosign (old future-check passed)', (clk) => {
    const d = new MeshDomain('X', seed(4));
    d.record(buildMeshExample().chain[0]!);
    expect(() => d.publishHead([new MeshWitness(seed(3), { clock: () => clk })], 100)).toThrow(/future/);
  });

  // a +Infinity skew allowance made the future-dated check true for every head
  it.each([Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('a witness with a skew allowance of %s refuses to cosign', (skew) => {
    const d = new MeshDomain('X', seed(4));
    d.record(buildMeshExample().chain[0]!);
    expect(() => d.publishHead([new MeshWitness(seed(3), { clock: () => 0, maxClockSkewMs: skew })], 1_000_000_000)).toThrow(/future/);
  });

  describe('checkCosignedHead takes the freshness branch', () => {
    const headOf = () => {
      const ex = buildMeshExample();
      const ch = Object.values(ex.proof.heads)[0]!;
      return { ex, ch, dom: ch.head.domain };
    };
    it('the example head is accepted with the example clock', () => {
      const { ex, ch, dom } = headOf();
      expect(checkCosignedHead(ch, dom, ex.trust)).toBeUndefined();
    });
    // old checks `timestamp > now + skew` and `now - timestamp > maxAge` were false for NaN, so a NaN bound or clock read as fresh
    it.each(BAD)('a clock of %s is refused', (now) => {
      const { ex, ch, dom } = headOf();
      expect(checkCosignedHead(ch, dom, { ...ex.trust, now })).toBeDefined();
    });
    it('a NaN maxHeadAgeMs or maxClockSkewMs is refused (the stale and future checks each reach their own NaN)', () => {
      const { ex, ch, dom } = headOf();
      expect(checkCosignedHead(ch, dom, { ...ex.trust, maxHeadAgeMs: Number.NaN })).toBe('head is stale');
      expect(checkCosignedHead(ch, dom, { ...ex.trust, maxClockSkewMs: Number.NaN })).toBe('head timestamp is in the future');
    });
    // a +Infinity skew allowance admitted every future-dated head
    it.each([Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('a maxClockSkewMs of %s is refused', (maxClockSkewMs) => {
      const { ex, ch, dom } = headOf();
      expect(checkCosignedHead(ch, dom, { ...ex.trust, maxClockSkewMs })).toBe('head timestamp is in the future');
    });
    // an unbounded head age admits a head of any age
    it('an infinite maxHeadAgeMs is refused', () => {
      const { ex, ch, dom } = headOf();
      expect(checkCosignedHead(ch, dom, { ...ex.trust, maxHeadAgeMs: Number.POSITIVE_INFINITY })).toBe('head is stale');
    });
  });
});
