import { describe, expect, it } from 'vitest';
import { mintRoot, delegate, type Caveat } from './capability';
import { encodeKey, publicKeyOf } from './keys';
import { MeshDomain, MeshWitness, buildMeshExample, checkCosignedHead, translateCapability, verifyMeshProof, verifyTranslatedCapability } from './mesh';

const BAD = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY];
const pub = (s: Uint8Array) => encodeKey(publicKeyOf(s));
const seed = (n: number) => new Uint8Array(32).fill(n);

// every old check here was `a > b` or `a < b`, which is false when either side is NaN: the proof was admitted.
describe('a non-finite clock never admits (mesh)', () => {
  it.each(BAD)('verifyMeshProof refuses a trust clock of %s', (now) => {
    const ex = buildMeshExample();
    expect(verifyMeshProof(ex.proof, { ...ex.trust, now }).ok).toBe(false);
  });

  it('verifyTranslatedCapability refuses an expiring capability at a NaN clock', () => {
    const now = Number.NaN;
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

  it('a witness whose own clock is NaN refuses to cosign (old future-check passed)', () => {
    const d = new MeshDomain('X', seed(4));
    d.record(buildMeshExample().chain[0]!);
    expect(() => d.publishHead([new MeshWitness(seed(3), { clock: () => Number.NaN })], 100)).toThrow(/future/);
  });

  it('a witness whose own clock is +Infinity refuses to cosign (an infinite clock admits any head time)', () => {
    const d = new MeshDomain('X', seed(4));
    d.record(buildMeshExample().chain[0]!);
    expect(() => d.publishHead([new MeshWitness(seed(3), { clock: () => Number.POSITIVE_INFINITY })], 100)).toThrow(/future/);
  });

  it('a witness with an unbounded clock skew refuses to cosign (an infinite skew admits any head)', () => {
    const d = new MeshDomain('X', seed(4));
    d.record(buildMeshExample().chain[0]!);
    expect(() => d.publishHead([new MeshWitness(seed(3), { clock: () => 0, maxClockSkewMs: Number.POSITIVE_INFINITY })], 100)).toThrow(/future/);
  });

  it('an unbounded maxClockSkewMs never admits a mesh proof (an infinite skew admits any action time)', () => {
    const ex = buildMeshExample();
    expect(verifyMeshProof(ex.proof, { ...ex.trust, maxClockSkewMs: Number.POSITIVE_INFINITY }).ok).toBe(false);
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
    it('an infinite maxHeadAgeMs or maxClockSkewMs is refused (an unbounded window admits any head)', () => {
      const { ex, ch, dom } = headOf();
      expect(checkCosignedHead(ch, dom, { ...ex.trust, maxHeadAgeMs: Number.POSITIVE_INFINITY })).toBe('head is stale');
      expect(checkCosignedHead(ch, dom, { ...ex.trust, maxClockSkewMs: Number.POSITIVE_INFINITY })).toBe('head timestamp is in the future');
    });
    it('a NaN maxHeadAgeMs or maxClockSkewMs is refused (the stale and future checks each reach their own NaN)', () => {
      const { ex, ch, dom } = headOf();
      expect(checkCosignedHead(ch, dom, { ...ex.trust, maxHeadAgeMs: Number.NaN })).toBe('head is stale');
      expect(checkCosignedHead(ch, dom, { ...ex.trust, maxClockSkewMs: Number.NaN })).toBe('head timestamp is in the future');
    });
  });
});
