import { describe, expect, it } from 'vitest';
import {
  ACCESS_TIERS,
  NO_FACTS,
  TIER_PRESETS,
  TIER_TABLE,
  classifyPresentedTier,
  meetsTier,
  minimumTierFor,
  parseTierRule,
  preset,
  requiredTierFor,
  tier3,
  type PresentedFacts,
} from './index';

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const KEYS: (keyof PresentedFacts)[] = ['webBotAuth', 'pca', 'intent', 'evidence', 'bond'];
const randomFacts = (r: () => number): PresentedFacts => Object.fromEntries(KEYS.map((k) => [k, r() < 0.5])) as unknown as PresentedFacts;

describe('the §3.15 tier table', () => {
  it('has one row per tier, in order, and allowances only grow with the tier', () => {
    expect(TIER_TABLE.map((t) => t.tier)).toEqual([0, 1, 2, 3, 4]);
    for (let i = 1; i < TIER_TABLE.length; i++) for (const c of TIER_TABLE[i - 1]!.allows) expect(TIER_TABLE[i]!.allows).toContain(c);
  });
  it('minimum tiers per action class match the table', () => {
    expect(minimumTierFor('public_page')).toBe(0);
    expect(minimumTierFor('public_catalog_read')).toBe(1);
    expect(minimumTierFor('own_data_read')).toBe(2);
    expect(minimumTierFor('reversible_write')).toBe(2);
    expect(minimumTierFor('payment_under_cap')).toBe(3);
    expect(minimumTierFor('irreversible_with_jit')).toBe(3);
    expect(minimumTierFor('refund')).toBe(4);
  });
});

describe('classifyPresentedTier', () => {
  it('nothing proven is Tier 0; each tier needs exactly its column', () => {
    expect(classifyPresentedTier(NO_FACTS)).toBe(0);
    expect(classifyPresentedTier({ ...NO_FACTS, webBotAuth: true })).toBe(1);
    expect(classifyPresentedTier({ ...NO_FACTS, pca: true })).toBe(2);
    expect(classifyPresentedTier({ ...NO_FACTS, intent: true })).toBe(0); // intent without a verified PCActn proves nothing
    expect(classifyPresentedTier({ ...NO_FACTS, pca: true, intent: true })).toBe(3);
    expect(classifyPresentedTier({ ...NO_FACTS, pca: true, intent: true, evidence: true })).toBe(3);
    expect(classifyPresentedTier({ webBotAuth: false, pca: true, intent: true, evidence: true, bond: true })).toBe(4);
  });
  it('property: monotone (proving more never lowers the tier) and the result is met', () => {
    const r = mulberry32(0x5eed);
    for (let n = 0; n < 2000; n++) {
      const f = randomFacts(r);
      const t = classifyPresentedTier(f);
      expect(meetsTier(f, t)).toBe(true);
      for (const k of KEYS) {
        if (f[k]) continue;
        expect(classifyPresentedTier({ ...f, [k]: true })).toBeGreaterThanOrEqual(t);
      }
      // every tier above the result is NOT met
      for (const u of ACCESS_TIERS) if (u > t) expect(meetsTier(f, u)).toBe(false);
    }
  });
});

describe('requiredTierFor', () => {
  it('explicit rules win; defaults follow the table and fail closed', () => {
    expect(requiredTierFor('air.search', 'reversible', { tiers: { 'air.search': { tier: 1 } } })).toBe(1);
    expect(requiredTierFor('cat.list', 'reversible', undefined, { kind: 'read', public: true })).toBe(1);
    expect(requiredTierFor('acct.read', 'reversible', undefined, { kind: 'read' })).toBe(2);
    expect(requiredTierFor('cart.add', 'reversible', undefined, { kind: 'write' })).toBe(2);
    expect(requiredTierFor('air.book', 'irreversible')).toBe(3);
    expect(requiredTierFor('msg.send', 'rate_limited')).toBe(3);
    expect(requiredTierFor('pay', 'reversible', undefined, { payment: true })).toBe(3);
    expect(requiredTierFor('air.refund', 'reversible', undefined, { refund: true })).toBe(4);
    expect(requiredTierFor('unknown', undefined)).toBe(3);
  });
  it('property: adding a risk hint never lowers the required tier', () => {
    const r = mulberry32(42);
    const revs = [undefined, 'reversible', 'rate_limited', 'irreversible'] as const;
    for (let n = 0; n < 500; n++) {
      const rev = revs[Math.floor(r() * revs.length)];
      const base = { kind: r() < 0.5 ? ('read' as const) : ('write' as const), public: r() < 0.5 };
      const t = requiredTierFor('v', rev, undefined, base);
      for (const h of ['payment', 'refund', 'highValue', 'bond'] as const) expect(requiredTierFor('v', rev, undefined, { ...base, [h]: true })).toBeGreaterThanOrEqual(t);
    }
  });
});

describe('tier rules (§5 tiers)', () => {
  it('presets are valid rules and tier3 defaults to typed JIT for irreversible actions', () => {
    for (const p of TIER_PRESETS) expect(parseTierRule(JSON.parse(JSON.stringify(p)))).toEqual(JSON.parse(JSON.stringify(p)));
    expect(tier3.jit?.irreversible).toBe('typed');
    expect(preset(4, { bond_min_cents: 10000 }).bond_min_cents).toBe(10000);
  });
  it('parses the §5 example rules', () => {
    expect(parseTierRule({ tier: 1, rate: { max: 30, per_secs: 60, key: 'agent' } }).rate).toEqual({ max: 30, per_secs: 60, key: 'agent' });
    expect(parseTierRule({ tier: 3, jit: { irreversible: 'typed', reversible: 'none' }, max_total_cents: 500000 }).max_total_cents).toBe(500000);
    expect(parseTierRule({ tier: 4, bond_min_cents: 10000 }).bond_min_cents).toBe(10000);
  });
  it('unknown members and misplaced members are configuration errors', () => {
    expect(() => parseTierRule({ tier: 2, tierr: 3 })).toThrow(/unknown member/);
    expect(() => parseTierRule({ tier: 5 })).toThrow();
    expect(() => parseTierRule({ tier: 2, jit: { irreversible: 'typed' } })).toThrow(/Tier 3/);
    expect(() => parseTierRule({ tier: 3, bond_min_cents: 1 })).toThrow(/Tier 4/);
    expect(() => parseTierRule({ tier: 3, jit: { irreversible: 'retina' } })).toThrow();
    expect(() => parseTierRule({ tier: 1, rate: { max: 0, per_secs: 60 } })).toThrow();
    expect(() => parseTierRule({ tier: 1, rate: { max: 1, per_secs: 60, burst: 2 } })).toThrow(/unknown member/);
  });
});
