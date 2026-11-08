/**
 * T9 (0.5): verifier-side revocation staleness. A maximum age on the signed epoch's `issued_at` (independent of the
 * signer's `not_after`), a stricter default window for irreversible actions, and an age check / refusal on the
 * unsigned-root path that had none.
 */
import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair } from './keys';
import type { VerifyContext } from './pcactn';
import {
  REVOCATION_EPOCH_VALIDITY_MS,
  REVOCATION_IRREVERSIBLE_MAX_AGE_MS,
  RevocationSet,
  checkRevocationAge,
  checkRevocationEpoch,
  createRevocationChecker,
  effectiveReversibility,
  revocationMaxAgeMs,
  signRevocationEpoch,
  type RevocationCheckerOptions,
  type RevocationEpoch,
} from './revocation';

const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const G = generateKeyPair();
const guardianPublic = encodeKey(G.publicKey);
const set = new RevocationSet(['cap-revoked']);
const epochAt = (issued: number, o: { epoch?: number; notAfter?: number; root?: string } = {}): RevocationEpoch =>
  signRevocationEpoch(G.secretKey, {
    instance_id: 'i', grant_ref: 'g1', epoch: o.epoch ?? 0, set_size: set.size, root: o.root ?? set.root, issued_at: issued, not_after: o.notAfter ?? issued + 10 * 60_000,
  });
const ctxFor = (cls: string | undefined, o: { ids?: string[]; now?: number } = {}): VerifyContext =>
  ({
    pcactn: { grant_ref: 'g1', cap_chain: (o.ids ?? ['cap-a']).map((id) => ({ id })), action: cls === undefined ? {} : { reversibility_class: cls }, freshness: { epoch: 0 } },
    grant: { id: 'g1' },
    nowEpoch: o.now ?? NOW,
  }) as unknown as VerifyContext;
const checker = (o: Partial<RevocationCheckerOptions>) =>
  createRevocationChecker({ guardianPublic, proofFor: (id) => set.nonMembershipProof(id), ...o });
const run = async (c: ReturnType<typeof checker>, ctx: VerifyContext) => {
  const r = (await c(ctx)) as { enforced: boolean; ok?: boolean; reason?: string };
  return r.ok ? 'ok' : r.reason;
};

describe('checkRevocationEpoch maxAgeMs (verifier-side cap)', () => {
  it('an epoch older than the cap is denied even before its signed not_after; at the cap it passes', () => {
    const ep = epochAt(NOW - 200_000); // not_after = NOW + 400 s: the signer still calls it valid
    expect(checkRevocationEpoch(ep, { guardianPublic, now: NOW })).toEqual({ ok: true });
    expect(checkRevocationEpoch(ep, { guardianPublic, now: NOW, maxAgeMs: 120_000 })).toEqual({
      ok: false,
      reason: "revocation epoch is 200000 ms old, over the verifier's maximum of 120000 ms (stale revocation state)",
    });
    expect(checkRevocationEpoch(ep, { guardianPublic, now: NOW, maxAgeMs: 200_000 })).toEqual({ ok: true });
    expect(checkRevocationEpoch(ep, { guardianPublic, now: NOW, maxAgeMs: 199_999 }).ok).toBe(false);
  });

  it('a malformed cap fails closed (NaN never admits)', () => {
    expect(checkRevocationEpoch(epochAt(NOW), { guardianPublic, now: NOW, maxAgeMs: Number.NaN }).ok).toBe(false);
  });
});

describe('policy helpers', () => {
  it('defaults: 5 min for any action, 2 min for irreversible, rate_limited = max; per-class values are capped by the max', () => {
    expect([REVOCATION_EPOCH_VALIDITY_MS, REVOCATION_IRREVERSIBLE_MAX_AGE_MS]).toEqual([300_000, 120_000]);
    expect(['reversible', 'rate_limited', 'irreversible'].map((c) => revocationMaxAgeMs({}, c as never))).toEqual([300_000, 300_000, 120_000]);
    expect(['reversible', 'rate_limited', 'irreversible'].map((c) => revocationMaxAgeMs({ maxRevocationAgeMs: 60_000 }, c as never))).toEqual([60_000, 60_000, 60_000]);
    expect(['reversible', 'rate_limited', 'irreversible'].map((c) => revocationMaxAgeMs({ staleness: { rate_limited: 90_000, irreversible: 10_000 } }, c as never))).toEqual([300_000, 90_000, 10_000]);
    expect(revocationMaxAgeMs({ maxRevocationAgeMs: 50_000, staleness: { rate_limited: 90_000 } }, 'rate_limited')).toBe(50_000);
    // the old names stay accepted for one release: the class word `costly` and the option `staleness.costly`
    expect(['reversible', 'costly', 'irreversible'].map((c) => revocationMaxAgeMs({ staleness: { costly: 90_000, irreversible: 10_000 } }, c as never))).toEqual([300_000, 90_000, 10_000]);
    expect(revocationMaxAgeMs({ staleness: { rate_limited: 70_000, costly: 90_000 } }, 'costly')).toBe(70_000);
  });

  it('effective class: the stricter of server and signed; missing or unknown = irreversible', () => {
    expect(effectiveReversibility(undefined, 'reversible')).toBe('reversible');
    expect(effectiveReversibility('irreversible', 'reversible')).toBe('irreversible');
    expect(effectiveReversibility('reversible', 'rate_limited')).toBe('rate_limited');
    expect(effectiveReversibility('reversible', 'costly')).toBe('rate_limited');
    expect(effectiveReversibility(undefined, undefined)).toBe('irreversible');
    expect(effectiveReversibility(undefined, 'whatever')).toBe('irreversible');
  });

  it('checkRevocationAge: unknown, future and over-age all deny with a named reason', () => {
    expect(checkRevocationAge(undefined, NOW, 1000)).toEqual({ ok: false, reason: 'revocation state age is unknown (unverifiable revocation state)' });
    expect(checkRevocationAge(NOW + 60_001, NOW, 1000)).toEqual({ ok: false, reason: 'revocation state issued in the future' });
    expect(checkRevocationAge(NOW + 60_000, NOW, 1000)).toEqual({ ok: true });
    expect(checkRevocationAge(NOW - 1001, NOW, 1000).ok).toBe(false);
    expect(checkRevocationAge(NOW - 1000, NOW, 1000)).toEqual({ ok: true });
  });

  it('malformed policy values are refused at construction', () => {
    expect(() => checker({ root: () => set.root, maxRevocationAgeMs: 0 })).toThrow(/maxRevocationAgeMs/);
    expect(() => checker({ root: () => set.root, staleness: { irreversible: -1 } })).toThrow(/staleness.irreversible/);
    expect(() => checker({ root: () => set.root, staleness: { costly: Number.NaN } })).toThrow(/staleness.costly/);
    expect(() => checker({ root: () => set.root, staleness: { rate_limited: Number.NaN } })).toThrow(/staleness.rate_limited/);
  });
});

describe('createRevocationChecker with a staleness policy', () => {
  const ep150 = epochAt(NOW - 150_000); // 150 s old: inside 5 min, outside the 2 min irreversible window

  it('the same signed epoch is accepted for a reversible action and denied for an irreversible one', async () => {
    const c = checker({ epoch: () => ep150, staleness: {} });
    expect(await run(c, ctxFor('reversible'))).toBe('ok');
    expect(await run(c, ctxFor('costly'))).toBe('ok');
    expect(await run(c, ctxFor('irreversible'))).toBe("revocation epoch is 150000 ms old, over the verifier's maximum of 120000 ms (stale revocation state)");
    // missing class = irreversible
    expect(await run(c, ctxFor(undefined))).toMatch(/stale revocation state/);
  });

  it("the server's catalog class wins when it is stricter than the signed one", async () => {
    const c = checker({ epoch: () => ep150, staleness: {}, reversibilityClass: () => 'irreversible' });
    expect(await run(c, ctxFor('reversible'))).toMatch(/stale revocation state/);
  });

  it('without a policy nothing changes: the 150 s epoch passes for an irreversible action (pre-0.5 behaviour)', async () => {
    expect(await run(checker({ epoch: () => ep150 }), ctxFor('irreversible'))).toBe('ok');
  });

  it('a revoked capability is still denied under a fresh epoch', async () => {
    const c = checker({ epoch: () => epochAt(NOW), staleness: {}, proofFor: (id) => (set.has(id) ? undefined : set.nonMembershipProof(id)) });
    expect(await run(c, ctxFor('reversible', { ids: ['cap-revoked'] }))).toBe('no non-membership proof for cap-revoked');
  });

  describe('unsigned root path (no epoch)', () => {
    it('without a policy a bare root has no staleness check at all (unchanged)', async () => {
      expect(await run(checker({ root: () => set.root }), ctxFor('irreversible'))).toBe('ok');
    });

    it('irreversible: refused unless explicitly allowed', async () => {
      const c = checker({ root: () => set.root, rootIssuedAt: () => NOW, maxRevocationAgeMs: 300_000 });
      expect(await run(c, ctxFor('irreversible'))).toBe('unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)');
      const allowed = checker({ root: () => set.root, rootIssuedAt: () => NOW, maxRevocationAgeMs: 300_000, allowUnsignedRootForIrreversible: true });
      expect(await run(allowed, ctxFor('irreversible'))).toBe('ok');
      // allowed, but still held to the irreversible window
      const staleAllowed = checker({ root: () => set.root, rootIssuedAt: () => NOW - 121_000, staleness: {}, allowUnsignedRootForIrreversible: true });
      expect(await run(staleAllowed, ctxFor('irreversible'))).toBe("revocation root is 121000 ms old, over the verifier's maximum of 120000 ms (stale revocation state)");
    });

    it('reversible: an unknown root age is unverifiable and denies; a stale one denies; a fresh one passes', async () => {
      expect(await run(checker({ root: () => set.root, staleness: {} }), ctxFor('reversible'))).toBe('revocation root age is unknown (unverifiable revocation state)');
      expect(await run(checker({ root: () => set.root, rootIssuedAt: () => NOW - 301_000, staleness: {} }), ctxFor('reversible'))).toMatch(/301000 ms old/);
      expect(await run(checker({ root: () => set.root, rootIssuedAt: () => NOW - 299_000, staleness: {} }), ctxFor('reversible'))).toBe('ok');
    });
  });
});
