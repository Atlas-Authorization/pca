import { describe, expect, it } from 'vitest';
import { generateKeyPair, encodeKey } from '@atlasauth/pca';
import { signerOf } from './sig';
import { BlueprintRegistry, MemoryBlueprintStore, checkBlueprints, signBlueprint, type NewBlueprint } from './blueprint';
import { WindowReadAccumulator } from './list-authorized';
import { assembleBundle, signBundle, verifyBundle, type PolicyBundleBody } from './bundle';

const NOW = 1_800_000_000_000;
const operator = generateKeyPair();
const bpKey = generateKeyPair();
const BP = encodeKey(bpKey.publicKey);
const base: NewBlueprint = { id: 'bot', key: BP, ceiling: [], epoch: 1, status: 'active', issued_at: NOW };
const chain = [{ issuer: 'root', holder: BP }, { issuer: BP, holder: 'inst' }];

describe('a non-finite number never admits (grants)', () => {
  it('checkBlueprints: a NaN minEpoch escalates as stale state, never allows', async () => {
    const reg = new BlueprintRegistry([signerOf(operator.secretKey)], new MemoryBlueprintStore());
    expect((await reg.accept(signBlueprint(operator.secretKey, base))).ok).toBe(true);
    // old check `have < NaN` was false, so the freshness gate passed
    const d = await checkBlueprints(chain, reg, { now: NOW, minEpoch: Number.NaN });
    expect(d.decision).toBe('escalate');
  });
  it('WindowReadAccumulator: a NaN charge or a NaN cap refuses', () => {
    // old check `n + units > cap` was false for NaN on either side, so the read was admitted
    expect(new WindowReadAccumulator(5, 100).charge('k', Number.NaN, 0)).toBe(false);
    expect(new WindowReadAccumulator(Number.NaN, 100).charge('k', 1, 0)).toBe(false);
    expect(new WindowReadAccumulator(5, 100).charge('k', Number.POSITIVE_INFINITY, 0)).toBe(false);
  });
  it('checkBlueprints: an infinite minEpoch escalates, never allows', async () => {
    const reg = new BlueprintRegistry([signerOf(operator.secretKey)], new MemoryBlueprintStore());
    expect((await reg.accept(signBlueprint(operator.secretKey, base))).ok).toBe(true);
    // old check `have >= -Infinity` was true, so a -Infinity floor admitted
    for (const minEpoch of [Number.NEGATIVE_INFINITY, Number.POSITIVE_INFINITY]) {
      expect((await checkBlueprints(chain, reg, { now: NOW, minEpoch })).decision).toBe('escalate');
    }
  });
  it('WindowReadAccumulator: an infinite charge or clock refuses', () => {
    // old check `n + -Infinity <= cap` was true, and it poisoned the window total
    expect(new WindowReadAccumulator(5, 100).charge('k', Number.NEGATIVE_INFINITY, 0)).toBe(false);
    // a -Infinity clock opened a fresh window and reset the spend
    const acc = new WindowReadAccumulator(5, 100);
    expect(acc.charge('k', 5, 0)).toBe(true);
    for (const now of [Number.NEGATIVE_INFINITY, Number.POSITIVE_INFINITY]) expect(acc.charge('k', 1, now)).toBe(false);
    expect(acc.charge('k', 1, 1)).toBe(false);
  });
  it('verifyBundle: a non-finite accepted revision refuses', () => {
    const body: PolicyBundleBody = { v: 1, kind: 'pca-policy-bundle', revision: 1, grants: ['g1'], template_digests: [], min_verifier_version: '0.5.0', issued_at: 1 } as PolicyBundleBody;
    const b = assembleBundle(body, [signBundle(body, operator.secretKey)]);
    const o = { signers: [signerOf(operator.secretKey)], threshold: 1, verifierVersion: '1.0.0' };
    // old check `revision >= -Infinity` was true, so a -Infinity floor accepted any revision
    expect(verifyBundle(b, { ...o, last: { revision: Number.NEGATIVE_INFINITY, digest: 'x' } }).ok).toBe(false);
    expect(verifyBundle(b, { ...o, last: { revision: Number.POSITIVE_INFINITY, digest: 'x' } }).ok).toBe(false);
  });
});
