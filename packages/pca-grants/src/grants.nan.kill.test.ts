import { describe, expect, it } from 'vitest';
import { generateKeyPair, encodeKey } from '@atlasauth/pca';
import { signerOf } from './sig';
import { BlueprintRegistry, MemoryBlueprintStore, checkBlueprints, signBlueprint, type NewBlueprint } from './blueprint';
import { WindowReadAccumulator } from './list-authorized';

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
    expect(new WindowReadAccumulator(5, 100).charge('k', Number.NEGATIVE_INFINITY, 0)).toBe(false);
  });
});
