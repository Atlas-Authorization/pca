import { describe, expect, it } from 'vitest';
import { sha256, utf8 } from '@atlasauth/pca';
import { signGoalArtifact, signPayload, signerId, verifyGoalArtifact, verifyPayload, type SignedPayload } from '../src/sign';

const SECRET = sha256(utf8('atlas-pca-tests/goal-sign-kill-key'));
const PK = signerId(SECRET);
// Round-trip through JSON to get the envelope type without a cast.
const asPayload = (o: object): SignedPayload<number> => JSON.parse(JSON.stringify(o));

describe('verifyPayload', () => {
  it('accepts a payload signed under its own kind and rejects other pins', () => {
    const p = signPayload('k', 1, SECRET);
    expect(verifyPayload(p, 'k', [PK])).toBe(true);
    expect(verifyPayload(p, 'k', [])).toBe(false);
    expect(verifyPayload(p, 'other', [PK])).toBe(false);
  });
  it('rejects an envelope version other than 1 even when the signature is valid', () => {
    const art = signGoalArtifact('k', { v: 2, kind: 'k', signer: PK, payload: 1 }, SECRET);
    expect(verifyGoalArtifact('k', art, 'signer', [PK])).toBe(true);
    expect(verifyPayload(asPayload(art), 'k', [PK])).toBe(false);
  });
  it('rejects an envelope whose kind differs from the asked kind even when signed under the asked domain', () => {
    const art = signGoalArtifact('b', { v: 1, kind: 'a', signer: PK, payload: 1 }, SECRET);
    expect(verifyGoalArtifact('b', art, 'signer', [PK])).toBe(true);
    expect(verifyPayload(asPayload(art), 'b', [PK])).toBe(false);
  });
});

describe('verifyGoalArtifact', () => {
  it('is total: a throwing member read yields false', () => {
    const o: Record<string, unknown> = {};
    Object.defineProperty(o, 'signer', { enumerable: true, get: () => { throw new Error('boom'); } });
    expect(verifyGoalArtifact('k', o, 'signer', [PK])).toBe(false);
  });
  it('rejects an artifact that is not a plain object even if its own members carry a valid signature', () => {
    const art = signGoalArtifact('k', { signer: PK, payload: 1 }, SECRET);
    expect(verifyGoalArtifact('k', art, 'signer', [PK])).toBe(true);
    const inheriting: Record<string, unknown> = Object.assign(Object.create({ inherited: 1 }) as Record<string, unknown>, art);
    expect(verifyGoalArtifact('k', inheriting, 'signer', [PK])).toBe(false);
  });
});
