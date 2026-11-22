/**
 * Mutation kills for the 0.5.0 flagship gate survivors in pca-sandbox: values that change between reads. A runtime claim's
 * `sig` and `attestor` are type-checked on their first read and used again at verification; an authorize result's
 * `operation` is checked by isAuthorizedFor and read again when the handle is minted. Each later read is the one that
 * counts, so a member that stops being what was checked must not turn into an accepted claim or a crash.
 */
import { describe, expect, it } from 'vitest';
import { generateKeyPair, hashCanonical, encodeKey } from '@atlasauth/pca';
import type { AuthorizeResult } from '@atlasauth/pca';
import { claimFixture } from './test-auth';
import { HandleTable, ReceiptLog, verifiedRuntimeClass } from './index';

/** A copy of `o` whose `key` returns values[0], values[1], ... on successive reads (the last value repeats). */
const unstable = <T extends object>(o: T, key: string, values: unknown[]) => {
  let n = 0;
  const c = { ...o } as Record<string, unknown>;
  Object.defineProperty(c, key, { enumerable: true, configurable: true, get: () => values[Math.min(n++, values.length - 1)] });
  return c;
};

describe('verifiedRuntimeClass: sig and attestor are re-read at verification', () => {
  it('a sig that is the valid signature only on its first read is none', () => {
    const f = claimFixture();
    expect(verifiedRuntimeClass(f.claim, f.trust)).toBe('wasi_no_ambient');
    const tampered = f.claim.sig.slice(1) + 'A';
    expect(verifiedRuntimeClass(unstable(f.claim, 'sig', [f.claim.sig, tampered]), f.trust)).toBe('none');
  });
  it('an attestor that is the pinned key for four reads and another key on the fifth is none', () => {
    // reads: type check, pinned check, key-length check, the copy into the signed body, the verification key
    const f = claimFixture();
    const other = encodeKey(generateKeyPair().publicKey);
    const a = f.claim.attestor;
    expect(verifiedRuntimeClass(unstable(f.claim, 'attestor', [a, a, a, a, a]), f.trust)).toBe('wasi_no_ambient');
    expect(verifiedRuntimeClass(unstable(f.claim, 'attestor', [a, a, a, a, other]), f.trust)).toBe('none');
  });
});

describe('HandleTable.mint: the operation id is read once more after authorization', () => {
  it('an operation that is gone on the second read mints with an empty op_id', () => {
    const op = { verb: 'notes.read', resource: 'notes', params: { id: 'n-7' } };
    const bound = { id: 'op-1', verb: op.verb, resource: op.resource, params_digest: hashCanonical(op.params) };
    const result = unstable({ allow: true }, 'operation', [bound, undefined]) as unknown as AuthorizeResult;
    const log = new ReceiptLog();
    const t = new HandleTable('none', log, { 'notes.read': () => Uint8Array.of(1) });
    const h = t.mint(result, op);
    expect(h).toBe(1);
    t.use(h);
    expect(log.entries[0]!.subject.op_id).toBe('');
  });
});
