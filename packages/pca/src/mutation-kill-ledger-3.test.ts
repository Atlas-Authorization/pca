/** ledger.ts residual mutants: input type guards of verifyLedgerConsistency (the size-0 path is otherwise vacuous) and the proof/head size binding. */
import { describe, expect, it } from 'vitest';
import { b64u, sha256, utf8 } from './hash';
import { generateKeyPair, encodeKey } from './keys';
import { EMPTY_TREE_ROOT, signTreeHead, verifyHeadConsistency, verifyLedgerConsistency } from './ledger';

describe('verifyLedgerConsistency input guards', () => {
  it('a non-string newRoot is refused even on the vacuous size-0 path', () => {
    for (const newRoot of [123, null, undefined, {}, ['x']]) {
      expect(verifyLedgerConsistency(EMPTY_TREE_ROOT, newRoot as never, { oldSize: 0, newSize: 5, path: [] })).toBe(false);
    }
    expect(verifyLedgerConsistency(EMPTY_TREE_ROOT, 'any-root', { oldSize: 0, newSize: 5, path: [] })).toBe(true);
  });
  it('a non-string oldRoot is refused', () => {
    expect(verifyLedgerConsistency(7 as never, 7 as never, { oldSize: 3, newSize: 3, path: [] })).toBe(false);
  });
  it('a non-array path is refused even when it has length 0', () => {
    for (const path of ['', { length: 0 }]) {
      expect(verifyLedgerConsistency(EMPTY_TREE_ROOT, 'any-root', { oldSize: 0, newSize: 5, path: path as never })).toBe(false);
    }
  });
});

describe('verifyHeadConsistency binds the proof sizes to the signed heads', () => {
  it('a proof claiming oldSize 0 does not connect an older head of another size, even if that head carries the empty root', () => {
    const g = generateKeyPair();
    const pub = encodeKey(g.publicKey);
    const older = signTreeHead(g.secretKey, { instance_id: 'ins', principal: 'p', size: 5, root: EMPTY_TREE_ROOT, prev_root: '', timestamp: 1 });
    // a well-formed root (canonical base64url of 32 bytes): the opt-in proved consistency verifier (PCA_VERIFIED_CORE=merkle-strict)
    // refuses any other encoding, so a placeholder like 'r9' would make the positive control below fail for that reason instead
    const r9 = b64u(sha256(utf8('r9')));
    const newer = signTreeHead(g.secretKey, { instance_id: 'ins', principal: 'p', size: 9, root: r9, prev_root: 'r8', timestamp: 2 });
    expect(verifyHeadConsistency(older, newer, { oldSize: 0, newSize: 9, path: [] }, pub)).toBe(false);
    const older0 = signTreeHead(g.secretKey, { instance_id: 'ins', principal: 'p', size: 0, root: EMPTY_TREE_ROOT, prev_root: '', timestamp: 1 });
    expect(verifyHeadConsistency(older0, newer, { oldSize: 0, newSize: 9, path: [] }, pub)).toBe(true);
  });
});
