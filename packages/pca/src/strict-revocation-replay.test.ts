/**
 * Strictness follow-ups of the 2026-10-12 JavaScript-semantics audit: revocation proofs take only safe-integer
 * index / size and canonical 32-byte siblings, a signed revocation epoch's issued_at / not_after are safe integers, and
 * the replay key is injective (a part with a lone surrogate has no UTF-8 encoding and is refused).
 */
import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair } from './keys';
import { type PCActn } from './pcactn';
import { RevocationSet, checkRevocationEpoch, signRevocationEpoch, verifyMembership, verifyNonMembership } from './revocation';
import { type ReplayStore, guardPCActnReplay, replayKey } from './replay';

describe('revocation proofs: strict shapes', () => {
  const set = new RevocationSet(['a', 'c', 'e']);
  it('a non-membership proof with a sibling that is not 32 bytes is refused (the honest one verifies)', () => {
    const good = set.nonMembershipProof('b');
    expect(verifyNonMembership(set.root, good, 'b')).toBe(true);
    const lo = good.lo!;
    for (const hash of [lo.proof.path[0]!.hash + 'AAAA', lo.proof.path[0]!.hash.slice(0, 40), '', 5]) {
      const bad = structuredClone(good);
      bad.lo!.proof.path[0]!.hash = hash as string;
      expect(verifyNonMembership(set.root, bad, 'b')).toBe(false);
    }
  });
  it('a membership proof with a non-canonical or wrong-length sibling is refused', () => {
    const good = set.membershipProof('c');
    expect(verifyMembership(set.root, good, 'c')).toBe(true);
    const bad = structuredClone(good);
    bad.path[0]!.hash = bad.path[0]!.hash + 'A';
    expect(verifyMembership(set.root, bad, 'c')).toBe(false);
  });
  it('size and index must be safe integers', () => {
    const good = set.nonMembershipProof('b');
    expect(verifyNonMembership(set.root, { ...structuredClone(good), size: 2 ** 53 }, 'b')).toBe(false);
    expect(verifyNonMembership(set.root, { ...structuredClone(good), size: 3.5 }, 'b')).toBe(false);
    const m = set.membershipProof('c');
    expect(verifyMembership(set.root, { ...m, index: 2 ** 53 }, 'c')).toBe(false);
    expect(verifyMembership(set.root, { ...m, index: 1.5 }, 'c')).toBe(false);
  });
});

describe('revocation epoch: issued_at / not_after are safe integers', () => {
  const G = generateKeyPair();
  const gPub = encodeKey(G.publicKey);
  const NOW = 1_000_000;
  const set = new RevocationSet(['x']);
  const ep = (over: Record<string, unknown>) =>
    signRevocationEpoch(G.secretKey, { instance_id: 'i', grant_ref: 'g', epoch: 1, set_size: set.size, root: set.root, issued_at: NOW, not_after: NOW + 60_000, ...over } as never);
  it('a well-formed epoch verifies', () => {
    expect(checkRevocationEpoch(ep({}), { guardianPublic: gPub, now: NOW, grantRef: 'g' })).toEqual({ ok: true });
  });
  it('a guardian-signed epoch with a null / string / fractional window is malformed (it used to pass the window by coercion)', () => {
    for (const over of [{ issued_at: null }, { issued_at: NOW + 0.5 }, { not_after: String(NOW + 60_000) }, { not_after: NOW + 60_000.5 }]) {
      expect(checkRevocationEpoch(ep(over), { guardianPublic: gPub, now: NOW, grantRef: 'g' }), JSON.stringify(over)).toEqual({ ok: false, reason: 'malformed revocation epoch' });
    }
  });
});

describe('replay key: injective over well-formed strings only', () => {
  it('a part with a lone surrogate (or a non-string part) is refused instead of colliding through U+FFFD', () => {
    for (const bad of ['\ud800', 'a\udbffb', '\udc00', 5 as unknown as string]) {
      expect(() => replayKey('ns', bad)).toThrow('replayKey: every part must be a well-formed string (no lone surrogates)');
      expect(() => replayKey(bad, 'x')).toThrow(TypeError);
    }
    expect(replayKey('ns', '�')).toMatch(/^ns:/);
    expect(replayKey('ns', '😀')).toMatch(/^ns:/); // a surrogate PAIR is a well-formed character
  });
  it('a verifier audience with a lone surrogate is refused before any store call', async () => {
    const calls: string[] = [];
    const store: ReplayStore = { consumeOnce: async (k) => (calls.push(k), true) };
    const aud = 'rs\ud800';
    const p = { aud, iat: 1_800_000_000_000, exp: 1_800_000_060_000, counter: 1, nonce: 'n', grant_ref: 'g', cap_chain: [{ holder: 'h' }] } as unknown as PCActn;
    expect(await guardPCActnReplay(store, p, { aud, now: 1_800_000_000_000 })).toEqual({ ok: false, code: 'malformed', reason: 'verifier audience is invalid' });
    expect(calls).toHaveLength(0);
  });
});
