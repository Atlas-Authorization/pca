import { describe, expect, it } from 'vitest';
import { attenuate, mintRoot } from './capability';
import { encodeKey, generateKeyPair } from './keys';
import { type PCActn, type VerifyContext } from './pcactn';
import {
  REVEPOCH_DOMAIN,
  REVOCATION_EPOCH_REFRESH_MS,
  REVOCATION_EPOCH_VALIDITY_MS,
  checkRevocationEpoch,
  revokeMessage,
  signRevocationEpoch,
  RevocationSet,
  createRevocationChecker, verifyMembership, verifyNonMembership,
} from './revocation';
import { sign, verifyB64u } from './keys';

const ids = (n: number) => Array.from({ length: n }, (_, i) => `cap-${String(i * 2).padStart(3, '0')}`); // even only

describe('revocation set', () => {
  it('orders ids by UTF-8 bytes (code points), not UTF-16 code units: an astral id sorts AFTER U+FFFD', () => {
    const astral = '\u{1F600}'; // UTF-16 lead surrogate 0xD83D < 0xFFFD, but code point 0x1F600 > 0xFFFD
    const bmp = '\uFFFD';
    const forward = new RevocationSet(['a', astral, bmp]);
    const reverse = new RevocationSet([bmp, astral, 'a']);
    expect(forward.list()).toEqual(['a', bmp, astral]);
    expect(forward.list()).toEqual([...forward.list()].sort((x, y) => Buffer.compare(Buffer.from(x), Buffer.from(y))));
    expect(forward.root).toBe(reverse.root); // order-independent: the committed root only depends on the SET
    // membership + non-membership proofs hold across the BMP/astral boundary
    for (const id of [astral, bmp, 'a']) expect(verifyMembership(forward.root, forward.membershipProof(id), id)).toBe(true);
    for (const absent of ['\uFFFE', '\u{1F601}', '\u{10FFFF}', 'b']) {
      expect(verifyNonMembership(forward.root, forward.nonMembershipProof(absent), absent)).toBe(true);
    }
    // a revoked astral id has no non-membership proof, and a forged bracket that uses UTF-16 order is rejected
    expect(() => forward.nonMembershipProof(astral)).toThrow('nonMembershipProof: id is revoked');
    const bracket = forward.nonMembershipProof('\uFFFE');
    expect(verifyNonMembership(forward.root, bracket, astral)).toBe(false);
  });
  it('is order-independent and idempotent', () => {
    const a = new RevocationSet(['b', 'a', 'c']);
    const b = new RevocationSet(['c', 'b', 'a', 'a']);
    expect(a.root).toBe(b.root);
    expect(b.size).toBe(3);
    expect(b.revoke('a')).toBe(false);
    const before = a.root;
    a.revoke('d');
    expect(a.root).not.toBe(before);
  });
  it('membership proofs verify for every size; wrong id / root fail', () => {
    for (let n = 1; n <= 12; n++) {
      const s = new RevocationSet(ids(n));
      for (const id of ids(n)) expect(verifyMembership(s.root, s.membershipProof(id), id)).toBe(true);
      expect(verifyMembership(s.root, s.membershipProof(ids(n)[0]!), 'cap-001')).toBe(false);
      expect(verifyMembership(new RevocationSet(['z']).root, s.membershipProof(ids(n)[0]!), ids(n)[0]!)).toBe(false);
    }
    expect(() => new RevocationSet().membershipProof('x')).toThrow();
  });
  it('non-revoked ids (below, between, above) have valid non-membership proofs', () => {
    for (let n = 1; n <= 12; n++) {
      const s = new RevocationSet(ids(n));
      const probes = ['a', ...ids(n).map((i) => i.replace('cap-', 'cap-') + 'x'), 'cap-001', 'zzz'];
      for (const x of probes) {
        const p = s.nonMembershipProof(x);
        expect(verifyNonMembership(s.root, p, x)).toBe(true);
      }
    }
  });
  it('a revoked id has no valid non-membership proof', () => {
    const s = new RevocationSet(ids(8));
    for (const id of ids(8)) {
      expect(() => s.nonMembershipProof(id)).toThrow();
      // reuse the proof of a neighbour: must fail
      const p = s.nonMembershipProof(id + 'x');
      expect(verifyNonMembership(s.root, p, id)).toBe(false);
    }
  });
  it('boundaries: empty, smallest, largest', () => {
    const e = new RevocationSet();
    expect(verifyNonMembership(e.root, e.nonMembershipProof('x'), 'x')).toBe(true);
    expect(verifyNonMembership(new RevocationSet(['a']).root, e.nonMembershipProof('x'), 'x')).toBe(false);
    const s = new RevocationSet(['m', 'p', 't']);
    const low = s.nonMembershipProof('a');
    expect(low.lo).toBeUndefined();
    expect(verifyNonMembership(s.root, low, 'a')).toBe(true);
    const high = s.nonMembershipProof('z');
    expect(high.hi).toBeUndefined();
    expect(verifyNonMembership(s.root, high, 'z')).toBe(true);
    // boundary proofs cannot be reused on the wrong side
    expect(verifyNonMembership(s.root, low, 'n')).toBe(false);
    expect(verifyNonMembership(s.root, high, 'n')).toBe(false);
    // empty-claim proof against a non-empty root
    expect(verifyNonMembership(s.root, { size: 0 }, 'a')).toBe(false);
    expect(verifyNonMembership(s.root, { size: 3 }, 'a')).toBe(false);
  });
  it('tampered / non-adjacent / stale proofs fail', () => {
    const s = new RevocationSet(['b', 'd', 'f', 'h']);
    const p = s.nonMembershipProof('e'); // d..f
    expect(verifyNonMembership(s.root, p, 'e')).toBe(true);
    // non-adjacent bracket: b..h around 'e'
    const wide = { size: 4, lo: { id: 'b', proof: s.membershipProof('b') }, hi: { id: 'h', proof: s.membershipProof('h') } };
    expect(verifyNonMembership(s.root, wide, 'e')).toBe(false);
    // swapped leaf id
    expect(verifyNonMembership(s.root, { ...p, lo: { ...p.lo!, id: 'c' } }, 'e')).toBe(false);
    // tampered path hash
    const t = structuredClone(p);
    t.hi!.proof.path[0]!.hash = t.lo!.proof.path[0]!.hash;
    expect(verifyNonMembership(s.root, t, 'e')).toBe(false);
    // lying about size / index
    expect(verifyNonMembership(s.root, { ...p, size: 5 }, 'e')).toBe(false);
    const idx = structuredClone(p);
    idx.lo!.proof.index = 0;
    expect(verifyNonMembership(s.root, idx, 'e')).toBe(false);
    // stale root (before later revocations) does not match the new proof
    const old = s.root;
    s.revoke('e');
    expect(verifyNonMembership(s.root, p, 'e')).toBe(false);
    expect(verifyNonMembership(old, p, 'e')).toBe(true); // valid against the old epoch only
    expect(verifyNonMembership(s.root, { size: 4 } as never, 'e')).toBe(false);
    expect(verifyNonMembership(s.root, null as never, 'e')).toBe(false);
  });
});

describe('revocation checker hook', () => {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const grant = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), caveats: [] });
  const child = attenuate(grant, [], A.secretKey);
  const ctx = { pcactn: { cap_chain: [grant, child] } as unknown as PCActn, grant } as VerifyContext;

  const make = (set: RevocationSet, root = set.root) =>
    createRevocationChecker({
      root: () => root,
      proofFor: (id) => (set.has(id) ? undefined : set.nonMembershipProof(id)),
    });

  it('passes when nothing in the chain is revoked', async () => {
    expect(await make(new RevocationSet(['other']))(ctx)).toEqual({ enforced: true, ok: true });
  });
  it('rejects when the leaf or an ancestor is revoked', async () => {
    const r1 = await make(new RevocationSet([child.id]))(ctx);
    expect(r1).toMatchObject({ enforced: true, ok: false });
    const r2 = await make(new RevocationSet([grant.id]))(ctx);
    expect(r2).toMatchObject({ enforced: true, ok: false });
  });
  it('fails closed on missing root, missing proof, or a forged proof', async () => {
    const s = new RevocationSet(['x']);
    expect(await createRevocationChecker({ root: () => undefined, proofFor: () => undefined })(ctx)).toMatchObject({ ok: false });
    expect(await createRevocationChecker({ root: () => s.root, proofFor: () => undefined })(ctx)).toMatchObject({ ok: false });
    const revoked = new RevocationSet([child.id]);
    const forged = createRevocationChecker({ root: () => revoked.root, proofFor: () => new RevocationSet(['x']).nonMembershipProof(child.id) });
    expect(await forged(ctx)).toMatchObject({ ok: false });
  });
  it('supports a custom ids selector (leaf only)', async () => {
    const set = new RevocationSet([grant.id]);
    const c = createRevocationChecker({ root: () => set.root, proofFor: (id) => (set.has(id) ? undefined : set.nonMembershipProof(id)), ids: () => [child.id] });
    expect(await c(ctx)).toEqual({ enforced: true, ok: true });
  });
});

describe('signed revocation epoch', () => {
  const G = generateKeyPair();
  const gPub = encodeKey(G.publicKey);
  const P = generateKeyPair();
  const A = generateKeyPair();
  const grant = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), caveats: [] });
  const child = attenuate(grant, [], A.secretKey);
  const NOW = 1_000_000;
  const ep = (set: RevocationSet, epoch: number, issued = NOW, over: object = {}) =>
    signRevocationEpoch(G.secretKey, {
      instance_id: 'i', grant_ref: grant.id, epoch, set_size: set.size, root: set.root, issued_at: issued, not_after: issued + REVOCATION_EPOCH_VALIDITY_MS, ...over,
    });
  const ctxAt = (fresh: number, nowEpoch = NOW) => ({ pcactn: { grant_ref: grant.id, freshness: { epoch: fresh }, cap_chain: [grant, child] } as unknown as PCActn, grant, nowEpoch }) as VerifyContext;
  const checker = (e: ReturnType<typeof ep>, set: RevocationSet, last?: number) =>
    createRevocationChecker({
      epoch: () => e,
      guardianPublic: gPub,
      lastAcceptedEpoch: () => last,
      proofFor: (id) => (set.has(id) ? undefined : set.nonMembershipProof(id)),
    });

  it('signs and verifies; refresh interval is shorter than validity', () => {
    const set = new RevocationSet(['x']);
    const e = ep(set, 1);
    expect(checkRevocationEpoch(e, { guardianPublic: gPub, now: NOW, grantRef: grant.id })).toEqual({ ok: true });
    expect(REVOCATION_EPOCH_REFRESH_MS).toBeLessThan(REVOCATION_EPOCH_VALIDITY_MS);
    expect(REVEPOCH_DOMAIN).toBe('atlas-pca/revepoch/v1\0');
    for (const t of [{ epoch: 2 }, { root: 'z' }, { not_after: e.not_after + 1 }, { set_size: 9 }, { grant_ref: 'other' }]) {
      expect(checkRevocationEpoch({ ...e, ...t }, { guardianPublic: gPub, now: NOW }).ok).toBe(false);
    }
    expect(checkRevocationEpoch(e, { guardianPublic: encodeKey(generateKeyPair().publicKey), now: NOW }).ok).toBe(false);
  });

  it('rejects an expired epoch (now > not_after) and one for another grant', () => {
    const e = ep(new RevocationSet(), 0);
    expect(checkRevocationEpoch(e, { guardianPublic: gPub, now: e.not_after }).ok).toBe(true);
    expect(checkRevocationEpoch(e, { guardianPublic: gPub, now: e.not_after + 1 })).toMatchObject({ ok: false, reason: expect.stringContaining('expired') });
    expect(checkRevocationEpoch(e, { guardianPublic: gPub, now: NOW, grantRef: 'someone-else' }).ok).toBe(false);
  });

  it('checker: passes with a fresh epoch; rejects stale/expired/rollback epochs', async () => {
    const set = new RevocationSet(['unrelated']);
    expect(await checker(ep(set, 3), set, 3)(ctxAt(3))).toEqual({ enforced: true, ok: true });
    expect(await checker(ep(set, 3), set)(ctxAt(3, NOW + REVOCATION_EPOCH_VALIDITY_MS + 1))).toMatchObject({ ok: false });
    // rollback: the verifier already accepted epoch 5
    expect(await checker(ep(set, 3), set, 5)(ctxAt(5))).toMatchObject({ ok: false, reason: expect.stringContaining('rollback') });
    // missing epoch / unpinned guardian fail closed
    expect(await createRevocationChecker({ epoch: () => undefined, guardianPublic: gPub, proofFor: () => undefined })(ctxAt(0))).toMatchObject({ ok: false });
    expect(await createRevocationChecker({ epoch: () => ep(set, 1), proofFor: () => set.nonMembershipProof(child.id) })(ctxAt(1))).toMatchObject({ ok: false });
  });

  it('REPLAYED PRE-REVOCATION ROOT: a captured old epoch cannot hide a later revocation', async () => {
    const before = new RevocationSet();
    const after = new RevocationSet([child.id]);
    const oldEpoch = ep(before, 0); // signed, unexpired, but pre-revocation
    const newEpoch = ep(after, 1);
    // attacker presents the OLD signed epoch + a non-membership proof against it, for an action the principal
    // revoked: the verifier has already accepted epoch 1 -> rollback rejection.
    const replay = createRevocationChecker({ epoch: () => oldEpoch, guardianPublic: gPub, lastAcceptedEpoch: () => 1, proofFor: () => before.nonMembershipProof(child.id) });
    expect(await replay(ctxAt(1))).toMatchObject({ ok: false, reason: expect.stringContaining('rollback') });
    // a verifier with no pin is still protected by the signed freshness: the PCActn built after the revocation
    // (freshness.epoch 1) is not satisfied by epoch 0 only when epoch is newer; and an action that predates the
    // new epoch is rejected against the new one.
    expect(await checker(newEpoch, after)(ctxAt(0))).toMatchObject({ ok: false, reason: expect.stringContaining('predates') });
    // and a revoked cap has no valid proof against the true new epoch
    expect(await createRevocationChecker({ epoch: () => newEpoch, guardianPublic: gPub, proofFor: () => before.nonMembershipProof(child.id) })(ctxAt(1))).toMatchObject({ ok: false });
    // root mismatch between a caller-supplied root and the signed epoch
    expect(await createRevocationChecker({ root: () => before.root, epoch: () => newEpoch, guardianPublic: gPub, proofFor: () => before.nonMembershipProof(child.id) })(ctxAt(1))).toMatchObject({ ok: false });
    // onEpochAccepted fires only on success
    let seen = -1;
    await createRevocationChecker({ epoch: () => ep(before, 0), guardianPublic: gPub, proofFor: (id) => before.nonMembershipProof(id), onEpochAccepted: (e) => { seen = e.epoch; } })(ctxAt(0));
    expect(seen).toBe(0);
  });

  it('principal revoke message is domain-separated and verifies under the principal key only', () => {
    const msg = revokeMessage(grant.id, child.id);
    const sig = encodeKey(sign(P.secretKey, msg));
    expect(verifyB64u(encodeKey(P.publicKey), msg, sig)).toBe(true);
    expect(verifyB64u(encodeKey(A.publicKey), msg, sig)).toBe(false);
    expect(verifyB64u(encodeKey(P.publicKey), revokeMessage(grant.id, 'other'), sig)).toBe(false);
  });
});
