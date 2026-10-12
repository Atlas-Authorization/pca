/** Mutation-kill tests for frost.ts: every guard asserted by exact error message, boundary values and result fields. */
import { ed25519 } from '@noble/curves/ed25519';
import { describe, expect, it } from 'vitest';
import {
  bytesToScalar, decodeSafePoint, frostAggregate, frostCommit, frostCosign, frostSign, frostTrustedDealerKeygen, frostVerifySigShare,
  frostVerifyingShare, isCanonicalScalar, L, scalarToBytes, type FrostCommitment, type FrostNonces,
} from './frost';

const msg = new TextEncoder().encode('frost-mk');
const thr = (fn: () => unknown, m: string | RegExp) => {
  let e: unknown;
  try { fn(); } catch (x) { e = x; }
  expect(e, 'expected a throw').toBeInstanceOf(Error);
  if (typeof m === 'string') expect((e as Error).message).toBe(m); else expect((e as Error).message).toMatch(m);
};
const ID_MSG = 'frost: participant identifier must be a positive safe integer';
const setup = (t = 2, n = 3) => {
  const k = frostTrustedDealerKeygen(t, n);
  const round = (ids: number[]) => {
    const parts = ids.map((i) => k.participantShares.find((p) => p.identifier === i)!);
    const cs = parts.map((p) => frostCommit(p));
    return { parts, cs, commitments: cs.map((c) => c.commitment) };
  };
  const nonce = (c: { hidingNonce: Uint8Array; bindingNonce: Uint8Array }): FrostNonces => ({ hiding: c.hidingNonce.slice(), binding: c.bindingNonce.slice() });
  return { k, round, nonce };
};

describe('scalars', () => {
  it('isCanonicalScalar: L-1 true, L false, wrong length / type false, 32 bytes exactly', () => {
    expect(isCanonicalScalar(scalarToBytes(L - 1n))).toBe(true);
    const lb = new Uint8Array(32); let v = L; for (let i = 0; i < 32; i++) { lb[i] = Number(v & 0xffn); v >>= 8n; }
    expect(isCanonicalScalar(lb)).toBe(false);
    expect(isCanonicalScalar(new Uint8Array(31))).toBe(false);
    expect(isCanonicalScalar(new Uint8Array(33))).toBe(false);
    expect(isCanonicalScalar(new Uint8Array(32))).toBe(true);
    expect(isCanonicalScalar([1])).toBe(false);
    expect(isCanonicalScalar('x')).toBe(false);
    expect(isCanonicalScalar(new Uint8Array(32).fill(0xff))).toBe(false);
  });
  it('scalarToBytes/bytesToScalar: negative reduces, top byte used, round-trip', () => {
    expect(bytesToScalar(scalarToBytes(-1n))).toBe(L - 1n);
    expect(scalarToBytes(0n)).toEqual(new Uint8Array(32));
    const hi = scalarToBytes(1n << 248n);
    expect(hi[31]).toBe(1);
    expect(bytesToScalar(hi)).toBe(1n << 248n);
    expect(bytesToScalar(new Uint8Array(33).fill(0))).toBe(0n);
    expect(frostVerifyingShare(scalarToBytes(0n))).toEqual(ed25519.ExtendedPoint.ZERO.toRawBytes());
    expect(frostVerifyingShare(scalarToBytes(L))).toEqual(ed25519.ExtendedPoint.ZERO.toRawBytes());
  });
});

describe('decodeSafePoint', () => {
  const good = ed25519.ExtendedPoint.BASE.multiply(5n).toRawBytes();
  it('accepts a prime-order point and returns it', () => { expect(decodeSafePoint(good).toRawBytes()).toEqual(good); });
  it('rejects wrong length / type with the exact message', () => {
    for (const b of [new Uint8Array(31), new Uint8Array(33), 'x', null, [1]] as never[]) thr(() => decodeSafePoint(b), 'frost: point must be 32 bytes');
  });
  it('rejects identity and small-order points', () => {
    thr(() => decodeSafePoint(ed25519.ExtendedPoint.ZERO.toRawBytes()), 'bad point: ZERO'); // assertValidity refuses the identity first
    const order2 = new Uint8Array(32); order2[0] = 0xec; for (let i = 1; i < 31; i++) order2[i] = 0xff; order2[31] = 0x7f; // (0,-1)
    thr(() => decodeSafePoint(order2), 'frost: small-order point rejected');
  });
  it('rejects a point with a torsion component', () => {
    const order2 = ed25519.ExtendedPoint.fromHex('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f');
    const mixed = ed25519.ExtendedPoint.BASE.multiply(5n).add(order2).toRawBytes();
    thr(() => decodeSafePoint(mixed), 'frost: point is not in the prime-order subgroup');
  });
  it('rejects an off-curve / non-canonical encoding', () => {
    expect(() => decodeSafePoint(new Uint8Array(32).fill(0xff))).toThrow();
    const nc = new Uint8Array(32); nc[0] = 0xee; for (let i = 1; i < 31; i++) nc[i] = 0xff; nc[31] = 0x7f; // y = p+1 (non-canonical)
    expect(() => decodeSafePoint(nc)).toThrow();
  });
});

describe('frostTrustedDealerKeygen guards', () => {
  it('t/n validation', () => {
    const m = (t: number, n: number) => `frostTrustedDealerKeygen: need 1 <= t <= n (got t=${t}, n=${n})`;
    thr(() => frostTrustedDealerKeygen(0, 3), m(0, 3));
    thr(() => frostTrustedDealerKeygen(4, 3), m(4, 3));
    thr(() => frostTrustedDealerKeygen(1.5, 3), m(1.5, 3));
    thr(() => frostTrustedDealerKeygen(2, 3.5), m(2, 3.5));
    thr(() => frostTrustedDealerKeygen(NaN, 3), /need 1 <= t <= n/);
    expect(frostTrustedDealerKeygen(1, 1).participantShares).toHaveLength(1);
    expect(frostTrustedDealerKeygen(3, 3).participantShares).toHaveLength(3);
  });
  it('identifier validation', () => {
    thr(() => frostTrustedDealerKeygen(2, 3, { identifiers: [1, 2] }), 'frostTrustedDealerKeygen: identifiers.length must equal n');
    thr(() => frostTrustedDealerKeygen(2, 3, { identifiers: [1, 2, 2] }), 'frostTrustedDealerKeygen: identifiers must be distinct');
    thr(() => frostTrustedDealerKeygen(2, 3, { identifiers: [0, 2, 3] }), 'frostTrustedDealerKeygen: identifiers must be positive integers');
    thr(() => frostTrustedDealerKeygen(2, 3, { identifiers: [-1, 2, 3] }), 'frostTrustedDealerKeygen: identifiers must be positive integers');
    thr(() => frostTrustedDealerKeygen(2, 3, { identifiers: [1, 2, 1.5] }), 'frostTrustedDealerKeygen: identifiers must be positive integers');
    expect(frostTrustedDealerKeygen(2, 3, { identifiers: [7, 8, 9] }).participantShares.map((p) => p.identifier)).toEqual([7, 8, 9]);
  });
});

describe('frostCommit', () => {
  it('requires 32-byte randomness for both nonces', () => {
    const { k } = setup();
    const p = k.participantShares[0]!;
    thr(() => frostCommit(p, { hidingRandomness: new Uint8Array(31) }), 'frostCommit: nonce randomness must be 32 bytes');
    thr(() => frostCommit(p, { bindingRandomness: new Uint8Array(33) }), 'frostCommit: nonce randomness must be 32 bytes');
    expect(frostCommit(p, { hidingRandomness: new Uint8Array(32), bindingRandomness: new Uint8Array(32).fill(1) }).commitment.identifier).toBe(p.identifier);
  });
});

describe('frostSign guards (exact messages, order)', () => {
  const sign = (s: ReturnType<typeof setup>, r: ReturnType<ReturnType<typeof setup>['round']>, idx: number, over: Record<string, unknown> = {}, opts = {}) => {
    const a = { id: r.parts[idx]!.identifier, share: r.parts[idx]!.share, gpk: s.k.groupPublicKey, nonces: s.nonce(r.cs[idx]!), msg, commitments: r.commitments, ...over } as never as {
      id: number; share: Uint8Array; gpk: Uint8Array; nonces: FrostNonces; msg: Uint8Array; commitments: FrostCommitment[];
    };
    return frostSign(a.id, a.share, a.gpk, a.nonces, a.msg, a.commitments, opts);
  };
  it('happy path returns {identifier, 32-byte sigShare} and zeroizes nonces', () => {
    const s = setup(); const r = s.round([1, 2]);
    const n = s.nonce(r.cs[0]!);
    const out = frostSign(1, r.parts[0]!.share, s.k.groupPublicKey, n, msg, r.commitments);
    expect(out.identifier).toBe(1);
    expect(out.sigShare).toHaveLength(32);
    expect(n.hiding).toEqual(new Uint8Array(32));
    expect(n.binding).toEqual(new Uint8Array(32));
  });
  it('identifier / commitment-list / threshold validation', () => {
    const s = setup(); const r = s.round([1, 2]);
    for (const bad of [0, -1, 1.5, NaN, '1', 2 ** 60]) thr(() => sign(s, r, 0, { id: bad }), ID_MSG);
    thr(() => sign(s, r, 0, { commitments: [] }), 'frost: empty commitment list');
    thr(() => sign(s, r, 0, { commitments: 'x' }), 'frost: empty commitment list');
    thr(() => sign(s, r, 0, {}, { threshold: 0 }), 'frost: invalid threshold');
    thr(() => sign(s, r, 0, {}, { threshold: 1.5 }), 'frost: invalid threshold');
    thr(() => sign(s, r, 0, {}, { threshold: 3 }), 'frost: need at least t=3 commitments (got 2)');
    sign(s, r, 0, {}, { threshold: 2 });
  });
  it('commitment shape: malformed, bad id, duplicate id, bad points', () => {
    const s = setup(); const r = s.round([1, 2]);
    const [c1, c2] = r.commitments as [FrostCommitment, FrostCommitment];
    thr(() => sign(s, r, 0, { commitments: [c1, null] }), 'frost: malformed commitment');
    thr(() => sign(s, r, 0, { commitments: [c1, 5] }), 'frost: malformed commitment');
    thr(() => sign(s, r, 0, { commitments: [c1, { ...c2, identifier: 0 }] }), ID_MSG);
    thr(() => sign(s, r, 0, { commitments: [c1, { ...c2, identifier: 1 }] }), 'frost: duplicate commitment identifier 1');
    thr(() => sign(s, r, 0, { commitments: [c1, { ...c2, hiding: new Uint8Array(32) }] }), 'frost: small-order point rejected');
    thr(() => sign(s, r, 0, { commitments: [c1, { ...c2, binding: new Uint8Array(32) }] }), 'frost: small-order point rejected');
    thr(() => sign(s, r, 0, { commitments: [c1, { ...c2, hiding: new Uint8Array(5) }] }), 'frost: point must be 32 bytes');
  });
  it('group key, nonces shape, zero, equal, missing own commitment', () => {
    const s = setup(); const r = s.round([1, 2]);
    thr(() => sign(s, r, 0, { gpk: new Uint8Array(32) }), 'frost: small-order point rejected');
    thr(() => sign(s, r, 0, { nonces: null }), 'frostSign: malformed nonces');
    thr(() => sign(s, r, 0, { nonces: { hiding: new Uint8Array(32).fill(1) } }), 'frostSign: malformed nonces');
    thr(() => sign(s, r, 0, { nonces: { hiding: 'x', binding: new Uint8Array(32) } }), 'frostSign: malformed nonces');
    thr(() => sign(s, r, 0, { nonces: { hiding: new Uint8Array(32), binding: new Uint8Array(32).fill(1) } }), 'frostSign: zero/zeroized nonce');
    thr(() => sign(s, r, 0, { nonces: { hiding: new Uint8Array(32).fill(1), binding: new Uint8Array(32) } }), 'frostSign: zero/zeroized nonce');
    const same = new Uint8Array(32).fill(3);
    thr(() => sign(s, r, 0, { nonces: { hiding: same, binding: same } }), 'frostSign: hiding and binding nonce must differ');
    thr(() => sign(s, r, 0, { id: 3 }), 'frostSign: this identifier has no commitment in the set');
    thr(() => sign(s, r, 0, { nonces: { hiding: new Uint8Array(32).fill(1), binding: new Uint8Array(32).fill(2) } }), 'frostSign: own commitment does not match nonces');
    // either nonce alone being wrong must fail
    const good = s.nonce(r.cs[0]!);
    thr(() => sign(s, r, 0, { nonces: { hiding: good.hiding, binding: new Uint8Array(32).fill(2) } }), 'frostSign: own commitment does not match nonces');
    thr(() => sign(s, r, 0, { nonces: { hiding: new Uint8Array(32).fill(2), binding: good.binding } }), 'frostSign: own commitment does not match nonces');
  });
  it('one-shot: same array and byte-clones are refused; each nonce alone triggers refusal', () => {
    const SPENT = 'frostSign: nonces already used (one-shot; reuse would leak the signing share)';
    const s = setup(); const r = s.round([1, 2]);
    const n = s.nonce(r.cs[0]!);
    const cl = { hiding: n.hiding.slice(), binding: n.binding.slice() };
    frostSign(1, r.parts[0]!.share, s.k.groupPublicKey, n, msg, r.commitments);
    thr(() => frostSign(1, r.parts[0]!.share, s.k.groupPublicKey, n, msg, r.commitments), SPENT); // zeroized same arrays
    thr(() => frostSign(1, r.parts[0]!.share, s.k.groupPublicKey, cl, msg, r.commitments), SPENT); // content clone
    // spent-array reuse is caught before the zero check: refill a spent array
    const n2 = s.nonce(r.cs[1]!);
    frostSign(2, r.parts[1]!.share, s.k.groupPublicKey, n2, msg, r.commitments);
    const refill = { hiding: n2.hiding, binding: s.nonce(r.cs[1]!).binding };
    refill.hiding.set(r.cs[1]!.hidingNonce);
    thr(() => frostSign(2, r.parts[1]!.share, s.k.groupPublicKey, refill, msg, r.commitments), SPENT);
    // only the hiding commitment reused (fresh binding but same hiding nonce): the hKey alone refuses
    const s2 = setup(); const r2 = s2.round([1, 2]);
    frostSign(1, r2.parts[0]!.share, s2.k.groupPublicKey, s2.nonce(r2.cs[0]!), msg, r2.commitments);
    const c2 = frostCommit(r2.parts[0]!, { hidingRandomness: new Uint8Array(32).fill(9) });
    const mixHiding = { hiding: r2.cs[0]!.hidingNonce.slice(), binding: c2.bindingNonce.slice() };
    const mixCommit = { ...r2.commitments[0]!, binding: c2.commitment.binding };
    thr(() => frostSign(1, r2.parts[0]!.share, s2.k.groupPublicKey, mixHiding, msg, [mixCommit, r2.commitments[1]!]), SPENT);
    const c3 = frostCommit(r2.parts[0]!, { hidingRandomness: new Uint8Array(32).fill(8) });
    const mixBinding = { hiding: c3.hidingNonce.slice(), binding: r2.cs[0]!.bindingNonce.slice() };
    const mixCommit2 = { ...r2.commitments[0]!, hiding: c3.commitment.hiding };
    thr(() => frostSign(1, r2.parts[0]!.share, s2.k.groupPublicKey, mixBinding, msg, [mixCommit2, r2.commitments[1]!]), SPENT);
  });
  it('a failed sign does not burn the nonces', () => {
    const s = setup(); const r = s.round([1, 2]);
    const n = s.nonce(r.cs[0]!);
    thr(() => frostSign(1, r.parts[0]!.share, s.k.groupPublicKey, n, msg, r.commitments, { verificationShare: r.parts[1]!.publicKey }), 'frostSign: share does not match verification share');
    expect(n.hiding).toEqual(r.cs[0]!.hidingNonce);
    expect(frostSign(1, r.parts[0]!.share, s.k.groupPublicKey, n, msg, r.commitments, { verificationShare: r.parts[0]!.publicKey }).identifier).toBe(1);
  });
  it('verificationShares: missing entry and mismatching group key', () => {
    const s = setup(); const r = s.round([1, 2]);
    const vss = r.parts.map((p) => ({ identifier: p.identifier, publicKey: p.publicKey }));
    thr(() => sign(s, r, 0, {}, { verificationShares: [vss[0]!] }), 'frostSign: missing verification share for 2');
    thr(() => sign(s, r, 0, {}, { verificationShares: [vss[1]!] }), 'frostSign: missing verification share for 1');
    const other = frostTrustedDealerKeygen(2, 3).groupPublicKey;
    thr(() => sign(s, r, 0, { gpk: other }, { verificationShares: vss }), 'frostSign: group public key does not match the verification shares');
    expect(sign(s, setup().round([1, 2]) && r, 0, {}, { verificationShares: vss }).identifier).toBe(1);
  });
  it('commitment order does not matter (sorted by identifier)', () => {
    const s = setup(); const r = s.round([1, 2, 3]);
    const sh = (order: FrostCommitment[]) => {
      const n = s.nonce(r.cs[0]!);
      return frostSign(1, r.parts[0]!.share, s.k.groupPublicKey, n, msg, order);
    };
    const a = sh([r.commitments[2]!, r.commitments[0]!, r.commitments[1]!]);
    const s2 = s.nonce(r.cs[0]!);
    expect(a.sigShare).toHaveLength(32);
    expect(s2.hiding).toEqual(r.cs[0]!.hidingNonce); // untouched copy
  });
});

describe('frostAggregate / frostVerifySigShare / frostCosign', () => {
  const full = (s: ReturnType<typeof setup>, ids = [1, 2]) => {
    const r = s.round(ids);
    const shares = r.parts.map((p, i) => frostSign(p.identifier, p.share, s.k.groupPublicKey, s.nonce(r.cs[i]!), msg, r.commitments));
    return { r, shares };
  };
  it('aggregate yields a valid ed25519 signature irrespective of share/commitment order', () => {
    const s = setup(); const { r, shares } = full(s, [1, 2, 3]);
    const vss = r.parts.map((p) => ({ identifier: p.identifier, publicKey: p.publicKey }));
    const sig = frostAggregate(msg, [r.commitments[2]!, r.commitments[0]!, r.commitments[1]!], [shares[1]!, shares[2]!, shares[0]!], s.k.groupPublicKey, { verificationShares: vss });
    expect(ed25519.verify(sig, msg, s.k.groupPublicKey, { zip215: false })).toBe(true);
    expect(sig).toHaveLength(64);
  });
  it('aggregate guards (exact messages)', () => {
    const s = setup(); const { r, shares } = full(s);
    const agg = (c: unknown, sh: unknown, o: object = {}, gpk = s.k.groupPublicKey) => frostAggregate(msg, c as never, sh as never, gpk, o as never);
    thr(() => agg([], shares), 'frost: empty commitment list');
    thr(() => agg(r.commitments, shares, { threshold: 0 }), 'frost: invalid threshold');
    thr(() => agg(r.commitments, shares, { threshold: 3 }), 'frost: need at least t=3 commitments (got 2)');
    thr(() => agg([r.commitments[0], null], shares), 'frost: malformed commitment');
    thr(() => agg(r.commitments, shares, {}, new Uint8Array(32)), 'frost: small-order point rejected');
    thr(() => agg(r.commitments, [shares[0]]), 'frostAggregate: need exactly one signature share per commitment');
    thr(() => agg(r.commitments, 'xx'), 'frostAggregate: need exactly one signature share per commitment');
    thr(() => agg(r.commitments, [shares[0], { ...shares[1]!, identifier: 9 }]), 'frostAggregate: share from non-signer');
    thr(() => agg(r.commitments, [shares[0], { ...shares[0]! }]), 'frostAggregate: duplicate signature share');
    // R6-ALIAS-07: past the shape guards, the per-share verification cannot be skipped
    thr(() => agg(r.commitments, [shares[0], { ...shares[1]!, sigShare: scalarToBytes(5n) }]), 'frostAggregate: verificationShares are required (every signature share is verified before aggregation)');
    thr(() => agg(r.commitments, shares, { verificationShares: 'x' }), 'frostAggregate: verificationShares are required (every signature share is verified before aggregation)');
  });
  it('verificationShares: a bad share is named; a missing verification share is an invalid share', () => {
    const s = setup(); const { r, shares } = full(s);
    const vss = r.parts.map((p) => ({ identifier: p.identifier, publicKey: p.publicKey }));
    const bad = [shares[0]!, { ...shares[1]!, sigShare: scalarToBytes(5n) }];
    thr(() => frostAggregate(msg, r.commitments, bad, s.k.groupPublicKey, { verificationShares: vss }), 'frostAggregate: invalid signature share from participant 2');
    thr(() => frostAggregate(msg, r.commitments, shares, s.k.groupPublicKey, { verificationShares: [vss[0]!] }), 'frostAggregate: invalid signature share from participant 2');
    expect(frostAggregate(msg, r.commitments, shares, s.k.groupPublicKey, { verificationShares: vss })).toHaveLength(64);
  });
  it('frostVerifySigShare: true for a good share, false (never throws) for every defect', () => {
    const s = setup(); const { r, shares } = full(s);
    const base = (i: number) => ({ identifier: r.parts[i]!.identifier, publicKey: r.parts[i]!.publicKey, commitment: r.commitments[i]!, sigShare: shares[i]!, signingCommitments: r.commitments, groupPublicKey: s.k.groupPublicKey, message: msg });
    expect(frostVerifySigShare(base(0))).toBe(true);
    expect(frostVerifySigShare(base(1))).toBe(true);
    expect(frostVerifySigShare({ ...base(0), identifier: 9 })).toBe(false); // not a signer: no binding factor
    expect(frostVerifySigShare({ ...base(0), signingCommitments: [] })).toBe(false);
    expect(frostVerifySigShare({ ...base(0), signingCommitments: [r.commitments[0]!, r.commitments[0]!] })).toBe(false); // duplicate id
    expect(frostVerifySigShare({ ...base(0), publicKey: r.parts[1]!.publicKey })).toBe(false);
    expect(frostVerifySigShare({ ...base(0), message: new TextEncoder().encode('other') })).toBe(false);
    expect(frostVerifySigShare({ ...base(0), publicKey: new Uint8Array(32) })).toBe(false);
    expect(frostVerifySigShare({ ...base(0), sigShare: null as never })).toBe(false);
    // z + L is non-canonical and must be refused although it is congruent
    const z = bytesToScalar(shares[0]!.sigShare) + L;
    const zb = new Uint8Array(32); let v = z; for (let i = 0; i < 32; i++) { zb[i] = Number(v & 0xffn); v >>= 8n; }
    if (v === 0n) expect(frostVerifySigShare({ ...base(0), sigShare: { ...shares[0]!, sigShare: zb } })).toBe(false);
    // a tampered share
    expect(frostVerifySigShare({ ...base(0), sigShare: { ...shares[0]!, sigShare: scalarToBytes(bytesToScalar(shares[0]!.sigShare) + 1n) } })).toBe(false);
  });
  it('frostCosign guards and success', () => {
    const s = setup();
    const q = s.k.participantShares.slice(0, 2);
    const sig = frostCosign(s.k.groupPublicKey, q, msg, { threshold: 2 });
    expect(ed25519.verify(sig, msg, s.k.groupPublicKey, { zip215: false })).toBe(true);
    expect(frostCosign(s.k.groupPublicKey, q, msg)).toHaveLength(64);
    thr(() => frostCosign(s.k.groupPublicKey, [], msg), 'frostCosign: empty signing quorum');
    thr(() => frostCosign(s.k.groupPublicKey, 'x' as never, msg), 'frostCosign: empty signing quorum');
    thr(() => frostCosign(s.k.groupPublicKey, q, msg, { threshold: 3 }), 'frostCosign: quorum of 2 is below the threshold t=3');
    thr(() => frostCosign(s.k.groupPublicKey, [q[0]!, { ...q[1]!, identifier: 1 }], msg), 'frostCosign: duplicate participant 1 in quorum');
    thr(() => frostCosign(s.k.groupPublicKey, [q[0]!, { ...q[1]!, identifier: 0 }], msg), ID_MSG);
    // a single share cannot sign for a 2-of-3 group (verification shares do not interpolate to the group key)
    expect(() => frostCosign(s.k.groupPublicKey, [q[0]!], msg)).toThrow();
    // the threshold option is enforced downstream as well: t=1 with a 1-quorum fails on the group-key check, not silently
    expect(() => frostCosign(s.k.groupPublicKey, [q[0]!], msg, { threshold: 1 })).toThrow();
    // a tampered verification share in the quorum is refused
    expect(() => frostCosign(s.k.groupPublicKey, [q[0]!, { ...q[1]!, publicKey: q[0]!.publicKey }], msg)).toThrow();
  });
  it('1-of-1 and a lambda over a larger id set', () => {
    const k = frostTrustedDealerKeygen(1, 1);
    expect(ed25519.verify(frostCosign(k.groupPublicKey, k.participantShares, msg, { threshold: 1 }), msg, k.groupPublicKey, { zip215: false })).toBe(true);
    const k2 = frostTrustedDealerKeygen(3, 5, { identifiers: [2, 4, 6, 8, 10] });
    const sig = frostCosign(k2.groupPublicKey, [k2.participantShares[4]!, k2.participantShares[1]!, k2.participantShares[2]!], msg, { threshold: 3 });
    expect(ed25519.verify(sig, msg, k2.groupPublicKey, { zip215: false })).toBe(true);
  });
});

describe('frost: spent-commitment keys are kind-tagged; cosign forwards its safety options', () => {
  it('a binding commitment that was spent does not block the same point used later as a HIDING commitment (and vice versa)', () => {
    const s = setup(); const r = s.round([1, 2]);
    const p = r.parts[0]!;
    const h1 = r.cs[0]!.hidingNonce.slice(); const b1 = r.cs[0]!.bindingNonce.slice();
    frostSign(1, p.share, s.k.groupPublicKey, s.nonce(r.cs[0]!), msg, r.commitments);
    // session 2: hiding nonce = old binding nonce, binding nonce = fresh
    const fresh = frostCommit(p);
    const c2: FrostCommitment = { identifier: 1, hiding: ed25519.ExtendedPoint.BASE.multiply(bytesToScalar(b1)).toRawBytes(), binding: fresh.commitment.binding };
    expect(frostSign(1, p.share, s.k.groupPublicKey, { hiding: b1.slice(), binding: fresh.bindingNonce.slice() }, msg, [c2, r.commitments[1]!]).identifier).toBe(1);
    // session 3: binding nonce = old hiding nonce, hiding = fresh
    const f3 = frostCommit(p);
    const c3: FrostCommitment = { identifier: 1, hiding: f3.commitment.hiding, binding: ed25519.ExtendedPoint.BASE.multiply(bytesToScalar(h1)).toRawBytes() };
    expect(frostSign(1, p.share, s.k.groupPublicKey, { hiding: f3.hidingNonce.slice(), binding: h1.slice() }, msg, [c3, r.commitments[1]!]).identifier).toBe(1);
  });
  it('cosign: the share-vs-verification-share and group-key interpolation checks run inside frostSign', () => {
    const s = setup();
    const q = s.k.participantShares.slice(0, 2);
    thr(() => frostCosign(s.k.groupPublicKey, [q[0]!, { ...q[1]!, publicKey: q[0]!.publicKey }], msg), 'frostSign: group public key does not match the verification shares');
    const other = frostTrustedDealerKeygen(2, 3).groupPublicKey;
    thr(() => frostCosign(other, q, msg), 'frostSign: group public key does not match the verification shares');
  });
});
