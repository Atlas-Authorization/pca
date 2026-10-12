/** Mutation-kill tests (round 2) for frost.ts: the one-shot nonce-reuse guard (WeakSet + content-keyed FIFO), validation order, threshold forwarding. */
import { ed25519 } from '@noble/curves/ed25519';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  bytesToScalar, frostAggregate, frostCommit, frostCosign, frostSign, frostTrustedDealerKeygen, frostVerifySigShare,
  H1, H2, H4, H5, L, scalarToBytes, SPENT_COMMITMENT_CAP, type FrostCommitment, type FrostNonces,
} from './frost';

const msg = new TextEncoder().encode('frost-mk-2');
const P = ed25519.ExtendedPoint;
const USED = 'frostSign: nonces already used (one-shot; reuse would leak the signing share)';
const ID_MSG = 'frost: participant identifier must be a positive safe integer';
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const thr = (fn: () => unknown, m: string) => {
  let e: unknown;
  try { fn(); } catch (x) { e = x; }
  expect(e, 'expected a throw').toBeInstanceOf(Error);
  expect((e as Error).message).toBe(m);
};
const setup = (t = 2, n = 3, identifiers?: number[]) => {
  const k = frostTrustedDealerKeygen(t, n, identifiers ? { identifiers } : {});
  const round = (ids: number[]) => {
    const parts = ids.map((i) => k.participantShares.find((p) => p.identifier === i)!);
    const cs = parts.map((p) => frostCommit(p));
    return { parts, cs, commitments: cs.map((c) => c.commitment) };
  };
  const nonce = (c: { hidingNonce: Uint8Array; bindingNonce: Uint8Array }): FrostNonces => ({ hiding: c.hidingNonce.slice(), binding: c.bindingNonce.slice() });
  return { k, round, nonce };
};

afterEach(() => { vi.restoreAllMocks(); });

/** Run `fn` while recording every string added to any Set; returns the added keys and the Set instances that received a nonce key. */
function recordSetAdds(fn: () => void) {
  const keys: string[] = [];
  const sets = new Set<Set<string>>();
  const orig = Set.prototype.add;
  vi.spyOn(Set.prototype, 'add').mockImplementation(function (this: Set<unknown>, v: unknown) {
    if (typeof v === 'string' && /^[hb][0-9a-f]{64}$/.test(v)) { keys.push(v); sets.add(this as Set<string>); }
    return orig.call(this, v);
  });
  try { fn(); } finally { vi.restoreAllMocks(); }
  return { keys, sets };
}

/** A fresh signing round for participant 1 whose hiding and binding commitments both contain a byte < 0x10 (exercises zero-padding). */
function signOnce(opts: { padded?: boolean } = {}) {
  const s = setup();
  for (let tries = 0; tries < 400; tries++) {
    const r = s.round([1, 2]);
    const c = r.commitments[0]!;
    const small = (b: Uint8Array) => b.some((x) => x < 16);
    if (opts.padded && !(small(c.hiding) && small(c.binding))) continue;
    const mine = r.cs[0]!;
    const sig = () => frostSign(1, r.parts[0]!.share, s.k.groupPublicKey, s.nonce(mine), msg, r.commitments);
    return { s, r, sig, c };
  }
  throw new Error('no commitment with small bytes found');
}

describe('spent-commitment key format (content-keyed one-shot guard)', () => {
  it("records exactly 'h'+full-hex(hiding) and 'b'+full-hex(binding), zero-padded per byte", () => {
    const o = signOnce({ padded: true });
    expect(o.c.hiding.some((x) => x < 16) && o.c.binding.some((x) => x < 16)).toBe(true);
    const { keys } = recordSetAdds(() => { o.sig(); });
    expect(keys).toEqual(['h' + hex(o.c.hiding), 'b' + hex(o.c.binding)]);
    expect(keys[0]).toHaveLength(65);
    expect(keys[1]).toHaveLength(65);
  });
});

describe('spent-commitment FIFO cap', () => {
  const grab = () => {
    const o = signOnce();
    const { sets } = recordSetAdds(() => { o.sig(); });
    expect(sets.size).toBe(1);
    return [...sets][0]!;
  };
  const fill = (spent: Set<string>, total: number) => {
    spent.clear();
    spent.add('old0');
    spent.add('old1');
    for (let i = 2; i < total; i++) spent.add('f' + i);
    expect(spent.size).toBe(total);
  };
  it('cap constant is 262144', () => { expect(SPENT_COMMITMENT_CAP).toBe(262_144); });
  it('exceeding the cap evicts exactly the oldest entry (FIFO) and keeps the new keys', () => {
    const spent = grab();
    fill(spent, SPENT_COMMITMENT_CAP - 1); // h -> CAP (no evict), b -> CAP+1 (evict oldest)
    const o = signOnce();
    o.sig();
    expect(spent.has('old0')).toBe(false);
    expect(spent.has('old1')).toBe(true);
    expect(spent.has('f2')).toBe(true);
    expect(spent.size).toBe(SPENT_COMMITMENT_CAP);
    expect(spent.has('h' + hex(o.c.hiding))).toBe(true);
    expect(spent.has('b' + hex(o.c.binding))).toBe(true);
    spent.clear();
  });
  it('reaching exactly the cap does NOT evict (strictly greater than)', () => {
    const spent = grab();
    fill(spent, SPENT_COMMITMENT_CAP - 2); // h -> CAP-1, b -> CAP: no eviction
    const o = signOnce();
    o.sig();
    expect(spent.has('old0')).toBe(true);
    expect(spent.size).toBe(SPENT_COMMITMENT_CAP);
    spent.clear();
  });
  it('an evicted-too-old entry is the only thing forgotten: a recent spent nonce clone is still refused', () => {
    const o = signOnce();
    o.sig();
    thr(() => o.sig(), USED); // byte-clone of the spent nonces (same commitments)
  });
});

describe('WeakSet one-shot (exact error before zero check)', () => {
  it('a zeroized spent array mixed with a fresh one is refused as already used (either position)', () => {
    const s = setup();
    const r1 = s.round([1, 2]);
    const n1 = s.nonce(r1.cs[0]!);
    frostSign(1, r1.parts[0]!.share, s.k.groupPublicKey, n1, msg, r1.commitments);
    expect(n1.hiding).toEqual(new Uint8Array(32));
    const r2 = s.round([1, 2]);
    const f2 = s.nonce(r2.cs[0]!);
    thr(() => frostSign(1, r2.parts[0]!.share, s.k.groupPublicKey, { hiding: n1.hiding, binding: f2.binding }, msg, r2.commitments), USED);
    const r3 = s.round([1, 2]);
    const f3 = s.nonce(r3.cs[0]!);
    thr(() => frostSign(1, r3.parts[0]!.share, s.k.groupPublicKey, { hiding: f3.hiding, binding: n1.binding }, msg, r3.commitments), USED);
    // and the whole spent pair is refused the same way
    thr(() => frostSign(1, r3.parts[0]!.share, s.k.groupPublicKey, n1, msg, r3.commitments), USED);
  });
});

describe('frostSign validates every commitment point before anything else', () => {
  const order2 = new Uint8Array(32); order2[0] = 0xec; for (let i = 1; i < 31; i++) order2[i] = 0xff; order2[31] = 0x7f;
  const run = (bad: 'hiding' | 'binding') => {
    const s = setup();
    const r = s.round([1, 2]);
    const cm: FrostCommitment[] = [r.commitments[0]!, { ...r.commitments[1]!, [bad]: order2 }];
    const zeroed: FrostNonces = { hiding: new Uint8Array(32), binding: new Uint8Array(32) }; // would otherwise fail 'zero/zeroized nonce'
    thr(() => frostSign(1, r.parts[0]!.share, s.k.groupPublicKey, zeroed, msg, cm), 'frost: small-order point rejected');
  };
  it('bad hiding point of another signer is rejected first', () => { run('hiding'); });
  it('bad binding point of another signer is rejected first', () => { run('binding'); });
  it('frostAggregate rejects a bad commitment point before the group key', () => {
    const s = setup();
    const r = s.round([1, 2]);
    const cm: FrostCommitment[] = [r.commitments[0]!, { ...r.commitments[1]!, hiding: order2 }];
    thr(() => frostAggregate(msg, cm, [], new Uint8Array(32), {} as never), 'frost: small-order point rejected');
    const cm2: FrostCommitment[] = [r.commitments[0]!, { ...r.commitments[1]!, binding: order2 }];
    thr(() => frostAggregate(msg, cm2, [], new Uint8Array(32), {} as never), 'frost: small-order point rejected');
  });
});

describe('frostVerifySigShare validates the commitment list', () => {
  it('a duplicated commitment is refused even if the share is valid for the duplicated list', () => {
    const s = setup();
    const r = s.round([1, 2]);
    const [c1, c2] = r.commitments as [FrostCommitment, FrostCommitment];
    const gpk = s.k.groupPublicKey;
    const ref = (list: FrostCommitment[]) => {
      const enc = new Uint8Array(list.length * 96);
      list.forEach((c, i) => { enc.set(scalarToBytes(BigInt(c.identifier)), i * 96); enc.set(c.hiding, i * 96 + 32); enc.set(c.binding, i * 96 + 64); });
      const prefix = new Uint8Array([...gpk, ...H4(msg), ...H5(enc)]);
      const rho = (id: number) => H1(new Uint8Array([...prefix, ...scalarToBytes(BigInt(id))]));
      let R = P.ZERO;
      for (const c of list) R = R.add(P.fromHex(c.hiding)).add(P.fromHex(c.binding).multiply(rho(c.identifier)));
      const c = H2(new Uint8Array([...R.toRawBytes(), ...gpk, ...msg]));
      const d = bytesToScalar(r.cs[0]!.hidingNonce), e = bytesToScalar(r.cs[0]!.bindingNonce);
      const sk = bytesToScalar(r.parts[0]!.share);
      const ids = [...new Set(list.map((x) => x.identifier))].sort((a, b) => a - b);
      const x1 = 1n; let num = 1n, den = 1n;
      for (const j of ids) if (j !== 1) { num = (num * BigInt(j)) % L; den = (den * (BigInt(j) - x1)) % L; }
      let inv = 1n, b = den, ex = L - 2n;
      while (ex > 0n) { if (ex & 1n) inv = (inv * b) % L; b = (b * b) % L; ex >>= 1n; }
      const lam = (num * inv) % L;
      return ((d + e * rho(1) + lam * sk * c) % L + L) % L;
    };
    const check = (list: FrostCommitment[]) => frostVerifySigShare({
      identifier: 1, publicKey: r.parts[0]!.publicKey, commitment: c1,
      sigShare: { identifier: 1, sigShare: scalarToBytes(ref(list)) }, signingCommitments: list, groupPublicKey: gpk, message: msg,
    });
    expect(check([c1, c2])).toBe(true); // reference model is right
    expect(check([c1, c1, c2])).toBe(false); // duplicate identifier rejected
  });
});

describe('frostCosign', () => {
  it('rejects an invalid identifier in the quorum with the id message (before duplicate detection)', () => {
    const s = setup();
    const p = s.k.participantShares[0]!;
    thr(() => frostCosign(s.k.groupPublicKey, [{ ...p, identifier: 0 }, { ...p, identifier: 0 }], msg), ID_MSG);
    thr(() => frostCosign(s.k.groupPublicKey, [{ ...p, identifier: -3 }, { ...p, identifier: -3 }], msg), ID_MSG);
  });
  it('forwards the threshold to every frostSign and to frostAggregate', () => {
    const s = setup(2, 3, [11, 12, 13]);
    const quorum2 = s.k.participantShares.slice(0, 2);
    const quorum3 = s.k.participantShares;
    const count = (quorum: typeof quorum2, threshold: number | undefined) => {
      const spy = vi.spyOn(Number, 'isSafeInteger');
      const sig = frostCosign(s.k.groupPublicKey, quorum, msg, threshold === undefined ? {} : { threshold });
      const n = spy.mock.calls.filter((c) => c[0] === 2).length;
      spy.mockRestore();
      expect(ed25519.verify(sig, msg, s.k.groupPublicKey)).toBe(true);
      return n;
    };
    expect(count(quorum2, 2)).toBe(3); // 2 signers + the aggregate
    expect(count(quorum3, 2)).toBe(4); // 3 signers + the aggregate
    expect(count(quorum2, undefined)).toBe(0);
  });
  it('rejects a quorum below the threshold with the exact message', () => {
    const s = setup();
    thr(() => frostCosign(s.k.groupPublicKey, s.k.participantShares.slice(0, 1), msg, { threshold: 2 }), 'frostCosign: quorum of 1 is below the threshold t=2');
  });
  it('re-verifies every signature share in the aggregate (same work as the manual flow with verificationShares)', () => {
    const s = setup();
    const quorum = s.k.participantShares.slice(0, 2);
    const vss = quorum.map((p) => ({ identifier: p.identifier, publicKey: p.publicKey }));
    const eq = (fn: () => void) => {
      const spy = vi.spyOn(P.prototype, 'equals');
      fn();
      const n = spy.mock.calls.length;
      spy.mockRestore();
      return n;
    };
    const manual = (withVss: boolean) => () => {
      const commits = quorum.map((p) => frostCommit(p));
      const commitments = commits.map((c) => c.commitment);
      const shares = quorum.map((p, i) => frostSign(p.identifier, p.share, s.k.groupPublicKey, { hiding: commits[i]!.hidingNonce, binding: commits[i]!.bindingNonce }, msg, commitments, { verificationShare: p.publicKey, verificationShares: vss }));
      frostAggregate(msg, commitments, shares, s.k.groupPublicKey, (withVss ? { verificationShares: vss } : {}) as never);
    };
    const cosign = eq(() => { frostCosign(s.k.groupPublicKey, quorum, msg); });
    const withVss = eq(manual(true));
    expect(withVss).toBeGreaterThan(0);
    expect(cosign).toBe(withVss);
    // R6-ALIAS-07: the unverified path no longer exists
    expect(manual(false)).toThrow('frostAggregate: verificationShares are required');
  });
});

describe('frostAggregate final verification', () => {
  it('verifies strictly (RFC 8032, zip215: false)', () => {
    const s = setup();
    const r = s.round([1, 2]);
    const shares = r.parts.map((p, i) => frostSign(p.identifier, p.share, s.k.groupPublicKey, s.nonce(r.cs[i]!), msg, r.commitments));
    const vss = r.parts.map((p) => ({ identifier: p.identifier, publicKey: p.publicKey }));
    const spy = vi.spyOn(ed25519, 'verify');
    const sig = frostAggregate(msg, r.commitments, shares, s.k.groupPublicKey, { verificationShares: vss });
    const calls = spy.mock.calls;
    spy.mockRestore();
    expect(calls).toHaveLength(1);
    expect(calls[0]![3]).toEqual({ zip215: false });
    expect(ed25519.verify(sig, msg, s.k.groupPublicKey)).toBe(true);
  });
});
