import { describe, expect, it } from 'vitest';
import { frostAggregate, frostTrustedDealerKeygen, type FrostCommitment } from './frost';
import { b64u } from './hash';
import { generateKeyPair, verify } from './keys';
import { GuardianSignerService, issueAllowToken, type Round1Response } from './frost-net';
import { assertNonceStoreContract, MemoryNonceStore, type NonceRecord, type NonceStore } from './frost-nonce-store';

const MSG = new TextEncoder().encode('transfer 100 to alice');
const MSG2 = new TextEncoder().encode('transfer 9999 to mallory');

function setup() {
  const kg = frostTrustedDealerKeygen(2, 3);
  const policy = generateKeyPair();
  const vss = kg.participantShares.map((p) => ({ identifier: p.identifier, publicKey: p.publicKey }));
  const wireVss = vss.map((v) => ({ identifier: v.identifier, publicKey: b64u(v.publicKey) }));
  /** A signer over `store`; calling it again with the same store simulates a process restart. */
  const signer = (index: number, store?: NonceStore) =>
    new GuardianSignerService({
      identifier: kg.participantShares[index]!.identifier,
      share: kg.participantShares[index]!.share,
      groupPublicKey: kg.groupPublicKey,
      threshold: 2,
      policyAuthorityPublicKey: policy.publicKey,
      ...(store ? { nonceStore: store } : {}),
    });
  const r2 = (session: string, msg: Uint8Array, commitments: Array<Extract<Round1Response, { ok: true }>['commitment']>) => ({
    typ: 'pca.frost.round2.v1' as const,
    session_id: session,
    message: b64u(msg),
    group_pk: b64u(kg.groupPublicKey),
    commitments,
    verification_shares: wireVss,
    allow: issueAllowToken(policy.secretKey, { message: msg, groupPublicKey: kg.groupPublicKey }),
  });
  const open = (svc: GuardianSignerService, session: string) => {
    const r = svc.round1({ typ: 'pca.frost.round1.v1', session_id: session });
    if (!r.ok) throw new Error(r.reason);
    return r.commitment;
  };
  return { kg, policy, vss, signer, r2, open };
}

describe('MemoryNonceStore meets the nonce-store contract', () => {
  it('passes the conformance check', () => assertNonceStoreContract(() => new MemoryNonceStore()));
  it('the conformance check rejects a store that forgets spent markers (negative control)', () => {
    class Forgetful extends MemoryNonceStore {
      override isSpent(): boolean {
        return false;
      }
      override create(id: string, r: NonceRecord): void {
        super.create(id, r);
      }
    }
    expect(() => assertNonceStoreContract(() => new Forgetful())).toThrow(/nonce-store contract/);
  });
});

describe('FROST signer session recovery', () => {
  it('a signer restarted between round 1 and round 2 still signs, and the aggregate verifies', () => {
    const f = setup();
    const store0 = new MemoryNonceStore(), store1 = new MemoryNonceStore();
    const a0 = f.signer(0, store0), a1 = f.signer(1, store1);
    const commits = [f.open(a0, 's1'), f.open(a1, 's1')];
    const b0 = f.signer(0, store0), b1 = f.signer(1, store1); // restart: new objects, same durable state
    const shares = [b0, b1].map((s) => {
      const r = s.round2(f.r2('s1', MSG, commits));
      if (!r.ok) throw new Error(r.reason);
      return { identifier: r.identifier, sigShare: Uint8Array.from(Buffer.from(r.sig_share.replace(/-/g, '+').replace(/_/g, '/'), 'base64')) };
    });
    const list: FrostCommitment[] = commits.map((c) => ({ identifier: c.identifier, hiding: new Uint8Array(Buffer.from(c.hiding, 'base64url')), binding: new Uint8Array(Buffer.from(c.binding, 'base64url')) }));
    const sig = frostAggregate(MSG, list, shares, f.kg.groupPublicKey, { threshold: 2, verificationShares: f.vss });
    expect(verify(f.kg.groupPublicKey, MSG, sig)).toBe(true);
  });

  it('after a share is released, a restarted signer refuses the same session for the same or a different message', () => {
    const f = setup();
    const store = new MemoryNonceStore();
    const a = f.signer(0, store), peer = f.signer(1);
    const commits = [f.open(a, 's2'), f.open(peer, 's2')];
    expect(a.round2(f.r2('s2', MSG, commits)).ok).toBe(true);
    const b = f.signer(0, store); // restart
    for (const msg of [MSG, MSG2]) {
      const r = b.round2(f.r2('s2', msg, commits));
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toMatch(/already signed/);
    }
    // and the session id cannot be reopened with fresh nonces to sign a different message under the old commitments
    const again = b.round1({ typ: 'pca.frost.round1.v1', session_id: 's2' });
    expect(again.ok).toBe(false);
  });

  it('a crash after the spent marker and before the share leaves the session unusable, not reusable', () => {
    const f = setup();
    const store = new MemoryNonceStore();
    const a = f.signer(0, store), peer = f.signer(1);
    const commits = [f.open(a, 's3'), f.open(peer, 's3')];
    store.spend('s3'); // the marker is durable; the process dies before computing the share
    const b = f.signer(0, store);
    const r = b.round2(f.r2('s3', MSG, commits));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/already signed/);
    expect(store.load('s3')).toBeUndefined(); // the secret nonces are gone
  });

  it('an authorization failure keeps the session live; a failure inside frostSign (after the marker) burns it', () => {
    const f = setup();
    const store = new MemoryNonceStore();
    const a = f.signer(0, store), peer = f.signer(1);
    const commits = [f.open(a, 's4'), f.open(peer, 's4')];
    // authorization failure happens before the marker: the session stays live for an honest retry
    const bad = { ...f.r2('s4', MSG, commits), message: b64u(MSG2) };
    expect(a.round2(bad).ok).toBe(false);
    expect(store.isSpent('s4')).toBe(false);
    // wrong verification shares are only caught inside frostSign, after the marker: the session is burned
    const wrongVss = { ...f.r2('s4', MSG, commits), verification_shares: f.r2('s4', MSG, commits).verification_shares.map((v, i) => (i === 0 ? { ...v, publicKey: b64u(f.vss[1]!.publicKey) } : v)) };
    const burned = a.round2(wrongVss);
    expect(burned.ok).toBe(false);
    expect(store.isSpent('s4')).toBe(true);
    const retry = a.round2(f.r2('s4', MSG, commits));
    expect(retry.ok).toBe(false);
    if (!retry.ok) expect(retry.reason).toMatch(/already signed/);
  });

  it('a store that fails on create means no commitment is released', () => {
    const f = setup();
    const store = new MemoryNonceStore();
    store.create = () => {
      throw new Error('disk full');
    };
    const r = f.signer(0, store).round1({ typ: 'pca.frost.round1.v1', session_id: 's5' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/disk full/);
  });

  it('a store that fails on spend means no signature share is released, and the nonces were not consumed', () => {
    const f = setup();
    const store = new MemoryNonceStore();
    const a = f.signer(0, store), peer = f.signer(1);
    const commits = [f.open(a, 's6'), f.open(peer, 's6')];
    const realSpend = store.spend.bind(store);
    store.spend = () => {
      throw new Error('io error');
    };
    const r = a.round2(f.r2('s6', MSG, commits));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/io error/);
    store.spend = realSpend; // the store recovers: the same session can still sign exactly once
    expect(a.round2(f.r2('s6', MSG, commits)).ok).toBe(true);
    expect(a.round2(f.r2('s6', MSG, commits)).ok).toBe(false);
  });

  it('refuses a malformed nonceStore at construction', () => {
    const f = setup();
    expect(() => f.signer(0, {} as unknown as NonceStore)).toThrow(/nonceStore/);
  });

  it('without a store, a restart loses the session (fail closed) and never reuses a nonce', () => {
    const f = setup();
    const a = f.signer(0), peer = f.signer(1);
    const commits = [f.open(a, 's7'), f.open(peer, 's7')];
    const b = f.signer(0); // restart with no durable state
    const r = b.round2(f.r2('s7', MSG, commits));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/no round-1 state/);
  });
});
