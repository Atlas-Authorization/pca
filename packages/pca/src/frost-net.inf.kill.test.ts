import { describe, expect, it } from 'vitest';
import { frostTrustedDealerKeygen } from './frost';
import { generateKeyPair } from './keys';
import { b64u, utf8 } from './hash';
import { GuardianSignerService, issueAllowToken } from './frost-net';

const MSG = utf8('transfer 100 USDC to bob');

describe('a non-finite session clock never keeps a round-1 session alive (frost-net)', () => {
  // old `now - createdAt > ttl` was false for a round-1 stamped at +Infinity, so the session never aged out
  it.each([Number.POSITIVE_INFINITY, Number.NaN])('a round-1 stamped at %s is refused at round 2', (stamp) => {
    const kg = frostTrustedDealerKeygen(2, 3);
    const policy = generateKeyPair();
    let clock = stamp;
    const svc = new GuardianSignerService({
      identifier: 1,
      share: kg.participantShares[0]!.share,
      groupPublicKey: kg.groupPublicKey,
      threshold: 2,
      policyAuthorityPublicKey: policy.publicKey,
      sessionTtlMs: 100,
      now: () => clock,
    });
    const r1 = svc.round1({ typ: 'pca.frost.round1.v1', session_id: 'inf' });
    expect(r1.ok).toBe(true);
    if (!r1.ok) throw new Error('unreachable');
    clock = 1_000;
    const r2 = svc.round2({
      typ: 'pca.frost.round2.v1',
      session_id: 'inf',
      message: b64u(MSG),
      group_pk: b64u(kg.groupPublicKey),
      commitments: [r1.commitment],
      verification_shares: [{ identifier: 1, publicKey: b64u(kg.participantShares[0]!.publicKey) }],
      allow: issueAllowToken(policy.secretKey, { message: MSG, groupPublicKey: kg.groupPublicKey }),
    });
    expect(r2.ok).toBe(false);
    if (r2.ok) throw new Error('unreachable');
    expect(r2.reason).toMatch(/stale-session/);
  });
});
