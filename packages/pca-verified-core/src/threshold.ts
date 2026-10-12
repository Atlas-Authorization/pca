import { Threshold, bn, fromSeq, num, opt, seq, D, none, some } from './bridge';

export type SignerRole = 'agent' | 'guardian' | 'principal';
const ROLE: Record<SignerRole, () => unknown> = {
  agent: () => Threshold.Role.create_Agent(),
  guardian: () => Threshold.Role.create_Guardian(),
  principal: () => Threshold.Role.create_Principal(),
};
const roleName = (r: { is_Agent: boolean; is_Guardian: boolean }): SignerRole => (r.is_Agent ? 'agent' : r.is_Guardian ? 'guardian' : 'principal');

/** One signer-set entry, with the primitive facts already evaluated. `role` undefined == an unknown role string. */
export interface SignerFacts<K> {
  role: SignerRole | undefined;
  /** the public key is a well-formed 32-byte b64u key. */
  keyOk: boolean;
  /** the registered `pq_pk`, when present, is well-formed. */
  pqOk: boolean;
  key: K;
}
export interface ShareFacts<K> {
  /** share is an object with string role and publicKey. */
  wellFormed: boolean;
  role: SignerRole | undefined;
  key: K;
  /** the share's `alg` names a registered suite. */
  algKnown: boolean;
  /** the share names no `pq_pk` of its own, or names exactly the one its role registers. */
  pqPkOk: boolean;
  /** signature verification over the role/set/t-bound share message (lazy). */
  sigOk: () => boolean;
}
export interface BaselineFacts<K> {
  holderIsString: boolean;
  holder: K;
  /** F-2 baseline PQ-key rule (lazy). */
  pqKeyOk: () => boolean;
  /** leaf signature over the bare message (lazy). */
  leafSigOk: () => boolean;
}

export type ThresholdReason =
  | { kind: 'invalid-t' | 'set-malformed' | 'set-pq' | 'one-key-two-roles' | 'malformed-share' | 'need-more' }
  | { kind: 'two-keys-for-role'; entry: number }
  | { kind: 'role-not-in-set' | 'key-not-registered' | 'unknown-alg' | 'pq-pk-mismatch' | 'invalid-sig'; share: number };

export interface ThresholdDecision {
  ok: boolean;
  /** number of DISTINCT valid keys == distinct roles (proved: count == roles.length, roles pairwise distinct, <= 3). */
  count: number;
  roles: SignerRole[];
  reason?: ThresholdReason;
}

/** Verified t-of-n distinct-role count (formal/dafny/Threshold.dfy: Verify). `t` that is not 1, 2 or 3 must be passed as-is (non-integers as -1). */
export function decideThreshold<K>(
  signers: readonly SignerFacts<K>[],
  shares: readonly ShareFacts<K>[],
  t: number,
  baseline?: BaselineFacts<K>,
): ThresholdDecision {
  const es = seq(signers.map((s) => Threshold.Signer.create_Signer(s.role === undefined ? none() : some(ROLE[s.role]()), s.keyOk, s.pqOk, s.key)));
  const shs = seq(shares.map((s) => Threshold.Share.create_Share(s.wellFormed, s.role === undefined ? none() : some(ROLE[s.role]()), s.key, s.algKnown, s.pqPkOk, s.sigOk)));
  const bl = baseline === undefined ? none() : some(Threshold.Baseline.create_Baseline(baseline.holderIsString, baseline.holder, baseline.pqKeyOk, baseline.leafSigOk));
  const v = Threshold.__default.Verify(es, shs, Number.isSafeInteger(t) ? bn(t) : bn(-1), bl);
  const out: ThresholdDecision = { ok: v.dtor_ok, count: num(v.dtor_count), roles: fromSeq<{ is_Agent: boolean; is_Guardian: boolean }>(v.dtor_roles).map(roleName) };
  if (v.dtor_reason.is_Some) {
    const r = v.dtor_reason.dtor_v;
    const k = (
      [
        ['is_InvalidT', 'invalid-t'],
        ['is_SetMalformed', 'set-malformed'],
        ['is_SetPq', 'set-pq'],
        ['is_OneKeyTwoRoles', 'one-key-two-roles'],
        ['is_MalformedShare', 'malformed-share'],
        ['is_NeedMore', 'need-more'],
      ] as const
    ).find(([f]) => r[f]);
    if (r.is_TwoKeysForRole) out.reason = { kind: 'two-keys-for-role', entry: num(r.dtor_entry) };
    else if (k) out.reason = { kind: k[1] };
    else {
      const kind = r.is_RoleNotInSet ? 'role-not-in-set' : r.is_KeyNotRegistered ? 'key-not-registered' : r.is_UnknownAlg ? 'unknown-alg' : r.is_PqPkMismatch ? 'pq-pk-mismatch' : 'invalid-sig';
      out.reason = { kind, share: num(r.dtor_share) };
    }
  }
  return out;
}

export { opt, D };
