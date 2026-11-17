/**
 * Human sign-off. A proposal is data. It becomes a grant only through `issueGrant`, which demands an approval that:
 *   - is signed by a pinned reviewer, with a key signature or a user-verified passkey assertion;
 *   - commits to the exact proposal digest, the exact verification report digest, the exact list of sensitive actions the
 *     reviewer confirmed, and an expiry (so none of those can be swapped after the signature);
 *   - was made over a report that passed (every observed action replayed through the real verifier).
 * Nothing learned from traces reaches enforcement any other way.
 */
import { b64u, hashCanonicalLenient, mintGrant, publicKeyOf, sha256, unb64u, utf8, type Capability } from '@atlasauth/pca';
import { signDomainBody, verifyDomainBody } from '@atlasauth/pca-grants';
import { verifyAssertion, type CredentialPublicKey } from '@atlasauth/pca-webauthn';
import { intact } from './synth';
import type { Report } from './verify';
import type { Proposal } from './types';

const DOMAIN = 'atlas-pca/autopilot-approval/v1\0';
const CHALLENGE_DOMAIN = 'atlas-pca/autopilot-approval-challenge/v1\0';
export const MAX_APPROVAL_TTL_MS = 24 * 3_600_000;
export const DEFAULT_APPROVAL_TTL_MS = 15 * 60_000;

export interface Common { v: 1; kind: 'pca-autopilot-approval'; proposal_digest: string; report_digest: string; confirmed: string[]; principal: string; at: number; expires_at: number }
export interface KeyApproval extends Common { method: 'key'; sig: string }
export interface PasskeyApproval extends Common { method: 'passkey'; assertion: { authenticatorData: string; clientDataJSON: string; signature: string } }
export type Approval = KeyApproval | PasskeyApproval;

const body = (a: Common) => ({ v: a.v, kind: a.kind, proposal_digest: a.proposal_digest, report_digest: a.report_digest, confirmed: a.confirmed, principal: a.principal, at: a.at, expires_at: a.expires_at });

/** The digest a report commits to is recomputed, never trusted from its own field. */
export function reportIntact(r: Report): boolean {
  const { digest, ...rest } = r;
  return typeof digest === 'string' && hashCanonicalLenient(JSON.parse(JSON.stringify(rest))) === digest;
}

/** Throws unless the proposal is unmodified, the report is for it and intact, and the report passed. */
export function gate(p: Proposal, r: Report): void {
  if (!intact(p)) throw new Error('the proposal was modified after it was made');
  if (!reportIntact(r) || r.proposalDigest !== p.digest) throw new Error('the report is not for this proposal');
  if (!r.ok) throw new Error('refusing to sign: the proposal did not verify (replay, lint or basis failed)');
}

/** The 32-byte challenge a passkey must sign: it binds the proposal, the report, the confirmations and the expiry. */
export function approvalChallenge(p: Proposal, r: Report, confirmed: readonly string[], expiresAt: number): Uint8Array {
  return sha256(utf8(CHALLENGE_DOMAIN + hashCanonicalLenient({ p: p.digest, r: r.digest, c: [...confirmed].sort(), e: expiresAt })));
}

/** Sign an approval with a reviewer key. `confirmed` defaults to the sensitive actions the proposal already includes. */
export function signApproval(secret: Uint8Array, p: Proposal, r: Report, o: { at: number; ttlMs?: number; confirmed?: readonly string[] }): KeyApproval {
  gate(p, r);
  const ttl = o.ttlMs ?? DEFAULT_APPROVAL_TTL_MS;
  if (!Number.isFinite(ttl) || ttl <= 0 || ttl > MAX_APPROVAL_TTL_MS) throw new RangeError('approval ttl must be positive and at most 24h');
  const base: Common = { v: 1, kind: 'pca-autopilot-approval', proposal_digest: p.digest, report_digest: r.digest, confirmed: [...(o.confirmed ?? p.confirmedSensitive)].sort(), principal: b64u(publicKeyOf(secret)), at: o.at, expires_at: o.at + ttl };
  return { ...base, method: 'key', sig: signDomainBody(DOMAIN, body(base), secret) };
}

export interface PasskeyOptions {
  /** Registered credential public keys by the principal label the approval carries. */
  credentials?: Readonly<Record<string, CredentialPublicKey>>;
  rpId?: string;
  origins?: string[];
  /** Per credential: the signature counter stored at its last accepted assertion. */
  storedSignCount?: (principal: string) => number;
}

/** `signCount` (passkey only) is the counter to store for the next verification of that credential. */
export type ApprovalCheck = { ok: true; principal: string; method: 'key' | 'passkey'; signCount?: number } | { ok: false; reason: string };

/** Verify an approval for exactly this proposal and report. Never throws; anything doubtful is a refusal. */
export function verifyApproval(a: unknown, p: Proposal, r: Report, o: { principals: readonly string[]; now: number } & PasskeyOptions): ApprovalCheck {
  const no = (reason: string): ApprovalCheck => ({ ok: false, reason });
  try {
    gate(p, r);
    const x = a as Approval;
    if (x === null || typeof x !== 'object' || x.v !== 1 || x.kind !== 'pca-autopilot-approval') return no('not an approval');
    if (typeof x.principal !== 'string' || !o.principals.includes(x.principal)) return no('the signer is not a pinned reviewer');
    if (x.proposal_digest !== p.digest) return no('the approval is for a different proposal');
    if (x.report_digest !== r.digest) return no('the approval is for a different verification report');
    if (!Array.isArray(x.confirmed) || x.confirmed.length !== p.confirmedSensitive.length || [...x.confirmed].sort().some((c, i) => c !== p.confirmedSensitive[i])) return no('the confirmed sensitive actions do not match the proposal exactly');
    if (!Number.isSafeInteger(x.at) || !Number.isSafeInteger(x.expires_at) || x.expires_at <= x.at || x.expires_at - x.at > MAX_APPROVAL_TTL_MS) return no('bad approval validity window');
    if (o.now < x.at || o.now >= x.expires_at) return no('the approval is not valid now (expired or not yet valid)');
    if (x.method === 'key') return verifyDomainBody(DOMAIN, body(x), x.principal, x.sig) ? { ok: true, principal: x.principal, method: 'key' } : no('bad signature');
    if (x.method === 'passkey') {
      const pk = o.credentials?.[x.principal];
      if (pk === undefined || o.rpId === undefined || o.origins === undefined || o.storedSignCount === undefined) return no('passkey verification needs credentials, rpId, origins and storedSignCount');
      const res = verifyAssertion(
        { authenticatorData: unb64u(x.assertion.authenticatorData), clientDataJSON: unb64u(x.assertion.clientDataJSON), signature: unb64u(x.assertion.signature), publicKey: pk },
        { expectedChallenge: approvalChallenge(p, r, x.confirmed, x.expires_at), rpId: o.rpId, origins: o.origins, requireUV: true, storedSignCount: o.storedSignCount(x.principal) },
      );
      return res.ok ? { ok: true, principal: x.principal, method: 'passkey', signCount: res.signCount } : no(`passkey assertion refused: ${res.reason}`);
    }
    return no('unknown approval method');
  } catch (e) {
    return no(e instanceof Error ? e.message : 'could not verify');
  }
}

/**
 * Mint the grant from an approved proposal. Re-checks everything: this is the only door from a proposal to authority. The
 * grant is signed by `principalSecret`, which need not be the reviewer's key.
 */
export function issueGrant(p: Proposal, r: Report, approval: unknown, o: { principalSecret: Uint8Array; holder: string; goal: string; principals: readonly string[]; now: number; goalSalt?: string } & PasskeyOptions): { grant: Capability; goalSalt: string; approvedBy: string } {
  const c = verifyApproval(approval, p, r, o);
  if (!c.ok) throw new Error(`grant not issued: ${c.reason}`);
  const exp = p.policy.caveats.find((v) => v.type === 'expires');
  if (exp !== undefined && !(typeof exp.at === 'number' && exp.at > o.now)) throw new Error('grant not issued: the proposal has already expired; propose again');
  const { grant, goalSalt } = mintGrant({
    principalSecret: o.principalSecret, principalPublic: b64u(publicKeyOf(o.principalSecret)), holder: o.holder, goal: o.goal,
    ...(o.goalSalt !== undefined ? { salt: o.goalSalt } : {}),
    envelope: { predicates: p.policy.predicates, caveats: p.policy.caveats, agent_binding: {}, risk_policy: p.riskPolicy },
  });
  return { grant, goalSalt, approvedBy: c.principal };
}
