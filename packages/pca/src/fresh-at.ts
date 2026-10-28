import { b64u, canonicalBytesStrict, decodeB64uStrict, hashCanonical, utf8 } from './hash';
import { publicKeyOf, sign, verifyB64u } from './keys';

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
const isSafeInt = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;
const isStr = (x: unknown, max = 512): x is string => typeof x === 'string' && x.length > 0 && x.length <= max;
const signerOf = (secret: Uint8Array): string => b64u(publicKeyOf(secret));
const withDomain = (domain: string, body: unknown): Uint8Array => {
  const d = utf8(domain);
  const b = canonicalBytesStrict(body);
  const out = new Uint8Array(d.length + b.length);
  out.set(d);
  out.set(b, d.length);
  return out;
};
const signBody = (domain: string, body: unknown, secret: Uint8Array): string => b64u(sign(secret, withDomain(domain, body)));
function verifyBody(domain: string, body: unknown, signer: string, sig: unknown): boolean {
  try {
    return typeof sig === 'string' && decodeB64uStrict(sig, 64) !== null && verifyB64u(signer, withDomain(domain, body), sig);
  } catch {
    return false;
  }
}

/**
 * CONSISTENCY TOKENS (`fresh_at`). The Zanzibar "zookie" idea in PCA's vocabulary: every write (grant change, revoke,
 * budget commit, content change) returns a signed high-water mark of the verifier-side state it produced. A caller attaches
 * the newest token it holds to later requests; the verifier refuses to DECIDE against state older than the token
 * (`stale_state` = escalate, "refresh and retry", never allow). This closes the new-enemy problem: a revoke or restriction
 * is ordered before any later decision that carries its token.
 *
 * It is also a PCActn MEMBER (`fresh_at`, SIGNED by the leaf signature) and the verifier's `fresh_at` check reads it; a side-carried
 * token (a header next to the PCActn) is still readable for one release through `FreshAtPolicy.sideCarried`.
 *
 * The token is a MONOTONE high-water mark: {@link mergeFreshAt} is the field-wise maximum, so a client can fold tokens
 * from many writes into one and a stale token can never lower a fresher one.
 */
export const FRESH_AT_DOMAIN = 'atlas-pca/fresh-at/v1\0';
export const FRESH_AT_REF_DOMAIN = 'atlas-pca/fresh-at-ref/v1';

export interface FreshAtState {
  revocation_epoch: number;
  ledger_tree_size: number;
  budget_version: number;
  /** Revision of the policy bundle in force (orders policy states; digests alone are not ordered). */
  policy_revision: number;
  policy_digest: string;
}
export type FreshAtToken = FreshAt;
export interface FreshAt extends FreshAtState {
  v: 1;
  /** What the state is about: an instance, a principal or a grant. A token for another scope is refused. */
  scope: string;
  issued_at: number;
  signer: string;
  sig: string;
}
const NUMERIC = ['revocation_epoch', 'ledger_tree_size', 'budget_version', 'policy_revision'] as const;
const bodyOf = (t: Omit<FreshAt, 'sig'>) => ({
  v: t.v, scope: t.scope, revocation_epoch: t.revocation_epoch, ledger_tree_size: t.ledger_tree_size,
  budget_version: t.budget_version, policy_revision: t.policy_revision, policy_digest: t.policy_digest, issued_at: t.issued_at, signer: t.signer,
});

export function signFreshAt(secret: Uint8Array, scope: string, state: FreshAtState, issuedAt: number): FreshAt {
  const ok = isStr(scope, 256) && isStr(state.policy_digest, 128) && NUMERIC.every((k) => isSafeInt(state[k])) && isSafeInt(issuedAt);
  if (!ok) throw new RangeError('signFreshAt: a malformed state');
  const base = { v: 1 as const, scope, ...state, issued_at: issuedAt, signer: signerOf(secret) };
  return { ...base, sig: signBody(FRESH_AT_DOMAIN, bodyOf(base), secret) };
}

/** Well formed and signed by `signer` over exactly its content. Never throws. */
export function verifyFreshAt(t: unknown, signer: string): t is FreshAt {
  if (!isObj(t) || t.v !== 1 || t.signer !== signer || !isStr(t.scope, 256) || !isStr(t.policy_digest, 128) || !isSafeInt(t.issued_at)) return false;
  if (!NUMERIC.every((k) => isSafeInt(t[k]))) return false;
  const { sig, ...base } = t as unknown as FreshAt;
  return verifyBody(FRESH_AT_DOMAIN, bodyOf(base), signer, sig);
}

/** The content address a PCActn or request signs to bind the token it carried. */
export const freshAtDigest = (t: FreshAt): string => hashCanonical({ d: FRESH_AT_REF_DOMAIN, t });

/** Field-wise maximum of two states (the client-side fold). Equal revisions with different digests keep `a`'s digest; see checkFreshAt for the fork case. */
export function mergeFreshAt<T extends FreshAtState>(a: T, b: FreshAtState): FreshAtState {
  return {
    revocation_epoch: Math.max(a.revocation_epoch, b.revocation_epoch),
    ledger_tree_size: Math.max(a.ledger_tree_size, b.ledger_tree_size),
    budget_version: Math.max(a.budget_version, b.budget_version),
    policy_revision: Math.max(a.policy_revision, b.policy_revision),
    policy_digest: b.policy_revision > a.policy_revision ? b.policy_digest : a.policy_digest,
  };
}

export type FreshAtCode = 'bad_token' | 'wrong_scope' | 'token_from_the_future' | 'token_too_old' | 'stale_state' | 'policy_fork';
export type FreshAtVerdict =
  | { decision: 'ok' }
  /** The verifier is behind the token: ask the caller to refresh (re-read state) and retry. Never an allow. */
  | { decision: 'escalate'; code: 'stale_state'; behind: Array<keyof FreshAtState> }
  | { decision: 'deny'; code: Exclude<FreshAtCode, 'stale_state'> };

export interface CheckFreshAtOptions {
  signer: string;
  scope: string;
  now: number;
  /** Refuse a token whose own age exceeds this (ms). Absent: only the state ordering applies. */
  maxTokenAgeMs?: number;
}

/**
 * May the verifier decide against `local` for a request carrying `token`? Order of checks (each fails closed):
 * signature/shape -> scope -> issued in the future (> 60 s skew) -> token age -> policy fork (same revision, different
 * digest) -> any of the four counters behind the token => escalate `stale_state`.
 */
export function checkFreshAt(token: unknown, local: FreshAtState, o: CheckFreshAtOptions): FreshAtVerdict {
  if (!verifyFreshAt(token, o.signer)) return { decision: 'deny', code: 'bad_token' };
  if (token.scope !== o.scope) return { decision: 'deny', code: 'wrong_scope' };
  if (!(token.issued_at <= o.now + 60_000)) return { decision: 'deny', code: 'token_from_the_future' };
  if (o.maxTokenAgeMs !== undefined && !(o.now - token.issued_at <= o.maxTokenAgeMs)) return { decision: 'deny', code: 'token_too_old' };
  if (token.policy_revision === local.policy_revision && token.policy_digest !== local.policy_digest) return { decision: 'deny', code: 'policy_fork' };
  const behind = NUMERIC.filter((k) => !(local[k] >= token[k]));
  return behind.length === 0 ? { decision: 'ok' } : { decision: 'escalate', code: 'stale_state', behind };
}

export type AdmitDecision = 'allow' | 'deny' | 'escalate';
/** Compose a freshness verdict into a decision: it can only tighten (allow -> escalate/deny), never loosen. */
export function gateDecision(decision: AdmitDecision, v: FreshAtVerdict): AdmitDecision {
  if (decision === 'deny') return 'deny';
  if (v.decision === 'deny') return 'deny';
  if (v.decision === 'escalate') return 'escalate';
  return decision;
}

/** Verifier-side state holder: advance on every write, mint the token for the write, check incoming tokens. */
export class FreshAtIssuer {
  private state: FreshAtState;
  constructor(private readonly secret: Uint8Array, readonly scope: string, initial: FreshAtState) {
    this.state = { ...initial };
  }
  get current(): FreshAtState {
    return { ...this.state };
  }
  /** Apply a write (any subset of counters; each only moves forward) and return its token. */
  advance(patch: Partial<FreshAtState>, now: number): FreshAt {
    this.state = mergeFreshAt(this.state, { ...this.state, ...patch });
    return signFreshAt(this.secret, this.scope, this.state, now);
  }
  check(token: unknown, now: number, maxTokenAgeMs?: number): FreshAtVerdict {
    return checkFreshAt(token, this.state, { signer: signerOf(this.secret), scope: this.scope, now, ...(maxTokenAgeMs !== undefined ? { maxTokenAgeMs } : {}) });
  }
}


// ---- the PCActn member + the verifier check ----------------------------------------------------------------------------------

/** Closed key set of the `fresh_at` member (unknown keys are unsigned malleability inside a signed member). */
const FRESH_AT_KEYS = new Set(['v', 'scope', 'revocation_epoch', 'ledger_tree_size', 'budget_version', 'policy_revision', 'policy_digest', 'issued_at', 'signer', 'sig']);
/** Wire shape of the member. Returns the problem or null. Does NOT check the signature (that is the `fresh_at` check). */
export function validateFreshAtWire(v: unknown): string | null {
  if (!isObj(v)) return "'fresh_at' must be an object";
  for (const k of Object.keys(v)) if (!FRESH_AT_KEYS.has(k)) return `'fresh_at' has an unknown field '${k}'`;
  if (v.v !== 1) return "'fresh_at.v' must be 1";
  if (!isStr(v.scope, 256) || !isStr(v.policy_digest, 128)) return "'fresh_at' scope and policy_digest must be non-empty strings";
  for (const k of ['revocation_epoch', 'ledger_tree_size', 'budget_version', 'policy_revision', 'issued_at'] as const) if (!isSafeInt(v[k])) return `'fresh_at.${k}' must be a non-negative safe integer`;
  if (decodeB64uStrict(v.signer, 32) === null) return "'fresh_at.signer' is not canonical base64url (32 bytes)";
  if (decodeB64uStrict(v.sig, 64) === null) return "'fresh_at.sig' is not canonical base64url (64 bytes)";
  return null;
}

/** Verifier-side configuration of the `fresh_at` check. */
export interface FreshAtPolicy {
  /** The pinned token signer (b64u Ed25519 public key). */
  signer: string;
  /** The scope this verifier decides for; a token for another scope is refused. */
  scope: string;
  /** The verifier's OWN current state counters. */
  local: FreshAtState;
  maxTokenAgeMs?: number;
  /** Every PCActn must carry (or have side-carried) a token; none is `escalate: fresh_at token required` (refresh and retry). */
  require?: boolean;
  /** The pre-member form: a token that travelled beside the PCActn (an HTTP header). Read only when the PCActn has no member. Removed after 0.5. */
  sideCarried?: unknown;
}
export type FreshAtCheck = { status: 'none' } | { status: 'pass' } | { status: 'fail'; reason: string };

/**
 * The verifier's `fresh_at` check. Reported (pass/fail) only when the PCActn carries the member, a side-carried token is read, or the
 * policy requires one; otherwise `none` (byte-identical to before). A stale verifier is an ESCALATE-class failure
 * (`escalate: stale_state ...`, the decision fold turns it into `escalate`), anything else is a hard failure.
 */
export function decideFreshAt(member: unknown, policy: FreshAtPolicy | undefined, now: number): FreshAtCheck {
  const token = member !== undefined ? member : policy?.sideCarried;
  if (policy === undefined) return member !== undefined ? { status: 'fail', reason: 'the PCActn carries fresh_at but this verifier has no fresh_at policy (fail closed)' } : { status: 'none' };
  if (token === undefined) return policy.require ? { status: 'fail', reason: 'escalate: a consistency token is required (refresh and retry with the token of your latest write)' } : { status: 'none' };
  const v = checkFreshAt(token, policy.local, { signer: policy.signer, scope: policy.scope, now, ...(policy.maxTokenAgeMs !== undefined ? { maxTokenAgeMs: policy.maxTokenAgeMs } : {}) });
  if (v.decision === 'ok') return { status: 'pass' };
  if (v.decision === 'escalate') return { status: 'fail', reason: `escalate: stale_state (verifier state is behind the token on ${v.behind.join(', ')})` };
  return { status: 'fail', reason: v.code };
}
