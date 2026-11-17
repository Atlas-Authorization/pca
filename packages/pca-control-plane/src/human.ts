/**
 * The only way to loosen: a signed human action. Lifting a freeze or revoking a directive needs a signature by a
 * pinned human key over a short-lived, single-use, directive-bound statement. Nothing automatic can produce one.
 */
import { b64u, canonicalBytesLenient, hashCanonicalLenient, publicKeyOf, sign, utf8, verifyB64u } from '@atlasauth/pca';

export const HUMAN_DOMAIN = 'atlas-pca/control-plane/human/v1\0';
/** A human action is valid for at most this long, so a leaked one is of little use. */
export const MAX_HUMAN_ACTION_MS = 5 * 60_000;
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const KEY_RE = /^[A-Za-z0-9_-]{43}$/;

export interface HumanActionClaim {
  v: 1;
  op: 'unfreeze' | 'revoke';
  /** The id of the one directive this lifts; a signature for one directive never lifts another. */
  directive: string;
  /** Single-use. */
  nonce: string;
  iat: number;
  exp: number;
  /** b64u Ed25519 key of the human. */
  human: string;
}
export interface HumanAction extends HumanActionClaim {
  sig: string;
}

const messageOf = (c: HumanActionClaim): Uint8Array => {
  const pre = utf8(HUMAN_DOMAIN);
  const body = canonicalBytesLenient(c);
  const m = new Uint8Array(pre.length + body.length);
  m.set(pre);
  m.set(body, pre.length);
  return m;
};

export const humanActionDigest = (a: HumanAction): string => hashCanonicalLenient(a);

/** What a human signs (the dashboard / CLI shows this and signs it with the human's key). */
export function signHumanAction(secret: Uint8Array, c: Omit<HumanActionClaim, 'human' | 'v'>): HumanAction {
  const claim: HumanActionClaim = { v: 1, ...c, human: b64u(publicKeyOf(secret)) };
  return { ...claim, sig: b64u(sign(secret, messageOf(claim))) };
}

export type HumanCheck = { ok: true } | { ok: false; reason: 'malformed' | 'human' | 'signature' | 'expired' | 'not_yet_valid' | 'too_long' };

/** Verify the signature and window. The caller still checks the nonce (single use) and that `directive` names a directive of the right kind. */
export function verifyHumanAction(a: unknown, o: { humans: readonly string[]; now: number }): HumanCheck {
  try {
    if (a === null || typeof a !== 'object') return { ok: false, reason: 'malformed' };
    const { sig, ...c } = a as HumanAction;
    if (c.v !== 1 || (c.op !== 'unfreeze' && c.op !== 'revoke') || typeof sig !== 'string' || !SIG_RE.test(sig)) return { ok: false, reason: 'malformed' };
    if (typeof c.directive !== 'string' || c.directive.length === 0 || c.directive.length > 128) return { ok: false, reason: 'malformed' };
    if (typeof c.nonce !== 'string' || c.nonce.length < 16 || c.nonce.length > 128) return { ok: false, reason: 'malformed' };
    if (!Number.isFinite(c.iat) || !Number.isFinite(c.exp) || !Number.isFinite(o.now)) return { ok: false, reason: 'malformed' };
    if (typeof c.human !== 'string' || !KEY_RE.test(c.human)) return { ok: false, reason: 'malformed' };
    if (!o.humans.includes(c.human)) return { ok: false, reason: 'human' };
    if (!verifyB64u(c.human, messageOf(c as HumanActionClaim), sig)) return { ok: false, reason: 'signature' };
    if (c.exp - c.iat > MAX_HUMAN_ACTION_MS) return { ok: false, reason: 'too_long' };
    if (c.iat > o.now + 30_000) return { ok: false, reason: 'not_yet_valid' };
    if (!(c.exp > o.now)) return { ok: false, reason: 'expired' };
    return { ok: true };
  } catch {
    return { ok: false, reason: 'malformed' };
  }
}
