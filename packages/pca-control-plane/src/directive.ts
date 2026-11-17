/**
 * Directives: the control plane's only output. A directive is a signed, content-addressed, expiring statement
 * "treat this subject more strictly", consumed by hooks that already exist (risk policy, revocation registry,
 * Shared Signals). It can only TIGHTEN: every kind below makes authorization stricter, and the parameter check
 * ({@link directiveParamsError}) refuses any value that would loosen. Loosening is never a directive; it is a
 * signed human action ({@link ./human}) that lifts one.
 */
import { b64u, canonicalBytesLenient, hashCanonicalLenient, publicKeyOf, sign, utf8, verifyB64u } from '@atlasauth/pca';
import type { Directive, DirectiveClaim, DirectiveKind, DirectiveParams, Subject } from './types';

export const DIRECTIVE_DOMAIN = 'atlas-pca/control-plane/directive/v1\0';
/** The longest an expiring directive may live. A control plane renews a still-justified one instead of issuing a long one. */
export const MAX_DIRECTIVE_TTL_MS = 24 * 3_600_000;
export const DIRECTIVE_KINDS: readonly DirectiveKind[] = ['tighten', 'shrink_budget', 'require_step_up', 'freeze'];
const SUBJECT_KINDS = ['agent', 'session', 'grant', 'fleet'];
const MAX_STR = 256;
const MAX_REASON = 512;
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const KEY_RE = /^[A-Za-z0-9_-]{43}$/;

const num = (x: unknown): x is number => typeof x === 'number' && Number.isFinite(x);
const str = (x: unknown, max: number, min = 0): x is string => typeof x === 'string' && x.length >= min && x.length <= max;

/** Why these parameters are not an allowed (tightening) value for the kind, or null. */
export function directiveParamsError(kind: DirectiveKind, p: unknown): string | null {
  if (p === null || typeof p !== 'object' || Array.isArray(p)) return 'params must be an object';
  const o = p as DirectiveParams;
  const keys = Object.keys(o);
  switch (kind) {
    case 'tighten':
      if (keys.some((k) => k !== 'kappa_mult' && k !== 'theta_mult')) return 'tighten takes only kappa_mult and theta_mult';
      if (!num(o.kappa_mult) || o.kappa_mult < 1 || o.kappa_mult > 100) return 'kappa_mult must be a finite number in [1, 100] (it can only raise the cost)';
      if (!num(o.theta_mult) || o.theta_mult <= 0 || o.theta_mult > 1) return 'theta_mult must be a finite number in (0, 1] (it can only lower the thresholds)';
      return null;
    case 'shrink_budget':
      if (keys.some((k) => k !== 'factor')) return 'shrink_budget takes only factor';
      if (!num(o.factor) || o.factor < 0 || o.factor >= 1) return 'factor must be a finite number in [0, 1) (it can only shrink the budget)';
      return null;
    default:
      return keys.length === 0 ? null : `${kind} takes no parameters`;
  }
}

export function subjectError(s: unknown): string | null {
  if (s === null || typeof s !== 'object') return 'subject must be an object';
  const o = s as Subject;
  if (!SUBJECT_KINDS.includes(o.kind)) return 'subject.kind is unknown';
  if (!str(o.id, MAX_STR, 1)) return 'subject.id must be a non-empty string';
  if (o.kind === 'fleet' && o.id !== '*') return 'the fleet subject id is *';
  return null;
}

/** Why the claim is malformed or would loosen, or null. Pure shape check; no time, no signature. */
export function claimError(c: unknown): string | null {
  if (c === null || typeof c !== 'object' || Array.isArray(c)) return 'claim must be an object';
  const x = c as DirectiveClaim;
  if (x.v !== 1) return 'unsupported version';
  if (!DIRECTIVE_KINDS.includes(x.kind)) return 'unknown kind';
  const s = subjectError(x.subject);
  if (s) return s;
  const p = directiveParamsError(x.kind, x.params);
  if (p) return p;
  if (x.cause !== 'auto' && x.cause !== 'operator') return 'unknown cause';
  if (!str(x.by, 128, 1) || !str(x.reason, MAX_REASON) || !str(x.evidence, 128)) return 'by, reason and evidence must be bounded strings';
  if (!num(x.iat) || x.iat < 0 || !Number.isSafeInteger(x.seq) || x.seq < 1) return 'iat and seq must be finite and non-negative';
  if (typeof x.signer !== 'string' || !KEY_RE.test(x.signer)) return 'signer must be an Ed25519 key';
  if (x.kind === 'freeze') {
    if (x.exp !== undefined) return 'a freeze does not expire; a signed human lifts it';
  } else if (!num(x.exp) || x.exp <= x.iat || x.exp - x.iat > MAX_DIRECTIVE_TTL_MS) return 'exp must be finite, after iat and within 24 hours';
  return null;
}

const messageOf = (claimWithId: object): Uint8Array => {
  const pre = utf8(DIRECTIVE_DOMAIN);
  const body = canonicalBytesLenient(claimWithId);
  const m = new Uint8Array(pre.length + body.length);
  m.set(pre);
  m.set(body, pre.length);
  return m;
};

export const directiveId = (c: DirectiveClaim): string => hashCanonicalLenient(c);

/** Sign a claim (the signer key is set from `secret`). Throws on a claim that is malformed or would loosen. */
export function signDirective(secret: Uint8Array, c: Omit<DirectiveClaim, 'signer'>): Directive {
  const claim = { ...c, signer: b64u(publicKeyOf(secret)) } as DirectiveClaim;
  const bad = claimError(claim);
  if (bad) throw new Error(`signDirective: ${bad}`);
  const id = directiveId(claim);
  return { ...claim, id, sig: b64u(sign(secret, messageOf({ ...claim, id }))) };
}

export type DirectiveCheck = { ok: true } | { ok: false; reason: 'malformed' | 'signer' | 'id' | 'signature' | 'not_yet_valid' | 'expired' | 'replayed' };

export interface VerifyDirectiveOptions {
  /** The pinned control-plane key (b64u). Required: a directive from any other key is refused. */
  signer: string;
  now: number;
  /** Highest seq already applied; a directive at or below it is a replay. */
  floorSeq?: number;
  /** Tolerated clock skew for `iat`. Default 60 s. */
  skewMs?: number;
}

/** Verify a directive. Never throws; every refusal has one reason. A refused directive must simply not be applied (it can never loosen anything). */
export function verifyDirective(d: unknown, o: VerifyDirectiveOptions): DirectiveCheck {
  try {
    if (d === null || typeof d !== 'object') return { ok: false, reason: 'malformed' };
    const { id, sig, ...claim } = d as Directive;
    if (typeof id !== 'string' || typeof sig !== 'string' || !SIG_RE.test(sig) || claimError(claim)) return { ok: false, reason: 'malformed' };
    const c = claim as DirectiveClaim;
    if (typeof o.signer !== 'string' || c.signer !== o.signer) return { ok: false, reason: 'signer' };
    if (id !== directiveId(c)) return { ok: false, reason: 'id' };
    if (!verifyB64u(c.signer, messageOf({ ...c, id }), sig)) return { ok: false, reason: 'signature' };
    if (!Number.isFinite(o.now)) return { ok: false, reason: 'malformed' };
    if (c.iat > o.now + (o.skewMs ?? 60_000)) return { ok: false, reason: 'not_yet_valid' };
    if (c.exp !== undefined && !(c.exp > o.now)) return { ok: false, reason: 'expired' };
    if (o.floorSeq !== undefined && !(c.seq > o.floorSeq)) return { ok: false, reason: 'replayed' };
    return { ok: true };
  } catch {
    return { ok: false, reason: 'malformed' };
  }
}

/** True when `a` is at least as strict as `b` for the same kind (so `b` adds nothing). */
export function atLeastAsStrict(a: DirectiveClaim, b: DirectiveClaim): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === 'tighten') return a.params.kappa_mult! >= b.params.kappa_mult! && a.params.theta_mult! <= b.params.theta_mult!;
  if (a.kind === 'shrink_budget') return a.params.factor! <= b.params.factor!;
  return true;
}

/**
 * The signed directive inside an API view. The hosted API adds unsigned display fields (`object`, `active`, `lifted`, `siem`)
 * beside the signed ones; verify with `verifyDirective(directiveOf(view), ...)`, never the view itself.
 */
export function directiveOf(view: unknown): Directive {
  const v = view as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const k of ['v', 'id', 'kind', 'subject', 'params', 'cause', 'by', 'reason', 'evidence', 'iat', 'exp', 'seq', 'signer', 'sig']) if (v?.[k] !== undefined) out[k] = v[k];
  return out as unknown as Directive;
}
