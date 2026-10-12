/**
 * @atlasauth/pca-ciba — a CIBA on-ramp for PCA's FROST step-up.
 *
 * CIBA (OpenID Connect Client-Initiated Backchannel Authentication, OpenID CIBA Core) is the
 * convergent human-in-the-loop (HITL) primitive every modern IdP ships — Auth0 ("CIBA / push
 * authorization"), Descope, Stytch — for *asynchronous* out-of-band approval: a backend starts an
 * `auth_req_id`, the human is notified on a separate device, and the backend learns the decision by
 * polling (POLL) or via a callback (PING/PUSH). Its `binding_message` field carries the short
 * human-readable context the person sees while approving, so the thing they approve on their phone is
 * provably the thing the agent is about to do.
 *
 * This package is a BRIDGE, not a replacement. PCA's cryptographic step-up (FROST threshold cosign —
 * see `@atlasauth/pca` `threshold`/`frost`) stays the *enforcement*: a tier-3 action proceeds only once
 * a real threshold signature recharges the trust budget. CIBA is only the human-notification / decision
 * *envelope* around that cosign — it standardises how the human is asked and how the answer comes back.
 * PCA's FROST step-up is cryptographically stronger than a bare CIBA approval (an OP's yes/no is a
 * trusted single party; a FROST cosign is an unforgeable t-of-n signature); this just gives it the
 * industry-standard async-approval + binding-message on-ramp.
 *
 * Risk-adaptive gating is the point. If every action prompts a human, humans blanket-approve (Anthropic
 * observed 93% blanket-approval under always-prompt). So only a tier-3 step-up — a human-required,
 * typically irreversible/high-risk action — is routed through CIBA. Tier-2 (guardian auto-cosign) and
 * tier-1 (`auto`) never interrupt a person. `requiresCiba()` encodes exactly that gate.
 *
 * Everything here is pure or in-memory and authorises nothing on its own: the resource server's verifier
 * (`requirePCA` / the adjudicator) and the FROST cosigners remain the run-time authority.
 */

import { randomBytes } from 'node:crypto';
import { domainToASCII } from 'node:url';
import {
  type StepUpRequest,
  type Review,
  type TrustBudget,
  type RiskPolicy,
  applyCosign,
  hashCanonical,
} from '@atlasauth/pca';

// ---- CIBA backchannel auth request ----------------------------------------------------------------

/** A CIBA backchannel authentication request derived from a PCA step-up. */
export interface CibaAuthRequest {
  /**
   * The CIBA `auth_req_id` — the opaque handle the backend polls / correlates on. Derived
   * deterministically from the step-up id, so the same step-up always maps to the same request.
   */
  auth_req_id: string;
  /**
   * The human-readable approval context shown to the person (OpenID CIBA `binding_message`): what is
   * being approved and why, traced to the goal the agent was given.
   */
  binding_message: string;
  /** CIBA `scope` (space-delimited), carrying `openid` + a PCA step-up scope for this verb. */
  scope: string;
  /** CIBA `requested_expiry` in SECONDS — how long the human has to decide. */
  requested_expiry: number;
  /** CIBA `interval` in SECONDS — minimum poll spacing for POLL mode. */
  interval: number;
  /** CIBA `login_hint` — who to notify, if the caller supplied one. */
  login_hint?: string;
  /** The PCA step-up this request fulfils (back-link for correlation). */
  stepUpId: string;
  /** The PCA risk tier that produced the step-up (2 guardian / 3 human). */
  tier: 2 | 3;
}

/** Options shared by `toCibaAuthRequest` and the broker's `start`. */
export interface CibaRequestOptions {
  /** Override the `requested_expiry` (seconds). Must be a positive integer (CIBA Core 7.1). Default 300. */
  expiresInSec?: number;
  /**
   * Use this `auth_req_id` instead of the deterministic derivation. CIBA Core 7.3 requires an
   * `auth_req_id` to carry at least 128 bits of entropy and use only `A-Za-z0-9.-_`; the default
   * derivation hashes PUBLIC step-up fields and is therefore NOT secret. {@link createCibaBroker}
   * always supplies a fresh random value here.
   */
  authReqId?: string;
  /**
   * Include the per-verb step-up scope `urn:atlas:pca:stepup:<verb>` next to `openid`. Default `true`.
   * Real providers reject scopes that are not registered for the client (Keycloak answers `invalid_scope`),
   * and per-verb scopes are open-ended, so set `false` when the OP has no such scope; the verb is then
   * carried by the `binding_message` alone.
   */
  stepUpScope?: boolean;
  /** CIBA `login_hint` for the OP: the identifier of the human to notify. */
  loginHint?: string;
  /**
   * Constrain the `binding_message` for providers that restrict it. CIBA Core 7.1 only says the message
   * SHOULD be short and plain text; real providers enforce more (Keycloak 26.8 accepts at most 50
   * characters from a narrow ASCII set and rejects spaces, `$`, `:`, `,`, `(`, `)` and `@` with
   * `invalid_binding_message`). With `tokenOnly` the message is rendered as hyphen-joined tokens using only
   * `A-Za-z0-9._-` (for example `Approve-stripe.payout-80-USD-acct-1`), cut at `maxChars` on a token
   * boundary. Default: the rich one-line form, unchanged.
   */
  bindingMessage?: { maxChars?: number; tokenOnly?: boolean };
  /** CIBA `interval` (seconds, positive integer): minimum poll spacing the OP/broker enforces. Default 5. */
  interval?: number;
  /**
   * The agent's human-facing name used in the binding message ("because you asked <actsFor> to …"),
   * e.g. `"support-bot"`. Default `"your agent"`.
   */
  actsFor?: string;
}

const DEFAULT_EXPIRY_SEC = 300;
const DEFAULT_INTERVAL_SEC = 5;
/** CIBA Core 7.3: `auth_req_id` characters are restricted to A-Z a-z 0-9 . - _ . */
const AUTH_REQ_ID_RE = /^[A-Za-z0-9._-]+$/;
/** 128 bits of base64url is 22 characters; reject anything shorter (CIBA Core 7.3). */
const MIN_AUTH_REQ_ID_LEN = 22;
/** RFC 6749 3.3 `scope-token`: %x21 / %x23-5B / %x5D-7E. */
const SCOPE_TOKEN_RE = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
/** The goal text is free-form (agent / user supplied); cap what is shown to a person on a small screen. */
const MAX_GOAL_CHARS = 100;

/**
 * Make untrusted text safe for a one-line, plain-text approval prompt (CIBA Core 7.1: `binding_message`
 * SHOULD be short and use a limited set of plain-text characters): control characters, line breaks and
 * bidi / zero-width formatting characters become spaces, runs of whitespace collapse.
 */
function plainText(value: string): string {
  return value
    .replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, ' ')
    .replace(/\s+/gu, ' ')
    .trim();
}

function clip(value: string, max: number): string {
  const chars = Array.from(value);
  return chars.length <= max ? value : `${chars.slice(0, max - 1).join('')}…`;
}

const FORGED_CLAUSE_RE = /because\s+you\s+asked/i;

/**
 * R3-05: the approval message is rendered ONLY from this canonical, fixed-order structure. Anything in the
 * step-up that is not part of it is not shown, so it is REFUSED: the person must never approve something the
 * message does not display.
 */
export interface CibaAction {
  verb: string;
  /** Plain non-negative decimal, shown in full. Present together with `currency` and `payee`. */
  amount?: string;
  /** 3-letter currency code, upper-cased; always shown next to the amount. */
  currency?: string;
  /** Who receives the value. Required whenever `amount` is present. */
  payee?: string;
  resource: string;
}

/** Keys of `params` the renderer displays. Every other key makes the request unrenderable. */
const PAYEE_KEYS = ['payee', 'to', 'recipient', 'beneficiary', 'destination'] as const;
const DISPLAYED_PARAM_KEYS: ReadonlySet<string> = new Set(['amount', 'currency', ...PAYEE_KEYS]);
/** verb / resource are identifiers, never free text: this class cannot hold quotes, spaces, bidi or control characters. */
const IDENT_RE = /^[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,63}$/;
const MAX_PAYEE_CHARS = 64;
/** Control, format (bidi, zero-width, joiners), line/paragraph separators, specials and unpaired surrogates. */
const UNDISPLAYABLE_RE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\u2028\u2029\uFFF9-\uFFFD]/u;

function identifier(value: unknown, what: string): string {
  if (typeof value !== 'string' || !IDENT_RE.test(value)) {
    throw new RangeError(`ciba: the step-up ${what} must be a plain identifier (letters, digits and . _ : / # @ + -, at most 64 characters); refusing to render free text in the approval message`);
  }
  if (FORGED_CLAUSE_RE.test(value)) throw new RangeError(`ciba: the step-up ${what} contains an approval-explanation clause`);
  return value;
}

function payeeText(value: unknown): string {
  if (typeof value !== 'string') throw new RangeError('ciba: the payee must be a string (a nested value cannot be shown to the approver)');
  const t = value.normalize('NFC');
  if (t.length === 0 || t.trim() !== t || /\s{2,}/u.test(t)) throw new RangeError('ciba: the payee must be non-empty without leading, trailing or repeated whitespace');
  if (UNDISPLAYABLE_RE.test(t) || /[\r\n\t]/.test(t)) throw new RangeError('ciba: the payee contains control, bidirectional or invisible characters and cannot be displayed');
  if (/["\\]/.test(t)) throw new RangeError('ciba: the payee must not contain quote or backslash characters');
  if (Array.from(t).length > MAX_PAYEE_CHARS) throw new RangeError(`ciba: the payee is longer than ${String(MAX_PAYEE_CHARS)} characters; refusing to truncate what the person approves`);
  if (FORGED_CLAUSE_RE.test(t)) throw new RangeError('ciba: the payee contains an approval-explanation clause');
  // R4-13 lookalikes. NFC already composed what can be composed, so any combining mark left is a stacked/decorative one;
  // compatibility forms (fullwidth, ligatures, circled letters) differ from their plain look-alike under NFKC; and a payee
  // that mixes scripts ("Pаypal", Cyrillic а) is the classic homograph. All are refused. A payee in ONE non-Latin script is
  // legitimate, so it is allowed but rendered WITH its ASCII form (see `asciiForm`) so a whole-script look-alike
  // ("аррlе" in Cyrillic) is never shown as just the text it imitates.
  if (/\p{M}/u.test(t)) throw new RangeError('ciba: the payee contains combining marks and cannot be shown unambiguously');
  if (t.normalize('NFKC') !== t) throw new RangeError('ciba: the payee contains compatibility/fullwidth characters that imitate plain ones');
  if (scriptsOf(t).size > 1) throw new RangeError('ciba: the payee mixes writing systems (a homograph risk); refusing so the person never approves a look-alike');
  return t;
}

/** Writing-system groups present in `t` (letters only; digits, punctuation and spaces are script-neutral). */
const SCRIPT_GROUPS: readonly (readonly [string, RegExp])[] = [
  ['latin', /\p{Script=Latin}/u],
  ['cyrillic', /\p{Script=Cyrillic}/u],
  ['greek', /\p{Script=Greek}/u],
  ['armenian', /\p{Script=Armenian}/u],
  ['hebrew', /\p{Script=Hebrew}/u],
  ['arabic', /\p{Script=Arabic}/u],
  ['cjk', /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Bopomofo}]/u],
  ['indic-thai', /[\p{Script=Devanagari}\p{Script=Bengali}\p{Script=Tamil}\p{Script=Thai}\p{Script=Georgian}]/u],
];
function scriptsOf(t: string): Set<string> {
  const found = new Set<string>();
  for (const ch of t) {
    if (!/\p{L}/u.test(ch)) continue;
    const g = SCRIPT_GROUPS.find(([, re]) => re.test(ch));
    found.add(g ? g[0] : 'other:' + ch);
  }
  return found;
}

/** Plain-ASCII rendering of a payee: itself when ASCII, else the punycode of each word (or \u escapes when IDNA refuses). */
export function asciiForm(payee: string): string {
  if (/^[\x20-\x7E]*$/.test(payee)) return payee;
  return payee
    .split(' ')
    .map((w) => (/^[\x20-\x7E]*$/.test(w) ? w : domainToASCII(w) || Array.from(w, (c) => (c.codePointAt(0)! > 0x7e ? `\\u{${c.codePointAt(0)!.toString(16)}}` : c)).join('')))
    .join(' ');
}

/**
 * Build the canonical action from a step-up. Fail loud (R3-05): unknown `params` keys, a nested or malformed amount,
 * a missing currency or payee next to an amount, two different payee fields, and non-identifier verb / resource all throw.
 */
export function cibaActionFromStepUp(stepUp: StepUpRequest): CibaAction {
  const params = (stepUp.params ?? {}) as Record<string, unknown>;
  if (params === null || typeof params !== 'object' || Array.isArray(params)) throw new RangeError('ciba: step-up params must be an object');
  const unknown = Object.keys(params).filter((k) => !DISPLAYED_PARAM_KEYS.has(k) && params[k] !== undefined);
  if (unknown.length > 0) {
    throw new RangeError(`ciba: step-up params field(s) ${unknown.join(', ')} are not displayed in the approval message (displayable: amount, currency, ${PAYEE_KEYS.join('/')}); refusing so the person never approves a hidden field`);
  }
  const present = (v: unknown): boolean => v !== undefined && v !== null;
  const action: CibaAction = { verb: identifier(stepUp.verb, 'verb'), resource: identifier(stepUp.resource, 'resource') };
  const payeeKeys = PAYEE_KEYS.filter((k) => present(params[k]));
  if (payeeKeys.length > 1) throw new RangeError(`ciba: more than one payee field (${payeeKeys.join(', ')}) in params; the approver would see only one`);
  const hasAmount = present(params['amount']);
  if (hasAmount) {
    const amt = params['amount'];
    const text = typeof amt === 'number' && Number.isFinite(amt) ? String(amt) : typeof amt === 'string' ? amt : '';
    if (!PLAIN_AMOUNT_RE.test(text)) throw new RangeError('ciba: the binding message needs a plain non-negative decimal amount (no sign or exponent)');
    const cur = params['currency'];
    if (typeof cur !== 'string' || !CURRENCY_RE.test(cur)) throw new RangeError('ciba: the binding message needs a 3-letter currency code next to the amount');
    if (payeeKeys.length === 0) throw new RangeError('ciba: an amount needs a payee (payee / to / recipient / beneficiary / destination) so the approver sees who receives it');
    action.amount = text;
    action.currency = cur.toUpperCase();
  } else if (present(params['currency'])) {
    throw new RangeError('ciba: a currency without an amount cannot be displayed');
  }
  if (payeeKeys.length === 1) action.payee = payeeText(params[payeeKeys[0]!]);
  return action;
}

/** A plain non-negative decimal: no sign, no exponent, no leading junk. */
const PLAIN_AMOUNT_RE = /^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/;
const CURRENCY_RE = /^[A-Za-z]{3}$/;

/**
 * Build the CIBA `binding_message`: the one-line human-readable approval context, in the FIXED order
 * `Approve <verb> <amount> <CUR> to "<payee>" on <resource>`. The head is built from the canonical action and is NEVER
 * truncated; only the optional goal-lineage clause ("because you asked <agent> to '<goal>'") may shrink or drop to fit
 * `maxChars`. If the head alone does not fit, throw. Falls back to the salted goal commitment when the plaintext goal
 * isn't carried on the step-up.
 */
function bindingMessage(stepUp: StepUpRequest, actsFor: string, maxChars?: number): string {
  const a = cibaActionFromStepUp(stepUp);
  const head =
    `Approve ${a.verb}` +
    (a.amount !== undefined ? ` ${a.amount} ${a.currency!}` : '') +
    (a.payee !== undefined ? ` to "${a.payee}"${/^[\x20-\x7E]*$/.test(a.payee) ? '' : ` [non-ASCII name; ASCII form: ${asciiForm(a.payee)}]`}` : '') +
    ` on ${a.resource}`;
  const limit = maxChars ?? Infinity;
  if (Array.from(head).length > limit) {
    throw new RangeError(`ciba: the binding message needs ${String(Array.from(head).length)} characters but bindingMessage.maxChars is ${String(maxChars)}; refusing to truncate what the person approves`);
  }
  const plainGoal = stepUp.goal !== undefined ? plainText(stepUp.goal).replace(/['\u2018\u2019]/g, '\u2032') : '';
  const goalText =
    plainGoal.length > 0
      ? clip(plainGoal, MAX_GOAL_CHARS)
      : stepUp.goalCommit.length > 0
        ? `goal ${stepUp.goalCommit.slice(0, 10)}…`
        : undefined;
  if (goalText === undefined) return head;
  const prefix = ` — because you asked ${actsFor} to '`;
  const room = limit - Array.from(head + prefix).length - 1;
  if (room >= Array.from(goalText).length) return `${head}${prefix}${goalText}'`;
  if (room >= 8) return `${head}${prefix}${clip(goalText, room)}'`;
  return head;
}

function tokenise(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/-{2,}/g, '-').replace(/^[-.]+|[-.]+$/g, '');
}

/**
 * The compact, provider-safe rendering used by `bindingMessage: { tokenOnly: true }`, same fixed order:
 * `Approve-<verb>-<amount>-<CUR>-to-<payee>-<resource>`. The message is the human's only view of what they approve,
 * so it is all-or-nothing: the same canonical action as the rich form, a payee that is not plain ASCII (tokenising
 * would silently drop characters) or a limit that would cut any field throws instead of sending a different message.
 */
function compactBindingMessage(stepUp: StepUpRequest, maxChars: number): string {
  const a = cibaActionFromStepUp(stepUp);
  if (a.payee !== undefined && !/^[\x20-\x7E]+$/.test(a.payee)) {
    throw new RangeError('ciba: tokenOnly binding message needs an ASCII payee (tokenising would drop characters the person must see)');
  }
  const raw = ['Approve', a.verb, ...(a.amount !== undefined ? [a.amount, a.currency!] : []), ...(a.payee !== undefined ? ['to', a.payee] : []), a.resource];
  const parts = raw.map(tokenise);
  if (parts.some((p) => p.length === 0)) {
    throw new RangeError('ciba: tokenOnly binding message cannot represent the verb, payee or resource');
  }
  const out = parts.join('-');
  if (out.length > maxChars) {
    throw new RangeError(
      `ciba: the binding message needs ${String(out.length)} characters but bindingMessage.maxChars is ${String(maxChars)}; refusing to truncate what the person approves`,
    );
  }
  return out;
}

/**
 * Map a PCA {@link StepUpRequest} to a {@link CibaAuthRequest}. Pure: derives a stable `auth_req_id`
 * from the step-up id, renders the `binding_message`, and carries the scope / expiry / poll interval.
 * Does not start a flow or notify anyone — that's the broker.
 */
export function toCibaAuthRequest(stepUp: StepUpRequest, opts: CibaRequestOptions = {}): CibaAuthRequest {
  const actsFor = opts.actsFor !== undefined && plainText(opts.actsFor).length > 0 ? clip(plainText(opts.actsFor), 40) : 'your agent';
  const requestedExpiry = opts.expiresInSec !== undefined ? opts.expiresInSec : DEFAULT_EXPIRY_SEC;
  if (!Number.isSafeInteger(requestedExpiry) || requestedExpiry <= 0) {
    throw new RangeError(`ciba: requested_expiry must be a positive integer number of seconds, got ${String(requestedExpiry)}`);
  }
  // The verb is spliced into ONE scope-token. A space in it would otherwise smuggle in extra scope tokens.
  const stepUpScope = `urn:atlas:pca:stepup:${stepUp.verb}`;
  if (!SCOPE_TOKEN_RE.test(stepUpScope)) {
    throw new RangeError('ciba: the step-up verb cannot be carried as an OAuth scope-token (RFC 6749 3.3)');
  }
  const scope = opts.stepUpScope === false ? 'openid' : `openid ${stepUpScope}`;
  const interval = opts.interval !== undefined ? opts.interval : DEFAULT_INTERVAL_SEC;
  if (!Number.isSafeInteger(interval) || interval <= 0) {
    throw new RangeError(`ciba: interval must be a positive integer number of seconds, got ${String(interval)}`);
  }
  const auth_req_id = opts.authReqId ?? hashCanonical({ d: 'atlas-pca/ciba/auth_req_id/v1', stepUp: stepUp.id });
  if (!AUTH_REQ_ID_RE.test(auth_req_id) || auth_req_id.length < MIN_AUTH_REQ_ID_LEN || auth_req_id.length > 1024) {
    throw new RangeError('ciba: auth_req_id must use only A-Za-z0-9.-_ and be 22..1024 characters (CIBA Core 7.3)');
  }
  const bm = opts.bindingMessage;
  if (bm?.maxChars !== undefined && (!Number.isSafeInteger(bm.maxChars) || bm.maxChars < 1)) {
    throw new RangeError('ciba: bindingMessage.maxChars must be a positive integer');
  }
  const maxChars = bm?.maxChars ?? 50;
  const binding_message =
    bm?.tokenOnly === true
      ? compactBindingMessage(stepUp, maxChars)
      : bindingMessage(stepUp, actsFor, bm?.maxChars);
  return {
    auth_req_id,
    binding_message,
    scope,
    requested_expiry: requestedExpiry,
    interval,
    ...(opts.loginHint !== undefined ? { login_hint: opts.loginHint } : {}),
    stepUpId: stepUp.id,
    tier: stepUp.tier,
  };
}

// ---- in-memory broker (POLL + PING/PUSH) ----------------------------------------------------------

/** The settled outcome of a CIBA request, with `pending` while the human hasn't acted and `expired`
 *  once `requested_expiry` elapses. */
export type CibaStatus = 'pending' | 'approved' | 'denied' | 'expired';

/** A broker session: the request plus the (lazily-evaluated) decision state. */
export interface CibaSession {
  auth_req_id: string;
  request: CibaAuthRequest;
  /** Effective status computed at read time (never a stale stored flag). */
  status: CibaStatus;
  /** ms epoch the session was started. */
  createdAt: number;
  /** ms epoch the request expires (`createdAt + requested_expiry·1000`). */
  expiresAt: number;
  /** Who acted, once resolved. */
  decidedBy?: string;
  /** ms epoch the human acted, once resolved. */
  decidedAt?: number;
}

/** Options for {@link createCibaBroker}. */
export interface CibaBrokerOptions {
  /** Clock (ms). Default `Date.now`. Inject for deterministic tests / expiry. */
  now?: () => number;
  /**
   * PING/PUSH mode: called once, synchronously, the moment a session is resolved (approved or denied).
   * Omit it to use pure POLL mode (the caller drives `poll`).
   */
  onComplete?: (session: CibaSession) => void;
}

/**
 * What a CIBA token request (CIBA Core 10.1 / 11) gets back from the broker: `ok` exactly once on
 * approval; otherwise the OAuth `error` the token endpoint must return. After `slow_down`, `interval`
 * is the new minimum spacing in seconds (the old one plus 5, CIBA Core 11).
 */
export type CibaTokenOutcome =
  | { ok: true; session: CibaSession }
  | { ok: false; error: 'authorization_pending' | 'slow_down' | 'access_denied' | 'expired_token' | 'invalid_grant'; interval: number };

/** The in-memory CIBA broker returned by {@link createCibaBroker}. */
export interface CibaBroker {
  /** Begin a backchannel flow for a step-up; returns the CIBA auth request (status starts `pending`). */
  start(stepUp: StepUpRequest, opts?: CibaRequestOptions): CibaAuthRequest;
  /** POLL: the current effective status (`authorization_pending` semantics while `pending`). */
  poll(auth_req_id: string): { status: CibaStatus };
  /**
   * Token-endpoint semantics for POLL mode (CIBA Core 11): enforces the poll `interval` (a request that
   * arrives sooner than `interval` seconds after the previous one gets `slow_down` and the interval grows
   * by 5 s), and makes a successful approval single-use (a replayed `auth_req_id` gets `invalid_grant`).
   * Unlike {@link CibaBroker.poll}, which is a side-effect-free status read.
   */
  token(auth_req_id: string): CibaTokenOutcome;
  /** The human acts out-of-band: approve or deny. Fires `onComplete` (PING/PUSH) if configured. */
  resolve(auth_req_id: string, decision: 'approve' | 'deny', by: string): CibaSession;
  /** Read a full session snapshot (status computed at read time), or `undefined` if unknown. */
  get(auth_req_id: string): CibaSession | undefined;
}

interface StoredSession {
  request: CibaAuthRequest;
  createdAt: number;
  expiresAt: number;
  decision?: 'approve' | 'deny';
  decidedBy?: string;
  decidedAt?: number;
  /** Current minimum poll spacing in seconds (grows by 5 on each `slow_down`). */
  interval: number;
  /** ms epoch of the previous token request. */
  lastPollAt?: number;
  /** An approval is redeemable once. */
  consumed?: boolean;
}

/** Status is computed, never stored — a decision wins, else expiry, else pending (read-time truth). */
function effectiveStatus(s: StoredSession, now: number): CibaStatus {
  if (s.decision === 'approve') return 'approved';
  if (s.decision === 'deny') return 'denied';
  if (now >= s.expiresAt) return 'expired';
  return 'pending';
}

function snapshot(s: StoredSession, now: number): CibaSession {
  return {
    auth_req_id: s.request.auth_req_id,
    request: s.request,
    status: effectiveStatus(s, now),
    createdAt: s.createdAt,
    expiresAt: s.expiresAt,
    ...(s.decidedBy !== undefined ? { decidedBy: s.decidedBy } : {}),
    ...(s.decidedAt !== undefined ? { decidedAt: s.decidedAt } : {}),
  };
}

/**
 * An in-memory CIBA broker. Models the backchannel lifecycle without any network: `start` opens a
 * session, `poll` reports `pending`/`approved`/`denied`/`expired`, and `resolve` records the human's
 * decision. Supports both delivery modes — POLL (caller drives `poll`) and PING/PUSH (an `onComplete`
 * callback fires on resolution). A production deployment swaps this for the real OP + FROST cosigners;
 * the shape stays the same.
 */
export function createCibaBroker(opts: CibaBrokerOptions = {}): CibaBroker {
  const clock = opts.now ?? Date.now;
  const sessions = new Map<string, StoredSession>();
  /** step-up id -> the auth_req_id of its live (pending or approved) flow, so a repeated `start` is idempotent. */
  const liveByStepUp = new Map<string, string>();

  return {
    start(stepUp, reqOpts) {
      const now = clock();
      const existingId = liveByStepUp.get(stepUp.id);
      const existing = existingId !== undefined ? sessions.get(existingId) : undefined;
      if (existing !== undefined) {
        const st = effectiveStatus(existing, now);
        // Never reset a flow that is still waiting or already approved: that would silently discard a decision.
        if (st === 'pending' || st === 'approved') return existing.request;
      }
      // CIBA Core 7.3: an unguessable auth_req_id (160 random bits, base64url) per flow.
      const request = toCibaAuthRequest(stepUp, { ...reqOpts, authReqId: randomBytes(20).toString('base64url') });
      const createdAt = now;
      const stored: StoredSession = {
        request,
        createdAt,
        expiresAt: createdAt + request.requested_expiry * 1000,
        interval: request.interval,
      };
      sessions.set(request.auth_req_id, stored);
      liveByStepUp.set(stepUp.id, request.auth_req_id);
      return request;
    },
    poll(auth_req_id) {
      const s = sessions.get(auth_req_id);
      if (!s) throw new Error(`ciba: unknown auth_req_id ${auth_req_id}`);
      return { status: effectiveStatus(s, clock()) };
    },
    token(auth_req_id) {
      const s = sessions.get(auth_req_id);
      if (!s) return { ok: false, error: 'invalid_grant', interval: DEFAULT_INTERVAL_SEC };
      const now = clock();
      if (s.consumed) return { ok: false, error: 'invalid_grant', interval: s.interval };
      const tooSoon = s.lastPollAt !== undefined && now - s.lastPollAt < s.interval * 1000;
      s.lastPollAt = now;
      if (tooSoon) {
        s.interval += 5;
        return { ok: false, error: 'slow_down', interval: s.interval };
      }
      const st = effectiveStatus(s, now);
      if (st === 'pending') return { ok: false, error: 'authorization_pending', interval: s.interval };
      if (st === 'denied') return { ok: false, error: 'access_denied', interval: s.interval };
      if (st === 'expired') return { ok: false, error: 'expired_token', interval: s.interval };
      s.consumed = true;
      return { ok: true, session: snapshot(s, now) };
    },
    resolve(auth_req_id, decision, by) {
      const s = sessions.get(auth_req_id);
      if (!s) throw new Error(`ciba: unknown auth_req_id ${auth_req_id}`);
      const now = clock();
      const current = effectiveStatus(s, now);
      if (current !== 'pending') {
        throw new Error(`ciba: cannot resolve ${auth_req_id} — already ${current}`);
      }
      s.decision = decision;
      s.decidedBy = by;
      s.decidedAt = now;
      const snap = snapshot(s, now);
      if (opts.onComplete) opts.onComplete(snap);
      return snap;
    },
    get(auth_req_id) {
      const s = sessions.get(auth_req_id);
      return s ? snapshot(s, clock()) : undefined;
    },
  };
}

// ---- risk-adaptive gating + the hand-off back to the cryptographic cosign -------------------------

/**
 * The gate: does this review need a CIBA human-approval round-trip? Only a tier-3 step-up (human
 * required — typically irreversible / high blast-radius) does. A tier-2 step-up is handled by the
 * guardian's auto-cosign, and an `auto`/`deny` review never notifies a human. This is the
 * risk-adaptive interrupt that avoids blanket-approval fatigue.
 */
export function requiresCiba(review: Review): boolean {
  return review.kind === 'step_up' && review.request.tier === 3;
}

/** The budget effect of a settled CIBA decision. */
export interface CibaCosignResult {
  /** The trust budget after applying the decision (recharged on approve, unchanged on deny). */
  budget: TrustBudget;
  /** Whether a (budget-level) cosign was applied. */
  cosigned: boolean;
}

/**
 * Fold a settled CIBA decision back into PCA's trust budget. On `approve`, recharge via `applyCosign`
 * (partial ρ per cosign, or full with `{ full: true }`); on `deny`, the budget is unchanged.
 *
 * NOTE: this is the BUDGET-level effect only. The actual cryptographic cosign that authorises a tier-3
 * action is a FROST threshold signature (`@atlasauth/pca` `threshold`/`frost`), produced out of band and
 * verified by the resource server — CIBA carries the human *decision*, not the signature. A real
 * integration gates `applyCosign` on a verified FROST cosign; here we model the budget recharge the
 * approval authorises.
 */
export function cibaDecisionToCosign(
  decision: 'approve' | 'deny',
  budget: TrustBudget,
  policy: RiskPolicy,
  now: number,
  opts: { full?: boolean } = {},
): CibaCosignResult {
  if (decision === 'approve') return { budget: applyCosign(budget, policy, now, opts), cosigned: true };
  return { budget, cosigned: false };
}

export * from './client';
