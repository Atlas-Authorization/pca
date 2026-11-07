/**
 * The client half of MCP authorization step-up, with the PCA extension.
 *
 * - {@link parseChallenges}: a small RFC 9110 section 11 `WWW-Authenticate` parser (quoted strings, several challenges).
 * - {@link planStepUp}: what to do with a `403 insufficient_scope`. A stock client takes the `scope` union and
 *   re-authorizes (MCP "Step-Up Authorization Flow"). A PCA-aware client that finds a valid `pca_need` hands the typed
 *   requirement to its approval flow instead, and still carries the scope union as the fallback. It never approves anything.
 * - {@link checkAuthorizationResponseIss}: the RFC 9207 section 2.4 table from the MCP authorization specification.
 *
 * Sources (fetched 2026-10-26): MCP authorization, revisions 2025-11-25, 2026-07-28 and draft, section "Scope Challenge
 * Handling" and "Authorization Response Validation"; RFC 6750 section 3; RFC 9207.
 */

import { pcaNeedFromChallenge, type PcaNeed, type PcaNeedCode } from '@atlasauth/pca';

export interface Challenge {
  /** Lower-cased auth scheme (`bearer`, `pca-stepup`, ...). */
  scheme: string;
  /** Parameter names lower-cased; quoted-string values unescaped. A repeated name keeps its FIRST value. */
  params: Record<string, string>;
}

/** Parse the value of a `WWW-Authenticate` header into its challenges. Tolerant of garbage: it never throws. */
export function parseChallenges(header: unknown): Challenge[] {
  const out: Challenge[] = [];
  if (typeof header !== 'string') return out;
  let i = 0;
  const n = header.length;
  const ws = (): void => {
    while (i < n && (header[i] === ' ' || header[i] === '\t' || header[i] === ',')) i++;
  };
  const token = (): string => {
    const s = i;
    while (i < n && !' \t,="'.includes(header[i] as string)) i++;
    return header.slice(s, i);
  };
  let cur: Challenge | null = null;
  ws();
  while (i < n) {
    const name = token();
    if (name === '') {
      i++; // a stray quote or equals sign: skip it
      continue;
    }
    while (i < n && (header[i] === ' ' || header[i] === '\t')) i++;
    if (header[i] === '=' ) {
      i++;
      while (i < n && (header[i] === ' ' || header[i] === '\t')) i++;
      let val = '';
      if (header[i] === '"') {
        i++;
        while (i < n && header[i] !== '"') {
          if (header[i] === '\\' && i + 1 < n) i++;
          val += header[i];
          i++;
        }
        i++; // closing quote
      } else {
        val = token();
      }
      if (cur !== null && !(name.toLowerCase() in cur.params)) cur.params[name.toLowerCase()] = val;
    } else {
      cur = { scheme: name.toLowerCase(), params: {} };
      out.push(cur);
    }
    ws();
  }
  return out;
}

export interface StepUpState {
  /** Scopes already requested (granted or attempted) for this client and resource. */
  requested: readonly string[];
  /** Step-up attempts already made for this resource and operation. */
  attempts: number;
  /** Retry limit ("no more than a few times"). Default 3. */
  maxAttempts?: number;
  /** Opt in to the PCA flow. A stock client leaves this off and never looks at `pca_need`. Default false. */
  pcaAware?: boolean;
}

export type StepUpPlan =
  | { action: 'scope'; scopes: string[]; attempts: number }
  | { action: 'pca'; need: PcaNeed; fallbackScopes: string[]; attempts: number }
  | { action: 'give_up'; reason: 'not_insufficient_scope' | 'retry_limit' | 'no_new_scope' };

const splitScopes = (s: string | undefined): string[] => (s === undefined ? [] : s.split(' ').filter((x) => x.length > 0));

/**
 * Decide the next step for a response. Only `403` with `error="insufficient_scope"` on a Bearer challenge is a step-up.
 * The scope list is the UNION of what was requested before and what the challenge names (MCP: preserve previously granted
 * permissions), sorted so retries are deterministic. If the union adds nothing and there is no usable `pca_need`, asking
 * again cannot succeed, so give up instead of looping. The attempt counter bounds every path.
 */
export function planStepUp(status: number, wwwAuthenticate: unknown, state: StepUpState): StepUpPlan {
  const max = state.maxAttempts ?? 3;
  const bearer = status === 403 ? parseChallenges(wwwAuthenticate).find((c) => c.scheme === 'bearer') : undefined;
  if (bearer === undefined || bearer.params.error !== 'insufficient_scope') return { action: 'give_up', reason: 'not_insufficient_scope' };
  if (state.attempts >= max) return { action: 'give_up', reason: 'retry_limit' };
  const had = new Set(state.requested);
  const union = [...new Set([...state.requested, ...splitScopes(bearer.params.scope)])].sort();
  const attempts = state.attempts + 1;
  if (state.pcaAware === true) {
    const r = typeof wwwAuthenticate === 'string' ? pcaNeedFromChallenge(wwwAuthenticate) : null;
    if (r !== null && r.ok) return { action: 'pca', need: r.need, fallbackScopes: union, attempts };
    // a missing or malformed pca_need is not an error: fall through to the stock behaviour
  }
  if (union.every((s) => had.has(s))) return { action: 'give_up', reason: 'no_new_scope' };
  return { action: 'scope', scopes: union, attempts };
}

/** The reason a present-but-unusable `pca_need` was ignored, for client logs. */
export function pcaNeedProblem(wwwAuthenticate: unknown): PcaNeedCode | null {
  const r = pcaNeedFromChallenge(wwwAuthenticate);
  return r !== null && !r.ok ? r.code : null;
}

export type IssDecision = { proceed: true } | { proceed: false; reason: 'iss_missing' | 'iss_mismatch' | 'no_recorded_issuer' };

/**
 * RFC 9207 section 2.4 as tabulated in the MCP authorization specification (2026-07-28, draft): compare a present `iss`
 * with the recorded issuer by simple string comparison (no case folding, default-port elision, trailing-slash or
 * percent-encoding normalization); reject an absent `iss` only when the server advertised
 * `authorization_response_iss_parameter_supported: true`. The recorded issuer must have been captured from validated
 * metadata BEFORE the redirect; without one nothing can be checked and the response is refused. Applies equally to error
 * responses: on a mismatch the caller must not act on or display `error`, `error_description` or `error_uri`.
 */
export function checkAuthorizationResponseIss(a: { recordedIssuer: string | undefined; issParameterSupported: boolean | undefined; iss: string | undefined }): IssDecision {
  if (typeof a.recordedIssuer !== 'string' || a.recordedIssuer.length === 0) return { proceed: false, reason: 'no_recorded_issuer' };
  if (a.iss === undefined) {
    return a.issParameterSupported === true ? { proceed: false, reason: 'iss_missing' } : { proceed: true };
  }
  return a.iss === a.recordedIssuer ? { proceed: true } : { proceed: false, reason: 'iss_mismatch' };
}
