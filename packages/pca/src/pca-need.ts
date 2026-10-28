import { b64u, canonicalBytesStrict, decodeB64uStrict, hashCanonical } from './hash';
import { strictParse } from './strict-json';

/**
 * THE `pca_need` CHALLENGE PARAMETER (additive, advisory).
 *
 * A resource server that answers `403 insufficient_scope` can add one extra `WWW-Authenticate` auth-param,
 * `pca_need="<base64url JSON>"`, carrying the typed requirement behind the denial: which verb on which resource
 * is missing, the scopes a plain MCP/OAuth client would request, and (optionally) the residual envelope, discharges
 * or escalation tier a PCA-aware client can turn into an approve/amend flow. A stock client ignores unknown
 * auth-params (RFC 9110 section 11.2 / RFC 6750 section 3) and falls back to the scope step-up it already does.
 *
 * It is a HINT. It is unsigned, it never grants or widens anything, and the resource server decides again on the
 * next request from the proof it is shown. A client must treat every field as untrusted display text (an attacker
 * who can alter the header can only make the client ask for more than needed, which the principal then reviews).
 */
export const PCA_NEED_PARAM = 'pca_need';
export const PCA_NEED_DOMAIN = 'atlas-pca/need/v1';
/** Longest encoded value accepted. A header value past this is refused, never truncated. */
export const PCA_NEED_MAX_ENCODED = 2048;

export type PcaNeedKind = 'scope' | 'grant' | 'discharge' | 'escalate';
const KINDS: readonly string[] = ['scope', 'grant', 'discharge', 'escalate'];

export interface PcaNeed {
  v: 1;
  kind: PcaNeedKind;
  verb: string;
  resource: string;
  /** The scopes the plain `scope` parameter of the same challenge names (the stock-client fallback). */
  scopes?: string[];
  /** The grant this need is about, when the server knows it. */
  grant_ref?: string;
  /** Residual envelope (advisory): named numeric ceilings the request would need, e.g. `money.usd`. */
  limits?: Record<string, number>;
  /** Discharges the client could obtain: pinned issuer plus the claim it must attest. */
  discharges?: Array<{ issuer: string; claim: string }>;
  /** Step-up tier (2 guardian, 3 principal) for `kind: 'escalate'`. */
  tier?: 2 | 3;
  /** Digest of the policy the need was computed against. */
  policy_digest?: string;
}

export type PcaNeedCode =
  | 'too_long'
  | 'bad_base64'
  | 'bad_utf8'
  | 'bad_json'
  | 'bad_shape'
  | 'bad_version'
  | 'bad_kind'
  | 'bad_field'
  | 'unknown_member';

export type PcaNeedResult = { ok: true; need: PcaNeed } | { ok: false; code: PcaNeedCode };

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
const isStr = (x: unknown, max: number): x is string => typeof x === 'string' && x.length > 0 && x.length <= max;
const MEMBERS = new Set(['v', 'kind', 'verb', 'resource', 'scopes', 'grant_ref', 'limits', 'discharges', 'tier', 'policy_digest']);
const MAX_LIST = 16;

/** Validate a decoded need. Unknown members are refused: an unreviewed field must not ride along. */
export function validatePcaNeed(x: unknown): PcaNeedResult {
  if (!isObj(x)) return { ok: false, code: 'bad_shape' };
  for (const k of Object.keys(x)) if (!MEMBERS.has(k)) return { ok: false, code: 'unknown_member' };
  if (x.v !== 1) return { ok: false, code: 'bad_version' };
  if (typeof x.kind !== 'string' || !KINDS.includes(x.kind)) return { ok: false, code: 'bad_kind' };
  if (!isStr(x.verb, 128) || !isStr(x.resource, 512)) return { ok: false, code: 'bad_field' };
  if (x.scopes !== undefined && !(Array.isArray(x.scopes) && x.scopes.length <= MAX_LIST && x.scopes.every((s) => isStr(s, 128) && !/\s/.test(s)))) {
    return { ok: false, code: 'bad_field' };
  }
  if (x.grant_ref !== undefined && !isStr(x.grant_ref, 128)) return { ok: false, code: 'bad_field' };
  if (x.policy_digest !== undefined && !isStr(x.policy_digest, 128)) return { ok: false, code: 'bad_field' };
  if (x.tier !== undefined && x.tier !== 2 && x.tier !== 3) return { ok: false, code: 'bad_field' };
  if (x.limits !== undefined) {
    if (!isObj(x.limits) || Object.keys(x.limits).length > MAX_LIST) return { ok: false, code: 'bad_field' };
    for (const [k, v] of Object.entries(x.limits)) {
      if (!isStr(k, 64) || typeof v !== 'number' || !Number.isFinite(v) || v < 0) return { ok: false, code: 'bad_field' };
    }
  }
  if (x.discharges !== undefined) {
    if (!Array.isArray(x.discharges) || x.discharges.length > MAX_LIST) return { ok: false, code: 'bad_field' };
    for (const d of x.discharges) {
      if (!isObj(d) || Object.keys(d).some((k) => k !== 'issuer' && k !== 'claim') || !isStr(d.issuer, 512) || !isStr(d.claim, 256)) {
        return { ok: false, code: 'bad_field' };
      }
    }
  }
  // A step-up tier only means something for an escalation; a tier on another kind is a malformed need.
  if (x.tier !== undefined && x.kind !== 'escalate') return { ok: false, code: 'bad_field' };
  if (x.kind === 'escalate' && x.tier === undefined) return { ok: false, code: 'bad_field' };
  return { ok: true, need: x as unknown as PcaNeed };
}

/** Encode a need as the unpadded base64url of its strict-canonical JSON. Throws on a malformed need or an over-long value. */
export function encodePcaNeed(need: PcaNeed): string {
  const v = validatePcaNeed(need);
  if (!v.ok) throw new RangeError(`encodePcaNeed: malformed need (${v.code})`);
  const enc = b64u(canonicalBytesStrict(need));
  if (enc.length > PCA_NEED_MAX_ENCODED) throw new RangeError('encodePcaNeed: the need is too large for a header');
  return enc;
}

/** Decode a `pca_need` value. Never throws; every failure is a typed code and the caller falls back to plain scope step-up. */
export function decodePcaNeed(value: unknown): PcaNeedResult {
  if (typeof value !== 'string' || value.length === 0) return { ok: false, code: 'bad_base64' };
  if (value.length > PCA_NEED_MAX_ENCODED) return { ok: false, code: 'too_long' };
  const bytes = decodeB64uStrict(value);
  if (bytes === null) return { ok: false, code: 'bad_base64' };
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return { ok: false, code: 'bad_utf8' };
  }
  let parsed: unknown;
  try {
    parsed = strictParse(text);
  } catch {
    return { ok: false, code: 'bad_json' };
  }
  return validatePcaNeed(parsed);
}

/** The content address an approval flow cites for a need (domain-separated, over the canonical form). */
export const pcaNeedDigest = (need: PcaNeed): string => hashCanonical({ d: PCA_NEED_DOMAIN, need });

/**
 * Pull the first `pca_need` auth-param out of a `WWW-Authenticate` header value (one or more RFC 7235 challenges) and
 * decode it. Only a quoted-string value is read. Absent: `null`. Present but bad: the typed failure.
 */
export function pcaNeedFromChallenge(header: unknown): PcaNeedResult | null {
  if (typeof header !== 'string') return null;
  const m = /(?:^|[\s,])pca_need="([^"\\]*)"/.exec(header);
  if (m === null) return null;
  return decodePcaNeed(m[1]);
}
