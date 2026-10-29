/**
 * DETECTOR ADAPTERS: vendor guardrail responses to signed, tighten-only receipts (track K9).
 *
 * The gateway that calls a detector signs what it saw (`@atlasauth/pca` `signDetectorReceipt`); the verifier pins the
 * gateway key and folds the receipts with `detectorSignal`, where `suspicious` can only lower a decision and `no_finding` is
 * exactly no receipt. The adapters below are deliberately one-sided: a response is `no_finding` only when it is well-formed
 * AND says nothing was detected. Anything malformed, unexpected or ambiguous becomes `suspicious` with category
 * `detector_error`, so a broken integration adds friction instead of looking clean. (A clean answer buys nothing anyway.)
 *
 * Response shapes:
 *   - Lakera Guard `POST /v2/guard` (docs.lakera.ai `api-reference/lakera-api/guard/screen-content`, fetched 2026-10-27):
 *     `{flagged: boolean, breakdown?: [{detector_type, detected, ...}], metadata: {request_uuid}, ...}`. In `detect` mode
 *     `flagged` is always false, so the per-detector `breakdown[].detected` is read as well.
 *   - Prompt Security `POST https://<region>.prompt.security/api/protect`: UNVERIFIED against the vendor's own
 *     documentation (prompt.security/docs answered 404 and docs.prompt.security did not resolve, 2026-10-27, twice). Two
 *     open-source integrations read DIFFERENT shapes: LiteLLM (BerriAI/litellm aa33b052 `guardrail_hooks/prompt_security`)
 *     reads `result.prompt.action` and `result.prompt.violations[]`; NVIDIA NeMo Guardrails (`library/prompt_security/
 *     actions.py`, develop branch) reads `result.action` (default `log`), `block` blocks, `modify` rewrites. This adapter
 *     accepts both and is clean only when every action present is neither `block` nor `modify` and no violation is listed.
 *   - generic: `{flagged: boolean, categories?: string[]}`.
 */
import { detectorInputDigest, signDetectorReceipt, type DetectorReceipt, type DetectorReceiptBody } from '@atlasauth/pca';

export interface AdapterContext {
  /** Policy id of the detector (`^[a-z][a-z0-9_]{0,63}$`). */
  detector: string;
  /** Model / ruleset version reported by the vendor or configured (1..64 bytes). */
  version: string;
  /** The exact content sent to the detector. */
  content: unknown;
  /** The gateway's signing key. */
  secretKey: Uint8Array;
  /** Epoch ms. */
  now: number;
  session?: string;
  calibration_ref?: string;
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const CAT_RE = /^[a-z][a-z0-9_]{0,63}$/;
/** Vendor category text to a receipt category id (lowercase, non-alphanumerics to `_`); unusable text becomes `other`. */
export function categoryId(s: unknown): string {
  if (typeof s !== 'string') return 'other';
  const c = s.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').replace(/^([0-9])/, 'c_$1').slice(0, 64);
  return CAT_RE.test(c) ? c : 'other';
}

function receipt(ctx: AdapterContext, suspicious: boolean, categories: Iterable<string>): DetectorReceipt {
  const cats = suspicious ? [...new Set(categories)].sort().slice(0, 8) : [];
  const body: DetectorReceiptBody = {
    v: 1,
    kind: 'pca-detector-receipt',
    detector: ctx.detector,
    version: ctx.version,
    input_digest: detectorInputDigest(ctx.content),
    verdict: suspicious ? 'suspicious' : 'no_finding',
    categories: cats,
    iat: ctx.now,
    ...(ctx.session !== undefined ? { session: ctx.session } : {}),
    ...(ctx.calibration_ref !== undefined ? { calibration_ref: ctx.calibration_ref } : {}),
  };
  return signDetectorReceipt(body, ctx.secretKey);
}
const errorReceipt = (ctx: AdapterContext) => receipt(ctx, true, ['detector_error']);

/** Lakera Guard v2 `/guard` response. */
export function lakeraReceipt(response: unknown, ctx: AdapterContext): DetectorReceipt {
  if (!isObj(response) || typeof response.flagged !== 'boolean') return errorReceipt(ctx);
  const cats = new Set<string>();
  if (response.breakdown !== undefined) {
    if (!Array.isArray(response.breakdown)) return errorReceipt(ctx);
    for (const b of response.breakdown) {
      if (!isObj(b) || typeof b.detected !== 'boolean') return errorReceipt(ctx);
      if (b.detected) cats.add(categoryId(b.detector_type));
    }
  }
  const suspicious = response.flagged || cats.size > 0;
  if (suspicious && cats.size === 0) cats.add('flagged');
  return receipt(ctx, suspicious, cats);
}

/** Prompt Security `/api/protect` response (shape UNVERIFIED, see the module comment; both integration shapes accepted). */
export function promptSecurityReceipt(response: unknown, ctx: AdapterContext): DetectorReceipt {
  const r = isObj(response) && isObj(response.result) ? response.result : undefined;
  if (!r) return errorReceipt(ctx);
  const p = r.prompt;
  if (p !== undefined && !isObj(p)) return errorReceipt(ctx);
  const actions = [r.action, isObj(p) ? p.action : undefined].filter((a) => a !== undefined);
  if (actions.length === 0 || !actions.every((a) => typeof a === 'string')) return errorReceipt(ctx);
  const violations = isObj(p) ? p.violations : undefined;
  if (violations !== undefined && !Array.isArray(violations)) return errorReceipt(ctx);
  const cats = new Set(((violations as unknown[]) ?? []).map(categoryId));
  if (actions.includes('block')) cats.add('blocked');
  if (actions.includes('modify')) cats.add('modified');
  return receipt(ctx, cats.size > 0, cats);
}

/** Any detector that answers `{flagged, categories?}`. */
export function genericReceipt(response: unknown, ctx: AdapterContext): DetectorReceipt {
  if (!isObj(response) || typeof response.flagged !== 'boolean') return errorReceipt(ctx);
  if (response.categories !== undefined && !Array.isArray(response.categories)) return errorReceipt(ctx);
  const cats = new Set(((response.categories as unknown[]) ?? []).map(categoryId));
  if (!response.flagged && cats.size > 0) return errorReceipt(ctx); // categories on a clean answer: ambiguous
  if (response.flagged && cats.size === 0) cats.add('flagged');
  return receipt(ctx, response.flagged, cats);
}
