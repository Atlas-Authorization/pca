import type { Caveat } from '@atlasauth/pca';
import { REVERSIBILITY_ORDER } from './types';

/**
 * Static satisfiability of a PCA envelope caveat set (the leaf's cumulative, append-only, conjunctive
 * caveats). This answers "is there ANY runtime context under which these caveats can all hold?" — the
 * global gate on whether the authority can ever admit anything.
 *
 * The caveats constrain the runtime CaveatContext (now, blast radius, delegation depth, rate window,
 * reversibility class), not the action's predicate fields. The analyzer treats the context as chosen
 * favourably (the most permissive the authority could ever encounter) — the right stance for "what can
 * this authority EVER do". The one caveat tied to the action itself is `reversibility_max`, whose cap
 * is returned so the per-action check can enforce `class(action) <= cap`.
 *
 * Mirrors `envelopeCaveatEvaluator` in @atlasauth/pca (unknown/ malformed => fail closed).
 */
export interface CaveatAnalysis {
  /** Some context satisfies every caveat. */
  sat: boolean;
  reason?: string;
  /** Strictest `reversibility_max` cap as an index into REVERSIBILITY_ORDER, if any caveat sets one. */
  revCap?: number;
}

function finite(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}

export function analyzeCaveats(caveats: readonly Caveat[] | undefined): CaveatAnalysis {
  if (!Array.isArray(caveats)) return { sat: false, reason: 'caveats are not an array' };
  let notBeforeMax = -Infinity; // the action can only happen at now >= this
  let expiresMin = Infinity; // ...and now < this
  let revCap: number | undefined;

  for (const cv of caveats) {
    if (cv === null || typeof cv !== 'object' || typeof cv.type !== 'string') {
      return { sat: false, reason: 'malformed caveat (not an object with a string type)' };
    }
    switch (cv.type) {
      case 'expires': {
        const at = finite(cv.at);
        if (at === undefined) return { sat: false, reason: 'expires.at is not a finite number' };
        expiresMin = Math.min(expiresMin, at);
        break;
      }
      case 'not_before': {
        const at = finite(cv.at);
        if (at === undefined) return { sat: false, reason: 'not_before.at is not a finite number' };
        notBeforeMax = Math.max(notBeforeMax, at);
        break;
      }
      case 'rate': {
        const max = finite(cv.max);
        const per = finite(cv.per_secs);
        if (max === undefined || per === undefined || per <= 0) {
          return { sat: false, reason: 'rate caveat requires finite max and per_secs > 0' };
        }
        // With zero prior actions the count is 0, so the gate `0 < max` needs max >= 1.
        if (max < 1) return { sat: false, reason: `rate.max ${max} < 1 forbids every action` };
        break;
      }
      case 'max_blast_radius': {
        const max = finite(cv.max);
        if (max === undefined) return { sat: false, reason: 'max_blast_radius.max is not a finite number' };
        // The least blast radius is 0, so this is satisfiable iff max >= 0.
        if (max < 0) return { sat: false, reason: 'max_blast_radius.max < 0 forbids every action' };
        break;
      }
      case 'reversibility_max': {
        const idx = (REVERSIBILITY_ORDER as readonly string[]).indexOf(String(cv.class));
        if (idx < 0) return { sat: false, reason: `reversibility_max.class '${String(cv.class)}' is unknown` };
        revCap = revCap === undefined ? idx : Math.min(revCap, idx);
        break;
      }
      case 'delegation_depth': {
        const max = finite(cv.max);
        if (max === undefined) return { sat: false, reason: 'delegation_depth.max is not a finite number' };
        // The least depth is 0, so this is satisfiable iff max >= 0.
        if (max < 0) return { sat: false, reason: 'delegation_depth.max < 0 forbids every action' };
        break;
      }
      case 'budget_alloc': {
        const lim = finite(cv.limit);
        if (lim === undefined || lim < 0) {
          return { sat: false, reason: 'budget_alloc.limit must be a finite number >= 0' };
        }
        break;
      }
      default:
        return { sat: false, reason: `unknown caveat type '${cv.type}' (fail closed)` };
    }
  }

  if (notBeforeMax !== -Infinity && expiresMin !== Infinity && notBeforeMax >= expiresMin) {
    return {
      sat: false,
      reason: `not_before (${notBeforeMax}) >= expires (${expiresMin}): the validity window is empty`,
    };
  }
  return { sat: true, revCap };
}
