import { cellStats, type HarmModel, type Omega } from '@atlasauth/pca-intent';
import { cellOfAction, flatIndex } from './box';
import { cellKey } from './canary';
import { CLARIFY_REASONS, type ClarifyReason } from './card';
import { binEnt } from './stats';
import { isObj, type ActionValues } from './wire';

/**
 * AGENT-INITIATED CLARIFICATION (§3.14, V13). The agent may ask BEFORE acting:
 *
 *   POST /v1/pca/intent/sessions/:sid/clarify   { "candidates": [≤ 8 structured actions], "reason": <enum> }
 *
 * There is no free-text field, and unknown members are refused: a candidate is `{verb, values}` with scalar values
 * only, and `reason` is a closed enum shown as a fixed label. The wallet maps each candidate to its own cell:
 *   - certain cells are answered at once, as a dry run (`admitted` / `denied` / `outside`), at no question cost;
 *   - among the uncertain ones (0 < p < 1, not vetoed, inside every ceiling, not already asked) it picks the cell of
 *     maximal expected information gain I(y; a) under the current asymmetric noise, ties broken by risk weight
 *     μ̃(c)·E[h | c] (descending), then by cell index, then by candidate position; it asks that cell through the trusted
 *     channel. The answer becomes a delta exactly like an `intent_required` answer.
 * Clarified cells are visited cells, so T13's bound Q ≤ |U_0 ∩ Vis| is unchanged, and the per-session cap applies.
 */

export const MAX_CANDIDATES = 8;
const MAX_VALUES = 64;
const MAX_STRING = 256;
const PATH_RE = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$/i;

export interface ClarifyRequest {
  candidates: ActionValues[];
  reason: ClarifyReason;
}

export type ParsedClarify = { ok: true; request: ClarifyRequest } | { ok: false; error: string };

/** Strict parse of a clarification body. Never throws. */
export function parseClarifyRequest(body: unknown): ParsedClarify {
  if (!isObj(body)) return { ok: false, error: 'body must be an object' };
  for (const k of Object.keys(body)) if (k !== 'candidates' && k !== 'reason') return { ok: false, error: `unknown member "${k}" (clarifications carry no text)` };
  if (typeof body.reason !== 'string' || !(CLARIFY_REASONS as readonly string[]).includes(body.reason)) return { ok: false, error: `reason must be one of ${CLARIFY_REASONS.join(', ')}` };
  const cands = body.candidates;
  if (!Array.isArray(cands) || cands.length === 0 || cands.length > MAX_CANDIDATES) return { ok: false, error: `candidates must be 1..${MAX_CANDIDATES} structured actions` };
  const out: ActionValues[] = [];
  for (const [i, c] of cands.entries()) {
    if (!isObj(c)) return { ok: false, error: `candidates[${i}] must be an object` };
    for (const k of Object.keys(c)) if (k !== 'verb' && k !== 'values') return { ok: false, error: `candidates[${i}] has an unknown member "${k}"` };
    if (typeof c.verb !== 'string' || c.verb.length === 0 || c.verb.length > 128) return { ok: false, error: `candidates[${i}].verb must be a non-empty string` };
    if (!isObj(c.values)) return { ok: false, error: `candidates[${i}].values must be an object` };
    const entries = Object.entries(c.values);
    if (entries.length > MAX_VALUES) return { ok: false, error: `candidates[${i}] has too many values` };
    const values: Record<string, number | string> = {};
    for (const [p, v] of entries) {
      if (!PATH_RE.test(p)) return { ok: false, error: `candidates[${i}] has a malformed path` };
      // The agent names only the action. Lifted dimensions (env.acc / env.world / env.prov / env.mon) are computed by
      // the wallet and the verifier, never taken from the agent.
      if (!(p === 'action.resource' || p.startsWith('action.params.'))) return { ok: false, error: `candidates[${i}].values may only name action.params.* or action.resource` };
      if (typeof v === 'number') {
        if (!Number.isSafeInteger(v)) return { ok: false, error: `candidates[${i}].values.${p} must be a safe integer` };
      } else if (typeof v !== 'string' || v.length > MAX_STRING) return { ok: false, error: `candidates[${i}].values.${p} must be a string (≤ ${MAX_STRING}) or an integer` };
      values[p] = v;
    }
    out.push({ verb: c.verb, values });
  }
  return { ok: true, request: { candidates: out, reason: body.reason as ClarifyReason } };
}

export type ClarifyVerdictKind = 'admitted' | 'denied' | 'outside' | 'asked' | 'uncertain';

/** A dry-run verdict for one candidate. It never carries p: the agent learns only what an attempt would learn. */
export interface ClarifyVerdict {
  index: number;
  verdict: ClarifyVerdictKind;
}

export interface ClarifyPlanInput {
  omega: Omega;
  view: {
    p(verb: string, idx: readonly number[]): number;
    vetoed(verb: string, idx: readonly number[]): boolean;
    outsideCeiling(verb: string, idx: readonly number[]): boolean;
  };
  candidates: readonly ActionValues[];
  /** The wallet's lift of an action into Ω̃ (accumulator posts, provenance, world values). Identity when absent. */
  lift?: (a: ActionValues) => ActionValues;
  /** Cells already asked in this session (`verb|i,j,…`). */
  asked: ReadonlySet<string>;
  etaPos: number;
  etaNeg: number;
  harm: HarmModel;
}

export interface ClarifyPlan {
  verdicts: ClarifyVerdict[];
  ask: { index: number; verb: string; idx: number[]; p: number; ig: number } | null;
}

/** Expected information gain of asking a cell with acceptance p under asymmetric noise (bits). */
export function informationGain(p: number, etaPos: number, etaNeg: number): number {
  const py = p * (1 - etaNeg) + (1 - p) * etaPos;
  return binEnt(py) - (p * binEnt(etaNeg) + (1 - p) * binEnt(etaPos));
}

export function planClarification(input: ClarifyPlanInput): ClarifyPlan {
  const verdicts: ClarifyVerdict[] = [];
  let best: { index: number; verb: string; idx: number[]; p: number; ig: number; weight: number; flat: number } | null = null;
  const seen = new Set<string>();
  input.candidates.forEach((cand, index) => {
    const at = cellOfAction(input.omega, input.lift ? input.lift(cand) : cand);
    if (!at) return void verdicts.push({ index, verdict: 'outside' });
    const { vs, idx } = at;
    if (input.view.outsideCeiling(vs.verb, idx) || input.view.vetoed(vs.verb, idx)) return void verdicts.push({ index, verdict: 'denied' });
    const p = input.view.p(vs.verb, idx);
    if (p <= 0) return void verdicts.push({ index, verdict: 'denied' });
    if (p >= 1) return void verdicts.push({ index, verdict: 'admitted' });
    const key = cellKey(vs.verb, idx);
    if (input.asked.has(key)) return void verdicts.push({ index, verdict: 'asked' });
    verdicts.push({ index, verdict: 'uncertain' });
    if (seen.has(key)) return;
    seen.add(key);
    const ig = informationGain(p, input.etaPos, input.etaNeg);
    const s = cellStats(vs, idx, input.harm);
    const cand2 = { index, verb: vs.verb, idx, p, ig, weight: s.mass * s.harm, flat: flatIndex(vs, idx) };
    if (
      !best ||
      cand2.ig > best.ig + 1e-12 ||
      (Math.abs(cand2.ig - best.ig) <= 1e-12 && (cand2.weight > best.weight || (cand2.weight === best.weight && cand2.flat < best.flat)))
    ) best = cand2;
  });
  const b = best as { index: number; verb: string; idx: number[]; p: number; ig: number } | null;
  return { verdicts, ask: b ? { index: b.index, verb: b.verb, idx: b.idx, p: b.p, ig: b.ig } : null };
}
