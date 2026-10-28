import { renderCard } from './card';
import { decodeGoal, encodeGoal } from './codec';
import { extractCandidates } from './interpret';
import type { Cond, Goal, Quantity } from './ir';
import { canonicalizeGoal, stable } from './normalize';
import type { IntentOntology } from './ontology';

/**
 * Round-trip checks (spec F4).
 * (a) Deterministic card: the card is T1's PolicyCard (`renderCard`, card.ts), one line per clause with exact numbers, and its
 *     lossless token tape decodes back to the goal (G-T10, proved in GoalRender.dfy; `cardRoundTrips` is the TypeScript codec's
 *     check of the same statement).
 * (b) LLM explainer + comparator: a detector, measured by mutation, tighten-only (it can only escalate).
 */

/** decode(encode(goal)) equals the goal: nothing the goal says is lost on the card tape. */
export const cardRoundTrips = (g: Goal): boolean => stable(decodeGoal(encodeGoal(g))) === stable(g);

// ---------------- explainer / comparator (detector, measured by mutation) ----------------

export interface Explainer { id: string; explain(proseLines: string[]): Promise<string> }
export interface Comparator { id: string; family: string; equivalent(goalText: string, explanation: string): Promise<{ equivalent: boolean; reason?: string }> }

/** Round trip (b): the explainer sees ONLY the compiled card lines, never the goal text or the model's reasoning. */
export async function roundTrip(goal: Goal, goalText: string, explainer: Explainer, comparator: Comparator): Promise<'ok' | 'escalate'> {
  try { const e = await explainer.explain(renderCard(goal).lines); return (await comparator.equivalent(goalText, e)).equivalent ? 'ok' : 'escalate'; } catch { return 'escalate'; }
}

/** Offline reference pair: the card lines themselves, judged by a lexical comparator (ids, amounts). */
export const deterministicExplainer: Explainer = { id: 'card-prose', async explain(p) { return p.join('\n'); } };
const cardAmounts = (explanation: string): { ccy: string; minor: number }[] =>
  [...explanation.matchAll(/(\d+) ([A-Z]{3}) minor units/g)].map((m) => ({ ccy: m[2]!, minor: Number(m[1]) }));
export function lexicalComparator(o: IntentOntology): Comparator {
  return {
    id: 'lexical', family: 'rule',
    async equivalent(text, explanation) {
      const a = extractCandidates(text, o), b = extractCandidates(explanation, o);
      const bAmounts = cardAmounts(explanation);
      const ids = (x: string[]): string => [...new Set(x)].sort().join(',');
      if (ids(a.ids) !== ids(b.ids)) return { equivalent: false, reason: 'ids differ' };
      // every amount stated in the policy must be one the principal wrote (the principal may write extras only as decoys)
      const wrote = new Set(a.amounts.map((m) => `${m.ccy}${m.minor}`));
      for (const m of bAmounts) if (!wrote.has(`${m.ccy}${m.minor}`)) return { equivalent: false, reason: `amount ${m.ccy} ${m.minor} not stated by the principal` };
      if (a.amounts.length > 0 && bAmounts.length === 0) return { equivalent: false, reason: 'no amount in the policy' };
      return { equivalent: true };
    },
  };
}

// ---------------- mutation detection ----------------

export type MutationKind = 'widen_cap' | 'widen_where' | 'drop_prohibit' | 'drop_bound' | 'swap_resource' | 'add_grant';
export const MUTATION_KINDS: MutationKind[] = ['widen_cap', 'widen_where', 'drop_prohibit', 'drop_bound', 'swap_resource', 'add_grant'];

const scale = (x: Quantity, f: number): Quantity => (x.u.k === 'money' || x.u.k === 'count' ? { ...x, n: x.n * f } : x);
const mapLitsInCond = (c: Cond, f: (q: Quantity) => Quantity): Cond =>
  c.k === 'cmp' ? { ...c, r: c.r.k === 'lit' && c.r.v.k === 'q' && (c.op === 'lte' || c.op === 'lt') ? { k: 'lit', v: { k: 'q', q: f(c.r.v.q) } } : c.r }
    : c.k === 'and' || c.k === 'or' ? { ...c, a: mapLitsInCond(c.a, f), b: mapLitsInCond(c.b, f) } : c;

/** Semantic mutations that WIDEN the policy (or leave it equal). Returns undefined when the goal has nothing to mutate. */
export function mutateGoal(g: Goal, kind: MutationKind, ontology: IntentOntology): Goal | undefined {
  const x = JSON.parse(JSON.stringify(g)) as Goal;
  switch (kind) {
    case 'widen_cap': { const b = x.bounds[0]; if (!b) return undefined; b.cap = scale(b.cap, 10); return x; }
    case 'widen_where': { const gr = x.grants.find((y) => JSON.stringify(mapLitsInCond(y.cond, (z) => scale(z, 10))) !== JSON.stringify(y.cond)); if (!gr) return undefined; gr.cond = mapLitsInCond(gr.cond, (z) => scale(z, 10)); return x; }
    case 'drop_prohibit': if (x.prohibits.length === 0) return undefined; x.prohibits.pop(); return x;
    case 'drop_bound': if (x.bounds.length === 0) return undefined; x.bounds.pop(); return x;
    case 'swap_resource': {
      const gr = x.grants.find((y) => y.res.k === 'exact'); if (!gr || gr.res.k !== 'exact') return undefined;
      gr.res = { k: 'exact', id: gr.res.id + '9' }; return x;
    }
    case 'add_grant': {
      const have = new Set(x.grants.map((y) => y.verb));
      const v = ontology.verbs.find((y) => y.effect !== 'read' && !have.has(y.id) && !x.prohibits.some((p) => p.target.k === 'verb' && p.target.verb === y.id));
      if (!v) return undefined;
      x.grants.push({ gid: 'injected', verb: v.id, res: { k: 'any', reason: 'injected' }, cond: { k: 'true' } }); x.wildcardAck.push('injected'); return canonicalizeGoal(x);
    }
  }
}

export interface DetectionReport { kind: MutationKind; applied: number; detected: number; rate: number }

/** Fraction of semantic widenings the explainer+comparator pair flags (they can only escalate; this is a measured detector). */
export async function measureDetection(cases: { goal: Goal; text: string }[], ontology: IntentOntology, explainer: Explainer, comparator: Comparator): Promise<DetectionReport[]> {
  const out: DetectionReport[] = [];
  for (const kind of MUTATION_KINDS) {
    let applied = 0, detected = 0;
    for (const c of cases) {
      const m = mutateGoal(c.goal, kind, ontology);
      if (!m) continue;
      applied++;
      if ((await roundTrip(m, c.text, explainer, comparator)) === 'escalate') detected++;
    }
    out.push({ kind, applied, detected, rate: applied ? detected / applied : 0 });
  }
  return out;
}
