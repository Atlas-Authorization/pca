import { boundaryExamples, buildSpace, cells, decideCase, replay } from './examples';
import { fmtAct } from './fmt';
import type { Act, Goal, Hole, Hist, Ontology, RelDecl } from './ir';
import { meet } from './nversion';

/** One interpreter's reading of the principal's text. */
export interface Reading { id: string; family: string; deterministic: boolean; goal: Goal; notes: string[] }

/** An action, the admitted actions before it (re-admitted under each reading's own goal: history is counted by the admitting grant) and its relation facts. */
export interface DistinguishingCase { act: Act; prior: Act[]; rels: RelDecl[] }

export interface Question extends DistinguishingCase {
  id: string;
  text: string;
  /** reading ids that allow the action / do not */
  allow: string[];
  notAllow: string[];
  score: number;
}

export const DEFAULT_RISK: Record<string, number> = { read: 1, reversible: 2, external_send: 8, irreversible: 10 };

export interface QuestionOpts {
  /** the IR ontology the readings are decided against (effect classes, parameter types) */
  ont: Ontology;
  /** risk of an action (default: by the effect class of its verb in `ont`; unknown verbs are the riskiest) */
  riskOf?: (a: Act) => number;
  /** probability mass of an action cell (default 1: uniform over cells) */
  massOf?: (a: Act) => number;
}

const h2 = (p: number): number => (p <= 0 || p >= 1 ? 0 : -(p * Math.log2(p) + (1 - p) * Math.log2(1 - p)));
export const allowsWitness = (g: Goal, ont: Ontology, w: DistinguishingCase): boolean => {
  const hist: Hist = replay(g, ont, w.prior, w.rels);
  return decideCase(g, ont, { act: w.act, hist, rels: w.rels }).decision === 'allow';
};
const allowSet = (r: Reading, w: DistinguishingCase, ont: Ontology): boolean => allowsWitness(r.goal, ont, w);

/** Candidate witness actions: decision-cell representatives of the joint space plus every reading's cap sequences. */
function witnesses(readings: Reading[], ont: Ontology): DistinguishingCase[] {
  const goals = readings.map((r) => r.goal);
  const out: DistinguishingCase[] = cells(buildSpace(goals)).cases.map((c) => ({ act: c.act, prior: [], rels: c.rels }));
  for (const r of readings) for (const e of boundaryExamples(r.goal, { ont, extra: goals }).examples) if (e.kind === 'cap_sequence') out.push({ act: e.act, prior: e.hist.adms.map((a) => a.act), rels: e.rels });
  return out;
}

/** Questions over the symmetric difference of the readings, ranked by H2(vote) x risk x mass (best first). */
export function questions(readings: Reading[], opts: QuestionOpts): Question[] {
  const ont = opts.ont;
  const k = readings.length;
  const cls = new Map(ont.verbs.map((v) => [v.verb, v.cls] as const));
  const risk = opts.riskOf ?? ((a: Act) => DEFAULT_RISK[cls.get(a.verb) ?? ''] ?? 10);
  const out: Question[] = [];
  const seen = new Set<string>();
  for (const w of witnesses(readings, ont)) {
    const yes = readings.filter((r) => allowSet(r, w, ont)).map((r) => r.id);
    if (yes.length === 0 || yes.length === k) continue;
    const id = JSON.stringify([w.act, w.prior.length]);
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({
      id, ...w, allow: yes, notAllow: readings.map((r) => r.id).filter((x) => !yes.includes(x)),
      text: `Should this be allowed: ${fmtAct(w.act)}${w.prior.length ? ` (after ${w.prior.length} earlier identical action(s))` : ''}?`,
      score: h2(yes.length / k) * risk(w.act) * (opts.massOf?.(w.act) ?? 1),
    });
  }
  return out.sort((a, b) => b.score - a.score || (a.id < b.id ? -1 : 1));
}

/** Fraction of witness cells on which the readings do not all agree on Allow. */
export function disagreementMass(readings: Reading[], ont: Ontology): number {
  const w = witnesses(readings, ont);
  if (w.length === 0) return 0;
  let split = 0;
  for (const x of w) { const n = readings.filter((r) => allowSet(r, x, ont)).length; if (n > 0 && n < readings.length) split++; }
  return split / w.length;
}

export type Answer = 'allow' | 'deny';
export interface DisambiguationResult {
  status: 'resolved' | 'budget_exhausted';
  /** resolved: the surviving reading(s)' meet (all equivalent). otherwise: the meet of survivors, carrying a Hole. */
  goal: Goal;
  asked: Question[];
  residualMass: number;
  remaining: string[];
}

/**
 * Active disambiguation by version-space halving over the finite class of readings (spec F1). Every question strictly
 * shrinks the class (an answer refutes the readings that disagree with it), so at most k-1 questions; when the question
 * ranking has a balanced split at every step the count is at most ceil(log2 k) (Lean `halving_queries`).
 * Realizability (assumption, stated): the principal's intent is one of the readings. If it is not, no answer pattern
 * reveals it here (each question splits the survivors, so some survivor always matches); the residual guard is the
 * signed boundary-example confirmation (examples.ts), which checks the final policy against the principal directly.
 */
export async function disambiguate(readings: Reading[], ask: (q: Question) => Promise<Answer> | Answer, opts: QuestionOpts & { budget?: number }): Promise<DisambiguationResult> {
  const ont = opts.ont;
  const budget = opts.budget ?? readings.length;
  let active = [...readings];
  const asked: Question[] = [];
  const hole = (hid: string, q: string): Hole => ({ hid, q, domain: [], affects: [], global: true });
  while (active.length > 1 && asked.length < budget) {
    const q = questions(active, opts)[0];
    if (!q) break; // the survivors agree on every witness cell
    asked.push(q);
    const ans = await ask(q);
    const next = active.filter((r) => allowSet(r, q, ont) === (ans === 'allow'));
    // every question is a split of the active class, so some reading matches any answer: `next` is never empty
    active = next;
  }
  const mass = disagreementMass(active, ont);
  const g = meet(active.map((r) => r.goal));
  const canonHoles = (hs: Hole[]): Hole[] => [...hs].sort((a, b) => (a.hid < b.hid ? -1 : a.hid > b.hid ? 1 : 0));
  if (mass > 0) return { status: 'budget_exhausted', goal: { ...g, holes: canonHoles([...g.holes, hole('budget', 'Question budget exhausted with disagreement left.')]) }, asked, residualMass: mass, remaining: active.map((r) => r.id) };
  return { status: 'resolved', goal: g, asked, residualMass: 0, remaining: active.map((r) => r.id) };
}
