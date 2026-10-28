import { hashCanonical, type SignerSuiteOpts } from '@atlasauth/pca';
import { goalDigest } from './digests';
import type { Act, Cond, Decision, Goal, Grant, Hist, Ontology, Quantity, RelDecl, ResPart, ResSel, Value } from './ir';
import { stable } from './normalize';
import { refExplain } from './refsem';
import { signPayload, verifyPayload, type PinnedSigner, type SignedPayload, type SignerSecret } from './sign';

/**
 * Boundary examples and signed GoalTests (spec F2), over the Goal IR (ir.ts) and its reference semantics (refsem.ts).
 *
 * Decision cells. An action is classified per coordinate (verb, resource, relation bits, each parameter) against the
 * literals of the policy(ies). Every comparison in the decided fragment (cmp against literals, exact/oneof/related/all_of
 * selectors, verb match) depends only on that classification, so actions in one cell get one decision, and `cells()`
 * enumerates one representative per cell: any other policy over the same literals that differs on a cell differs on a
 * representative (the coverage theorem, tested in core.test.ts). History-dependent bounds are covered by the
 * separate cap sequences. A literal missing from the policy is not a coordinate: only the unmentioned-dimension
 * probes reach it (stated assumption).
 *
 * Relation membership lives in the IR ontology (`Ontology.rels`), so a decision cell that fixes "this resource is / is not in
 * that relation" carries those facts with it: a `Case` is an action plus the relation facts it is decided under.
 */
export interface Space {
  verbs: string[];
  resources: string[];
  rels: { rel: string; anchor: string }[];
  /** param -> quantity groups (unit key -> sorted distinct values) and discrete (string) literals */
  q: Map<string, Map<string, number[]>>;
  d: Map<string, string[]>;
}

/** An action and the relation facts it is decided under (replacing `Ontology.rels` for this decision). */
export interface Case { act: Act; rels: RelDecl[] }

export const EMPTY_HIST: Hist = { adms: [], last: -1, aggs: {} };
export const decisionOf = (d: 0 | 1 | 2): Decision => (d === 2 ? 'allow' : d === 1 ? 'escalate' : 'deny');
export const rankOf = (d: Decision): number => (d === 'allow' ? 0 : d === 'escalate' ? 1 : 2);
/** An action with the fixed envelope the examples use (one session, one principal, no delegation, time 0). */
export const mkAct = (verb: string, res: string, params: Act['params'] = {}, over: Partial<Act> = {}): Act => ({ verb, res, params, t: 0, sess: 's', prin: 'p', org: 'o', agent: 'a', depth: 0, ...over });

export interface Verdict { decision: Decision; /** the admitting grant of an Allow */ witness: string | null; /** a prohibition fires or is unknown for this action */ prohibited: boolean }
/** The reference decision of a goal for an action, its history and its relation facts. */
export function decideCase(g: Goal, ont: Ontology, c: { act: Act; hist?: Hist; rels?: RelDecl[] }): Verdict {
  const x = refExplain(g, c.rels ? { ...ont, rels: c.rels } : ont, c.act, c.hist ?? EMPTY_HIST);
  return { decision: decisionOf(x.d), witness: x.witness, prohibited: x.prohibit < 2 };
}
/** The history of the admitted prefix of `acts`: an action refused by the goal is not recorded (the PEP records only admitted actions). */
export function replay(g: Goal, ont: Ontology, acts: Act[], rels: RelDecl[]): Hist {
  const h: Hist = { adms: [], last: -1, aggs: {} };
  for (const act of acts) {
    const v = decideCase(g, ont, { act, hist: h, rels });
    if (v.decision === 'allow' && v.witness !== null) { h.adms.push({ gid: v.witness, act }); h.last = act.t; }
  }
  return h;
}

const qval = (q: Quantity): number => q.n;
const qkey = (q: Quantity): string => (q.u.k === 'money' ? `money:${q.u.ccy}` : q.u.k);
const unitOfKey = (key: string): Quantity['u'] => (key.startsWith('money:') ? { k: 'money', ccy: key.slice(6) } : { k: key as 'count' });
const dkey = (v: Value): string | undefined => (v.k === 's' ? `s:${v.s}` : undefined);

function walkCond(c: Cond, f: (p: string, v: Value) => void): void {
  if (c.k === 'cmp') {
    const p = c.l.k === 'param' ? c.l.path : c.r.k === 'param' ? c.r.path : undefined;
    const other = c.l.k === 'param' ? c.r : c.l;
    if (p === undefined || other.k !== 'lit') return;
    if (other.v.k === 'set') other.v.items.forEach((v) => f(p, v)); else f(p, other.v);
  } else if (c.k === 'and' || c.k === 'or') { walkCond(c.a, f); walkCond(c.b, f); }
  else if (c.k === 'not') walkCond(c.c, f);
}
const parts = (s: ResSel): ResPart[] => (s.k === 'all_of' ? s.parts : s.k === 'any' ? [] : [s]);

export function buildSpace(goals: Goal[], extraVerbs: string[] = []): Space {
  const verbs = new Set<string>(extraVerbs), resources = new Set<string>(), rels = new Map<string, { rel: string; anchor: string }>();
  const q = new Map<string, Map<string, Set<number>>>(), d = new Map<string, Set<string>>();
  const lit = (p: string, v: Value): void => {
    if (v.k === 'q') { const m = q.get(p) ?? new Map(); const s = m.get(qkey(v.q)) ?? new Set(); s.add(qval(v.q)); m.set(qkey(v.q), s); q.set(p, m); }
    else { const k = dkey(v); if (k === undefined) return; const s = d.get(p) ?? new Set(); s.add(k); d.set(p, s); }
  };
  const res = (s: ResSel): void => parts(s).forEach((x) => {
    if (x.k === 'exact') resources.add(x.id); else if (x.k === 'oneof') x.ids.forEach((i) => resources.add(i)); else rels.set(x.rel + '\0' + x.anchor, { rel: x.rel, anchor: x.anchor });
  });
  for (const g of goals) {
    for (const gr of g.grants) { verbs.add(gr.verb); res(gr.res); walkCond(gr.cond, lit); }
    for (const p of g.prohibits) { if (p.target.k === 'verb') verbs.add(p.target.verb); res(p.res); walkCond(p.cond, lit); }
    g.escalateOn.forEach((c) => walkCond(c, lit));
    for (const b of g.bounds) if (b.agg === 'sum' && b.value.k === 'param') lit(b.value.path, { k: 'q', q: b.cap }); // reps around the cap so witnesses carry the summed param
  }
  const sortNum = (s: Set<number>): number[] => [...s].sort((a, b) => a - b);
  return {
    verbs: [...verbs].sort(), resources: [...resources].sort(), rels: [...rels.values()].sort((a, b) => (a.rel + a.anchor < b.rel + b.anchor ? -1 : 1)),
    q: new Map([...q].map(([p, m]) => [p, new Map([...m].map(([k, s]) => [k, sortNum(s)]))])),
    d: new Map([...d].map(([p, s]) => [p, [...s].sort()])),
  };
}

function classifyLit(sp: Space, p: string, l: Value | undefined): string {
  if (l === undefined || l.k === 'set') return 'missing';
  const groups = sp.q.get(p), ds = sp.d.get(p);
  if (l.k === 'q') {
    const g = groups?.get(qkey(l.q));
    if (!g) return groups || ds ? 'unit' : 'any';
    const v = qval(l.q);
    const i = g.indexOf(v);
    if (i >= 0) return `${qkey(l.q)}=${i}`;
    let pos = 0; while (pos < g.length && g[pos]! < v) pos++;
    return `${qkey(l.q)}@${pos}`; // strictly between literal pos-1 and pos
  }
  const k = dkey(l)!;
  if (!ds) return groups ? 'unit' : 'any';
  return ds.includes(k) ? k : 'other';
}

const relBit = (c: Case, rel: string, anchor: string): number => (c.rels.find((x) => x.rel === rel && x.anchor === anchor)?.members.includes(c.act.res) ? 1 : 0);

/** The decision cell of a case under a space (canonical string; the unit of precedents). */
export function cellKey(sp: Space, c: Case): string {
  const params = new Set<string>([...sp.q.keys(), ...sp.d.keys()]);
  return stable({
    v: sp.verbs.includes(c.act.verb) ? c.act.verb : '*',
    r: sp.resources.includes(c.act.res) ? c.act.res : '*',
    l: sp.rels.map((x) => relBit(c, x.rel, x.anchor)),
    p: Object.fromEntries([...params].sort().map((p) => [p, classifyLit(sp, p, c.act.params[p])])),
  });
}

const OTHER = '\u0000other';
function paramOptions(sp: Space, p: string): (Value | undefined)[] {
  const out: (Value | undefined)[] = [undefined];
  const seen = new Set<string>();
  const add = (v: Value): void => { const k = stable(v); if (!seen.has(k)) { seen.add(k); out.push(v); } };
  for (const [key, vals] of sp.q.get(p) ?? []) {
    const isInstant = key === 'instant';
    for (const v of vals) for (const x of [v - 1, v, v + 1]) if (x >= 0 || isInstant) add({ k: 'q', q: { u: unitOfKey(key), n: x } });
    if (key.startsWith('money:')) add({ k: 'q', q: { u: { k: 'money', ccy: 'ZZZ' }, n: 0 } }); // unit mismatch -> Unknown
  }
  for (const k of sp.d.get(p) ?? []) add({ k: 's', s: k.slice(2) });
  if (sp.d.has(p)) add({ k: 's', s: OTHER });
  return out;
}

export const MAX_CELLS = 40_000;

export interface Cells { cases: Case[]; complete: boolean }

/** One representative per decision cell. `complete:false` when the grid exceeded MAX_CELLS (then it is a subset). */
export function cells(sp: Space, opts: { verbs?: string[] } = {}): Cells {
  const verbs = opts.verbs ?? [...sp.verbs, '\u0000other-verb'];
  const resources = [...sp.resources, '\u0000other-resource'];
  const params = [...new Set<string>([...sp.q.keys(), ...sp.d.keys()])].sort();
  const pOpts = params.map((p) => paramOptions(sp, p));
  const relBits = sp.rels.length;
  let total = verbs.length * resources.length * 2 ** relBits;
  for (const o of pOpts) total *= o.length;
  const complete = total <= MAX_CELLS;
  const out: Case[] = [];
  const seen = new Set<string>();
  const push = (c: Case): void => { const k = cellKey(sp, c); if (!seen.has(k)) { seen.add(k); out.push(c); } };
  const build = (verb: string, resource: string, bits: number, choice: (Value | undefined)[]): Case => {
    const pr: Act['params'] = {};
    params.forEach((p, i) => { if (choice[i] !== undefined) pr[p] = choice[i]!; });
    return { act: mkAct(verb, resource, pr), rels: sp.rels.map((x, i) => ({ rel: x.rel, anchor: x.anchor, members: bits & (1 << i) ? [resource] : [] })) };
  };
  if (complete) {
    const idx = new Array(params.length).fill(0) as number[];
    for (const verb of verbs) for (const res of resources) for (let bits = 0; bits < 2 ** relBits; bits++) {
      idx.fill(0);
      for (;;) {
        push(build(verb, res, bits, idx.map((j, i) => pOpts[i]![j])));
        let k = 0;
        while (k < idx.length && ++idx[k]! === pOpts[k]!.length) { idx[k] = 0; k++; }
        if (k === idx.length) break;
      }
    }
  } else {
    // Subset: the all-defaults base plus every single-coordinate perturbation of it.
    const base = (verb: string): Case => build(verb, resources[0]!, 0, pOpts.map((o) => o[Math.min(2, o.length - 1)]));
    for (const verb of verbs) {
      push(base(verb));
      for (const res of resources) for (let bits = 0; bits < 2 ** relBits; bits++) push(build(verb, res, bits, pOpts.map((o) => o[Math.min(2, o.length - 1)])));
      pOpts.forEach((o, i) => o.forEach((l) => { const ch = pOpts.map((x) => x[Math.min(2, x.length - 1)]); ch[i] = l; push(build(verb, resources[0]!, 0, ch)); }));
    }
  }
  return { cases: out, complete };
}

const magnitude = (a: Act): number => Object.values(a.params).reduce((s, v) => s + (v.k === 'q' ? Math.abs(qval(v.q)) : 0), 0);

/** The smallest-magnitude case the grant admits (a minimal Allow witness), or undefined if its Allow set is empty. */
export function allowWitness(g: Goal, gr: Grant, ont: Ontology): Case | undefined {
  const sp = buildSpace([g]);
  let best: Case | undefined;
  for (const c of cells(sp, { verbs: [gr.verb] }).cases) {
    const v = decideCase(g, ont, c);
    if (v.decision === 'allow' && v.witness === gr.gid && (!best || magnitude(c.act) < magnitude(best.act))) best = c;
  }
  return best;
}

export type ExampleKind = 'allow_witness' | 'prohibit_trigger' | 'boundary' | 'member' | 'cap_sequence' | 'probe';
export interface Example { id: string; kind: ExampleKind; why: string; act: Act; hist: Hist; rels: RelDecl[]; decision: Decision }

/** The full example set (decision-cell representatives plus cap sequences plus unmentioned-dimension probes). */
export function boundaryExamples(g: Goal, opts: { ont: Ontology; extra?: Goal[]; verbs?: string[] }): { examples: Example[]; complete: boolean } {
  const { ont } = opts;
  const goals = [g, ...(opts.extra ?? [])];
  const sp = buildSpace(goals, opts.verbs ?? []);
  const c = cells(sp);
  const out: Example[] = [];
  const add = (kind: ExampleKind, why: string, cs: Case, hist: Hist = EMPTY_HIST): void => {
    out.push({ id: `${kind}:${hashCanonical({ act: cs.act, hist, rels: cs.rels }).slice(0, 12)}`, kind, why, act: cs.act, hist, rels: cs.rels, decision: decideCase(g, ont, { act: cs.act, hist, rels: cs.rels }).decision });
  };
  for (const cs of c.cases) {
    const v = decideCase(g, ont, cs);
    add(v.prohibited && v.decision === 'deny' ? 'prohibit_trigger' : v.decision === 'allow' ? 'member' : 'boundary', `cell ${v.decision}`, cs);
  }
  for (const gr of g.grants) { const w = allowWitness(g, gr, ont); if (w) add('allow_witness', `minimal Allow witness of grant ${gr.gid}`, w); }
  for (const b of g.bounds) {
    const gids = b.sel.k === 'gids' ? b.sel.gids : [];
    const gr = g.grants.find((x) => gids.includes(x.gid));
    const w = gr ? allowWitness(g, gr, ont) : undefined;
    if (!w) continue;
    const per = b.agg === 'count' ? 1 : (() => { const v = b.value.k === 'param' ? w.act.params[b.value.path] : undefined; return v && v.k === 'q' ? qval(v.q) : 0; })();
    if (b.agg === 'sum' && per <= 0) continue;
    const n = Math.floor(qval(b.cap) / per);
    if (n > 60) continue; // sequence too long to review; the aggregate theorem (not examples) covers it
    add('cap_sequence', `reach the ${b.bid} cap with ${n} action(s), then one more`, w, replay(g, ont, Array.from({ length: n }, () => w.act), w.rels));
  }
  // unmentioned-dimension probes: extreme amount, other resource, other relation anchor.
  for (const gr of g.grants) {
    const w = allowWitness(g, gr, ont);
    if (!w) continue;
    for (const [p, l] of Object.entries(w.act.params)) if (l.k === 'q' && l.q.u.k === 'money') add('probe', `extreme ${p}`, { ...w, act: { ...w.act, params: { ...w.act.params, [p]: { k: 'q', q: { ...l.q, n: 1_000_000_000 } } } } });
    const nothing = w.rels.map((r) => ({ ...r, members: [] as string[] }));
    add('probe', 'other resource', { act: { ...w.act, res: '\u0000other-resource' }, rels: nothing });
    add('probe', 'other customer/anchor', { act: w.act, rels: nothing });
  }
  const seen = new Set<string>();
  return { examples: out.filter((e) => (seen.has(e.id) ? false : (seen.add(e.id), true))), complete: c.complete };
}

/** Review subset: cap examples, riskiest-looking first (Allow of the unmentioned, then Allow, then boundary), stable. */
export function reviewSet(examples: Example[], cap: number): Example[] {
  const w: Record<ExampleKind, number> = { probe: 0, cap_sequence: 1, allow_witness: 2, prohibit_trigger: 3, member: 4, boundary: 5 };
  return [...examples].sort((a, b) => rankOf(a.decision) - rankOf(b.decision) || w[a.kind] - w[b.kind] || (a.id < b.id ? -1 : 1)).slice(0, cap);
}

// ---------------- GoalTest and the pin ----------------

export type TestAnswer = 'allow' | 'deny' | 'ask';
/** A principal-confirmed example. `rels` are the relation facts the case is decided under (omitted: the ontology's own). */
export interface GoalTest { id: string; act: Act; hist: Hist; answer: TestAnswer; rels?: RelDecl[] }
export interface GoalTestSet { goal_digest: string; ontology_digest: string; tests: GoalTest[]; tests_digest: string }

export const expectedDecision = (a: GoalTest['answer']): Decision => (a === 'allow' ? 'allow' : a === 'deny' ? 'deny' : 'escalate');
/** Order-independent digest of a test list. */
export const testsDigest = (tests: readonly GoalTest[]): string =>
  hashCanonical({ d: 'atlas-pca/goal-tests/v1', tests: [...tests].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)) });

export function makeGoalTests(g: Goal, confirmed: { example: Example; answer: TestAnswer }[]): GoalTestSet {
  const tests: GoalTest[] = confirmed.map((c) => ({ id: c.example.id, act: c.example.act, hist: c.example.hist, rels: c.example.rels, answer: c.answer }));
  return { goal_digest: goalDigest(g), ontology_digest: g.ontDigest, tests, tests_digest: testsDigest(tests) };
}
export const signGoalTests = (s: GoalTestSet, secret: SignerSecret, suite?: SignerSuiteOpts): SignedPayload<GoalTestSet> => signPayload('goal-tests', s, secret, suite);

export type DecideFn = (t: GoalTest) => Decision;

export interface TestFailure { id: string; expected: Decision; got: Decision }
/** Recompile check: any recompile (new ontology, compiler, model) must reproduce every confirmed test or the policy is refused. */
export function checkGoalTests(s: SignedPayload<GoalTestSet>, pins: readonly (string | PinnedSigner)[], decideFn: DecideFn): { ok: boolean; reason?: string; failures: TestFailure[] } {
  if (!verifyPayload(s, 'goal-tests', pins)) return { ok: false, reason: 'signature', failures: [] };
  if (testsDigest(s.payload.tests) !== s.payload.tests_digest) return { ok: false, reason: 'tests_digest', failures: [] };
  const failures: TestFailure[] = [];
  for (const t of s.payload.tests) { const got = decideFn(t); if (got !== expectedDecision(t.answer)) failures.push({ id: t.id, expected: expectedDecision(t.answer), got }); }
  return failures.length ? { ok: false, reason: 'test_regression', failures } : { ok: true, failures };
}

/** The pin: policy version cannot silently change under a signed test set. */
export interface PolicyPin { goal_digest: string; policy_digest: string; tests_digest: string; ontology_digest: string }
export const signPin = (p: PolicyPin, secret: SignerSecret, suite?: SignerSuiteOpts): SignedPayload<PolicyPin> => signPayload('policy-pin', p, secret, suite);
export function checkPin(pin: SignedPayload<PolicyPin>, pins: readonly (string | PinnedSigner)[], cur: { goal: Goal; policy_digest: string; tests: GoalTestSet }): { ok: boolean; reason?: string } {
  if (!verifyPayload(pin, 'policy-pin', pins)) return { ok: false, reason: 'signature' };
  const p = pin.payload;
  if (p.goal_digest !== goalDigest(cur.goal)) return { ok: false, reason: 'goal changed under the pin' };
  if (p.policy_digest !== cur.policy_digest) return { ok: false, reason: 'policy changed under the pin' };
  if (p.tests_digest !== cur.tests.tests_digest || p.tests_digest !== testsDigest(cur.tests.tests)) return { ok: false, reason: 'tests changed under the pin' };
  if (p.ontology_digest !== cur.goal.ontDigest) return { ok: false, reason: 'ontology changed under the pin' };
  return { ok: true };
}
