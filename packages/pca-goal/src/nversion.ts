import { disagreementMass, questions, type Reading, type QuestionOpts } from './disambiguate';
import type { Bound, Cond, Goal, Grant, Hole, Prohibit, ResPart, ResSel } from './ir';
import { canonicalizeGoal, stable } from './normalize';

/**
 * N-version interpretation (spec F3): the enforced policy is the semantic meet of the readings.
 * Theorem (Lean `Meet.lean`, `allow_meetList`): Allow(meet gs) a implies Allow(g) a for every g in gs.
 *
 * The meet lives in the Goal IR: grants are the cross product of the readings' grants on equal verbs (a merged grant is
 * named `x&y&z`), resources intersect through `all_of`, conditions conjoin. A bound of one reading counts the actions admitted
 * by the merged grants derived from the grants that bound selected (`Bound.sel`), so each admitted action is counted once, as
 * the source reading counts it, and the merged goal never admits more than any reading.
 */
const partsOf = (s: ResSel): ResPart[] => (s.k === 'all_of' ? s.parts : s.k === 'any' ? [] : [s]);
const intersect = (a: ResSel, b: ResSel): ResSel => {
  if (a.k === 'any') return b;
  if (b.k === 'any') return a;
  const uniq = [...new Map([...partsOf(a), ...partsOf(b)].map((p) => [stable(p), p])).values()];
  return uniq.length === 1 ? uniq[0]! : { k: 'all_of', parts: uniq };
};
const conj = (a: Cond, b: Cond): Cond => (a.k === 'true' ? b : b.k === 'true' ? a : { k: 'and', a, b });

/** A merged grant and, per reading, the gid of the grant it was derived from. */
interface Tracked { g: Grant; from: string[] }
const cross = (a: Tracked[], b: Tracked[]): Tracked[] => {
  const out: Tracked[] = [];
  for (const x of a) for (const y of b) if (x.g.verb === y.g.verb) out.push({ g: { gid: `${x.g.gid}&${y.g.gid}`, verb: x.g.verb, res: intersect(x.g.res, y.g.res), cond: conj(x.g.cond, y.g.cond) }, from: [...x.from, ...y.from] });
  return out;
};

/** Meet of grants: cross product on equal verbs, resource intersection, conjoined conditions. */
export function meetGrants(a: Grant[], b: Grant[]): Grant[] {
  return cross(a.map((g) => ({ g, from: [g.gid] })), b.map((g) => ({ g, from: [g.gid] }))).map((t) => t.g);
}

export function meet(goals: Goal[]): Goal {
  if (goals.length === 0) throw new Error('meet: no goals');
  const first = goals[0]!;
  for (const g of goals) if (g.principal !== first.principal || g.ontDigest !== first.ontDigest || g.nlDigest !== first.nlDigest) throw new Error('meet: readings must share principal, ontology and text');
  if (goals.length === 1) return first;
  let tracked: Tracked[] = first.grants.map((g) => ({ g, from: [g.gid] }));
  for (const g of goals.slice(1)) tracked = cross(tracked, g.grants.map((x) => ({ g: x, from: [x.gid] })));
  const grants = tracked.map((t) => t.g);
  const derived = (i: number, gids: string[]): string[] => tracked.filter((t) => gids.includes(t.from[i]!)).map((t) => t.g.gid);
  const prohibits: Prohibit[] = [];
  const pseen = new Map<string, string>();
  goals.forEach((g, i) => g.prohibits.forEach((p) => {
    const body = stable({ ...p, pid: '' });
    if (pseen.has(body)) return;
    const taken = [...pseen.values()].includes(p.pid);
    pseen.set(body, p.pid);
    prohibits.push(taken ? { ...p, pid: `${p.pid}#${i}` } : p);
  }));
  const bounds: Bound[] = [];
  const bseen = new Map<string, Bound>();
  goals.forEach((g, i) => g.bounds.forEach((b) => {
    const sel = b.sel.k === 'gids' ? { k: 'gids' as const, gids: derived(i, b.sel.gids).sort() } : b.sel;
    if (sel.k === 'gids' && sel.gids.length === 0) return; // no merged grant derives from the selected grants: nothing to count
    const key = stable({ sel, agg: b.agg, value: b.value, key: b.key, window: b.window, scope: b.scope, unit: b.cap.u });
    const prev = bseen.get(key);
    if (prev) { // the same aggregate over the same counted grants in several readings: the minimum cap, the stricter exceed action
      if (b.cap.n < prev.cap.n) prev.cap = b.cap;
      if (b.onExceed === 'deny') prev.onExceed = 'deny';
      return;
    }
    const nb: Bound = { ...b, sel, bid: bounds.some((x) => x.bid === b.bid) ? `${b.bid}#${i}` : b.bid };
    bounds.push(nb); bseen.set(key, nb);
  }));
  const escSeen = new Map<string, Cond>();
  goals.forEach((g) => g.escalateOn.forEach((c) => escSeen.set(stable(c), c)));
  const idle = goals.map((g) => g.validity.maxIdle).filter((x) => x > 0);
  const touch = tracked.filter((t) => goals.every((g, i) => g.deleg.mayTouch.includes(t.from[i]!))).map((t) => t.g.gid);
  const ack = tracked.filter((t) => t.g.res.k === 'any' && goals.every((g, i) => g.grants.find((x) => x.gid === t.from[i])?.res.k !== 'any' || g.wildcardAck.includes(t.from[i]!))).map((t) => t.g.gid);
  const holes = new Map<string, Hole>();
  goals.forEach((g, i) => g.holes.forEach((h) => {
    const prev = holes.get(h.hid);
    const affects = [...new Set([...(prev?.affects ?? []), ...derived(i, h.affects)])].sort();
    holes.set(h.hid, { ...h, affects, global: h.global || (prev?.global ?? false) });
  }));
  return canonicalizeGoal({
    ...first, grants, prohibits, bounds, escalateOn: [...escSeen.values()],
    sources: [...new Set(goals.flatMap((g) => g.sources))],
    validity: { notBefore: Math.max(...goals.map((g) => g.validity.notBefore)), notAfter: Math.min(...goals.map((g) => g.validity.notAfter)), maxIdle: idle.length ? Math.min(...idle) : 0 },
    deleg: { maxDepth: Math.min(...goals.map((g) => g.deleg.maxDepth)), narrowOnly: true, mayTouch: touch },
    holes: [...holes.values()], wildcardAck: ack,
  });
}

export interface PanelIssue { code: 'too_few' | 'no_deterministic' | 'no_family_diversity'; msg: string }

/** Panel requirements (F3): k >= 3, at least one deterministic non-LLM interpreter, at least two distinct model families. */
export function checkPanel(readings: Reading[]): PanelIssue[] {
  const out: PanelIssue[] = [];
  if (readings.length < 3) out.push({ code: 'too_few', msg: 'need at least 3 interpreters' });
  if (!readings.some((r) => r.deterministic)) out.push({ code: 'no_deterministic', msg: 'need at least one deterministic template interpreter' });
  if (new Set(readings.filter((r) => !r.deterministic).map((r) => r.family)).size < 2) out.push({ code: 'no_family_diversity', msg: 'need at least two distinct model families' });
  return out;
}

export interface NVersionResult {
  merged: Goal;
  panelIssues: PanelIssue[];
  /** holes for grants present in only some readings and for witness cells the readings split on (above the threshold) */
  disagreementHoles: Hole[];
  mass: number;
  /** auto-signable only when the panel is valid and no hole remains */
  signable: boolean;
}

export function nVersion(readings: Reading[], opts: QuestionOpts & { massThreshold?: number }): NVersionResult {
  const merged = meet(readings.map((r) => r.goal));
  const panelIssues = checkPanel(readings);
  const verbSets = readings.map((r) => new Set(r.goal.grants.map((g) => g.verb)));
  const allVerbs = new Set(verbSets.flatMap((s) => [...s]));
  const holes: Hole[] = [];
  for (const v of [...allVerbs].sort()) if (verbSets.some((s) => !s.has(v))) holes.push({ hid: `nv:verb:${v}`, q: `Only some readings allow "${v}". Should it be allowed at all?`, domain: [], affects: [], global: false });
  const mass = disagreementMass(readings, opts.ont);
  if (mass > (opts.massThreshold ?? 0)) {
    const q = questions(readings, opts)[0];
    holes.push({ hid: 'nv:split', q: q?.text ?? 'The readings disagree.', domain: [], affects: [], global: true });
  }
  const all = [...merged.holes, ...holes];
  return { merged: canonicalizeGoal({ ...merged, holes: [...new Map(all.map((h) => [h.hid, h])).values()] }), panelIssues, disagreementHoles: holes, mass, signable: panelIssues.length === 0 && all.length === 0 };
}
