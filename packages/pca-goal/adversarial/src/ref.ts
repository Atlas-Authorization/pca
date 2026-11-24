// Reference implementations of the spec'd behaviours that sit around the IR semantics (F3 intersection, F1 holes, G-T9 tighten
// meet, rules 20/21, G-T4 PEP, goal_commit v3, W14 binding, locale parsing, deterministic template interpreter).
// They define the post-spec outcome each W test asserts. Where the merged tree has the real implementation (decision.ts tighten/pepDecision/
// decideUnits, escalation.ts, intent-binding.ts, review.ts, src/nversion.ts meet) the subject adapter calls THAT; these stay the second opinion.
import { createHash, timingSafeEqual } from 'node:crypto';
import { digest } from './canon.ts';
import type { Act, Bound, Cond, Decision, Goal, Grant, Hole, Ontology, ResPart, ResSel } from './types.ts';
import { andAll, ctrue, emptyGoal, lit, param } from './gen.ts';
import { DOMAINS } from './domains.ts';
import { canonicalOrder } from './oracle.ts';

// ----- F3 N-version intersection (merged is no broader than any reading): all_of selectors, conjoined conditions, one bound per source bound -----
const partsOf = (s: ResSel): ResPart[] | 'any' => (s.k === 'any' ? 'any' : s.k === 'all_of' ? s.parts : [s]);
export function intersect(gs: Goal[], o: Ontology, name = 'merged'): Goal {
  const m = emptyGoal({ ontology: o, name });
  m.principal = gs[0]!.principal; m.ontDigest = gs[0]!.ontDigest; m.nlDigest = digest('nl', gs.map((g) => g.nlDigest));
  const live = gs.map((g) => g.grants.filter((x) => !g.holes.some((h) => h.global || h.affects.includes(x.gid))));
  const tuples: Grant[][] = live.reduce<Grant[][]>((acc, gr) => acc.flatMap((t) => gr.filter((x) => !t.length || x.verb === t[0]!.verb).map((x) => [...t, x])), [[]]).filter((t) => t.length === gs.length);
  for (const t of tuples) {
    const ps = t.map((x) => partsOf(x.res));
    const parts = ps.filter((x): x is ResPart[] => x !== 'any').flat();
    const uniq = [...new Map(parts.map((p) => [JSON.stringify(p), p])).values()];
    const res: ResSel = uniq.length === 0 ? { k: 'any', reason: 'merged' } : uniq.length === 1 ? uniq[0]! : { k: 'all_of', parts: uniq };
    const gid = t.map((x) => x.gid).join('+');
    m.grants.push({ gid, verb: t[0]!.verb, res, cond: andAll(t.map((x) => x.cond)) });
    if (res.k === 'any') m.wildcardAck.push(gid);
  }
  gs.forEach((g, i) => {
    g.prohibits.forEach((p) => m.prohibits.push({ ...p, pid: `${i}.${p.pid}` }));
    g.escalateOn.forEach((c) => m.escalateOn.push(c));
    g.bounds.forEach((b) => {
      const sel = b.sel.k === 'gids' ? { k: 'gids' as const, gids: m.grants.map((x) => x.gid).filter((cg) => (b.sel as { gids: string[] }).gids.includes(cg.split('+')[i]!)) } : b.sel;
      if (sel.k === 'gids' && sel.gids.length === 0) return;
      m.bounds.push({ ...b, bid: `${i}.${b.bid}`, sel } as Bound);
    });
  });
  const idle = gs.map((g) => g.validity.maxIdle).filter((x) => x > 0);
  m.validity = { notBefore: Math.max(...gs.map((g) => g.validity.notBefore)), notAfter: Math.min(...gs.map((g) => g.validity.notAfter)), maxIdle: idle.length ? Math.min(...idle) : 0 };
  m.deleg = { maxDepth: Math.min(...gs.map((g) => g.deleg.maxDepth)), narrowOnly: true, mayTouch: m.grants.map((x) => x.gid).filter((cg) => cg.split('+').every((c, i) => gs[i]!.deleg.mayTouch.includes(c))) };
  m.wildcardAck.sort();
  return canonicalOrder(m);
}
// ----- F1/F3 reconcile: a grant present in only some readings becomes a Hole (never an Allow) -----
export function reconcile(readings: Goal[], _o: Ontology): Goal {
  void _o;
  const key = (g: Grant) => JSON.stringify([g.verb, g.res, g.cond]);
  const count = new Map<string, number>();
  readings.forEach((g) => new Set(g.grants.map(key)).forEach((k) => count.set(k, (count.get(k) ?? 0) + 1)));
  const merged: Goal = JSON.parse(JSON.stringify(readings[0]!));
  const holes: Hole[] = [];
  merged.grants = [];
  const seen = new Set<string>();
  for (const g of readings) for (const gr of g.grants) {
    const k = key(gr); if (seen.has(k)) continue; seen.add(k);
    const gid = 'g' + String(merged.grants.length + 1).padStart(3, '0');
    merged.grants.push({ ...gr, gid });
    if (count.get(k) !== readings.length) holes.push({ hid: 'h' + String(holes.length + 1).padStart(3, '0'), q: `Readings disagree on ${gr.verb}; allow it?`, domain: ['allow', 'deny'], affects: [gid], global: false });
  }
  merged.bounds = []; merged.deleg.mayTouch = []; merged.wildcardAck = merged.grants.filter((x) => x.res.k === 'any').map((x) => x.gid);
  merged.holes = holes;
  return merged;
}
// ----- G-T9 tighten-only meet; rule 20 (units) and rule 21 (model polarity) -----
const RANK: Record<Decision, number> = { deny: 0, escalate: 1, allow: 2 };
export type Signal = 'ok' | 'escalate' | 'deny';
export const meet = (d: Decision, s: Signal): Decision => (RANK[s as Decision] < RANK[d] ? (s as Decision) : d);
export const MODEL_PATHS = ['env.class.', 'env.prov.', 'env.judge.', 'env.world.'];
export const polarityViolations = (grantWheres: Cond[]): string[] => {
  const out: string[] = [];
  const walk = (c: Cond): void => {
    if (c.k === 'and' || c.k === 'or') { walk(c.a); return walk(c.b); }
    if (c.k === 'not') return walk(c.c);
    if (c.k === 'cmp') for (const t of [c.l, c.r]) if (t.k === 'param' && MODEL_PATHS.some((p) => t.path.startsWith(p))) out.push(t.path);
  };
  grantWheres.forEach(walk);
  return [...new Set(out)].sort();
};
export type UnitTag = { currency: string; exponent: number };
export const unitsCheck = (schema: Record<string, UnitTag>, terms: Record<string, UnitTag>): string[] =>
  Object.keys(terms).sort().filter((p) => !(p in schema) || schema[p]!.currency !== terms[p]!.currency || schema[p]!.exponent !== terms[p]!.exponent);
export const claimGate = (base: Decision, minPpm: number, claimedPpm: number, replayedPpm?: number): Decision =>
  replayedPpm !== undefined && !(replayedPpm >= minPpm) ? meet(base, 'escalate') : base; // a bare claim never changes the outcome; a NaN replay tightens
export const provenanceSignal = (prov: Record<string, 'principal' | 'agent' | 'untrusted'>, sensitive: string[]): Signal =>
  sensitive.some((p) => prov[p] !== 'principal') ? 'escalate' : 'ok';
// ----- G-T4 PEP: escalate with no valid bound answer is refused -----
export type Answer = { policy_digest: string; action_digest: string; history_head: string; valid: boolean };
export const actionDigest = (a: Act): string => digest('action', a);
export function pepAdmit(d: Decision, ctx: { policy_digest: string; action_digest: string; history_head: string }, ans?: Answer): boolean {
  if (d === 'allow') return true;
  if (d === 'deny') return false;
  return !!ans && ans.valid && ans.policy_digest === ctx.policy_digest && ans.action_digest === ctx.action_digest && ans.history_head === ctx.history_head;
}
// ----- W14 decision-to-effect binding -----
export const bindDecision = (a: Act, d: Decision) => ({ decision: d, action_digest: actionDigest(a) });
export const guardExecute = (b: { decision: Decision; action_digest: string }, executed: Act): boolean => b.decision === 'allow' && b.action_digest === actionDigest(executed);
// ----- W1/W4 goal_commit v3 and approval digest -----
export const goalCommit = (goalDigest: string, policyDigest: string, salt: string): string =>
  createHash('sha256').update(`pca-goal:v3:commit:${goalDigest}:${policyDigest}:${salt}`).digest('base64url');
export const openCommit = (c: string, goalDigest: string, policyDigest: string, salt: string): boolean => {
  const x = Buffer.from(c), y = Buffer.from(goalCommit(goalDigest, policyDigest, salt));
  return x.length === y.length && timingSafeEqual(x, y);
};
export type ApprovalBody = { goal_digest: string; policy_digest: string; card_digest: string; ontology_digest: string; tests_digest: string; nl_digest: string; model_set_digest: string; expires: number };
export const approvalDigest = (b: ApprovalBody): string => digest('approval', b);
// ----- locale-safe number parsing (front end only; ambiguity is a Hole) -----
export type Parsed = { minor: number } | { hole: 'AMBIGUOUS_NUMBER' } | { error: 'BAD_NUMBER' };
export function parseMoney(text: string, exponent: number, locale: 'en' | 'de' | null): Parsed {
  const t = text.trim().replace(/^[$€£]\s*/, '');
  if (!/^\d[\d.,]*$/.test(t)) return { error: 'BAD_NUMBER' };
  const dec = locale === 'en' ? '.' : locale === 'de' ? ',' : null, grp = locale === 'en' ? ',' : locale === 'de' ? '.' : null;
  let intPart: string, frac = '';
  if (dec) {
    const parts = t.split(dec);
    if (parts.length > 2) return { error: 'BAD_NUMBER' };
    intPart = parts[0]!.split(grp!).join(''); frac = parts[1] ?? '';
    if (parts[0]!.split(grp!).slice(1).some((x) => x.length !== 3)) return { error: 'BAD_NUMBER' };
    if (!/^\d+$/.test(intPart) || (frac && !/^\d+$/.test(frac))) return { error: 'BAD_NUMBER' };
  } else {
    const seps = t.match(/[.,]/g) ?? [];
    if (seps.length === 0) intPart = t;
    else if (new Set(seps).size === 1 && seps.length === 1) { const [a, b] = t.split(seps[0]!); if (b!.length === 3) return { hole: 'AMBIGUOUS_NUMBER' }; intPart = a!; frac = b!; }
    else if (new Set(seps).size === 1) return { hole: 'AMBIGUOUS_NUMBER' };
    else { const last = Math.max(t.lastIndexOf('.'), t.lastIndexOf(',')); intPart = t.slice(0, last).replace(/[.,]/g, ''); frac = t.slice(last + 1); }
  }
  if (frac.length > exponent) return { error: 'BAD_NUMBER' };
  return { minor: Number(intPart + frac.padEnd(exponent, '0')) };
}
// ----- deterministic template interpreter (typed form in, Goal out; free text never reaches structure) -----
export type Form = { template: 'refund_duplicate'; slots: { customer: string; max_amount_minor: number; ccy: string; max_refunds: number }; nl: string };
export function interpretForm(f: Form, o: Ontology): { ok: true; goal: Goal } | { ok: false; error: string } {
  const keys = Object.keys(f.slots).sort().join(',');
  if (f.template !== 'refund_duplicate' || keys !== 'ccy,customer,max_amount_minor,max_refunds') return { ok: false, error: 'FORM_SHAPE' };
  if (!/^cust:[A-Za-z0-9_-]{1,32}$/.test(f.slots.customer)) return { ok: false, error: 'SLOT_customer' };
  if (!Number.isSafeInteger(f.slots.max_amount_minor) || f.slots.max_amount_minor < 0 || !/^[A-Z]{3}$/.test(f.slots.ccy)) return { ok: false, error: 'SLOT_amount' };
  if (!Number.isSafeInteger(f.slots.max_refunds) || f.slots.max_refunds < 1) return { ok: false, error: 'SLOT_count' };
  const g = emptyGoal(DOMAINS[0]!);
  void o;
  const u = { k: 'money' as const, ccy: f.slots.ccy };
  g.nlDigest = digest('nl', f.nl);
  g.grants = [{ gid: 'g1', verb: 'refund', res: { k: 'related', rel: 'charges_of', anchor: f.slots.customer }, cond: { k: 'cmp', op: 'lte', l: param('amount'), r: lit({ k: 'q', q: { u, n: f.slots.max_amount_minor } }) } }];
  g.bounds = [{ bid: 'b1', sel: { k: 'gids', gids: ['g1'] }, agg: 'count', value: lit({ k: 'q', q: { u: { k: 'count' }, n: 1 } }), key: '', window: { k: 'lifetime' }, scope: { k: 'principal' }, cap: { u: { k: 'count' }, n: f.slots.max_refunds }, onExceed: 'deny' }];
  g.prohibits = [{ pid: 'x1', target: { k: 'effect', cls: 'irreversible' }, res: { k: 'any', reason: 'never' }, cond: ctrue }];
  return { ok: true, goal: g };
}
