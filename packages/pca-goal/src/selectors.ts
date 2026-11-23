// selectors.ts - trait selectors and role-addressed parameters for the Goal IR (docs/pca/specs/action-kit.md section 8).
//
// A `SelGoal` is a Goal whose grants name a VerbSel (`verb` or `class`: every verb of the pinned catalog with all of the traits and
// none of the excluded ones), whose prohibitions and bounds may select by trait, and whose terms may name a parameter by ROLE
// (`ParamRole(money.amount)`). `expandSelGoal` lowers it, against the PINNED catalog, to an ordinary `Goal` (one grant per verb,
// each with that verb's own parameter path); the unchanged proved compiler then does the rest, so every theorem about the core
// compiler holds for selector goals by composition. The expansion is the function formalised and proved in
// formal/dafny/GoalSelect.dfy (G-A4 class verbs, T6 growth, soundness); this module mirrors it line by line, and the differential
// harness (scripts/select-diff.ts) compares the class verbs with the compiled Dafny.
//
// Fail-closed rules (the same in the Dafny model):
//   - a grant verb with no unique parameter of a role the grant's condition names is DROPPED from the grant (reported);
//   - a prohibition whose role term is unresolved for a verb applies to that verb UNCONDITIONALLY (never weaker);
//   - a bound whose role-addressed value cannot be resolved for every selected verb is a type error, not a weaker bound;
//   - an allow selector is positive: no `none_of` (the absence of a trait is never a safety claim), at least one trait;
//   - UNCONFIRMED means maximally dangerous: a verb whose def has no valid signed review has the marker `pca.unreviewed` in its closure
//     (the top of the registry). A class ALLOW never covers such a verb (it is excluded as if every allow carried
//     `none_of: [pca.unreviewed]`); a class PROHIBITION or a bound over a trait selector ALWAYS covers it, whatever its `all_of` and
//     `none_of` say (a carve-out can never rescue an unreviewed verb);
//   - a trait id the registry does not know is a type error.
import { hashCanonical } from '@atlasauth/pca';
import {
  CORE_REGISTRY, DOMAIN_VERBS, closure, domainRoles, effective,
  type ActionDef, type DomainName, type Registry, type ReviewOpts,
} from '@atlasauth/pca-actions';
import { CORE_PACK_DEFS } from '@atlasauth/pca-actions';
import { compileGoal } from './compiler';
import type {
  Act, Agg, Cond, Goal, Grant, Hole, Op, Ontology, OnExceed, Prohibit, Bound, Quantity, ResSel, Scope, Sel, Term, Ty, Unit, Value, Window, CompileResult, Policy,
  Validity, Delegation, VerbDecl,
} from './ir';
import { renderCard } from './card';
import type { Tape } from '@atlasauth/pca-verified-core';

// ---------------------------------------------------------------- the selector-extended IR

export type VerbSel = { k: 'verb'; verb: string } | { k: 'class'; all_of: string[]; none_of: string[] };
export type TermX =
  | { k: 'param'; path: string; ty: Ty }
  | { k: 'role'; role: string }
  | { k: 'lit'; v: Value }
  | { k: 'hist'; bid: string; u: Unit };
export type CondX =
  | { k: 'true' }
  | { k: 'cmp'; op: Op; l: TermX; r: TermX }
  | { k: 'and'; a: CondX; b: CondX }
  | { k: 'or'; a: CondX; b: CondX }
  | { k: 'not'; c: CondX };
export interface GrantX { gid: string; sel: VerbSel; res: ResSel; cond: CondX }
export type ProhTargetX = { k: 'verb'; verb: string } | { k: 'effect'; cls: string } | { k: 'trait'; all_of: string[]; none_of: string[] };
export interface ProhibitX { pid: string; target: ProhTargetX; res: ResSel; cond: CondX }
export type SelX = { k: 'gids'; gids: string[] } | { k: 'effect'; cls: string } | { k: 'trait'; all_of: string[]; none_of: string[] };
export interface BoundX { bid: string; sel: SelX; agg: Agg; value: TermX; key: string; window: Window; scope: Scope; cap: Quantity; onExceed: OnExceed }

/** A Goal with selector clauses. `catDigest` pins the catalog the selectors were written against (the pack root of the signed pack). */
export interface SelGoal {
  v: 2;
  principal: string;
  ontDigest: string;
  catDigest: string;
  nlDigest: string;
  sources: string[];
  grants: GrantX[];
  prohibits: ProhibitX[];
  bounds: BoundX[];
  validity: Validity;
  deleg: Delegation;
  escalateOn: Cond[];
  wildcardAck: string[];
  holes: Hole[];
}

// ---------------------------------------------------------------- the pinned catalog

/** One verb of the catalog: its id in the ontology, the trait ids of its closure (sorted), and role -> the parameter paths carrying it. */
export interface CatVerb { verb: string; traits: string[]; roles: Record<string, string[]> }
/** The catalog selectors are expanded against: every trait id of the registry and the verbs (sorted by verb id). */
export interface SelCatalog { known: string[]; verbs: CatVerb[] }

const byStr = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** The catalog of a pack of defs (verb ids and parameter paths are the defs' own). */
export function selCatalogOfDefs(defs: readonly ActionDef[], reg: Registry = CORE_REGISTRY, review: ReviewOpts = {}): SelCatalog {
  const verbs: CatVerb[] = defs.map((d) => {
    const roles: Record<string, string[]> = {};
    for (const name of Object.keys(d.params).sort(byStr)) {
      const r = d.params[name]!.role;
      if (r !== undefined) (roles[r] ??= []).push(name);
    }
    return { verb: d.verb, traits: effective(d, reg, review).closure, roles };
  }).sort((a, b) => byStr(a.verb, b.verb));
  return { known: [...reg.traits.keys()].sort(byStr), verbs };
}

/** The catalog of one domain ontology: the NL short ids and NL parameter names, with the traits of the defs behind them. */
export function selCatalogOfDomain(domain: DomainName, reg: Registry = CORE_REGISTRY, review: ReviewOpts = {}): SelCatalog {
  const roles = domainRoles(domain);
  const verbs: CatVerb[] = DOMAIN_VERBS[domain].map((b) => {
    const d = CORE_PACK_DEFS.find((x) => x.verb === b.verb)!;
    return { verb: b.id, traits: effective(d, reg, review).closure, roles: roles[b.id] ?? {} };
  }).sort((a, b) => byStr(a.verb, b.verb));
  return { known: [...reg.traits.keys()].sort(byStr), verbs };
}

/** Digest of the catalog (what `SelGoal.catDigest` must equal): canonical JSON of the sorted verbs and the known trait ids. */
export const selCatalogDigest = (c: SelCatalog): string => hashCanonical({ d: 'atlas-pca/goal-sel-catalog/v1', catalog: c });
/** Digest of the whole signed selector goal. */
export const selGoalDigest = (g: SelGoal): string => hashCanonical({ d: 'atlas-pca/goal-ir-sel/v1', goal: g });

// ---------------------------------------------------------------- G-A4: the verbs of a Class selector

const hasAll = (ts: readonly string[], req: readonly string[]): boolean => req.every((t) => ts.includes(t));
const hasNone = (ts: readonly string[], ex: readonly string[]): boolean => ex.every((t) => !ts.includes(t));
/** The verbs of the catalog, in catalog order, whose trait closure contains every `allOf` trait and none of the `noneOf` traits. */
export const classVerbs = (cat: SelCatalog, allOf: readonly string[], noneOf: readonly string[]): string[] =>
  cat.verbs.filter((v) => hasAll(v.traits, allOf) && hasNone(v.traits, noneOf)).map((v) => v.verb);

/** The marker trait every unconfirmed verb carries (it is in the top of the registry; a confirmed verb never has it). */
export const UNREVIEWED = 'pca.unreviewed';
/** The verbs a class ALLOW covers: the class, minus every unconfirmed verb. */
export const allowClassVerbs = (cat: SelCatalog, allOf: readonly string[], noneOf: readonly string[]): string[] => classVerbs(cat, allOf, [...noneOf, UNREVIEWED]);
/** The verbs a class PROHIBITION or bound covers: the class, plus every unconfirmed verb whatever the selector says. */
export const floatClassVerbs = (cat: SelCatalog, allOf: readonly string[], noneOf: readonly string[]): string[] =>
  cat.verbs.filter((v) => v.traits.includes(UNREVIEWED) || (hasAll(v.traits, allOf) && hasNone(v.traits, noneOf))).map((v) => v.verb);

// ---------------------------------------------------------------- role resolution

interface Resolved { path: string; ty: Ty }
const declOf = (ont: Ontology, verb: string): VerbDecl | undefined => ont.verbs.find((v) => v.verb === verb);
const infoOf = (cat: SelCatalog, verb: string): CatVerb | undefined => cat.verbs.find((v) => v.verb === verb);

/** The one parameter of `verb` carrying `role`, with its declared type; none, several or undeclared: undefined. */
export function resolveRole(ont: Ontology, cat: SelCatalog, verb: string, role: string): Resolved | undefined {
  const info = infoOf(cat, verb);
  const decl = declOf(ont, verb);
  if (!info || !decl) return undefined;
  const paths = Object.prototype.hasOwnProperty.call(info.roles, role) ? info.roles[role]! : [];
  if (paths.length !== 1) return undefined;
  const p = decl.params.find((x) => x.path === paths[0]);
  return p ? { path: p.path, ty: p.ty } : undefined;
}

function resolveTerm(ont: Ontology, cat: SelCatalog, verb: string, t: TermX): Term | undefined {
  switch (t.k) {
    case 'param': return { k: 'param', path: t.path, ty: t.ty };
    case 'lit': return { k: 'lit', v: t.v };
    case 'hist': return { k: 'hist', bid: t.bid, u: t.u };
    case 'role': { const r = resolveRole(ont, cat, verb, t.role); return r ? { k: 'param', path: r.path, ty: r.ty } : undefined; }
  }
}
/** undefined as soon as one role term is unresolved for the verb. */
function resolveCond(ont: Ontology, cat: SelCatalog, verb: string, c: CondX): Cond | undefined {
  switch (c.k) {
    case 'true': return { k: 'true' };
    case 'cmp': { const l = resolveTerm(ont, cat, verb, c.l); const r = resolveTerm(ont, cat, verb, c.r); return l && r ? { k: 'cmp', op: c.op, l, r } : undefined; }
    case 'and': case 'or': { const a = resolveCond(ont, cat, verb, c.a); const b = resolveCond(ont, cat, verb, c.b); return a && b ? { k: c.k, a, b } : undefined; }
    case 'not': { const a = resolveCond(ont, cat, verb, c.c); return a ? { k: 'not', c: a } : undefined; }
  }
}

// ---------------------------------------------------------------- the expansion

export interface ExpandReport {
  grants: { gid: string; verbs: string[]; dropped: { verb: string; reason: 'role_unresolved' }[] }[];
  /** `unconditional`: the verbs whose role term was unresolved, so the prohibition applies to them without its condition. */
  prohibits: { pid: string; verbs: string[]; unconditional: string[] }[];
  /** `dropped`: the bound selects no expanded grant, so it bounds nothing. */
  bounds: { bid: string; gids: string[]; dropped: boolean; value: 'literal' | 'shared_path' | 'role_key' }[];
}

interface EG { src: string; g: Grant }

const grantVerbs = (cat: SelCatalog, s: VerbSel): string[] => (s.k === 'verb' ? [s.verb] : allowClassVerbs(cat, s.all_of, s.none_of));

function expandGrants(ont: Ontology, cat: SelCatalog, gs: readonly GrantX[], report: ExpandReport): EG[] {
  const out: EG[] = [];
  for (const gr of gs) {
    const verbs = grantVerbs(cat, gr.sel);
    const dropped: { verb: string; reason: 'role_unresolved' }[] = [];
    for (const v of verbs) {
      const c = resolveCond(ont, cat, v, gr.cond);
      if (c === undefined) { dropped.push({ verb: v, reason: 'role_unresolved' }); continue; }
      out.push({ src: gr.gid, g: { gid: gr.sel.k === 'class' ? `${gr.gid}.${v}` : gr.gid, verb: v, res: gr.res, cond: c } });
    }
    report.grants.push({ gid: gr.gid, verbs, dropped });
  }
  return out;
}

const prohVerbs = (ont: Ontology, cat: SelCatalog, t: ProhTargetX): string[] =>
  t.k === 'verb' ? [t.verb] : t.k === 'effect' ? ont.verbs.filter((v) => v.cls === t.cls).map((v) => v.verb) : floatClassVerbs(cat, t.all_of, t.none_of);

function expandProhibits(ont: Ontology, cat: SelCatalog, ps: readonly ProhibitX[], report: ExpandReport): Prohibit[] {
  const out: Prohibit[] = [];
  for (const p of ps) {
    const verbs = prohVerbs(ont, cat, p.target);
    const unconditional: string[] = [];
    for (const v of verbs) {
      const c = resolveCond(ont, cat, v, p.cond);
      if (c === undefined) unconditional.push(v);
      out.push({ pid: p.target.k === 'verb' ? p.pid : `${p.pid}.${v}`, target: { k: 'verb', verb: v }, res: p.res, cond: c ?? { k: 'true' } });
    }
    report.prohibits.push({ pid: p.pid, verbs, unconditional });
  }
  return out;
}

const idsOf = (es: readonly EG[], srcs: readonly string[]): string[] => es.filter((e) => srcs.includes(e.src)).map((e) => e.g.gid);
const gidsOfVerbs = (es: readonly EG[], vs: readonly string[]): string[] => es.filter((e) => vs.includes(e.g.verb)).map((e) => e.g.gid);
const verbsOfGids = (es: readonly EG[], gids: readonly string[]): string[] => es.filter((e) => gids.includes(e.g.gid)).map((e) => e.g.verb);

/** The verbs a bound's role-addressed value must resolve for. */
function boundRoleVerbs(ont: Ontology, cat: SelCatalog, es: readonly EG[], s: SelX): string[] {
  switch (s.k) {
    case 'gids': return verbsOfGids(es, idsOf(es, s.gids));
    case 'effect': return ont.verbs.filter((v) => v.cls === s.cls).map((v) => v.verb);
    case 'trait': return verbsOfGids(es, gidsOfVerbs(es, floatClassVerbs(cat, s.all_of, s.none_of)));
  }
}

/** One value term for the whole bound: the shared path when every verb agrees; the role key `@<role>` when the paths differ but the type is one. */
function boundValue(ont: Ontology, cat: SelCatalog, vs: readonly string[], t: TermX): { term: Term; how: 'literal' | 'shared_path' | 'role_key' } | undefined {
  switch (t.k) {
    case 'param': return { term: { k: 'param', path: t.path, ty: t.ty }, how: 'literal' };
    case 'lit': return { term: { k: 'lit', v: t.v }, how: 'literal' };
    case 'hist': return { term: { k: 'hist', bid: t.bid, u: t.u }, how: 'literal' };
    case 'role': {
      const rs: Resolved[] = [];
      for (const v of vs) { const r = resolveRole(ont, cat, v, t.role); if (!r) return undefined; rs.push(r); }
      if (rs.length === 0) return undefined;
      const same = (a: Ty, b: Ty): boolean => JSON.stringify(a) === JSON.stringify(b);
      if (rs.every((r) => r.path === rs[0]!.path && same(r.ty, rs[0]!.ty))) return { term: { k: 'param', path: rs[0]!.path, ty: rs[0]!.ty }, how: 'shared_path' };
      if (rs.every((r) => same(r.ty, rs[0]!.ty))) return { term: { k: 'param', path: `@${t.role}`, ty: rs[0]!.ty }, how: 'role_key' };
      return undefined;
    }
  }
}

function expandBounds(ont: Ontology, cat: SelCatalog, es: readonly EG[], bs: readonly BoundX[], report: ExpandReport): Bound[] {
  const out: Bound[] = [];
  for (const b of bs) {
    const bv = boundValue(ont, cat, boundRoleVerbs(ont, cat, es, b.sel), b.value);
    if (bv === undefined) continue; // a type error (selReasons), never reached when the goal is well typed
    const mk = (sel: Sel): Bound => ({ bid: b.bid, sel, agg: b.agg, value: bv.term, key: b.key, window: b.window, scope: b.scope, cap: b.cap, onExceed: b.onExceed });
    let gids: string[] | undefined;
    if (b.sel.k === 'gids') gids = idsOf(es, b.sel.gids);
    else if (b.sel.k === 'trait') gids = gidsOfVerbs(es, floatClassVerbs(cat, b.sel.all_of, b.sel.none_of));
    if (b.sel.k === 'effect') { out.push(mk({ k: 'effect', cls: b.sel.cls })); report.bounds.push({ bid: b.bid, gids: [], dropped: false, value: bv.how }); continue; }
    if (gids!.length === 0) { report.bounds.push({ bid: b.bid, gids: [], dropped: true, value: bv.how }); continue; }
    out.push(mk({ k: 'gids', gids: gids! }));
    report.bounds.push({ bid: b.bid, gids: gids!, dropped: false, value: bv.how });
  }
  return out;
}

/** Lower a selector goal to an ordinary Goal against the PINNED catalog. Pure and total; typing is `selReasons` + the core typechecker. */
export function expandSelGoal(sg: SelGoal, ont: Ontology, cat: SelCatalog): { goal: Goal; report: ExpandReport } {
  const report: ExpandReport = { grants: [], prohibits: [], bounds: [] };
  const es = expandGrants(ont, cat, sg.grants, report);
  const prohibits = expandProhibits(ont, cat, sg.prohibits, report);
  const bounds = expandBounds(ont, cat, es, sg.bounds, report);
  const goal: Goal = {
    v: 1,
    principal: sg.principal,
    ontDigest: sg.ontDigest,
    nlDigest: sg.nlDigest,
    sources: sg.sources,
    grants: es.map((e) => e.g),
    prohibits,
    bounds,
    validity: sg.validity,
    deleg: { ...sg.deleg, mayTouch: idsOf(es, sg.deleg.mayTouch) },
    escalateOn: sg.escalateOn,
    wildcardAck: idsOf(es, sg.wildcardAck),
    holes: sg.holes.map((h) => ({ ...h, affects: idsOf(es, h.affects) })),
  };
  return { goal, report };
}

// ---------------------------------------------------------------- typing of the selector layer

/** Ids are `[0-9A-Za-z_]`: the expanded id `<gid>.<verb>` then sorts exactly as (gid, verb), so the canonical-order rule of the core holds. */
export const SEL_ID_RE = /^[0-9A-Za-z_]{1,64}$/;

const allKnown = (known: readonly string[], ids: readonly string[]): boolean => ids.every((i) => i.length > 0 && known.includes(i));
const grantSelOk = (cat: SelCatalog, g: GrantX): boolean => g.sel.k === 'verb' || (g.sel.all_of.length > 0 && g.sel.none_of.length === 0 && allKnown(cat.known, g.sel.all_of));
const prohSelOk = (cat: SelCatalog, p: ProhibitX): boolean => p.target.k !== 'trait' || (allKnown(cat.known, p.target.all_of) && allKnown(cat.known, p.target.none_of));
const boundSelOk = (cat: SelCatalog, gs: readonly GrantX[], b: BoundX): boolean =>
  b.sel.k === 'gids' ? b.sel.gids.every((i) => gs.some((g) => g.gid === i)) : b.sel.k === 'effect' ? true : allKnown(cat.known, b.sel.all_of) && allKnown(cat.known, b.sel.none_of);

/**
 * The type reasons of the selector layer, in the order of the Dafny model (`XReasons`), preceded by the checks that are about the
 * wire rather than the semantics: the pin (`catalog_digest_mismatch`) and the id grammar (`bad_id`). [] = well typed at this layer.
 */
export function selReasons(sg: SelGoal, ont: Ontology, cat: SelCatalog): string[] {
  const out: string[] = [];
  if (sg.catDigest !== selCatalogDigest(cat)) out.push('catalog_digest_mismatch');
  const ids = [...sg.grants.map((g) => g.gid), ...sg.prohibits.map((p) => p.pid), ...sg.bounds.map((b) => b.bid)];
  if (!ids.every((i) => SEL_ID_RE.test(i))) out.push('bad_id');
  if (!cat.verbs.every((v) => declOf(ont, v.verb) !== undefined)) out.push('catalog_mismatch');
  if (!sg.grants.every((g) => grantSelOk(cat, g))) out.push('bad_grant_selector');
  if (!sg.prohibits.every((p) => prohSelOk(cat, p))) out.push('bad_prohibit_selector');
  if (!sg.bounds.every((b) => boundSelOk(cat, sg.grants, b))) out.push('bad_bound_selector');
  const es = expandGrants(ont, cat, sg.grants, { grants: [], prohibits: [], bounds: [] });
  if (!sg.bounds.every((b) => boundValue(ont, cat, boundRoleVerbs(ont, cat, es, b.sel), b.value) !== undefined)) out.push('unresolved_role_bound');
  return out;
}

export type SelCompileResult = (CompileResult & { report?: undefined }) | { ok: true; policy: Policy; goal: Goal; report: ExpandReport } | { ok: false; reasons: string[]; report?: ExpandReport };

/** CompileX: selector reasons first (fail closed), then expansion and the proved core compiler. */
export function compileSelGoal(sg: SelGoal, ont: Ontology, cat: SelCatalog): { ok: true; policy: Policy; goal: Goal; report: ExpandReport } | { ok: false; reasons: string[] } {
  const rs = selReasons(sg, ont, cat);
  if (rs.length > 0) return { ok: false, reasons: rs };
  const { goal, report } = expandSelGoal(sg, ont, cat);
  const c = compileGoal(goal, ont);
  return c.ok ? { ok: true, policy: c.policy, goal, report } : { ok: false, reasons: c.reasons };
}

// ---------------------------------------------------------------- acts

/**
 * Add the role keys a role-addressed bound may read: for every role the act's verb carries on exactly one parameter that the act
 * supplies, `@<role>` is that parameter's value. Any `@` key the caller sent is removed first (a caller cannot forge a role value).
 */
export function withRoleParams(act: Act, cat: SelCatalog): Act {
  const params: Act['params'] = {};
  for (const [k, v] of Object.entries(act.params)) if (!k.startsWith('@')) params[k] = v;
  const info = infoOf(cat, act.verb);
  if (info) for (const [role, paths] of Object.entries(info.roles)) {
    if (paths.length === 1 && Object.prototype.hasOwnProperty.call(params, paths[0]!)) params[`@${role}`] = params[paths[0]!]!;
  }
  return { ...act, params };
}

// ---------------------------------------------------------------- the policy card

const q = (s: string): string => JSON.stringify(s);
function selectorText(all: readonly string[], none: readonly string[], reg: Registry): string {
  const phrase = (id: string): string => reg.traits.get(id)?.card_phrase ?? id;
  const a = all.length > 0 ? `every action that ${all.map(phrase).join(' and ')}` : 'every action';
  return none.length > 0 ? `${a}, except those that ${none.map(phrase).join(' or ')}` : a;
}
/**
 * The card of a selector goal: one line per selector clause in the words of the trait phrases (never a model), with the verbs the
 * pinned catalog gives it, then the card of the expansion (the exact clauses that run). The principal reads both.
 */
export function renderSelCard(sg: SelGoal, ont: Ontology, cat: SelCatalog, reg: Registry = CORE_REGISTRY): { lines: string[]; warnings: string[] } {
  const { goal, report } = expandSelGoal(sg, ont, cat);
  const lines: string[] = [];
  const warnings: string[] = [];
  sg.grants.forEach((g, i) => {
    const r = report.grants[i]!;
    if (g.sel.k === 'class') lines.push(`ALLOW ${q(g.gid)}: ${selectorText(g.sel.all_of, [], reg)} [${r.verbs.length} verb(s) in the pinned catalog: ${r.verbs.map(q).join(', ')}]`);
    for (const d of r.dropped) warnings.push(`grant ${q(g.gid)} does not cover ${q(d.verb)}: it has no unique parameter for a role the condition names`);
  });
  sg.prohibits.forEach((p, i) => {
    const r = report.prohibits[i]!;
    if (p.target.k === 'trait') lines.push(`NEVER ${q(p.pid)}: ${selectorText(p.target.all_of, p.target.none_of, reg)}, today ${r.verbs.length} verb(s) [${r.verbs.map(q).join(', ')}]; it also covers every verb added to the catalog later`);
    for (const v of r.unconditional) warnings.push(`prohibition ${q(p.pid)} applies to ${q(v)} without its condition: the verb has no unique parameter for a role the condition names`);
  });
  sg.bounds.forEach((b, i) => {
    const r = report.bounds[i];
    if (b.sel.k === 'trait' && r) lines.push(`LIMIT ${q(b.bid)}: over ${selectorText(b.sel.all_of, b.sel.none_of, reg)} (${r.gids.length} grant(s))`);
    if (r?.dropped) warnings.push(`limit ${q(b.bid)} selects no grant and bounds nothing`);
    if (r?.value === 'role_key') warnings.push(`limit ${q(b.bid)} sums a role the verbs carry on different parameters: the action must supply the role key`);
  });
  const core = renderCard(goal);
  return { lines: [...lines, ...core.lines], warnings: [...warnings, ...core.warnings] };
}

/** The closure of a trait id list under the registry (a selector written with a parent trait covers the children by `implies`). */
export const traitClosure = (ids: readonly string[], reg: Registry = CORE_REGISTRY): string[] => closure(reg, ids);

// ---------------------------------------------------------------- the carrier form (the differential with the extracted model)

const ROLE_MARK = '\u0001role:';
const carryTerm = (t: TermX): Term => (t.k === 'role' ? { k: 'param', path: ROLE_MARK + t.role, ty: { k: 's' } } : t.k === 'param' ? { k: 'param', path: t.path, ty: t.ty } : t.k === 'lit' ? { k: 'lit', v: t.v } : { k: 'hist', bid: t.bid, u: t.u });
function carryCond(c: CondX): Cond {
  switch (c.k) {
    case 'true': return { k: 'true' };
    case 'cmp': return { k: 'cmp', op: c.op, l: carryTerm(c.l), r: carryTerm(c.r) };
    case 'and': case 'or': return { k: c.k, a: carryCond(c.a), b: carryCond(c.b) };
    case 'not': return { k: 'not', c: carryCond(c.c) };
  }
}
const sel2 = (all: readonly string[], none: readonly string[]): string => `${all.join('\u0002')}\u0001${none.join('\u0002')}`;

/**
 * An ordinary Goal tape's worth of data carrying a selector goal (selectors ride in strings and role-marked params), so the
 * extracted model decodes it with its existing Goal decoder. Mirrors `CarrierToX` in formal/dafny/GoalSelect.dfy.
 */
export function selCarrier(sg: SelGoal): Goal {
  const dummy: Ty = { k: 's' };
  void dummy;
  return {
    v: 1, principal: sg.principal, ontDigest: sg.ontDigest, nlDigest: sg.nlDigest, sources: sg.sources,
    grants: sg.grants.map((g) => ({ gid: g.gid, verb: g.sel.k === 'verb' ? `V\u0001${g.sel.verb}` : `C\u0001${sel2(g.sel.all_of, g.sel.none_of)}`, res: g.res, cond: carryCond(g.cond) })),
    prohibits: sg.prohibits.map((p) => ({
      pid: p.pid, res: p.res, cond: carryCond(p.cond),
      target: { k: 'verb', verb: p.target.k === 'verb' ? `V\u0001${p.target.verb}` : p.target.k === 'effect' ? `E\u0001${p.target.cls}` : `T\u0001${sel2(p.target.all_of, p.target.none_of)}` },
    })),
    bounds: sg.bounds.map((b) => ({
      bid: b.bid, key: b.key, window: b.window, scope: b.scope, cap: b.cap, onExceed: b.onExceed, agg: b.agg, value: carryTerm(b.value),
      sel: b.sel.k === 'gids' ? { k: 'gids', gids: b.sel.gids } : b.sel.k === 'effect' ? { k: 'effect', cls: b.sel.cls } : { k: 'effect', cls: `T\u0001${sel2(b.sel.all_of, b.sel.none_of)}` },
    })),
    validity: sg.validity, deleg: sg.deleg, escalateOn: sg.escalateOn, wildcardAck: sg.wildcardAck, holes: sg.holes,
  };
}

/** The catalog tape `DecCatalog` reads: known trait ids, then per verb: verb, traits, number of roles, (role, paths)*. */
export function encodeSelCatalog(c: SelCatalog): Tape {
  const strs = (xs: readonly string[]): Tape => [['i', xs.length], ...xs.map((x): Tape[number] => ['s', x])];
  const out: Tape[number][] = [...strs(c.known), ['i', c.verbs.length]];
  for (const v of c.verbs) {
    const roles = Object.entries(v.roles);
    out.push(['s', v.verb], ...strs(v.traits), ['i', roles.length]);
    for (const [r, ps] of roles) out.push(['s', r], ...strs(ps));
  }
  return out;
}
