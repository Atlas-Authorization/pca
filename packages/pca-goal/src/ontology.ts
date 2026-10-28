import { hashCanonical, type SignerSuiteOpts } from '@atlasauth/pca';
import { allowWitness } from './examples';
import type { Cond, Goal, Grant, Hole, Op, OnExceed, Ontology as IrOntology, ParamDecl, Prohibit, ProhTarget, Quantity, RelDecl, ResPart, ResSel, Term, Ty, Unit, Value, VerbDecl } from './ir';
import { nlDigest } from './digests';
import { canonicalizeGoal } from './normalize';
import { signPayload, verifyPayload, type PinnedSigner, type SignedPayload, type SignerSecret } from './sign';

export const EFFECT_CLASSES = ['read', 'reversible', 'external_send', 'irreversible'] as const;
export type EffectClass = (typeof EFFECT_CLASSES)[number];
export type ParamKind = 'money' | 'count' | 'duration' | 'instant' | 'bytes' | 'ratio' | 'id' | 'enum' | 'text';

export interface OntUnit { kind: 'money' | 'count' | 'duration' | 'bytes' | 'ratio' | 'instant'; exponent?: number }
export interface OntType { id: string; id_prefix: string }
export interface OntRelation { id: string; from: string; to: string }
export interface OntParam { kind: ParamKind; /** money: allowed currencies (keys of units); enum: values; id: the entity type */ ccys?: string[]; values?: string[]; of?: string }
export interface OntVerb { id: string; effect: EffectClass; resource_type: string; params: Record<string, OntParam> }
export type SlotKind = 'money' | 'count' | 'duration' | 'instant' | 'id' | 'id_list' | 'enum' | 'enum_list' | 'text_list';
/** `cue`: words that, near an amount or number in the text, select this slot (deterministic interpreter and grounding). */
export interface TemplateSlot { name: string; kind: SlotKind; cue?: string[]; ccy?: string; of?: string; values?: string[]; mandatory: boolean; default?: SlotValue; max?: number }
export type SlotValue = { ccy: string; minor: number } | { n: number } | { ms: number } | { epoch_ms: number } | string | string[];

/**
 * Template-side terms and conditions: the Goal IR's `Cond` with two authoring conveniences, a parameter named without its type
 * (the type comes from the ontology verb when the template is instantiated) and a `slot` reference replaced by a typed literal.
 * Strings that start with `$` inside resource selectors are slot references as well.
 */
export type TTerm = { k: 'param'; path: string } | { k: 'slot'; slot: string } | { k: 'lit'; v: Value };
export type TCond = { k: 'true' } | { k: 'cmp'; op: Op; l: TTerm; r: TTerm } | { k: 'and'; a: TCond; b: TCond } | { k: 'or'; a: TCond; b: TCond } | { k: 'not'; c: TCond };
export type TemplateGrant = Omit<Grant, 'cond'> & { cond: TCond };
export type TemplateProhibit = Omit<Prohibit, 'cond'> & { cond: TCond };
/**
 * A limit in authoring form: instantiation turns it into an IR `Bound` (selecting the surviving grants by id, lifetime window,
 * session scope). `cap_slot` takes the cap from a count or money slot instead of the literal `cap`; `param` is the summed parameter.
 */
export interface TemplateBound { bid: string; agg: 'sum' | 'count'; over: string[] | 'all'; param?: string; cap: Quantity; onExceed: OnExceed; cap_slot?: string }
export interface Template {
  id: string; title: string;
  /** lowercase phrases that select this template in free text (deterministic interpreter) */
  phrases: string[];
  slots: TemplateSlot[];
  grants: TemplateGrant[]; prohibits: TemplateProhibit[]; bounds: TemplateBound[];
  example: Record<string, SlotValue>;
}
/** The intent-fidelity ontology: the signed authoring vocabulary (aliases, templates, units). `toIrOntology` projects it onto the IR's `Ontology`. */
export interface IntentOntology {
  id: string; version: number; domain: string;
  types: OntType[]; units: Record<string, OntUnit>; relations: OntRelation[]; verbs: OntVerb[];
  /** Total alias map: synonym -> canonical verb id. Declared, signed, never guessed. */
  aliases: Record<string, string>;
  templates: Template[];
}

export const ontologyDigest = (o: IntentOntology): string => hashCanonical({ d: 'atlas-pca/goal-intent-ontology/v1', ontology: o });
export const signOntology = (o: IntentOntology, secret: SignerSecret, suite?: SignerSuiteOpts): SignedPayload<IntentOntology> => signPayload('ontology', o, secret, suite);
export const verifyOntology = (s: SignedPayload<IntentOntology>, pins: readonly (string | PinnedSigner)[]): boolean => verifyPayload(s, 'ontology', pins);

const norm = (s: string): string => s.normalize('NFKC').toLowerCase().replace(/[​-‏⁠﻿]/g, '');

export function resolveVerb(o: IntentOntology, word: string): string | undefined {
  const w = word.trim();
  if (o.verbs.some((v) => v.id === w)) return w;
  const hit = o.aliases[w];
  if (hit !== undefined && Object.prototype.hasOwnProperty.call(o.aliases, w)) return hit;
  return undefined; // case or homoglyph variants are NOT guessed
}

// ---------------- projection onto the IR ontology ----------------

/** The currency a goal is written in: the first money quantity in its conditions or bound caps (undefined for a goal without money). */
export function goalCcy(g: Goal): string | undefined {
  let found: string | undefined;
  const t = (x: Term): void => {
    if (x.k !== 'lit') return;
    for (const v of x.v.k === 'set' ? x.v.items : [x.v]) if (found === undefined && v.k === 'q' && v.q.u.k === 'money') found = v.q.u.ccy;
  };
  const c = (x: Cond): void => { if (x.k === 'cmp') { t(x.l); t(x.r); } else if (x.k === 'and' || x.k === 'or') { c(x.a); c(x.b); } else if (x.k === 'not') c(x.c); };
  for (const gr of g.grants) c(gr.cond);
  for (const p of g.prohibits) c(p.cond);
  g.escalateOn.forEach(c);
  for (const b of g.bounds) if (found === undefined && b.cap.u.k === 'money') found = b.cap.u.ccy;
  return found;
}

export interface IrOntOpts {
  /** The currency every money parameter is declared in (the IR declares one unit per parameter). Default: USD when allowed, else the first allowed. */
  ccy?: string;
  /** Relation facts: the members of each (relation, anchor). A relation anchor a goal mentions must be declared for the goal to typecheck. */
  rels?: RelDecl[];
}
const paramTy = (p: OntParam, ccy: string | undefined): Ty =>
  p.kind === 'id' || p.kind === 'enum' || p.kind === 'text' ? { k: 's' }
    : p.kind === 'money' ? { k: 'q', u: { k: 'money', ccy: ccy !== undefined && p.ccys?.includes(ccy) ? ccy : p.ccys?.includes('USD') ? 'USD' : p.ccys![0]! } }
      : { k: 'q', u: { k: p.kind } };

/** T1's `Ontology` (verbs with their effect class and typed parameters, relation tables) for an intent ontology. The ONE adapter. */
export function toIrOntology(o: IntentOntology, opts: IrOntOpts = {}): IrOntology {
  const verbs: VerbDecl[] = o.verbs.map((v) => ({
    verb: v.id, cls: v.effect,
    params: Object.keys(v.params).sort().map((path): ParamDecl => ({ path, ty: paramTy(v.params[path]!, opts.ccy) })),
  }));
  return { verbs, rels: opts.rels ?? [] };
}
/** The IR ontology a goal is typed and decided against: money parameters in the goal's own currency. */
export const ontologyForGoal = (o: IntentOntology, g: Goal, rels: RelDecl[] = []): IrOntology => {
  const ccy = goalCcy(g);
  return toIrOntology(o, { ...(ccy !== undefined ? { ccy } : {}), rels });
};
/** Relation anchors a goal mentions, declared with no members (typing needs them; facts come per case). */
export function goalAnchors(g: Goal): RelDecl[] {
  const out = new Map<string, RelDecl>();
  const sel = (s: ResSel | ResPart): void => { if (s.k === 'related') out.set(s.rel + '\0' + s.anchor, { rel: s.rel, anchor: s.anchor, members: [] }); else if (s.k === 'all_of') s.parts.forEach(sel); };
  for (const gr of g.grants) sel(gr.res);
  for (const p of g.prohibits) sel(p.res);
  return [...out.values()].sort((a, b) => (a.rel + '\0' + a.anchor < b.rel + '\0' + b.anchor ? -1 : 1));
}

const refsRes = (s: ResSel): string[] => {
  const d = (x: string): string[] => (x.startsWith('$') ? [x.slice(1)] : []);
  return s.k === 'exact' ? d(s.id) : s.k === 'oneof' ? s.ids.flatMap(d) : s.k === 'related' ? d(s.anchor) : s.k === 'all_of' ? s.parts.flatMap(refsRes) : [];
};
const refsTerm = (x: TTerm): string[] => (x.k === 'slot' ? [x.slot] : []);
const refsCond = (c: TCond): string[] => (c.k === 'cmp' ? [...refsTerm(c.l), ...refsTerm(c.r)] : c.k === 'and' || c.k === 'or' ? [...refsCond(c.a), ...refsCond(c.b)] : c.k === 'not' ? refsCond(c.c) : []);
const refsGrant = (g: TemplateGrant): string[] => [...refsRes(g.res), ...refsCond(g.cond)];
const refsProhibit = (p: TemplateProhibit): string[] => [...refsRes(p.res), ...refsCond(p.cond)];
const refsBound = (b: TemplateBound): string[] => (b.cap_slot ? [b.cap_slot] : []);
/** Every `$slot` / slot-term reference of a template. */
const slotRefs = (t: Template): string[] => [...t.grants.flatMap(refsGrant), ...t.prohibits.flatMap(refsProhibit), ...t.bounds.flatMap(refsBound)];

export interface OntologyIssue { code: string; where: string; msg: string }

/**
 * Well-formedness checker (F6). Decision procedure: returns every defect, an empty list means well formed.
 * Checked: typing total, unit systems closed, alias map a function with no cycles/chains/confusables, every verb has an
 * effect class, templates type-check, and templates compile to non-empty, bounded Allow-sets.
 */
export function checkOntology(o: IntentOntology): OntologyIssue[] {
  const I: OntologyIssue[] = [];
  const bad = (code: string, where: string, msg: string): void => { I.push({ code, where, msg }); };
  const typeIds = new Set<string>(); const prefixes = new Set<string>();
  for (const t of o.types) {
    if (typeIds.has(t.id)) bad('dup_type', t.id, 'duplicate type id');
    typeIds.add(t.id);
    if (!t.id_prefix || prefixes.has(t.id_prefix)) bad('dup_prefix', t.id, 'id prefix empty or reused');
    prefixes.add(t.id_prefix);
  }
  for (const [u, d] of Object.entries(o.units)) {
    if (d.kind === 'money' && !(Number.isInteger(d.exponent) && d.exponent! >= 0 && d.exponent! <= 4)) bad('unit_exponent', u, 'money unit needs an integer exponent 0..4');
    if (d.kind !== 'money' && d.exponent !== undefined) bad('unit_exponent', u, 'only money units carry an exponent');
  }
  const relIds = new Set<string>();
  for (const r of o.relations) {
    if (relIds.has(r.id)) bad('dup_relation', r.id, 'duplicate relation');
    relIds.add(r.id);
    if (!typeIds.has(r.from) || !typeIds.has(r.to)) bad('relation_type', r.id, 'relation endpoint type is not declared');
  }
  const verbIds = new Set<string>();
  const verbs = new Map<string, OntVerb>();
  for (const v of o.verbs) {
    if (verbIds.has(v.id)) bad('dup_verb', v.id, 'duplicate verb');
    verbIds.add(v.id); verbs.set(v.id, v);
    if (!(EFFECT_CLASSES as readonly string[]).includes(v.effect)) bad('no_effect_class', v.id, 'verb has no valid effect class');
    if (!typeIds.has(v.resource_type)) bad('verb_resource_type', v.id, 'resource type is not declared');
    for (const [p, pt] of Object.entries(v.params)) {
      if (pt.kind === 'money') {
        if (!pt.ccys?.length) bad('param_ccy', `${v.id}.${p}`, 'money parameter lists no currency');
        for (const c of pt.ccys ?? []) if (o.units[c]?.kind !== 'money') bad('unit_unknown', `${v.id}.${p}`, `currency ${c} is not a declared money unit`);
      } else if (pt.kind === 'enum') { if (!pt.values?.length) bad('param_enum', `${v.id}.${p}`, 'enum parameter has no values'); }
      else if (pt.kind === 'id') { if (!pt.of || !typeIds.has(pt.of)) bad('param_type', `${v.id}.${p}`, 'id parameter type is not declared'); }
      else if (pt.kind !== 'text') {
        if (!Object.values(o.units).some((u) => u.kind === pt.kind)) bad('unit_unknown', `${v.id}.${p}`, `no declared unit of kind ${pt.kind}`);
      }
    }
  }
  // Alias map: a function (JS object keys are unique), keys normalized and collision-free, targets canonical, no chains or cycles.
  const seen = new Map<string, string>();
  for (const [k, target] of Object.entries(o.aliases)) {
    if (k !== norm(k) || /[^\x20-\x7e]/.test(k) && k !== k.normalize('NFKC')) bad('alias_key', k, 'alias key is not in normalized form');
    if (/[​-‏⁠﻿]/.test(k)) bad('alias_key', k, 'alias key contains invisible characters');
    const n = norm(k);
    if (seen.has(n) && seen.get(n) !== k) bad('alias_collision', k, `collides with ${seen.get(n)} after normalization`);
    seen.set(n, k);
    if (!verbIds.has(target)) bad('alias_target', k, 'alias target is not a canonical verb');
    if (Object.prototype.hasOwnProperty.call(o.aliases, target)) bad('alias_chain', k, 'alias target is itself an alias (chain or cycle)');
    if (verbIds.has(k) && k !== target) bad('alias_shadow', k, 'alias shadows a canonical verb');
  }
  // Templates.
  const tids = new Set<string>();
  for (const t of o.templates) {
    const w = `template:${t.id}`;
    if (tids.has(t.id)) bad('dup_template', w, 'duplicate template id');
    tids.add(t.id);
    const slotNames = new Set(t.slots.map((s) => s.name));
    if (slotNames.size !== t.slots.length) bad('dup_slot', w, 'duplicate slot');
    for (const r of slotRefs(t)) if (!slotNames.has(r)) bad('slot_undeclared', w, `slot ${r} is used but not declared`);
    for (const s of t.slots) {
      if ((s.kind === 'id' || s.kind === 'id_list') && (!s.of || !typeIds.has(s.of))) bad('slot_type', `${w}.${s.name}`, 'id slot type is not declared');
      if (s.kind === 'money' && o.units[s.ccy ?? '']?.kind !== 'money') bad('slot_ccy', `${w}.${s.name}`, 'money slot currency is not a declared unit');
      if ((s.kind === 'enum' || s.kind === 'enum_list') && !s.values?.length) bad('slot_enum', `${w}.${s.name}`, 'enum slot has no values');
      if (!s.mandatory && s.default === undefined) bad('slot_default', `${w}.${s.name}`, 'optional slot needs a default (an unfilled slot must be a hole or a default)');
      if (slotRefs(t).includes(s.name) === false) bad('slot_unused', `${w}.${s.name}`, 'declared slot is never used');
    }
    if (t.grants.length === 0) bad('empty_allow', w, 'template has no grant (empty Allow set)');
    const gids = new Set(t.grants.map((g) => g.gid));
    if (gids.size !== t.grants.length) bad('dup_gid', w, 'duplicate grant id');
    for (const g of t.grants) {
      const v = verbs.get(g.verb);
      if (!v) { bad('grant_verb', `${w}.${g.gid}`, 'grant verb is not in the ontology'); continue; }
      checkResource(o, g.res, v, `${w}.${g.gid}`, bad);
      checkCond(g.cond, v, t, `${w}.${g.gid}`, bad);
      if (g.res.k === 'any' && !(v.effect === 'read' && t.bounds.length > 0)) bad('unbounded', `${w}.${g.gid}`, 'wildcard resource in a template');
      if (v.effect !== 'read' && g.res.k === 'related' && t.bounds.length === 0) bad('unbounded', `${w}.${g.gid}`, 'non-read grant on a related set needs an aggregate bound');
    }
    for (const p of t.prohibits) {
      if (p.target.k === 'verb' && !verbs.has(p.target.verb)) bad('prohibit_verb', `${w}.${p.pid}`, 'prohibit verb is not in the ontology');
      if (p.target.k === 'effect' && !(EFFECT_CLASSES as readonly string[]).includes(p.target.cls)) bad('prohibit_effect', `${w}.${p.pid}`, 'unknown effect class');
    }
    for (const b of t.bounds) {
      if (b.over !== 'all' && b.over.some((x) => !gids.has(x))) bad('bound_over', `${w}.${b.bid}`, 'bound selects an unknown grant');
      if (b.cap_slot && !slotNames.has(b.cap_slot)) bad('slot_undeclared', w, `cap slot ${b.cap_slot} is not declared`);
      if (b.cap_slot) { const cs = t.slots.find((x) => x.name === b.cap_slot); if (cs && !(cs.kind === 'money' || cs.kind === 'count')) bad('bound_cap', `${w}.${b.bid}`, 'cap slot must be money or count'); if (cs && b.agg === 'count' && cs.kind !== 'count') bad('bound_cap', `${w}.${b.bid}`, 'count bound needs a count slot'); if (cs && b.agg === 'sum' && cs.kind !== 'money') bad('bound_cap', `${w}.${b.bid}`, 'sum bound over money needs a money slot'); }
      if (b.agg === 'sum' && !b.param) bad('bound_value', `${w}.${b.bid}`, 'sum bound has no value parameter');
    }
    // non-empty and bounded after instantiation with the declared example
    const g = instantiateTemplate(o, t.id, t.example, { principal: 'p', nl: '' });
    if (g.holes.length > 0) bad('example_holes', w, `example leaves holes: ${g.holes.map((h) => h.hid).join(',')}`);
    else if (g.grants.length !== t.grants.length) bad('empty_allow', w, 'example instantiation dropped a grant');
    else if (!hasAllowWitness(o, g)) bad('empty_allow', w, 'instantiated template has an empty Allow set');
  }
  return I;
}

function checkResource(o: IntentOntology, s: ResSel | ResPart, v: OntVerb, w: string, bad: (c: string, w: string, m: string) => void): void {
  const prefix = o.types.find((t) => t.id === v.resource_type)?.id_prefix;
  const idOk = (id: string, pre: string | undefined): boolean => id.startsWith('$') || (pre !== undefined && id.startsWith(pre));
  if (s.k === 'exact' && !idOk(s.id, prefix)) bad('resource_type', w, 'exact resource id has the wrong type prefix');
  else if (s.k === 'oneof') { if (s.ids.length === 0) bad('resource_empty', w, 'one_of is empty'); for (const i of s.ids) if (!idOk(i, prefix)) bad('resource_type', w, 'one_of member has the wrong type prefix'); }
  else if (s.k === 'related') {
    const r = o.relations.find((x) => x.id === s.rel);
    if (!r) bad('relation_unknown', w, `relation ${s.rel} is not declared`);
    else {
      if (r.to !== v.resource_type) bad('relation_type', w, 'relation target type differs from the verb resource type');
      const anchorPre = o.types.find((t) => t.id === r.from)?.id_prefix;
      if (!idOk(s.anchor, anchorPre)) bad('resource_type', w, 'relation anchor has the wrong type prefix');
    }
  } else if (s.k === 'all_of') { if (s.parts.length < 2) bad('all_of_arity', w, 'all_of needs at least two parts'); s.parts.forEach((x) => checkResource(o, x, v, w, bad)); }
}

function checkCond(c: TCond, v: OntVerb, t: Template, w: string, bad: (c: string, w: string, m: string) => void): void {
  if (c.k === 'and' || c.k === 'or') { checkCond(c.a, v, t, w, bad); checkCond(c.b, v, t, w, bad); return; }
  if (c.k === 'not') { checkCond(c.c, v, t, w, bad); return; }
  if (c.k !== 'cmp') return;
  const p = c.l.k === 'param' ? v.params[c.l.path] : undefined;
  if (c.l.k !== 'param' || !p) { bad('cond_param', w, 'left side of a comparison must be a declared parameter of the verb'); return; }
  const ordered = c.op === 'lt' || c.op === 'lte' || c.op === 'gt' || c.op === 'gte';
  if (ordered && (p.kind === 'text' || p.kind === 'enum' || p.kind === 'id')) bad('cond_order', w, 'ordering on a text/enum/id parameter');
  const x = c.r;
  if (x.k === 'slot') {
    const s = t.slots.find((q) => q.name === x.slot);
    if (!s) return;
    const okKind = p.kind === 'money' ? s.kind === 'money' : p.kind === s.kind || (p.kind === 'enum' && (s.kind === 'enum' || s.kind === 'enum_list')) || (p.kind === 'id' && (s.kind === 'id' || s.kind === 'id_list')) || (p.kind === 'text' && s.kind === 'text_list');
    if (!okKind) bad('cond_type', w, `slot ${s.name} (${s.kind}) does not type-check against parameter kind ${p.kind}`);
    if (p.kind === 'money' && s.kind === 'money' && !p.ccys?.includes(s.ccy ?? '')) bad('cond_unit', w, 'slot currency is not accepted by the parameter');
    const list = s.kind === 'id_list' || s.kind === 'enum_list' || s.kind === 'text_list';
    if (list !== (c.op === 'in' || c.op === 'nin')) bad('cond_type', w, 'list slots pair with in/nin and scalar slots with the other operators');
  } else if (x.k === 'lit') {
    const l = x.v;
    if (l.k === 'set') { if (l.items.length === 0) bad('cond_type', w, 'empty literal list'); for (const i of l.items) litCheck(i, p, w, bad); if (c.op !== 'in' && c.op !== 'nin') bad('cond_type', w, 'a literal set pairs with in/nin'); }
    else { litCheck(l, p, w, bad); if (c.op === 'in' || c.op === 'nin') bad('cond_type', w, 'in/nin needs a list'); }
  } else bad('cond_term', w, 'unsupported right-hand term');
}
function litCheck(l: Value, p: OntParam, w: string, bad: (c: string, w: string, m: string) => void): void {
  if (l.k === 'q') {
    if (l.q.u.k !== p.kind) bad('cond_type', w, 'literal kind differs from the parameter kind');
    if (l.q.u.k === 'money' && !p.ccys?.includes(l.q.u.ccy)) bad('cond_unit', w, 'literal currency is not accepted by the parameter');
  } else if (l.k === 's') {
    if (p.kind !== 'enum' && p.kind !== 'id' && p.kind !== 'text') bad('cond_type', w, 'literal kind differs from the parameter kind');
    if (p.kind === 'enum' && !p.values?.includes(l.s)) bad('cond_enum', w, 'enum literal is not a member');
  } else bad('cond_type', w, 'nested literal set');
}

/** A cheap Allow witness for the checker: build an action from the grant's selector and conditions. */
const hasAllowWitness = (o: IntentOntology, g: Goal): boolean => {
  const ont = ontologyForGoal(o, g);
  return g.grants.every((gr) => allowWitness(g, gr, ont) !== undefined);
};

export interface InstantiateOpts { principal: string; nl: string; sources?: string[] }

const quantityOf = (s: TemplateSlot, v: SlotValue): Quantity | undefined => {
  if (typeof v === 'string' || Array.isArray(v)) return undefined;
  if ('minor' in v && s.kind === 'money' && v.ccy === s.ccy && Number.isSafeInteger(v.minor) && v.minor >= 0) return { u: { k: 'money', ccy: v.ccy }, n: v.minor };
  if ('n' in v && s.kind === 'count' && Number.isSafeInteger(v.n) && v.n >= 0) return { u: { k: 'count' }, n: v.n };
  if ('ms' in v && s.kind === 'duration' && Number.isSafeInteger(v.ms) && v.ms >= 0) return { u: { k: 'duration' }, n: v.ms };
  if ('epoch_ms' in v && s.kind === 'instant' && Number.isSafeInteger(v.epoch_ms)) return { u: { k: 'instant' }, n: v.epoch_ms };
  return undefined;
};
const sv = (s: string): Value => ({ k: 's', s });

/** Typed value(s) of a slot, or a reason string when it is missing/invalid (the slot then becomes a Hole). */
export function slotLits(o: IntentOntology, s: TemplateSlot, v: SlotValue | undefined): Value[] | string {
  if (v === undefined) return 'missing';
  switch (s.kind) {
    case 'money': case 'count': case 'duration': case 'instant': {
      const q = quantityOf(s, v);
      if (!q) return 'ill-typed';
      if (s.max !== undefined && (s.kind === 'instant' ? 0 : q.n) > s.max) return 'above the template maximum';
      return [{ k: 'q', q }];
    }
    case 'id': {
      const pre = o.types.find((t) => t.id === s.of)?.id_prefix;
      return typeof v === 'string' && pre && v.startsWith(pre) && v.length > pre.length && /^[A-Za-z0-9_-]+$/.test(v) ? [sv(v)] : 'ill-typed';
    }
    case 'id_list': {
      const pre = o.types.find((t) => t.id === s.of)?.id_prefix;
      return Array.isArray(v) && v.length > 0 && v.every((x) => pre && x.startsWith(pre) && /^[A-Za-z0-9_-]+$/.test(x)) ? v.map(sv) : 'ill-typed';
    }
    case 'enum': return typeof v === 'string' && s.values?.includes(v) ? [sv(v)] : 'ill-typed';
    case 'enum_list': return Array.isArray(v) && v.length > 0 && v.every((x) => s.values?.includes(x)) ? v.map(sv) : 'ill-typed';
    case 'text_list': return Array.isArray(v) && v.length > 0 && v.every((x) => typeof x === 'string' && x.length > 0 && x === x.normalize('NFKC') && !/[​-‏⁠﻿]/.test(x)) ? v.map(sv) : 'ill-typed';
  }
}

const isListSlot = (t: Template, name: string): boolean => /_list$/.test(t.slots.find((x) => x.name === name)?.kind ?? '');
const FOREVER = Number.MAX_SAFE_INTEGER;

/**
 * Template -> Goal (T1's IR, canonical order). Mandatory slots that are missing or ill-typed become Holes; every clause
 * depending on a hole is dropped (the most restrictive completion), so the draft is a sub-policy of any completion (G-T7) and
 * holes are limited to the template's declared slots. A prohibition that depends on a hole widens to every resource instead.
 * Limits become IR bounds over the surviving grants (counted by admitting grant, lifetime window, session scope).
 */
export function instantiateTemplate(o: IntentOntology, templateId: string, values: Record<string, SlotValue>, opts: InstantiateOpts): Goal {
  const t = o.templates.find((x) => x.id === templateId);
  if (!t) throw new Error(`unknown template ${templateId}`);
  const bound = new Map<string, Value[]>();
  const holes: Hole[] = [];
  for (const s of t.slots) {
    const r = slotLits(o, s, values[s.name] ?? s.default);
    if (typeof r === 'string') holes.push({ hid: s.name, q: `What is the ${s.name.replace(/_/g, ' ')} (${s.kind}${s.ccy ? ' ' + s.ccy : ''})? (${r})`, domain: [], affects: [], global: false });
    else bound.set(s.name, r);
  }
  const deps = (refs: string[]): boolean => refs.every((r) => bound.has(r));
  const single = (name: string): Value => bound.get(name)![0]!;
  const sub = (id: string): string => (id.startsWith('$') ? (single(id.slice(1)) as { s: string }).s : id);
  const subPart = (r: ResPart): ResPart => (r.k === 'exact' ? { k: 'exact', id: sub(r.id) } : r.k === 'oneof' ? { k: 'oneof', ids: r.ids.map(sub) } : { ...r, anchor: sub(r.anchor) });
  const subRes = (r: ResSel): ResSel => (r.k === 'any' ? r : r.k === 'all_of' ? { k: 'all_of', parts: r.parts.map(subPart) } : subPart(r));
  const verbOf = new Map(o.verbs.map((v) => [v.id, v] as const));
  const tyOf = (verb: string | undefined, path: string, ccy: string | undefined): Ty => {
    const p = (verb !== undefined ? verbOf.get(verb) : undefined)?.params[path] ?? o.verbs.map((v) => v.params[path]).find((x) => x !== undefined);
    if (!p) throw new Error(`parameter ${path} is not declared by any verb`);
    return paramTy(p, ccy);
  };
  const lit = (x: TTerm): Term | undefined => {
    if (x.k === 'slot') { const l = bound.get(x.slot)!; return { k: 'lit', v: isListSlot(t, x.slot) ? { k: 'set', items: l } : l[0]! }; }
    return x.k === 'lit' ? { k: 'lit', v: x.v } : undefined;
  };
  const ccyOf = (x: Term | undefined): string | undefined => (x?.k === 'lit' && x.v.k === 'q' && x.v.q.u.k === 'money' ? x.v.q.u.ccy : undefined);
  const subCond = (c: TCond, verb: string | undefined): Cond => {
    if (c.k === 'true') return c;
    if (c.k === 'and') return { k: 'and', a: subCond(c.a, verb), b: subCond(c.b, verb) };
    if (c.k === 'or') return { k: 'or', a: subCond(c.a, verb), b: subCond(c.b, verb) };
    if (c.k === 'not') return { k: 'not', c: subCond(c.c, verb) };
    const lv = lit(c.l), rv = lit(c.r);
    const hint = ccyOf(lv) ?? ccyOf(rv);
    const term = (x: TTerm, v: Term | undefined): Term => v ?? { k: 'param', path: (x as { path: string }).path, ty: tyOf(verb, (x as { path: string }).path, hint) };
    return { k: 'cmp', op: c.op, l: term(c.l, lv), r: term(c.r, rv) };
  };
  const dropped = new Set<string>();
  const grants: Grant[] = [];
  const keepBound = t.bounds.filter((b) => deps(refsBound(b)));
  for (const b of t.bounds) if (!keepBound.includes(b)) for (const g of t.grants) if (b.over === 'all' || b.over.includes(g.gid)) dropped.add(g.gid);
  for (const g of t.grants) {
    if (dropped.has(g.gid) || !deps(refsGrant(g))) dropped.add(g.gid);
    else grants.push({ gid: g.gid, verb: g.verb, res: subRes(g.res), cond: subCond(g.cond, g.verb) });
  }
  const prohibits: Prohibit[] = t.prohibits.map((p) => {
    const verb = p.target.k === 'verb' ? p.target.verb : o.verbs.find((v) => v.effect === (p.target as { cls: string }).cls)?.id;
    return deps(refsProhibit(p)) ? { pid: p.pid, target: p.target as ProhTarget, res: subRes(p.res), cond: subCond(p.cond, verb) } : { pid: p.pid, target: p.target as ProhTarget, res: { k: 'any', reason: 'hole' }, cond: { k: 'true' } };
  });
  const kept = new Set(grants.map((g) => g.gid));
  const bounds = [];
  for (const b of keepBound) {
    const gids = (b.over === 'all' ? grants.map((g) => g.gid) : b.over.filter((x) => kept.has(x)));
    if (gids.length === 0) continue;
    const capLit = b.cap_slot ? single(b.cap_slot) : undefined;
    const cap: Quantity = capLit && capLit.k === 'q' ? capLit.q : b.cap;
    const verb = grants.find((g) => g.gid === gids[0])!.verb;
    bounds.push({
      bid: b.bid, sel: { k: 'gids' as const, gids }, agg: b.agg,
      value: b.agg === 'sum' ? { k: 'param' as const, path: b.param!, ty: tyOf(verb, b.param!, cap.u.k === 'money' ? cap.u.ccy : undefined) } : { k: 'lit' as const, v: { k: 'q' as const, q: { u: { k: 'count' as const }, n: 1 } } },
      key: '', window: { k: 'lifetime' as const }, scope: { k: 'session' as const }, cap, onExceed: b.onExceed,
    });
  }
  return canonicalizeGoal({
    v: 1, principal: opts.principal, ontDigest: ontologyDigest(o), nlDigest: nlDigest(opts.nl), sources: [...(opts.sources ?? [])],
    grants, prohibits, bounds,
    validity: { notBefore: 0, notAfter: FOREVER, maxIdle: 0 }, deleg: { maxDepth: 0, narrowOnly: true, mayTouch: [] },
    escalateOn: [], wildcardAck: [], holes,
  });
}

// ---- Locale-aware human number parsing (interpreter front end only; the IR has no locale) ----

export type MoneyResult = { ok: true; minor: number } | { ok: false; reason: string };

/**
 * "1,000.50", "1.000,50", "$20", "20 dollars". Ambiguous literals ("1,000" with no locale hint, "1.000") are NOT guessed:
 * they yield a failure and become a Hole. `locale` 'en' reads ',' as thousands, 'de' reads '.' as thousands.
 */
export function parseHumanAmount(text: string, exponent: number, locale?: 'en' | 'de'): MoneyResult {
  const t = text.normalize('NFKC').trim().replace(/[^\d.,]/g, '');
  if (!/^\d[\d.,]*$/.test(t) || /[.,]{2}/.test(t)) return { ok: false, reason: 'not a number' };
  const lastDot = t.lastIndexOf('.'), lastComma = t.lastIndexOf(',');
  let dec: '.' | ',' | undefined; let thou: '.' | ',' | undefined;
  if (lastDot >= 0 && lastComma >= 0) { dec = lastDot > lastComma ? '.' : ','; thou = dec === '.' ? ',' : '.'; }
  else if (lastDot >= 0 || lastComma >= 0) {
    const sep = (lastDot >= 0 ? '.' : ',') as '.' | ',';
    const parts = t.split(sep);
    const groupLike = parts.length > 2 || parts[parts.length - 1]!.length === 3;
    if (!groupLike) dec = sep;
    else if (parts.length > 2) thou = sep;
    else if (locale) { if ((locale === 'en') === (sep === ',')) thou = sep; else dec = sep; }
    else return { ok: false, reason: 'ambiguous separator' };
  }
  let intPart = t, frac = '';
  if (dec) { const i = t.lastIndexOf(dec); intPart = t.slice(0, i); frac = t.slice(i + 1); }
  if (thou) {
    const groups = intPart.split(thou);
    if (groups.slice(1).some((g) => g.length !== 3) || groups[0]!.length === 0 || groups[0]!.length > 3) return { ok: false, reason: 'malformed grouping' };
    intPart = groups.join('');
  }
  if (frac.length > exponent) return { ok: false, reason: 'more decimals than the currency allows' };
  const minor = Number(intPart + frac.padEnd(exponent, '0'));
  return Number.isSafeInteger(minor) ? { ok: true, minor } : { ok: false, reason: 'out of range' };
}

