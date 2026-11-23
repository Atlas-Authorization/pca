// hosted.ts - the hosted action registry of one Atlas instance: the publish gate (what a new version of a namespace may change
// without a reviewer) and the verifier's view of the active versions (what the hosted adjudication path reads: provenance
// facts, trait floors for rule 22, undo eligibility, the server reversibility class, compiled business rules).
// Pure: storage, keys and time are the caller's. The API stores what `publishGate` returns and builds `hostedView` per request.
//
// Fail closed everywhere: an action the view does not know, an action that is not confirmed by a reviewer key the instance pins,
// or a deprecated action, gets the top of the trait registry (every floor) and no provenance facts (sensitive), is irreversible,
// and is never undoable.

import { hashCanonical, readEnvelope, type Capability, type PcaOperation, type ProvActionInfo, type UndoEngine } from '@atlasauth/pca';
import { CAVEAT_KINDS, type ActionDef, type CaveatKind } from './def';
import { verifyPack, type PackKey, type SignedActionPack } from './build';
import { compileBusinessRules, diffBusinessRules, lintBusinessRules, rulesReviewError, type BusinessRules, type CompiledRules, type RulesReview } from './business-rules';
import type { ReviewerPins } from './confirmation';
import { CORE_REGISTRY } from './core-traits';
import { diffDefs, type DiffClass } from './diff';
import { defDigest } from './digest';
import { effective, isConfirmed, type ReviewOpts } from './effective';
import { attestationVerifier } from './import/review';
import { compareVersions } from './pack';
import { provenanceInfoOf } from './provenance';
import { extendRegistry, floorDecision, floorOf, topTraits, type Decision, type Profile, type Registry, type TraitDef } from './traits';
import { undoEngine } from './undo';

export const RULES_DOC_KIND = 'pca-action-rules';
export const HOSTED_VERSION_DOMAIN = 'atlas-pca/hosted-action-version/v1';
const PLAIN_SEMVER = /^\d+\.\d+\.\d+$/;

/** The business rules a version carries, per verb, with the reviewer signatures that widened rules need. */
export interface RulesDoc {
  v: 1;
  kind: typeof RULES_DOC_KIND;
  ns: string;
  rules: Record<string, BusinessRules>;
  reviews?: Record<string, RulesReview>;
}

/** One stored version of a namespace. */
export interface HostedVersion {
  ns: string;
  version: string;
  /** Digest of {pack, rules, traits, deprecated}: the content address of this version. */
  digest: string;
  /** Digest of the version this one replaced (null for the first). */
  prev: string | null;
  pack: SignedActionPack;
  rules: RulesDoc;
  /** Custom trait definitions the pack was built against (empty: the core registry). */
  traits: TraitDef[];
  /** Verbs removed from the namespace: still listed, always treated as unknown (strictest). */
  deprecated: string[];
  /** One entry per verb that changed against the replaced version. */
  changes: HostedChange[];
}

export interface HostedChange {
  verb: string;
  class: DiffClass | 'added' | 'removed' | 'deprecated';
  reasons: string[];
  /** The rules diff, when the rules changed. */
  rules?: { class: DiffClass; reasons: string[] };
  /** True when a reviewer signature covered a widening (a confirmation or a rules review). */
  reviewed?: boolean;
}

export type GateCode = 'bad_pack' | 'bad_rules' | 'bad_traits' | 'bad_version' | 'ns_mismatch' | 'not_newer' | 'widen_unreviewed';
export type GateResult = { ok: true; version: HostedVersion } | { ok: false; code: GateCode; reason: string; verbs?: string[]; changes?: HostedChange[] };

export interface GateInput {
  /** The active version of the namespace (absent: the first publish). */
  current?: HostedVersion;
  pack: unknown;
  rules?: unknown;
  traits?: unknown;
  /** Publisher keys the instance pins (kid -> Ed25519). */
  publisherKeys: readonly PackKey[];
  /** Reviewer keys the instance pins: the only signatures that count as a confirmation or a rules review. */
  pins: ReviewerPins | undefined;
  /** Re-activating a stored version (pinning) instead of publishing a new one: no version-order check. */
  pin?: boolean;
}

const fail = (code: GateCode, reason: string, verbs?: string[]): GateResult => ({ ok: false, code, reason, ...(verbs ? { verbs } : {}) });

/** The trait registry of a version: core plus its custom traits. Throws for custom traits that do not extend their implies. */
export const registryOfTraits = (traits: readonly TraitDef[]): Registry => (traits.length === 0 ? CORE_REGISTRY : extendRegistry(CORE_REGISTRY, traits));

export const reviewOptsOf = (pins: ReviewerPins | undefined, reg: Registry): ReviewOpts => (pins === undefined ? {} : { attestationVerified: attestationVerifier({ pins, registry: reg }) });

/** Null iff `x` is a rules document for `ns` whose every verb is in `defs` and whose rules lint without errors. */
export function rulesDocError(x: unknown, ns: string, defs: readonly ActionDef[]): string | null {
  if (x === null || typeof x !== 'object' || Array.isArray(x)) return 'rules must be a pca-action-rules document';
  const r = x as Record<string, unknown>;
  for (const k of Object.keys(r)) if (!['v', 'kind', 'ns', 'rules', 'reviews'].includes(k)) return `rules: unknown member '${k}'`;
  if (r.v !== 1 || r.kind !== RULES_DOC_KIND) return `rules: not a ${RULES_DOC_KIND} v1 document`;
  if (r.ns !== ns) return `rules: ns '${String(r.ns)}' is not the pack's '${ns}'`;
  if (r.rules === null || typeof r.rules !== 'object' || Array.isArray(r.rules)) return 'rules.rules must map verbs to rules blocks';
  if (r.reviews !== undefined && (r.reviews === null || typeof r.reviews !== 'object' || Array.isArray(r.reviews))) return 'rules.reviews must map verbs to rules reviews';
  const byVerb = new Map(defs.map((d) => [d.verb, d]));
  for (const [verb, block] of Object.entries(r.rules as Record<string, unknown>)) {
    const d = byVerb.get(verb);
    if (!d) return `rules: '${verb}' is not an action of the pack`;
    const errs = lintBusinessRules(d, block).filter((f) => f.severity === 'error');
    if (errs.length > 0) return `rules for '${verb}': ${errs.map((f) => f.message).join('; ')}`;
  }
  for (const verb of Object.keys((r.reviews ?? {}) as object)) if (!byVerb.has(verb)) return `rules.reviews: '${verb}' is not an action of the pack`;
  return null;
}

export const hostedVersionDigest = (v: Pick<HostedVersion, 'pack' | 'rules' | 'traits' | 'deprecated'>): string =>
  hashCanonical({ d: HOSTED_VERSION_DOMAIN, pack: v.pack, rules: v.rules, traits: v.traits, deprecated: [...v.deprecated].sort() });

const EFFECTIVE_DIMS = ['confirmation', 'effective.traits', 'effective.profile'];

/**
 * Decide whether a version may become the active one of its namespace, and compute what it changes. Refused:
 *   bad_pack       the pack does not verify under a pinned publisher key (signature, Merkle root, every def valid);
 *   bad_traits     its custom traits are malformed or weaken what they imply;
 *   bad_rules      the rules document is malformed, names an unknown action, or lints with an error (a contradiction);
 *   ns_mismatch    another namespace than the active version's;
 *   bad_version / not_newer   a version that is not plain MAJOR.MINOR.PATCH above the active one (publish only);
 *   widen_unreviewed   an action whose effective authority widens without a valid confirmation of the new definition, or whose
 *                  rules widen (a higher ceiling, a dropped approval, more recipients, ...) without a valid rules review.
 * Removed actions become deprecated (listed, strictest). New and changed unconfirmed actions are accepted: they are strict.
 */
export function publishGate(i: GateInput): GateResult {
  let traits: TraitDef[] = [];
  if (i.traits !== undefined) {
    if (!Array.isArray(i.traits)) return fail('bad_traits', 'traits must be a list of trait definitions');
    traits = i.traits as TraitDef[];
  }
  let reg: Registry;
  try { reg = registryOfTraits(traits); } catch (e) { return fail('bad_traits', (e as Error).message); }
  const pv = verifyPack(i.pack, i.publisherKeys, reg);
  if (!pv.ok) return fail('bad_pack', pv.reason);
  const pack = i.pack as SignedActionPack;
  if (!PLAIN_SEMVER.test(pack.version)) return fail('bad_version', `version '${pack.version}' must be MAJOR.MINOR.PATCH`);
  const cur = i.current;
  if (cur && cur.ns !== pack.ns) return fail('ns_mismatch', `the active namespace is '${cur.ns}', the pack is '${pack.ns}'`);
  if (cur && !i.pin && compareVersions(pack.version, cur.version) <= 0) return fail('not_newer', `version ${pack.version} is not above the active ${cur.version}`);
  const rules: RulesDoc = i.rules === undefined ? { v: 1, kind: RULES_DOC_KIND, ns: pack.ns, rules: {} } : (i.rules as RulesDoc);
  const re = rulesDocError(rules, pack.ns, pack.defs);
  if (re) return fail('bad_rules', re);

  const review = reviewOptsOf(i.pins, reg);
  const prevReg = cur ? (() => { try { return registryOfTraits(cur.traits); } catch { return reg; } })() : reg;
  const prevReview = reviewOptsOf(i.pins, prevReg);
  const changes: HostedChange[] = [];
  const blocked: string[] = [];
  const reasons: string[] = [];
  const oldDefs = new Map((cur?.pack.defs ?? []).map((d) => [d.verb, d]));
  const oldDep = new Set(cur?.deprecated ?? []);
  const newVerbs = new Set(pack.defs.map((d) => d.verb));
  for (const n of pack.defs) {
    const o = oldDefs.get(n.verb);
    const newRules = rules.rules[n.verb];
    const confirmed = safeConfirmed(n, review);
    let change: HostedChange;
    if (!o || oldDep.has(n.verb)) {
      // a new (or re-added) action: unconfirmed it is strict; confirmed it carries the reviewer's signature over this exact def
      change = { verb: n.verb, class: 'added', reasons: [], ...(confirmed ? { reviewed: true } : {}) };
    } else {
      // compare what each version ENFORCES (each under its own registry): a confirmation is judged against the instance pins
      const d = diffDefsAcross(o, n, prevReg, reg, prevReview, review);
      change = { verb: n.verb, class: d.class, reasons: d.reasons };
      const effWidens = d.reasons.some((r) => EFFECTIVE_DIMS.some((dim) => r.startsWith(`${dim}: widen`) || r.startsWith(`${dim}: incomparable`)));
      if (effWidens) {
        if (confirmed) change.reviewed = true;
        else { blocked.push(n.verb); reasons.push(`${n.verb}: its effective authority widens without a valid confirmation of the new definition`); }
      }
    }
    const oldRules = o && !oldDep.has(n.verb) ? cur!.rules.rules[n.verb] : undefined;
    if (oldRules !== undefined || newRules !== undefined) {
      let rd: { class: DiffClass; reasons: string[] };
      try { rd = diffBusinessRules(n, oldRules, newRules); } catch (e) { rd = { class: 'incomparable', reasons: [`rules: ${(e as Error).message}`] }; }
      // rules apply to confirmed and unconfirmed actions alike (a dropped deny turns a refusal into a question), so any widening
      // of them needs a reviewer, whatever the state of the definition
      if (rd.class !== 'equal') change.rules = rd;
      if (rd.class === 'widen' || rd.class === 'incomparable') {
        // removing every rule is reviewed as the empty block
        const err = rulesReviewError(rules.reviews?.[n.verb], n, newRules ?? {}, i.pins);
        if (err === null) change.reviewed = true;
        else { blocked.push(n.verb); reasons.push(`${n.verb}: its business rules widen (${rd.reasons.join(', ')}) without a valid rules review: ${err}`); }
      }
    }
    if (change.class !== 'equal' || change.rules) changes.push(change);
  }
  const deprecated = new Set([...oldDep].filter((v) => !newVerbs.has(v)));
  for (const v of oldDefs.keys()) {
    if (newVerbs.has(v) || oldDep.has(v)) continue;
    deprecated.add(v);
    changes.push({ verb: v, class: 'deprecated', reasons: ['removed from the namespace: treated as unknown'] });
  }
  if (blocked.length > 0) return { ...fail('widen_unreviewed', reasons.join('\n'), [...new Set(blocked)].sort()), changes: changes.sort((a, b) => (a.verb < b.verb ? -1 : 1)) } as GateResult;
  // deprecated defs stay listed (history, the console) but only from the version that removed them
  const keep: SignedActionPack = pack;
  const body = { pack: keep, rules, traits, deprecated: [...deprecated].sort() };
  return { ok: true, version: { ns: pack.ns, version: pack.version, digest: hostedVersionDigest(body), prev: cur?.digest ?? null, ...body, changes: changes.sort((a, b) => (a.verb < b.verb ? -1 : 1)) } };
}

function safeConfirmed(d: ActionDef, review: ReviewOpts): boolean {
  try { return isConfirmed(d, review); } catch { return false; }
}

/** diffDefs, but each side under its own registry and review (a trait registry change shows up in the effective dimensions). */
function diffDefsAcross(o: ActionDef, n: ActionDef, oReg: Registry, nReg: Registry, oRev: ReviewOpts, nRev: ReviewOpts): { class: DiffClass; reasons: string[] } {
  const base = diffDefs(o, n, nReg, nRev);
  if (oReg === nReg) return base;
  // the effective profile under the OLD registry against the NEW one: a lowered custom floor widens
  const eo = effective(o, oReg, oRev).eff;
  const en = effective(n, nReg, nRev).eff;
  const le = (a: Profile, b: Profile) => floorLeq(a, b);
  const rel = le(eo, en) ? (le(en, eo) ? null : 'narrow') : le(en, eo) ? 'widen' : 'incomparable';
  if (rel === null) return base;
  const reasons = [...base.reasons.filter((r) => !r.startsWith('effective.profile')), `effective.profile: ${rel}`].sort();
  const cls: DiffClass = rel === 'incomparable' || base.class === 'incomparable' || (rel === 'widen' && base.class === 'narrow') || (rel === 'narrow' && base.class === 'widen') ? 'incomparable' : rel === 'widen' || base.class === 'widen' ? 'widen' : 'narrow';
  return { class: cls, reasons };
}
const REV = { reversible: 0, rate_limited: 1, irreversible: 2 } as const;
function floorLeq(p: Profile, q: Profile): boolean {
  const sub = (a: readonly string[], b: readonly string[]) => a.every((x) => b.includes(x));
  return p.risk <= q.risk && REV[p.rev] <= REV[q.rev] && p.blast_ppm <= q.blast_ppm && p.esc <= q.esc && sub(p.caveats, q.caveats) && sub(p.context, q.context) && sub(p.prules, q.prules);
}

// ---- the verifier's view -----------------------------------------------------------------------------------------------------

export type ServerClass = 'reversible' | 'costly' | 'irreversible';

export interface HostedLookup {
  verb: string;
  /** Known, not deprecated, and confirmed by a reviewer key the instance pins. */
  confirmed: boolean;
  known: boolean;
  deprecated: boolean;
  def_digest?: string;
  /** The definition's idempotency key parameter (for the call context the server establishes). */
  idempotency_param?: string;
  /** The effective profile: the definition's when confirmed, else the top of the registry. */
  profile: Profile;
  traits: string[];
  /** The server reversibility class (the hosted risk vocabulary): `irreversible` unless confirmed. */
  serverClass: ServerClass;
  rules?: CompiledRules;
}

export interface HostedView {
  /** Versions the view was built from (ns@version), for audit. */
  versions: string[];
  lookup(verb: string): HostedLookup;
  /** The `provenance.actions` resolver: confirmed, non-deprecated exact verbs only; anything else undefined (sensitive). */
  provenance(op: { verb: string }): ProvActionInfo | undefined;
  /** Undo eligibility from confirmed definitions (exact verb; a deprecated action never). */
  undo: UndoEngine;
  /** Rule 22: the floor decision for this action under what the grant provides and the call context the server observed. */
  floor(verb: string, grant: GrantFactsIn, callContext: readonly string[]): Decision;
}

export interface GrantFactsIn {
  caveats: readonly string[];
  max_esc: number;
  preauth_esc: number;
}

/** Grant facts for rule 22 from a stored grant: envelope caveat types plus the pin block's caveats and escalation tiers. */
export function grantFactsOf(grant: Capability): GrantFactsIn {
  const env = readEnvelope(grant) as { caveats?: Array<{ type?: unknown }>; actions?: { caveats?: unknown; max_esc?: unknown; preauth_esc?: unknown } } | null;
  const a = env?.actions;
  const int = (v: unknown, d: number) => (Number.isSafeInteger(v) && (v as number) >= 0 && (v as number) <= 3 ? (v as number) : d);
  const caveats = [...(env?.caveats ?? []).map((c) => c?.type), ...(Array.isArray(a?.caveats) ? a!.caveats : [])].filter((t): t is string => typeof t === 'string');
  return { caveats, max_esc: int(a?.max_esc, 3), preauth_esc: int(a?.preauth_esc, 0) };
}

const SERVER_CLASS = { reversible: 'reversible', rate_limited: 'costly', irreversible: 'irreversible' } as const;

/**
 * Build the verifier's view from the active versions of an instance. A version whose custom traits no longer load still counts
 * (the instance stays in registry mode) and every action it names is refused: known, unconfirmed, and its rules replaced by a
 * deny. A def that fails to normalize is treated the same way at lookup.
 */
export function hostedView(versions: readonly HostedVersion[], pins: ReviewerPins | undefined): HostedView {
  type Entry = { def: ActionDef; reg: Registry; review: ReviewOpts; rules?: BusinessRules };
  const byVerb = new Map<string, Entry>();
  const deprecated = new Set<string>();
  const regs: Registry[] = [];
  const names: string[] = [];
  const broken = new Set<string>();
  for (const v of versions) {
    names.push(`${v.ns}@${v.version}`);
    let reg: Registry;
    try { reg = registryOfTraits(v.traits); } catch {
      for (const d of v.pack?.defs ?? []) if (typeof d?.verb === 'string') broken.add(d.verb);
      continue;
    }
    regs.push(reg);
    const review = reviewOptsOf(pins, reg);
    for (const d of v.pack.defs) if (!byVerb.has(d.verb)) byVerb.set(d.verb, { def: d, reg, review, ...(v.rules.rules[d.verb] ? { rules: v.rules.rules[d.verb] } : {}) });
    for (const x of v.deprecated) deprecated.add(x);
  }
  for (const x of deprecated) byVerb.delete(x);
  for (const x of broken) byVerb.delete(x);
  // the strictest profile any active registry has (an unknown verb could be anything)
  const top = regs.length === 0 ? floorOf(CORE_REGISTRY, topTraits(CORE_REGISTRY)) : regs.map((r) => floorOf(r, topTraits(r))).reduce((a, b) => (floorLeq(a, b) ? b : floorLeq(b, a) ? a : joinProfiles(a, b)));
  const topTraitIds = [...new Set((regs.length === 0 ? [CORE_REGISTRY] : regs).flatMap((r) => topTraits(r)))].sort();
  const cache = new Map<string, HostedLookup>();
  const lookup = (verb: string): HostedLookup => {
    const hit = cache.get(verb);
    if (hit) return hit;
    const e = byVerb.get(verb);
    let out: HostedLookup = { verb, confirmed: false, known: e !== undefined, deprecated: deprecated.has(verb), profile: top, traits: topTraitIds, serverClass: 'irreversible' };
    if (!e && broken.has(verb) && !deprecated.has(verb)) out = { ...out, known: true, rules: BROKEN_RULES(verb) };
    if (e) {
      try {
        const eff = effective(e.def, e.reg, e.review);
        const confirmed = eff.confirmed === true;
        const idem = e.def.idempotency?.mode === 'key_param' ? e.def.idempotency.param : undefined;
        out = { ...out, def_digest: defDigest(e.def), ...(idem !== undefined ? { idempotency_param: idem } : {}), confirmed, ...(confirmed ? { profile: eff.eff, traits: eff.traits, serverClass: SERVER_CLASS[eff.eff.rev] } : {}) };
        // rules apply whether or not the action is confirmed: they only tighten
        if (e.rules) out.rules = compileBusinessRules(e.def, e.rules);
      } catch {
        // a def or rules block that no longer compiles: unknown-strict, and its rules cannot be dropped silently
        out = { ...out, confirmed: false, profile: top, traits: topTraitIds, serverClass: 'irreversible', rules: BROKEN_RULES(verb) };
      }
    }
    cache.set(verb, out);
    return out;
  };
  const prov = new Map<string, ProvActionInfo>();
  for (const [verb, e] of byVerb) {
    try { if (safeConfirmed(e.def, e.review)) prov.set(verb, provenanceInfoOf(e.def, e.reg, e.review)); } catch { /* unknown: sensitive */ }
  }
  const undoByReg = new Map<Registry, UndoEngine>();
  for (const reg of new Set([...byVerb.values()].map((e) => e.reg))) undoByReg.set(reg, undoEngine({ defs: [...byVerb.values()].filter((e) => e.reg === reg).map((e) => e.def), pins, registry: reg }));
  return {
    versions: names,
    lookup,
    provenance: (op) => prov.get(op.verb),
    undo: {
      plan(op: PcaOperation, ctx: { operationId: string }) {
        const e = byVerb.get(op.verb);
        if (!e) return null;
        return undoByReg.get(e.reg)!.plan(op, ctx);
      },
    },
    floor(verb, grant, callContext) {
      try {
        const kinds = grant.caveats.filter((c): c is CaveatKind => (CAVEAT_KINDS as readonly string[]).includes(c));
        return floorDecision({ caveats: kinds, max_esc: grant.max_esc, preauth_esc: grant.preauth_esc }, { context: callContext }, lookup(verb).profile);
      } catch {
        return 'deny';
      }
    },
  };
}

/** A rules block that no longer compiles denies every call of its action (its tightening must not silently disappear). */
const BROKEN_RULES = (verb: string): CompiledRules => ({ v: 1, verb, rules_digest: '', def_digest: '', tighten: [{ id: 'rules_broken', when: { field: 'action.verb', op: 'eq', value: verb }, signal: 'deny', reason: 'the business rules of this action no longer compile' }], accumulators: [] });

function joinProfiles(a: Profile, b: Profile): Profile {
  const u = (x: readonly string[], y: readonly string[]) => [...new Set([...x, ...y])].sort();
  const rev = REV[a.rev] >= REV[b.rev] ? a.rev : b.rev;
  return { risk: Math.max(a.risk, b.risk), rev, blast_ppm: Math.max(a.blast_ppm, b.blast_ppm), esc: Math.max(a.esc, b.esc), caveats: u(a.caveats, b.caveats), context: u(a.context, b.context), prules: u(a.prules, b.prules) } as Profile;
}

/** The context keys the hosted server itself establishes for a call: it always checks revocation fresh; an idempotency key present. */
export function hostedCallContext(l: Pick<HostedLookup, 'idempotency_param'> | undefined, params: Record<string, unknown> | undefined): string[] {
  const out = ['fresh_revocation'];
  const k = l?.idempotency_param;
  if (k !== undefined && params !== undefined && typeof params[k] === 'string' && (params[k] as string).length > 0) out.push('idempotency');
  return out;
}

/** One rate limit of a compiled rules block for one caller: the durable event key it counts under, and its window. */
export interface RateKey {
  /** The accumulator id (`rate_<i>`): the count goes into `RulesInput.counts[id]`. */
  id: string;
  /** Undefined when the caller's principal / organisation is unknown: then the count is absent and the rule fires (fail closed). */
  key?: string;
  /** The sliding window, in milliseconds. */
  ms: number;
}

/**
 * The event keys of a rules block's rate limits. A key names the verb, the window and the scope id (never a rule index or the
 * rules digest), so editing or reordering the rules never resets a count.
 */
export function rateKeysOf(c: CompiledRules, who: { principal?: string; org?: string }): RateKey[] {
  return c.accumulators.map((a) => {
    const scope = a.scope === 'org' ? 'org' : 'principal';
    const id = scope === 'org' ? who.org : who.principal;
    const ms = a.win.kind === 'task' ? 0 : a.win.ms;
    return { id: a.id, ms, ...(typeof id === 'string' && id.length > 0 && ms > 0 ? { key: `${c.verb}|${ms}|${scope}:${id}` } : {}) };
  });
}
