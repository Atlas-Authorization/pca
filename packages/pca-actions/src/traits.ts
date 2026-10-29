// traits.ts - the trait algebra (docs/pca/specs/action-kit.md section 3): Profile lattice, trait registry, closure,
// floors, FloorDecision. Pure integer-and-set arithmetic, no imports beyond ./def, so every language ports it in a few lines.
//
// Profile order p <= q iff componentwise <= (risk, rev, blast_ppm, esc) and subset (caveats, context, prules).
// Join is componentwise max / union. Everything below is monotone, which is what theorems T1..T7 rest on
// (formal/dafny/TraitExpand.dfy, formal/intent/lean/PcaIntent/TraitAlg.lean).

import {
  ActionKitError, CAVEAT_KINDS, CONTEXT_KEYS, MAX_REGISTRY_TRAITS, MAX_TRAIT_IMPLIES_DEPTH, PARAM_RULE_IDS, PPM_MAX, REV_RANK, REVERSIBILITY, TAINT_CONTEXT_RE, TRAIT_ID_RE,
  type CaveatKind, type ContextKey, type ParamRuleId, type Rev, type TraitId,
} from './def';

export const RISK_MAX = 3;
export const ESC_MAX = 3;
/** Escalation tiers: auto < confirm < cosign < stepup. */
export const ESC_TIERS = ['auto', 'confirm', 'cosign', 'stepup'] as const;
export const RISK_NAMES = ['low', 'elevated', 'high', 'critical'] as const;

export interface Profile {
  /** 0..3: low < elevated < high < critical. */
  risk: number;
  rev: Rev;
  /** Minimum blast, parts per million (0..1_000_000). */
  blast_ppm: number;
  /** Minimum escalation tier, 0..3. */
  esc: number;
  /** Sorted, distinct. */
  caveats: CaveatKind[];
  context: ContextKey[];
  prules: ParamRuleId[];
}

const uniqSorted = <T extends string>(xs: readonly T[]): T[] => [...new Set(xs)].sort() as T[];
const union = <T extends string>(a: readonly T[], b: readonly T[]): T[] => uniqSorted([...a, ...b]);
const subset = (a: readonly string[], b: readonly string[]): boolean => a.every((x) => b.includes(x));

/** The bottom element: no restriction. */
export const BOTTOM: Profile = Object.freeze({ risk: 0, rev: 'reversible', blast_ppm: 0, esc: 0, caveats: [], context: [], prules: [] }) as Profile;

/** Build a canonical profile (sorted, distinct sets) from a partial one. Does not validate; see {@link profileError}. */
export function profile(p: Partial<Profile> = {}): Profile {
  return {
    risk: p.risk ?? 0,
    rev: p.rev ?? 'reversible',
    blast_ppm: p.blast_ppm ?? 0,
    esc: p.esc ?? 0,
    caveats: uniqSorted(p.caveats ?? []),
    context: uniqSorted(p.context ?? []),
    prules: uniqSorted(p.prules ?? []),
  };
}

const isIntIn = (x: unknown, lo: number, hi: number): x is number => typeof x === 'number' && Number.isSafeInteger(x) && x >= lo && x <= hi;
export const isContextKey = (k: unknown): k is ContextKey =>
  typeof k === 'string' && ((CONTEXT_KEYS as readonly string[]).includes(k) || TAINT_CONTEXT_RE.test(k));

/** Null if `p` is a well-formed canonical profile, else the reason. */
export function profileError(p: unknown): string | null {
  if (p === null || typeof p !== 'object' || Array.isArray(p)) return 'profile must be an object';
  const o = p as Record<string, unknown>;
  const keys = Object.keys(o);
  for (const k of keys) if (!['risk', 'rev', 'blast_ppm', 'esc', 'caveats', 'context', 'prules'].includes(k)) return `profile: unknown member '${k}'`;
  if (!isIntIn(o.risk, 0, RISK_MAX)) return 'profile.risk must be an integer in 0..3';
  if (!(REVERSIBILITY as readonly unknown[]).includes(o.rev)) return 'profile.rev is not a reversibility class';
  if (!isIntIn(o.blast_ppm, 0, PPM_MAX)) return 'profile.blast_ppm must be an integer in 0..1000000';
  if (!isIntIn(o.esc, 0, ESC_MAX)) return 'profile.esc must be an integer in 0..3';
  const sets: [string, (x: unknown) => boolean][] = [
    ['caveats', (x) => (CAVEAT_KINDS as readonly unknown[]).includes(x)],
    ['context', isContextKey],
    ['prules', (x) => (PARAM_RULE_IDS as readonly unknown[]).includes(x)],
  ];
  for (const [name, ok] of sets) {
    const a = o[name];
    if (!Array.isArray(a) || a.length > 64 || !a.every(ok)) return `profile.${name} must be an array of known ${name} entries`;
    for (let i = 1; i < a.length; i++) if (!((a[i - 1] as string) < (a[i] as string))) return `profile.${name} must be sorted and distinct`;
  }
  return null;
}

/** Join (least upper bound). */
export function join(p: Profile, q: Profile): Profile {
  return {
    risk: Math.max(p.risk, q.risk),
    rev: REV_RANK[p.rev] >= REV_RANK[q.rev] ? p.rev : q.rev,
    blast_ppm: Math.max(p.blast_ppm, q.blast_ppm),
    esc: Math.max(p.esc, q.esc),
    caveats: union(p.caveats, q.caveats),
    context: union(p.context, q.context),
    prules: union(p.prules, q.prules),
  };
}

export const joinAll = (ps: readonly Profile[]): Profile => ps.reduce(join, BOTTOM);

/** p <= q in the profile order. */
export function leq(p: Profile, q: Profile): boolean {
  return (
    p.risk <= q.risk && REV_RANK[p.rev] <= REV_RANK[q.rev] && p.blast_ppm <= q.blast_ppm && p.esc <= q.esc &&
    subset(p.caveats, q.caveats) && subset(p.context, q.context) && subset(p.prules, q.prules)
  );
}

export const profileEq = (p: Profile, q: Profile): boolean => leq(p, q) && leq(q, p);

// ---- trait registry --------------------------------------------------------------------------------------------------

export interface TraitDef {
  /** `pca.<name>` (core, reserved) or `<ns>.<name>`. */
  id: TraitId;
  /** DAG, depth <= 8. */
  implies: TraitId[];
  floor: Profile;
  /** Deterministic phrase shown on the policy card. */
  card_phrase: string;
  /** Importer heuristic ids that propose this trait (A3). */
  suggest?: string[];
}

export const CORE_NAMESPACE = 'pca.';

export interface Registry {
  readonly traits: ReadonlyMap<TraitId, TraitDef>;
}

/**
 * Null if `defs` form a valid registry, else the first reason. Rules: ids well formed and distinct; `pca.` ids only when
 * `opts.core`; every `implies` names a trait of the registry; no cycle; implies depth <= 8; every floor well formed; and
 * T5: `floor(t) >= join of floor(u)` for all u in implies(t) (a trait can only extend what it implies).
 */
export function registryError(defs: readonly TraitDef[], opts: { core?: boolean } = {}): string | null {
  if (!Array.isArray(defs) || defs.length > MAX_REGISTRY_TRAITS) return `a registry holds at most ${MAX_REGISTRY_TRAITS} traits`;
  const by = new Map<string, TraitDef>();
  for (const t of defs) {
    if (t === null || typeof t !== 'object') return 'trait must be an object';
    if (typeof t.id !== 'string' || !TRAIT_ID_RE.test(t.id)) return `trait id '${String(t.id)}' is malformed`;
    if (t.id.startsWith(CORE_NAMESPACE) && !opts.core) return `trait '${t.id}': the pca. namespace is reserved for core traits`;
    if (by.has(t.id)) return `trait '${t.id}' is defined twice`;
    if (!Array.isArray(t.implies) || t.implies.length > 8 || new Set(t.implies).size !== t.implies.length || t.implies.some((u: unknown) => typeof u !== 'string')) return `trait '${t.id}': implies must be up to 8 distinct trait ids`;
    const pe = profileError(t.floor);
    if (pe) return `trait '${t.id}': ${pe}`;
    if (typeof t.card_phrase !== 'string' || t.card_phrase.length === 0 || t.card_phrase.length > 120) return `trait '${t.id}': card_phrase must be a non-empty string up to 120 characters`;
    by.set(t.id, t);
  }
  // implies must resolve, T5, then cycle/depth.
  for (const t of defs) {
    for (const u of t.implies) {
      const ud = by.get(u);
      if (!ud) return `trait '${t.id}' implies unknown trait '${u}'`;
      if (!leq(ud.floor, t.floor)) return `trait '${t.id}': floor is below the floor of implied '${u}' (a trait may only extend what it implies)`;
    }
  }
  const depth = new Map<string, number>();
  const visiting = new Set<string>();
  const walk = (id: string): number => {
    const known = depth.get(id);
    if (known !== undefined) return known;
    if (visiting.has(id)) return -1;
    visiting.add(id);
    let d = 1;
    for (const u of by.get(id)!.implies) {
      const du = walk(u);
      if (du < 0) return -1;
      d = Math.max(d, du + 1);
    }
    visiting.delete(id);
    depth.set(id, d);
    return d;
  };
  for (const t of defs) {
    const d = walk(t.id);
    if (d < 0) return `trait '${t.id}': implies cycle`;
    if (d > MAX_TRAIT_IMPLIES_DEPTH) return `trait '${t.id}': implies depth ${d} exceeds ${MAX_TRAIT_IMPLIES_DEPTH}`;
  }
  return null;
}

/** Build a registry; throws {@link ActionKitError} `bad_registry` when {@link registryError} is non-null. */
export function buildRegistry(defs: readonly TraitDef[], opts: { core?: boolean } = {}): Registry {
  const e = registryError(defs, opts);
  if (e) throw new ActionKitError('bad_registry', e);
  return { traits: new Map(defs.map((t) => [t.id, t])) };
}

/** Core registry extended with custom traits (which must not use `pca.` and must extend what they imply). */
export function extendRegistry(base: Registry, custom: readonly TraitDef[]): Registry {
  const all = [...base.traits.values()];
  const coreIds = new Set(all.map((t) => t.id));
  for (const c of custom) if (coreIds.has(c.id) || c.id.startsWith(CORE_NAMESPACE)) throw new ActionKitError('bad_registry', `custom trait '${c.id}' may not redefine a core trait`);
  const e = registryError([...all, ...custom], { core: true });
  if (e) throw new ActionKitError('bad_registry', e);
  return { traits: new Map([...all, ...custom].map((t) => [t.id, t])) };
}

/** cl_R(S): the closure of a set of trait ids under `implies`, sorted. Throws `unknown_trait`. */
export function closure(reg: Registry, ids: readonly TraitId[]): TraitId[] {
  const seen = new Set<string>();
  const stack = [...ids];
  while (stack.length > 0) {
    const id = stack.pop()!;
    if (seen.has(id)) continue;
    const t = reg.traits.get(id);
    if (!t) throw new ActionKitError('unknown_trait', `unknown trait '${id}'`);
    seen.add(id);
    for (const u of t.implies) stack.push(u);
  }
  return [...seen].sort();
}

/**
 * The TOP element of the trait lattice of a registry: every trait it defines. A def without a valid human confirmation has
 * exactly this effective trait set ("unconfirmed means maximally dangerous"), so the classifier can never lower it.
 * Sorted. Contains every high-risk core trait and `pca.unreviewed`, and every custom trait of the registry.
 */
export const topTraits = (reg: Registry): TraitId[] => [...reg.traits.keys()].sort();

/** F_R(S): the join of the floors of the closure of S (empty = bottom). */
export function floorOf(reg: Registry, ids: readonly TraitId[]): Profile {
  return joinAll(closure(reg, ids).map((id) => reg.traits.get(id)!.floor));
}

// ---- floor decision (rule 22) ----------------------------------------------------------------------------------------

export type Decision = 'deny' | 'escalate' | 'allow';
export const DECISION_RANK: Readonly<Record<Decision, number>> = { deny: 0, escalate: 1, allow: 2 };

/** What the stored grant provides for the floor check. */
export interface GrantFacts {
  /** Caveat kinds the grant carries (bounds it already imposes). */
  caveats: readonly CaveatKind[];
  /** Highest escalation tier the grant authorizes at all (a tier above it is a terminal deny). */
  max_esc: number;
  /** Highest tier the grant pre-authorizes without asking (a tier above it, up to max_esc, escalates). */
  preauth_esc: number;
}
/** What the verifier observed about the call (never agent claims). */
export interface CallFacts {
  context: readonly ContextKey[];
}

/**
 * FloorDecision(G, call, rho): deny if rho.esc exceeds G.max_esc; else escalate if a required caveat is missing from G, a
 * required context key is missing from the call, or rho.esc exceeds G.preauth_esc; else allow. Antitone in rho (T4).
 */
export function floorDecision(g: GrantFacts, call: CallFacts, rho: Profile): Decision {
  if (rho.esc > g.max_esc) return 'deny';
  if (!subset(rho.caveats, g.caveats) || !subset(rho.context, call.context) || rho.esc > g.preauth_esc) return 'escalate';
  return 'allow';
}

/** Meet in the order deny < escalate < allow (the final decision is the meet of every component). */
export function meetDecision(a: Decision, b: Decision): Decision {
  return DECISION_RANK[a] <= DECISION_RANK[b] ? a : b;
}
