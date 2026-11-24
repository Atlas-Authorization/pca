import { compareUtf8 } from '@atlasauth/pca';
import {
  accPost,
  accumulationParams,
  monitorState,
  monitorStates,
  type AccumulatorDecl,
  type ActionSchema,
  type IntentEvent,
  type MonitorDecl,
  type UnsignedActionSchema,
} from '@atlasauth/pca/ext/intent';
import { canonValue } from './schema';
import { cellOf, numCells, type Dim, type NumDim, type Omega, type Outcome, type VerbSpace } from './omega';

/**
 * TRAJECTORY INTENT AS ORDINARY INTENT (PCA Intent Layer v2 §2.1–2.2, §3.1; milestone V2, T10, T11, T30).
 *
 * The augmented outcome space Ω̃ adds, to every verb, one NUMERIC dimension per accumulator ψ_j (path
 * `env.acc.<id>.post`, domain {0..A_j}, cuts from every reading the compilers produced) and one CATEGORICAL dimension
 * per monitor 𝔐_k (path `env.mon.<id>.state`, its closed state set, no ⊥). So Ω̃ IS an outcome space in the sense of v1
 * §2.1: cells, Θ̃, π_n, p_n, G̃_τ, R̂ and the Intent Map format are v1's, applied to Ω̃ (T10). The learner, the grant
 * synthesiser and replay carry over unchanged; the map records nothing new beyond the dimension paths.
 *
 * lift(ξ, ω, t) = (ω, post_ψ1(ξ,ω,t), …, post_ψm(ξ,ω,t), q_𝔐1(ξ), …, q_𝔐r(ξ)): the verifier computes it (never the
 * agent) and the grant predicates read it from `env.acc` / `env.mon`. The per-step admission rule of a trajectory grant
 * G̃ is "admit ω at (ξ, t) iff lift(ξ, ω, t) ∈ G̃"; a denied attempt leaves ξ unchanged.
 */

export const ACC_DIM_PREFIX = 'env.acc.';
export const MON_DIM_PREFIX = 'env.mon.';
export const accDimPath = (id: string): string => `${ACC_DIM_PREFIX}${id}.post`;
export const monDimPath = (id: string): string => `${MON_DIM_PREFIX}${id}.state`;

/** The v2 dimension kind of a path (a naming convention over v1 dimensions; the map format is unchanged). */
export type DimKindV2 = 'param' | 'acc' | 'mon' | 'canon' | 'world' | 'rel' | 'prov' | 'class' | 'other';
export function dimKindOf(path: string): DimKindV2 {
  if (path.startsWith('action.params.')) return 'param';
  if (path.startsWith(ACC_DIM_PREFIX)) return 'acc';
  if (path.startsWith(MON_DIM_PREFIX)) return 'mon';
  if (path.startsWith('env.canon.')) return 'canon';
  if (path.startsWith('env.world.')) return 'world';
  if (path.startsWith('env.rel.')) return 'rel';
  if (path.startsWith('env.prov.')) return 'prov';
  if (path.startsWith('env.class.')) return 'class';
  return 'other';
}

/** Ψ: the session's accumulators and monitors (as fixed in the session root S). */
export interface Psi {
  accumulators: AccumulatorDecl[];
  monitors: MonitorDecl[];
}

export interface AugmentOptions {
  /** Cuts per accumulator id (the readings: e.g. 40000 and 80000 for "under $400 for the two of us"). */
  cuts?: Record<string, number[]>;
  /** Which verbs get the accumulator / monitor dimensions: every verb (spec default) or only the verbs ψ selects. */
  scope?: 'all' | 'selected';
  schema?: Pick<ActionSchema | UnsignedActionSchema, 'verbs'>;
}

/** Ω̃ from Ω and Ψ (wallet-held accumulators, e.g. the question cap, are not dimensions). */
export function augmentOmega(omega: Omega, psi: Psi, opts: AugmentOptions = {}): Omega {
  const selects = (a: AccumulatorDecl, verb: string): boolean => {
    if (a.sel.verbs?.includes(verb)) return true;
    if (a.sel.accumulates_into !== undefined) {
      const v = opts.schema?.verbs.find((x) => x.verb === verb);
      return !!v && accumulationParams(v, a.sel.accumulates_into).length > 0;
    }
    return false;
  };
  return {
    v: 1,
    approximate: [...omega.approximate],
    verbs: omega.verbs.map((vs) => {
      const extra: Dim[] = [];
      for (const a of psi.accumulators) {
        if (a.holder.kind === 'wallet') continue;
        if (opts.scope === 'selected' && !selects(a, vs.verb)) continue;
        if (a.domain_max === undefined) throw new Error(`augmentOmega: accumulator '${a.id}' needs domain_max (A_ψ) to be a dimension of Ω̃`);
        const cuts = [...new Set(opts.cuts?.[a.id] ?? [])].filter((c) => Number.isSafeInteger(c) && c >= 0 && c <= a.domain_max!).sort((x, y) => x - y);
        const d: NumDim = { kind: 'num', path: accDimPath(a.id), lo: 0, hi: a.domain_max, cuts, dist: 'loguniform' };
        extra.push(d);
      }
      for (const m of psi.monitors) {
        if (opts.scope === 'selected' && !(m.q ? predicateVerbs(m.q).includes(vs.verb) || predicateVerbs(m.q).includes('*') : true)) continue;
        extra.push({ kind: 'cat', path: monDimPath(m.id), values: monitorStates(m).map((value) => ({ kind: 'exact' as const, value })) });
      }
      const dims = [...vs.dims.filter((d) => dimKindOf(d.path) !== 'acc' && dimKindOf(d.path) !== 'mon'), ...extra].sort((a, b) => compareUtf8(a.path, b.path));
      return { ...vs, dims };
    }),
  };
}

const predicateVerbs = (p: { verb: string | string[] }): string[] => (Array.isArray(p.verb) ? p.verb : [p.verb]);

/** A concrete candidate action (the plaintext the verifier sees). */
export interface CandidateAction {
  verb: string;
  resource: string;
  params: Record<string, unknown>;
  t: number;
}

/**
 * lift(ξ, ω, t) as an Outcome of Ω̃: the verb's dimensions read from the action (raw params, canonical projections) and
 * the accumulator post values and monitor states computed from the history. Null when the verb is not in Ω̃.
 */
export function liftAction(omegaTilde: Omega, psi: Psi, history: readonly IntentEvent[], cand: CandidateAction, schema?: Pick<ActionSchema | UnsignedActionSchema, 'verbs'>): Outcome | null {
  const vs = omegaTilde.verbs.find((v) => v.verb === cand.verb);
  if (!vs) return null;
  const decl = schema?.verbs.find((v) => v.verb === cand.verb);
  const values: Record<string, number | string> = {};
  for (const d of vs.dims) {
    const k = dimKindOf(d.path);
    if (k === 'param') {
      const name = d.path.slice('action.params.'.length);
      const x = Object.prototype.hasOwnProperty.call(cand.params, name) ? Object.getOwnPropertyDescriptor(cand.params, name)?.value : undefined;
      if (typeof x === 'number' || typeof x === 'string') values[d.path] = x;
    } else if (k === 'canon') {
      const name = d.path.slice('env.canon.'.length);
      const pd = decl?.params['action.params.' + name];
      if (pd && Object.prototype.hasOwnProperty.call(cand.params, name)) values[d.path] = canonValue(pd, Object.getOwnPropertyDescriptor(cand.params, name)?.value);
    } else if (k === 'acc') {
      const id = d.path.slice(ACC_DIM_PREFIX.length, -'.post'.length);
      const a = psi.accumulators.find((x) => x.id === id);
      if (a) values[d.path] = accPost(a, history, cand, schema);
    } else if (k === 'mon') {
      const id = d.path.slice(MON_DIM_PREFIX.length, -'.state'.length);
      const m = psi.monitors.find((x) => x.id === id);
      if (m) values[d.path] = monitorState(m, history);
    } else if (d.path === 'action.resource') values[d.path] = cand.resource;
  }
  return { verb: cand.verb, values };
}

/** The per-dimension cell of lift(ξ, ω, t), or null when it lies outside Ω̃ (⊠: fail closed). */
export function liftedCell(omegaTilde: Omega, o: Outcome): { vs: VerbSpace; cell: number[] } | null {
  const vs = omegaTilde.verbs.find((v) => v.verb === o.verb);
  if (!vs) return null;
  const cell = cellOf(vs, o);
  return cell ? { vs, cell } : null;
}

/**
 * The trajectory-grant step rule (spec §2.2): admit ω at (ξ, t) iff lift(ξ, ω, t) lies in a cell `inGrant` accepts.
 * Returns the new history (ξ extended by a `reserved` event) on admission, the unchanged one otherwise.
 */
export function stepTrajectory(
  omegaTilde: Omega,
  psi: Psi,
  history: readonly IntentEvent[],
  cand: CandidateAction & { id: string },
  inGrant: (verb: string, cell: number[]) => boolean,
  schema?: Pick<ActionSchema | UnsignedActionSchema, 'verbs'>,
): { admitted: boolean; history: IntentEvent[]; lifted: Outcome | null } {
  const lifted = liftAction(omegaTilde, psi, history, cand, schema);
  const c = lifted ? liftedCell(omegaTilde, lifted) : null;
  const ok = c !== null && inGrant(cand.verb, c.cell);
  return { admitted: ok, history: ok ? [...history, { id: cand.id, verb: cand.verb, resource: cand.resource, params: cand.params, t: cand.t, status: 'reserved' }] : [...history], lifted };
}

// ---- the wallet's default Ψ (§3.1 step 1 (ii)/(iii), the money floor) ------------------------------------------

export interface DefaultPsiOptions {
  /** A_ψ for every spend accumulator (in the unit's minor units). */
  spendDomainMax: number;
  /** The per-session question cap q_max (default 6, §3.4). */
  questionCap?: number;
  holder?: AccumulatorDecl['holder'];
}

const sanitize = (u: string) => u.replace(/[^A-Za-z0-9_]/g, '_').slice(0, 58);

/**
 * The accumulators the wallet always adds: a per-task `spend` sum for every accumulation unit any verb feeds
 * (`accumulates_into`, which makes SEL hold across verbs), a per-verb spend sum for every `money.amount` parameter the
 * site forgot to tag (the wallet floor), and the wallet-held question counter.
 */
export function defaultAccumulators(schema: Pick<ActionSchema | UnsignedActionSchema, 'verbs'>, o: DefaultPsiOptions): AccumulatorDecl[] {
  const holder = o.holder ?? { kind: 'site_local' as const };
  const units = new Set<string>();
  const untagged: { verb: string; path: string }[] = [];
  for (const v of schema.verbs) {
    for (const [path, d] of Object.entries(v.params)) {
      (d.accumulates_into ?? []).forEach((u) => units.add(u));
      if (d.type === 'integer' && d.semantic === 'money.amount' && !(d.accumulates_into ?? []).length) untagged.push({ verb: v.verb, path });
    }
  }
  const out: AccumulatorDecl[] = [];
  for (const u of [...units].sort(compareUtf8)) {
    out.push({ id: `spend_${sanitize(u)}`, agg: 'sum', unit: u, sel: { accumulates_into: u }, win: { kind: 'task' }, key: null, domain_max: o.spendDomainMax, holder });
  }
  for (const { verb, path } of untagged.sort((a, b) => compareUtf8(a.verb + a.path, b.verb + b.path))) {
    out.push({ id: `spend_${sanitize(verb)}_${sanitize(path.slice('action.params.'.length))}`.slice(0, 64), agg: 'sum', val: path, sel: { verbs: [verb] }, win: { kind: 'task' }, key: null, domain_max: o.spendDomainMax, holder });
  }
  out.push({ id: 'questions', agg: 'count', sel: { event: 'intent_required' }, win: { kind: 'task' }, key: null, cap: o.questionCap ?? 6, holder: { kind: 'wallet' } });
  return out;
}

// ---- rendering an accumulator cell (§3.1 step 2) --------------------------------------------------------------

/**
 * The fact line for an accumulator dimension of a cell: "brings this trip's total to between X and Y (this action: Z)".
 * `fmt` renders an amount in the unit (default: the integer).
 */
export function describeAccCell(d: NumDim, cellIndex: number, label: string, thisAction?: number, fmt: (x: number) => string = String): string {
  const c = numCells(d)[cellIndex];
  if (!c) throw new Error('describeAccCell: no such cell');
  const range = c.lo === c.hi ? `exactly ${fmt(c.lo)}` : `between ${fmt(c.lo)} and ${fmt(c.hi)}`;
  return `${label}: ${range}${thisAction !== undefined ? ` (this action: ${fmt(thisAction)})` : ''}`;
}

/** T29: the per-session harm range of a trajectory Monte Carlo estimate is [0, L_max · H_max]. */
export function trajectoryHarmRange(maxSessionLength: number, harmMax: number): number {
  if (!(Number.isSafeInteger(maxSessionLength) && maxSessionLength >= 0) || !(harmMax >= 0)) throw new Error('trajectoryHarmRange: bad arguments');
  return maxSessionLength * harmMax;
}
