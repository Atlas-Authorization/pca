// ir.ts - the Goal IR (goal-to-decision spec, section 3). These types are the JSON form of the Dafny datatypes in
// formal/dafny/GoalIr.dfy and are normative: the Dafny parser (GoalRender.dfy, via the typed bridge in
// @atlasauth/pca-verified-core) accepts exactly the values these types describe and rejects everything else.
//
// All numbers are safe integers (no floats). A Quantity is an exact integer in the unit's minor scale: Money in minor units of
// its currency, Ratio in parts per million, Duration/Instant in milliseconds. There is no implicit unit or currency conversion.
// Objects use a discriminant `k`; every field listed is required (no optional members), so the canonical JSON of a value is unique.

/** A unit tag. Money carries its ISO-4217 style currency code (non-empty). */
export type Unit =
  | { k: 'money'; ccy: string }
  | { k: 'count' }
  | { k: 'duration' }
  | { k: 'instant' }
  | { k: 'bytes' }
  | { k: 'ratio' };

export interface Quantity { u: Unit; n: number }

/** A value: a quantity, a text/enum/id string, or (only as the right side of `in` / `nin`) a literal set. */
export type Value = { k: 'q'; q: Quantity } | { k: 's'; s: string } | { k: 'set'; items: Value[] };

/** Static types: a quantity of one unit, or text (supports only eq / ne / in / nin: no ordering, no regex). */
export type Ty = { k: 'q'; u: Unit } | { k: 's' };

export type Term =
  | { k: 'param'; path: string; ty: Ty }
  | { k: 'lit'; v: Value }
  /** The aggregate the durable store supplies for bound `bid`, of unit `u`. */
  | { k: 'hist'; bid: string; u: Unit };

export type Op = 'eq' | 'ne' | 'lt' | 'lte' | 'gt' | 'gte' | 'in' | 'nin';

export type Cond =
  | { k: 'true' }
  | { k: 'cmp'; op: Op; l: Term; r: Term }
  | { k: 'and'; a: Cond; b: Cond }
  | { k: 'or'; a: Cond; b: Cond }
  | { k: 'not'; c: Cond };

/** A conjunct of an `all_of` selector (flat: never a wildcard, never nested). */
export type ResPart =
  | { k: 'exact'; id: string }
  | { k: 'oneof'; ids: string[] }
  | { k: 'related'; rel: string; anchor: string };

/**
 * Which resources a clause names. `any` is a wildcard and is permitted on a grant only when its gid is in `Goal.wildcardAck`.
 * `all_of` (at least two parts) names the resources that satisfy EVERY part: it is how the N-version meet of two readings stays
 * narrower than both (the intersection is computed by the proved compiler, `ResolveParts` in GoalIr.dfy).
 */
export type ResSel =
  | ResPart
  | { k: 'any'; reason: string }
  | { k: 'all_of'; parts: ResPart[] };

export interface Grant { gid: string; verb: string; res: ResSel; cond: Cond }

/** A prohibition names an effect CLASS (ontology) or one verb: aliased verbs of the same class are covered (W13). */
export type ProhTarget = { k: 'verb'; verb: string } | { k: 'effect'; cls: string };
export interface Prohibit { pid: string; target: ProhTarget; res: ResSel; cond: Cond }

export type Agg = 'count' | 'sum' | 'max' | 'distinct';
export type Sel = { k: 'gids'; gids: string[] } | { k: 'effect'; cls: string };
export type Window =
  | { k: 'task' }
  | { k: 'sliding'; ms: number }
  | { k: 'period'; ms: number; t0: number }
  | { k: 'lifetime' };
export type Scope = { k: 'session' } | { k: 'principal' } | { k: 'org' } | { k: 'fleet'; agents: string[] };
export type OnExceed = 'deny' | 'escalate';

export interface Bound {
  bid: string;
  sel: Sel;
  agg: Agg;
  /** The summed / maxed term (sum, max), ignored for count; `key` names the distinct-counted param (distinct), '' otherwise. */
  value: Term;
  key: string;
  window: Window;
  scope: Scope;
  cap: Quantity;
  onExceed: OnExceed;
}

export interface Validity { notBefore: number; notAfter: number; maxIdle: number }
export interface Delegation { maxDepth: number; narrowOnly: boolean; mayTouch: string[] }

/** An unresolved ambiguity. Allowed only in a draft: a goal with holes is not signable. */
export interface Hole { hid: string; q: string; domain: string[]; affects: string[]; global: boolean }

export interface Goal {
  v: number;
  principal: string;
  ontDigest: string;
  nlDigest: string;
  sources: string[];
  /** grants, prohibits, bounds and holes are in canonical order: strictly increasing by id (code-point order). */
  grants: Grant[];
  prohibits: Prohibit[];
  bounds: Bound[];
  validity: Validity;
  deleg: Delegation;
  escalateOn: Cond[];
  wildcardAck: string[];
  holes: Hole[];
}

export interface ParamDecl { path: string; ty: Ty }
export interface VerbDecl { verb: string; cls: string; params: ParamDecl[] }
export interface RelDecl { rel: string; anchor: string; members: string[] }
/** The signed vocabulary a goal is typed against (closed world: a verb or param not declared here is Deny). */
export interface Ontology { verbs: VerbDecl[]; rels: RelDecl[] }

export interface Act {
  verb: string;
  res: string;
  /** flattened parameter paths (`a.b`) to values */
  params: Record<string, Value>;
  t: number;
  sess: string;
  prin: string;
  org: string;
  agent: string;
  /** delegation depth of the acting key (0 = the principal's own agent) */
  depth: number;
}
export interface Adm { gid: string; act: Act }
export interface Hist {
  adms: Adm[];
  /** time of the last admitted action, -1 if none */
  last: number;
  aggs: Record<string, Quantity>;
}

export type Decision = 'allow' | 'deny' | 'escalate';
/** What the decision function returns for an Allow: the grant that admitted the action and the bounds that were checked (G-T3). */
export interface Witness { gid: string; bids: string[] }

/** The lowered policy (output of the compiler): negation-normal conditions, resolved resource patterns and bound selections. */
export type NCond =
  | { k: 'true' }
  | { k: 'false' }
  | { k: 'atom'; op: Op; l: Term; r: Term }
  | { k: 'and'; a: NCond; b: NCond }
  | { k: 'or'; a: NCond; b: NCond };
export type ResPat = { k: 'star' } | { k: 'set'; ids: string[] };
export interface LPred { gid: string; verb: string; res: ResPat; cond: NCond }
export interface LProh { pid: string; verbs: string[]; res: ResPat; cond: NCond }
export interface LCeil {
  bid: string;
  selGids: string[];
  selVerbs: string[];
  agg: Agg;
  value: Term;
  key: string;
  window: Window;
  scope: Scope;
  cap: Quantity;
  onExceed: OnExceed;
}
export interface Policy {
  preds: LPred[];
  prohs: LProh[];
  ceils: LCeil[];
  escs: NCond[];
  validity: Validity;
  deleg: Delegation;
}

export type CompileResult = { ok: true; policy: Policy } | { ok: false; reasons: string[] };
