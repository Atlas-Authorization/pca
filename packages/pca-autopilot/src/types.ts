import type { Caveat, Predicate, RiskPolicy } from '@atlasauth/pca';

/** Where a trace came from. */
export type TraceSource = 'receipt' | 'otel' | 'jsonl';

/** One observed action, normalized. Parameters are flat primitives only; anything else is dropped at ingest. */
export interface Trace {
  /** Stable id of the (tenant, verb, resource, outcome) group: what a reviewer confirms or refuses. */
  id: string;
  /** Epoch ms. */
  at: number;
  verb: string;
  resource: string;
  params: Record<string, string | number | boolean>;
  outcome: 'allow' | 'deny';
  tenant?: string;
  actor?: string;
  source: TraceSource;
  /** Why this action needs an explicit per-item confirmation before it can shape authority (empty: it does not). */
  sensitive: string[];
}

export interface Rejected {
  /** 0-based line or element index in the input. */
  index: number;
  reason: string;
}

export interface TraceSet {
  v: 1;
  traces: Trace[];
  rejected: Rejected[];
  /** Records dropped because the input exceeded `maxTraces`. */
  truncated: number;
  /** Digest of the normalized traces (order-independent input, deterministic output). */
  digest: string;
}

export interface IngestOptions {
  /** Hard cap on accepted records (flood guard). Default 100000. */
  maxTraces?: number;
  /** Verb substrings that always need confirmation. Default: the policy linter's dangerous-verb list. */
  dangerousVerbs?: readonly string[];
  /** When given, an action by any other actor needs confirmation. */
  trustedActors?: readonly string[];
  /** Resource regexes (case-insensitive source strings) that need confirmation, added to the built-in secret-like list. */
  sensitiveResources?: readonly string[];
  /** Receipt logs: refuse a log whose hash chain is broken (default true). */
  requireIntactChain?: boolean;
}

export interface SynthOptions {
  /** Tenant to synthesize for. Required when the traces span more than one tenant; never merged across tenants. */
  tenant?: string;
  /** Headroom on numeric caps and the rate, as a fraction of the observed maximum (0 = exact). Default 0.2, max 10. */
  margin?: number;
  /** Distinct siblings needed before the last path segment is generalized to `parent/*`. Default 3. */
  minDistinct?: number;
  /** A string parameter with at most this many distinct values is pinned to them. Default 5. */
  maxEnum?: number;
  /** Rate window in seconds. Default 3600. */
  windowSecs?: number;
  /** Grant lifetime from `now`. Default 30 days. */
  ttlMs?: number;
  /** Trace ids (from `heldBack`) the reviewer explicitly confirms. Anything else sensitive stays out. */
  confirmed?: readonly string[];
  /** Clock. Pass it for a byte-reproducible proposal. */
  now?: number;
  /** Refuse (rather than emit) a policy with more rules than this. Default 200. */
  maxRules?: number;
}

/** The documented generalization ladder. A rule never sits above the rung that produced it. */
export const GENERALIZATION_LADDER = [
  { rung: 0, name: 'exact', admits: 'only the observed resource' },
  { rung: 1, name: 'sibling-wildcard', admits: 'every resource one level below the shared parent (and, because the matcher is a prefix, anything deeper under it)' },
] as const;

export interface RuleExplanation {
  verb: string;
  resource: string;
  rung: 0 | 1;
  observed: number;
  observedResources: string[];
  why: string;
  /** One line per parameter bound (or left free, with the reason). */
  params: string[];
}

export interface HeldItem {
  id: string;
  verb: string;
  resource: string;
  count: number;
  reasons: string[];
  /** `blocked` = the enforcer denied it while observing; `sensitive` = a heuristic flagged it. */
  kind: 'sensitive' | 'blocked';
}

export interface Proposal {
  v: 1;
  kind: 'pca-autopilot-proposal';
  tenant?: string;
  policy: { predicates: Predicate[]; caveats: Caveat[] };
  riskPolicy: RiskPolicy;
  margin: number;
  createdAt: number;
  basis: { traceSetDigest: string; included: number; from: number; to: number };
  rules: RuleExplanation[];
  /** Sensitive or blocked actions that did NOT shape this proposal. */
  heldBack: HeldItem[];
  /** Sensitive actions that DID, because the reviewer named them. The approval must repeat exactly this list. */
  confirmedSensitive: string[];
  notes: string[];
  /** Blocked (denied while observing) action groups this amendment admits, by trace id. Empty for a first proposal. */
  admitDenied: string[];
  /** Digest of the proposal this one amends or tightens. */
  amends?: string;
  digest: string;
}
