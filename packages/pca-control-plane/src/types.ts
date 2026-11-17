import type { ImmuneState } from '@atlasauth/pca/ext/research';

export type SubjectKind = 'agent' | 'session' | 'grant' | 'fleet';
/** What a directive acts on. The fleet subject has the fixed id `*`. */
export interface Subject {
  kind: SubjectKind;
  id: string;
}
export const FLEET: Subject = Object.freeze({ kind: 'fleet', id: '*' }) as Subject;

export type Outcome = 'auto' | 'step_up' | 'deny' | 'executed';
export const OUTCOMES: readonly Outcome[] = ['auto', 'step_up', 'deny', 'executed'];

/** One action and the verdict it got, as a gateway or resource server reports it. `r` is the action's risk in [0,1]. */
export interface ControlEvent {
  /** Unique per source (a duplicate id inside one batch is dropped). */
  id: string;
  at: number;
  agent: string;
  session?: string;
  grant?: string;
  verb: string;
  resource: string;
  outcome: Outcome;
  r: number;
  /** Which mode decided it, when the reporter says (the guided setup uses it to see the first enforced decision). */
  mode?: 'observe' | 'enforce';
  /**
   * The parameters a proxy recorded for this receipt (safe integers, booleans, short enum strings), with the digest the receipt
   * carries for them. The control plane does not use it; the guided setup checks the binding before it learns an amount cap.
   */
  observed?: { seq: number; params: Record<string, string | number | boolean>; omitted: string[]; digest: string };
}

export type DirectiveKind = 'tighten' | 'shrink_budget' | 'require_step_up' | 'freeze';
export type DirectiveCause = 'auto' | 'operator';

export interface DirectiveParams {
  /** tighten: multiplies kappa (>= 1). */
  kappa_mult?: number;
  /** tighten: multiplies theta1 and theta2 (in (0, 1]). */
  theta_mult?: number;
  /** shrink_budget: multiplies the autonomous budget ceiling and remaining balance (in [0, 1)). */
  factor?: number;
}

/** The signed part of a directive. */
export interface DirectiveClaim {
  v: 1;
  kind: DirectiveKind;
  subject: Subject;
  params: DirectiveParams;
  cause: DirectiveCause;
  /** Who asked (an operator id) or which rule fired. */
  by: string;
  reason: string;
  /** Digest of the evidence the decision was derived from (an agent record, or empty for a manual directive). */
  evidence: string;
  iat: number;
  /** Required for every kind but `freeze`: a freeze lasts until a signed human lifts it. */
  exp?: number;
  /** Strictly increasing per control plane: a consumer keeps a floor and refuses anything at or below it. */
  seq: number;
  /** b64u Ed25519 key of the control plane that issued it. */
  signer: string;
}
export interface Directive extends DirectiveClaim {
  /** Content address of the claim (every field above). */
  id: string;
  sig: string;
}

export interface Lift {
  op: 'unfreeze' | 'revoke';
  at: number;
  /** b64u key of the human who signed it. */
  human: string;
  nonce: string;
  /** Digest of the signed human action, for the audit trail. */
  action: string;
}
export interface StoredDirective {
  directive: Directive;
  lift?: Lift;
}

export interface TimelineEntry {
  at: number;
  verb: string;
  resource: string;
  outcome: Outcome | 'malformed';
  r: number;
}

export interface AgentRecord {
  agent: string;
  immune: ImmuneState;
  first_seen: number;
  last_seen: number;
  actions: number;
  autos: number;
  step_ups: number;
  denies: number;
  executed: number;
  malformed: number;
  total_risk: number;
  /** Threat read after the last event (heuristic, tighten-only). */
  score: number;
  level: 'calm' | 'elevated' | 'high';
  signals: string[];
  sessions: string[];
  grants: string[];
  timeline: TimelineEntry[];
  /** Store-maintained version, for compare-and-swap. */
  ver: number;
}

export interface FleetRecord {
  immune: ImmuneState;
  agents: number;
  events: number;
  malformed: number;
  ver: number;
}
