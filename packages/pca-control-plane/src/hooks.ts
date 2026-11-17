/**
 * Verifier-side consumption. Nothing here adds an enforcement path: it turns verified directives into the inputs the
 * existing hooks already take (a tightened risk policy, revocation-registry entries, Shared Signals events).
 */
import type { RiskPolicy } from '@atlasauth/pca';
import { assertNoWiden } from '@atlasauth/pca/ext/research';
import type { RevocationInput, RevocationKey } from '@atlasauth/pca-revoke';
import { EVENT_TYPES, type CaepRiskLevelChangeEvent, type SetEvents } from '@atlasauth/pca-signals';
import { verifyDirective } from './directive';
import type { Directive } from './types';

/** What applies to one agent (or session, grant) right now. */
export interface Effective {
  frozen: boolean;
  /** Id of the freeze directive. */
  frozen_by?: string;
  kappa_mult: number;
  theta_mult: number;
  budget_factor: number;
  step_up: boolean;
  /** Ids of the verified, unexpired directives that produced this. */
  directives: string[];
}

export const NO_EFFECT: Effective = Object.freeze({ frozen: false, kappa_mult: 1, theta_mult: 1, budget_factor: 1, step_up: false, directives: [] as string[] }) as Effective;

/**
 * Combine directives into the strictest reading: highest kappa, lowest theta, smallest budget factor, any step-up or
 * freeze. A directive that does not verify (wrong signer, bad signature, expired, malformed) is skipped and counted:
 * skipping can only mean LESS tightening than the control plane meant, never a loosening of anything already in force.
 */
export function effectiveOf(directives: readonly Directive[], o: { signer: string | readonly string[]; now: number }): { effective: Effective; invalid: number } {
  const e: Effective = { frozen: false, kappa_mult: 1, theta_mult: 1, budget_factor: 1, step_up: false, directives: [] };
  let invalid = 0;
  const signers = typeof o.signer === 'string' ? [o.signer] : o.signer;
  for (const d of directives) {
    if (!signers.some((signer) => verifyDirective(d, { signer, now: o.now }).ok)) {
      invalid++;
      continue;
    }
    e.directives.push(d.id);
    if (d.kind === 'freeze') {
      e.frozen = true;
      e.frozen_by ??= d.id;
    } else if (d.kind === 'tighten') {
      e.kappa_mult = Math.max(e.kappa_mult, d.params.kappa_mult!);
      e.theta_mult = Math.min(e.theta_mult, d.params.theta_mult!);
    } else if (d.kind === 'shrink_budget') e.budget_factor = Math.min(e.budget_factor, d.params.factor!);
    else e.step_up = true;
  }
  return { effective: e, invalid };
}

const clamp01 = (x: number) => Math.max(0, Math.min(1, x));

/** The risk policy to enforce: the base, tightened. Throws if the result would widen the base (it cannot, by construction). */
export function tightenPolicy(base: RiskPolicy, eff: Effective): RiskPolicy {
  const t = eff.step_up ? 0 : eff.theta_mult;
  const out: RiskPolicy = { ...base, weights: { ...base.weights }, kappa: base.kappa * eff.kappa_mult, theta1: clamp01(base.theta1 * t), theta2: clamp01(base.theta2 * t) };
  assertNoWiden(base, out);
  return out;
}

/** The budget ceiling or balance to enforce: never above the input. */
export const shrinkBudget = (budget: number, eff: Effective): number => (Number.isFinite(budget) ? Math.max(0, budget * eff.budget_factor) : 0);

/** Registry entries for a freeze: an agent freeze revokes the agent's holder key. Other kinds revoke nothing here (see {@link toSignalEvents}). */
export function toRevocationInputs(d: Directive): RevocationInput[] {
  if (d.kind !== 'freeze' || d.subject.kind !== 'agent') return [];
  return [{ kind: 'holder', value: d.subject.id, reason: `control plane freeze: ${d.reason}`.slice(0, 256), revokedAt: d.iat }];
}
/** The registry key a signed human unfreeze removes. */
export function toRevocationKey(d: Directive): RevocationKey | undefined {
  return d.kind === 'freeze' && d.subject.kind === 'agent' ? { kind: 'holder', value: d.subject.id } : undefined;
}

/** Apply every active agent freeze to a registry (idempotent). Pass the result of `engine.activeDirectives()`. */
export async function syncRegistry(registry: { revoke(i: RevocationInput): Promise<unknown> }, directives: readonly Directive[]): Promise<number> {
  let n = 0;
  for (const d of directives) {
    for (const i of toRevocationInputs(d)) {
      await registry.revoke(i);
      n++;
    }
  }
  return n;
}

/**
 * The Shared Signals event for a signed human lift. It is informational: a SET never un-revokes (`applySET` is monotone), so a
 * receiver that sees it re-reads the control-plane state instead of dropping a revocation on its own.
 */
export function toLiftSignalEvents(d: Directive, atMs: number): SetEvents {
  const subject = { format: 'opaque', id: d.subject.id };
  return { [EVENT_TYPES.riskLevelChange]: { principal: d.subject.kind === 'fleet' ? 'TENANT' : d.subject.kind === 'session' ? 'SESSION' : 'DEVICE', current_level: 'LOW', previous_level: 'HIGH', risk_reason: `lifted: ${d.kind}`, event_timestamp: Math.floor(atMs / 1000), subject } };
}

/**
 * The Shared Signals events for a directive, ready for `buildSET({ events, ... })`:
 * agent freeze -> kill-switch, grant freeze -> grant-revoked, session freeze -> intent-revoked, everything else a
 * risk-level change (a fleet freeze is a HIGH tenant risk level; consumers read `effectiveOf` for the freeze itself).
 */
export function toSignalEvents(d: Directive, atMs: number = d.iat): SetEvents {
  const ts = Math.floor(atMs / 1000);
  const subject = { format: 'opaque', id: d.subject.id };
  const reason = d.reason.slice(0, 256);
  if (d.kind === 'freeze') {
    if (d.subject.kind === 'agent') return { [EVENT_TYPES.killSwitch]: { agent: d.subject.id, reason, event_timestamp: ts, subject } };
    if (d.subject.kind === 'grant') return { [EVENT_TYPES.grantRevoked]: { grant_ref: d.subject.id, reason, event_timestamp: ts, subject } };
    if (d.subject.kind === 'session') return { [EVENT_TYPES.intentRevoked]: { ids: [`pca-intent:session:${d.subject.id}`], session: d.subject.id, reason, event_timestamp: ts, subject } };
  }
  const level: CaepRiskLevelChangeEvent['current_level'] = d.kind === 'tighten' ? 'MEDIUM' : 'HIGH';
  return { [EVENT_TYPES.riskLevelChange]: { principal: d.subject.kind === 'fleet' ? 'TENANT' : d.subject.kind === 'session' ? 'SESSION' : 'DEVICE', current_level: level, risk_reason: `${d.kind}: ${reason}`, event_timestamp: ts, subject } };
}
