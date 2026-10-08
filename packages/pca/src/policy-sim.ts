/**
 * Policy simulation + linting (spec Part 2.3 "authoring + the standing Policy Agent").
 *
 * Before a principal enables a grant, they want to know what it will actually DO: replay a batch of
 * historical / hypothetical actions against the compiled policy and see which auto-admit, which force a
 * human step-up, and which are denied — plus static lints that catch the classic mistakes (an
 * unbounded money verb, a wildcard resource on an irreversible action, a limit that matches nothing,
 * a budget so large it never asks a human).
 *
 * This is PURE and OFFLINE: it composes `compilePolicy` + the predicate/caveat evaluators + the trust
 * budget algebra (risk.ts). It mutates nothing, signs nothing, and reaches no network. It is a planning
 * tool — the resource server's verifier remains the authority at run time.
 */

import type { CompiledPolicy } from './facade';
import { type Catalog, DEFAULT_CATALOG } from './catalog';
import {
  type ActionContext,
  REVERSIBILITY_ORDER,
  evaluateCaveats,
  evaluatePredicates,
} from './predicates';
import { type TrustBudget, admit, cost, leak } from './risk';

// ---- simulation -----------------------------------------------------------------------------------

export interface SimAction {
  verb: string;
  resource: string;
  params?: Record<string, unknown>;
  /** Epoch ms this action occurs at (drives budget leak + rate windows). Default: ascending from `start`. */
  at?: number;
}

export type SimOutcome = 'auto' | 'step_up' | 'deny';

export interface SimResult {
  action: SimAction;
  outcome: SimOutcome;
  /** Risk tier admit() assigned (when not denied by policy). */
  t?: 1 | 2 | 3;
  /** Risk value used. */
  r: number;
  reason?: string;
  /** Trust budget remaining AFTER this action. */
  budgetAfter: number;
}

export interface SimReport {
  results: SimResult[];
  auto: number;
  stepUp: number;
  deny: number;
  /** Budget left at the end of the replay. */
  endBudget: number;
  /** Largest single-action risk seen. */
  peakRisk: number;
  /** Total risk of machine-only (auto) actions — must be ≤ bMax/κ by the safety theorem. */
  autonomousRisk: number;
}

function riskOf(policy: CompiledPolicy, catalog: Catalog, verb: string, params?: Record<string, unknown>): number {
  const spec = catalog.get(verb);
  if (policy.budgetModel === 'dollars' && spec?.amountField) {
    const amt = Number((params ?? {})[spec.amountField]);
    if (Number.isFinite(amt) && policy.riskPolicy.kappa > 0) return Math.max(0, Math.min(1, amt / policy.riskPolicy.kappa));
  }
  return Math.max(0, Math.min(1, spec ? spec.blastRadius : 0.8));
}

/**
 * Replay actions in time order against the policy, threading the trust budget exactly as the server
 * would (leak between actions; debit κ·r on every metered admit; escalate to step-up when the budget
 * cannot cover a machine-band action). Returns per-action outcomes + aggregate counts.
 */
export function simulate(
  policy: CompiledPolicy,
  actions: SimAction[],
  opts: { catalog?: Catalog; start?: number } = {},
): SimReport {
  const catalog = opts.catalog ?? DEFAULT_CATALOG;
  const start = opts.start ?? 0;
  const ordered = actions
    .map((a, i) => ({ a, at: a.at ?? start + i }))
    .sort((x, y) => x.at - y.at);

  let budget: TrustBudget = { B: policy.riskPolicy.bMax, tau: start, asOf: start };
  const recent: number[] = [];
  const results: SimResult[] = [];
  let peakRisk = 0;
  let autonomousRisk = 0;

  for (const { a, at } of ordered) {
    const spec = catalog.get(a.verb);
    const ctx: ActionContext = {
      action: { verb: a.verb, resource: a.resource, params: a.params ?? {}, reversibility_class: spec?.reversibility ?? 'irreversible' },
    };
    const r = riskOf(policy, catalog, a.verb, a.params);
    peakRisk = Math.max(peakRisk, r);

    const pred = evaluatePredicates(policy.predicates, ctx);
    const cav = pred.allowed
      ? evaluateCaveats(policy.caveats, { now: at, blastRadius: spec?.blastRadius ?? 1, reversibilityClass: spec?.reversibility ?? 'irreversible', recentActionTimes: [...recent] })
      : { ok: false, failed: [] as string[] };

    budget = leak(budget, at, policy.riskPolicy.lambda);

    if (!pred.allowed) {
      results.push({ action: a, outcome: 'deny', r, reason: pred.reason ?? 'no predicate permits this action', budgetAfter: budget.B });
      continue;
    }
    if (!cav.ok) {
      results.push({ action: a, outcome: 'deny', r, reason: `caveat(s) failed: ${cav.failed.join(', ')}`, budgetAfter: budget.B });
      continue;
    }
    const adm = admit(r, budget, policy.riskPolicy);
    if (adm.t === 1 && adm.admit) {
      budget = { ...budget, B: budget.B - cost(r, policy.riskPolicy.kappa) };
      autonomousRisk += r;
      recent.push(at);
      results.push({ action: a, outcome: 'auto', t: 1, r, budgetAfter: budget.B });
    } else {
      // t=2 (guardian auto-cosign) and t=3 (human) both surface as a step-up in the planning view.
      results.push({ action: a, outcome: 'step_up', t: adm.t, r, reason: adm.needStepUp ? `requires tier ${adm.t}` : undefined, budgetAfter: budget.B });
    }
  }

  return {
    results,
    auto: results.filter((x) => x.outcome === 'auto').length,
    stepUp: results.filter((x) => x.outcome === 'step_up').length,
    deny: results.filter((x) => x.outcome === 'deny').length,
    endBudget: budget.B,
    peakRisk,
    autonomousRisk,
  };
}

// ---- linting --------------------------------------------------------------------------------------

export interface Lint {
  level: 'error' | 'warn' | 'info';
  code: string;
  message: string;
}

const sev = (c: string): number => REVERSIBILITY_ORDER.indexOf(c as (typeof REVERSIBILITY_ORDER)[number]);

/**
 * Static lints over a compiled policy. `error` = almost certainly a mistake (e.g. a limit that matches
 * no granted action); `warn` = a real risk worth a second look; `info` = a notable but intentional
 * property. Pure.
 */
export function lintPolicy(policy: CompiledPolicy, opts: { catalog?: Catalog } = {}): Lint[] {
  const catalog = opts.catalog ?? DEFAULT_CATALOG;
  const lints: Lint[] = [];
  // A configured limit (raw key: bare action name or FQ verb) that matches no granted action — a typo.
  const grantedNames = new Set(policy.actions.flatMap((s) => [s.verb, s.action]));
  for (const key of Object.keys(policy.inputLimits)) {
    if (!grantedNames.has(key)) {
      lints.push({ level: 'error', code: 'limit-unmatched', message: `limit for '${key}' matches no granted action` });
    }
  }

  // Money / irreversible actions that are over-broad or unbounded.
  for (const spec of policy.actions) {
    const pred = policy.predicates.find((p) => p.verb === spec.verb);
    const broad = !pred?.resource || pred.resource === '*';
    if (spec.amountField && !policy.limits[spec.verb]) {
      lints.push({ level: 'warn', code: 'money-unbounded', message: `money action '${spec.verb}' has no per-call limit — spend is bounded only by the trust budget` });
    }
    if (broad && sev(spec.reversibility) >= sev('rate_limited')) {
      lints.push({ level: 'warn', code: 'broad-resource', message: `'${spec.verb}' (${spec.reversibility}) matches ANY resource — consider a resource prefix` });
    }
    if (!catalog.get(spec.verb)) {
      lints.push({ level: 'info', code: 'uncatalogued', message: `'${spec.verb}' is not in the catalog — treated conservatively (irreversible, high blast radius)` });
    }
  }

  // The budget never forces a human: all within-cap actions auto-admit (t=1). Intentional for a
  // capped autonomous agent, but worth stating.
  const { theta2, bMax, kappa } = policy.riskPolicy;
  if (theta2 >= 1) {
    const hasIrrev = policy.actions.some((s) => sev(s.reversibility) >= sev('irreversible'));
    lints.push({
      level: hasIrrev ? 'warn' : 'info',
      code: 'no-step-up-band',
      message: `theta2 ≥ 1: no action triggers a human step-up until the budget is exhausted${hasIrrev ? ' — including irreversible actions' : ''}`,
    });
  }

  // A very large autonomous bound (bMax/κ · κ = bMax in dollar model).
  if (kappa > 0 && bMax / kappa > 100) {
    lints.push({ level: 'warn', code: 'large-autonomy', message: `autonomous bound is ${Math.round(bMax / kappa)}× a max-risk action between human co-signs` });
  }

  return lints;
}
