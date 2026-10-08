/**
 * Principal's live agent console — data layer (spec Part 2.2 "what are my agents doing now, what did
 * they do, anomalies, one-click freeze"). Projects a stream of actions into a per-agent activity view
 * with a threat read (reusing the behavioral immune system), and models the kill switch.
 *
 * Pure + offline: a projection over records you feed it. The "freeze" here is a local kill-switch
 * SET the client/gateway consults before dispatching; authoritative revocation is the transparency
 * ledger's revocation epoch (server-side) — this is the fast UX layer in front of it.
 */

import { type PCActn, pcactnDigest } from './pcactn';
import { INITIAL_IMMUNE_STATE, assess, observe, type ThreatAssessment } from './immune';

export type ActivityOutcome = 'auto' | 'step_up' | 'deny' | 'executed';

export interface ActivityEvent {
  at: number;
  /** The acting agent — the leaf holder key (b64u) of the action's capability chain. */
  agent: string;
  verb: string;
  resource: string;
  outcome: ActivityOutcome;
  /** Risk the action carried. */
  r?: number;
  /** Provenance taint level the action carried (L4 lattice) — for data-flow / DLP evidence. */
  taint?: number;
  /** PCActn digest (content address) for drill-down. */
  digest?: string;
  /** Goal-lineage: the grant's signed goal commitment. */
  goalCommit?: string;
}

/** Derive an activity event from a PCActn + the verifier's outcome. */
export function eventFromPCActn(p: PCActn, outcome: ActivityOutcome, at?: number): ActivityEvent {
  const leaf = p.cap_chain[p.cap_chain.length - 1];
  return {
    at: at ?? p.iat,
    agent: leaf?.holder ?? 'unknown',
    verb: p.action.verb,
    resource: p.action.resource,
    outcome,
    r: p.risk_claim?.r,
    taint: p.provenance?.taint_level,
    digest: pcactnDigest(p),
  };
}

export interface AgentSummary {
  agent: string;
  actions: number;
  autos: number;
  stepUps: number;
  denies: number;
  executed: number;
  totalRisk: number;
  firstSeen: number;
  lastSeen: number;
  /** Current threat read for this agent (from its action history). */
  threat: ThreatAssessment;
}

export interface ConsoleView {
  agents: AgentSummary[];
  totals: { actions: number; autos: number; stepUps: number; denies: number; executed: number };
  window: { from: number; to: number };
}

/** Project a stream of activity events into a per-agent console view with a threat read. */
export function buildConsole(events: ActivityEvent[]): ConsoleView {
  const byAgent = new Map<string, ActivityEvent[]>();
  for (const e of events) {
    const arr = byAgent.get(e.agent) ?? [];
    arr.push(e);
    byAgent.set(e.agent, arr);
  }

  const agents: AgentSummary[] = [];
  for (const [agent, evs] of byAgent) {
    const sorted = [...evs].sort((a, b) => a.at - b.at);
    let immune = INITIAL_IMMUNE_STATE;
    let autos = 0, stepUps = 0, denies = 0, executed = 0, totalRisk = 0;
    for (const e of sorted) {
      const r = e.r ?? 0;
      totalRisk += r;
      if (e.outcome === 'auto') autos++;
      else if (e.outcome === 'step_up') stepUps++;
      else if (e.outcome === 'deny') denies++;
      else if (e.outcome === 'executed') executed++;
      immune = observe(immune, { r, at: e.at, stepUp: e.outcome === 'step_up', denied: e.outcome === 'deny' });
    }
    agents.push({
      agent,
      actions: sorted.length,
      autos,
      stepUps,
      denies,
      executed,
      totalRisk,
      firstSeen: sorted[0]!.at,
      lastSeen: sorted[sorted.length - 1]!.at,
      threat: assess(immune),
    });
  }
  agents.sort((a, b) => b.threat.score - a.threat.score || b.lastSeen - a.lastSeen);

  const totals = agents.reduce(
    (t, a) => ({
      actions: t.actions + a.actions,
      autos: t.autos + a.autos,
      stepUps: t.stepUps + a.stepUps,
      denies: t.denies + a.denies,
      executed: t.executed + a.executed,
    }),
    { actions: 0, autos: 0, stepUps: 0, denies: 0, executed: 0 },
  );
  const ats = events.map((e) => e.at);
  return { agents, totals, window: { from: ats.length ? Math.min(...ats) : 0, to: ats.length ? Math.max(...ats) : 0 } };
}

/** Agents whose current threat read is not calm (the console's "anomalies" panel). */
export function anomalies(view: ConsoleView): AgentSummary[] {
  return view.agents.filter((a) => a.threat.level !== 'calm');
}

// ---- freeze (the kill switch) ---------------------------------------------------------------------

export interface FreezeSet {
  /** Frozen agent ids (sorted, serializable). */
  frozen: string[];
}

export const EMPTY_FREEZE: FreezeSet = { frozen: [] };

export function freezeAgent(set: FreezeSet, agent: string): FreezeSet {
  if (set.frozen.includes(agent)) return set;
  return { frozen: [...set.frozen, agent].sort() };
}

export function unfreezeAgent(set: FreezeSet, agent: string): FreezeSet {
  return { frozen: set.frozen.filter((a) => a !== agent) };
}

export function isFrozen(set: FreezeSet, agent: string): boolean {
  return set.frozen.includes(agent);
}
