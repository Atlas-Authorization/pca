/**
 * Multi-agent session — the delegation-tree "team" view (spec Part 2.2, orchestration). A root agent
 * plus the sub-agents it delegates to all share ONE signed goal; a session groups them so a principal
 * sees the whole team under a goal, and the console can be scoped to just that team. Composes the
 * facade's sub-agent delegation + the console projection. Pure.
 */

import { b64u } from './hash';
import type { Agent } from './facade';
import { type ConsoleView, type ActivityEvent, buildConsole } from './console';
import { readEnvelope } from './envelope';

export interface Session {
  root: Agent;
  /** Root first, then each added sub-agent, in delegation order. */
  members: Agent[];
  /** The shared signed goal commitment (from the root grant). */
  goalCommit: string;
}

/** Start a session from a root agent. */
export function startSession(root: Agent): Session {
  return { root, members: [root], goalCommit: readEnvelope(root.grant)?.goal_commit ?? '' };
}

/** Add a sub-agent (one attenuated delegation hop under the root's current leaf). */
export function addMember(session: Session, opts: Parameters<Agent['subAgent']>[0] = {}): { session: Session; member: Agent } {
  const parent = session.members[session.members.length - 1]!;
  const member = parent.subAgent(opts);
  return { session: { ...session, members: [...session.members, member] }, member };
}

/** The holder ids (b64u public keys) of every agent in the session. */
export function sessionAgents(session: Session): string[] {
  return session.members.map((m) => b64u(m.holder.publicKey));
}

/** A console view scoped to just this session's agents. */
export function sessionConsole(session: Session, events: ActivityEvent[]): ConsoleView {
  const ids = new Set(sessionAgents(session));
  return buildConsole(events.filter((e) => ids.has(e.agent)));
}

/** True iff every member shares the root's goal commitment (a well-formed team). */
export function sharesGoal(session: Session): boolean {
  return session.members.every((m) => (readEnvelope(m.grant)?.goal_commit ?? '') === session.goalCommit);
}

/** Depth of the delegation tree (0 = root only). */
export function sessionDepth(session: Session): number {
  return session.members.length - 1;
}
