import { describe, expect, it } from 'vitest';
import { addMember, sessionAgents, sessionConsole, sessionDepth, sharesGoal, startSession } from './session';
import { agent } from './facade';
import { generateKeyPair } from './keys';
import { b64u } from './hash';
import type { ActivityEvent } from './console';

const AUD = 'ins_test';
const mkRoot = () => agent({ principal: generateKeyPair(), goal: 'ship the release', permissions: { github: ['create_pr', 'comment'] }, aud: AUD });

describe('session', () => {
  it('groups root + sub-agents under one shared goal', () => {
    const root = mkRoot();
    let s = startSession(root);
    expect(sessionDepth(s)).toBe(0);
    const r1 = addMember(s);
    s = r1.session;
    const r2 = addMember(s);
    s = r2.session;
    expect(s.members).toHaveLength(3);
    expect(sessionDepth(s)).toBe(2);
    expect(sharesGoal(s)).toBe(true);
    // each member is a distinct holder, all under the same root grant/goal
    const ids = sessionAgents(s);
    expect(new Set(ids).size).toBe(3);
    expect(ids[0]).toBe(b64u(root.holder.publicKey));
  });

  it('scopes the console to session members only', () => {
    const root = mkRoot();
    const s0 = startSession(root);
    const { session: s, member } = addMember(s0);
    const memberId = b64u(member.holder.publicKey);
    const rootId = b64u(root.holder.publicKey);
    const events: ActivityEvent[] = [
      { at: 1, agent: rootId, verb: 'github.create_pr', resource: 'repo:1', outcome: 'auto' },
      { at: 2, agent: memberId, verb: 'github.comment', resource: 'repo:1', outcome: 'auto' },
      { at: 3, agent: 'outsider', verb: 'x', resource: 'y', outcome: 'deny' }, // not in session
    ];
    const view = sessionConsole(s, events);
    expect(view.totals.actions).toBe(2); // outsider filtered out
    expect(view.agents.map((a) => a.agent).sort()).toEqual([memberId, rootId].sort());
  });
});
