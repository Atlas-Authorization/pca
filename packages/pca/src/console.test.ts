import { describe, expect, it } from 'vitest';
import {
  EMPTY_FREEZE,
  type ActivityEvent,
  anomalies,
  buildConsole,
  eventFromPCActn,
  freezeAgent,
  isFrozen,
  unfreezeAgent,
} from './console';
import { agent } from './facade';
import { generateKeyPair } from './keys';

const AUD = 'ins_test';

const ev = (agentId: string, outcome: ActivityEvent['outcome'], r: number, at: number): ActivityEvent => ({
  at,
  agent: agentId,
  verb: 'stripe.refund',
  resource: 'charge:1',
  outcome,
  r,
});

describe('eventFromPCActn', () => {
  it('derives the acting agent + verb + digest from a real PCActn', () => {
    const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: { gmail: ['send'] }, aud: AUD });
    const { pcactn } = a.act('gmail.send', 'msg:1', {}, { counter: 1 });
    const e = eventFromPCActn(pcactn, 'executed');
    expect(e.verb).toBe('gmail.send');
    expect(e.agent).toBe(pcactn.cap_chain[pcactn.cap_chain.length - 1]!.holder);
    expect(e.digest).toBeTruthy();
    expect(e.at).toBe(pcactn.iat);
  });
});

describe('buildConsole', () => {
  it('summarizes per agent and ranks the most-threatening first', () => {
    const events: ActivityEvent[] = [
      // calm agent
      ...Array.from({ length: 10 }, (_, i) => ev('calm-agent', 'auto', 0.1, i)),
      // noisy agent: repeated denies → high threat
      ev('bad-agent', 'auto', 0.1, 0),
      ev('bad-agent', 'deny', 0.2, 1),
      ev('bad-agent', 'deny', 0.2, 2),
      ev('bad-agent', 'deny', 0.2, 3),
    ];
    const view = buildConsole(events);
    expect(view.totals.actions).toBe(14);
    expect(view.totals.denies).toBe(3);
    // most-threatening first
    expect(view.agents[0]!.agent).toBe('bad-agent');
    expect(view.agents[0]!.threat.level).toBe('high');
    const calm = view.agents.find((a) => a.agent === 'calm-agent')!;
    expect(calm.threat.level).toBe('calm');
    expect(calm.autos).toBe(10);
  });

  it('anomalies() returns only non-calm agents', () => {
    const events: ActivityEvent[] = [
      ...Array.from({ length: 10 }, (_, i) => ev('calm', 'auto', 0.1, i)),
      ev('x', 'deny', 0.2, 0),
      ev('x', 'deny', 0.2, 1),
      ev('x', 'deny', 0.2, 2),
    ];
    const anoms = anomalies(buildConsole(events));
    expect(anoms.map((a) => a.agent)).toEqual(['x']);
  });

  it('handles an empty stream', () => {
    const view = buildConsole([]);
    expect(view.agents).toHaveLength(0);
    expect(view.window).toEqual({ from: 0, to: 0 });
  });
});

describe('freeze (kill switch)', () => {
  it('freezes, reports, and unfreezes agents idempotently', () => {
    let f = EMPTY_FREEZE;
    f = freezeAgent(f, 'agent-2');
    f = freezeAgent(f, 'agent-1');
    f = freezeAgent(f, 'agent-1'); // idempotent
    expect(f.frozen).toEqual(['agent-1', 'agent-2']); // sorted
    expect(isFrozen(f, 'agent-1')).toBe(true);
    expect(isFrozen(f, 'agent-3')).toBe(false);
    f = unfreezeAgent(f, 'agent-1');
    expect(isFrozen(f, 'agent-1')).toBe(false);
    // EMPTY_FREEZE not mutated
    expect(EMPTY_FREEZE.frozen).toEqual([]);
  });
});
