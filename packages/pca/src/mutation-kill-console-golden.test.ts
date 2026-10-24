/**
 * 0.4.2 mutation kills: the console projection (per-agent counts, risk sums, first/last seen, ordering, totals, window), event
 * derivation from a PCActn, and the freeze set. The fleet view is pinned against testdata/console-golden.json (reviewed by hand;
 * GEN_GOLDEN=<path> regenerates it).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import { type ActivityEvent, anomalies, buildConsole, eventFromPCActn, freezeAgent, isFrozen, unfreezeAgent } from './console';

const ev = (agent: string, at: number, outcome: ActivityEvent['outcome'], r?: number): ActivityEvent => ({ at, agent, verb: 'v', resource: 'r', outcome, ...(r === undefined ? {} : { r }) });
// deliberately unsorted; a1 escalates and is denied (threat), a2 is calm, a3 only executed, a4 a single event
const events: ActivityEvent[] = [
  ev('a1', 30, 'deny', 0.9), ev('a2', 5, 'auto', 0.1), ev('a1', 10, 'step_up', 0.8), ev('a3', 7, 'executed', 0.3), ev('a1', 20, 'step_up', 0.85),
  ev('a2', 6, 'auto'), ev('a1', 5, 'auto', 0.2), ev('a4', 40, 'executed'), ev('a1', 31, 'deny', 0.95), ev('a1', 32, 'deny', 0.99), ev('a3', 8, 'auto', 0.05),
];

it('the fleet view is exactly the reviewed golden', () => {
  const view = buildConsole(events);
  const out = { view, anomalies: anomalies(view).map((a) => a.agent), empty: buildConsole([]) };
  if (process.env.GEN_GOLDEN) writeFileSync(process.env.GEN_GOLDEN, JSON.stringify(out, null, 1) + '\n');
  expect(JSON.parse(JSON.stringify(out))).toEqual(JSON.parse(readFileSync(resolve(__dirname, '..', 'testdata', 'console-golden.json'), 'utf8')));
});
it('input order does not matter, and the input is not mutated', () => {
  const copy = events.map((e) => ({ ...e }));
  const a = buildConsole(events);
  const b = buildConsole([...events].reverse());
  expect(b).toEqual(a);
  expect(events).toEqual(copy);
});
it('totals are the sums over agents; the window spans the earliest and latest event', () => {
  const v = buildConsole(events);
  expect(v.totals).toEqual({ actions: 11, autos: 4, stepUps: 2, denies: 3, executed: 2 });
  expect(v.window).toEqual({ from: 5, to: 40 });
  expect(buildConsole([ev('x', 9, 'auto')]).window).toEqual({ from: 9, to: 9 });
});
it('eventFromPCActn: leaf holder, verb, resource, risk, taint and digest; defaults when absent', () => {
  const p = (extra: Record<string, unknown> = {}) => ({ iat: 77, cap_chain: [{ holder: 'root' }, { holder: 'leaf' }], action: { verb: 'a.b', resource: 'res', params_digest: 'pd' }, ...extra }) as never;
  const full = eventFromPCActn(p({ risk_claim: { r: 0.4 }, provenance: { taint_level: 2 } }), 'auto');
  expect(full).toMatchObject({ at: 77, agent: 'leaf', verb: 'a.b', resource: 'res', outcome: 'auto', r: 0.4, taint: 2 });
  expect(typeof full.digest).toBe('string');
  expect(full.digest!.length).toBeGreaterThan(20);
  const bare = eventFromPCActn(p(), 'deny', 5);
  expect(bare).toMatchObject({ at: 5, agent: 'leaf', outcome: 'deny' });
  expect(bare.r).toBeUndefined();
  expect(bare.taint).toBeUndefined();
  expect(eventFromPCActn(p({ cap_chain: [] }), 'auto').agent).toBe('unknown');
  expect(eventFromPCActn(p({ cap_chain: [{}] }), 'auto').agent).toBe('unknown');
});
it('the freeze set: sorted, idempotent, reversible', () => {
  let s = freezeAgent({ frozen: [] }, 'b');
  s = freezeAgent(s, 'a');
  expect(s).toEqual({ frozen: ['a', 'b'] });
  expect(freezeAgent(s, 'a')).toBe(s);
  expect(isFrozen(s, 'a')).toBe(true);
  expect(isFrozen(s, 'c')).toBe(false);
  expect(unfreezeAgent(s, 'a')).toEqual({ frozen: ['b'] });
  expect(unfreezeAgent(s, 'zz')).toEqual({ frozen: ['a', 'b'] });
  expect(s).toEqual({ frozen: ['a', 'b'] });
});
