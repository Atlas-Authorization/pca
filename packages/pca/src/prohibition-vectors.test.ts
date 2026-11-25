import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { certify, checkForbidCertificate, clausesError, decideClauses, type ClauseOptions, type ForbidCertificate, type PolicyClause } from './forbid-certificate';
import type { ActionContext } from './predicates';
import { checkAndAdvance, checkProhibitions, emptyState, tickState, validateConstitution, verifySignedSafetyEvidence, type Constitution, type MonitorState } from './prohibitions';
import { buildProhibitionVectors } from './test-support/prohibition-vectors';

const PATH = new URL('../conformance/prohibition-vectors.json', import.meta.url);
type Opt = ClauseOptions | undefined;
const file = JSON.parse(readFileSync(PATH, 'utf8')) as {
  clauses: Array<{ name: string; clauses: unknown; action: ActionContext; options?: Opt; expect: { error: string | null; decision: string; winner: unknown; shadowed: string[]; values: unknown[] } }>;
  check: Array<{ name: string; certificate: ForbidCertificate; clauses: unknown; action: ActionContext; options?: Opt; expect: { ok: boolean; reason?: string } }>;
  constitution: Array<{ name: string; constitution: unknown; action: ActionContext; state: MonitorState; expect: { problems: string[]; result: unknown } }>;
  evidence: Array<{ name: string; signed: unknown; expected: unknown; expect: { ok: boolean; reason?: string } }>;
  monitor: Array<{ name: string; constitution: Constitution; genesis_now: number; steps: Array<{ action: ActionContext; now?: number; expect: Record<string, unknown> }> }>;
};

describe('prohibition-vectors.json', () => {
  it('is what the generator writes', () => {
    expect(`${JSON.stringify(buildProhibitionVectors(), null, 2)}\n`).toBe(readFileSync(PATH, 'utf8'));
  });
  it('has every table populated (a vector file that silently loses its rows would pass every replay)', () => {
    expect([file.clauses.length, file.check.length, file.constitution.length, file.monitor.length, file.evidence.length].every((n) => n > 4)).toBe(true);
  });
  it.each(file.clauses)('clauses: $name', (v) => {
    expect(clausesError(v.clauses)).toBe(v.expect.error);
    const d = decideClauses(v.clauses as PolicyClause[], v.action, v.options);
    expect({ decision: d.decision, winner: d.witness.winner, shadowed: d.witness.shadowed, values: d.values }).toEqual({ decision: v.expect.decision, winner: v.expect.winner, shadowed: v.expect.shadowed, values: v.expect.values });
    if (v.expect.error !== null) expect(d.witness.winner).toEqual({ kind: 'malformed', id: null });
  });
  it.each(file.check)('check: $name', (v) => {
    expect(checkForbidCertificate(v.certificate, v.clauses as PolicyClause[], v.action, v.options)).toEqual(v.expect);
    if (v.expect.ok) expect(certify(v.clauses as PolicyClause[], v.action, v.options)).toEqual(v.certificate);
  });
  it.each(file.constitution)('constitution: $name', (v) => {
    expect(validateConstitution(v.constitution)).toEqual(v.expect.problems);
    expect(checkProhibitions(v.action, v.constitution as Constitution, v.state)).toEqual(v.expect.result);
  });
  it.each(file.monitor)('monitor: $name', (v) => {
    let st = emptyState(v.genesis_now);
    for (const step of v.steps) {
      let cur = st;
      if (step.now !== undefined) {
        const t = tickState(st, step.now);
        if (!t.ok) {
          expect({ allow: false, decidedBy: 'clock', reason: t.reason }).toEqual(step.expect);
          continue;
        }
        cur = t.state;
      }
      const r = checkAndAdvance(true, step.action, v.constitution, cur);
      st = r.allow ? r.next : cur;
      expect({ allow: r.allow, decidedBy: r.decidedBy, violated: r.prohibition.violated, seq: r.next.seq }).toEqual(step.expect);
    }
  });
  it.each(file.evidence)('evidence: $name', (v) => {
    expect(verifySignedSafetyEvidence(v.signed as never, v.expected as never)).toEqual(v.expect);
  });
});
