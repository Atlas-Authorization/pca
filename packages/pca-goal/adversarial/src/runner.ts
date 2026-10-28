// TS vector runner: replays every committed vector through a Subject and reports disagreements.
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { canon, goalDigest } from './canon.ts';
import { VECTOR_DIR } from './vectors.ts';
import type { Subject } from './subject.ts';

export function loadVectors(dir = VECTOR_DIR): Array<Record<string, any>> { // eslint-disable-line @typescript-eslint/no-explicit-any
  return readdirSync(dir).filter((f) => f.endsWith('.json') && f !== 'index.json').sort().map((f) => JSON.parse(readFileSync(join(dir, f), 'utf8')));
}
export function runVectors(s: Subject, vectors = loadVectors()): string[] {
  const bad: string[] = [];
  for (const v of vectors) {
    if (v.kind === 'fn') { const e = runFn(s, v); if (e) bad.push(`${v.id}: ${e}`); continue; }
    if (s.goalDigest && s.goalDigest(v.goal) !== v.goal_digest) bad.push(`${v.id}: goal_digest`);
    if (s.typecheck) {
      const r = s.typecheck(v.goal, v.ontology);
      if (canon(r) !== canon(v.compile.reasons)) bad.push(`${v.id}: reasons ${canon(r)} != ${canon(v.compile.reasons)}`);
    }
    if (s.policyDigest && s.policyDigest(v.goal, v.ontology) !== v.policy_digest) bad.push(`${v.id}: policy_digest`);
    if (s.decide && v.compile.ok) for (const [i, p] of v.probes.entries()) {
      const d = s.decide(v.goal, v.ontology, p.action, p.history);
      if (d.decision !== p.expect.decision || canon(d.witness) !== canon(p.expect.witness)) bad.push(`${v.id}#${i}: ${canon(d)} != ${canon(p.expect)}`);
    }
  }
  return bad;
}
function runFn(s: Subject, v: { fn: string; input: any; expect: any }): string | null { // eslint-disable-line @typescript-eslint/no-explicit-any
  const got = ((): unknown => {
    switch (v.fn) {
      case 'canon': return { canon: canon(v.input), digest: (s.goalDigest ?? goalDigest)(v.input) };
      case 'units': return s.unitsCheck?.(v.input.schema, v.input.terms);
      case 'polarity': return s.polarityViolations?.(v.input);
      case 'meet': return s.meet?.(v.input.decision, v.input.signal);
      case 'pep': return s.pepAdmit ? s.pepAdmit(v.input.decision, v.input.ctx, v.input.answer ?? undefined) : undefined;
      case 'commit': return s.goalCommit ? { commit: s.goalCommit(v.input.goal_digest, v.input.policy_digest, v.input.salt), opens_other_goal: false } : undefined;
      case 'claim': return s.claimGate?.(v.input.base, v.input.min_ppm, v.input.claimed_ppm, v.input.replayed_ppm ?? undefined);
      default: return 'unknown fn';
    }
  })();
  return got === undefined || canon(got) === canon(v.expect) ? null : `${v.fn} got ${canon(got)} want ${canon(v.expect)}`;
}
