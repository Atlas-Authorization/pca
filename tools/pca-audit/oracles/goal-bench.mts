// Oracle: @atlasauth/pca-goal bench.ts (deterministic labelled cases, simulated model fixtures, the four-level evaluation, calibration report).
// PORTING (fn(args) -> native entry point, comparison rule; all compare by JSON value):
//   rngSeq(seed, n) -> n successive GoalBench.rng(seed).next() values (doubles)
//   generateCases(domain, n, seed, hostileEvery|null, hostileOnly) -> GoalBench.generateCases; truthGoalOf(case) -> GoalBench.truthGoal
//   simulateOutputOf(case, modelId) -> GoalBench.simulateOutput(case, id, err, follow) with the model's {err, follow} (model-a 0.08/0.45, model-b 0.12/0.3)
//   recordFixturesOf(cases) -> GoalBench.recordFixtures (a map prompt-key -> raw output)
//   evalCaseOf(case) -> GoalBench.evalCase(case, completionsFrom(recordFixtures([case])), null, false, null)
//   summarizeOf(domain, outcomes, modelSet, compileWidening|null) -> GoalBench.summarize; compileWideningOf(cases) -> GoalBench.compileWideningCount over truth goals (self-check)
//   runDomainOf(domain, cases) -> GoalBench.runDomain(domain, cases, recordFixtures(cases), null, false) = {report, outcomes}; caseSetDigest(cases) -> GoalBench.caseSetDigest
import * as B0 from '../../../packages/pca-goal/src/bench';
import { Oracle, refWrite } from './lib.mjs';
const B: any = (B0 as any).default ?? B0;
const o = new Oracle('goal-bench', 'tools/pca-audit/oracles/goal-bench.mts', 'TS-reference oracle for pca-goal bench.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const DOMAINS = ['payments', 'email', 'calendar_travel', 'code_repos', 'data_access'];

for (const s of [0, 1, 42, 2 ** 31, 2 ** 32 - 1, -1, 123456789]) await run('rngSeq', (sd: number, k: number) => { const r = B.rng(sd); return Array.from({ length: k }, () => r()); }, [s, 12]);
const ALL: Record<string, any[]> = {};
for (const d of DOMAINS) {
  for (const [nn, sd, he, ho] of [[18, 1, null, false], [14, 7, 3, false], [10, 99, null, true], [12, 2 ** 31 + 5, 2, false]] as const) {
    await run('generateCases', (dm: string, c: number, s: number, h: any, hh: boolean) => B.generateCases(dm, c, s, { ...(h !== null ? { hostileEvery: h } : {}), ...(hh ? { hostileOnly: true } : {}) }), [d, nn, sd, he, ho]);
  }
  ALL[d] = B.generateCases(d, 18, 1, { hostileEvery: 3 });
  const hostile = B.generateCases(d, 16, 5, { hostileOnly: true });
  for (const c of [...ALL[d], ...hostile]) {
    await run('simulateOutputOf', (cc: any, id: string) => B.simulateOutput(cc, B.SIM_SPECS.find((x: any) => x.id === id)), [c, 'model-a']);
    await run('simulateOutputOf', (cc: any, id: string) => B.simulateOutput(cc, B.SIM_SPECS.find((x: any) => x.id === id)), [c, 'model-b']);
  }
  for (const c of ALL[d].slice(0, 4)) await run('truthGoalOf', B.truthGoal, [c]);
  await run('recordFixturesOf', B.recordFixtures, [ALL[d].slice(0, 5)]);
  await run('caseSetDigest', B.caseSetDigest, [ALL[d]]);
  const evalSet = [...ALL[d].filter((_: any, i: number) => i < 3), ...hostile.slice(0, 3)];
  for (const c of evalSet) await run('evalCaseOf', async (cc: any) => B.evalCase(cc, B.completionsFrom(B.recordFixtures([cc]))), [c]);
  await run('compileWideningOf', (cs: any[]) => B.compileWideningCount(cs.map((cc) => { const goal = B.truthGoal(cc); return { goal, ont: B.truthOnt(cc, goal) }; })), [ALL[d].slice(0, 2)]);
}
await run('runDomainOf', async (dm: string, cs: any[]) => B.runDomain(dm, cs, B.recordFixtures(cs)), ['payments', B.generateCases('payments', 8, 3, { hostileEvery: 4 })]);
await run('runDomainOf', async (dm: string, cs: any[]) => B.runDomain(dm, cs, B.recordFixtures(cs)), ['email', B.generateCases('email', 6, 11)]);
// synthetic outcomes: monotone loss rows, mixed acceptance
const outs = (k: number, bias: number) => Array.from({ length: k }, (_, i) => {
  const l1 = (i * 7 + bias) % 5 === 0 ? 1 : 0, l2 = l1 && (i + bias) % 3 === 0 ? 1 : 0, l3 = l2 && i % 2 === 0 ? 1 : 0;
  return { id: 'c' + i, loss: [l1 | l2 | l3, l2 | l3, l3, 0], accepted: [i % 4 !== 0, i % 3 !== 0, i % 2 === 0, false], falseRestricted: [i % 5 === 0, i % 6 === 0, i % 7 === 0, false], questions: i % 3, panelIssue: i % 9 === 0 };
});
for (const d of DOMAINS) for (const [k, b] of [[40, 0], [200, 1], [7, 2], [1, 0], [0, 0]]) {
  await run('summarizeOf', (dm: string, os: any[], ms: string, cw: any) => B.summarize(dm, os, ms, cw ?? undefined), [d, outs(k, b), 'recorded-fixtures', k % 2 ? { k: 1, n: 40 } : null]);
}
await run('summarizeOf', (dm: string, os: any[], ms: string, cw: any) => B.summarize(dm, os, ms, cw ?? undefined), ['payments', [{ id: 'x', loss: [0, 1, 0, 0], accepted: [true, true, true, false], falseRestricted: [false, false, false, false], questions: 0, panelIssue: false }, { id: 'y', loss: [0, 0, 0, 0], accepted: [true, true, true, false], falseRestricted: [false, false, false, false], questions: 0, panelIssue: false }], 'm', null]);
await run('summarizeOf', (dm: string, os: any[], ms: string, cw: any) => B.summarize(dm, os, ms, cw ?? undefined), ['payments', [{ id: 'x', loss: [0, 2, 0, 0], accepted: [true], falseRestricted: [false], questions: 0 }], 'm', null]);
refWrite(o, 'goal-bench');
