// Oracle: the proved goal kernel (formal/dafny/Goal.dfy, GoalApi entry points) at the TOKEN-TAPE level, for every native port.
// Source: every goal vector of packages/pca-conformance/vectors/goal (kinds gen / ill / w). For each one the TypeScript codec encodes
// goal, ontology, actions and histories, and the extracted JavaScript kernel (packages/pca-verified-core goalCall) is run for
// typecheck, compile, render and, per probe, decideg + decidep. Every recorded output is first checked against the conformance
// vector itself (reasons, policy digest, decision + witness), so the corpus is anchored to the shared vectors, not only to the JS run.
// Format: the shared oracle format (lib.mjs), one case per goal: fn 'kernel', name = vector id, args [goal, ont, [[act, hist], ...]],
//   out {typecheck, compile, render, probes: [[decideg, decidep], ...]} (probe i of out belongs to probe i of args).
// Every tape is in the harness text syntax: space-separated kN (keyword), iN (integer), s<hex>.<hex>... (code points; bare s = empty).
// Probes are a deterministic subset per goal (see PER below); the TypeScript and native vector runners replay all of them.
// PORTING: kernel(op, goalTape, ontTape, actTape, histTape) -> tape must equal the recorded tape exactly, for all five ops.
// Run: tsx --tsconfig tools/pca-audit/oracles/tsconfig.json tools/pca-audit/oracles/goal-kernel.mts
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import * as C0 from '../../../packages/pca-goal/src/codec';
import * as G0 from '../../../packages/pca-verified-core/src/goal';
import { Oracle, ROOT, refWrite } from './lib.mjs';
const C: any = (C0 as any).default ?? C0;
const G: any = (G0 as any).default ?? G0;

const canon = (x: unknown): string =>
  x === null || typeof x !== 'object' ? JSON.stringify(x)
  : Array.isArray(x) ? `[${x.map(canon).join(',')}]`
  : `{${Object.keys(x).sort().map((k) => `${JSON.stringify(k)}:${canon((x as any)[k])}`).join(',')}}`;
const b64u = (b: Buffer) => b.toString('base64url');
const policyDigest = (p: unknown) => b64u(createHash('sha256').update(canon(p)).digest());
const txt = (t: any): string => G.tapeToText(t);
const call = (op: string, ...t: any[]) => G.goalCall(op, ...t);
const dec = (n: number) => (n === 2 ? 'allow' : n === 1 ? 'escalate' : 'deny');

// at most PER probes per goal (the full set is > 5 MB): the first probe of each expected decision, then the earliest others
const PER = 30;
const pick = (ps: any[]): Array<[any, number]> => {
  const keep = new Set<number>();
  for (const d of ['allow', 'escalate', 'deny']) { const i = ps.findIndex((p) => p.expect.decision === d); if (i >= 0) keep.add(i); }
  for (let i = 0; i < ps.length && keep.size < PER; i++) keep.add(i);
  return [...keep].sort((a, b) => a - b).map((i) => [ps[i], i]);
};
const dir = ROOT + 'packages/pca-conformance/vectors/goal/';
const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json') && f !== 'index.json').sort();
const o = new Oracle('goal-kernel', 'tools/pca-audit/oracles/goal-kernel.mts', 'Proved goal kernel (GoalApi TypecheckT/CompileT/RenderT/DecideGoalT/DecidePolicyT) on the goal conformance vectors; tapes in harness text syntax.');
let probes = 0;
const bad: string[] = [];
for (const f of files) {
  const v = JSON.parse(fs.readFileSync(dir + f, 'utf8'));
  if (v.kind === 'fn') continue;
  const g = C.encodeGoal(v.goal), on = C.encodeOntology(v.ontology);
  const tc = call('typecheck', g, on), cp = call('compile', g, on), rd = call('render', g);
  // anchors: reasons, policy digest, render round trip (G-T10)
  const reasons = tc[0][1] === 0 ? [] : tc.slice(2, 2 + tc[1][1]).map((x: any) => x[1]);
  if (canon(reasons) !== canon(v.compile.reasons)) bad.push(`${v.id}: reasons`);
  const pd = cp[0][1] === 0 ? policyDigest(C.decodePolicy(cp.slice(1))) : null;
  if (pd !== v.policy_digest) bad.push(`${v.id}: policy_digest`);
  if (rd[0][1] !== 0 || canon(C.decodeGoal(rd.slice(1))) !== canon(C.decodeGoal(g))) bad.push(`${v.id}: render`);
  const ps = pick(v.compile.ok ? v.probes : []).map(([p, i]: [any, number]) => {
    const a = C.encodeAct(p.action), h = C.encodeHist(p.history);
    const dg = call('decideg', g, on, a, h), dp = call('decidep', g, on, a, h);
    const d = dec(dp[1][1]);
    const w = d === 'allow' ? { gid: dp[2][1], bids: dp.slice(4, 4 + dp[3][1]).map((x: any) => x[1]) } : null;
    if (dp[0][1] !== 0 || d !== p.expect.decision || canon(w) !== canon(p.expect.witness)) bad.push(`${v.id}#${i}: decidep`);
    if (d === 'allow' && dp[4 + dp[3][1]][1] !== 1) bad.push(`${v.id}#${i}: witness not checked`);
    return [[txt(a), txt(h)], [txt(dg), txt(dp)]];
  });
  probes += ps.length;
  o.add('kernel', v.id, [txt(g), txt(on), ps.map((x: any) => x[0])], { typecheck: txt(tc), compile: txt(cp), render: txt(rd), probes: ps.map((x: any) => x[1]) });
}
if (bad.length) { console.error(bad.slice(0, 20).join('\n')); throw new Error(`${bad.length} disagreements with the conformance vectors`); }
refWrite(o, 'goal-kernel');
console.log(`${probes} probes`);
