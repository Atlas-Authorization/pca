// compiler.ts - the typed front door of the proved goal compiler. Every function here is a thin wrapper over a Dafny entry point
// (generated/pca_goal.js through @atlasauth/pca-verified-core `goalCall`); there is no decision logic in this file.
import { goalCall, type Tape } from '@atlasauth/pca-verified-core';
import { createHash } from 'node:crypto';
import { decodePolicy, encodeAct, encodeGoal, encodeHist, encodeOntology, IrError } from './codec';
import type { Act, CompileResult, Decision, Goal, Hist, Ontology, Policy, Witness } from './ir';

const first = (t: Tape): number => {
  const x = t[0];
  if (!x || x[0] !== 'i') throw new IrError('malformed compiler output');
  return x[1];
};
const reasonsOf = (t: Tape): string[] => {
  const n = (t[1] as readonly ['i', number] | undefined)?.[1] ?? 0;
  return t.slice(2, 2 + n).map((x) => (x[0] === 's' ? x[1] : ''));
};

/** Type reasons of a goal against an ontology; [] = well typed. A malformed tape throws (it cannot come from `encodeGoal`). */
export function typecheck(goal: Goal, ont: Ontology): string[] {
  const out = goalCall('typecheck', encodeGoal(goal), encodeOntology(ont));
  const s = first(out);
  if (s === 0) return [];
  if (s === 1) return reasonsOf(out);
  throw new IrError('compiler rejected the input tape');
}

/** C: Goal -> Policy | Escalate(reasons). Ill-typed goals are rejected, never coerced; a goal with holes compiles to its most restrictive completion. */
export function compileGoal(goal: Goal, ont: Ontology): CompileResult {
  const out = goalCall('compile', encodeGoal(goal), encodeOntology(ont));
  const s = first(out);
  if (s === 0) return { ok: true, policy: decodePolicy(out.slice(1)) };
  if (s === 1) return { ok: false, reasons: reasonsOf(out) };
  throw new IrError('compiler rejected the input tape');
}

/** The reference semantics D_G(a, H) (the specification the compiled policy is proved equal to). */
export function decideGoal(goal: Goal, ont: Ontology, act: Act, hist: Hist): Decision {
  const out = goalCall('decideg', encodeGoal(goal), encodeOntology(ont), encodeAct(act), encodeHist(hist));
  if (first(out) !== 0) throw new IrError('compiler rejected the input tape');
  return toDecision((out[1] as readonly ['i', number])[1]);
}
const toDecision = (n: number): Decision => (n === 2 ? 'allow' : n === 1 ? 'escalate' : 'deny');

/** The compiled policy's decision with the witness of an Allow (G-T3) and the separate checker's verdict on that witness. */
export function decidePolicy(goal: Goal, ont: Ontology, act: Act, hist: Hist):
  | { ok: false; reasons: string[] }
  | { ok: true; decision: Decision; witness: Witness | null; witnessChecked: boolean } {
  const out = goalCall('decidep', encodeGoal(goal), encodeOntology(ont), encodeAct(act), encodeHist(hist));
  const s = first(out);
  if (s === 1) return { ok: false, reasons: reasonsOf(out) };
  if (s !== 0) throw new IrError('compiler rejected the input tape');
  const decision = toDecision((out[1] as readonly ['i', number])[1]);
  const gid = (out[2] as readonly ['s', string])[1];
  const n = (out[3] as readonly ['i', number])[1];
  const bids = out.slice(4, 4 + n).map((x) => (x[0] === 's' ? x[1] : ''));
  const checked = (out[4 + n] as readonly ['i', number])[1] === 1;
  return { ok: true, decision, witness: decision === 'allow' ? { gid, bids } : null, witnessChecked: checked };
}

/** The card as a token tape (formal/dafny/GoalRender.dfy `Render`): lossless, `decodeGoal(renderTape(g))` equals g (G-T10). */
export function renderTape(goal: Goal): Tape {
  const out = goalCall('render', encodeGoal(goal));
  if (first(out) !== 0) throw new IrError('goal tape rejected');
  return out.slice(1);
}

/** Canonical bytes of a policy (sorted-key JSON, no floats), the input of the policy digest (G-T5). */
export function canonicalPolicy(p: Policy): string {
  const c = (x: unknown): string =>
    x === null || typeof x !== 'object' ? JSON.stringify(x)
    : Array.isArray(x) ? `[${x.map(c).join(',')}]`
    : `{${Object.keys(x).sort().map((k) => `${JSON.stringify(k)}:${c((x as Record<string, unknown>)[k])}`).join(',')}}`;
  return c(p);
}
export const policyDigest = (p: Policy): string => createHash('sha256').update(canonicalPolicy(p)).digest('base64url');
