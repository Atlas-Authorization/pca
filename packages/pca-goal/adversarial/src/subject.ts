// The adapter between the suite and the implementation under test. `refSubject` is the oracle itself (it validates the tests and the
// vectors on any tree). `loadRealSubject` maps the REAL exports of @atlasauth/pca-goal (compiler, digests, liftLegacy) and of
// @atlasauth/pca (tighten, pepDecision, escalation answers); a missing export leaves that capability undefined, and the tests that
// need it are skipped locally and FAIL when GOAL_REQUIRE_SUBJECT=1 (CI sets it once the extracted compiler is available).
// Capabilities with NO counterpart outside this suite yet (intersect, reconcile, interpretForm, parseMoney, claimGate, provenanceSignal,
// unitsCheck, polarityViolations, bindDecision, guardExecute) are only tested against the reference functions of ref.ts.
import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Act, Goal, Hist, Ontology, Verdict } from './types.ts';
import * as O from './oracle.ts';
import * as R from './ref.ts';
import { goalDigest } from './canon.ts';

export type Subject = {
  name: string;
  /** type reasons of GoalCompile.dfy (`[]` = well typed) */
  typecheck?: (g: Goal, o: Ontology) => string[];
  decide?: (g: Goal, o: Ontology, a: Act, h: Hist) => Verdict;
  goalDigest?: (g: Goal) => string;
  /** digest of the lowered policy; null when the goal does not compile */
  policyDigest?: (g: Goal, o: Ontology) => string | null;
  verifyWitness?: (g: Goal, o: Ontology, a: Act, h: Hist, w: Verdict['witness']) => boolean;
  intersect?: typeof R.intersect;
  reconcile?: typeof R.reconcile;
  liftLegacy?: (o: { permissions: Record<string, string[]>; limits?: Record<string, string>; principal: string }) => { goal: Goal; ontology: Ontology };
  parseMoney?: typeof R.parseMoney;
  goalCommit?: typeof R.goalCommit;
  openCommit?: typeof R.openCommit;
  approvalDigest?: typeof R.approvalDigest;
  meet?: typeof R.meet;
  pepAdmit?: typeof R.pepAdmit;
  unitsCheck?: typeof R.unitsCheck;
  polarityViolations?: typeof R.polarityViolations;
  claimGate?: typeof R.claimGate;
  provenanceSignal?: typeof R.provenanceSignal;
  bindDecision?: typeof R.bindDecision;
  guardExecute?: typeof R.guardExecute;
  interpretForm?: typeof R.interpretForm;
};
export const refSubject: Subject = {
  name: 'reference-oracle', typecheck: (g, o) => O.typeReasons(o, g), decide: O.decide, goalDigest, policyDigest: (g, o) => (O.typecheck(g, o).ok ? O.policyDigest(o, g) : null),
  verifyWitness: O.verifyWitness, intersect: R.intersect, reconcile: R.reconcile, parseMoney: R.parseMoney, goalCommit: R.goalCommit, openCommit: R.openCommit,
  approvalDigest: R.approvalDigest, meet: R.meet, pepAdmit: R.pepAdmit, unitsCheck: R.unitsCheck, polarityViolations: R.polarityViolations,
  claimGate: R.claimGate, provenanceSignal: R.provenanceSignal, bindDecision: R.bindDecision, guardExecute: R.guardExecute, interpretForm: R.interpretForm,
};
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Mod = Record<string, any>;
// Resolve from packages/pca-goal (its workspace links), not from this folder: the suite has no node_modules of its own.
const pkgRequire = createRequire(resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'package.json'));
const load = async (spec: string): Promise<Mod | null> => { try { return pkgRequire(spec) as Mod; } catch { return null; } };
export async function loadRealSubject(): Promise<Subject | null> {
  const spec = process.env.GOAL_SUBJECT_MODULE ?? resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'dist', 'index.js'); // the built package
  const m = await load(spec);
  if (!m) return null;
  const s: Subject = { name: '@atlasauth/pca-goal' };
  const fn = (n: string): ((...a: any[]) => any) | undefined => (typeof m[n] === 'function' ? m[n] : undefined); // eslint-disable-line @typescript-eslint/no-explicit-any
  const typecheck = fn('typecheck'), compile = fn('compileGoal'), decideP = fn('decidePolicy');
  if (typecheck) s.typecheck = (g, o) => typecheck(g, o);
  if (decideP) s.decide = (g, o, a, h) => {
    const r = decideP(g, o, a, h);
    return r.ok ? { decision: r.decision, witness: r.witness } : { decision: 'deny', witness: null };
  };
  if (fn('goalDigest')) s.goalDigest = fn('goalDigest');
  if (compile && fn('policyDigest')) s.policyDigest = (g, o) => { const r = compile(g, o); return r.ok ? fn('policyDigest')!(r.policy) : null; };
  if (fn('liftLegacy')) s.liftLegacy = fn('liftLegacy');
  // decision lattice and escalation: the real implementations in @atlasauth/pca (G-T4 PEP, G-T9 tighten)
  const p = await load('@atlasauth/pca');
  if (p && typeof p.tighten === 'function') s.meet = (d, sig) => p.tighten(d, sig);
  if (p && typeof p.pepDecision === 'function' && typeof p.signEscalationAnswer === 'function' && typeof p.verifyEscalationAnswer === 'function' && typeof p.generateKeyPair === 'function') {
    s.pepAdmit = (d, ctx, ans) => {
      if (d !== 'escalate' || !ans) return p.pepDecision(d, false) === 'allow';
      const kp = p.generateKeyPair();
      const now = 1_750_000_000_000;
      const principal = p.b64u(kp.publicKey);
      const body = { v: 1, kind: 'pca-escalation-answer', principal, policy_digest: ans.policy_digest, action_digest: ans.action_digest, history_head: ans.history_head, decision: 'allow', iat: now, expires_at: now + 3_600_000, nonce: p.b64u(randomBytes(16)) };
      const signed = p.signEscalationAnswer(body, kp.secretKey);
      const sent = ans.valid ? signed : { ...signed, sig: (signed.sig[0] === 'A' ? 'B' : 'A') + signed.sig.slice(1) };
      const v = p.verifyEscalationAnswer(sent, [principal], ctx, now);
      return p.pepDecision('escalate', v.ok === true && v.decision === 'allow') === 'allow';
    };
  }
  return s;
}
/** Capabilities with no counterpart in the shipped package yet (see the header): tested against ref.ts only, never demanded of the real subject. */
export const REF_ONLY: ReadonlySet<keyof Subject> = new Set<keyof Subject>(['intersect', 'reconcile', 'interpretForm', 'parseMoney', 'goalCommit', 'openCommit', 'approvalDigest', 'unitsCheck', 'polarityViolations', 'claimGate', 'provenanceSignal', 'bindDecision', 'guardExecute']);
export const REQUIRE = process.env.GOAL_REQUIRE_SUBJECT === '1';
