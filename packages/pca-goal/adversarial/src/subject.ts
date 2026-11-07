// The adapter between the suite and the implementation under test. `refSubject` is the oracle itself (it validates the tests and the
// vectors on any tree). `loadRealSubject` maps EVERY capability to the real shipped code, with the same signature as ref.ts:
//   @atlasauth/pca-goal: compiler/typecheck/decidePolicy, digests (goalDigest, approvalDigest), liftLegacy, meet (intersect),
//     nVersion (reconcile), interpretForm, parseMoney, bindDecision/guardExecute/claimGate, goalCommit/openCommit (binding.ts);
//   @atlasauth/pca: tighten (meet), pepDecision + signed escalation answers (pepAdmit), decideUnits (rule 20, unitsCheck),
//     modelPathsRead (rule 21, polarityViolations);
//   @atlasauth/pca/ext/intent: decideParamProvenance (rule 17, provenanceSignal).
// No capability is reference-only: a missing export leaves it undefined, and the tests that need it are skipped locally and FAIL
// when GOAL_REQUIRE_SUBJECT=1 (CI), so no capability can silently lose its real counterpart.
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
  // N-version meet and reconciliation: the real N-version reading merge (a grant only some readings allow is dropped and becomes a Hole)
  const meetG = fn('meet'), nVer = fn('nVersion');
  if (meetG) s.intersect = (gs) => meetG(gs);
  if (nVer) s.reconcile = (gs, o) => nVer(gs.map((goal, i) => ({ id: `r${i}`, family: 'rule', deterministic: true, goal, notes: [] })), { ont: o }).merged;
  for (const n of ['interpretForm', 'parseMoney', 'approvalDigest', 'bindDecision', 'guardExecute', 'claimGate'] as const) if (fn(n)) (s as any)[n] = fn(n); // eslint-disable-line @typescript-eslint/no-explicit-any
  // goal binding v3 commit construction is shipped by the package itself (binding.ts)
  if (fn('goalCommit')) s.goalCommit = fn('goalCommit');
  if (fn('openCommit')) s.openCommit = fn('openCommit');
  // the intent-layer rules live in the intent extension of @atlasauth/pca
  const x = await load('@atlasauth/pca/ext/intent');
  if (x && typeof x.decideParamProvenance === 'function') {
    s.provenanceSignal = (prov, sensitive) => {
      const path = (n: string) => `action.params.${n}`;
      const level = { principal: 'trusted', untrusted: 'web' } as Record<string, string>; // 'agent' and undeclared stay unvouched => agent
      const declared = sensitive.filter((n) => prov[n] !== undefined);
      const r = x.decideParamProvenance({
        aud: 'aud', session: 'sess', action: { params: Object.fromEntries(sensitive.map((n) => [n, 'v'])) },
        prov: Object.fromEntries(declared.map((n) => [path(n), [`${prov[n]}:${n}`]])),
        policy: { params: Object.fromEntries(sensitive.map((n) => [path(n), 'material'])), registry: Object.fromEntries(declared.filter((n) => level[prov[n]!]).map((n) => [`${prov[n]}:${n}`, level[prov[n]!]])) },
      });
      return r.outcome === 'pass' ? 'ok' : r.outcome === 'question' ? 'escalate' : 'deny';
    };
  }
  // rules 20 and 21: the real verifier rules over the verifier's wire shapes; the adapter only re-expresses the IR terms in them
  if (p && typeof p.decideUnits === 'function') {
    s.unitsCheck = (schema, terms) => Object.keys(terms).sort().filter((n) => {
      const key = `action.params.${n}`;
      const t = terms[n]!, d = schema[n];
      return p.decideUnits({
        units: { [key]: { kind: 'money', currency: t.currency, exponent: t.exponent } }, verb: 'v', verb_params: { [key]: { unit: n } },
        schema_units: d ? { [n]: { kind: 'money', currency: d.currency, exponent: d.exponent } } : {}, predicates: [],
      }).ok !== true;
    });
  }
  if (p && typeof p.modelPathsRead === 'function') {
    s.polarityViolations = (wheres) => {
      const walk = (c: any): any => c.k === 'and' ? { all_of: [walk(c.a), walk(c.b)] } : c.k === 'or' ? { any_of: [walk(c.a), walk(c.b)] } : c.k === 'not' ? { not: walk(c.c) } // eslint-disable-line @typescript-eslint/no-explicit-any
        : c.k === 'cmp' ? { all_of: [c.l, c.r].filter((t: any) => t.k === 'param').map((t: any) => ({ field: t.path })) } : { all_of: [] }; // eslint-disable-line @typescript-eslint/no-explicit-any
      const conds = wheres.map(walk);
      const worlds = JSON.stringify(conds).match(/env\.world\.[^."]+/g)?.map((w) => w.split('.')[2]!) ?? []; // env.world.<w> is model-derived (single oracle)
      return p.modelPathsRead([[{ where: conds }]], worlds);
    };
  }
  return s;
}
export const REQUIRE = process.env.GOAL_REQUIRE_SUBJECT === '1';
