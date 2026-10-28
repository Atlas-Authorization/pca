import { b64u, hashCanonical, sha256, sign, utf8, verifyB64u } from '@atlasauth/pca';
import { DEFAULT_MAX_COMBINATIONS, collect, collectProbes, contextOfAction, decide, decideAction, probeSet, repToAction, toModel, vetoApplies } from './enumerate';
import { thresholdsOf } from './exposure';
import { alwaysDenies } from './index';
import { policyDigestOf } from './residual';
import { witnessOf, permitId } from './coverage';
import type { AnalyzerAction, AnalyzerDecision, PolicyInput } from './types';

/**
 * POLICY-AS-CODE TEST RUNNER (borrowed-ideas item 29, security contract C-256).
 *
 * A policy test document lists actions with the decision the author expects (and optionally the clause expected to decide). It
 * names the policy it was written for by digest, and may be signed, so a recompile that drifts (a new compiler, a new ontology
 * version, a model-written policy) must still reproduce every confirmed example or the run fails. `generateBoundaryTests`
 * writes the examples a reviewer would otherwise have to think of: one minimal allow per permit clause, one trigger per
 * prohibition, and for every numeric threshold the points just below, at and just above it. Expectations in a generated
 * document are the policy's CURRENT behaviour, to be read and confirmed by a person (`ask` marks an escalation they must rule
 * on); the confirmed document is what gets signed and pinned.
 */

export const POLICY_TESTS_KIND = 'pca-policy-tests';
export const POLICY_TESTS_SIG_DOMAIN = 'atlas-pca/policy-tests/v1\0';

export interface PolicyTestCase {
  name: string;
  action: AnalyzerAction;
  expect: AnalyzerDecision;
  /** The clause expected to decide, e.g. `permit[0]` or a prohibition id. Omitted = not asserted. */
  decidedBy?: string;
}

export interface PolicyTestDoc {
  v: 1;
  kind: typeof POLICY_TESTS_KIND;
  /** Digest of the policy the examples were confirmed against. */
  policy_digest: string;
  cases: PolicyTestCase[];
}

export interface SignedPolicyTests {
  doc: PolicyTestDoc;
  signer: string;
  sig: string;
}

export interface TestFailure {
  name: string;
  expected: AnalyzerDecision;
  got: AnalyzerDecision;
  decidedBy: string | null;
  expectedDecidedBy?: string;
}

export interface TestRun {
  total: number;
  passed: number;
  failures: TestFailure[];
  /** The document names the policy that was run (a drifted policy must still reproduce every case). */
  digestMatch: boolean;
  ok: boolean;
}

export function policyTestsDoc(policy: PolicyInput, cases: PolicyTestCase[]): PolicyTestDoc {
  return { v: 1, kind: POLICY_TESTS_KIND, policy_digest: policyDigestOf(toModel(policy)), cases };
}

/** Run a document against a policy. With `requireDigest` a changed policy fails even if every case still passes. */
export function runPolicyTests(policy: PolicyInput, doc: PolicyTestDoc, opts: { requireDigest?: boolean } = {}): TestRun {
  const model = toModel(policy);
  const failures: TestFailure[] = [];
  for (const c of doc.cases) {
    const w = witnessOf(model, c.action);
    const decidedBy = w.winner.id;
    if (w.decision !== c.expect || (c.decidedBy !== undefined && c.decidedBy !== decidedBy)) {
      failures.push({ name: c.name, expected: c.expect, got: w.decision, decidedBy, ...(c.decidedBy !== undefined ? { expectedDecidedBy: c.decidedBy } : {}) });
    }
  }
  const digestMatch = doc.policy_digest === policyDigestOf(model);
  return { total: doc.cases.length, passed: doc.cases.length - failures.length, failures, digestMatch, ok: failures.length === 0 && (opts.requireDigest !== true || digestMatch) };
}

function message(doc: PolicyTestDoc): Uint8Array {
  const pre = utf8(POLICY_TESTS_SIG_DOMAIN);
  const d = sha256(utf8(hashCanonical(doc)));
  const m = new Uint8Array(pre.length + d.length);
  m.set(pre);
  m.set(d, pre.length);
  return m;
}

/** The principal signs the confirmed examples (pinned alongside the approval). */
export function signPolicyTests(doc: PolicyTestDoc, secret: Uint8Array, signerPublic: string): SignedPolicyTests {
  return { doc, signer: signerPublic, sig: b64u(sign(secret, message(doc))) };
}

export function verifyPolicyTests(s: SignedPolicyTests, expectedSigner: string): boolean {
  try {
    return s.signer === expectedSigner && s.doc?.kind === POLICY_TESTS_KIND && typeof s.sig === 'string' && verifyB64u(s.signer, message(s.doc), s.sig);
  } catch {
    return false;
  }
}

export interface GenerateOptions {
  /** Distance used for the points next to a threshold (default 1). */
  epsilon?: number;
}

/** Boundary examples for every clause and numeric threshold of the policy; expectations are the current behaviour. */
export function generateBoundaryTests(policy: PolicyInput, o: GenerateOptions = {}): PolicyTestDoc {
  const eps = o.epsilon ?? 1;
  const model = toModel(policy);
  const cases: PolicyTestCase[] = [];
  const seen = new Set<string>();
  const add = (name: string, action: AnalyzerAction): void => {
    const key = JSON.stringify(action);
    if (seen.has(key)) return;
    seen.add(key);
    const w = witnessOf(model, action);
    cases.push({ name, action, expect: w.decision, ...(w.winner.id !== null ? { decidedBy: w.winner.id } : {}) });
  };
  model.predicates.forEach((p, i) => {
    const r = alwaysDenies({ predicates: [p], caveats: model.caveats, vetoes: model.vetoes, tighten: model.tighten });
    const base = r.witness ?? alwaysDenies({ predicates: [p], caveats: model.caveats }).witness;
    if (!base) return;
    add(`${permitId(i)}: minimal admitted action`, base);
    for (const path of paramPaths(p)) {
      const name = path.slice('action.params.'.length);
      for (const t of thresholdsOf(toModel({ predicates: [p] }), path)) {
        for (const [tag, v] of [['below', t - eps], ['at', t], ['above', t + eps]] as const) add(`${permitId(i)}: ${name} ${tag} ${t}`, { ...base, params: { ...(base.params ?? {}), [name]: v } });
      }
    }
    add(`${permitId(i)}: unmentioned resource`, { ...base, resource: base.resource + '/__other__' });
  });
  // a trigger per prohibition: an action some permit would allow and this prohibition stops (so the prohibition is what is tested)
  const permitOnly = { ...model, vetoes: [], tighten: [] };
  const pr = collectProbes({ predicateSets: [probeSet(model)], varyReversibility: model.revCap !== undefined });
  for (const v of model.vetoes) {
    const hit = collect(pr, (rep) => decide(permitOnly, rep) !== 'deny' && vetoApplies(v, contextOfAction(repToAction(rep))), DEFAULT_MAX_COMBINATIONS, 1).hits[0];
    if (hit) add(`${v.id}: trigger`, repToAction(hit));
  }
  return policyTestsDoc(policy, cases);
}

function paramPaths(p: { where?: unknown }): string[] {
  const out = new Set<string>();
  const walk = (c: unknown): void => {
    if (c === null || typeof c !== 'object') return;
    const o = c as Record<string, unknown>;
    if (typeof o.field === 'string' && o.field.startsWith('action.params.')) out.add(o.field);
    for (const k of ['all_of', 'any_of']) if (Array.isArray(o[k])) (o[k] as unknown[]).forEach(walk);
    if (o.not) walk(o.not);
  };
  if (Array.isArray(p.where)) p.where.forEach(walk);
  return [...out];
}

/** Decision of every case under `policy` (for a table in a PR comment). */
export function decideAll(policy: PolicyInput, doc: PolicyTestDoc): AnalyzerDecision[] {
  const model = toModel(policy);
  return doc.cases.map((c) => decideAction(model, c.action));
}
