/**
 * Missing-X -> result tables for forbid-certificate, policy-link, policy-sim and policy-debug (the cases the shared vectors
 * and the module tests do not name). Each row asserts the whole result.
 */
import { describe, expect, it } from 'vitest';
import { certificateConsistent, certify, checkForbidCertificate, decideClauses, type PolicyClause } from './forbid-certificate';
import { createLink, instantiateTemplate, resolveLink, signTemplate, signTighten, templateDigest, verifyLinkedPolicy, verifyTighten, type TemplateRegistry } from './policy-link';
import { compilePolicy } from './facade';
import { simulate } from './policy-sim';
import { counterfactual, explainDecision, explainRisk } from './policy-debug';
import { decide } from './policy-vm';
import { DEFAULT_RISK_POLICY, type RiskInputs } from './risk';
import type { ActionContext } from './predicates';
import { CLAUSES } from './test-support/forbid-certificate-vectors';
import { PUB, TEMPLATE } from './test-support/policy-link-vectors';

const act = (verb: string, resource: string, params?: Record<string, unknown>): ActionContext => ({ action: { verb, resource, ...(params ? { params } : {}) } });
const MALFORMED = { decision: 'deny', witness: { winner: { kind: 'malformed', id: null }, shadowed: [] }, values: [] };

describe('forbid-certificate: missing X -> result', () => {
  it('clauses that are not an array, or an action with no verb or resource, decide as the malformed deny', () => {
    expect(decideClauses(null as never, act('a', 'b'))).toEqual(MALFORMED);
    expect(decideClauses(CLAUSES, undefined as never)).toEqual(MALFORMED);
    expect(decideClauses(CLAUSES, {} as never)).toEqual(MALFORMED);
    expect(decideClauses(CLAUSES, { action: { verb: 'pay.send' } } as never)).toEqual(MALFORMED);
    expect(decideClauses(CLAUSES, { action: { verb: 1, resource: 'r' } } as never)).toEqual(MALFORMED);
  });

  it('a predicate that throws while it is evaluated never matches: a permit that throws leaves the default deny', () => {
    const boom: PolicyClause = { id: 'p', kind: 'permit', when: Object.defineProperty({}, 'verb', { enumerable: true, get() { throw new Error('boom'); } }) as never };
    expect(decideClauses([boom], act('pay.send', '/x'))).toEqual({ decision: 'deny', witness: { winner: { kind: 'none', id: null }, shadowed: [] }, values: [{ id: 'p', kind: 'permit', value: 'false' }] });
  });

  it('the certificate of a malformed request is the table-less deny; against a well formed request it does not match', () => {
    const cert = certify(CLAUSES, {} as never);
    expect(cert.decision).toBe('deny');
    expect(cert.winner).toEqual({ kind: 'malformed', id: null });
    expect(cert.shadowed).toEqual([]);
    expect(cert.clauses).toEqual([]);
    expect(certificateConsistent(cert)).toBe(true);
    expect(checkForbidCertificate(cert, CLAUSES, act('pay.send', '/acct/1', { amount: 1 }))).toEqual({ ok: false, reason: 'certificate does not match the recomputed decision' });
  });

  it('a malformed-winner certificate without a shadowed list is inconsistent', () => {
    const noShadow = { v: 1, kind: 'forbid-wins', policy: 'p', action: 'a', decision: 'deny', winner: { kind: 'malformed', id: null }, clauses: [] };
    expect(certificateConsistent(noShadow as never)).toBe(false);
    expect(certificateConsistent({ ...noShadow, shadowed: [], clauses: undefined } as never)).toBe(false);
  });
});

describe('policy-link: missing X -> result', () => {
  const secret = new Uint8Array(32).fill(7);
  const slots = { acct: 'a42', cap: 200, region: 'eu', verbs: ['mail.draft', 'mail.send'] };
  const signed = signTemplate(TEMPLATE, secret, PUB);
  const digest = templateDigest(TEMPLATE);
  const reg: TemplateRegistry = { templates: { [digest]: signed }, trusted: [PUB] };
  const ref = createLink(TEMPLATE, slots);

  it('no registry at all, or a reference to a version the registry lacks', () => {
    expect(resolveLink(ref, undefined as never)).toEqual({ ok: false, reason: 'link resolution error (fail closed)' });
    expect(resolveLink(ref, { templates: {}, trusted: [PUB] })).toEqual({ ok: false, reason: 'template version is not in the registry' });
    expect(verifyLinkedPolicy({ template_ref: ref, predicates: [], caveats: [] }, { templates: {}, trusted: [PUB] })).toEqual({ ok: false, reason: 'template version is not in the registry' });
  });

  it('an empty trust list refuses an otherwise valid template', () => {
    expect(resolveLink(ref, { templates: { [digest]: signed }, trusted: [] })).toEqual({ ok: false, reason: 'template signer is not trusted' });
  });

  it('a registry entry filed under another version digest is refused', () => {
    const other = signTemplate({ ...TEMPLATE, version: '9' }, secret, PUB);
    expect(resolveLink(ref, { templates: { [digest]: other }, trusted: [PUB] })).toEqual({ ok: false, reason: 'registry entry does not match its digest' });
  });

  it('a reference naming another template id than the signed template is refused', () => {
    expect(resolveLink({ ...ref, template_id: 'other_id' }, reg)).toEqual({ ok: false, reason: 'template id does not match the reference' });
  });

  it('a non-object envelope, slots that are not an object, and a missing overlay are refused', () => {
    expect(verifyLinkedPolicy(null as never, reg)).toEqual({ ok: false, reason: 'link verification error (fail closed)' });
    expect(instantiateTemplate(TEMPLATE, null as never)).toEqual({ ok: false, reason: 'slots must be an object' });
    expect(verifyTighten(undefined as never, [PUB])).toEqual({ ok: false, reason: 'overlay must be an object' });
  });

  it('an overlay signed by an untrusted key that names this version is a refusal, not a silent skip', () => {
    const overlay = signTighten({ v: 1, kind: 'pca-template-tighten', template_id: TEMPLATE.id, version_digest: digest, add_where: [{ field: 'env.tier', op: 'ne', value: 'frozen' }] }, secret, 'AAAA');
    expect(resolveLink(ref, { ...reg, overlays: [overlay] })).toEqual({ ok: false, reason: 'overlay signer is not trusted' });
  });

  it('createLink refuses slots the template refuses', () => {
    expect(() => createLink(TEMPLATE, { ...slots, cap: 'x' })).toThrow(/^createLink: /);
  });
});

describe('policy-sim: missing X -> result', () => {
  const policy = compilePolicy({ permissions: { gmail: ['send'] }, now: 0 });
  const B = policy.riskPolicy.bMax;

  it('no actions is an empty report with the full budget', () => {
    expect(simulate(policy, [])).toEqual({ results: [], auto: 0, stepUp: 0, deny: 0, endBudget: B, peakRisk: 0, autonomousRisk: 0 });
  });

  it('an action with no finite time is denied with risk 1, not replayed', () => {
    for (const at of [Number.NaN, Number.POSITIVE_INFINITY]) {
      const a = { verb: 'gmail.send', resource: 'm:1', at };
      expect(simulate(policy, [a])).toEqual({
        results: [{ action: a, outcome: 'deny', r: 1, reason: 'action has no finite time', budgetAfter: B }],
        auto: 0,
        stepUp: 0,
        deny: 1,
        endBudget: B,
        peakRisk: 0,
        autonomousRisk: 0,
      });
    }
  });

  it('an ungranted verb is denied and spends nothing', () => {
    const rep = simulate(policy, [{ verb: 'gmail.delete', resource: 'm:1', at: 1 }]);
    expect(rep.results.map((r) => r.outcome)).toEqual(['deny']);
    expect(rep.auto).toBe(0);
    expect(rep.autonomousRisk).toBe(0);
  });
});

describe('policy-debug: missing X -> result', () => {
  const lowRisk: RiskInputs = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
  const nan = Number.NaN;

  it('non-finite risk inputs are the worst case of their term, so r saturates to 1', () => {
    const e = explainRisk({ semanticDistance: nan, reversibility: nan, blastRadius: nan, taint: nan, confidence: nan, age: nan }, DEFAULT_RISK_POLICY.weights);
    expect(e.terms.map((t) => [t.term, t.input])).toEqual([['semanticDistance', 1], ['reversibility', 0], ['blastRadius', 1], ['taint', 1], ['confidence', 0], ['age', 1]]);
    expect(e.r).toBe(1);
    expect(explainRisk({ ...lowRisk, reversibility: Number.POSITIVE_INFINITY }, DEFAULT_RISK_POLICY.weights).terms[1]!.input).toBe(0);
  });

  it('a non-finite caution floor counts as no floor', () => {
    const e = explainRisk(lowRisk, DEFAULT_RISK_POLICY.weights, nan);
    expect(e.rFloor).toBe(0);
    expect(e.r).toBe(e.rScore);
  });

  it('no deltas is an empty counterfactual over the baseline', () => {
    const now = 1_000_000;
    const input = { grant: { id: 'x', issuer: 'i', holder: 'h', caveats: [] } as never, action: { action: { verb: 'v', resource: 'r', params: {} } }, risk: lowRisk, budget: { B: 1, tau: now, asOf: now }, now };
    const rep = counterfactual(input, []);
    expect(rep.outcomes).toEqual([]);
    expect(rep.flipping).toEqual([]);
    expect(rep.thresholdChanging).toEqual([]);
    expect(rep.baseline).toEqual(explainDecision(input));
    expect(rep.baseline.autoAllow).toBe(decide(input).admit);
    expect(rep.baseline.autoAllow).toBe(false);
  });
});
