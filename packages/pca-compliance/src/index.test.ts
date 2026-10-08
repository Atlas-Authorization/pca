import { describe, expect, it } from 'vitest';
import {
  type Capability,
  type CapabilityChain,
  type PCActn,
  type PlanNode,
  type PolicyDecision,
  type Signer,
  type ThresholdSignature,
  type VerifyResult,
  DEFAULT_RISK_POLICY,
  assembleThreshold,
  attenuate,
  budgetAllocCaveat,
  buildPCActn,
  decide,
  delegate,
  encodeKey,
  generateKeyPair,
  mintGrant,
  mintRoot,
  requiredThreshold,
  signShare,
  thresholdMessage,
  verifyPCActnCore,
} from '@atlasauth/pca';
import {
  type AuditEvent,
  type ComplianceFramework,
  COMPLIANCE_FRAMEWORKS,
  CONTROL_MAPPINGS,
  controlMappings,
  renderJson,
  renderMarkdown,
  toAuditEvent,
  toComplianceReport,
} from './index';

// A fixed clock so every fixture is deterministic and the reporting period is stable.
const NOW = 1_800_000_000_000;
const AUD = 'rs-prod-1';

// ---------------------------------------------------------------------------------------------------
// Fixtures — REAL verified PCActns built with the core, one per auditor-facing outcome.
// ---------------------------------------------------------------------------------------------------

/** Keys: Principal (root) → Agent (delegate) → Sub-agent (leaf holder that acts), + a Guardian. */
function keys() {
  return {
    principal: generateKeyPair(),
    agent: generateKeyPair(),
    sub: generateKeyPair(),
    guardian: generateKeyPair(),
  };
}

const PLAN: PlanNode[] = [
  { id: 'n-refund', verb: 'stripe.refund', resource: 'charge/ch_1', reversibility_class: 'reversible' },
  { id: 'n-delete', verb: 'account.delete', resource: 'acct/ac_9', reversibility_class: 'irreversible' },
];

/** Mint a real envelope grant (principal → agent) that permits the refund verb. */
function mintEnvelopeGrant(k: ReturnType<typeof keys>): Capability {
  const { grant } = mintGrant({
    principalSecret: k.principal.secretKey,
    principalPublic: encodeKey(k.principal.publicKey),
    holder: encodeKey(k.agent.publicKey),
    goal: 'process customer refunds',
    envelope: {
      predicates: [
        { verb: 'stripe.refund', resource: 'charge/*' },
        { verb: 'account.delete', resource: 'acct/*' },
      ],
      caveats: [],
      agent_binding: {},
      risk_policy: DEFAULT_RISK_POLICY,
    },
  });
  return grant;
}

/** A real three-hop chain: root envelope grant → attenuated agent hop → sub-agent leaf. */
function buildChain(k: ReturnType<typeof keys>, grant: Capability): CapabilityChain {
  // Agent narrows its own authority with a per-subtree budget allocation (a real attenuating caveat).
  const agentHop = attenuate(grant, [budgetAllocCaveat(0.5)], k.agent.secretKey);
  // Agent delegates to the sub-agent that will actually act (rebind holder).
  const leaf = delegate(agentHop, encodeKey(k.sub.publicKey), [], k.agent.secretKey);
  return [grant, agentHop, leaf];
}

/** Build + sign a real PCActn for a plan node, signed by the sub-agent (leaf holder). */
function buildActn(
  k: ReturnType<typeof keys>,
  grant: Capability,
  chain: CapabilityChain,
  nodeId: string,
  opts: { threshold?: ThresholdSignature; counter?: number } = {},
): PCActn {
  const actn = buildPCActn({
    grant,
    chain,
    plan: PLAN,
    nodeId,
    counter: opts.counter ?? 1,
    signerSecret: k.sub.secretKey,
    aud: AUD,
    iat: NOW,
    exp: NOW + 60_000,
  });
  if (opts.threshold) return { ...actn, threshold: opts.threshold };
  return actn;
}

/** Build a real principal+guardian threshold co-signature over a PCActn (the signed human-override). */
function coSign(k: ReturnType<typeof keys>, actn: PCActn): ThresholdSignature {
  const signerSet: Signer[] = [
    { role: 'agent', publicKey: encodeKey(k.sub.publicKey) },
    { role: 'guardian', publicKey: encodeKey(k.guardian.publicKey) },
    { role: 'principal', publicKey: encodeKey(k.principal.publicKey) },
  ];
  const msg = thresholdMessage(actn);
  const t = 3;
  const agentShare = signShare('agent', k.sub.secretKey, msg);
  const guardianShare = signShare('guardian', k.guardian.secretKey, msg, { signerSet, t });
  const principalShare = signShare('principal', k.principal.secretKey, msg, { signerSet, t });
  return assembleThreshold([agentShare, guardianShare, principalShare]);
}

interface Fixture {
  event: AuditEvent;
  verify: VerifyResult;
  decision?: PolicyDecision;
}

/** ALLOW — a low-risk refund, auto-admitted by the real Policy VM. */
async function allowFixture(): Promise<Fixture> {
  const k = keys();
  const grant = mintEnvelopeGrant(k);
  const chain = buildChain(k, grant);
  const actn = buildActn(k, grant, chain, 'n-refund');
  const verify = await verifyPCActnCore(actn, { grant, nowEpoch: NOW, audience: AUD });
  const decision = decide({
    grant,
    chain,
    action: { action: { verb: 'stripe.refund', resource: 'charge/ch_1' } },
    plan: PLAN,
    risk: { semanticDistance: 0.05, reversibility: 1, blastRadius: 0.05, taint: 0, confidence: 1 },
    budget: { B: 1, tau: NOW },
    now: NOW,
    nodeId: 'n-refund',
  });
  const event = toAuditEvent({ pcactn: actn, verify, decision, now: NOW });
  return { event, verify, decision };
}

/** DENY — a tampered PCActn: the core verifier rejects it (real deny from the core). */
async function denyFixture(): Promise<Fixture> {
  const k = keys();
  const grant = mintEnvelopeGrant(k);
  const chain = buildChain(k, grant);
  const actn = buildActn(k, grant, chain, 'n-refund', { counter: 2 });
  // Tamper with the signed action AFTER signing: plan-inclusion + leaf-signature must now fail.
  const tampered: PCActn = { ...actn, action: { ...actn.action, resource: 'charge/ch_ATTACKER' } };
  const verify = await verifyPCActnCore(tampered, { grant, nowEpoch: NOW, audience: AUD });
  const event = toAuditEvent({ pcactn: tampered, verify, now: NOW });
  return { event, verify };
}

/** STEP-UP (approved) — a high-risk irreversible action, released by a signed principal co-signature. */
async function stepUpFixture(): Promise<Fixture> {
  const k = keys();
  const grant = mintEnvelopeGrant(k);
  const chain = buildChain(k, grant);
  const base = buildActn(k, grant, chain, 'n-delete', { counter: 3 });
  const threshold = coSign(k, base);
  const actn = buildActn(k, grant, chain, 'n-delete', { threshold, counter: 3 });
  const verify = await verifyPCActnCore(actn, { grant, nowEpoch: NOW, audience: AUD });
  // A step-up decision: policy satisfied, but a co-signature is required (and here, supplied).
  const rt = requiredThreshold(0.9, DEFAULT_RISK_POLICY, { irreversible: true });
  const decision: PolicyDecision = {
    releaseGuardianShare: true,
    requiredThreshold: rt,
    r: 0.9,
    admit: false,
    needStepUp: true,
    reasons: ['high-risk irreversible action requires human co-signature'],
    budget: { B: 1, tau: NOW },
  };
  const event = toAuditEvent({ pcactn: actn, verify, decision, now: NOW });
  return { event, verify, decision };
}

// ---------------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------------

describe('toAuditEvent — normalizes a verified PCActn + decision', () => {
  it('ALLOW: records agent/principal, the full delegation chain, decision + evidence', async () => {
    const { event, verify } = await allowFixture();
    expect(verify.allow).toBe(true);
    expect(event.schema).toBe('atlas-pca/audit-event/v1');
    expect(event.decision.outcome).toBe('allow');
    expect(event.decision.proofVerified).toBe(true);
    expect(event.action.verb).toBe('stripe.refund');
    expect(event.action.resource).toBe('charge/ch_1');

    // Delegation chain: 3 hops (root + agent + leaf), depth 2, each with issuer→holder.
    expect(event.delegation.hops).toHaveLength(3);
    expect(event.delegation.depth).toBe(2);
    expect(event.delegation.hops[0]?.isRoot).toBe(true);
    const leafHop = event.delegation.hops[2];
    expect(leafHop?.holder).toBe(event.agent.holder);
    // The agent hop added a budget_alloc caveat — the scope it narrowed is captured.
    const agentHop = event.delegation.hops[1];
    expect(agentHop?.budgetAlloc).toBe(0.5);
    expect(agentHop?.scope.some((s) => s.includes('budget allocation'))).toBe(true);

    // Cryptographic evidence binds the entry to a real, verifiable proof.
    expect(event.evidence.cryptographicallyVerifiable).toBe(true);
    expect(event.evidence.pcactnDigest).not.toBe('(undigestible)');
    expect(event.evidence.leafSignature).not.toBe('(unsigned)');
    expect(event.evidence.planRoot).not.toBe('(none)');

    // Risk/tier/budget drawn from the real Policy-VM decision.
    expect(typeof event.risk.r).toBe('number');
    expect(event.risk.tier).toBe(1);
    expect(event.humanOverride).toBeUndefined();
  });

  it('DENY: a tampered PCActn fails core verification and is recorded as a deny', async () => {
    const { event, verify } = await denyFixture();
    expect(verify.allow).toBe(false);
    expect(event.decision.outcome).toBe('deny');
    expect(event.decision.proofVerified).toBe(false);
    // At least one normative check failed (plan inclusion / leaf signature).
    const failed = Object.values(event.decision.checks).filter((s) => s === 'fail');
    expect(failed.length).toBeGreaterThan(0);
    expect(event.evidence.cryptographicallyVerifiable).toBe(false);
  });

  it('STEP-UP: a signed principal co-signature is surfaced as the human-override', async () => {
    const { event, verify } = await stepUpFixture();
    expect(verify.allow).toBe(true);
    expect(event.decision.outcome).toBe('step-up');
    expect(event.humanOverride).toBeDefined();
    expect(event.humanOverride?.humanApproved).toBe(true);
    expect(event.humanOverride?.approvers).toHaveLength(1);
    expect(event.humanOverride?.guardianCosigners).toHaveLength(1);
    expect(event.humanOverride?.roles).toContain('principal');
    expect(event.humanOverride?.requiredTier).toBe(3);
    expect(event.risk.tier).toBe(3);
  });

  it('is total: a malformed input degrades rather than throwing', () => {
    const empty: Partial<PCActn> = {};
    const event = toAuditEvent({ pcactn: empty as PCActn, verify: { allow: false, checks: {} }, now: NOW });
    expect(event.decision.outcome).toBe('deny');
    expect(event.delegation.hops).toHaveLength(0);
    expect(event.agent.principal).toBeUndefined();
    expect(event.action.verb).toBe('(unknown verb)');
  });
});

describe('CONTROL_MAPPINGS — the exported, auditable table', () => {
  it('covers EU AI Act Art. 12 + Art. 50, ISO 42001 clauses, and SOC 2 CC6', () => {
    const ids = CONTROL_MAPPINGS.map((m) => m.controlId);
    expect(ids).toContain('eu-ai-act:art-12');
    expect(ids).toContain('eu-ai-act:art-50');
    expect(ids).toContain('iso-42001:A.6.2.8'); // reasoning trace
    expect(ids).toContain('iso-42001:A.9.2'); // delegation
    expect(ids).toContain('iso-42001:A.9.3'); // human oversight
    expect(ids).toContain('iso-42001:A.6.2.2'); // intended use
    expect(ids).toContain('soc2:CC6.1');
    expect(ids).toContain('soc2:CC6.2');
    expect(ids).toContain('soc2:CC6.3');
    // Every clause reference is non-empty and cites the right framework language.
    expect(CONTROL_MAPPINGS.find((m) => m.controlId === 'eu-ai-act:art-12')?.clause).toMatch(/Article 12/);
    expect(CONTROL_MAPPINGS.find((m) => m.controlId === 'eu-ai-act:art-50')?.clause).toMatch(/Article 50/);
  });

  it('controlMappings(framework) filters to one framework; no framework returns all', () => {
    for (const fw of COMPLIANCE_FRAMEWORKS) {
      const rows = controlMappings(fw);
      expect(rows.length).toBeGreaterThan(0);
      expect(rows.every((r) => r.framework === fw)).toBe(true);
    }
    expect(controlMappings()).toHaveLength(CONTROL_MAPPINGS.length);
  });

  it('rejects an unknown framework', () => {
    const bad: string = 'nist-csf';
    expect(() => controlMappings(bad as ComplianceFramework)).toThrow();
  });
});

describe('toComplianceReport — maps events onto a framework with coverage + assurances', () => {
  async function allEvents(): Promise<AuditEvent[]> {
    const [a, d, s] = await Promise.all([allowFixture(), denyFixture(), stepUpFixture()]);
    return [a.event, d.event, s.event];
  }

  it('eu-ai-act: Art. 12 verifiability + Art. 50 disclosure, correct control ids', async () => {
    const report = toComplianceReport(await allEvents(), { framework: 'eu-ai-act', now: NOW });
    expect(report.framework).toBe('eu-ai-act');
    expect(report.eventCount).toBe(3);
    const ids = report.items.map((i) => i.controlId);
    expect(ids).toEqual(['eu-ai-act:art-12', 'eu-ai-act:art-50']);

    // Art. 12: all three entries cite a verifiable proof? The deny is a tampered proof (not verifiable),
    // so Art. 12 is PARTIAL (2/3 verifiable) — the report is honest about it.
    const art12 = report.items.find((i) => i.controlId === 'eu-ai-act:art-12');
    expect(art12?.status).toBe('partial');
    expect(art12?.evidence).toMatch(/2\/3/);

    // Art. 50: every action discloses agent + principal + decision.
    const art50 = report.items.find((i) => i.controlId === 'eu-ai-act:art-50');
    expect(art50?.status).toBe('satisfied');

    // Assurances + period.
    expect(report.assurances.cryptographicallyVerifiable).toBe(false); // tampered deny present
    expect(report.assurances.explicitDelegationChain).toBe(true);
    expect(report.assurances.signedHumanOverrides).toBe(true);
    expect(report.period.from.epochMs).toBe(NOW);
  });

  it('iso-42001: reasoning-trace, delegation chain, and SIGNED human oversight', async () => {
    const report = toComplianceReport(await allEvents(), { framework: 'iso-42001', now: NOW });
    const ids = report.items.map((i) => i.controlId);
    expect(ids).toEqual(['iso-42001:A.6.2.8', 'iso-42001:A.9.2', 'iso-42001:A.9.3', 'iso-42001:A.6.2.2']);

    // Delegation chain satisfied: all 3 events carry a chain (max depth 2).
    const deleg = report.items.find((i) => i.controlId === 'iso-42001:A.9.2');
    expect(deleg?.status).toBe('satisfied');
    expect(deleg?.evidence).toMatch(/max depth 2/);

    // Human oversight satisfied: a signed principal co-signature was exercised.
    const oversight = report.items.find((i) => i.controlId === 'iso-42001:A.9.3');
    expect(oversight?.status).toBe('satisfied');
    expect(oversight?.evidence).toMatch(/signed human co-signature/);

    // Intended-use: all actions bound to a committed plan root.
    const intended = report.items.find((i) => i.controlId === 'iso-42001:A.6.2.2');
    expect(intended?.status).toBe('satisfied');
    expect(intended?.evidence).toMatch(/3\/3/);
  });

  it('soc2: CC6.1/6.2/6.3 — deny-by-default, traceability, attenuation', async () => {
    const report = toComplianceReport(await allEvents(), { framework: 'soc2', now: NOW });
    const ids = report.items.map((i) => i.controlId);
    expect(ids).toEqual(['soc2:CC6.1', 'soc2:CC6.2', 'soc2:CC6.3']);

    const cc61 = report.items.find((i) => i.controlId === 'soc2:CC6.1');
    expect(cc61?.status).toBe('satisfied');
    expect(cc61?.findings.some((f) => /denied/.test(f))).toBe(true); // the tampered deny shows enforcement

    const cc62 = report.items.find((i) => i.controlId === 'soc2:CC6.2');
    expect(cc62?.status).toBe('satisfied');

    const cc63 = report.items.find((i) => i.controlId === 'soc2:CC6.3');
    expect(cc63?.status).toBe('satisfied'); // attenuating hop (budget_alloc) + a denial present
  });

  it('coverage summary counts satisfied/partial/not-evidenced correctly', async () => {
    const report = toComplianceReport(await allEvents(), { framework: 'eu-ai-act', now: NOW });
    const { coverage } = report;
    expect(coverage.total).toBe(report.items.length);
    expect(coverage.satisfied + coverage.partial + coverage.notEvidenced).toBe(coverage.total);
    const satisfied = report.items.filter((i) => i.status === 'satisfied').length;
    expect(coverage.satisfied).toBe(satisfied);
    expect(coverage.satisfiedPercent).toBe(Math.round((satisfied / coverage.total) * 100));
  });

  it('empty event set: every control is not-evidenced, assurances off', () => {
    const report = toComplianceReport([], { framework: 'iso-42001', now: NOW });
    expect(report.eventCount).toBe(0);
    expect(report.items.every((i) => i.status === 'not-evidenced')).toBe(true);
    expect(report.coverage.satisfied).toBe(0);
    expect(report.assurances.cryptographicallyVerifiable).toBe(false);
    expect(report.assurances.narrative).toMatch(/No events/);
  });

  it('rejects an unknown framework', async () => {
    const events = await allEvents();
    const bad: string = 'pci-dss';
    expect(() => toComplianceReport(events, { framework: bad as ComplianceFramework })).toThrow();
  });
});

describe('renderers', () => {
  async function report() {
    const [a, d, s] = await Promise.all([allowFixture(), denyFixture(), stepUpFixture()]);
    return toComplianceReport([a.event, d.event, s.event], { framework: 'eu-ai-act', now: NOW });
  }

  it('renderMarkdown produces an auditor-facing document with the control table + assurances', async () => {
    const md = renderMarkdown(await report());
    expect(md).toMatch(/# PCA compliance evidence — eu-ai-act/);
    expect(md).toMatch(/Why this trail is admissible/);
    expect(md).toMatch(/Cryptographically verifiable/);
    expect(md).toMatch(/Explicit delegation chain/);
    expect(md).toMatch(/Signed human-overrides/);
    expect(md).toMatch(/## Coverage summary/);
    expect(md).toMatch(/eu-ai-act:art-12/);
    expect(md).toMatch(/EU AI Act, Article 50/);
    expect(md).toMatch(/not a legal certification/);
  });

  it('renderJson round-trips to the same structured report', async () => {
    const r = await report();
    const json = renderJson(r);
    const parsed = JSON.parse(json) as typeof r;
    expect(parsed.schema).toBe('atlas-pca/compliance-report/v1');
    expect(parsed.framework).toBe('eu-ai-act');
    expect(parsed.items.map((i) => i.controlId)).toEqual(r.items.map((i) => i.controlId));
    expect(parsed.coverage).toEqual(r.coverage);
  });
});
