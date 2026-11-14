import { describe, expect, it } from 'vitest';
import { mintRoot } from '../capability';
import { buildCatalog, defineAction } from '../catalog';
import { CATALOG_REVERSIBILITY_SCORE, catalogRisk } from '../catalog-risk';
import { mintGrant } from '../envelope';
import { encodeKey, generateKeyPair } from '../keys';
import { paramsDigest, type PlanNode } from '../merkle';
import { buildPCActn, encodePCActn, type PCActn } from '../pcactn';
import { DEFAULT_RISK_POLICY, requiredThreshold, riskScore, type RiskInputs, type RiskPolicy } from '../risk';
import { InMemoryTrustedInputRegistry } from '../taint';
import { authorize, type AuthorizeOptions, type AuthorizeResult } from './authorize';
import { memoryPcaStore, requirePCA } from './require-pca';
import { verifyPCActn, type PcaOperation } from './verify';
import { principalDirect } from '../test-support/provenance';

const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const AUD = 'rs-risk';

function setup(verb: string, policy: RiskPolicy = { ...DEFAULT_RISK_POLICY, bMax: 1000 }) {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const { grant } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    holder: encodeKey(holder.publicKey),
    goal: 'work',
    envelope: { predicates: [{ verb, resource: '*' }], caveats: [], agent_binding: {}, risk_policy: policy },
  });
  const sign = (o: PcaOperation, extra: Partial<Parameters<typeof buildPCActn>[0]> = {}): PCActn => {
    const node: PlanNode = { id: 'n1', verb: o.verb, resource: o.resource, params_digest: paramsDigest(o.params), reversibility_class: 'reversible' };
    return buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params: o.params, counter: 1, signerSecret: holder.secretKey, aud: AUD, now: NOW, ...extra });
  };
  const opts = (over: Partial<AuthorizeOptions> = {}): AuthorizeOptions => ({
    provenance: principalDirect(),
    audience: AUD,
    resolveGrant: async () => grant,
    budgetStore: memoryPcaStore(),
    hooks: { revocation: () => ({ enforced: true, ok: true }) },
    plan: 'single-step',
    now: () => NOW,
    ...over,
  });
  return { grant, sign, opts };
}

const failed = (r: AuthorizeResult) =>
  Object.entries(r.verdict.checks)
    .filter(([, s]) => s === 'fail')
    .map(([k]) => k)
    .sort();

describe('T4: the agent cannot lower the server-derived risk', () => {
  // fixed server inputs for one fixed operation; semanticDistance comes from the single-step plan (0), age from the
  // freshly seeded budget (0)
  const SERVER: Partial<RiskInputs> = { reversibility: 0.5, blastRadius: 0.3, taint: 0.5, confidence: 0.8 };
  const serverR = riskScore({ semanticDistance: 0, age: 0, ...SERVER } as RiskInputs, DEFAULT_RISK_POLICY.weights);
  const OP: PcaOperation = { verb: 'docs.update', resource: 'doc:1', params: { title: 't' } };

  const claims: { name: string; extra: Partial<Parameters<typeof buildPCActn>[0]>; caution: number }[] = [];
  for (const r of [0, 1])
    for (const inputs of [{}, { blastRadius: 0, taint: 0, reversibility: 1, confidence: 1, semanticDistance: 0 }])
      for (const caution of [undefined, 0, 0.9])
        for (const taint of [0, 1])
          claims.push({
            name: `risk_claim.r=${r} inputs=${Object.keys(inputs).length ? 'all-benign' : 'none'} caution=${String(caution)} taint_level=${taint}`,
            extra: { riskClaim: { r, inputs }, provenance: { causal_hash: '', taint_level: taint, trusted_refs: [] }, ...(caution !== undefined ? { caution } : {}) },
            caution: caution ?? 0,
          });

  it('server-only risk is what the formula gives for the server inputs (sanity)', () => {
    expect(serverR).toBeCloseTo(0.25 * 0 + 0.2 * 0.5 + 0.2 * 0.3 + 0.2 * 0.5 + 0.1 * 0.2, 12);
  });

  it(`over ${2 * 2 * 3 * 2} agent claims: r = max(server r, signed caution) and t never drops below the server-only t`, async () => {
    const { sign, opts } = setup(OP.verb);
    const serverT = requiredThreshold(serverR, DEFAULT_RISK_POLICY).t;
    const rows: string[] = [];
    for (const c of claims) {
      const r = await authorize({ pcactn: sign(OP, c.extra), operation: OP }, opts({ risk: () => SERVER }));
      const want = Math.max(serverR, c.caution);
      const ok = r.verdict.r === want && r.verdict.r >= serverR && r.verdict.requiredThreshold.t >= serverT && r.verdict.requiredThreshold.t === requiredThreshold(want, DEFAULT_RISK_POLICY).t;
      if (!ok) rows.push(`${c.name}: r=${r.verdict.r} t=${r.verdict.requiredThreshold.t}`);
    }
    expect(rows).toEqual([]);
  });

  it('a context() risk cannot lower the `risk` option and vice versa (riskier input wins)', async () => {
    const { sign, opts } = setup(OP.verb);
    const benign = { reversibility: 1, blastRadius: 0, taint: 0, confidence: 1 };
    const a = await authorize({ pcactn: sign(OP), operation: OP }, opts({ risk: () => SERVER, context: () => ({ risk: benign }) }));
    const b = await authorize({ pcactn: sign(OP), operation: OP }, opts({ risk: () => benign, context: () => ({ risk: SERVER }) }));
    expect([a.verdict.r, b.verdict.r]).toEqual([serverR, serverR]);
  });
});

describe('T4: requireRiskInputs (fail closed with a name, not a worst-case price)', () => {
  const OP: PcaOperation = { verb: 'docs.update', resource: 'doc:1', params: { title: 't' } };

  it('denies with the missing input named; passes once the server supplies it', async () => {
    const { sign, opts } = setup(OP.verb);
    const none = await authorize({ pcactn: sign(OP), operation: OP }, opts({ requireRiskInputs: ['blastRadius', 'taint'], risk: () => ({ taint: 0 }) }));
    expect(failed(none)).toContain('risk_inputs');
    expect(none.verdict.reasons).toContain('risk_inputs: required risk input(s) not supplied by the server: blastRadius');
    const some = await authorize({ pcactn: sign(OP), operation: OP }, opts({ requireRiskInputs: ['blastRadius', 'taint'], risk: () => ({ blastRadius: 0, taint: 0, reversibility: 1, confidence: 1 }) }));
    expect(some.verdict.checks.risk_inputs).toBe('pass');
  });

  it('semanticDistance counts as supplied when the server knows the plan; a non-finite value does not count', async () => {
    const { sign, opts } = setup(OP.verb);
    const r = await authorize({ pcactn: sign(OP), operation: OP }, opts({ requireRiskInputs: ['semanticDistance', 'blastRadius'], risk: () => ({ blastRadius: Number.NaN }) }));
    expect(r.verdict.reasons).toContain('risk_inputs: required risk input(s) not supplied by the server: blastRadius');
  });

  it('verifyPCActn: the option alone (no requirePCA)', async () => {
    const { grant, sign } = setup(OP.verb);
    const v = await verifyPCActn(sign(OP), { insecureSkipPlanRootCheck: true, grant, audience: AUD, now: NOW, context: { params: OP.params }, requireRiskInputs: ['confidence'] });
    expect([v.allow, v.checks.risk_inputs]).toEqual([false, 'fail']);
    const off = await verifyPCActn(sign(OP), { insecureSkipPlanRootCheck: true, grant, audience: AUD, now: NOW, context: { params: OP.params } });
    expect(off.checks.risk_inputs).toBeUndefined();
  });

  it('requirePCA forwards it (also under a custom `require` list)', async () => {
    const { grant, sign } = setup(OP.verb);
    const guard = requirePCA({ audience: AUD, resolveGrant: async () => grant, insecureAllowUnboundOperation: true, now: () => NOW, require: [], requireRiskInputs: ['blastRadius'], context: () => ({ params: OP.params }) });
    const p = sign(OP);
    const r = await guard({ headers: { 'pca-action': Buffer.from(encodePCActn(p)).toString('base64url') } });
    expect(r.ok ? 'ok' : r.verdict.checks.risk_inputs).toBe('fail');
  });
});

describe('T4: core gates reachable through requirePCA / authorize (`enforce`)', () => {
  const OP: PcaOperation = { verb: 'docs.update', resource: 'doc:1', params: { title: 't' } };
  const registry = (trusted: string[]) => {
    const r = new InMemoryTrustedInputRegistry();
    for (const t of trusted) r.recordTrusted(t);
    return r;
  };
  const benign = () => ({ reversibility: 1, blastRadius: 0, taint: 0, confidence: 1 });

  it('enforce.taint: a forged "trusted" provenance (taint_level 0, refs the server never vouched for) is refused', async () => {
    const { sign, opts } = setup(OP.verb);
    const p = sign(OP, { provenance: { causal_hash: '', taint_level: 0, trusted_refs: ['mail:inbox/msg-17'] } });
    const forged = await authorize({ pcactn: p, operation: OP }, opts({ risk: benign, enforce: { taint: { ctx: { registry: registry(['records:inv-1']) }, maxTaint: 0.25 } } }));
    expect(failed(forged)).toEqual(['taint_gate']);
    const vouched = await authorize({ pcactn: sign(OP, { provenance: { causal_hash: '', taint_level: 0, trusted_refs: ['records:inv-1'] } }), operation: OP }, opts({ risk: benign, enforce: { taint: { ctx: { registry: registry(['records:inv-1']) }, maxTaint: 0.25 } } }));
    expect([vouched.allow, vouched.verdict.checks.taint_gate]).toEqual([true, 'pass']);
  });

  it('enforce.freshness: a stub freshness anchor is refused, and the failure is reported as freshness: fail', async () => {
    const { sign, opts } = setup(OP.verb);
    const r = await authorize({ pcactn: sign(OP), operation: OP }, opts({ risk: benign, enforce: { freshness: { maxAgeMs: 60_000 } } }));
    expect([failed(r), r.verdict.checks.freshness]).toEqual([['freshness'], 'fail']);
    expect(r.verdict.reasons[0]).toBe('freshness: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)');
  });

  it('enforce.attestation: a required attestation the verifier does not enforce is refused', async () => {
    const { sign, opts } = setup(OP.verb);
    const r = await authorize({ pcactn: sign(OP), operation: OP }, opts({ risk: benign, enforce: { attestation: { verifier: () => ({ enforced: false }) } } }));
    expect(failed(r)).toEqual(['attestation']);
  });

  it('without `enforce` the gates stay not-enforced (unchanged)', async () => {
    const { sign, opts } = setup(OP.verb);
    const r = await authorize({ pcactn: sign(OP), operation: OP }, opts({ risk: benign }));
    expect([r.allow, r.verdict.checks.taint_gate, r.verdict.checks.freshness]).toEqual([true, 'not-enforced', 'not-enforced']);
  });
});

describe('T4: catalogRisk', () => {
  const policy = (kappa: number): RiskPolicy => ({ ...DEFAULT_RISK_POLICY, kappa, bMax: 1000 });

  it('money: blast radius = amount / kappa from the operation params; catalog class for reversibility', () => {
    const { grant } = setup('stripe.refund', policy(500));
    // a refund is irreversible (one definition with the Goal IR ontology): reversibility score 0
    expect(catalogRisk('stripe.refund', { amount: 42 }, grant)).toEqual({ reversibility: 0, blastRadius: 42 / 500, confidence: 1 });
    expect(catalogRisk('stripe.refund', { amount: 5000 }, grant)).toEqual({ reversibility: 0, blastRadius: 1, confidence: 1 });
    for (const bad of [undefined, {}, { amount: '42' }, { amount: -1 }, { amount: Number.NaN }]) {
      expect(catalogRisk('stripe.refund', bad as never, grant).blastRadius).toBe(1);
    }
    // a grant without a readable risk policy (no envelope): no kappa to price against, so the worst case
    const k = generateKeyPair();
    const bare = mintRoot({ principalSecret: k.secretKey, principalPublic: encodeKey(k.publicKey), holder: encodeKey(k.publicKey), caveats: [] });
    expect(catalogRisk('stripe.refund', { amount: 1 }, bare).blastRadius).toBe(1);
  });

  it('non-money: the catalog presets; server taint only when supplied; unknown verb returns {}', () => {
    const { grant } = setup('http.get');
    expect(catalogRisk('http.get', {}, grant)).toEqual({ reversibility: 1, blastRadius: 0.05, confidence: 1 });
    expect(catalogRisk('gmail.send', {}, grant, { taint: 0.25 })).toEqual({ reversibility: 0, blastRadius: 0.8, confidence: 1, taint: 0.25 });
    expect(catalogRisk('gmail.send', {}, grant, { taint: 7 }).taint).toBe(1);
    expect(catalogRisk('nope.nope', { amount: 1 }, grant)).toEqual({});
    const custom = buildCatalog([defineAction({ connector: 'crm', action: 'note', reversibility: 'rate_limited', blastRadius: 0.3, description: 'x' })]);
    expect(catalogRisk('crm.note', {}, grant, { catalog: custom })).toEqual({ reversibility: 0.4, blastRadius: 0.3, confidence: 1 });
    expect(CATALOG_REVERSIBILITY_SCORE).toEqual({ reversible: 1, rate_limited: 0.4, costly: 0.4, irreversible: 0 });
    expect(Object.isFrozen(CATALOG_REVERSIBILITY_SCORE)).toBe(true);
  });

  it('a non-money reversible tool under the default risk policy no longer defaults to a co-sign', async () => {
    const OP: PcaOperation = { verb: 'stripe.create_customer', resource: 'customers', params: { email: 'a@example.com' } };
    const { sign, opts } = setup(OP.verb, DEFAULT_RISK_POLICY);
    const bare = await authorize({ pcactn: sign(OP), operation: OP }, opts());
    expect([failed(bare), bare.verdict.requiredThreshold.t]).toEqual([['threshold'], 3]);
    const priced = await authorize({ pcactn: sign(OP), operation: OP }, opts({ risk: (o, g) => catalogRisk(o!.verb, o!.params, g, { taint: 0 }) }));
    expect([priced.allow, priced.verdict.requiredThreshold.t]).toEqual([true, 1]);
  });
});
