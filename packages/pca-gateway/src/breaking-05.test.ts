// 0.5 (B4): the gateway is full-policy by default. A configuration without `policy` is refused; signature-only is an
// explicit mode that needs a replay guard and, by default, a revocation check.
import { describe, expect, it } from 'vitest';
import { agent, createProvenanceRecorder, principalDirectProvenance, type PcaOperation, generateKeyPair, pcaHeaders, PCA_HEADER, type Agent } from '@atlasauth/pca';
import { BUILTIN_ACTIONS, buildCatalog, defineAction } from '@atlasauth/pca/ext/research';
import { authorize, bindParams, createGateway, envoyExtAuthz, memoryPcaStore, memoryReplayGuard, requestBinding, type GatewayOptions, type GatewayRequest } from './index';

// Provenance by default: these tests are about the gateway's other checks, so every operation is presented as coming straight
// from the principal (a principal-direct bundle under a pinned harness key; the session log is off). The gateway's own provenance
// handling is tested in provenance.test.ts.
const provRec = () => createProvenanceRecorder({ mediator: 'test-harness', kid: 'k1', secretKey: new Uint8Array(32).fill(1) });
const PROV = {
  provenance: { mediators: [provRec().pin], bundle: (_r: unknown, _p: unknown, o: PcaOperation) => principalDirectProvenance(provRec(), { verb: o.verb, resource: o.resource, params: o.params ?? {} }) },
  provenanceLog: false as const,
};

// the built-in stripe.refund is irreversible (never auto-approved, even within a cap); the full-mode allow path below grants the rate-limited refund
const RATE_LIMITED_REFUND = buildCatalog([...BUILTIN_ACTIONS, defineAction({ connector: 'stripe', action: 'refund', reversibility: 'rate_limited', blastRadius: 0.9, amountField: 'amount', description: 'Refund a charge (rate-limited).' })]);
const AUD = 'ins_b4';
const PATH = '/refunds/ch_1';

function world() {
  const roots: string[] = [];
  const a: Agent = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$100/day' }, aud: AUD, catalog: RATE_LIMITED_REFUND });
  const sigProof = () => {
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', requestBinding({ method: 'POST', path: PATH, headers: {} }));
    return pcaHeaders(encoded)[PCA_HEADER]!;
  };
  const fullProof = (params: Record<string, unknown>) => {
    const { encoded, pcactn } = a.act('stripe.refund', 'charge:ch_1', bindParams(params, requestBinding({ method: 'POST', path: PATH, headers: {} }, { body: false })));
    roots.push(pcactn.plan.root);
    return pcaHeaders(encoded)[PCA_HEADER]!;
  };
  const base: Omit<GatewayOptions, 'policy'> = {
    audience: AUD,
    routes: [{ method: 'POST', path: '/refunds/*', capability: { verb: 'stripe.refund' } }],
    resolveGrant: (ref) => (ref === a.grant.id ? a.grant : null),
  };
  const req = (header: string, body?: string): GatewayRequest => ({ method: 'POST', path: PATH, headers: { 'pca-action': header }, ...(body !== undefined ? { body } : {}) });
  return { a, base, roots, sigProof, fullProof, req };
}
const live = { revocation: () => ({ enforced: true as const, ok: true }) };
const settle = (d: { allow: boolean; status: number; code: string; reason?: string }) => ({ allow: d.allow, status: d.status, code: d.code, reason: d.reason });

describe('B4: no policy is a configuration error', () => {
  it('createGateway throws and authorize denies a genuine proof (it used to allow it, limits unchecked)', async () => {
    const w = world();
    const opts = w.base as GatewayOptions;
    expect(() => createGateway(opts)).toThrow(TypeError);
    expect(() => createGateway(opts)).toThrow(/pca-gateway: the gateway is missing policy \(\{ mode: 'full', params, state, isRevoked \} or an explicit \{ mode: 'signature-only' \}\)/);
    const d = await authorize(w.req(w.sigProof()), opts);
    expect(settle(d)).toEqual({
      allow: false,
      status: 403,
      code: 'proof-rejected',
      reason: "the gateway is missing policy ({ mode: 'full', params, state, isRevoked } or an explicit { mode: 'signature-only' }) (fail closed)",
    });
  });
  it('the Envoy shim refuses to start without a policy', () => {
    expect(() => envoyExtAuthz(world().base as GatewayOptions)).toThrow(/missing policy/);
  });
});

describe('B4: signature-only is explicit and needs a replay guard and a revocation check', () => {
  it('without a replayGuard it throws', () => {
    const w = world();
    expect(() => createGateway({ ...w.base, insecureSkipPlanRootCheck: true, policy: { mode: 'signature-only' }, hooks: live })).toThrow('pca-gateway: the gateway is missing replayGuard (signature-only mode needs a single-use guard)');
  });
  it('requireChecks defaults to [revocation]: no revocation hook throws, pass requireChecks: [] to waive', async () => {
    const w = world();
    const replayGuard = memoryReplayGuard();
    expect(() => createGateway({ ...w.base, insecureSkipPlanRootCheck: true, policy: { mode: 'signature-only' }, replayGuard })).toThrow(/missing hooks\.revocation/);
    const waived = createGateway({ ...w.base, insecureSkipPlanRootCheck: true, policy: { mode: 'signature-only' }, replayGuard, requireChecks: [] });
    expect((await waived(w.req(w.sigProof()))).allow).toBe(true);
  });
  it('a revoked grant is refused by the default required check, and a proof is single-use', async () => {
    const w = world();
    const header = w.sigProof();
    const gw = createGateway({ ...w.base, insecureSkipPlanRootCheck: true, policy: { mode: 'signature-only' }, replayGuard: memoryReplayGuard(), hooks: live });
    expect((await gw(w.req(header))).allow).toBe(true);
    expect(settle(await gw(w.req(header)))).toMatchObject({ allow: false, code: 'replayed-proof' });
    const revoked = createGateway({ ...w.base, insecureSkipPlanRootCheck: true, policy: { mode: 'signature-only' }, replayGuard: memoryReplayGuard(), hooks: { revocation: () => ({ enforced: true as const, ok: false }) } });
    const d = await revoked(w.req(w.sigProof()));
    expect(d.allow).toBe(false);
    expect(d.reason).toMatch(/revocation/);
  });
});

describe('B4: full mode is what an unconfigured gateway is asked to be', () => {
  it('a full-policy gateway needs no requireChecks (revocation comes from isRevoked) and enforces the limit', async () => {
    const w = world();
    const policy = { mode: 'full' as const, params: 'body' as const, state: memoryPcaStore(), isRevoked: () => false, ...PROV };
    const body = (amount: number) => JSON.stringify({ charge: 'ch_1', amount });
    const [over, ok] = [w.fullProof({ charge: 'ch_1', amount: 400 }), w.fullProof({ charge: 'ch_1', amount: 50 })];
    const gw = createGateway({ ...w.base, authorizedPlanRoots: w.roots, policy });
    expect(settle(await gw(w.req(over, body(400))))).toMatchObject({ allow: false, code: 'proof-rejected' });
    expect((await gw(w.req(ok, body(50)))).allow).toBe(true);
  });
});
