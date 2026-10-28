// 0.5 (B4): the gateway is full-policy by default. A configuration without `policy` is refused; signature-only is an
// explicit mode that needs a replay guard and, by default, a revocation check.
import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair, pcaHeaders, PCA_HEADER, type Agent } from '@atlasauth/pca';
import { authorize, bindParams, createGateway, envoyExtAuthz, memoryPcaStore, memoryReplayGuard, requestBinding, type GatewayOptions, type GatewayRequest } from './index';

const AUD = 'ins_b4';
const PATH = '/refunds/ch_1';

function world() {
  const a: Agent = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$100/day' }, aud: AUD });
  const sigProof = () => {
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', requestBinding({ method: 'POST', path: PATH, headers: {} }));
    return pcaHeaders(encoded)[PCA_HEADER]!;
  };
  const fullProof = (params: Record<string, unknown>) => {
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', bindParams(params, requestBinding({ method: 'POST', path: PATH, headers: {} }, { body: false })));
    return pcaHeaders(encoded)[PCA_HEADER]!;
  };
  const base: Omit<GatewayOptions, 'policy'> = {
    audience: AUD,
    routes: [{ method: 'POST', path: '/refunds/*', capability: { verb: 'stripe.refund' } }],
    resolveGrant: (ref) => (ref === a.grant.id ? a.grant : null),
  };
  const req = (header: string, body?: string): GatewayRequest => ({ method: 'POST', path: PATH, headers: { 'pca-action': header }, ...(body !== undefined ? { body } : {}) });
  return { a, base, sigProof, fullProof, req };
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
    expect(() => createGateway({ ...w.base, policy: { mode: 'signature-only' }, hooks: live })).toThrow('pca-gateway: the gateway is missing replayGuard (signature-only mode needs a single-use guard)');
  });
  it('requireChecks defaults to [revocation]: no revocation hook throws, pass requireChecks: [] to waive', async () => {
    const w = world();
    const replayGuard = memoryReplayGuard();
    expect(() => createGateway({ ...w.base, policy: { mode: 'signature-only' }, replayGuard })).toThrow(/missing hooks\.revocation/);
    const waived = createGateway({ ...w.base, policy: { mode: 'signature-only' }, replayGuard, requireChecks: [] });
    expect((await waived(w.req(w.sigProof()))).allow).toBe(true);
  });
  it('a revoked grant is refused by the default required check, and a proof is single-use', async () => {
    const w = world();
    const header = w.sigProof();
    const gw = createGateway({ ...w.base, policy: { mode: 'signature-only' }, replayGuard: memoryReplayGuard(), hooks: live });
    expect((await gw(w.req(header))).allow).toBe(true);
    expect(settle(await gw(w.req(header)))).toMatchObject({ allow: false, code: 'replayed-proof' });
    const revoked = createGateway({ ...w.base, policy: { mode: 'signature-only' }, replayGuard: memoryReplayGuard(), hooks: { revocation: () => ({ enforced: true as const, ok: false }) } });
    const d = await revoked(w.req(w.sigProof()));
    expect(d.allow).toBe(false);
    expect(d.reason).toMatch(/revocation/);
  });
});

describe('B4: full mode is what an unconfigured gateway is asked to be', () => {
  it('a full-policy gateway needs no requireChecks (revocation comes from isRevoked) and enforces the limit', async () => {
    const w = world();
    const policy = { mode: 'full' as const, params: 'body' as const, state: memoryPcaStore(), isRevoked: () => false };
    const gw = createGateway({ ...w.base, policy });
    const body = (amount: number) => JSON.stringify({ charge: 'ch_1', amount });
    expect(settle(await gw(w.req(w.fullProof({ charge: 'ch_1', amount: 400 }), body(400))))).toMatchObject({ allow: false, code: 'proof-rejected' });
    expect((await gw(w.req(w.fullProof({ charge: 'ch_1', amount: 50 }), body(50)))).allow).toBe(true);
  });
});
