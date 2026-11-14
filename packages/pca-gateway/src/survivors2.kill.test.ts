import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair, pcaHeaders, PCA_HEADER, PROV_HEADER, type Agent } from '@atlasauth/pca';
import { BUILTIN_ACTIONS, buildCatalog, defineAction } from '@atlasauth/pca/ext/research';
import { authorize, bindParams, memoryPcaStore, requestBinding, type GatewayFullPolicy, type GatewayOptions, type GatewayPolicy, type GatewayRequest } from './index';

const CATALOG = buildCatalog([...BUILTIN_ACTIONS, defineAction({ connector: 'stripe', action: 'refund', reversibility: 'rate_limited', blastRadius: 0.9, amountField: 'amount', description: 'Refund a charge (rate-limited).' })]);
const AUD = 'ins_surv2_gw';
const VERB = 'stripe.refund';
const PATH = '/refunds/ch_1';
const refund = (amount: number) => ({ charge: 'ch_1', amount });
const json = (v: unknown) => JSON.stringify(v);
const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');

function world() {
  const a: Agent = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$1000/day' }, aud: AUD, catalog: CATALOG });
  const roots: string[] = [];
  const policy: GatewayFullPolicy = { mode: 'full', params: 'body', state: memoryPcaStore(), isRevoked: () => false };
  const opts: GatewayOptions = { audience: AUD, routes: [{ method: 'POST', path: '/refunds/*', capability: { verb: VERB } }], resolveGrant: (ref) => (ref === a.grant.id ? a.grant : null), authorizedPlanRoots: roots, policy };
  const sign = (params: Record<string, unknown>) => {
    const binding = requestBinding({ method: 'POST', path: PATH, headers: {} }, { body: false });
    const r = a.act(VERB, 'charge:ch_1', bindParams(params, binding));
    roots.push(r.pcactn.plan.root);
    return pcaHeaders(r.encoded, r.provenance);
  };
  const req = (h: Record<string, string>, body: string, extra: Record<string, string> = {}): GatewayRequest => ({
    method: 'POST',
    path: PATH,
    headers: { 'pca-action': h[PCA_HEADER]!, ...(h[PROV_HEADER] ? { 'pca-provenance': h[PROV_HEADER] } : {}), ...extra },
    body,
  });
  return { a, opts, policy, sign, req };
}

describe('denials keep the decoded proof on the decision', () => {
  it('a misconfigured full policy attaches the proof', async () => {
    const w = world();
    const d = await authorize(w.req(w.sign(refund(50)), json(refund(50))), { ...w.opts, policy: { ...w.policy, state: undefined as never } as GatewayPolicy });
    expect(d.code).toBe('proof-rejected');
    expect(d.pcactn?.grant_ref).toBe(w.a.grant.id);
    expect(d.pcactn?.action.verb).toBe(VERB);
  });
  it('a body that is not the signed params attaches the verdict and the proof', async () => {
    const w = world();
    const d = await authorize(w.req(w.sign(refund(50)), json(refund(90))), w.opts);
    expect(d.code).toBe('request-mismatch');
    expect(d.pcactn?.grant_ref).toBe(w.a.grant.id);
    expect(d.verdict?.checks).toBeDefined();
  });
  it('a request whose params are not an object is refused with the proof attached', async () => {
    const w = world();
    const d = await authorize(w.req(w.sign(refund(50)), '5'), w.opts);
    expect(d.code).toBe('request-mismatch');
    expect(d.pcactn?.grant_ref).toBe(w.a.grant.id);
  });
});

describe('a presented provenance bundle without a session never aborts the gate', () => {
  for (const bundle of [{}, { receipts: [] }, { receipts: [null] }, { receipts: [{}] }]) {
    it(`bundle ${JSON.stringify(bundle)} is judged, not thrown on`, async () => {
      const w = world();
      const d = await authorize(w.req(w.sign(refund(50)), json(refund(50)), { 'pca-provenance': enc(bundle) }), w.opts);
      expect(d.allow).toBe(false);
    });
  }
});
