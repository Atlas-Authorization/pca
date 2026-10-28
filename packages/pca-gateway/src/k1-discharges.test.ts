// Track K9: needs_discharge grants work through the gateway. The presented discharges are read from the PCA-Discharges
// header (as requirePCA and the native guards read them) or, when the body is not the signed params, from body member
// pca_discharges; the verifier's pins decide; without a k1 configuration every K1 caveat refuses.
import { describe, expect, it } from 'vitest';
import { agent, b64u, capHash, dischargeActionDigest, encodeKey, generateKeyPair, pcaHeaders, PCA_HEADER, signDischarge, type Agent, type Caveat, type DischargePin } from '@atlasauth/pca';
import { BUILTIN_ACTIONS, buildCatalog, defineAction } from '@atlasauth/pca/ext/research';
import { authorize, bindParams, createGateway, memoryPcaStore, requestBinding, type GatewayFullPolicy, type GatewayOptions, type GatewayRequest } from './index';

const CATALOG = buildCatalog([...BUILTIN_ACTIONS, defineAction({ connector: 'stripe', action: 'refund', reversibility: 'rate_limited', blastRadius: 0.9, amountField: 'amount', description: 'Refund a charge (rate-limited).' })]);
const AUD = 'ins_k9_gw';
const VERB = 'stripe.refund';
const PATH = '/refunds/ch_1';
const issuer = generateKeyPair();
const rogue = generateKeyPair();
const PIN: DischargePin = { label: 'risk-team', class: 'human', pk: encodeKey(issuer.publicKey) };
const CAVEAT = { type: 'needs_discharge', id: 'kyc', issuer: 'risk-team', issuer_class: 'human', bind: 'action', ttl_ms: 600_000, require: [{ claim: 'kyc_level', op: 'gte', value: 2 }] } as unknown as Caveat;
const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
const refund = { charge: 'ch_1', amount: 50 };

function world(o: { k1?: GatewayFullPolicy['k1']; params?: GatewayFullPolicy['params'] } = {}) {
  const root: Agent = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$100/day' }, aud: AUD, catalog: CATALOG });
  const a = root.subAgent({ addedCaveats: [CAVEAT] });
  const policy: GatewayFullPolicy = { mode: 'full', params: o.params ?? 'body', state: memoryPcaStore(), isRevoked: () => false, ...(o.k1 !== undefined ? { k1: o.k1 } : {}) };
  const opts: GatewayOptions = { audience: AUD, routes: [{ method: 'POST', path: '/refunds/*', capability: { verb: VERB } }], resolveGrant: (ref) => (ref === a.grant.id ? a.grant : null), policy };
  const binding = requestBinding({ method: 'POST', path: PATH, query: '', headers: {} }, { body: false });
  const { encoded, pcactn } = a.act(VERB, 'charge:ch_1', bindParams(refund, binding));
  const discharge = (signer = issuer.secretKey, claims: Record<string, number> = { kyc_level: 3 }) =>
    signDischarge({ v: 1, kind: 'pca-discharge', caveat_id: 'kyc', issuer: 'risk-team', cap_hash: capHash(pcactn.cap_chain[1]!), bind: 'action', action_digest: dischargeActionDigest(pcactn), claims, iat: Date.now() - 1000, not_after: Date.now() + 60_000, nonce: b64u(new Uint8Array(16).fill(7)) } as never, signer);
  const req = (headers: Record<string, string> = {}, body = JSON.stringify(refund)): GatewayRequest => ({ method: 'POST', path: PATH, headers: { ...pcaHeaders(encoded), ...headers }, body });
  return { opts, discharge, req, pcactn };
}

describe('pca-gateway: needs_discharge grants (K9)', () => {
  it('admits with a discharge in PCA-Discharges, signed by the pinned issuer', async () => {
    const w = world({ k1: { pins: [PIN] } });
    const d = await authorize(w.req({ 'pca-discharges': enc([w.discharge()]) }), w.opts);
    expect({ allow: d.allow, code: d.code }).toEqual({ allow: true, code: 'allow' });
  });
  it('refuses without a discharge, with a rogue or under-claimed one, and with an unreadable header', async () => {
    const w = world({ k1: { pins: [PIN] } });
    for (const h of [{}, { 'pca-discharges': enc([w.discharge(rogue.secretKey)]) }, { 'pca-discharges': enc([w.discharge(issuer.secretKey, { kyc_level: 1 })]) }, { 'pca-discharges': '!!!' }]) {
      const d = await authorize(w.req(h), w.opts);
      expect(d.allow).toBe(false);
      expect(d.code).toBe('proof-rejected');
    }
  });
  it('without a k1 configuration the caveat refuses even with a valid discharge (fail closed)', async () => {
    const w = world();
    const d = await authorize(w.req({ 'pca-discharges': enc([w.discharge()]) }), w.opts);
    expect(d.allow).toBe(false);
  });
  it('body form: with function params the discharges may ride in the JSON body as pca_discharges', async () => {
    let disc: unknown;
    const w = world({ k1: { pins: [PIN] }, params: (r) => {
      const b = JSON.parse(r.body ?? '{}') as Record<string, unknown>;
      const { pca_discharges: _d, ...rest } = b;
      return rest;
    } });
    disc = w.discharge();
    const d = await authorize(w.req({}, JSON.stringify({ ...refund, pca_discharges: [disc] })), w.opts);
    expect({ allow: d.allow, code: d.code }).toEqual({ allow: true, code: 'allow' });
  });
  it('with params from the body (signed), body members are not read: the header is the only form', async () => {
    const w = world({ k1: { pins: [PIN] } });
    const d = await authorize(w.req({}, JSON.stringify({ ...refund, pca_discharges: [w.discharge()] })), w.opts);
    expect(d.allow).toBe(false);
  });
  it('the configured k1 wins over presented members and may be a function; createGateway keeps it', async () => {
    const w = world({ k1: async () => ({ pins: [PIN] }) });
    const gw = createGateway(w.opts);
    expect((await gw(w.req({ 'pca-discharges': enc([w.discharge()]) }))).allow).toBe(true);
    const own = world({ k1: async () => ({ pins: [PIN], discharges: [] }) });
    expect((await authorize(own.req({ 'pca-discharges': enc([own.discharge()]) }), own.opts)).allow).toBe(false);
  });
});
