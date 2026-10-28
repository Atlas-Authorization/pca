import { describe, expect, it } from 'vitest';
import { ContractEnforcer } from '../contract-enforcer';
import { CONTRACT_VERSION, signContract } from '../contracts';
import { createMemoryDurableKv } from '../durable-state';
import { mintGrant } from '../envelope';
import { encodeKey, generateKeyPair } from '../keys';
import { paramsDigest, type PlanNode } from '../merkle';
import { buildPCActn, encodePCActn } from '../pcactn';
import type { RiskPolicy } from '../risk';
import { createAuthorizer, missingAuthorizeComponents, type AuthorizeOptions } from './authorize';
import { memoryPcaStore } from './require-pca';

const SPEND_POLICY: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 };
const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const AUD = 'rs';
const principal = generateKeyPair();
const holder = generateKeyPair();
const hPub = encodeKey(holder.publicKey);
const grant = mintGrant({
  principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: hPub, goal: 'g',
  envelope: { predicates: [{ verb: ['do'], resource: '*', where: [] }], caveats: [], agent_binding: {}, risk_policy: SPEND_POLICY },
}).grant;
let counter = 0;
const params = { payee: 'acme', amount: 1 };
const operation = { verb: 'do', resource: 'r', params };
const act = () => {
  const node: PlanNode = { id: 'n1', verb: 'do', resource: 'r', params_digest: paramsDigest(params), reversibility_class: 'reversible' };
  return buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params, counter: ++counter, signerSecret: holder.secretKey, aud: AUD, now: NOW });
};
const options = (over: Partial<AuthorizeOptions> = {}): AuthorizeOptions => ({
  audience: AUD, resolveGrant: async (r) => (r === grant.id ? grant : null), budgetStore: memoryPcaStore(),
  hooks: { revocation: () => ({ enforced: true, ok: true }) }, plan: 'single-step', now: () => NOW,
  risk: (o) => ({ blastRadius: Math.min(1, Number(o?.params?.amount) / 100), semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }), ...over,
});
const kv = () => createMemoryDurableKv();
const mk = (clause: object) =>
  signContract({ version: CONTRACT_VERSION, principal: encodeKey(principal.publicKey), clauses: [clause as never] }, principal.secretKey);
const enforcer = (clause: object, k = kv()) => ContractEnforcer.open(k, mk(clause), { principal: encodeKey(principal.publicKey), now: () => NOW });
const NEVER_DO = { id: 'no-do', kind: 'never', p: { verb: 'do' } };
const NEVER_OTHER = { id: 'no-other', kind: 'never', p: { verb: 'other' } };

describe('authorize + contracts', () => {
  it('default behaviour is unchanged without the option', async () => {
    expect((await createAuthorizer(options())({ operation, pcactn: act() })).allow).toBe(true);
  });
  it('a violated contract refuses with the exact reason and leaves the replay counter unconsumed', async () => {
    const store = memoryPcaStore();
    const pc = act();
    const denied = await createAuthorizer(options({ budgetStore: store, contracts: enforcer(NEVER_DO) }))({ operation, pcactn: pc });
    expect(denied).toMatchObject({ allow: false, status: 403, reason: 'contract: violated (no-do)' });
    // the SAME PCActn (same counter) still verifies against the same store: nothing was spent by the denial
    expect((await createAuthorizer(options({ budgetStore: store }))({ operation, pcactn: pc })).allow).toBe(true);
    // control: a second presentation after a real allow is a replay
    expect((await createAuthorizer(options({ budgetStore: store }))({ operation, pcactn: pc })).allow).toBe(false);
  });
  it('a latched contract refuses everything until the signed reset', async () => {
    const k = kv();
    const e = enforcer(NEVER_OTHER, k);
    await e.check({ action: { verb: 'other', resource: 'r' } });
    const r = await createAuthorizer(options({ contracts: e }))({ operation, pcactn: act() });
    expect(r).toMatchObject({ allow: false, reason: 'contract: latched (no-other)' });
  });
  it('a compliant call is admitted and committed to the contract state', async () => {
    const e = enforcer(NEVER_OTHER);
    expect((await createAuthorizer(options({ contracts: e }))({ operation, pcactn: act() })).allow).toBe(true);
    expect((await e.state())?.state.seq).toBe(1);
  });
  it('a refused call (guard denial) does not advance the contract state', async () => {
    const e = enforcer(NEVER_OTHER);
    const pc = act();
    const a = createAuthorizer(options({ contracts: e }));
    expect((await a({ operation, pcactn: pc })).allow).toBe(true);
    expect((await a({ operation, pcactn: pc })).allow).toBe(false); // replay
    expect((await e.state())?.state.seq).toBe(1);
  });
});

describe('authorize + adaptivePolicy', () => {
  const tight: RiskPolicy = { ...SPEND_POLICY, theta1: 0, theta2: 0 };
  it('a tightened policy that requires a higher threshold refuses with the exact reason', async () => {
    const r = await createAuthorizer(options({ adaptivePolicy: () => tight }))({ operation, pcactn: act() });
    expect(r).toMatchObject({ allow: false, status: 403, reason: expect.stringMatching(/^adaptive: tightened policy requires threshold t=3 \(grant policy: t=1\)$/) });
  });
  it('an adaptive denial leaves the replay counter unconsumed', async () => {
    const store = memoryPcaStore();
    const pc = act();
    const denied = await createAuthorizer(options({ budgetStore: store, adaptivePolicy: () => tight }))({ operation, pcactn: pc });
    expect(denied).toMatchObject({ allow: false, reason: 'adaptive: tightened policy requires threshold t=3 (grant policy: t=1)' });
    expect((await createAuthorizer(options({ budgetStore: store }))({ operation, pcactn: pc })).allow).toBe(true);
  });
  it('an invalid adaptive policy also leaves the counter unconsumed', async () => {
    const store = memoryPcaStore();
    const pc = act();
    expect((await createAuthorizer(options({ budgetStore: store, adaptivePolicy: () => ({ ...SPEND_POLICY, kappa: -1 }) }))({ operation, pcactn: pc })).allow).toBe(false);
    expect((await createAuthorizer(options({ budgetStore: store }))({ operation, pcactn: pc })).allow).toBe(true);
  });
  it('without a risk source the early check is skipped and the verified check still refuses', async () => {
    const o = options({ adaptivePolicy: () => tight });
    delete (o as { risk?: unknown }).risk;
    const r = await createAuthorizer({ ...o, context: () => ({ risk: { blastRadius: 0.5, semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 } }) })({ operation, pcactn: act() });
    expect(r).toMatchObject({ allow: false });
    expect((r as { reason: string }).reason.startsWith('adaptive:')).toBe(true);
  });
  it('a looser policy cannot widen: it is ignored', async () => {
    expect((await createAuthorizer(options({ adaptivePolicy: () => ({ ...SPEND_POLICY, theta1: 1, theta2: 1 }) }))({ operation, pcactn: act() })).allow).toBe(true);
  });
  it('no adaptive policy (undefined) leaves the decision unchanged', async () => {
    expect((await createAuthorizer(options({ adaptivePolicy: async () => undefined }))({ operation, pcactn: act() })).allow).toBe(true);
  });
  it('an invalid policy refuses (fail closed)', async () => {
    const r = await createAuthorizer(options({ adaptivePolicy: () => ({ ...SPEND_POLICY, kappa: -1 }) }))({ operation, pcactn: act() });
    expect(r).toMatchObject({ allow: false });
    expect((r as { reason: string }).reason.startsWith('adaptive: invalid policy')).toBe(true);
  });
  it('a throwing provider refuses (fail closed)', async () => {
    const r = await createAuthorizer(options({ adaptivePolicy: () => { throw new Error('boom'); } }))({ operation, pcactn: act() });
    expect(r).toMatchObject({ allow: false, reason: 'authorize error (fail closed): boom' });
  });
});
