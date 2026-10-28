import { describe, expect, it } from 'vitest';
import { mintGrant } from '../envelope';
import { b64u } from '../hash';
import { encodeKey, generateKeyPair, publicKeyOf } from '../keys';
import { paramsDigest, type PlanNode } from '../merkle';
import { buildPCActn } from '../pcactn';
import type { RiskPolicy } from '../risk';
const ZERO_RISK: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, theta1: 0.5, theta2: 0.8, kappa: 1, lambda: 0, rho: 0, bMax: 1_000 };
import { signStepReceipt, signWorkflow, wfOutput, type WorkflowBody } from '../workflow';
import { createAuthorizer } from './authorize';
import { memoryPcaStore } from './require-pca';

const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const AUD = 'rs';
const P = new Uint8Array(32).fill(61);
const RS = new Uint8Array(32).fill(62);

function rig() {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const pPub = encodeKey(principal.publicKey);
  const grant = mintGrant({ principalSecret: principal.secretKey, principalPublic: pPub, holder: encodeKey(holder.publicKey), goal: 'g', envelope: { predicates: [{ verb: '*', resource: '*', where: [] }], caveats: [], agent_binding: {}, risk_policy: ZERO_RISK } }).grant;
  let counter = 0;
  const params = { amount: 30 };
  const node: PlanNode = { id: 'n1', verb: 'pay', resource: 'bill', params_digest: paramsDigest(params), reversibility_class: 'reversible' };
  const mk = () => buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params, counter: ++counter, signerSecret: holder.secretKey, aud: AUD, now: NOW });
  const root = mk().plan.root;
  const step = (id: string, verb: string, resource: string, deps: string[] = []) => ({ id, verb, resource, params_digest: null, deps, sink: null, deny_labels: [], escalate_labels: [], fresh_ms: null, cost: {} });
  const body: WorkflowBody = {
    v: 1, id: 'wf', principal: b64u(publicKeyOf(P)), goal_digest: null, plan_root: root, issued_at: NOW - 1000, expires_at: NOW + 1000,
    steps: [step('quote', 'quote', 'bill'), step('pay', 'pay', 'bill', ['quote'])],
    edges: [{ from: { step: 'quote', field: 'total' }, to: { step: 'pay', param: 'amount' }, op: 'le', unit: null, deny_labels: [], promise: null }],
    budget: { max_steps: 4, caps: {} },
  };
  const commitment = signWorkflow(P, body);
  const quote = signStepReceipt(RS, { workflow: body, step: 'quote', outcome: 'ok', paramsDigest: b64u(new Uint8Array(32)), outputs: { total: wfOutput(30, { num: true }) }, issuedAt: NOW - 10 });
  const az = (workflow?: { required?: boolean }) =>
    createAuthorizer({
      audience: AUD, resolveGrant: async (r) => (r === grant.id ? grant : null), budgetStore: memoryPcaStore(), hooks: { revocation: () => ({ enforced: true, ok: true }) }, plan: 'single-step', now: () => NOW, risk: () => ({ blastRadius: 0, semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }),
      workflow: { principal: b64u(publicKeyOf(P)), rsSigner: b64u(publicKeyOf(RS)), ...workflow },
    });
  return { mk, commitment, quote, az, params };
}

describe('authorize: a step inside a committed workflow is checked automatically (C-308)', () => {
  const operation = (params: Record<string, number>) => ({ verb: 'pay', resource: 'bill', params });
  it('allows the step when the quote receipt supports it', async () => {
    const r = rig();
    const out = await r.az()({ operation: operation(r.params), pcactn: r.mk(), workflow: { commitment: r.commitment, receipts: [r.quote], step: 'pay' } });
    expect(out.allow).toBe(true);
  });
  it('refuses a step whose dependency has no receipt, before the guard (the counter is not spent)', async () => {
    const r = rig();
    const pc = r.mk();
    const out = await r.az()({ operation: operation(r.params), pcactn: pc, workflow: { commitment: r.commitment, receipts: [], step: 'pay' } });
    expect(out.allow).toBe(false);
    if (!out.allow) {
      expect(out.decision).toBe('escalate'); // an unpromised dependency with an edge: pipelining without a domain escalates
      expect(out.reason).toBe('workflow: pipeline_unconstrained (step pay)');
      expect(out.verdict.checks).toEqual({ workflow: 'fail' });
    }
    // the refused PCActn was not consumed
    const ok = await r.az()({ operation: operation(r.params), pcactn: pc, workflow: { commitment: r.commitment, receipts: [r.quote], step: 'pay' } });
    expect(ok.allow).toBe(true);
  });
  it('refuses an amount above the quoted total (edge relation)', async () => {
    const r = rig();
    const out = await r.az()({ operation: operation({ amount: 31 }), pcactn: r.mk(), workflow: { commitment: r.commitment, receipts: [r.quote], step: 'pay' } });
    expect(out.allow).toBe(false);
    if (!out.allow) expect(out.reason).toBe('workflow: edge_relation (step pay)');
  });
  it('refuses a step the commitment does not list', async () => {
    const r = rig();
    const out = await r.az()({ operation: operation(r.params), pcactn: r.mk(), workflow: { commitment: r.commitment, receipts: [r.quote], step: 'wire' } });
    expect(out.allow).toBe(false);
    if (!out.allow) expect(out.reason).toBe('workflow: unplanned_step (step wire)');
  });
  it('refuses when the PCActn plan root is not the committed one', async () => {
    const r = rig();
    const other = { ...r.commitment.body, plan_root: b64u(new Uint8Array(32).fill(1)) };
    const out = await r.az()({ operation: operation(r.params), pcactn: r.mk(), workflow: { commitment: { ...r.commitment, body: other }, receipts: [r.quote], step: 'pay' } });
    expect(out.allow).toBe(false);
  });
  it('required: a call without a workflow is refused; not required: it proceeds', async () => {
    const r = rig();
    const req = await r.az({ required: true })({ operation: operation(r.params), pcactn: r.mk() });
    expect(req.allow).toBe(false);
    if (!req.allow) expect(req.reason).toBe('workflow: this call carries no workflow step (fail closed)');
    const loose = await r.az()({ operation: operation(r.params), pcactn: r.mk() });
    expect(loose.allow).toBe(true);
  });
});
