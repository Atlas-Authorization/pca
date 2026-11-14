/**
 * Workflow (DAG) authorization: the principal signs one commitment to a whole workflow, and every step is admitted only as
 * part of it. Every outcome below is printed; the script exits non-zero if any differs from the guide.
 */
import { admitStep, b64u, hashCanonical, publicKeyOf, signStepReceipt, signWorkflow, wfOutput, type SignedWorkflow, type WfReceipt, type WfRequest, type WorkflowBody } from '@atlasauth/pca';
import { expectEq, run } from './check.js';

const NOW = 1_800_000_000_000;
const principalSecret = new Uint8Array(32).fill(11); // the person or service that authorizes the workflow
const serverSecret = new Uint8Array(32).fill(12); // the resource server: signs one receipt per executed step
const PRINCIPAL = b64u(publicKeyOf(principalSecret));
const SERVER = b64u(publicKeyOf(serverSecret));

const step = (id: string, deps: string[], o: Record<string, unknown> = {}) =>
  ({ id, verb: `shop.${id}`, resource: 'cart/1', params_digest: null, deps, sink: null, deny_labels: [], escalate_labels: [], fresh_ms: null, cost: {}, ...o });

const body: WorkflowBody = {
  v: 1, id: 'checkout-1', principal: PRINCIPAL, goal_digest: null, plan_root: null, issued_at: NOW - 1000, expires_at: NOW + 60_000,
  steps: [
    step('quote', []),
    step('pay', ['quote']), // pay may only run after quote
    step('lookup', []),
    step('notify', ['lookup'], { deny_labels: ['pii'] }), // notify may never run downstream of data labelled pii
  ],
  // "pay's amount must be at most quote's total"
  edges: [{ from: { step: 'quote', field: 'total' }, to: { step: 'pay', param: 'amount' }, op: 'le', unit: null, deny_labels: [], promise: null }],
  budget: { max_steps: 3, caps: {} },
};
const signed: SignedWorkflow = signWorkflow(principalSecret, body);

const request = (id: string, params: Record<string, number> = {}): WfRequest => ({ step: id, verb: `shop.${id}`, resource: 'cart/1', params, units: {}, goal_digest: null, plan_root: null });
const admit = (receipts: unknown[], req: WfRequest, wf: SignedWorkflow = signed, rsSigner = SERVER) =>
  admitStep({ workflow: wf, principal: PRINCIPAL, rsSigner, receipts, now: NOW, request: req });
const receipt = (id: string, params: Record<string, number>, outputs: Parameters<typeof signStepReceipt>[1]['outputs'], prev?: WfReceipt, secret = serverSecret) =>
  signStepReceipt(secret, { workflow: body, step: id, outcome: 'ok', paramsDigest: hashCanonical(params), outputs, issuedAt: NOW - 1, ...(prev ? { prev } : {}) });
const verdict = (r: { decision: string; code: string | null }) => [r.decision, r.code];

run(() => {
  expectEq('first step, no receipts yet', verdict(admit([], request('quote'))), ['allow', null]);

  const quote = receipt('quote', {}, { total: wfOutput(30, { num: true }) });
  expectEq('pay at the quoted total', verdict(admit([quote], request('pay', { amount: 30 }))), ['allow', null]);
  expectEq('pay below the quoted total', verdict(admit([quote], request('pay', { amount: 12 }))), ['allow', null]);
  expectEq('pay above the quoted total', verdict(admit([quote], request('pay', { amount: 31 }))), ['deny', 'edge_relation']);
  expectEq('pay before the quote exists asks a human (nothing to check the amount against)', verdict(admit([], request('pay', { amount: 30 }))), ['escalate', 'pipeline_unconstrained']);
  expectEq('a step the commitment does not list', verdict(admit([quote], request('wire', { amount: 30 }))), ['deny', 'unplanned_step']);
  expectEq('the same step twice', verdict(admit([quote], request('quote'))), ['deny', 'already_done']);

  const forgedQuote = receipt('quote', {}, { total: wfOutput(9999, { num: true }) }, undefined, new Uint8Array(32).fill(99));
  expectEq('a receipt not signed by the pinned resource server', verdict(admit([forgedQuote], request('pay', { amount: 5000 }))), ['deny', 'bad_receipt']);

  const tampered = { ...signed, body: { ...body, expires_at: NOW + 999_999_999 } };
  expectEq('a commitment edited after signing', verdict(admit([], request('quote'), tampered)), ['deny', 'bad_signature']);

  const lookup = receipt('lookup', {}, { contact: wfOutput('customer-contact', { labels: ['pii'] }) });
  expectEq('notify after pii was read', verdict(admit([lookup], request('notify'))), ['deny', 'taint_flow']);

  const third = receipt('lookup', {}, {}, quote); // receipts form a chain: each one names the one before it
  const pay = receipt('pay', { amount: 30 }, {}, third);
  expectEq('the third step still fits the budget of three', verdict(admit([quote, third], request('pay', { amount: 30 }))), ['allow', null]);
  expectEq('a fourth step does not', verdict(admit([quote, third, pay], request('notify'))), ['deny', 'budget_exceeded']);
});
