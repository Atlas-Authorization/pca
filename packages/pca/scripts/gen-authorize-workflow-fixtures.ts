/**
 * Shared fixtures for the workflow gate INSIDE authorize() (K5, C-308), signed by the TypeScript reference and replayed end to end by
 * every native SDK: a signed PCActn per step, the operation, the workflow commitment and the step receipts so far, and the exact
 * authorize outcome (allow, status, decision, failing checks, a substring of the reason).
 *
 *   tsx scripts/gen-authorize-workflow-fixtures.ts [--check]     (from packages/pca; writes conformance/authorize-workflow-fixtures.json)
 *
 * Every step is also run through the TypeScript authorize() and must match `expect` (the generator throws on drift).
 * Byte-reproducible: keys are fixed and the grant's goal salt is injected, so `--check` (run in CI) compares against a fresh run.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { mintGrant } from '../src/envelope';
import { b64u, hashCanonical } from '../src/hash';
import { encodeKey, generateKeyPair, publicKeyOf } from '../src/keys';
import { paramsDigest, type PlanNode } from '../src/merkle';
import { buildPCActn } from '../src/pcactn';
import type { RiskPolicy } from '../src/risk';
import { createAuthorizer } from '../src/server/authorize';
import { memoryPcaStore } from '../src/server/require-pca';
import { signBody, signStepReceipt, signWorkflow, wfOutput, WORKFLOW_DOMAIN, type WfReceipt, type WorkflowBody } from '../src/workflow';

const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const AUD = 'workflow-rs';
const ZERO_RISK: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, theta1: 0.5, theta2: 0.8, kappa: 1, lambda: 0, rho: 0, bMax: 1_000 };
const P = new Uint8Array(32).fill(91);
const RS = new Uint8Array(32).fill(92);
const PK = b64u(publicKeyOf(P));
const RSK = b64u(publicKeyOf(RS));
const principal = generateKeyPairFixed(1);
const agent = generateKeyPairFixed(2);
function generateKeyPairFixed(n: number) {
  // deterministic keys: the generator output must be reproducible
  const secretKey = new Uint8Array(32).fill(100 + n);
  return { secretKey, publicKey: publicKeyOf(secretKey) };
}
void generateKeyPair;

const pPub = encodeKey(principal.publicKey);
const aPub = encodeKey(agent.publicKey);
const grant = mintGrant({
  principalSecret: principal.secretKey, principalPublic: pPub, holder: aPub, goal: 'refund flow', salt: b64u(new Uint8Array(16).fill(9)), // injected id source: the grant id (and so the file) is reproducible
  envelope: { predicates: [{ verb: '*', resource: '*', where: [] }], caveats: [], agent_binding: {}, risk_policy: ZERO_RISK },
}).grant;

const OPS = {
  quote: { verb: 'orders.quote', resource: 'orders/42', params: { order: 'o42' } },
  pay: { verb: 'payments.refund', resource: 'payments/42', params: { order: 'o42', amount: 30 } },
  payHigh: { verb: 'payments.refund', resource: 'payments/42', params: { order: 'o42', amount: 31 } },
  notify: { verb: 'mail.send', resource: 'mail/out', params: { ref: 'r1' } },
  wire: { verb: 'payments.wire', resource: 'payments/9', params: { amount: 1 } },
} as const;
type OpKey = keyof typeof OPS;
const nodeOf = (id: string, k: OpKey): PlanNode => ({ id, verb: OPS[k].verb, resource: OPS[k].resource, params_digest: paramsDigest(OPS[k].params), reversibility_class: 'reversible' });
const NODES: PlanNode[] = [nodeOf('quote', 'quote'), nodeOf('pay', 'pay'), nodeOf('payHigh', 'payHigh'), nodeOf('notify', 'notify'), nodeOf('wire', 'wire')];
let counter = 0;
const sign = (id: string) => buildPCActn({ grant, chain: [grant], plan: NODES, nodeId: id, params: OPS[id as OpKey].params, counter: ++counter, signerSecret: agent.secretKey, aud: AUD, now: NOW });
const ROOT = sign('quote').plan.root;

const stp = (id: string, k: OpKey, deps: string[] = [], o: Record<string, unknown> = {}) => ({ id, verb: OPS[k].verb, resource: OPS[k].resource, params_digest: null, deps, sink: null, deny_labels: [], escalate_labels: [], fresh_ms: null, cost: {}, ...o });
function bodyOf(over: Partial<WorkflowBody> = {}): WorkflowBody {
  return {
    v: 1, id: 'wf-refund', principal: PK, goal_digest: null, plan_root: ROOT, issued_at: NOW - 100_000, expires_at: NOW + 100_000,
    steps: [stp('quote', 'quote'), stp('pay', 'pay', ['quote']), stp('notify', 'notify', ['pay'], { deny_labels: ['secret'] })],
    edges: [
      { from: { step: 'quote', field: 'total' }, to: { step: 'pay', param: 'amount' }, op: 'le', unit: null, deny_labels: [], promise: null },
      { from: { step: 'pay', field: 'ref' }, to: { step: 'notify', param: 'ref' }, op: 'eq', unit: null, deny_labels: [], promise: null },
    ],
    budget: { max_steps: 5, caps: {} },
    ...over,
  };
}
const BODY = bodyOf();
const receipt = (b: WorkflowBody, s: string, outputs: Record<string, ReturnType<typeof wfOutput>>, prev?: WfReceipt, o: { secret?: Uint8Array } = {}) =>
  signStepReceipt(o.secret ?? RS, { workflow: b, step: s, outcome: 'ok', paramsDigest: hashCanonical({ s }), outputs, issuedAt: NOW - 1000, ...(prev ? { prev } : {}) });
const QUOTE = receipt(BODY, 'quote', { total: wfOutput(30, { num: true }) });
const PAY = receipt(BODY, 'pay', { ref: wfOutput('r1') }, QUOTE);

interface Step { pcactn: unknown; operation: unknown; workflow?: unknown; expect: { allow: boolean; decision: string; status: number; failed: string[]; reason?: string } }
interface Case { name: string; description: string; required: boolean; steps: Step[] }
const cases: Case[] = [];
const wfOf = (commitment: unknown, receipts: unknown[], step: string) => ({ commitment, receipts, step, units: {}, goal_digest: null });
const ALLOW = { allow: true, decision: 'allow', status: 200, failed: [] as string[] };
const REFUSED = (reason: string, decision = 'deny') => ({ allow: false, decision, status: 403, failed: ['workflow'], reason });

const SIGNED = signWorkflow(P, BODY);
const add = (name: string, description: string, required: boolean, steps: Step[]) => cases.push({ name, description, required, steps });
const pc = (id: string) => sign(id);

add('pay-after-quote', 'quote, then pay with the quote receipt: both allowed.', false, [
  { pcactn: pc('quote'), operation: OPS.quote, workflow: wfOf(SIGNED, [], 'quote'), expect: ALLOW },
  { pcactn: pc('pay'), operation: OPS.pay, workflow: wfOf(SIGNED, [QUOTE], 'pay'), expect: ALLOW },
]);
{
  const held = pc('pay');
  add('pay-before-quote-escalates-and-keeps-the-counter', 'pay with no quote receipt escalates (an unpromised dependency); the SAME PCActn is allowed once the receipt exists (the counter was not spent).', false, [
    { pcactn: held, operation: OPS.pay, workflow: wfOf(SIGNED, [], 'pay'), expect: REFUSED('workflow: pipeline_unconstrained (step pay)', 'escalate') },
    { pcactn: held, operation: OPS.pay, workflow: wfOf(SIGNED, [QUOTE], 'pay'), expect: ALLOW },
  ]);
}
add('amount-over-the-quote', 'refunding 31 against a quoted 30 is refused by the edge relation.', false, [
  { pcactn: pc('payHigh'), operation: OPS.payHigh, workflow: wfOf(SIGNED, [QUOTE], 'pay'), expect: REFUSED('workflow: edge_relation (step pay)') },
]);
add('step-not-in-the-workflow', 'a payment wire the principal never committed is refused although the plan root is the committed one.', false, [
  { pcactn: pc('wire'), operation: OPS.wire, workflow: wfOf(SIGNED, [QUOTE], 'wire'), expect: REFUSED('workflow: unplanned_step (step wire)') },
]);
add('step-with-other-verb', 'the operation differs from the committed verb for that step.', false, [
  { pcactn: pc('wire'), operation: OPS.wire, workflow: wfOf(SIGNED, [QUOTE], 'pay'), expect: REFUSED('workflow: step_mismatch (step pay)') },
]);
{
  const other = bodyOf({ plan_root: hashCanonical({ other: 'root' }) });
  add('plan-root-not-the-committed-one', 'the PCActn plan root is not the one the workflow commits.', false, [
    { pcactn: pc('quote'), operation: OPS.quote, workflow: wfOf(signWorkflow(P, other), [], 'quote'), expect: REFUSED('workflow: plan_root_mismatch (step quote)') },
  ]);
}
add('tampered-commitment', 'the commitment body was edited after signing.', false, [
  { pcactn: pc('quote'), operation: OPS.quote, workflow: wfOf({ body: { ...BODY, budget: { max_steps: 99, caps: {} } }, sig: SIGNED.sig }, [], 'quote'), expect: REFUSED('workflow: bad_signature (step quote)') },
]);
add('commitment-signed-under-another-domain', 'a signature over the same body under another domain does not verify.', false, [
  { pcactn: pc('quote'), operation: OPS.quote, workflow: wfOf({ body: BODY, sig: signBody(P, 'atlas-pca/other/v1\0', BODY) }, [], 'quote'), expect: REFUSED('workflow: bad_signature (step quote)') },
]);
{
  const expired = bodyOf({ expires_at: NOW - 1 });
  add('expired-commitment', 'the commitment is past its expiry.', false, [
    { pcactn: pc('quote'), operation: OPS.quote, workflow: wfOf(signWorkflow(P, expired), [], 'quote'), expect: REFUSED('workflow: expired (step quote)') },
  ]);
}
add('receipt-from-an-unpinned-key', 'a quote receipt signed by a key the server did not pin.', false, [
  { pcactn: pc('pay'), operation: OPS.pay, workflow: wfOf(SIGNED, [receipt(BODY, 'quote', { total: wfOutput(30, { num: true }) }, undefined, { secret: new Uint8Array(32).fill(7) })], 'pay'), expect: REFUSED('workflow: bad_receipt (step pay)') },
]);
{
  const secretQuote = receipt(BODY, 'quote', { total: wfOutput(30, { num: true }) });
  const secretPay = receipt(BODY, 'pay', { ref: wfOutput('r1', { labels: ['secret'] }) }, secretQuote);
  add('secret-label-reaches-a-guarded-step', 'a secret label produced by pay may not reach notify.', false, [
    { pcactn: pc('notify'), operation: OPS.notify, workflow: wfOf(SIGNED, [secretQuote, secretPay], 'notify'), expect: REFUSED('workflow: taint_flow (step notify)') },
  ]);
}
add('workflow-required-but-absent', 'with `required` set, a call that carries no workflow step is refused.', true, [
  { pcactn: pc('quote'), operation: OPS.quote, expect: REFUSED('workflow: this call carries no workflow step (fail closed)') },
]);
add('workflow-optional-and-absent', 'without `required`, a standalone action proceeds as before.', false, [
  { pcactn: pc('quote'), operation: OPS.quote, expect: ALLOW },
]);
add('replay-after-an-allowed-step', 'an allowed PCActn cannot be presented again: the workflow admits it, the replay counter refuses it.', false, (() => {
  const p = pc('quote');
  return [
    { pcactn: p, operation: OPS.quote, workflow: wfOf(SIGNED, [], 'quote'), expect: ALLOW },
    { pcactn: p, operation: OPS.quote, workflow: wfOf(SIGNED, [], 'quote'), expect: { allow: false, decision: 'deny', status: 403, failed: ['replay'], reason: 'replay:' } },
  ];
})());
// ordering: an undecodable PCActn is refused by the guard (401 wire) before any workflow admission; `required` and absent still wins
add('undecodable-pcactn-with-a-workflow', 'a PCActn that cannot be decoded is refused as a wire error even when it carries a workflow step.', false, [
  { pcactn: 'not-a-pcactn', operation: OPS.quote, workflow: wfOf(SIGNED, [], 'quote'), expect: { allow: false, decision: 'deny', status: 401, failed: ['pcactn'], reason: 'undecodable PCActn' } },
]);
add('undecodable-pcactn-without-a-workflow', 'the same undecodable PCActn with no workflow and none required: the same wire refusal.', false, [
  { pcactn: 'not-a-pcactn', operation: OPS.quote, expect: { allow: false, decision: 'deny', status: 401, failed: ['pcactn'], reason: 'undecodable PCActn' } },
]);
add('undecodable-pcactn-workflow-required-and-absent', 'with `required` set and no workflow step, the workflow refusal comes first (it needs no PCActn).', true, [
  { pcactn: 'not-a-pcactn', operation: OPS.quote, expect: REFUSED('workflow: this call carries no workflow step (fail closed)') },
]);
void WORKFLOW_DOMAIN;

// run every case through the TypeScript authorize() and require the recorded outcome
const out = { format: 'pca-authorize-workflow-fixtures/1', description: 'workflow admission inside authorize(): each case threads its steps through ONE replay store', now: NOW, audience: AUD, principal: PK, rs_signer: RSK, plan: NODES, grant, cases };
const text = async () => {
  for (const c of cases) {
    const az = createAuthorizer({
      audience: AUD, resolveGrant: async (r) => (r === grant.id ? grant : null), budgetStore: memoryPcaStore(), hooks: { revocation: () => ({ enforced: true, ok: true }) }, now: () => NOW,
      context: () => ({ plan: NODES, planAuthorized: true }), risk: () => ({ blastRadius: 0, semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }),
      workflow: { principal: PK, rsSigner: RSK, required: c.required },
    });
    for (const [i, s] of c.steps.entries()) {
      const wf = s.workflow as { commitment: unknown; receipts: unknown[]; step: string; units: Record<string, string>; goal_digest: string | null } | undefined;
      const r = await az({ operation: s.operation as never, pcactn: s.pcactn as never, ...(wf ? { workflow: { commitment: wf.commitment, receipts: wf.receipts, step: wf.step, units: wf.units, goalDigest: wf.goal_digest } } : {}) });
      const failed = Object.entries(r.verdict.checks).filter(([, v]) => v === 'fail').map(([k]) => k).sort();
      const got = { allow: r.allow, decision: r.decision, status: r.status, failed };
      const want = { allow: s.expect.allow, decision: s.expect.decision, status: s.expect.status, failed: s.expect.failed };
      if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error(`drift ${c.name}[${i}]: ${JSON.stringify(got)} != ${JSON.stringify(want)}`);
      if (s.expect.reason !== undefined && !(!r.allow && r.reason.includes(s.expect.reason))) throw new Error(`drift ${c.name}[${i}]: reason ${r.allow ? 'allowed' : r.reason}`);
    }
  }
  return `${JSON.stringify(out, null, 2)}\n`;
};
const file = join(__dirname, '..', 'conformance', 'authorize-workflow-fixtures.json');
text().then((t) => {
  if (process.argv.includes('--check')) {
    if (readFileSync(file, 'utf8') !== t) { console.error('authorize-workflow-fixtures.json is stale'); process.exit(1); }
  } else { writeFileSync(file, t); console.log(`wrote ${file}`); }
});
