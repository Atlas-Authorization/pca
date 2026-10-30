/**
 * An A2A hop. A planner agent asks a refund agent to do a job. The planner signs a proof for exactly that action and
 * attaches it to the A2A task; the refund agent verifies the proof with the A2A gate BEFORE it runs anything.
 *
 * Four outcomes, plus a revocation:
 *   1. a proof for the right agent and a small refund            -> runs
 *   2. a proof signed for a different agent                      -> refused (audience)
 *   3. a refund bigger than the planner was delegated            -> refused (the sub-delegation only narrows)
 *   4. the same proof sent a second time                         -> refused (replay)
 *
 * The receiver never trusts the task: the grant comes from its own list, and the action it checks the proof against
 * (verb, resource, params) is read from the task it is about to run, so a proof for another action does not fit.
 *
 * Run it:  npm start      (exits nonzero if any outcome is not the expected one)
 */

import {
  agent,
  catalogRisk,
  explainRefusal,
  generateKeyPair,
  paramsDigest,
  pcactnDigest,
  protect,
  readEnvelope,
  type PCActn,
  type PcaContext,
  type PlanNode,
} from '@atlasauth/pca';
import { attachPcaToA2ATask, pcaA2AMiddleware, type A2ATask } from '@atlasauth/pca-a2a';

const REFUND_AGENT = 'agent_refunds'; // the receiver's own id: proofs must be signed for it

// The person grants a parent agent up to $500/day of refunds. The planner is a sub-agent of it, narrowed to $100.
const parent = agent({
  principal: generateKeyPair(), // the person
  goal: 'refund customers for broken orders',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$500/day' },
  aud: REFUND_AGENT,
});
const planner = parent.subAgent({ addedCaveats: [{ type: 'max_spend', usd: 100 }] });

// ---- the planner (sender): sign one action and put it on the A2A task ----------------------------------------------

let n = 0;
function sendRefund(amount: number, aud?: string): A2ATask {
  const charge = `ch_${++n}`;
  const params = { amount, currency: 'usd' };
  const { pcactn } = planner.act('stripe.refund', `charge:${charge}`, params, aud ? { aud } : {});
  const task: A2ATask = {
    id: `task_${n}`,
    status: { state: 'submitted' },
    history: [{ role: 'user', messageId: `m_${n}`, parts: [{ kind: 'data', data: { charge, params } }] }],
  };
  return attachPcaToA2ATask(task, pcactn);
}

// ---- the refund agent (receiver) ---------------------------------------------------------------------------------

// protect() gives the receiver a revocation source it can flip. The A2A gate does the verification.
const server = protect({ audience: REFUND_AGENT, grants: [parent.grant], operation: () => ({ verb: 'stripe.refund', resource: '', params: {} }) });

/** The job in the task, as the receiver is about to run it. The proof must match this exactly (it commits to the params digest). */
function jobOf(task: A2ATask): { verb: string; resource: string; params: Record<string, unknown> } {
  const part = task.history?.[0]?.parts[0] as unknown as { data: { charge: string; params: Record<string, unknown> } } | undefined;
  return { verb: 'stripe.refund', resource: `charge:${part?.data.charge ?? ''}`, params: part?.data.params ?? {} };
}

const bMax = readEnvelope(parent.grant)?.risk_policy.bMax ?? 0;

let current: A2ATask | undefined; // the task being checked: the gate's context() needs the job it is about to run

const gate = pcaA2AMiddleware({
  aud: REFUND_AGENT,
  grant: parent.grant, // from the receiver's own list, never from the task
  hooks: server.options.hooks,
  context: (p: PCActn): PcaContext => {
    // The receiver's own view of the action. We do not read the plan, the params or the risk out of the proof.
    const job = jobOf(current!);
    const node: PlanNode = {
      id: String(p.plan.node_id),
      verb: job.verb,
      resource: job.resource,
      params_digest: paramsDigest(job.params),
      reversibility_class: p.action.reversibility_class as PlanNode['reversibility_class'],
    };
    const now = Date.now();
    // taint 0: this demo's task text is written by the demo itself. A real receiver derives it from where the content came from.
    return { params: job.params, plan: [node], planAuthorized: true, risk: catalogRisk(job.verb, job.params, parent.grant, { taint: 0 }), budget: { B: bMax, tau: now, asOf: now } };
  },
});

const seen = new Set<string>(); // shortcut: exact duplicates, in memory. Use a per-holder counter in a shared store when you run more than one instance.

async function receive(task: A2ATask): Promise<string> {
  current = task;
  const v = await gate(task);
  if (!v.ok) {
    const reason = (v.result?.reasons ?? [v.reason ?? 'denied']).find((x) => !x.includes('risk input')) ?? 'denied';
    return `DENIED (${reason}) -> ${explainRefusal(reason).fix}`;
  }
  const key = pcactnDigest(v.pcActn!);
  if (seen.has(key)) {
    const reason = 'replay: this proof was already used';
    return `DENIED (${reason}) -> ${explainRefusal(reason).fix}`;
  }
  seen.add(key);
  return 'ALLOWED';
}

// ---- the script --------------------------------------------------------------------------------------------------

let ok = true;
async function check(label: string, task: A2ATask, expect: 'ALLOWED' | 'DENIED'): Promise<void> {
  const out = await receive(task);
  const good = out.startsWith(expect);
  if (!good) ok = false;
  console.log(`${good ? 'ok  ' : 'FAIL'} ${label.padEnd(60)} -> ${out}`);
}

const first = sendRefund(60);
await check('planner asks for a $60 refund', first, 'ALLOWED');
await check('the proof was signed for another agent', sendRefund(60, 'agent_other'), 'DENIED');
await check('planner asks for $400 (it was delegated $100)', sendRefund(400), 'DENIED');
await check('the $60 task is sent again (replay)', first, 'DENIED');

server.revoke(parent.grant.id); // the person withdraws the grant: the hop stops everywhere
await check('after revoking the grant, a new $10 refund', sendRefund(10), 'DENIED');

console.log(ok ? '\nAll outcomes as expected.' : '\nAn outcome was not as expected.');
process.exit(ok ? 0 : 1);
