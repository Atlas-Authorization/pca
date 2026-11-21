---
title: Agent-to-agent (A2A) calls
order: 31
---

# Agent-to-agent (A2A) calls

A2A says how agents find each other and hand each other tasks. It does not say whether the task is something the person behind
the first agent allowed. PCA fills that gap: the sender signs the exact action and attaches the proof to the task, and the
receiver verifies it before it does anything.

Run the scaffold first:

```bash
npm create pca-app@latest my-a2a -- --template a2a
cd my-a2a && npm install && npm start
```

You see a refund allowed, then four refusals: a proof signed for another agent, a refund bigger than the sender was delegated,
the same task sent twice, and a new task after the grant is revoked.

## The sender

The sender is a sub-agent of the agent the person authorized. It signs one proof per task and attaches it.

```ts
import { agent, generateKeyPair } from '@atlasauth/pca';
import { attachPcaToA2ATask } from '@atlasauth/pca-a2a';

const parent = agent({ principal: generateKeyPair(), goal: 'refund customers', permissions: { stripe: ['refund'] },
                       limits: { refund: '$500/day' }, aud: 'agent_refunds' });
const planner = parent.subAgent({ addedCaveats: [{ type: 'max_spend', usd: 100 }] });

const { pcactn } = planner.act('stripe.refund', 'charge:ch_1', { amount: 60, currency: 'usd' });
const task = attachPcaToA2ATask({ id: 't1', status: { state: 'submitted' }, history: [/* the job */] }, pcactn);
```

`aud` is the receiving agent's own id. A proof signed for any other id is refused there.

## The receiver

```ts
import { pcaA2AMiddleware } from '@atlasauth/pca-a2a';

const gate = pcaA2AMiddleware({
  aud: 'agent_refunds',
  grant: storedGrant,                         // from your own list, never from the task
  hooks: { revocation: ({ grant }) => ({ enforced: true, ok: !revoked.has(grant.id) }) },
  context: (proof) => ({ /* params, plan, risk, budget: from the job you are about to run */ }),
});
const verdict = await gate(task);             // { ok: true, ... } or { ok: false, reason, result }
```

Three rules keep the receiver honest:

1. The grant (or the principal's key, `expectedRootIssuer`) comes from the receiver. A chain that arrives with the task is
   never its own authority.
2. The action it checks against, meaning verb, resource and params, is read from the job the receiver is about to run. The proof
   commits to those params, so a proof for a different amount or charge does not fit.
3. A proof is good for one action. The gate does not remember what it has seen, so keep a per-sender counter or a set of used
   proofs in a store all your instances share, and refuse a repeat with `replay`.

In the scaffold, `protect()` supplies the revocation source, and `explainRefusal(reason)` turns each refusal into a fix.

## More than one hop

Each further hop signs its own proof for its own audience, and its chain must extend the previous hop's. It can add
restrictions and never remove one. `verifyA2ADelegation` checks a whole path.

## When the receiver needs authority it does not have

It answers `TASK_STATE_AUTH_REQUIRED` with a typed need. A plain state change grants nothing. The caller resumes the task with a
fresh proof for exactly that need, and `resumeAuthRequired` checks that the proof matches the need before the task goes on.

## Signed Agent Cards

An Agent Card says who an agent is. `issueSignedAgentCard` signs it, and `verifyAgentCard` checks the signature. A signed card
proves who signed it. It does not prove authority: to trust an agent's authority, verify a proof.

## When something is refused

| Reason starts with | Meaning | Fix |
|---|---|---|
| `audience` | the proof names another receiver | sign with the receiver's own id |
| `delegated_caveats` or `policy` | the sender was narrowed below this action | delegate with the limits you intend |
| `replay` | the proof was already used | sign a fresh proof for each task |
| `revocation` | the grant was withdrawn | the person issues a new grant |
| `grant_ref_bound` | the receiver does not know this grant | add the grant to the receiver's list |

The full list is in [Refusal reasons](../reference/refusals.md). For the other golden paths, see [Golden paths](./golden-paths.md).
