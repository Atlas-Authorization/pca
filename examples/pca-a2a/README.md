# pca-a2a

An **A2A hop**: one agent signs an action for another agent, and the receiver verifies it before it runs anything.

```bash
npm install
npm start
```

You see four outcomes and a revocation, each with its reason:

| Outcome | Why |
|---|---|
| A $60 refund runs | the proof is for this agent, this charge and these params |
| A proof signed for another agent is refused | `audience`: the proof names a different receiver |
| A $400 refund is refused | the planner is a sub-agent narrowed to $100; a sub-delegation can only narrow |
| The same task sent twice is refused | `replay`: a proof is good for one action |
| After the grant is revoked, a new refund is refused | `protect()` gives the receiver a revocation switch |

- The sender builds the proof with `agent.act(...)` and rides it on the A2A task with `attachPcaToA2ATask`.
- The receiver guards incoming tasks with `pcaA2AMiddleware`. Its grant comes from its own list, and the action it checks
  against (verb, resource, params) comes from the task it is about to run, not from the proof.
- `explainRefusal(reason)` turns a refusal into what it means and how to fix it.

## Make it yours

- Replace the in-memory replay set with a per-sender counter in a store shared by all your instances.
- Replace `grant: parent.grant` with a lookup in your database.
- When the receiver needs authority it does not have, it can park the task in `TASK_STATE_AUTH_REQUIRED` and ask for a
  proof for exactly that need: see the A2A guide in the PCA docs.
