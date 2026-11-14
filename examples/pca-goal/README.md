# pca-goal

From a plain-English goal to an enforced policy: **draft, review, sign, enforce**.

```bash
npm install
npm start
```

1. `draftPolicyFromNL` asks a model (here a stub, so it runs offline) for a proposed policy. The model is injected;
   the result is only ever a draft.
2. A person reviews it: permissions, limits, analyzer findings, any verb the model made up.
3. `approveDraft` signs the exact draft. `loadApprovedPolicy` refuses an edited draft, an expired signature, or a
   key you did not pin.
4. `agentFromApprovedNL` is the only path from a draft to an agent. `protect()` and `requireAuthorized` decide every
   action on the server, against the signed grant.

## What this does not do

It does not prove the model understood the instruction, or that the reviewer read the draft. The signature shows that
a key you pinned approved this exact policy. For the typed, proof-carrying version (a goal compiled to policy with
tests and a semantic diff), see the goal-to-decision guide in the PCA docs.

## Make it yours

- Replace `complete` with a call to your model, using the prompt `nlPrompt(instruction)` builds.
- Keep the reviewer's secret key off the machine that runs the agent.
