---
title: Natural-language policy, generate then review
order: 10
---

# Natural-language policy: generate, then review

A language model can draft a policy from a plain instruction. It can never enforce one. This page describes the loop and states exactly what it does and does not guarantee.

> **Status: experimental.** It lives under `@atlasauth/pca/ext/research`. See [maturity tiers](../maturity.md).

## The loop

1. `draftPolicyFromNL({ instruction, complete })` calls your model (an injected `complete(prompt)` function) and returns a **draft**: permissions, limits, the static-analyzer findings, any verbs the model made up, and a digest of the exact content. A draft is data. Nothing can be minted from it.
2. A human reviews the draft and calls `approveDraft(draft, reviewerSecret)`. That signs the digest (Ed25519, domain separated) together with the catalog digest, the instruction text, the model id and the prompt, and a validity window of at most 24 hours (approval v2).
3. `agentFromApprovedNL({ draft, approval, reviewers, principal, goal })` is the only path from the draft to an agent. `reviewers` is the list of reviewer public keys **you** pin. `loadApprovedPolicy` does the same check without minting an agent.

```ts
import { agentFromApprovedNL, approveDraft, draftPolicyFromNL } from '@atlasauth/pca/ext/research';

const draft = await draftPolicyFromNL({ instruction: 'let the support bot refund up to $200/day', complete });
// show draft.permissions, draft.limits, draft.lints to a person...
const approval = approveDraft(draft, reviewerSecretKey);
const { agent } = agentFromApprovedNL({ draft, approval, reviewers: [reviewerPublicKey], principal, goal: draft.instruction, aud: 'rs.example' });
```

## What is guaranteed

- Nothing a model said is turned into policy without an unexpired signature, from a key you pinned, over the exact permissions, limits and catalog.
- Every verb is in your connector catalog. A verb the model invented blocks approval and is refused by the loader.
- A draft with an error-level analyzer finding, or with no permissions at all, is refused.
- The loader recomputes the digest, the grounding and the analyzer findings from the draft content. It does not trust the draft's own `analyzerOk` or `lints` fields.
- Model output larger than 16 KiB is refused.

## What is not guaranteed

- That the model understood the instruction. A draft can be wrong and still well formed.
- That the reviewer read it. The signature proves a pinned key approved a digest, not that a person understood it.
- That the catalog's risk labels are right for your business.

## Refusal reasons

`loadApprovedPolicy` returns `{ ok: false, reason }` and never throws. Reasons: `no_reviewers_pinned`, `not_a_draft`, `catalog_mismatch`, `tampered_draft`, `unknown_verbs`, `empty_permissions`, `analyzer_error`, `malformed_approval`, `digest_mismatch`, `reviewer_not_pinned`, `ttl_too_long`, `not_yet_valid`, `expired`, `bad_signature`, `goal_mismatch` (thrown by `agentFromApprovedNL` when `goal` is not the approved instruction).

Approvals signed before 0.5 (v1) still load for one release and are flagged `legacy_unbound_instruction`: their signature never covered the instruction.

## Upgrading

`agentFromNL` is removed because it minted an enforceable agent straight from model output. Replace it with the three steps above.
