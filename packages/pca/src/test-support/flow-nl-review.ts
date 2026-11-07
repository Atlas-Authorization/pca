/**
 * NL to policy, generate-then-review: a model proposes a DRAFT, a pinned human reviewer signs the exact
 * compiled policy, and only then can an agent be minted. Used by examples/nl-draft-review.ts and src/nl-example.test.ts.
 */
import { generateKeyPair } from '../keys';
import { b64u } from '../hash';
import { agentFromApprovedNL, approveDraft, draftPolicyFromNL } from '../nl';

export async function run(): Promise<{ verbs: string[]; refusedWithoutApproval: string }> {
  // 1. any model: an injected `complete(prompt)`. Here a fake one.
  const draft = await draftPolicyFromNL({
    instruction: 'let the support bot refund up to $200/day',
    complete: () => JSON.stringify({ permissions: { stripe: ['refund'] }, limits: { refund: '$200/day' } }),
  });
  // 2. the human reviews draft.permissions / draft.limits / draft.lints, then signs the digest with a key you pinned.
  const reviewer = generateKeyPair();
  const approval = approveDraft(draft, reviewer.secretKey);
  const reviewers = [b64u(reviewer.publicKey)];
  // 3. no approval from a pinned key, no agent.
  let refusedWithoutApproval = '';
  try {
    agentFromApprovedNL({ draft, approval, reviewers: [b64u(generateKeyPair().publicKey)], principal: generateKeyPair(), goal: draft.instruction });
  } catch (e) {
    refusedWithoutApproval = (e as Error).message;
  }
  const { agent } = agentFromApprovedNL({ draft, approval, reviewers, principal: generateKeyPair(), goal: draft.instruction, aud: 'rs.example' });
  return { verbs: agent.policy.actions.map((s) => s.verb), refusedWithoutApproval };
}
