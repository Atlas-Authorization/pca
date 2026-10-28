/**
 * `explainRefusal(reason)`: turn a refusal reason from `authorize` / `requirePCA` / `verifyPCActn` into what it means, how to
 * fix it, and the page that explains it. The reasons themselves are pinned across all ten languages and the conformance
 * vectors, so they are never reworded; this maps them (by their leading check name) to guidance instead. Unknown reasons
 * return a generic entry that still links the table.
 */

/** Base of the published PCA docs. */
export const PCA_DOCS = 'https://github.com/Atlas-Authorization/pca/blob/main/docs';

export interface RefusalHelp {
  /** The check that refused (the reason's leading token), or `unknown`. */
  check: string;
  meaning: string;
  fix: string;
  docs: string;
}

const REF = `${PCA_DOCS}/reference/refusals.md`;

const TABLE: ReadonlyArray<readonly [string, string, string, string]> = [
  ['authorize_config', 'The guard was built without a required component, so it refuses every request (fail closed).', 'Add the component the reason names (audience, resolveGrant, budgetStore, hooks.revocation). protect() fills them with safe defaults.', `${PCA_DOCS}/guides/resource-server-quickstart.md`],
  ['authorize', 'The guard was built without a required component, so it refuses every request (fail closed).', 'Add the component the reason names (audience, resolveGrant, budgetStore, hooks.revocation). protect() fills them with safe defaults.', `${PCA_DOCS}/guides/resource-server-quickstart.md`],
  ['operation', 'The signed action is not the operation this route executes (other verb, resource or params).', 'Sign the action the route runs, with the same params. If this is a tool server, use one tool-to-action mapping on both sides.', `${REF}#operation`],
  ['audience', 'The proof was signed for a different server.', 'Make the agent sign with the same audience string the server is configured with.', `${REF}#audience`],
  ['replay', 'This proof (or an older counter) was already used.', 'Each action needs a fresh proof. If this is a retry of an action that already ran, use an operation record instead of resending.', `${REF}#replay`],
  ['counter_format', 'The proof carries no valid anti-replay counter.', 'Build the proof with the agent facade (act) or buildPCActn, which set it.', `${REF}#replay`],
  ['plan_root_authorized', 'The plan the action belongs to was not authorized by the principal.', 'Use plan: single-step (protect() does) for one-action proofs, or have the principal authorize the committed plan root.', `${REF}#plan_root_authorized`],
  ['plan_state', 'The plan is committed but not executable now (not authorized, expired or revoked).', 'Check the plan state named in the reason and re-authorize or recommit.', `${REF}#plan_root_authorized`],
  ['revocation', 'The grant, or the revocation source, refused.', 'The grant was revoked, or no revocation source is configured. Configure hooks.revocation (protect() does).', `${REF}#revocation`],
  ['validity', 'The proof is outside its validity window.', 'Check clocks on both sides; request a fresh proof.', `${REF}#validity`],
  ['grant_ref', 'The proof does not name a grant this server knows.', 'Register the principal\'s grant with the server (its grants list or resolveGrant). The grant comes from your store, never from the request.', `${REF}#grant_ref`],
  ['grant_ref_bound', 'The proof does not name a grant this server knows.', 'Register the principal\'s grant with the server (its grants list or resolveGrant). The grant comes from your store, never from the request.', `${REF}#grant_ref`],
  ['policy', 'The grant does not permit this action or these parameters (a predicate or limit failed).', 'Widen the grant if the action is legitimate (the principal signs a new one); otherwise this is the guard working.', `${REF}#policy`],
  ['delegated_caveats', 'A caveat added by a delegation refused the action.', 'The sub-agent was narrowed below this action. Delegate with the caveats you intend.', `${REF}#policy`],
  ['threshold', 'The risk needs a co-signature from the principal (step-up).', 'Collect the co-sign through the step-up flow, or lower the risk the server prices.', `${PCA_DOCS}/concepts/threshold-and-step-up.md`],
  ['risk_inputs', 'A risk input the server must vouch for was not supplied.', 'Supply it in the risk option (catalogRisk derives the common ones; protect() uses it).', `${REF}#risk_inputs`],
  ['chain', 'The delegation chain does not verify back to the grant.', 'Rebuild the chain with delegate()/subAgent(); do not edit a grant or hop after signing.', `${REF}#chain`],
  ['leaf_signature', 'The proof signature does not verify.', 'The proof was altered, or signed by a key that is not the chain leaf.', `${REF}#chain`],
  ['wire', 'The proof is not well-formed under the strict wire profile.', 'Send the proof exactly as encoded by encodePCActn (header PCA-Action, or body { pcactn }).', `${PCA_DOCS}/reference/wire-formats.md`],
  ['malformed', 'The proof could not be read.', 'Send the proof exactly as encoded by encodePCActn (header PCA-Action, or body { pcactn }).', `${PCA_DOCS}/reference/wire-formats.md`],
  ['freshness', 'The consistency token or revocation epoch is stale.', 'Refresh the token from the guardian and retry.', `${REF}#freshness`],
  ['template', 'The grant is not an instantiation of a linked policy template.', 'Mint the grant from the template the server requires.', `${PCA_DOCS}/guides/policy-analysis.md`],
];

/** Guidance for a refusal reason. Never throws. */
export function explainRefusal(reason: unknown): RefusalHelp {
  const text = typeof reason === 'string' ? reason : '';
  const head = /^[a-z_]+/.exec(text)?.[0] ?? '';
  const hit = TABLE.find(([c]) => c === head) ?? TABLE.find(([c]) => text.includes(`${c}:`));
  if (hit) return { check: hit[0], meaning: hit[1], fix: hit[2], docs: hit[3] };
  return { check: 'unknown', meaning: 'The guard refused and the reason is not in the table.', fix: 'Read the reason as written; every refusal names the check that failed.', docs: REF };
}
