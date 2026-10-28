export * from './hash';
export * from './strict-json';
export * from './strict-jws'; // canonical compact-JWS gate (run BEFORE jose)
export * from './wire';
export * from './keys';
export * from './pq';
export * from './safe-regex';
export * from './regex-budget';
export * from './regex-cache';
export * from './merkle';
export * from './capability';
export * from './pcactn';
// The full verifier entry points (Intent Layer loaded); they shadow the extension-free `verifyPCActnCore` / `validateWireV2` above.
export { verifyPCActnCore, validateWireV2 } from './pcactn-full';
export * from './pcactn-cheap-claims';
export * from './threshold';
export * from './predicates';
export * from './decision';
export * from './obligations'; // decision obligations: an unsupported obligation turns allow into deny (K8)
export * from './policy-classes'; // the classes consulted for a decision and who said no (K8)
export * from './missing-context'; // typed missing context and the stored-wins rule (K8)
export * from './escalation';
export * from './approval-render';
export * from './caveat-lang';
export * from './provenance-gate';
export * from './detector-receipt';
export * from './risk';
export * from './envelope';
export * from './policy-vm';
export * from './revocation';
export * from './action-scopes'; // scopes derived from the confirmed action (K6)
export * from './pca-need'; // the additive `pca_need` challenge parameter (K6)
export * from './pca-grant-details'; // the `pca_grant` RFC 9396 authorization-details type (K6)
// workflow (DAG) and read-side authorization (K5); the strict-shape helpers they share stay internal
export {
  WORKFLOW_DOMAIN, WF_RECEIPT_DOMAIN, WORKFLOW_LIMITS, admitStep, bindPromises, planRootAuthorized, signWorkflow, signStepReceipt, wfOutput, workflowDigest, receiptRef as wfReceiptRef,
  validWorkflowBody, dagError, workflowCommitmentError, workflowReceiptError, valueDigest as wfValueDigest,
} from './workflow';
export type { K5Decision, SignedWorkflow, WorkflowBody, WfStep, WfEdge, WfReceipt, WfOutput, WfRequest, WfResult, AdmitInput } from './workflow';
export {
  READ_GRANT_DOMAIN, READ_RECEIPT_DOMAIN, redactRead, checkSink, readChainLabels, readGrantDigest, readReceiptRef, signReadGrant, signReadReceipt, validReadGrantBody,
} from './readside';
export {
  memoryVault, redactReadWithVault, detokenize, signAggregateGrant, aggregateRead, emptyAggregateState, aggregateGrantDigest, validAggregateGrantBody, AGGREGATE_DOMAIN,
} from './read-vault';
export type { VaultEntry, VaultStore, DetokenizeInput, DetokenizeResult, AggregateRule, AggregateGrantBody, SignedAggregateGrant, AggregateState, AggregateInput, AggregateResult } from './read-vault';
export type { ReadGrantBody, SignedReadGrant, ReadReceipt, ReadField, ReadInput, ReadResult, SinkInput } from './readside';
export * from './fresh-at';// consistency tokens (`fresh_at`): the PCActn member + the verifier check
export * from './replay'; // ReplayStore / CounterStore contract + guardPCActnReplay + reference in-memory store
export * from './catalog-risk';
export * from './facade';

export * as prohibitions from './prohibitions';
export * as agentNative from './agent-native';
export * as taint from './taint';

export * from './adapters';
export * from './approvals';
export * from './approval-channels';
export * from './policy-templates';
export * from './forbid-certificate';
export * from './policy-link';
export * from './receipt';
export * from './discovery';
// NOTE: './durable-state' is Node-only (node:fs) and is deliberately NOT re-exported here; import it via '@atlasauth/pca/durable-state'.
// Resource-server verification (verdict + framework-neutral requirePCA guard). Lives HERE, not in any other product's SDK:
// PCA stands alone; the framework middleware packages (pca-fetch/express/fastify/hono/next) depend only on this package.
export * from './server/verify';
export * from './server/require-pca';
// The one authorization pipeline (requirePCA with every component required + binding to the executed operation).
export * from './server/authorize';
// One-call secure defaults for a resource server (grant list, replay store, revocation, single-step plan, catalog risk).
export * from './server/protect';
export * from './refusal-help';
export * from './assurance';
export * from './server/authorize-execution';
// Operation records (execute at most once, recheck before an irreversible side effect, recovery) and the plan lifecycle.
export * from './server/operations';
export * from './server/plan-lifecycle';
export * from './config-snapshot';
// Experimental extensions (FROST, attestation, ZK, optimistic, intent layer, ledger, research modules) are NOT exported here: import them from '@atlasauth/pca/ext/<name>'.
export * from './chain-compact';
