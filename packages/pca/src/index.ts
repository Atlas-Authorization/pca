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
export * from './escalation';
export * from './risk';
export * from './envelope';
export * from './policy-vm';
export * from './revocation';
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
export * from './receipt';
export * from './discovery';
// NOTE: './durable-state' is Node-only (node:fs) and is deliberately NOT re-exported here; import it via '@atlasauth/pca/durable-state'.
// Resource-server verification (verdict + framework-neutral requirePCA guard). Lives HERE, not in any other product's SDK:
// PCA stands alone; the framework middleware packages (pca-fetch/express/fastify/hono/next) depend only on this package.
export * from './server/verify';
export * from './server/require-pca';
// The one authorization pipeline (requirePCA with every component required + binding to the executed operation).
export * from './server/authorize';
export * from './assurance';
export * from './server/authorize-execution';
// Operation records (execute at most once, recheck before an irreversible side effect, recovery) and the plan lifecycle.
export * from './server/operations';
export * from './server/plan-lifecycle';
export * from './config-snapshot';
// Experimental extensions (FROST, attestation, ZK, optimistic, intent layer, ledger, research modules) are NOT exported here: import them from '@atlasauth/pca/ext/<name>'.
