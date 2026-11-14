/** A behavioural contract enforced durably. Run: pnpm --filter @atlasauth/pca exec tsx examples/contract-enforcer.ts */
import { runContractFlow } from '../src/test-support/flow-contract-enforcer';

console.log(await runContractFlow(['review', 'deploy', 'delete', 'review']));
