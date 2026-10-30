/** NL to policy, generate-then-review. Run: pnpm --filter @atlasauth/pca exec tsx examples/nl-draft-review.ts */
import { run } from '../src/test-support/flow-nl-review';

console.log(await run());
