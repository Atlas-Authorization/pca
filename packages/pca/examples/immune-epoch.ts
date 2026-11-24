/** Adaptive risk epoch: see src/test-support/flow-immune-epoch.ts. Run: pnpm --filter @atlasauth/pca exec tsx examples/immune-epoch.ts */
import type { ActivityEvent } from '../src/console';
import { runImmuneEpoch } from '../src/test-support/flow-immune-epoch';

const now = Date.now();
const events: ActivityEvent[] = Array.from({ length: 12 }, (_, i) => ({ agent: 'agent-1', verb: 'pay', resource: 'r', at: now - (12 - i) * 1000, outcome: i > 5 ? 'deny' : 'auto', r: i > 5 ? 0.9 : 0.1 }) as ActivityEvent);
console.log(await runImmuneEpoch(events, now));
