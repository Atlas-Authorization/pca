/**
 * THE RUNNER — the whole loop, end to end, in one process.
 *
 *   npm install
 *   npm start
 *
 * It starts the resource server, has the agent try three refunds — two within its $500 limit, one
 * over it — and prints ALLOWED / DENIED for each. It exits nonzero if an outcome is not the expected one. The legit refund verifies and is allowed; the
 * over-budget one is denied by the server's policy, even though the proof itself is perfectly valid.
 */

import type { AddressInfo } from 'node:net';
import { AUDIENCE, createQuickstartAgent } from './agent.js';
import { createServer } from './server.js';

async function main(): Promise<void> {
  // 1. The agent (built from the human's intent with the one-line facade).
  const agent = createQuickstartAgent();

  // 2. The resource server, told which grant to trust.
  const { app, authorize } = createServer({ grant: agent.grant, audience: AUDIENCE });

  // 3. Two actions the agent wants to take.
  const legit = agent.refund(42, 'ch_happy', 1); // within the $500 cap
  const second = agent.refund(100, 'ch_second', 2); // also within it: the first refund spent only 42 of the budget
  const overBudget = agent.refund(5000, 'ch_whale', 3); // over the $500 cap

  // 4. The human principal authorizes the plans with the server (registers their roots).
  authorize(legit.planRoot);
  authorize(second.planRoot);
  authorize(overBudget.planRoot);

  // 5. Start the server on an ephemeral port.
  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  const { port } = server.address() as AddressInfo;
  const url = `http://127.0.0.1:${port}/refunds`;

  // 6. Fire each action and print the verdict.
  const cases: ReadonlyArray<readonly [string, typeof legit, boolean]> = [
    ['refund $42 (within limit)', legit, true],
    ['refund $100 (within limit)', second, true],
    ['refund $5000 (over limit)', overBudget, false],
  ];
  let ok = true;
  for (const [label, action, expectAllowed] of cases) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pcactn: action.pcactn, charge: action.charge, params: action.params }),
    });
    const body = (await res.json()) as { error?: string; verdict?: { reasons?: string[] } };
    console.log(`${label.padEnd(28)} -> ${res.ok ? 'ALLOWED' : 'DENIED'} (HTTP ${res.status})`);
    if (!res.ok) console.log(`   reason: ${body.error ?? body.verdict?.reasons?.join('; ') ?? 'denied'}`);
    if (res.ok !== expectAllowed) ok = false;
  }

  server.close();
  if (!ok) {
    console.error('An outcome was not the expected one.');
    process.exitCode = 1;
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
