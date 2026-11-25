/**
 * One command: start the MCP server, run the agent against it, stop. Exits nonzero if any outcome is unexpected.
 *
 * Run it:  npm run demo
 */

import { startServer } from './server.js';
import { runAgent } from './agent.js';

const server = await startServer();
let ok = false;
try {
  ok = await runAgent();
} finally {
  server.close();
}
process.exit(ok ? 0 : 1);
