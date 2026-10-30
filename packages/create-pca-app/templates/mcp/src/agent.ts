/**
 * An MCP agent (client) that sends a proof-carrying action with every tool call.
 *
 * 1. The principal (the human) creates the agent with a grant: refunds only, at most $500 each.
 * 2. The grant is registered with the server out of band (here: a file in ./.grants).
 * 3. The MCP client's fetch is `pcaFetch`: it adds a fresh `PCA-Action` header, signed by the agent's key, to each
 *    `tools/call`.
 *
 * Then it makes five calls and checks the server's answers:
 *   refund $42            -> allowed
 *   refund $100           -> allowed (the server priced the first refund at 42 of the $500 budget)
 *   delete_customer       -> denied: the grant does not permit stripe.delete_customer
 *   refund $5000          -> denied: over the $500 limit
 *   refund with no proof  -> denied: the tool requires a proof-carrying action
 *
 * The agent signs the out-of-scope calls on purpose, to play a prompt-injected agent: its key can sign anything,
 * and the server still refuses, because the decision comes from the grant.
 *
 * Run it:  npm run agent     (with `npm start` running in another terminal)
 */

import { pathToFileURL } from 'node:url';
import { agent, generateKeyPair } from '@atlasauth/pca';
import { pcaFetch } from '@atlasauth/pca-mcp';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { registerGrant } from './store.js';
import { MCP_URL, toolAction } from './tools.js';

async function connect(fetchImpl: typeof fetch): Promise<Client> {
  const client = new Client({ name: 'pca-quickstart-agent', version: '0.1.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(MCP_URL), { fetch: fetchImpl }));
  return client;
}

function textOf(result: unknown): string {
  const content = (result as { content?: Array<{ type: string; text?: string }> }).content ?? [];
  return content.map((c) => c.text ?? '').join(' ');
}

/** Run the calls; returns true when every outcome is the expected one. */
export async function runAgent(): Promise<boolean> {
  const a = agent({
    principal: generateKeyPair(), // the human's key; in production their passkey-backed root key
    goal: 'refund customers for broken orders',
    permissions: { stripe: ['refund'] }, // refunds only
    limits: { refund: '$500/day' }, // at most $500 per refund
    aud: MCP_URL, // the MCP server these proofs are for
  });
  registerGrant(a.grant); // out of band: the principal registers the grant with the server

  const client = await connect(pcaFetch(a, toolAction));
  const plain = await connect(fetch); // a client that sends no proof at all

  const calls = [
    { label: 'refund $42', client, name: 'refund', args: { chargeId: 'ch_123', amount: 42 }, expect: 'allowed' },
    { label: 'refund $100', client, name: 'refund', args: { chargeId: 'ch_124', amount: 100 }, expect: 'allowed' },
    { label: 'delete_customer', client, name: 'delete_customer', args: { customerId: 'cus_42' }, expect: 'denied' },
    { label: 'refund $5000', client, name: 'refund', args: { chargeId: 'ch_456', amount: 5000 }, expect: 'denied' },
    { label: 'refund, no proof', client: plain, name: 'refund', args: { chargeId: 'ch_789', amount: 10 }, expect: 'denied' },
  ] as const;

  let ok = true;
  for (const c of calls) {
    const result = await c.client.callTool({ name: c.name, arguments: c.args });
    const got = result.isError === true ? 'denied' : 'allowed';
    if (got !== c.expect) ok = false;
    console.log(`${got === c.expect ? 'ok  ' : 'FAIL'} ${c.label.padEnd(17)} -> ${got.toUpperCase()}: ${textOf(result)}`);
  }
  await client.close();
  await plain.close();
  console.log(ok ? '\nAll outcomes as expected.' : '\nAn outcome was not as expected.');
  return ok;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runAgent().then(
    (ok) => process.exit(ok ? 0 : 1),
    (err: unknown) => {
      console.error(err);
      console.error('\nIs the server running? Start it with `npm start` in another terminal.');
      process.exit(1);
    },
  );
}
