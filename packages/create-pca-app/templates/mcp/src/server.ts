/**
 * An MCP server (Streamable HTTP) with two tools, `refund` and `delete_customer`. Every tool call must carry a
 * proof-carrying action in the `PCA-Action` header, and the tool runs only if `authorizeToolCall` allows it:
 *
 *   - the proof chains to a grant from THIS server's store and is for this server (audience), fresh and not replayed;
 *   - it is for THIS call: its signed verb and resource are what `toolAction(tool, args)` says, and the tool
 *     arguments match the signed digest;
 *   - the grant's permissions and limits allow it, and the agent's trust budget covers it.
 *
 * A refused call comes back as an MCP tool error (`isError: true`) with the reason, so the model can see why.
 *
 * Run it:  npm start     (then, in another terminal: npm run agent)
 */

import type { Server } from 'node:http';
import { pathToFileURL } from 'node:url';
import { memoryPcaStore } from '@atlasauth/pca';
import { authorizeToolCall } from '@atlasauth/pca-mcp-rs';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js';
import { z } from 'zod';
import { fileGrantStore } from './store.js';
import { MCP_URL, PORT, PRM_URL, toolAction } from './tools.js';

type ToolResult = { content: Array<{ type: 'text'; text: string }>; isError?: boolean };
type Extra = { requestInfo?: { headers: Record<string, string | string[] | undefined> } };

export function startServer(port: number = PORT): Promise<Server> {
  const grants = fileGrantStore();
  // Replay counters and trust budgets, per agent. In memory here; Redis or your database in production.
  const state = memoryPcaStore();

  /** Wrap a tool handler: authorize the call first, run the handler only when it is allowed. */
  function requirePca<A extends Record<string, unknown>>(tool: string, handler: (args: A) => ToolResult) {
    return async (args: A, extra: Extra): Promise<ToolResult> => {
      const r = await authorizeToolCall(
        { headers: extra.requestInfo?.headers ?? {} },
        {
          resource: MCP_URL, // the proof's signed audience must be this server
          prmUrl: PRM_URL, // named in the WWW-Authenticate challenge (r.wwwAuthenticate) if you refuse at the HTTP level
          tool,
          args,
          toolAction,
          resolveGrant: (ref) => grants.get(ref), // our own store, never the request
          isRevoked: (grant) => grants.isRevoked(grant.id),
          state,
        },
      );
      if (!r.ok) {
        console.log(`DENIED  ${tool}: ${r.reason}${r.hint ? `  (hint: ${r.hint})` : ''}`);
        return { content: [{ type: 'text', text: `PCA denied: ${r.reason}` }], isError: true };
      }
      console.log(`ALLOWED ${tool} ${JSON.stringify(args)}`);
      return handler(args);
    };
  }

  function mcpServer(): McpServer {
    const server = new McpServer({ name: 'pca-mcp-quickstart', version: '0.1.0' });
    server.registerTool(
      'refund',
      { description: 'Refund a charge.', inputSchema: { chargeId: z.string(), amount: z.number() } },
      requirePca('refund', (args: { chargeId: string; amount: number }) => ({
        content: [{ type: 'text', text: `refunded $${args.amount} on ${args.chargeId}` }],
      })),
    );
    server.registerTool(
      'delete_customer',
      { description: 'Delete a customer record.', inputSchema: { customerId: z.string() } },
      requirePca('delete_customer', (args: { customerId: string }) => ({
        content: [{ type: 'text', text: `deleted ${args.customerId}` }],
      })),
    );
    return server;
  }

  const app = createMcpExpressApp();
  // Stateless Streamable HTTP: a fresh server and transport per request.
  app.post('/mcp', async (req, res) => {
    const server = mcpServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  return new Promise((resolveListen) => {
    const http = app.listen(port, '127.0.0.1', () => {
      console.log(`MCP server on ${MCP_URL}; every tool call needs a PCA-Action header`);
      resolveListen(http);
    });
  });
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void startServer();
}
