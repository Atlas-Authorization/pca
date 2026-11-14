/**
 * How each MCP tool call maps to a PCA action (a verb and a resource).
 *
 * The agent uses this mapping to build the proof it sends with a tool call. The server uses the SAME mapping to
 * check that the proof it received is for the tool call it is about to run: a valid proof for "refund $42 on ch_1"
 * must not unlock "delete customer cus_9". In production the server owns this table; the agent can read it from
 * your docs or a published action schema.
 */

export const PORT = Number(process.env['PORT'] ?? 8788);

/** This MCP server's URL, and its audience: every proof is minted for it, and a proof for another server is refused. */
export const MCP_URL = `http://127.0.0.1:${PORT}/mcp`;
export const PRM_URL = `http://127.0.0.1:${PORT}/.well-known/oauth-protected-resource`;

/** The PCA verb and resource for one MCP tool call, or null for a tool that has no mapping (refused). */
export function toolAction(tool: string, args: Record<string, unknown>): { verb: string; resource: string } | null {
  switch (tool) {
    case 'refund':
      return { verb: 'stripe.refund', resource: `charge:${String(args['chargeId'])}` };
    case 'delete_customer':
      return { verb: 'stripe.delete_customer', resource: `customer:${String(args['customerId'])}` };
    default:
      return null;
  }
}
