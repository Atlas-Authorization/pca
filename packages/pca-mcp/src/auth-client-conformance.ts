/**
 * MCP authorization conformance matrix for the CLIENT side of step-up (see the resource-server rows in
 * `@atlasauth/pca-mcp-rs`, same sources and fetch date: github.com/modelcontextprotocol/modelcontextprotocol main at
 * 54b91cdb, 2026-10-26, docs/specification/<revision>/basic/authorization). The test runs a check per non-`n/a` cell.
 */
export const MCP_CLIENT_REVISIONS = ['2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28', 'draft'] as const;
export type McpClientRevision = (typeof MCP_CLIENT_REVISIONS)[number];
export type McpClientLevel = 'MUST' | 'SHOULD' | 'MAY' | 'EXT' | 'n/a';

export interface McpClientRow {
  id: string;
  requirement: string;
  levels: Record<McpClientRevision, McpClientLevel>;
  section: string;
}

const L = (a: McpClientLevel, b: McpClientLevel, c: McpClientLevel, d: McpClientLevel, e: McpClientLevel): Record<McpClientRevision, McpClientLevel> => ({
  '2025-03-26': a,
  '2025-06-18': b,
  '2025-11-25': c,
  '2026-07-28': d,
  draft: e,
});

export const MCP_AUTH_CLIENT_ROWS: readonly McpClientRow[] = [
  { id: 'parse-www-authenticate', requirement: 'Parse WWW-Authenticate headers (quoted strings, several challenges) and respond to 401.', levels: L('n/a', 'MUST', 'MUST', 'MUST', 'MUST'), section: 'Protected Resource Metadata Discovery Requirements' },
  { id: 'step-up-on-insufficient-scope', requirement: 'Respond to 403 insufficient_scope by re-authorizing with an increased scope set.', levels: L('n/a', 'n/a', 'SHOULD', 'SHOULD', 'SHOULD'), section: 'Step-Up Authorization Flow' },
  { id: 'scope-union', requirement: 'The new scope set is the union of the previously requested set and the challenge scopes.', levels: L('n/a', 'n/a', 'n/a', 'SHOULD', 'SHOULD'), section: 'Step-Up Authorization Flow, step 2' },
  { id: 'retry-limit', requirement: 'Retry no more than a few times and track upgrade attempts per resource and operation.', levels: L('n/a', 'n/a', 'SHOULD', 'SHOULD', 'SHOULD'), section: 'Step-Up Authorization Flow, step 4' },
  { id: 'iss-validation-table', requirement: 'Validate the RFC 9207 iss parameter against the recorded issuer, by the four-row table, with no normalization.', levels: L('n/a', 'n/a', 'n/a', 'MUST', 'MUST'), section: 'Authorization Response Validation' },
  { id: 'pca-need-ignored-by-stock-client', requirement: 'A client that does not know pca_need behaves exactly as without it.', levels: L('EXT', 'EXT', 'EXT', 'EXT', 'EXT'), section: 'RFC 9110 section 11.2 (unknown auth-params are ignored)' },
];
