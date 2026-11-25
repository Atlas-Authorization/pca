/**
 * MCP authorization conformance matrix for the resource-server side: one row per requirement, one cell per specification
 * revision, each cell carrying the requirement level the revision gives it and where. `spec-conformance.test.ts` runs a
 * check for every non-`n/a` cell, so compliance with a revision is a test result, not a claim.
 *
 * Sources, fetched 2026-10-26 from github.com/modelcontextprotocol/modelcontextprotocol (main at 54b91cdb), paths
 * docs/specification/<revision>/basic/authorization (a single file `authorization.mdx` before 2026-07-28, an `index.mdx`
 * with `authorization-server-discovery`, `client-registration` and `security-considerations` pages from 2026-07-28).
 * Published at https://modelcontextprotocol.io/specification/<revision>/basic/authorization. `draft` is the unreleased
 * working text; re-fetch before relying on a `draft` cell.
 *
 * The client-side rows (RFC 9207 `iss` table, scope union, retry limits) are in `@atlasauth/pca-mcp`.
 */
export const MCP_AUTH_REVISIONS = ['2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28', 'draft'] as const;
export type McpAuthRevision = (typeof MCP_AUTH_REVISIONS)[number];

/** `EXT` = not a requirement of the revision: an extension the revision's own references allow (RFC 6750 / RFC 9110 11.2). */
export type McpLevel = 'MUST' | 'MUST NOT' | 'SHOULD' | 'MAY' | 'EXT' | 'n/a';

export interface McpAuthRow {
  id: string;
  /** What a resource server does. */
  requirement: string;
  /** Level per revision. `n/a` = the revision has no such requirement (the check is not run for it). */
  levels: Record<McpAuthRevision, McpLevel>;
  /** Section of the specification the requirement comes from (same heading in every revision unless noted). */
  section: string;
}

const L = (a: McpLevel, b: McpLevel, c: McpLevel, d: McpLevel, e: McpLevel): Record<McpAuthRevision, McpLevel> => ({
  '2025-03-26': a,
  '2025-06-18': b,
  '2025-11-25': c,
  '2026-07-28': d,
  draft: e,
});

export const MCP_AUTH_RS_ROWS: readonly McpAuthRow[] = [
  { id: 'prm-served', requirement: 'Serve RFC 9728 Protected Resource Metadata naming the resource and its authorization servers.', levels: L('n/a', 'MUST', 'MUST', 'MUST', 'MUST'), section: 'Authorization Server Location' },
  { id: 'challenge-resource-metadata', requirement: 'A 401 carries WWW-Authenticate Bearer resource_metadata pointing at the metadata document.', levels: L('n/a', 'MUST', 'MUST', 'MUST', 'MUST'), section: 'Protected Resource Metadata Discovery Requirements' },
  { id: 'unauthorized-401', requirement: 'No proof, an invalid proof or an expired proof is HTTP 401.', levels: L('MUST', 'MUST', 'MUST', 'MUST', 'MUST'), section: 'Access Token Usage / Error Handling' },
  { id: 'forbidden-403', requirement: 'Valid credentials without sufficient permission are HTTP 403.', levels: L('MUST', 'MUST', 'MUST', 'MUST', 'MUST'), section: 'Error Handling' },
  { id: 'audience-validation', requirement: 'Accept only credentials issued for this server (RFC 8707 audience).', levels: L('n/a', 'MUST', 'MUST', 'MUST', 'MUST'), section: 'Token Handling' },
  { id: 'no-token-passthrough', requirement: 'Accept only this server\'s credential type; a foreign bearer token is not accepted.', levels: L('n/a', 'MUST NOT', 'MUST NOT', 'MUST NOT', 'MUST NOT'), section: 'Token Handling' },
  { id: 'insufficient-scope-challenge', requirement: '403 with error="insufficient_scope", scope and resource_metadata.', levels: L('n/a', 'n/a', 'SHOULD', 'SHOULD', 'SHOULD'), section: 'Runtime Insufficient Scope Errors' },
  { id: 'scope-in-first-401', requirement: 'The first 401 names the scopes the resource needs.', levels: L('n/a', 'n/a', 'SHOULD', 'SHOULD', 'SHOULD'), section: 'Scope Selection Strategy' },
  { id: 'scopes-one-challenge', requirement: 'All scopes the operation needs are emitted in a single challenge, not one per retry.', levels: L('n/a', 'n/a', 'n/a', 'SHOULD', 'SHOULD'), section: 'Server Scope Management' },
  { id: 'scope-hierarchy', requirement: 'A broader granted scope satisfies the narrower scopes it implies.', levels: L('n/a', 'n/a', 'n/a', 'MUST', 'MUST'), section: 'Step-Up Authorization Flow' },
  { id: 'pca-need-additive', requirement: 'The pca_need parameter changes nothing a stock client reads (status, error, scope, resource_metadata).', levels: L('EXT', 'EXT', 'EXT', 'EXT', 'EXT'), section: 'RFC 6750 section 3 / RFC 9110 section 11.2 (unknown auth-params are ignored)' },
];
