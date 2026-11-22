// Oracle: @atlasauth/pca-mcp importActionDefsFromMcp (the MCP tool list as action kit defs, then the rule-based trait suggestions of
// @atlasauth/pca-actions). Writes out/ref-mcp-import.json.gz.
// PORTING: importActionDefsFromMcp(source, opts) -> Mcp.importActionDefsFromMcp(source, opts), the result {defs, todo, source} compared as JSON by value.
//   `source` is a tool array (the reference also takes an object with listTools(), which a corpus cannot carry); `opts` {ns, uri?, licence?, now?, suggest?: 'rules' | 'none'} (default 'rules').
import { Oracle, refWrite, variants } from './lib.mjs';

const M: any = await import('../../../packages/pca-mcp/src/index.ts');
const o = new Oracle('mcp-import', 'tools/pca-audit/oracles/mcp-import.mts', 'TS-reference oracle for importActionDefsFromMcp (import then rule-based suggest).');

const obj = (properties: any, required: string[] = []) => ({ type: 'object', properties, required });
const TOOLS: any[] = [
  { name: 'send_mail', description: 'Send an email to a person.', inputSchema: obj({ to: { type: 'string', format: 'email' }, body: { type: 'string' } }, ['to']) },
  { name: 'delete_user', description: 'Delete a user account permanently.', inputSchema: obj({ id: { type: 'string' } }, ['id']), annotations: { destructiveHint: true } },
  { name: 'refund_payment', description: 'Refund a card payment.', inputSchema: obj({ amount: { type: 'integer' }, currency: { type: 'string' }, charge_id: { type: 'string' } }, ['amount', 'currency']) },
  { name: 'get_invoice', title: 'Get invoice', inputSchema: obj({ invoice_id: { type: 'string' } }), annotations: { readOnlyHint: true, idempotentHint: true } },
  { name: 'export_customers', description: 'Export all customers to a CSV file.', inputSchema: obj({ path: { type: 'string' }, api_key: { type: 'string' } }) },
  { name: 'run_query', description: 'Run a SQL query.', inputSchema: obj({ sql: { type: 'string' } }, ['sql']), annotations: { openWorldHint: true } },
  { name: 'list_orders', inputSchema: obj({ limit: { type: 'integer' }, cursor: { type: 'string' } }), annotations: { readOnlyHint: true } },
  { name: 'transfer_funds', description: 'Transfer money between accounts.', inputSchema: obj({ from: { type: 'string' }, to: { type: 'string' }, amount_cents: { type: 'integer' }, ccy: { type: 'string' } }, ['from', 'to', 'amount_cents']) },
  { name: 'invite_member', description: 'Invite a member to the workspace', inputSchema: obj({ email: { type: 'string', format: 'email' }, role: { type: 'string', enum: ['admin', 'member'] } }, ['email']) },
  { name: 'schedule_publication', description: 'Schedule a post for later.', inputSchema: obj({ when: { type: 'string', format: 'date-time' }, text: { type: 'string' } }) },
];
const SUGGEST = [undefined, 'rules', 'none'];
let k = 0;
for (const sg of SUGGEST) {
  const opts: any = { ns: 'mcp', ...(sg === undefined ? {} : { suggest: sg }) };
  await o.run('importActionDefsFromMcp', `one${k++}`, M.importActionDefsFromMcp, [TOOLS.slice(0, 1), opts]);
  await o.run('importActionDefsFromMcp', `all${k++}`, M.importActionDefsFromMcp, [TOOLS, opts]);
  await o.run('importActionDefsFromMcp', `empty${k++}`, M.importActionDefsFromMcp, [[], opts]);
  for (const t of TOOLS) await o.run('importActionDefsFromMcp', `t${k++}`, M.importActionDefsFromMcp, [[t], { ...opts, ns: 'acme' }]);
}
for (const [i, t] of [TOOLS[2], TOOLS[7], TOOLS[1]].entries())
  for (const [label, v] of variants(t, { depth: 4, maxPaths: 40 })) await o.run('importActionDefsFromMcp', `v${i}_${k++}`, M.importActionDefsFromMcp, [[v], { ns: 'v' }]);
await o.run('importActionDefsFromMcp', 'badns', M.importActionDefsFromMcp, [TOOLS.slice(0, 1), { ns: 'Bad NS' }]);
await o.run('importActionDefsFromMcp', 'nosource', M.importActionDefsFromMcp, [{}, { ns: 'mcp' }]);

refWrite(o, 'mcp-import');
