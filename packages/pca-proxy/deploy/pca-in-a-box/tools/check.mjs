// Asserts, from the audit logs (not from what the agent saw), that the proxies decided as the mode requires, and that both logs are
// intact hash chains.   node check.mjs observe|enforce
import { existsSync, readFileSync } from 'node:fs';
import { pca } from './lib.mjs';

const mode = process.argv[2];
if (mode !== 'observe' && mode !== 'enforce') throw new Error('usage: check.mjs observe|enforce');
const read = (p) => (existsSync(p) ? readFileSync(p, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
const norm = (s) => String(s).toLowerCase().replace(/[^a-z0-9]/g, '');
let failed = 0;
const say = (ok, msg) => { if (!ok) failed++; console.log(`${ok ? 'ok  ' : 'FAIL'} ${msg}`); };

const http = read('/data/audit/http.audit.jsonl');
const mcp = read('/data/audit/mcp.audit.jsonl');
for (const [name, log] of [['http', http], ['mcp', mcp]]) {
  const c = pca.verifyReceiptChain(log);
  say(c.ok && log.length > 0, `${name} audit log: ${log.length} receipts, hash chain ${c.ok ? 'intact' : `BROKEN (${c.reason})`}`);
}

// the newest decision for an action in this mode (the resource carries the operation id or tool name; the verb is the importer's
// noun.action form, so it never contains the name the operator wrote)
const last = (log, needle) => log.filter((r) => (r.checks?.mode ?? '') === mode && norm(r.resource).endsWith(norm(needle))).pop();
// [log, action, inside the signed grant]. The grant is learned from the routine work seen in observe mode; refunds and deletes were
// never observed, so they are outside it and refused by the grant in enforce mode.
const actions = [[http, 'createOrder', true], [http, 'listOrders', true], [http, 'getOrder', true], [http, 'refundOrder', false], [http, 'deleteOrder', false],
  [mcp, 'create_note', true], [mcp, 'search_notes', true], [mcp, 'delete_note', false]];
for (const [log, action, inside] of actions) {
  if (mode === 'observe' && !inside) continue;
  const r = last(log, action);
  if (!r) { say(false, `${action}: no ${mode}-mode decision in the log`); continue; }
  const allowed = r.checks?.allowed === 'true';
  const forwarded = r.outcome === 'allow';
  const code = r.checks?.code;
  if (mode === 'enforce') say(inside ? allowed && forwarded : !allowed && !forwarded && code === 'grant_denied', `${action}: ${allowed ? 'allowed' : `refused (${code})`}; ${inside ? 'inside the signed grant, expected allowed' : 'outside the signed grant, expected refused by the grant (grant_denied)'}`);
  else say(allowed && forwarded, `${action}: forwarded and recorded (observe mode refuses nothing)`);
}
if (mode === 'enforce') {
  say(http.some((r) => r.checks?.mode === 'enforce' && r.checks?.code === 'unmapped' && r.outcome === 'deny'), 'an unmapped route was refused (default deny)');
  say(existsSync('/data/autopilot/http.approval.json') && existsSync('/data/autopilot/mcp.approval.json'), 'both grants were signed by the reviewer before enforcing');
}
console.log(failed === 0 ? '\nthe audit logs agree' : `\n${failed} check(s) failed`);
process.exitCode = failed === 0 ? 0 : 1;
