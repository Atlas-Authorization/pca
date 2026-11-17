// Writes /data/config/pca-proxy-mcp.yaml for the sample MCP server: `pca-proxy init mcp` pins every tool to its current definition, then
// observe forwards everything, and enforce adds the grant the human signed (agent.issuedGrant).
//   node tools/mcp-config.mjs observe|enforce
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DATA, YAML, reviewerPub } from './lib.mjs';

const mode = process.argv[2];
if (mode !== 'observe' && mode !== 'enforce') throw new Error('usage: mcp-config.mjs observe|enforce');
const tmp = join(mkdtempSync(join(tmpdir(), 'mcp-')), 'init.yaml');
execFileSync('pca-proxy', ['init', 'mcp', '--ns', 'notes', '--out', tmp, '--', 'node', '/box/sample/notes-mcp-server.mjs'], { stdio: ['ignore', 'ignore', 'inherit'] });
const doc = YAML.parse(readFileSync(tmp, 'utf8'));

doc.mode = mode;
doc.audience = 'notes-mcp';
doc.agent = { goal: 'keep notes', principalKeyEnv: 'PCA_PRINCIPAL_KEY' };
doc.state = { dir: `/data/state-mcp-${mode}`, hmacKeyEnv: 'PCA_STATE_HMAC' };
doc.audit = { path: '/data/audit/mcp.audit.jsonl' };
doc.approvals = { store: '/data/approvals-mcp.json', waitSeconds: 1 };
// what each tool IS is the operator's knowledge; whether it may run is the signed grant's decision in enforce mode
const t = doc.mcp.tools;
t.search_notes = { ...t.search_notes, policy: 'allow', effect: 'read' };
t.create_note = { ...t.create_note, policy: 'approve', effect: 'write', reversibility: 'reversible' };
t.delete_note = { ...t.delete_note, policy: 'approve', effect: 'write', reversibility: 'irreversible' };
if (mode === 'enforce') {
  const file = join(DATA, 'autopilot', 'mcp.grant.json');
  if (!existsSync(file)) throw new Error('no signed grant yet: run make sign first');
  doc.agent.issuedGrant = { file, signer: reviewerPub() };
}
writeFileSync(join(DATA, 'config', 'pca-proxy-mcp.yaml'), YAML.stringify(doc), { mode: 0o600 });
console.log(`wrote ${join(DATA, 'config', 'pca-proxy-mcp.yaml')} (${mode})`);
