// Writes the enforce-mode configs: the proxy enforces the grant a human signed (agent.issuedGrant) and only that signer's grants.
//   node tools/enforce-config.mjs      (needs /data/autopilot/http.grant.json; the MCP config is written by mcp-config.mjs enforce)
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { DATA, YAML, reviewerPub } from './lib.mjs';

const grant = `${DATA}/autopilot/http.grant.json`;
if (!existsSync(grant)) throw new Error('no signed grant yet: run make sign first');
const doc = YAML.parse(readFileSync('/box/config/pca-proxy.enforce.yaml', 'utf8'));
doc.agent.issuedGrant = { file: grant, signer: reviewerPub() };
writeFileSync(`${DATA}/config/pca-proxy.yaml`, YAML.stringify(doc), { mode: 0o600 });
console.log('wrote the enforce config: the proxy now enforces the signed grant');
