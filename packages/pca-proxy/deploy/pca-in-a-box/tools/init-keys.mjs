// First start only: generate the dev keys into the data volume. Nothing here is committed anywhere; delete the volume to start over.
// Existing keys are never overwritten.
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { DATA, pca } from './lib.mjs';

const dirs = ['keys', 'config', 'audit', 'autopilot', 'log', 'witness'];
for (const d of dirs) mkdirSync(join(DATA, d), { recursive: true });
const keys = join(DATA, 'keys');
const put = (name, value) => {
  const p = join(keys, name);
  if (existsSync(p)) return false;
  writeFileSync(p, value + '\n', { mode: 0o600 });
  return true;
};
const pair = (name) => {
  const kp = pca.generateKeyPair();
  const made = put(`${name}.key`, pca.b64u(kp.secretKey));
  if (made) put(`${name}.pub`, pca.b64u(kp.publicKey));
  return made;
};

const made = [
  pair('principal'),   // the holder of the proxy's grant (the principal key the proxy derives its grant from)
  pair('reviewer'),    // the dev "human": signs autopilot reviews (use your own key outside the demo)
  pair('log'),         // the trust-directory log's signing key
  pair('witness'),     // the witness's key
  put('state-hmac.key', pca.b64u(randomBytes(32))),
  put('upstream.token', pca.b64u(randomBytes(24))),   // the only credential the sample API accepts
];
console.log(made.some(Boolean) ? 'dev keys generated into the data volume' : 'dev keys already present');
