// Emits RFC 9421 requests signed by @atlasauth/pca-vc with a fixed Ed25519 key (RFC 8032 test vector 1).
import { createPrivateKey } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { signRequestMessage } from '../src/index.ts';

const seed = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex');
const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
const key = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
const cases = [
  { method: 'POST', url: 'https://api.acme.com/v1/orders?x=1', headers: { 'content-type': 'application/json' } },
  { method: 'GET', url: 'https://bot.example/a', headers: { accept: 'text/html' }, signatureAgent: 'https://bots.acme.com' },
].map((c, i) => ({ ...c, created: 1700000000 + i, keyid: 'k1', ...signRequestMessage({ ...c, key, keyid: 'k1', created: 1700000000 + i }) }));
writeFileSync(resolve(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'ours-9421.json'), JSON.stringify({
  generator: '@atlasauth/pca-vc signRequestMessage via crosscheck/gen-ours.mts; key = RFC 8032 test vector 1', public_key_hex: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', cases }, null, 1));
console.log('ok');
