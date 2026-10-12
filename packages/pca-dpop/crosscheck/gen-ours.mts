// Emits a DPoP proof made by @atlasauth/pca-dpop with a fixed Ed25519 test key (RFC 8032 test vector 1 seed).
import { createDpopProof } from '../src/index.ts';
const d = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const x = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';
const priv = { kty: 'OKP', crv: 'Ed25519', x, d: Buffer.from(d, 'hex').toString('base64url') };
const proof = await createDpopProof({ method: 'POST', url: 'https://server.example.com/token', privateKey: priv, publicJwk: { kty: 'OKP', crv: 'Ed25519', x }, iat: 1700000000, jti: 'crosscheck-1', nonce: 'n-1', ath: 'abc' });
console.log(JSON.stringify({ proof, x }));
