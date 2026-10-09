/**
 * Verify a passportToVC() SD-JWT VC with the independent `@sd-jwt/core` library.
 * Setup: npm i --prefix "$SDJWT_LIB" @sd-jwt/core@0.22.0 @sd-jwt/crypto-nodejs@0.19.0
 * Run:   SDJWT_LIB=/path node crosscheck/sdjwt-js.mts   (exits non-zero on any disagreement)
 */
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { generateKeyPairSync, verify as nodeVerify } from 'node:crypto';
import { issuePassport } from '@atlasauth/pca';
import { didKeyFromEd25519, passportToVC } from '../src/index.ts';

const lib = process.env.SDJWT_LIB;
if (!lib) throw new Error('set SDJWT_LIB');
const req = createRequire(resolve(lib, 'x.js'));
const { SDJwtInstance } = req('@sd-jwt/core');
const { digest, generateSalt } = req('@sd-jwt/crypto-nodejs');
const version = JSON.parse(readFileSync(resolve(lib, 'node_modules/@sd-jwt/core/package.json'), 'utf8')).version;

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const did = didKeyFromEd25519(new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)));
const passport = issuePassport({ model_id: 'm-1', operator: 'op-1', hardware_rooted: true, issued_at: 1, weights_digest: 'w'.repeat(64), system_prompt_digest: 's'.repeat(64) });
const vc = await passportToVC(passport, { issuerKey: privateKey, issuerDid: did, subjectDid: did, ttlSec: 3600 });

const inst = new SDJwtInstance({
  hasher: digest, hashAlg: 'sha-256', saltGenerator: generateSalt,
  verifier: async (data: string, sig: string) => nodeVerify(null, Buffer.from(data), publicKey, Buffer.from(sig, 'base64url')),
});
const res = await inst.verify(vc);
const cs = res.payload.vc.credentialSubject;
if (cs.weights_digest !== 'w'.repeat(64) || cs.system_prompt_digest !== 's'.repeat(64) || cs.model_id !== 'm-1') throw new Error('disagreement');
console.log(`@sd-jwt/core ${version} verified a pca-vc SD-JWT VC and resolved the nested credentialSubject._sd disclosures`);
// withholding: drop the last disclosure and re-verify
const parts = vc.split('~'); parts.splice(parts.length - 2, 1);
const res2 = await inst.verify(parts.join('~'));
if (res2.payload.vc.credentialSubject.system_prompt_digest !== undefined) throw new Error('withheld claim leaked');
console.log('withheld disclosure stays hidden under @sd-jwt/core');
