import { compactJwsAliases } from '@atlasauth/pca';
import { exportJWK, generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import { createDpopProof, verifyDpopProof } from './index';

const URL1 = 'https://api.atlasauth.net/v1/pca/exec';

describe('canonical-spelling gate (re-encoded DPoP proof strings are rejected)', () => {
  for (const alg of ['ES256', 'EdDSA'] as const) {
    it(`${alg}: every alias is rejected with code 'malformed'; the original passes`, async () => {
      const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
      const privateJwk = await exportJWK(privateKey);
      const publicJwk = await exportJWK(publicKey);
      const proof = await createDpopProof({ method: 'POST', url: URL1, privateKey: privateJwk, publicJwk });
      await verifyDpopProof(proof, { method: 'POST', url: URL1, maxAgeSec: 300 });
      const aliases = compactJwsAliases(proof);
      expect(aliases.length).toBeGreaterThanOrEqual(7);
      for (const a of aliases) {
        await expect(verifyDpopProof(a.token, { method: 'POST', url: URL1, maxAgeSec: 300 }), a.name).rejects.toMatchObject({ code: 'malformed' });
      }
      expect(proof).toBeTruthy();
    });
  }
});
