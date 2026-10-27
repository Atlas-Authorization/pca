/** The README quick start, verbatim in behaviour. */
import { exportJWK, generateKeyPair } from 'jose';
import { expect, it } from 'vitest';
import { createDpopNonceIssuer, createDpopProof, createInMemoryDpopReplayStore, verifyDpopProof } from './index';

it('README quick start', async () => {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const issuer = createDpopNonceIssuer({ secret: new Uint8Array(32).fill(1) });
  const replayStore = createInMemoryDpopReplayStore();

  const proof = await createDpopProof({
    method: 'POST',
    url: 'https://api.example.com/refunds',
    privateKey: await exportJWK(privateKey),
    publicJwk: await exportJWK(publicKey),
    nonce: issuer.issue(),
  });

  const result = await verifyDpopProof(proof, {
    method: 'POST',
    url: 'https://api.example.com/refunds?ignored=1',
    maxAgeSec: 120,
    replayStore,
    requireReplayStore: true,
    nonceIssuer: issuer,
  });
  expect(typeof result.jkt).toBe('string');
  await expect(verifyDpopProof(proof, { method: 'POST', url: 'https://api.example.com/refunds', maxAgeSec: 120, replayStore, nonceIssuer: issuer })).rejects.toMatchObject({ code: 'jti_replay' });
});
