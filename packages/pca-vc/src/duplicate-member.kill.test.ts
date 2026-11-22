import { createHash, generateKeyPairSync } from 'node:crypto';
import { SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import { AGENT_PASSPORT_CONTEXT, AGENT_PASSPORT_VC_TYPE, VC_CONTEXT, verifyPassportVC } from './index';

// A disclosure whose JSON text repeats a member must be refused (JSON.parse keeps the last); other number spellings stay accepted.
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const b64u = (s: string) => Buffer.from(s, 'utf8').toString('base64url');
const digest = (d: string) => createHash('sha256').update(d, 'ascii').digest().toString('base64url');

async function vcWith(disclosureText: string): Promise<string> {
  const disclosure = b64u(disclosureText);
  const jwt = await new SignJWT({
    vc: {
      '@context': [VC_CONTEXT, AGENT_PASSPORT_CONTEXT],
      type: ['VerifiableCredential', AGENT_PASSPORT_VC_TYPE],
      credentialSubject: { id: 'did:example:s', passport_id: 'p', model_id: 'm', operator: 'o', hardware_rooted: true, issued_at: 1, _sd: [digest(disclosure)] },
    },
    _sd_alg: 'sha-256',
  })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'vc+sd-jwt' })
    .setIssuer('did:example:i')
    .setSubject('did:example:s')
    .sign(privateKey);
  return `${jwt}~${disclosure}~`;
}

describe('pca-vc disclosure duplicate members', () => {
  it('a duplicate member inside a disclosure is refused', async () => {
    await expect(verifyPassportVC(await vcWith('["s","weights_digest",{"a":1,"a":2}]'), publicKey)).rejects.toThrow('pca-vc: malformed disclosure');
  });
  it('non-canonical numbers (8.0, 1e3) in a disclosure are accepted', async () => {
    const r = await verifyPassportVC(await vcWith('[8.0,"weights_digest","dd"]'), publicKey);
    expect(r.passport.weights_digest).toBe('dd');
    await expect(verifyPassportVC(await vcWith('[1e3,"weights_digest","dd"]'), publicKey)).resolves.toBeDefined();
  });
});
