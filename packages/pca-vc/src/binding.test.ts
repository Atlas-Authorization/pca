import { generateKeyPairSync } from 'node:crypto';
import { SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import { issuePassport } from '@atlasauth/pca/ext/attestation';
import { VC_CONTEXT, didKeyFromEd25519, passportToVC, verifyPassportVC } from './index';

const keys = generateKeyPairSync('ed25519');
const did = didKeyFromEd25519(new Uint8Array(keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)));
const passport = issuePassport({ model_id: 'm', operator: 'op', hardware_rooted: true, issued_at: 1 });

describe('passport VC identity binding', () => {
  it('expectedIssuerDid: matching passes, any other issuer is refused', async () => {
    const vc = await passportToVC(passport, { issuerKey: keys.privateKey, issuerDid: did, subjectDid: did, ttlSec: 60 });
    expect((await verifyPassportVC(vc, keys.publicKey, { expectedIssuerDid: did })).issuerDid).toBe(did);
    await expect(verifyPassportVC(vc, keys.publicKey, { expectedIssuerDid: 'did:key:zOther' })).rejects.toThrow(
      'pca-vc: iss does not match expectedIssuerDid',
    );
  });

  it('a JWT sub that differs from credentialSubject.id is refused', async () => {
    const vc = {
      '@context': [VC_CONTEXT],
      type: ['VerifiableCredential', 'AgentPassportCredential'],
      credentialSubject: { id: did, passport_id: passport.id, model_id: 'm', operator: 'op', hardware_rooted: true, issued_at: 1 },
    };
    const jwt = await new SignJWT({ vc }).setProtectedHeader({ alg: 'EdDSA', typ: 'vc+sd-jwt' }).setIssuer(did).setSubject('did:key:zElse').sign(keys.privateKey);
    await expect(verifyPassportVC(`${jwt}~`, keys.publicKey)).rejects.toThrow('pca-vc: sub does not match credentialSubject.id');
  });
});
