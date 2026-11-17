/** A deterministic software authenticator for tests: an Ed25519 credential that signs like a platform passkey. */
import { b64u, generateKeyPair, publicKeyOf, sha256, sign, utf8, type KeyPair } from '@atlasauth/pca';
import type { CredentialPublicKey } from '@atlasauth/pca-webauthn';

export const RP = 'review.example.com';
export const ORIGIN = 'https://review.example.com';

export interface Authenticator { key: KeyPair; publicKey: CredentialPublicKey; credentials: { get: (o: { publicKey: { challenge: Uint8Array } }) => Promise<{ response: { authenticatorData: Uint8Array; clientDataJSON: Uint8Array; signature: Uint8Array } }> } }

/** flags: 0x05 = user present + verified; 0x01 = present only. */
export function authenticator(o: { flags?: number; signCount?: number; origin?: string; type?: string } = {}): Authenticator {
  const key = generateKeyPair();
  const get: Authenticator['credentials']['get'] = async ({ publicKey }) => {
    const ad = new Uint8Array(37);
    ad.set(sha256(utf8(RP)), 0);
    ad[32] = o.flags ?? 0x05;
    new DataView(ad.buffer).setUint32(33, o.signCount ?? 1, false);
    const cd = utf8(JSON.stringify({ type: o.type ?? 'webauthn.get', challenge: b64u(publicKey.challenge), origin: o.origin ?? ORIGIN, crossOrigin: false }));
    return { response: { authenticatorData: ad, clientDataJSON: cd, signature: sign(key.secretKey, new Uint8Array([...ad, ...sha256(cd)])) } };
  };
  return { key, publicKey: { kty: 'OKP', crv: 'Ed25519', x: b64u(publicKeyOf(key.secretKey)) }, credentials: { get } };
}
