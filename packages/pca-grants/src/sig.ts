import { b64u, canonicalBytesStrict, decodeB64uStrict, publicKeyOf, sign, utf8, verifyB64u } from '@atlasauth/pca';

/** Domain-separated Ed25519 signature over strict-canonical JSON. Shared by every signed artifact in this package. */
const msg = (domain: string, body: unknown): Uint8Array => {
  const d = utf8(domain);
  const b = canonicalBytesStrict(body);
  const out = new Uint8Array(d.length + b.length);
  out.set(d);
  out.set(b, d.length);
  return out;
};

export const signerOf = (secret: Uint8Array): string => b64u(publicKeyOf(secret));
export const signBody = (domain: string, body: unknown, secret: Uint8Array): string => b64u(sign(secret, msg(domain, body)));
/** True iff `sig` is a canonical 64-byte b64u signature by `signer` over exactly `body`. Never throws. */
export function verifyBody(domain: string, body: unknown, signer: string, sig: unknown): boolean {
  try {
    return typeof sig === 'string' && decodeB64uStrict(sig, 64) !== null && verifyB64u(signer, msg(domain, body), sig);
  } catch {
    return false;
  }
}
export const isSafeInt = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;
export const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
export const isStr = (x: unknown, max = 512): x is string => typeof x === 'string' && x.length > 0 && x.length <= max;
