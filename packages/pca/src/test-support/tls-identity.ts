/** TEST-ONLY: a deterministic self-signed P-256 identity (PEM key + cert) minted in-process, so TLS tests need no openssl. */
import { createPrivateKey } from 'node:crypto';
import { ext, forgeCert, forgeKey } from './forge-x509';

export function tlsIdentity(name: string): { keyPem: string; certPem: string } {
  const key = forgeKey(`tls-identity/${name}`, 'P-256');
  const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64url');
  const keyPem = createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d: b64(key.priv), x: b64(key.pub.subarray(1, 33)), y: b64(key.pub.subarray(33, 65)) }, format: 'jwk' })
    .export({ type: 'pkcs8', format: 'pem' })
    .toString();
  const subject = [['CN', name]] as const;
  // fixed validity window far from "now" on both sides: deterministic bytes and no clock sensitivity
  const cert = forgeCert({
    subject, issuer: subject, subjectKey: key, signer: key, serial: 1n,
    notBefore: new Date('2020-01-01T00:00:00Z'), notAfter: new Date('2049-12-31T00:00:00Z'),
    extensions: [ext.basicConstraints(true), ext.keyUsage(['digitalSignature', 'keyCertSign'])],
  });
  return { keyPem, certPem: cert.pem };
}
