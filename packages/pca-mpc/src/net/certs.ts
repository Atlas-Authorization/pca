/**
 * Per-run identity material for the TLS mesh: one fresh P-256 key + self-signed certificate per node,
 * generated with the vetted `openssl` CLI (no hand-rolled crypto, no X.509 code of our own). The keys
 * live only on the node that generated them; only the PUBLIC certificates are exchanged and pinned.
 */

import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export interface NodeIdentity {
  keyPath: string;
  certPath: string;
}

/** Generate `<dir>/key.pem` + `<dir>/cert.pem` for `cn` (valid 2 days: per-run, throw-away). */
export function generateIdentity(dir: string, cn: string, openssl = 'openssl'): NodeIdentity {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync(openssl, ['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', keyPath], { stdio: 'pipe' });
  execFileSync(
    openssl,
    ['req', '-new', '-x509', '-key', keyPath, '-subj', `/CN=${cn}`, '-days', '2', '-out', certPath, '-sha256'],
    { stdio: 'pipe' },
  );
  return { keyPath, certPath };
}

/** SHA-256 fingerprint (colon-hex, as Node reports it) of a PEM certificate. */
export function fingerprintOf(certPem: string): string {
  return new X509Certificate(certPem).fingerprint256;
}

export const readPem = (p: string): string => readFileSync(p, 'utf8');
