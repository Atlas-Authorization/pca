// Checks pca-dpop's RFC 8705 helpers against a certificate + thumbprint produced by an independent tool.
// Run (package dir): npx tsx crosscheck/mtls-check.mts <cert.pem> <expected x5t#S256> <other-cert.pem>
import { readFileSync } from 'node:fs';
import { assertMtlsBound, mtlsCnf, mtlsThumbprint, DpopVerificationError } from '../src/index.ts';

const [pemPath, expected, otherPath] = process.argv.slice(2);
if (pemPath === undefined || expected === undefined || otherPath === undefined) throw new Error('usage: mtls-check <cert.pem> <x5t> <other.pem>');
const pem = readFileSync(pemPath, 'utf8');
const other = readFileSync(otherPath, 'utf8');
const fail = (m: string): never => {
  console.error('FAIL', m);
  process.exit(1);
};
if (mtlsThumbprint(pem) !== expected) fail('mtlsThumbprint differs from the independent value');
if (mtlsCnf(pem)['x5t#S256'] !== expected) fail('mtlsCnf differs from the independent value');
if (assertMtlsBound(pem, { 'x5t#S256': expected })['x5t#S256'] !== expected) fail('assertMtlsBound rejected the bound certificate');
try {
  assertMtlsBound(other, { 'x5t#S256': expected });
  fail('assertMtlsBound accepted a different certificate');
} catch (e) {
  if (!(e instanceof DpopVerificationError) || e.code !== 'x5t') throw e;
}
console.log('mtls cross-check OK');
