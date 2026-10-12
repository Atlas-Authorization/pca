import { X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { fingerprintOf, generateIdentity, readPem } from './certs';
import { sharingsPerTriple } from './prep';

describe('sharingsPerTriple', () => {
  it('a, b, c plus (a-hat, c-hat) per sacrifice partner', () => {
    expect(sharingsPerTriple(0)).toBe(3);
    expect(sharingsPerTriple(1)).toBe(5);
    expect(sharingsPerTriple(2)).toBe(7);
    expect(sharingsPerTriple(5)).toBe(13);
  });
});

describe('generateIdentity', () => {
  const tmp = (): string => mkdtempSync(join(tmpdir(), 'pca-certs-kill-'));
  it('invokes openssl exactly twice with the pinned arguments and returns the key/cert paths', () => {
    const d = tmp();
    const log = join(d, 'calls.log');
    const fake = join(d, 'fake-openssl.sh');
    writeFileSync(fake, `#!/bin/sh\necho "$@" >> "${log}"\nfor a in "$@"; do prev="$cur"; cur="$a"; if [ "$prev" = "-out" ]; then echo "$cur" > "$cur"; fi; done\n`);
    chmodSync(fake, 0o755);
    const dir = join(d, 'nested', 'id');
    const id = generateIdentity(dir, 'node-7', fake);
    expect(id).toEqual({ keyPath: join(dir, 'key.pem'), certPath: join(dir, 'cert.pem') });
    const lines = readFileSync(log, 'utf8').trim().split('\n');
    expect(lines).toEqual([
      `ecparam -name prime256v1 -genkey -noout -out ${join(dir, 'key.pem')}`,
      `req -new -x509 -key ${join(dir, 'key.pem')} -subj /CN=node-7 -days 2 -out ${join(dir, 'cert.pem')} -sha256`,
    ]);
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    rmSync(d, { recursive: true, force: true });
  });
  it('creates the directory recursively and tolerates an existing one', () => {
    const d = tmp();
    const fake = join(d, 'fake.sh');
    writeFileSync(fake, '#!/bin/sh\nexit 0\n');
    chmodSync(fake, 0o755);
    generateIdentity(join(d, 'a', 'b', 'c'), 'x', fake);
    expect(existsSync(join(d, 'a', 'b', 'c'))).toBe(true);
    generateIdentity(join(d, 'a', 'b', 'c'), 'x', fake);
    rmSync(d, { recursive: true, force: true });
  });
  it('a failing openssl surfaces as an exception (and its output is not printed: stdio is piped)', () => {
    const d = tmp();
    const fake = join(d, 'bad.sh');
    writeFileSync(fake, '#!/bin/sh\necho SHOULD-NOT-LEAK-TO-TERMINAL\nexit 3\n');
    chmodSync(fake, 0o755);
    try {
      expect(() => generateIdentity(join(d, 'id'), 'x', fake)).toThrow();
      try {
        generateIdentity(join(d, 'id'), 'x', fake);
      } catch (e) {
        expect(String((e as { stdout?: Buffer }).stdout ?? '')).toContain('SHOULD-NOT-LEAK-TO-TERMINAL');
      }
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });
  const haveOpenssl = ((): boolean => {
    try {
      execFileSync('openssl', ['version'], { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  })();
  it.runIf(haveOpenssl)('with the real openssl: a P-256 key, a self-signed 2-day SHA-256 certificate for the CN, and a matching fingerprint', () => {
    const d = tmp();
    const id = generateIdentity(join(d, 'real'), 'party-3');
    const pem = readPem(id.certPath);
    expect(pem.startsWith('-----BEGIN CERTIFICATE-----')).toBe(true);
    expect(readFileSync(id.keyPath, 'utf8')).toContain('EC PRIVATE KEY');
    const x = new X509Certificate(pem);
    expect(x.subject).toBe('CN=party-3');
    expect(x.issuer).toBe('CN=party-3');
    expect(x.publicKey.asymmetricKeyDetails?.namedCurve).toBe('prime256v1');
    const days = (new Date(x.validTo).getTime() - new Date(x.validFrom).getTime()) / 86_400_000;
    expect(days).toBeGreaterThan(1.99);
    expect(days).toBeLessThan(2.01);
    expect(x.verify(x.publicKey)).toBe(true);
    expect(fingerprintOf(pem)).toBe(x.fingerprint256);
    expect(fingerprintOf(pem)).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    const text = execFileSync('openssl', ['x509', '-in', id.certPath, '-noout', '-text'], { encoding: 'utf8' });
    expect(text).toMatch(/Signature Algorithm: ecdsa-with-SHA256/);
    rmSync(d, { recursive: true, force: true });
  });
  it('readPem reads the file as utf8 text', () => {
    const d = tmp();
    writeFileSync(join(d, 'p.pem'), 'héllo\n');
    expect(readPem(join(d, 'p.pem'))).toBe('héllo\n');
    rmSync(d, { recursive: true, force: true });
  });
});
