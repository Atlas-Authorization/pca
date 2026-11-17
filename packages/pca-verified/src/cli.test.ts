import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { main } from './cli';

const lines = (f: (out: (s: string) => void) => Promise<number>): Promise<{ code: number; text: string }> => {
  const buf: string[] = [];
  return f((s) => buf.push(s)).then((code) => ({ code, text: buf.join('\n') }));
};

describe('cli', () => {
  it('usage errors exit 2 and print the usage', async () => {
    for (const argv of [[], ['nope'], ['run'], ['run', '--driver'], ['run', '--driver', 'x', '--profile', 'made-up'], ['run', '--driver', 'x', '--key', 'k.pem'], ['verify'], ['badge', 'a.json'], ['registry', 'verify', 'x.json']]) {
      const r = await lines((out) => main(argv, out));
      expect(r.code, JSON.stringify(argv)).toBe(2);
    }
  });
  it('verify refuses a statement file that is not one, and badge writes nothing for it', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcav-cli-'));
    const f = join(dir, 's.json');
    writeFileSync(f, JSON.stringify({ format: 'pca-verified-statement/1', statement: 'AAAA', public_key: 'AAAA', payload: {} }));
    const v = await lines((out) => main(['verify', f], out));
    expect(v.code).toBe(1);
    expect(v.text).toContain('NOT VERIFIED');
    const b = await lines((out) => main(['badge', f, '--out', join(dir, 'badge')], out));
    expect(b.code).toBe(1);
    expect(existsSync(join(dir, 'badge', 'badge.svg'))).toBe(false);
  });
  it('--limit makes a run that cannot be attested, and says so', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcav-cli-'));
    writeFileSync(join(dir, 'd.js'), "const fs=require('fs');fs.writeFileSync(process.argv[3],'');");
    const r = await lines((out) => main(['run', '--driver', `${JSON.stringify(process.execPath)} ${JSON.stringify(join(dir, 'd.js'))}`, '--limit', '3', '--timeout-ms', '3000', '--out', join(dir, 'o'), '--name', 'n', '--impl-version', '1', '--generate-key'], out));
    expect(r.code).toBe(1);
    expect(existsSync(join(dir, 'o', 'report.json'))).toBe(true);
    expect(existsSync(join(dir, 'o', 'core-verifier.statement.json'))).toBe(false);
  }, 60000);
});
