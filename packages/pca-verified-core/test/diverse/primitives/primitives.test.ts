// Reduced-size run of the N-version primitives harness (tools/pca-trustbase/primitives/run.mjs). In-process voters only (noble strict + zip215,
// node:crypto/OpenSSL, the real pca keys.ts/pq.ts wrappers) unless PRIM_RUST/PRIM_SLH/PRIM_GO/PRIM_PY are exported; the full multi-language,
// multi-million-case run is on a cloud box: tools/pca-trustbase/primitives/cloud.sh (see its header).
import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const ROOT = resolve(__dirname, '..', '..', '..', '..', '..');
const RUN = join(ROOT, 'tools', 'pca-trustbase', 'primitives', 'run.mjs');
const PCA = join(ROOT, 'packages', 'pca');
const ACVP = join(ROOT, 'tools', 'pca-trustbase', 'primitives', 'vectors', 'acvp');

describe('primitives N-version harness (reduced)', () => {
  it('Wycheproof/RFC8032 + hash/HMAC/Ed25519 agreement + adversarial Ed25519 set: no BUG-severity finding', () => {
    const out = mkdtempSync(join(tmpdir(), 'prim-'));
    const args = ['--import', 'tsx', RUN, '--suite', 'vectors,hash,hmac,edsign,edadv,edrand', '--n-hash', '1500', '--n-ed', '1500', '--adv-per-cat', '10', '--out', out, ...(existsSync(ACVP) ? ['--acvp', ACVP] : [])];
    let status = 0;
    try { execFileSync(process.execPath, args, { cwd: PCA, stdio: 'pipe', timeout: 600_000 }); } catch (e: any) { status = e.status ?? 1; process.stderr.write(String(e.stdout ?? '')); }
    const report = JSON.parse(readFileSync(join(out, 'report.json'), 'utf8'));
    const bugs = report.findings.filter((f: { sev: string }) => f.sev === 'BUG');
    expect(bugs).toEqual([]);
    expect(status).toBe(0);
    expect(report.suites.edadv.pcaAcceptsInvalid).toBe(0);
    expect(report.suites['wycheproof-ed25519'].vectors).toBeGreaterThan(100);
  }, 600_000);

  it('post-quantum suites agree across noble and OpenSSL (small sample)', () => {
    const out = mkdtempSync(join(tmpdir(), 'primpq-'));
    execFileSync(process.execPath, ['--import', 'tsx', RUN, '--suite', 'pq', '--n-pq', '4', '--out', out], { cwd: PCA, stdio: 'pipe', timeout: 600_000 });
    const report = JSON.parse(readFileSync(join(out, 'report.json'), 'utf8'));
    expect(report.findings.filter((f: { sev: string }) => f.sev === 'BUG')).toEqual([]);
  }, 600_000);
});
