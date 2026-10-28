/**
 * The vendor-attestation canary, run over the recorded real evidence in this repository (SEV-SNP Genoa, Intel TDX with PCS
 * collateral, Azure MAA over a TDX quote, NVIDIA H100 NVL), plus the harness's own fail-closed behaviour: a canary that
 * cannot tell a fail-open verifier from a good one is worse than none, so the judge is tested against both.
 */
import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { judgeCanary, runCanary, runCanaryCase, type Built, type CanaryCase, type CanaryManifest } from './attest-canary.test-util';
import type { HardwareAttestationResult } from './attestation';

const MANIFEST = resolve(__dirname, '..', 'fixtures', 'attest-canary', 'manifest.json');
const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8')) as CanaryManifest;
const DIR = resolve(MANIFEST, '..');

describe('recorded real-evidence canary', () => {
  it('every vendor case passes: verifies, every negative control is denied, nothing is near expiry', async () => {
    const { results, ok } = await runCanary(MANIFEST);
    expect(results.map((r) => [r.id, r.vendor, r.verdict, r.why])).toEqual([
      ['recorded-azure-genoa-sev-snp', 'sev-snp', 'pass', undefined],
      ['recorded-azure-intel-tdx-dcap', 'tdx', 'pass', undefined],
      ['recorded-azure-maa-tdx', 'azure-maa', 'pass', undefined],
      ['recorded-azure-h100-nvl-gpu-cc', 'nvidia-h100', 'pass', undefined],
    ]);
    expect(ok).toBe(true);
    for (const r of results) {
      expect(r.positive.ok).toBe(true);
      expect(r.controls.map((c) => [c.name, c.denied])).toEqual([['relayed-binding', true], ['flipped-evidence-byte', true], ['wrong-trust-pin', true]]);
      expect(r.expiry.alarm).toBe(false);
      expect(r.expiry.daysLeft).toBeGreaterThanOrEqual(14);
    }
  });

  it('a tight warning window turns the same evidence into an expiry alarm naming the days left', async () => {
    const snp = manifest.cases[0] as CanaryCase;
    const ok = await runCanaryCase(snp, DIR, 14);
    const days = ok.expiry.daysLeft!;
    const alarm = await runCanaryCase(snp, DIR, days + 1);
    expect([alarm.verdict, alarm.expiry.alarm, alarm.why]).toEqual(['fail', true, `collateral expires in ${days} days (< ${days + 1})`]);
    expect((await runCanaryCase(snp, DIR, days)).verdict).toBe('pass'); // the boundary: exactly `warnDays` left is not an alarm
  });

  it('a case whose pin is wrong for the recorded evidence FAILS the positive check (the pin matters)', async () => {
    const snp = { ...(manifest.cases[0] as CanaryCase), measurements: ['00'.repeat(48)] } as CanaryCase;
    const r = await runCanaryCase(snp, DIR);
    expect(r.verdict).toBe('fail');
    expect(r.why).toMatch(/^positive verification failed: /);
  });

  it('missing evidence is a failure, never a skip', async () => {
    const r = await runCanaryCase({ ...(manifest.cases[1] as CanaryCase), quoteFile: 'does-not-exist.bin' } as CanaryCase, DIR);
    expect([r.verdict, r.why]).toEqual(['fail', expect.stringMatching(/^canary error \(fail closed\): evidence file 'does-not-exist.bin' is missing or unreadable/)]);
  });

  it('an empty manifest does not pass', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'canary-'));
    writeFileSync(join(dir, 'm.json'), JSON.stringify({ cases: [] }));
    expect(await runCanary(join(dir, 'm.json'))).toEqual({ results: [], ok: false });
  });

  it('a manifest copied to another directory runs the same way (the live-run layout: evidence next to the manifest)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'canary-live-'));
    const h = manifest.cases[3] as CanaryCase & { reportFile: string; certChainFile: string; driverRimFile: string; vbiosRimFile: string; crlFiles: string[] };
    const rel = (p: string) => resolve(DIR, p);
    const names = { reportFile: 'report.bin', certChainFile: 'chain.pem', driverRimFile: 'driver.xml', vbiosRimFile: 'vbios.xml' } as const;
    for (const [k, n] of Object.entries(names)) copyFileSync(rel(h[k as keyof typeof names]), join(dir, n));
    h.crlFiles.forEach((p, i) => copyFileSync(rel(p), join(dir, `crl${i}.crl`)));
    const live = { ...h, ...names, crlFiles: h.crlFiles.map((_p, i) => `crl${i}.crl`), id: 'live-layout' };
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ cases: [live] }));
    const { results, ok } = await runCanary(join(dir, 'manifest.json'));
    expect([ok, results[0]!.verdict, results[0]!.why]).toEqual([true, 'pass', undefined]);
  });
});

describe('the judge tells a fail-open verifier from a good one', () => {
  const EXP = { holderPub: 'h', grantRef: 'g', epoch: 1, nonce: 'n' };
  const base = { id: 'x', vendor: 'sev-snp', expected: EXP };
  const GOOD: HardwareAttestationResult = { ok: true, bound: true, measured: { model_id: '', weights_digest: '', runtime_measurement: 'm', operator: '' } };
  const NOW = Date.parse('2026-10-09T00:00:00Z');
  const FAR = [new Date(NOW + 365 * 86_400_000).toISOString()];
  const built = (verify: Built['verify'], nextUpdates: number[] = [NOW + 365 * 86_400_000]): Built => ({ verify, certs: [], nextUpdates });
  const exact = (o?: { expected?: unknown; flip?: boolean; wrongPin?: boolean }): HardwareAttestationResult => (o && (o.expected || o.flip || o.wrongPin) ? { ok: false, reason: 'denied' } : GOOD);

  it('a verifier that accepts everything FAILS, and every control it accepted is named', async () => {
    const r = await judgeCanary(built(async () => GOOD), base, NOW, 14);
    expect([r.verdict, r.why]).toEqual(['fail', 'negative control accepted: relayed-binding, flipped-evidence-byte, wrong-trust-pin']);
  });
  it('a verifier that accepts a tampered byte but denies the rest names exactly that control', async () => {
    const r = await judgeCanary(built(async (o) => (o?.flip ? GOOD : exact(o))), base, NOW, 14);
    expect([r.verdict, r.why]).toEqual(['fail', 'negative control accepted: flipped-evidence-byte']);
  });
  it('a verifier that denies everything fails the positive check with its reason', async () => {
    const r = await judgeCanary(built(async () => ({ ok: false, reason: 'chain invalid' })), base, NOW, 14);
    expect([r.verdict, r.why]).toEqual(['fail', 'positive verification failed: chain invalid']);
  });
  it('ok without bound, or without a measured identity, is not a positive', async () => {
    for (const weak of [{ ok: true, measured: GOOD.measured }, { ok: true, bound: true }] as HardwareAttestationResult[]) {
      const r = await judgeCanary(built(async () => weak), base, NOW, 14);
      expect([r.verdict, r.positive.ok]).toEqual(['fail', false]);
    }
  });
  it('a verifier that throws fails closed', async () => {
    const r = await judgeCanary(built(async () => { throw new Error('boom'); }), base, NOW, 14);
    expect([r.verdict, r.why]).toEqual(['fail', 'canary error (fail closed): boom']);
  });
  it('no readable expiry fails (an unreadable chain cannot be assumed fresh); a good verifier with far expiry passes', async () => {
    expect((await judgeCanary(built(async (o) => exact(o), []), base, NOW, 14)).why).toBe('no certificate or collateral expiry could be read from the evidence');
    const r = await judgeCanary(built(async (o) => exact(o)), base, NOW, 14);
    expect([r.verdict, r.expiry]).toEqual(['pass', { earliestNotAfter: FAR[0], daysLeft: 365, alarm: false }]);
  });
});
