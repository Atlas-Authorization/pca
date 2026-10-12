/** Mutation-kill suite for the SEV-SNP side of index.ts: tolerant report parsing, evidence projection, verifyAmdAttestation, hardware tier. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { parseSevSnpReport, toHex } from '@atlasauth/pca';
import { ecdsaSign } from './test-support/forge-x509';
import { serializeSevSnpReport } from './test-support/sevsnp-report';
import { FORGE_CHIP, forgeAmdChain, type AmdChainOptions } from './test-support/forge-amd';
import {
  AMD_SEV_SNP_HARDWARE_ROOT_LABEL,
  AMD_SEV_SNP_SIGNED_REGION_END,
  KNOWN_AMD_ARK_SPKI_SHA384,
  KNOWN_REPORT_VERSIONS,
  buildEAT,
  evidenceFromReport,
  generateEatKeyPair,
  measuredFromReport,
  parseReportTolerant,
  verifyAmdAttestation,
  verifyFreshAttestedEAT,
} from './index';

const FULL = 0x2e8 + 72;
const rpt = (f: Parameters<typeof serializeSevSnpReport>[0] = {}): Uint8Array =>
  serializeSevSnpReport({ measurement: new Uint8Array(48).fill(0xaa), chip_id: new Uint8Array(64).fill(0xcc), reported_tcb: 0x0102_0304_0506_0708n, guest_svn: 9, ...f });

afterEach(() => vi.useRealTimers());

describe('constants', () => {
  it('values', () => {
    expect(AMD_SEV_SNP_SIGNED_REGION_END).toBe(0x2a0);
    expect([...KNOWN_REPORT_VERSIONS]).toEqual([2, 3, 5]);
    expect(AMD_SEV_SNP_HARDWARE_ROOT_LABEL).toBe('amd-sev-snp/ecdsa-p384 (VCEK→ASK→ARK; classical hardware root, not post-quantum)');
  });
});

describe('evidence projections', () => {
  const r = parseSevSnpReport(rpt({ version: 2, policy: 1n << 19n }));
  it('evidenceFromReport', () => {
    expect(evidenceFromReport(r)).toStrictEqual({
      version: 2, measurement: 'aa'.repeat(48), reported_tcb: '72623859790382856', guest_svn: 9, chip_id: 'cc'.repeat(64), debug: true,
    });
    expect(evidenceFromReport(parseSevSnpReport(rpt({ policy: 0n }))).debug).toBe(false);
    expect(evidenceFromReport(parseSevSnpReport(rpt({ policy: (1n << 19n) - 1n }))).debug).toBe(false);
    expect(evidenceFromReport(parseSevSnpReport(rpt({ policy: 1n << 18n }))).debug).toBe(false);
    expect(evidenceFromReport(parseSevSnpReport(rpt({ policy: 1n << 20n }))).debug).toBe(false);
    expect(evidenceFromReport(parseSevSnpReport(rpt({ policy: (1n << 19n) | 1n }))).debug).toBe(true);
  });
  it('measuredFromReport', () => {
    expect(measuredFromReport(r)).toStrictEqual({ model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: 'aa'.repeat(48), operator: 'cc'.repeat(64) });
  });
});

describe('parseReportTolerant', () => {
  it('inputs that are not byte arrays', () => {
    for (const v of ['x', [1, 2, 3], null, undefined, {}, new ArrayBuffer(8), 5]) {
      expect(parseReportTolerant(v as never), String(v)).toStrictEqual({ ok: false, version: 0, known: false, degraded: true, notes: ['input is not a Uint8Array'] });
    }
  });
  it('too short to hold even the version', () => {
    for (const n of [0, 1, 2, 3]) {
      expect(parseReportTolerant(new Uint8Array(n)), String(n)).toStrictEqual({ ok: false, version: 0, known: false, degraded: true, notes: ['buffer too short to read the report version'] });
    }
  });
  it('version readable but no launch measurement', () => {
    const b = rpt({ version: 2 });
    expect(parseReportTolerant(b.subarray(0, 4))).toStrictEqual({
      ok: false, version: 2, known: true, degraded: true,
      notes: [`buffer length 4 < full report ${FULL} — degraded header-only parse`, 'buffer too short to read the launch measurement'],
    });
    const r = parseReportTolerant(b.subarray(0, 0xbf));
    expect(r.ok).toBe(false);
    expect(r.notes.at(-1)).toBe('buffer too short to read the launch measurement');
    expect(parseReportTolerant(b.subarray(0, 0xc0)).ok).toBe(true);
    const unk = parseReportTolerant(rpt({ version: 9 }).subarray(0, 0xbf));
    expect(unk).toStrictEqual({
      ok: false, version: 9, known: false, degraded: true,
      notes: ['unknown report version 9 — parsing version-stable header fields only (newer firmware, e.g. GCP 2025-10-27, may relocate version-specific fields)', 'buffer too short to read the launch measurement'],
    });
  });
  it('known version, complete buffer: PCA parse, not degraded', () => {
    for (const version of [2, 3, 5]) {
      const b = rpt({ version });
      const r = parseReportTolerant(b);
      if (r.degraded) {
        expect(r.notes[0]).toMatch(/^full parse failed, falling back to the stable header: /);
        continue;
      }
      expect(r.ok).toBe(true);
      expect(r.known).toBe(true);
      expect(r.version).toBe(version);
      expect(r.notes).toEqual([]);
      expect(r.report?.version).toBe(version);
      expect(r.evidence).toStrictEqual(evidenceFromReport(parseSevSnpReport(b)));
    }
    const ok = parseReportTolerant(rpt({ version: 2 }));
    expect(ok.degraded).toBe(false);
    expect(ok.report).toBeDefined();
    expect(Object.keys(ok.evidence ?? {}).sort()).toEqual(['chip_id', 'debug', 'guest_svn', 'measurement', 'reported_tcb', 'version']);
  });
  it('known version one byte short of the full report degrades with the length note', () => {
    const b = rpt({ version: 2 }).subarray(0, FULL - 1);
    const r = parseReportTolerant(b);
    expect(r.degraded).toBe(true);
    expect(r.known).toBe(true);
    expect(r.notes).toEqual([`buffer length ${FULL - 1} < full report ${FULL} — degraded header-only parse`]);
    expect(r.report).toBeUndefined();
    const exact = parseReportTolerant(rpt({ version: 2 }).subarray(0, FULL));
    expect(exact.degraded).toBe(false);
  });
  it('degraded path reads exactly the fields that fit', () => {
    const base = rpt({ version: 9, policy: 1n << 19n });
    const unk = (n: number) => parseReportTolerant(base.subarray(0, n));
    expect(unk(0xc0).evidence).toStrictEqual({ version: 9, measurement: 'aa'.repeat(48), degraded: true, guest_svn: 9, debug: true });
    expect(unk(0x187).evidence).toStrictEqual({ version: 9, measurement: 'aa'.repeat(48), degraded: true, guest_svn: 9, debug: true });
    expect(unk(0x188).evidence).toStrictEqual({ version: 9, measurement: 'aa'.repeat(48), degraded: true, guest_svn: 9, debug: true, reported_tcb: '72623859790382856' });
    expect(unk(0x1df).evidence?.chip_id).toBeUndefined();
    expect(unk(0x1e0).evidence).toStrictEqual({
      version: 9, measurement: 'aa'.repeat(48), degraded: true, guest_svn: 9, debug: true, reported_tcb: '72623859790382856', chip_id: 'cc'.repeat(64),
    });
    const full = parseReportTolerant(base);
    expect(full.ok).toBe(true);
    expect(full.known).toBe(false);
    expect(full.degraded).toBe(true);
    expect(full.version).toBe(9);
    expect(full.notes).toEqual(['unknown report version 9 — parsing version-stable header fields only (newer firmware, e.g. GCP 2025-10-27, may relocate version-specific fields)']);
    expect(full.evidence?.debug).toBe(true);
    expect(parseReportTolerant(rpt({ version: 9, policy: 0n })).evidence?.debug).toBe(false);
    expect(parseReportTolerant(rpt({ version: 9, policy: 1n << 18n })).evidence?.debug).toBe(false);
  });
  it('reads the report from a view with a non-zero byte offset', () => {
    const big = new Uint8Array(0x100 + 0x4a0);
    big.set(rpt({ version: 9 }), 0x100);
    const view = big.subarray(0x100);
    const r = parseReportTolerant(view);
    expect(r.version).toBe(9);
    expect(r.evidence?.measurement).toBe('aa'.repeat(48));
    expect(r.evidence?.chip_id).toBe('cc'.repeat(64));
    expect(toHex(new Uint8Array([1]))).toBe('01');
  });
});

describe('verifyAmdAttestation: argument handling', () => {
  const certs = { vcek: new Uint8Array(1), ask: new Uint8Array(1), ark: new Uint8Array(1), nowMs: Date.now() };
  const R = new Uint8Array(10);
  const root = AMD_SEV_SNP_HARDWARE_ROOT_LABEL;
  it('exactly one of family or pin', async () => {
    const msg = 'exactly one of family or trustAnchorArkSpkiSha384 must be supplied (the ARK pin is never inferred)';
    expect(await verifyAmdAttestation(R, certs as never)).toStrictEqual({ ok: false, reason: msg, hardwareRoot: root });
    expect(await verifyAmdAttestation(R, { ...certs, family: 'milan', trustAnchorArkSpkiSha384: 'ab' } as never)).toStrictEqual({ ok: false, reason: msg, hardwareRoot: root });
    expect((await verifyAmdAttestation(R, { ...certs, family: 'milan' } as never)).reason).not.toBe(msg);
    expect((await verifyAmdAttestation(R, { ...certs, trustAnchorArkSpkiSha384: 'ab' } as never)).reason).not.toBe(msg);
  });
  it('unknown families, including inherited object keys', async () => {
    for (const f of ['zen', 'MILAN', 'toString', 'constructor', '__proto__', 'hasOwnProperty']) {
      expect(await verifyAmdAttestation(R, { ...certs, family: f } as never), f).toStrictEqual({ ok: false, reason: `unknown AMD family ${f} (expected milan | genoa | turin)`, hardwareRoot: root });
    }
    expect(Object.keys(KNOWN_AMD_ARK_SPKI_SHA384).sort()).toEqual(['genoa', 'milan', 'turin']);
  });
  it('certificate inputs that cannot be parsed', async () => {
    const pem = (n: number) => '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n'.repeat(n);
    const base = { ...certs, family: 'milan' };
    expect((await verifyAmdAttestation(R, { ...base, vcek: 'not a cert' } as never)).reason).toBe('certificate parse failed: expected exactly one PEM certificate, found 0');
    expect((await verifyAmdAttestation(R, { ...base, vcek: pem(2) } as never)).reason).toBe('certificate parse failed: expected exactly one PEM certificate, found 2');
    expect((await verifyAmdAttestation(R, { ...base, ask: pem(0) } as never)).reason).toBe('certificate parse failed: expected exactly one PEM certificate, found 0');
    expect((await verifyAmdAttestation(R, { ...base, ark: pem(3) } as never)).reason).toBe('certificate parse failed: expected exactly one PEM certificate, found 3');
    const r = await verifyAmdAttestation(R, { ...base, vcek: 'x' } as never);
    expect(r.ok).toBe(false);
    expect(r.hardwareRoot).toBe(root);
    expect(r).not.toHaveProperty('report');
  });
  it('a thrown non-Error is reported as unknown', async () => {
    const hostile = { get family(): never { throw 'boom'; } };
    const r = await verifyAmdAttestation(R, hostile as never);
    expect(r).toStrictEqual({ ok: false, reason: 'AMD attestation verification error (fail closed): unknown', hardwareRoot: root });
  });
  it('unexpected exceptions are reported fail-closed', async () => {
    const r = await verifyAmdAttestation(R, null as never);
    expect(r.ok).toBe(false);
    expect(r.hardwareRoot).toBe(root);
    expect(r.reason?.startsWith('AMD attestation verification error (fail closed): ')).toBe(true);
    expect((r.reason as string).length).toBeGreaterThan('AMD attestation verification error (fail closed): '.length);
  });
});

const NOW = Date.parse('2026-10-08T12:00:00Z');
const DAY = 86_400_000;
const MEAS = 'aa'.repeat(48);
const le72 = (b: Uint8Array): Uint8Array => {
  const o = new Uint8Array(72);
  o.set(Uint8Array.from(b).reverse(), 0);
  return o;
};
const cache = new Map<string, ReturnType<typeof forgeAmdChain>>();
const chain = (name: string, o: AmdChainOptions = {}): ReturnType<typeof forgeAmdChain> => {
  let c = cache.get(name);
  if (!c) {
    c = forgeAmdChain({ label: 'eat-amd-kill', ...o });
    cache.set(name, c);
  }
  return c;
};
function signed(c: ReturnType<typeof forgeAmdChain>, policy = 0n): Uint8Array {
  const f = { version: 2, vmpl: 0, policy, reported_tcb: 0x0003_0000_0000_0007n, measurement: new Uint8Array(48).fill(0xaa), chip_id: FORGE_CHIP };
  const parsed = parseSevSnpReport(serializeSevSnpReport(f));
  const sig = ecdsaSign(c.vcekKey, 'sha384', parsed.signed).raw;
  return serializeSevSnpReport({ ...f, signature: { r: le72(sig.subarray(0, 48)), s: le72(sig.subarray(48, 96)) } });
}
const inp = (c: ReturnType<typeof forgeAmdChain>, over: Record<string, unknown> = {}) => ({ vcek: c.vcekDer, ask: c.askDer, ark: c.arkDer, trustAnchorArkSpkiSha384: c.arkPin, nowMs: NOW, ...over });

describe('verifyAmdAttestation: forged chain', () => {
  it('success carries report, evidence and measured identity; PEM chains are accepted', async () => {
    const c = chain('ok');
    const r = await verifyAmdAttestation(signed(c), inp(c, { expectedMeasurement: MEAS }) as never);
    expect(r.ok).toBe(true);
    expect(r.reason).toBeUndefined();
    expect(r.hardwareRoot).toBe(AMD_SEV_SNP_HARDWARE_ROOT_LABEL);
    expect(r.report?.version).toBe(2);
    expect(r.evidence).toStrictEqual(evidenceFromReport(r.report!));
    expect(r.measured).toStrictEqual(measuredFromReport(r.report!));
    const pem = (d: Uint8Array) => `-----BEGIN CERTIFICATE-----\n${Buffer.from(d).toString('base64').replace(/(.{64})/g, '$1\n')}\n-----END CERTIFICATE-----\n`;
    const viaPem = await verifyAmdAttestation(signed(c), inp(c, { vcek: pem(c.vcekDer), ask: pem(c.askDer), ark: pem(c.arkDer) }) as never);
    expect(viaPem.ok).toBe(true);
  }, 180_000);
  it('expected measurement: mismatch fails, empty string means none', async () => {
    const c = chain('ok');
    const wrong = await verifyAmdAttestation(signed(c), inp(c, { expectedMeasurement: 'bb'.repeat(48) }) as never);
    expect(wrong.ok).toBe(false);
    expect(wrong.report).toBeDefined();
    expect((wrong.reason ?? '').length).toBeGreaterThan(0);
    expect((await verifyAmdAttestation(signed(c), inp(c, { expectedMeasurement: '' }) as never)).ok).toBe(true);
    expect((await verifyAmdAttestation(signed(c), inp(c, { expectedMeasurement: 5 }) as never)).ok).toBe(true);
    expect((await verifyAmdAttestation(signed(c), inp(c) as never)).ok).toBe(true);
  }, 180_000);
  it('debug policy: only the literal true opts in', async () => {
    const c = chain('ok');
    const dbg = signed(c, 1n << 19n);
    expect((await verifyAmdAttestation(dbg, inp(c) as never)).reason).toBe('guest policy has the DEBUG bit set (host can inspect the guest)');
    expect((await verifyAmdAttestation(dbg, inp(c, { allowDebug: false }) as never)).ok).toBe(false);
    expect((await verifyAmdAttestation(dbg, inp(c, { allowDebug: 1 }) as never)).ok).toBe(false);
    expect((await verifyAmdAttestation(dbg, inp(c, { allowDebug: true }) as never)).ok).toBe(true);
  }, 180_000);
  it('a failed verification still reports the parsed report', async () => {
    const c = chain('ok');
    const r = await verifyAmdAttestation(signed(c), { ...inp(c), trustAnchorArkSpkiSha384: undefined, family: 'genoa' } as never);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('cert chain invalid: ARK does not match the pinned AMD trust anchor');
    expect(r.report?.version).toBe(2);
    expect(r.evidence).toBeUndefined();
    expect(r.measured).toBeUndefined();
    const garbage = await verifyAmdAttestation(new Uint8Array(10), inp(c) as never);
    expect(garbage.ok).toBe(false);
    expect(garbage.report).toBeUndefined();
    expect(garbage).not.toHaveProperty('report');
  }, 180_000);
  it('clock skew relaxes the certificate validity window', async () => {
    const c = chain('vcek-just-expired', { vcek: { notBefore: new Date('2022-01-01T00:00:00Z'), notAfter: new Date(NOW - 1000) } });
    expect((await verifyAmdAttestation(signed(c), inp(c) as never)).reason).toBe('cert chain invalid: VCEK certificate has expired');
    expect((await verifyAmdAttestation(signed(c), inp(c, { clockSkewMs: 5000 }) as never)).ok).toBe(true);
    expect((await verifyAmdAttestation(signed(c), inp(c, { clockSkewMs: 500 }) as never)).ok).toBe(false);
    void DAY;
  }, 240_000);
});

describe('verifyFreshAttestedEAT with the hardware root', () => {
  const k = generateEatKeyPair();
  const T = 1_700_000_000_000;
  const mk = (c: ReturnType<typeof forgeAmdChain>, over: Record<string, unknown> = {}) =>
    buildEAT({
      issuer: 'I', key: k.privateKey, nonce: 'N', channelId: 'chan', now: T,
      measured: { model_id: 'm', weights_digest: 'w', runtime_measurement: MEAS, operator: 'op' }, ...over,
    });
  const amd = (c: ReturnType<typeof forgeAmdChain>, over: Record<string, unknown> = {}) => ({
    rawReport: signed(c), vcek: c.vcekDer, ask: c.askDer, ark: c.arkDer, trustAnchorArkSpkiSha384: c.arkPin, ...over,
  });
  const run = (c: ReturnType<typeof forgeAmdChain>, eat: string, a: Record<string, unknown>, extra: Record<string, unknown> = {}) =>
    verifyFreshAttestedEAT(eat, {
      verifyKey: k.publicKey, nonce: 'N', channelId: 'chan', now: NOW, policy: { referenceValues: { measurements: [MEAS] } }, amd: a, ...extra,
    } as never);
  it('a verified silicon report lifts the verdict to the hardware-rooted tier and the clock is the call clock', async () => {
    const c = chain('ok');
    const eat = mk(c, { now: NOW });
    const r = await run(c, eat, amd(c));
    expect(r.ok).toBe(true);
    expect(r.tier).toBe('affirming-hw-rooted');
    expect(r.reasons).toEqual([
      'signature + typ/iss verified',
      'fresh (nonce + iat within window)',
      'channel-bound (cnf matches live channel)',
      `AMD SEV-SNP hardware root verified (${AMD_SEV_SNP_HARDWARE_ROOT_LABEL})`,
      'launch measurement matches a reference value',
      `AMD SEV-SNP report signature + VCEK→ASK→ARK chain verified — ${AMD_SEV_SNP_HARDWARE_ROOT_LABEL}`,
    ]);
  }, 180_000);
  it('the EAT launch measurement is cross-bound to the silicon report unless overridden', async () => {
    const c = chain('ok');
    const eat = mk(c, { now: NOW, measured: { model_id: 'm', weights_digest: 'w', runtime_measurement: 'bb'.repeat(48), operator: 'op' } });
    const r = await run(c, eat, amd(c), { policy: { endorsements: { issuers: ['I'] } } });
    expect(r.ok).toBe(false);
    expect(r.tier).toBe('contraindicated');
    expect(r.reasons[3]?.startsWith('AMD hardware root verification failed: ')).toBe(true);
    const overridden = await run(c, eat, amd(c, { expectedMeasurement: MEAS }), { policy: { endorsements: { issuers: ['I'] } } });
    expect(overridden.ok).toBe(true);
    // an EAT without any launch measurement leaves the expectation open
    const none = buildEAT({ issuer: 'I', key: k.privateKey, nonce: 'N', channelId: 'chan', now: NOW });
    expect((await run(c, none, amd(c), { policy: { endorsements: { issuers: ['I'] } } })).ok).toBe(true);
    // the sevsnp block is the fallback source of the launch measurement
    const viaSev = buildEAT({ issuer: 'I', key: k.privateKey, nonce: 'N', channelId: 'chan', now: NOW, sevsnp: { version: 2, measurement: 'bb'.repeat(48) } });
    expect((await run(c, viaSev, amd(c), { policy: { endorsements: { issuers: ['I'] } } })).ok).toBe(false);
  }, 240_000);
  it('the certificate clock is the call clock: a non-finite or missing now falls back to the system clock', async () => {
    const c = chain('ok');
    const eat = mk(c, { now: NOW });
    vi.useFakeTimers();
    vi.setSystemTime(NOW + 1000);
    for (const now of [undefined, Number.NaN, Number.POSITIVE_INFINITY, '5' as never]) {
      const r = await verifyFreshAttestedEAT(eat, {
        verifyKey: k.publicKey, nonce: 'N', channelId: 'chan', policy: { referenceValues: { measurements: [MEAS] } }, amd: amd(c), now,
      } as never);
      expect(r.reasons, String(now)).toContain(`AMD SEV-SNP hardware root verified (${AMD_SEV_SNP_HARDWARE_ROOT_LABEL})`);
      expect(r.tier, String(now)).toBe('affirming-hw-rooted');
    }
  }, 240_000);
  it('allowDebug and clockSkewMs and the pin / family are forwarded', async () => {
    const c = chain('ok');
    const eat = mk(c, { now: NOW });
    const dbg = signed(c, 1n << 19n);
    expect((await run(c, eat, amd(c, { rawReport: dbg }))).reasons[3]).toBe('AMD hardware root verification failed: guest policy has the DEBUG bit set (host can inspect the guest)');
    expect((await run(c, eat, amd(c, { rawReport: dbg, allowDebug: true }))).ok).toBe(true);
    expect((await run(c, eat, amd(c, { rawReport: dbg, allowDebug: false }))).ok).toBe(false);
    const fam = await run(c, eat, amd(c, { trustAnchorArkSpkiSha384: undefined, family: 'genoa' }));
    expect(fam.reasons[3]).toBe('AMD hardware root verification failed: cert chain invalid: ARK does not match the pinned AMD trust anchor');
    const old = chain('vcek-just-expired2', { vcek: { notBefore: new Date('2022-01-01T00:00:00Z'), notAfter: new Date(NOW - 1000) } });
    const eatOld = mk(old, { now: NOW });
    expect((await run(old, eatOld, amd(old))).reasons[3]).toBe('AMD hardware root verification failed: cert chain invalid: VCEK certificate has expired');
    expect((await run(old, eatOld, amd(old, { clockSkewMs: 5000 }))).ok).toBe(true);
  }, 240_000);
});
