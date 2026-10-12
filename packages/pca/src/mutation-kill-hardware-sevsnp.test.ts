/**
 * Mutation-kill tests for hardware-sevsnp.ts. Every failure is asserted as the WHOLE result ({ ok: false, reason }),
 * every policy gate on both sides of its boundary, every parse bound at its exact edge.
 */
import { describe, expect, it, vi } from 'vitest';
import { p384 } from '@noble/curves/p384';
import { sha384 } from '@noble/hashes/sha512';
import {
  SEV_SNP_POLICY_DEBUG_BIT,
  checkSevSnpPolicy,
  ecdsaP384PublicKey,
  extractVcekPublicKey,
  fetchVcekFromKds,
  makeDefaultDeriveIdentity,
  parseSevSnpReport,
  sevSnpSignatureToCompact,
  verifyAmdCertChain,
  verifyGenuineSevSnpReport,
  verifySevSnpReportSignature,
} from './hardware-sevsnp';
import { attestationBinding, type ExpectedAttestationBinding } from './attestation';
import { serializeSevSnpReport } from './test-support/sevsnp-report';
import { forgeCert, forgeKey } from './test-support/forge-x509';
import { FORGE_CHIP, FORGE_NA, FORGE_NB, amdVcekExtensions, boolean, ext, extension, forgeAmdChain, integer, octets, pemOf, seq, type AmdChainOptions } from './test-support/forge-amd';

const NOW = Date.parse('2026-10-08T12:00:00Z');
const le72 = (v: bigint): Uint8Array => { const o = new Uint8Array(72); for (let i = 0; i < 72; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; };
const N = p384.CURVE.n;
const rep = (f: Parameters<typeof serializeSevSnpReport>[0] = {}) => parseSevSnpReport(serializeSevSnpReport(f));

describe('parseSevSnpReport bounds', () => {
  it('rejects a non-Uint8Array, and a buffer one byte short of the r/s fields; accepts exactly that length', () => {
    expect(() => parseSevSnpReport([] as never)).toThrow(new TypeError('parseSevSnpReport: expected Uint8Array'));
    expect(() => parseSevSnpReport(new Uint8Array(0x2e8 + 72 - 1))).toThrow(new RangeError('parseSevSnpReport: report too short (815 < 816)'));
    expect(parseSevSnpReport(new Uint8Array(0x2e8 + 72)).signature.s.length).toBe(72);
  });
  it('raw is an independent copy of the input', () => {
    const b = serializeSevSnpReport({ guest_svn: 5 });
    const p = parseSevSnpReport(b);
    b[0x04] = 99;
    expect(p.raw[0x04]).not.toBe(99);
    expect(p.raw).not.toBe(b);
  });
});

describe('sevSnpSignatureToCompact', () => {
  const ok = (r: bigint, s: bigint) => sevSnpSignatureToCompact({ r: le72(r), s: le72(s) });
  it('accepts 1 and n-1 for r and s; the compact form is big-endian r||s', () => {
    const c = ok(1n, N - 1n);
    expect(c.length).toBe(96);
    expect(c[47]).toBe(1);
    expect(() => ok(N - 1n, 1n)).not.toThrow();
  });
  it('rejects r or s equal to 0 or n, or above n, with the specific message', () => {
    for (const bad of [0n, N, N + 1n]) {
      expect(() => ok(bad, 5n)).toThrow(new RangeError('sev-snp signature: r out of range'));
      expect(() => ok(5n, bad)).toThrow(new RangeError('sev-snp signature: s out of range'));
    }
    // r bad AND s bad: r is reported first
    expect(() => ok(0n, 0n)).toThrow('r out of range');
  });
});

describe('verifySevSnpReportSignature accepts a high-S signature (AMD hardware does not normalise)', () => {
  it('both s and n-s verify', () => {
    const priv = p384.utils.randomPrivateKey();
    const pub = ecdsaP384PublicKey(p384.getPublicKey(priv, false));
    const unsigned = parseSevSnpReport(serializeSevSnpReport({ guest_svn: 3 }));
    const sig = p384.sign(sha384(unsigned.signed), priv, { lowS: false });
    const mk = (s: bigint) => parseSevSnpReport(serializeSevSnpReport({ guest_svn: 3, signature: { r: le72(sig.r), s: le72(s) } }));
    const high = sig.s > N / 2n ? sig.s : N - sig.s;
    const low = N - high;
    expect(verifySevSnpReportSignature(mk(low), pub)).toBe(true);
    expect(verifySevSnpReportSignature(mk(high), pub)).toBe(true);
    expect(verifySevSnpReportSignature(mk(low + 1n), pub)).toBe(false);
  });
});

describe('checkSevSnpPolicy: every gate at its boundary, exact reasons', () => {
  const hx = (b: Uint8Array) => Buffer.from(b).toString('hex');
  const M = new Uint8Array(48).fill(0x11);
  const HD = new Uint8Array(32).fill(0x22);
  const CH = new Uint8Array(64).fill(0xcd);
  const r = rep({ signature_algo: 1, guest_svn: 5, reported_tcb: 100n, committed_tcb: 200n, launch_tcb: 300n, vmpl: 0, measurement: M, host_data: HD, chip_id: CH });
  it('signature algorithm: required by default and when true, waivable only with an explicit false', () => {
    const bad = rep({ signature_algo: 2 });
    expect(checkSevSnpPolicy(bad, {})).toBe('unexpected signature_algo 2');
    expect(checkSevSnpPolicy(bad, { requireEcdsaP384: true })).toBe('unexpected signature_algo 2');
    expect(checkSevSnpPolicy(bad, { requireEcdsaP384: false })).toBeNull();
    expect(checkSevSnpPolicy(r, {})).toBeNull();
  });
  it('debug bit', () => {
    const dbg = rep({ policy: SEV_SNP_POLICY_DEBUG_BIT });
    expect(checkSevSnpPolicy(dbg, {})).toBe('guest policy has the DEBUG bit set (host can inspect the guest)');
    expect(checkSevSnpPolicy(dbg, { allowDebug: false })).toMatch(/DEBUG/);
    expect(checkSevSnpPolicy(dbg, { allowDebug: true })).toBeNull();
    expect(checkSevSnpPolicy(rep({ policy: SEV_SNP_POLICY_DEBUG_BIT >> 1n }), {})).toBeNull();
  });
  it('minGuestSvn: equal accepted, one below rejected, absent/non-number ignored', () => {
    expect(checkSevSnpPolicy(r, { minGuestSvn: 5 })).toBeNull();
    expect(checkSevSnpPolicy(r, { minGuestSvn: 6 })).toBe('guest_svn 5 below minimum 6');
    expect(checkSevSnpPolicy(r, { minGuestSvn: 0 })).toBeNull();
    expect(checkSevSnpPolicy(r, { minGuestSvn: '9' as never })).toBeNull();
  });
  for (const [k, field, msg] of [['minReportedTcb', 100n, 'reported_tcb below minimum (rollback?)'], ['minCommittedTcb', 200n, 'committed_tcb below minimum (rollback?)'], ['minLaunchTcb', 300n, 'launch_tcb below minimum']] as const) {
    it(`${k}: equal accepted, one below rejected, a non-bigint is ignored`, () => {
      expect(checkSevSnpPolicy(r, { [k]: field })).toBeNull();
      expect(checkSevSnpPolicy(r, { [k]: field + 1n })).toBe(msg);
      expect(checkSevSnpPolicy(r, { [k]: 0n })).toBeNull();
      expect(checkSevSnpPolicy(r, { [k]: Number(field) + 1 } as never)).toBeNull();
    });
  }
  it('the three TCB gates are independent (each one fires alone)', () => {
    const low = rep({ reported_tcb: 1n, committed_tcb: 1n, launch_tcb: 1n });
    expect(checkSevSnpPolicy(low, { minCommittedTcb: 5n })).toBe('committed_tcb below minimum (rollback?)');
    expect(checkSevSnpPolicy(low, { minLaunchTcb: 5n })).toBe('launch_tcb below minimum');
    expect(checkSevSnpPolicy(low, { minReportedTcb: 5n })).toBe('reported_tcb below minimum (rollback?)');
  });
  it('vmpl defaults to 0 and honours any / a specific level', () => {
    const v1 = rep({ vmpl: 1 });
    expect(checkSevSnpPolicy(v1, {})).toBe('vmpl 1 is not the required 0');
    expect(checkSevSnpPolicy(v1, { requireVmpl: 'any' })).toBeNull();
    expect(checkSevSnpPolicy(v1, { requireVmpl: 1 })).toBeNull();
    expect(checkSevSnpPolicy(r, { requireVmpl: 1 })).toBe('vmpl 0 is not the required 1');
  });
  it('allowlists: case-insensitive match, mismatch rejected, empty list = no gate', () => {
    expect(checkSevSnpPolicy(r, { measurements: [hx(M).toUpperCase()] })).toBeNull();
    expect(checkSevSnpPolicy(r, { measurements: ['00'] })).toBe('measurement not in policy allowlist');
    expect(checkSevSnpPolicy(r, { measurements: [] })).toBeNull();
    expect(checkSevSnpPolicy(r, { hostData: [hx(HD).toUpperCase()] })).toBeNull();
    expect(checkSevSnpPolicy(r, { hostData: ['00'] })).toBe('host_data not in policy allowlist');
    expect(checkSevSnpPolicy(r, { hostData: [] })).toBeNull();
    expect(checkSevSnpPolicy(r, { chipIds: [hx(CH).toUpperCase()] })).toBeNull();
    expect(checkSevSnpPolicy(r, { chipIds: [hx(CH)] })).toBeNull();
    expect(checkSevSnpPolicy(r, { chipIds: ['00'] })).toBe('chip_id not in policy allowlist');
    expect(checkSevSnpPolicy(r, { chipIds: [] })).toBeNull();
  });
  it('gates are evaluated in a fixed order: algo, debug, svn, tcbs, vmpl, measurement, host_data, chip', () => {
    const all = rep({ signature_algo: 2, policy: SEV_SNP_POLICY_DEBUG_BIT, vmpl: 1 });
    expect(checkSevSnpPolicy(all, { measurements: ['00'], minGuestSvn: 9 })).toMatch(/signature_algo/);
    expect(checkSevSnpPolicy({ ...all, signature_algo: 1 }, { measurements: ['00'], minGuestSvn: 9 })).toMatch(/DEBUG/);
    expect(checkSevSnpPolicy({ ...all, signature_algo: 1, policy: 0n }, { measurements: ['00'], minGuestSvn: 9 })).toMatch(/guest_svn/);
    expect(checkSevSnpPolicy({ ...all, signature_algo: 1, policy: 0n }, { measurements: ['00'] })).toMatch(/vmpl/);
    expect(checkSevSnpPolicy({ ...all, signature_algo: 1, policy: 0n, vmpl: 0 }, { measurements: ['00'], hostData: ['00'], chipIds: ['00'] })).toMatch(/measurement/);
    expect(checkSevSnpPolicy({ ...all, signature_algo: 1, policy: 0n, vmpl: 0 }, { hostData: ['00'], chipIds: ['00'] })).toMatch(/host_data/);
  });
});

describe('makeDefaultDeriveIdentity', () => {
  it('model_id empty, weights from host_data only when asked, never measured', () => {
    const r = rep({ measurement: new Uint8Array(48).fill(1), host_data: new Uint8Array(32).fill(2), chip_id: new Uint8Array(64).fill(3) });
    expect(makeDefaultDeriveIdentity(false)(r)).toEqual({ model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: '01'.repeat(48), operator: '03'.repeat(64) });
    expect(makeDefaultDeriveIdentity(true)(r).weights_digest).toBe('02'.repeat(32));
  });
});

describe('fetchVcekFromKds', () => {
  const tcb = 2n | (3n << 8n) | (10n << 48n) | (7n << 56n);
  it('builds the KDS URL from product, chip id and the four SPL bytes; defaults product to Milan', async () => {
    const f = vi.fn(async (_url: string) => ({ ok: true, status: 200, arrayBuffer: async () => new Uint8Array([9, 8]).buffer }));
    const out = await fetchVcekFromKds(new Uint8Array([0xab, 0xcd]), tcb, { fetch: f as never });
    expect([...out]).toEqual([9, 8]);
    expect(f.mock.calls[0]![0]).toBe('https://kdsintf.amd.com/vcek/v1/Milan/abcd?blSPL=2&teeSPL=3&snpSPL=10&ucodeSPL=7');
    await fetchVcekFromKds(new Uint8Array([1]), 0n, { fetch: f as never, product: 'Genoa', baseUrl: 'http://x/y' });
    expect(f.mock.calls[1]![0]).toBe('http://x/y/Genoa/01?blSPL=0&teeSPL=0&snpSPL=0&ucodeSPL=0');
  });
  it('throws on a non-2xx with status and URL, and when no fetch exists', async () => {
    const f = async () => ({ ok: false, status: 404 });
    await expect(fetchVcekFromKds(new Uint8Array([1]), 0n, { fetch: f as never, baseUrl: 'http://k' })).rejects.toThrow('KDS VCEK fetch failed: HTTP 404 for http://k/Milan/01?blSPL=0&teeSPL=0&snpSPL=0&ucodeSPL=0');
    vi.stubGlobal('fetch', undefined);
    try {
      await expect(fetchVcekFromKds(new Uint8Array([1]), 0n)).rejects.toThrow('fetchVcekFromKds: no fetch implementation available');
    } finally { vi.unstubAllGlobals(); }
  });
});

// ── forged chains ────────────────────────────────────────────────────────────────────────────────────
const cache = new Map<string, ReturnType<typeof forgeAmdChain>>();
const chain = (name: string, o: AmdChainOptions = {}) => { let c = cache.get(name); if (!c) { c = forgeAmdChain({ label: 'amd-test', ...o }); cache.set(name, c); } return c; };
const vf = (c: ReturnType<typeof forgeAmdChain>, over: { pem?: string; vcekDer?: Uint8Array; pin?: string; nowMs?: number; clockSkewMs?: number } = {}) =>
  verifyAmdCertChain({ vcekDer: over.vcekDer ?? c.vcekDer, askArkPem: over.pem ?? c.askArkPem, trustAnchorArkSpkiSha384: over.pin ?? c.arkPin, nowMs: over.nowMs ?? NOW, ...(over.clockSkewMs !== undefined ? { clockSkewMs: over.clockSkewMs } : {}) });
const bad = (reason: string) => ({ ok: false, reason });
const T = 180_000;

describe('verifyAmdCertChain: every failure is a whole { ok: false, reason } result', () => {
  it('clock preconditions', async () => {
    const c = chain('ok');
    const base = { vcekDer: c.vcekDer, askArkPem: c.askArkPem, trustAnchorArkSpkiSha384: c.arkPin };
    const NOWMSG = 'nowMs (verifier clock) is required for the AMD chain validity check';
    expect(await verifyAmdCertChain({ ...base } as never)).toEqual(bad(NOWMSG));
    expect(await verifyAmdCertChain({ ...base, nowMs: '5' as never })).toEqual(bad(NOWMSG));
    expect(await verifyAmdCertChain({ ...base, nowMs: Infinity })).toEqual(bad(NOWMSG));
    for (const s of [-1, Number.NaN, Infinity, '1' as never]) expect(await verifyAmdCertChain({ ...base, nowMs: NOW, clockSkewMs: s })).toEqual(bad('clockSkewMs must be a non-negative number'));
    expect((await verifyAmdCertChain({ ...base, nowMs: NOW, clockSkewMs: 0 })).ok).toBe(true);
  }, T);
  it('count, order, self-signed checks', async () => {
    const c = chain('ok');
    expect(await vf(c, { pem: pemOf(c.askDer) })).toEqual(bad('ASK+ARK chain must contain exactly two certificates (ASK then ARK)'));
    expect(await vf(c, { pem: pemOf(c.arkDer) + pemOf(c.askDer) })).toEqual(bad('second certificate of the chain is not a self-signed ARK (chain out of order?)'));
    expect(await vf(c, { pem: pemOf(c.arkDer) + pemOf(c.arkDer) })).toEqual(bad('first certificate of the chain is self-signed, not an ASK (chain out of order?)'));
    expect(await vf(c, { vcekDer: c.askDer })).toEqual(bad('ASK subject does not match the VCEK issuer'));
    // second cert: subject == issuer but NOT validly self-signed
    const unsigned = chain('arkBadSelfSig', { arkSignedBy: 'other-amd' });
    expect(await vf(unsigned)).toEqual(bad('second certificate of the chain is not a self-signed ARK (chain out of order?)'));
    // second cert: validly self-signed but subject != issuer
    const renamed = chain('arkRenamed', { arkIssuerName: 'SOMEONE-ELSE' });
    expect(await vf(renamed)).toEqual(bad('second certificate of the chain is not a self-signed ARK (chain out of order?)'));
  }, T);
  it('pin, ASK issuer / signature, VCEK signature', async () => {
    const c = chain('ok');
    expect(await vf(c, { pin: 'zz' })).toEqual(bad('ARK does not match the pinned AMD trust anchor'));
    expect(await vf(chain('askForeign', { askSignedBy: 'other-amd' }))).toEqual(bad('ASK is not signed by ARK'));
    // ASK signed by the ARK key but naming a different issuer
    expect(await vf(chain('askIssuer', { askIssuerName: 'SOMEONE-ELSE' }))).toEqual(bad('ASK is not signed by ARK'));
    expect(await vf(chain('vcekForeign', { vcekSignedBy: 'other-amd' }))).toEqual(bad('VCEK is not signed by ASK'));
  }, T);
  it('roles and critical extensions', async () => {
    const roles = chain('askNotCa', { ask: { extensions: [ext.basicConstraints(false), ext.keyUsage(['keyCertSign'])] } });
    expect(await vf(roles)).toEqual(bad('AMD chain role check failed: issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)'));
    const spl = amdVcekExtensions({ chip: FORGE_CHIP, bl: 7, tee: 0, snp: 3, ucode: 0 });
    const crit = chain('vcekCrit', { vcek: { extensions: [extension('1.2.3.4.5', true, octets(new Uint8Array([1]))), ...spl] } });
    expect(await vf(crit)).toEqual(bad('VCEK certificate has an unrecognised critical extension 1.2.3.4.5'));
    const nonCrit = chain('askBcNonCrit', { ask: { extensions: [extension('2.5.29.19', false, seq(boolean(true), integer(0))), ext.keyUsage(['keyCertSign'])] } });
    expect(await vf(nonCrit)).toEqual(bad('ASK certificate BasicConstraints is not marked critical'));
    const arkNonCrit = chain('arkBcNonCrit', { ark: { extensions: [extension('2.5.29.19', false, seq(boolean(true), integer(2))), ext.keyUsage(['keyCertSign'])] } });
    expect(await vf(arkNonCrit)).toEqual(bad('ARK certificate BasicConstraints is not marked critical'));
    // a VCEK needs no BasicConstraints at all (the profile applies to CAs only)
    expect((await vf(chain('vcekNoBc', { vcek: { extensions: spl } }))).ok).toBe(true);
  }, T);
  it('validity windows to the millisecond with skew on both ends', async () => {
    const from = new Date('2026-10-01T00:00:00Z');
    const to = new Date('2026-10-20T00:00:00Z');
    const c = chain('vcekWin', { vcek: { notBefore: from, notAfter: to } });
    expect(await vf(c, { nowMs: from.getTime() })).toMatchObject({ ok: true });
    expect(await vf(c, { nowMs: from.getTime() - 1 })).toEqual(bad('VCEK certificate is not yet valid'));
    expect(await vf(c, { nowMs: from.getTime() - 1000, clockSkewMs: 1000 })).toMatchObject({ ok: true });
    expect(await vf(c, { nowMs: from.getTime() - 1001, clockSkewMs: 1000 })).toEqual(bad('VCEK certificate is not yet valid'));
    expect(await vf(c, { nowMs: to.getTime() })).toMatchObject({ ok: true });
    expect(await vf(c, { nowMs: to.getTime() + 1 })).toEqual(bad('VCEK certificate has expired'));
    expect(await vf(c, { nowMs: to.getTime() + 1000, clockSkewMs: 1000 })).toMatchObject({ ok: true });
    expect(await vf(c, { nowMs: to.getTime() + 1001, clockSkewMs: 1000 })).toEqual(bad('VCEK certificate has expired'));
  }, T);
  it('garbage input becomes a fail-closed chain error carrying the parser message', async () => {
    const c = chain('ok');
    const r = await vf(c, { vcekDer: new Uint8Array([1, 2, 3]) });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^AMD chain verification error: /);
    expect(r.reason!.length).toBeGreaterThan('AMD chain verification error: '.length);
  }, T);
});

describe('extractVcekPublicKey refuses non-secp384r1 keys with the key description', () => {
  it('a P-256 certificate', async () => {
    const k = forgeKey('p256-vcek', 'P-256');
    const cert = forgeCert({ subject: [['CN', 's']], issuer: [['CN', 'i']], subjectKey: k, signer: forgeKey('sg', 'P-384'), serial: 1n, notBefore: FORGE_NB, notAfter: FORGE_NA, extensions: [ext.basicConstraints(false)] });
    await expect(extractVcekPublicKey(cert.der)).rejects.toThrow('VCEK is not EC secp384r1 (got ec/prime256v1)');
  });
});

// ── end to end with the forged chain and a locally signed report ────────────────────────────────────
const EXPECTED: ExpectedAttestationBinding = { holderPub: 'h', grantRef: 'g', epoch: 1, nonce: 'n', nonceIssuedAt: 1 };
function signedReport(c: ReturnType<typeof forgeAmdChain>, f: Parameters<typeof serializeSevSnpReport>[0]): Uint8Array {
  const fields = { version: 2, vmpl: 0, reported_tcb: 0x0003_0000_0000_0007n, chip_id: FORGE_CHIP, measurement: new Uint8Array(48).fill(9), host_data: new Uint8Array(32).fill(5), ...f };
  const parsed = parseSevSnpReport(serializeSevSnpReport(fields));
  const sig = p384.sign(p384.CURVE.hash(parsed.signed), c.vcekKey.priv, { lowS: false }).toCompactRawBytes();
  const le = (b: Uint8Array) => { const o = new Uint8Array(72); o.set(Uint8Array.from(b).reverse(), 0); return o; };
  return serializeSevSnpReport({ ...fields, signature: { r: le(sig.subarray(0, 48)), s: le(sig.subarray(48, 96)) } });
}

describe('verifyGenuineSevSnpReport: each stage fails with its own whole result', () => {
  const c = () => chain('ok');
  const base = (report: Uint8Array, over: Record<string, unknown> = {}) => ({ report, vcekDer: c().vcekDer, askArkPem: c().askArkPem, trustAnchorArkSpkiSha384: c().arkPin, nowMs: NOW, ...over });
  const good = () => signedReport(c(), { report_data: attestationBinding(EXPECTED) });
  it('success: identity is the default mapping, host_data NOT used as weights, report returned', async () => {
    const r = await verifyGenuineSevSnpReport(base(good(), { expected: EXPECTED, policy: { measurements: ['09'.repeat(48)] } }));
    expect(r.ok).toBe(true);
    expect(r.measured).toEqual({ model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: '09'.repeat(48), operator: Buffer.from(FORGE_CHIP).toString('hex') });
    expect(r.report?.guest_svn).toBe(0);
    expect(r.reason).toBeUndefined();
  }, T);
  it('parse failure, chain failure, bad signature, binding failures, report_data, policy', async () => {
    expect(await verifyGenuineSevSnpReport(base(new Uint8Array(10)))).toEqual(bad('report parse failed: parseSevSnpReport: report too short (10 < 816)'));
    expect(await verifyGenuineSevSnpReport(base(good(), { nowMs: undefined }))).toEqual(bad('cert chain invalid: nowMs (verifier clock) is required for the AMD chain validity check'));
    const tampered = good(); tampered[0x50]! ^= 1; // inside the signed region
    expect(await verifyGenuineSevSnpReport(base(tampered))).toEqual(bad('report signature does not verify under VCEK'));
    const otherChip = signedReport(c(), { chip_id: new Uint8Array(64).fill(1) });
    expect(await verifyGenuineSevSnpReport(base(otherChip))).toEqual(bad('VCEK CHIP_ID does not match report chip_id'));
    const wrongData = signedReport(c(), { report_data: new Uint8Array(64) });
    expect(await verifyGenuineSevSnpReport(base(wrongData, { expected: EXPECTED }))).toEqual(bad('report_data does not bind holder/grant/epoch/nonce'));
    expect((await verifyGenuineSevSnpReport(base(wrongData))).ok).toBe(true); // no expected binding: not checked
    expect(await verifyGenuineSevSnpReport(base(good(), { expected: EXPECTED, policy: { measurements: ['00'] } }))).toEqual(bad('measurement not in policy allowlist'));
    expect(await verifyGenuineSevSnpReport(base(good(), { expected: { ...EXPECTED, nonce: '' } }))).toEqual(bad('genuine verification error (fail closed): binding: nonce required'));
  }, T);
  it('a clock skew is forwarded to the chain check (and omitted skew means 0)', async () => {
    const win = chain('vcekWin');
    const to = new Date('2026-10-20T00:00:00Z').getTime();
    const r = signedReport(win, {});
    const b = { report: r, vcekDer: win.vcekDer, askArkPem: win.askArkPem, trustAnchorArkSpkiSha384: win.arkPin };
    expect((await verifyGenuineSevSnpReport({ ...b, nowMs: to + 500, clockSkewMs: 1000 })).ok).toBe(true);
    expect((await verifyGenuineSevSnpReport({ ...b, nowMs: to + 500 })).reason).toBe('cert chain invalid: VCEK certificate has expired');
  }, T);
});
