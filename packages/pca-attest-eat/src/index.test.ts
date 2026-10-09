import { describe, it, expect } from 'vitest';
import type { KeyObject } from 'node:crypto';
import type { MeasuredIdentity } from '@atlasauth/pca';
import { serializeSevSnpReport } from './test-support/sevsnp-report';
import {
  EAT_TYP,
  DEFAULT_EAT_ALG,
  DEFAULT_MAX_AGE_MS,
  KNOWN_REPORT_VERSIONS,
  generateEatKeyPair,
  issueNonce,
  bindChannel,
  deriveChannelCnf,
  buildEAT,
  verifyEAT,
  verifyFreshness,
  verifyChannelBinding,
  appraise,
  verifyFreshAttestedEAT,
  parseReportTolerant,
  evidenceFromReport,
  measuredFromReport,
  type EatClaims,
  type EatCnf,
  type EatSevSnpEvidence,
  type ReferenceValues,
  type Endorsements,
} from './index';

const ISS = 'https://attester.atlasauth.net';
const CHANNEL = 'tls-exporter-live-channel-abc';
const MEASUREMENT = 'a'.repeat(96); // 48-byte launch measurement, hex
const WEIGHTS = 'b'.repeat(96);
const CHIP_HEX = 'c'.repeat(128); // 64-byte chip id, hex
const OEM = 'oem-amd';

function keys(): { publicKey: KeyObject; privateKey: KeyObject } {
  return generateEatKeyPair();
}

/** The cnf a resource server observes for CHANNEL (what buildEAT with channelId emits). */
const CNF: EatCnf = deriveChannelCnf(CHANNEL);

function measured(over: Partial<MeasuredIdentity> = {}): MeasuredIdentity {
  return {
    model_id: 'gpt-x',
    weights_digest: WEIGHTS,
    weights_measured: true,
    runtime_measurement: MEASUREMENT,
    operator: CHIP_HEX,
    ...over,
  };
}

function evidence(over: Partial<EatSevSnpEvidence> = {}): EatSevSnpEvidence {
  return {
    version: 3,
    measurement: MEASUREMENT,
    reported_tcb: { bootloader: 3, tee: 0, snp: 20, microcode: 210 },
    guest_svn: 5,
    chip_id: CHIP_HEX,
    debug: false,
    ...over,
  };
}

function claimsWith(over: Partial<EatClaims> = {}): EatClaims {
  return { iss: ISS, iat: 1000, eat_nonce: 'n', cnf: CNF, oemid: OEM, dbgstat: 'disabled', measured: measured(), sevsnp: evidence(), ...over };
}

const refs: ReferenceValues = {
  measurements: [MEASUREMENT],
  models: ['gpt-x'],
  weightsMeasurements: [WEIGHTS],
  requireMeasuredWeights: true,
  minTcb: { bootloader: 3, tee: 0, snp: 20, microcode: 210 },
  minGuestSvn: 4,
  requireDebugDisabled: true,
};
const ends: Endorsements = { issuers: [ISS], oemids: [OEM], operators: [CHIP_HEX] };

describe('issueNonce', () => {
  it('mints a unique, time-stamped nonce', () => {
    const now = 1_700_000_000_000;
    const a = issueNonce({ now });
    const b = issueNonce({ now });
    expect(a.issuedAt).toBe(now);
    expect(a.value).not.toBe(b.value);
    expect(a.value.endsWith(`.${now.toString(36)}`)).toBe(true);
  });
});

describe('buildEAT / verifyEAT round-trip', () => {
  it('round-trips the common claims (EdDSA)', () => {
    const { publicKey, privateKey } = keys();
    const nonce = issueNonce({ now: 1000 }).value;
    const eat = buildEAT({
      issuer: ISS,
      nonce,
      channelId: CHANNEL,
      measured: measured(),
      sevsnp: evidence(),
      measurements: [{ type: 'runtime', value: 'r1' }],
      ueid: 'ueid-1',
      dbgstat: 'disabled-permanently',
      oemid: OEM,
      key: privateKey,
    });
    const claims = verifyEAT(eat, publicKey);
    expect(claims.iss).toBe(ISS);
    expect(claims.eat_nonce).toBe(nonce);
    expect(claims.cnf).toEqual(CNF);
    expect(claims.ueid).toBe('ueid-1');
    expect(claims.dbgstat).toBe('disabled-permanently');
    expect(claims.oemid).toBe(OEM);
    expect(claims.measured?.runtime_measurement).toBe(MEASUREMENT);
    expect(typeof claims.iat).toBe('number');
  });

  it('round-trips over ES256 as well', () => {
    const { publicKey, privateKey } = generateEatKeyPair('ES256');
    const eat = buildEAT({ issuer: ISS, nonce: 'n', channelId: CHANNEL, alg: 'ES256', key: privateKey });
    const claims = verifyEAT(eat, publicKey, { algorithms: ['ES256'] });
    expect(claims.iss).toBe(ISS);
  });

  it('sets the eat+jwt typ header + default alg, and rejects a wrong key', () => {
    const { privateKey } = keys();
    const { publicKey: other } = keys();
    const eat = buildEAT({ issuer: ISS, nonce: 'n', channelId: CHANNEL, key: privateKey });
    const [h] = eat.split('.');
    expect(h).toBeDefined();
    const header: unknown = JSON.parse(Buffer.from(h ?? '', 'base64url').toString());
    expect(header).toMatchObject({ typ: EAT_TYP, alg: DEFAULT_EAT_ALG });
    expect(() => verifyEAT(eat, other)).toThrow(/signature/i);
  });

  it('rejects a tampered claim set (payload mutated after signing)', () => {
    const { publicKey, privateKey } = keys();
    const eat = buildEAT({ issuer: ISS, nonce: 'n', channelId: CHANNEL, oemid: OEM, key: privateKey });
    const [h, p, s] = eat.split('.');
    expect(p).toBeDefined();
    const payload: Record<string, unknown> = { ...(JSON.parse(Buffer.from(p ?? '', 'base64url').toString()) as Record<string, unknown>) };
    payload.oemid = 'oem-EVIL';
    const forged = `${h ?? ''}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${s ?? ''}`;
    expect(() => verifyEAT(forged, publicKey)).toThrow(/signature/i);
  });

  it('refuses to build an unbound EAT (no channel binding)', () => {
    const { privateKey } = keys();
    expect(() => buildEAT({ issuer: ISS, nonce: 'n', channelBinding: {}, key: privateKey })).toThrow(/RA-TLS|channel binding/i);
  });

  it('rejects an EAT whose typ is not eat+jwt unless requireTyp:false', () => {
    const { publicKey, privateKey } = keys();
    const eat = buildEAT({ issuer: ISS, nonce: 'n', channelId: CHANNEL, key: privateKey });
    expect(() => verifyEAT(eat, publicKey, { typ: 'application/other' })).toThrow(/typ/i);
    expect(verifyEAT(eat, publicKey, { requireTyp: false })).toBeDefined();
  });

  it('enforces the issuer when required', () => {
    const { publicKey, privateKey } = keys();
    const eat = buildEAT({ issuer: ISS, nonce: 'n', channelId: CHANNEL, key: privateKey });
    expect(() => verifyEAT(eat, publicKey, { issuer: 'https://someone-else' })).toThrow(/issuer/i);
  });
});

describe('verifyFreshness — anti-replay', () => {
  function claimsAt(iatSec: number, nonce?: string): EatClaims {
    return { iss: ISS, iat: iatSec, ...(nonce !== undefined ? { eat_nonce: nonce } : {}), cnf: CNF };
  }

  it('accepts a fresh nonce + recent iat', () => {
    const now = 1_700_000_000_000;
    expect(verifyFreshness(claimsAt(now / 1000, 'nonce-1'), { expectedNonce: 'nonce-1', maxAgeMs: 60_000, now }).ok).toBe(true);
  });

  it('rejects a replayed EAT with a stale (old) iat', () => {
    const now = 1_700_000_000_000;
    const old = (now - 10 * 60_000) / 1000;
    const r = verifyFreshness(claimsAt(old, 'nonce-1'), { expectedNonce: 'nonce-1', maxAgeMs: DEFAULT_MAX_AGE_MS, now });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/stale|expired/i);
  });

  it('rejects a mismatched nonce', () => {
    const now = 1_700_000_000_000;
    const r = verifyFreshness(claimsAt(now / 1000, 'nonce-OTHER'), { expectedNonce: 'nonce-1', maxAgeMs: 60_000, now });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/does not match/i);
  });

  it('rejects an absent nonce', () => {
    const now = 1_700_000_000_000;
    const r = verifyFreshness(claimsAt(now / 1000), { expectedNonce: 'nonce-1', maxAgeMs: 60_000, now });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/no eat_nonce/i);
  });

  it('rejects a future iat', () => {
    const now = 1_700_000_000_000;
    const future = (now + 10 * 60_000) / 1000;
    const r = verifyFreshness(claimsAt(future, 'nonce-1'), { expectedNonce: 'nonce-1', maxAgeMs: 60_000, now });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/future/i);
  });
});

describe('bindChannel + verifyChannelBinding — RA-TLS', () => {
  const claims: EatClaims = { iss: ISS, iat: 1000, eat_nonce: 'n', cnf: CNF };

  it('bindChannel derives the same cnf a verifier recomputes from the channel id', () => {
    const bound = bindChannel(evidence(), CHANNEL, 'nonce-1');
    expect(bound.cnf).toEqual(CNF);
    expect(bound.nonce).toBe('nonce-1');
    expect(verifyChannelBinding({ ...claims, cnf: bound.cnf }, { channelId: CHANNEL }).ok).toBe(true);
  });

  it('bindChannel refuses an empty nonce', () => {
    expect(() => bindChannel(evidence(), CHANNEL, '')).toThrow(/nonce/i);
  });

  it('accepts a matching cnf (by channelId and by explicit cnf)', () => {
    expect(verifyChannelBinding(claims, { channelId: CHANNEL }).ok).toBe(true);
    expect(verifyChannelBinding(claims, { expectedCnf: { tls_exporter: CNF.tls_exporter } }).ok).toBe(true);
  });

  it('rejects a wrong channel (evidence lifted elsewhere)', () => {
    const r = verifyChannelBinding(claims, { channelId: 'a-DIFFERENT-channel' });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/TLS-exporter/i);
  });

  it('rejects a holder-key thumbprint mismatch', () => {
    const r = verifyChannelBinding({ ...claims, cnf: { ...CNF, jkt: 'thumb-A' } }, { expectedCnf: { jkt: 'thumb-B' } });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/thumbprint/i);
  });

  it('rejects an EAT with no cnf at all', () => {
    const r = verifyChannelBinding({ iss: ISS, iat: 1000, eat_nonce: 'n' }, { channelId: CHANNEL });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/no channel\/key binding/i);
  });
});

describe('appraise — RATS appraisal-policy split (evidence, referenceValues, endorsements)', () => {
  it('affirming when evidence matches endorsements + reference values', () => {
    const r = appraise(claimsWith(), refs, ends);
    expect(r.tier).toBe('affirming');
    expect(r.trustworthy).toBe(true);
    expect(r.reasons).toContain('launch measurement matches a reference value');
    expect(r.reasons).toContain('TCB at or above reference minimum');
  });

  it('affirming on an UPGRADED TCB (>= reference minimum), tolerating version drift', () => {
    const up = claimsWith({ sevsnp: evidence({ reported_tcb: { bootloader: 4, tee: 0, snp: 21, microcode: 211 } }) });
    expect(appraise(up, { minTcb: { bootloader: 3, tee: 0, snp: 20, microcode: 210 } }).tier).toBe('affirming');
  });

  it('contraindicated on a DOWNGRADED TCB version', () => {
    const down = claimsWith({ sevsnp: evidence({ reported_tcb: { bootloader: 1, tee: 0, snp: 10, microcode: 100 } }) });
    const r = appraise(down, { minTcb: { bootloader: 3, tee: 0, snp: 20, microcode: 210 } });
    expect(r.tier).toBe('contraindicated');
    expect(r.reasons.join(' ')).toMatch(/below the reference minimum|downgrade/i);
  });

  it('rejected (fail closed) on an UNKNOWN TCB format', () => {
    const unknown = claimsWith({ sevsnp: evidence({ reported_tcb: 'milan-fw-2025.10' }) });
    const r = appraise(unknown, { minTcb: 100 });
    expect(r.tier).toBe('rejected');
    expect(r.reasons.join(' ')).toMatch(/unknown format|failing closed/i);
  });

  it('contraindicated for a measurement not in reference values (runtime swap)', () => {
    const swapped = claimsWith({ measured: measured({ runtime_measurement: 'f'.repeat(96) }) });
    expect(appraise(swapped, { measurements: [MEASUREMENT] }).tier).toBe('contraindicated');
  });

  it('contraindicated when weights are not hardware-measured but required', () => {
    const soft = claimsWith({ measured: measured({ weights_measured: false }) });
    const r = appraise(soft, { requireMeasuredWeights: true });
    expect(r.tier).toBe('contraindicated');
    expect(r.reasons.join(' ')).toMatch(/hardware-measured/i);
  });

  it('rejected for an unendorsed issuer or operator', () => {
    expect(appraise(claimsWith(), {}, { issuers: ['https://evil'] }).tier).toBe('rejected');
    expect(appraise(claimsWith(), {}, { operators: ['other-chip'] }).tier).toBe('rejected');
  });

  it('rejected (fail closed) on an empty policy', () => {
    const r = appraise(claimsWith(), {}, {});
    expect(r.tier).toBe('rejected');
    expect(r.reasons[0]).toMatch(/empty appraisal policy/i);
  });

  it('contraindicated when the policy demands debug disabled but it is enabled', () => {
    const dbg = claimsWith({ dbgstat: 'enabled', sevsnp: evidence({ debug: true }) });
    expect(appraise(dbg, { requireDebugDisabled: true }).tier).toBe('contraindicated');
  });

  it('warning (not affirming) when the evidence came from a degraded parse', () => {
    const deg = claimsWith({ sevsnp: evidence({ degraded: true }) });
    const r = appraise(deg, refs, ends);
    expect(r.tier).toBe('warning');
    expect(r.trustworthy).toBe(true);
  });
});

describe('parseReportTolerant — version tolerance (RFC drift)', () => {
  const tcb = 0x01_00_00_00_00_14_00_03n; // bootloader=3, tee=0, snp=20(0x14), microcode=1
  function report(version: number): Uint8Array {
    return serializeSevSnpReport({
      version,
      guest_svn: 7,
      policy: 0n,
      measurement: Buffer.from(MEASUREMENT, 'hex'),
      reported_tcb: tcb,
      chip_id: Buffer.from(CHIP_HEX, 'hex'),
    });
  }

  it('fully parses a KNOWN version (v2) — not degraded', () => {
    const r = parseReportTolerant(report(2));
    expect(r.ok).toBe(true);
    expect(r.version).toBe(2);
    expect(r.known).toBe(true);
    expect(r.degraded).toBe(false);
    expect(r.report).toBeDefined();
    expect(r.evidence?.measurement).toBe(MEASUREMENT);
    expect(r.evidence?.guest_svn).toBe(7);
  });

  it('fully parses a KNOWN version (v3)', () => {
    const r = parseReportTolerant(report(3));
    expect(r.version).toBe(3);
    expect(r.known).toBe(true);
    expect(r.degraded).toBe(false);
    expect(KNOWN_REPORT_VERSIONS).toContain(3);
  });

  it('degrades gracefully on an UNKNOWN version (future firmware) instead of throwing', () => {
    const r = parseReportTolerant(report(99));
    expect(r.ok).toBe(true);
    expect(r.version).toBe(99);
    expect(r.known).toBe(false);
    expect(r.degraded).toBe(true);
    expect(r.evidence?.measurement).toBe(MEASUREMENT);
    expect(r.evidence?.degraded).toBe(true);
    expect(r.notes.join(' ')).toMatch(/unknown report version/i);
  });

  it('degrades (does not throw) on a buffer too short for the signature block', () => {
    const short = report(3).slice(0, 0x210); // header present, signature region truncated
    const r = parseReportTolerant(short);
    expect(r.ok).toBe(true);
    expect(r.degraded).toBe(true);
    expect(r.evidence?.measurement).toBe(MEASUREMENT);
  });

  it('returns ok:false (never throws) on a buffer too short to even read the version', () => {
    const r = parseReportTolerant(new Uint8Array(2));
    expect(r.ok).toBe(false);
    expect(r.degraded).toBe(true);
  });

  it('a degraded parse appraises to warning, a full parse to affirming', () => {
    const full = parseReportTolerant(report(3));
    const deg = parseReportTolerant(report(99));
    const policyRefs: ReferenceValues = { measurements: [MEASUREMENT], requireDebugDisabled: true };
    const base: EatClaims = { iss: ISS, iat: 1000 };
    expect(appraise({ ...base, sevsnp: full.evidence, measured: full.report ? measuredFromReport(full.report) : undefined }, policyRefs).tier).toBe('affirming');
    expect(appraise({ ...base, sevsnp: deg.evidence }, policyRefs).tier).toBe('warning');
  });
});

describe('evidenceFromReport / measuredFromReport — reuse PCA ParsedSevSnpReport', () => {
  it('projects a parsed report into EAT evidence + a MeasuredIdentity', () => {
    const bytes = serializeSevSnpReport({
      version: 3,
      guest_svn: 4,
      policy: 0n,
      measurement: Buffer.from(MEASUREMENT, 'hex'),
      reported_tcb: 0x14_00_03n,
      chip_id: Buffer.from(CHIP_HEX, 'hex'),
    });
    const parsed = parseReportTolerant(bytes);
    const report = parsed.report;
    expect(report).toBeDefined();
    if (!report) return;
    const ev = evidenceFromReport(report);
    expect(ev.measurement).toBe(MEASUREMENT);
    expect(ev.chip_id).toBe(CHIP_HEX);
    expect(ev.debug).toBe(false);
    expect(ev).not.toHaveProperty('weights_measurement');
    const id = measuredFromReport(report);
    expect(id.runtime_measurement).toBe(MEASUREMENT);
    expect(id.operator).toBe(CHIP_HEX);
    // SEV-SNP has no weights field: never a measured-weights claim from a report
    expect(id.weights_measured).toBe(false);
    expect(id.weights_digest).toBe('');
  });
});

describe('verifyFreshAttestedEAT — end to end', () => {
  const now = 1_700_000_000_000;

  function freshEat(privateKey: KeyObject, nonce: string, over: { channelId?: string; sevsnp?: EatSevSnpEvidence; measured?: MeasuredIdentity; iatNow?: number } = {}): string {
    return buildEAT({
      issuer: ISS,
      nonce,
      channelId: over.channelId ?? CHANNEL,
      measured: over.measured ?? measured(),
      sevsnp: over.sevsnp ?? evidence(),
      oemid: OEM,
      dbgstat: 'disabled',
      key: privateKey,
      now: over.iatNow ?? now,
    });
  }

  const policy = { endorsements: ends, referenceValues: refs };

  it('accepts a good, fresh, channel-bound, policy-matching EAT', async () => {
    const { publicKey, privateKey } = keys();
    const nonce = issueNonce({ now }).value;
    const v = await verifyFreshAttestedEAT(freshEat(privateKey, nonce), { nonce, channelId: CHANNEL, policy, verifyKey: publicKey, now, issuer: ISS });
    expect(v.ok).toBe(true);
    expect(v.tier).toBe('affirming');
    expect(v.claims?.iss).toBe(ISS);
  });

  it('rejects a replayed (stale iat) EAT', async () => {
    const { publicKey, privateKey } = keys();
    const nonce = issueNonce({ now }).value;
    const v = await verifyFreshAttestedEAT(freshEat(privateKey, nonce, { iatNow: now - 10 * 60_000 }), { nonce, channelId: CHANNEL, policy, verifyKey: publicKey, now });
    expect(v.ok).toBe(false);
    expect(v.reasons.join(' ')).toMatch(/stale|expired/i);
  });

  it('rejects a replayed EAT presented with the wrong nonce', async () => {
    const { publicKey, privateKey } = keys();
    const v = await verifyFreshAttestedEAT(freshEat(privateKey, issueNonce({ now }).value), { nonce: 'a-different-nonce', channelId: CHANNEL, policy, verifyKey: publicKey, now });
    expect(v.ok).toBe(false);
    expect(v.reasons.join(' ')).toMatch(/does not match/i);
  });

  it('rejects an EAT lifted to a different channel', async () => {
    const { publicKey, privateKey } = keys();
    const nonce = issueNonce({ now }).value;
    const v = await verifyFreshAttestedEAT(freshEat(privateKey, nonce), { nonce, channelId: 'OTHER-channel', policy, verifyKey: publicKey, now });
    expect(v.ok).toBe(false);
    expect(v.reasons.join(' ')).toMatch(/channel/i);
  });

  it('rejects an EAT whose evidence fails appraisal (downgraded TCB)', async () => {
    const { publicKey, privateKey } = keys();
    const nonce = issueNonce({ now }).value;
    const eat = freshEat(privateKey, nonce, { sevsnp: evidence({ reported_tcb: { bootloader: 1, tee: 0, snp: 1, microcode: 1 } }) });
    const v = await verifyFreshAttestedEAT(eat, { nonce, channelId: CHANNEL, policy, verifyKey: publicKey, now });
    expect(v.ok).toBe(false);
    expect(v.tier).toBe('contraindicated');
    expect(v.reasons.join(' ')).toMatch(/below the reference minimum|downgrade/i);
  });

  it('rejects a tampered/wrong-key EAT (signature)', async () => {
    const { privateKey } = keys();
    const { publicKey: other } = keys();
    const nonce = issueNonce({ now }).value;
    const v = await verifyFreshAttestedEAT(freshEat(privateKey, nonce), { nonce, channelId: CHANNEL, policy, verifyKey: other, now });
    expect(v.ok).toBe(false);
    expect(v.reasons.join(' ')).toMatch(/signature|invalid/i);
  });
});
