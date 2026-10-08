import { describe, it, expect } from 'vitest';
import {
  createHash,
  generateKeyPairSync,
  sign as nodeSign,
  type KeyObject,
} from 'node:crypto';
import { serializeSevSnpReport, type MeasuredIdentity } from '@atlasauth/pca';
import {
  EAT_TYP,
  DEFAULT_EAT_ALG,
  DEFAULT_MAX_AGE_MS,
  KNOWN_REPORT_VERSIONS,
  AMD_MILAN_ARK_SPKI_SHA384,
  KNOWN_AMD_ARK_SPKI_SHA384,
  AMD_SEV_SNP_HARDWARE_ROOT_LABEL,
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
  verifySevSnpSignature,
  verifyAmdCertChain,
  verifyAmdAttestation,
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
    weights_measurement: WEIGHTS,
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
    expect(claims.sevsnp?.weights_measurement).toBe(WEIGHTS);
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
      weights_measurement: Buffer.from(WEIGHTS, 'hex'),
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
      weights_measurement: Buffer.from(WEIGHTS, 'hex'),
    });
    const parsed = parseReportTolerant(bytes);
    const report = parsed.report;
    expect(report).toBeDefined();
    if (!report) return;
    const ev = evidenceFromReport(report);
    expect(ev.measurement).toBe(MEASUREMENT);
    expect(ev.chip_id).toBe(CHIP_HEX);
    expect(ev.debug).toBe(false);
    expect(ev.weights_measurement).toBe(WEIGHTS);
    const id = measuredFromReport(report);
    expect(id.runtime_measurement).toBe(MEASUREMENT);
    expect(id.operator).toBe(CHIP_HEX);
    expect(id.weights_measured).toBe(true);
    expect(id.weights_digest).toBe(WEIGHTS);
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

  it('accepts a good, fresh, channel-bound, policy-matching EAT', () => {
    const { publicKey, privateKey } = keys();
    const nonce = issueNonce({ now }).value;
    const v = verifyFreshAttestedEAT(freshEat(privateKey, nonce), { nonce, channelId: CHANNEL, policy, verifyKey: publicKey, now, issuer: ISS });
    expect(v.ok).toBe(true);
    expect(v.tier).toBe('affirming');
    expect(v.claims?.iss).toBe(ISS);
  });

  it('rejects a replayed (stale iat) EAT', () => {
    const { publicKey, privateKey } = keys();
    const nonce = issueNonce({ now }).value;
    const v = verifyFreshAttestedEAT(freshEat(privateKey, nonce, { iatNow: now - 10 * 60_000 }), { nonce, channelId: CHANNEL, policy, verifyKey: publicKey, now });
    expect(v.ok).toBe(false);
    expect(v.reasons.join(' ')).toMatch(/stale|expired/i);
  });

  it('rejects a replayed EAT presented with the wrong nonce', () => {
    const { publicKey, privateKey } = keys();
    const v = verifyFreshAttestedEAT(freshEat(privateKey, issueNonce({ now }).value), { nonce: 'a-different-nonce', channelId: CHANNEL, policy, verifyKey: publicKey, now });
    expect(v.ok).toBe(false);
    expect(v.reasons.join(' ')).toMatch(/does not match/i);
  });

  it('rejects an EAT lifted to a different channel', () => {
    const { publicKey, privateKey } = keys();
    const nonce = issueNonce({ now }).value;
    const v = verifyFreshAttestedEAT(freshEat(privateKey, nonce), { nonce, channelId: 'OTHER-channel', policy, verifyKey: publicKey, now });
    expect(v.ok).toBe(false);
    expect(v.reasons.join(' ')).toMatch(/channel/i);
  });

  it('rejects an EAT whose evidence fails appraisal (downgraded TCB)', () => {
    const { publicKey, privateKey } = keys();
    const nonce = issueNonce({ now }).value;
    const eat = freshEat(privateKey, nonce, { sevsnp: evidence({ reported_tcb: { bootloader: 1, tee: 0, snp: 1, microcode: 1 } }) });
    const v = verifyFreshAttestedEAT(eat, { nonce, channelId: CHANNEL, policy, verifyKey: publicKey, now });
    expect(v.ok).toBe(false);
    expect(v.tier).toBe('contraindicated');
    expect(v.reasons.join(' ')).toMatch(/below the reference minimum|downgrade/i);
  });

  it('rejects a tampered/wrong-key EAT (signature)', () => {
    const { privateKey } = keys();
    const { publicKey: other } = keys();
    const nonce = issueNonce({ now }).value;
    const v = verifyFreshAttestedEAT(freshEat(privateKey, nonce), { nonce, channelId: CHANNEL, policy, verifyKey: other, now });
    expect(v.ok).toBe(false);
    expect(v.reasons.join(' ')).toMatch(/signature|invalid/i);
  });
});

// ════════════════════════════════════════════════════════════════════════════════════════════════
// AMD SEV-SNP hardware root of trust — REAL signature + chain verification.
//
// Real silicon is not available in CI, so we synthesize a SELF-CONSISTENT chain of trust entirely with
// node:crypto: a P-384 "ARK" (self-signed), an "ASK" signed by the ARK, a "VCEK" signed by the ASK, and a
// synthetic ATTESTATION_REPORT whose signed region is signed by the VCEK key in AMD's little-endian r‖s
// layout. The certs are minimal but real X.509 DER so node's OpenSSL-backed X509Certificate.verify runs the
// genuine signature check — the same code path a real (RSA-PSS ASK/ARK + EC-P384 VCEK) chain takes.
// ════════════════════════════════════════════════════════════════════════════════════════════════

// ── Minimal DER encoder (test-only; just enough for a verifiable X.509 v3 ECDSA-P384 certificate) ──
function derLen(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
}
function derSeq(...items: Buffer[]): Buffer {
  return tlv(0x30, Buffer.concat(items));
}
function derSet(content: Buffer): Buffer {
  return tlv(0x31, content);
}
function derOid(dotted: string): Buffer {
  const arcs = dotted.split('.').map((x) => parseInt(x, 10));
  const body: number[] = [arcs[0]! * 40 + arcs[1]!];
  for (const arc of arcs.slice(2)) {
    const stack = [arc & 0x7f];
    let v = Math.floor(arc / 128);
    while (v > 0) {
      stack.unshift((v & 0x7f) | 0x80);
      v = Math.floor(v / 128);
    }
    body.push(...stack);
  }
  return tlv(0x06, Buffer.from(body));
}
function derInt(n: number): Buffer {
  const bytes: number[] = [];
  let v = n;
  if (v === 0) bytes.push(0);
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  if ((bytes[0]! & 0x80) !== 0) bytes.unshift(0x00); // keep it a positive INTEGER
  return tlv(0x02, Buffer.from(bytes));
}
function derUtf8(s: string): Buffer {
  return tlv(0x0c, Buffer.from(s, 'utf8'));
}
function derUtcTime(d: Date): Buffer {
  const p = (x: number): string => x.toString().padStart(2, '0');
  const s = `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x17, Buffer.from(s, 'ascii'));
}
function derBitString(content: Buffer): Buffer {
  return tlv(0x03, Buffer.concat([Buffer.from([0x00]), content])); // 0 unused bits
}
function derExplicit(tagNum: number, content: Buffer): Buffer {
  return tlv(0xa0 | tagNum, content); // context-specific [tagNum], constructed
}
function dnName(cn: string): Buffer {
  return derSeq(derSet(derSeq(derOid('2.5.4.3'), derUtf8(cn))));
}

const ECDSA_WITH_SHA384 = derSeq(derOid('1.2.840.10045.4.3.3'));

function p384(): { publicKey: KeyObject; privateKey: KeyObject } {
  return generateKeyPairSync('ec', { namedCurve: 'P-384' });
}
function spkiDer(pub: KeyObject): Buffer {
  return Buffer.from(pub.export({ type: 'spki', format: 'der' }));
}

/** Build a minimal but genuinely-verifiable X.509 v3 ECDSA-P384 certificate (DER). */
function makeCert(opts: {
  subjectCn: string;
  issuerCn: string;
  subjectPub: KeyObject;
  issuerPriv: KeyObject;
  serial?: number;
  notBefore?: Date;
  notAfter?: Date;
}): Buffer {
  const nowMs = Date.now();
  // Wide default window (years 2000–2049 are UTCTime-representable) so it spans both the real present and
  // the fixed `now = 1_700_000_000_000` (2023) the wiring tests pin.
  const nb = opts.notBefore ?? new Date(nowMs - 10 * 365 * 24 * 3600 * 1000);
  const na = opts.notAfter ?? new Date(nowMs + 10 * 365 * 24 * 3600 * 1000);
  const tbs = derSeq(
    derExplicit(0, derInt(2)), // version v3 (value 2)
    derInt(opts.serial ?? 1),
    ECDSA_WITH_SHA384,
    dnName(opts.issuerCn),
    derSeq(derUtcTime(nb), derUtcTime(na)),
    dnName(opts.subjectCn),
    spkiDer(opts.subjectPub),
  );
  const sig = nodeSign('sha384', tbs, { key: opts.issuerPriv, dsaEncoding: 'der' });
  return derSeq(tbs, ECDSA_WITH_SHA384, derBitString(sig));
}

// AMD SEV-SNP report offsets we touch in-test.
const OFF_MEASUREMENT = 0x090;
const OFF_SIG_R = 0x2a0;
const OFF_SIG_S = 0x2e8;
const SIGNED_END = 0x2a0;

/** Convert a 48-byte big-endian scalar to AMD's 72-byte little-endian field. */
function be48ToLe72(be48: Buffer): Buffer {
  const le = Buffer.alloc(72);
  for (let i = 0; i < 48; i++) le[i] = be48[47 - i]!;
  return le;
}

/** Sign the report's signed region [0,0x2A0) with `signerPriv` and splice the LE r‖s block into it. */
function signReport(report: Buffer, signerPriv: KeyObject): Buffer {
  const out = Buffer.from(report);
  const raw = nodeSign('sha384', out.subarray(0, SIGNED_END), { key: signerPriv, dsaEncoding: 'ieee-p1363' });
  const r = be48ToLe72(Buffer.from(raw.subarray(0, 48)));
  const s = be48ToLe72(Buffer.from(raw.subarray(48, 96)));
  out.set(r, OFF_SIG_R);
  out.set(s, OFF_SIG_S);
  return out;
}

interface TestChain {
  ark: Buffer;
  ask: Buffer;
  vcek: Buffer;
  arkFp: string;
  report: Buffer;
  vcekKeys: { publicKey: KeyObject; privateKey: KeyObject };
}

function buildTestChain(over: { vcekSignedBy?: KeyObject; askSignedBy?: KeyObject; vcekNotAfter?: Date } = {}): TestChain {
  const arkKeys = p384();
  const askKeys = p384();
  const vcekKeys = p384();
  const ark = makeCert({ subjectCn: 'AMD ARK test', issuerCn: 'AMD ARK test', subjectPub: arkKeys.publicKey, issuerPriv: arkKeys.privateKey });
  const ask = makeCert({ subjectCn: 'AMD ASK test', issuerCn: 'AMD ARK test', subjectPub: askKeys.publicKey, issuerPriv: over.askSignedBy ?? arkKeys.privateKey, serial: 2 });
  const vcek = makeCert({
    subjectCn: 'AMD VCEK test',
    issuerCn: 'AMD ASK test',
    subjectPub: vcekKeys.publicKey,
    issuerPriv: over.vcekSignedBy ?? askKeys.privateKey,
    serial: 3,
    ...(over.vcekNotAfter !== undefined ? { notAfter: over.vcekNotAfter } : {}),
  });
  const arkFp = createHash('sha384').update(spkiDer(arkKeys.publicKey)).digest('hex');
  const body = Buffer.from(
    serializeSevSnpReport({
      version: 3,
      guest_svn: 5,
      policy: 0n,
      measurement: Buffer.from(MEASUREMENT, 'hex'),
      reported_tcb: 0xd2_00_00_00_00_14_00_03n, // bl=3, tee=0, snp=20, ucode=210
      chip_id: Buffer.from(CHIP_HEX, 'hex'),
      weights_measurement: Buffer.from(WEIGHTS, 'hex'),
    }),
  );
  const report = signReport(body, vcekKeys.privateKey);
  return { ark, ask, vcek, arkFp, report, vcekKeys };
}

describe('verifySevSnpSignature / verifyAmdCertChain / verifyAmdAttestation — AMD silicon root', () => {
  it('ships the REAL AMD Milan ARK fingerprint as a constant', () => {
    expect(KNOWN_AMD_ARK_SPKI_SHA384.Milan).toBe(AMD_MILAN_ARK_SPKI_SHA384);
    expect(AMD_MILAN_ARK_SPKI_SHA384).toMatch(/^[0-9a-f]{96}$/); // SHA-384 hex
  });

  it('verifies a valid report signature and a valid VCEK→ASK→ARK chain', () => {
    const c = buildTestChain();
    expect(verifySevSnpSignature(c.report, c.vcek)).toEqual({ ok: true });
    const chain = verifyAmdCertChain(c.vcek, c.ask, c.ark, { rootFingerprint: c.arkFp });
    expect(chain.ok).toBe(true);
    expect(chain.arkFingerprint).toBe(c.arkFp);
    expect(chain.vcek).toBeDefined();
    const att = verifyAmdAttestation(c.report, { vcek: c.vcek, ask: c.ask, ark: c.ark, rootFingerprint: c.arkFp, expectedMeasurement: MEASUREMENT, requireDebugDisabled: true });
    expect(att.ok).toBe(true);
    expect(att.hardwareRoot).toBe(AMD_SEV_SNP_HARDWARE_ROOT_LABEL);
    expect(att.measured?.runtime_measurement).toBe(MEASUREMENT);
    expect(att.evidence?.measurement).toBe(MEASUREMENT);
  });

  it('accepts PEM-encoded certificates too', () => {
    const c = buildTestChain();
    const pem = (der: Buffer): string => `-----BEGIN CERTIFICATE-----\n${der.toString('base64').replace(/(.{64})/g, '$1\n')}\n-----END CERTIFICATE-----\n`;
    const att = verifyAmdAttestation(c.report, { vcek: pem(c.vcek), ask: pem(c.ask), ark: pem(c.ark), rootFingerprint: c.arkFp });
    expect(att.ok).toBe(true);
  });

  it('fails a tampered report body (signature no longer matches)', () => {
    const c = buildTestChain();
    const tampered = Buffer.from(c.report);
    tampered[OFF_MEASUREMENT] = (tampered[OFF_MEASUREMENT]! ^ 0xff) & 0xff; // flip a byte inside the signed region
    const sig = verifySevSnpSignature(tampered, c.vcek);
    expect(sig.ok).toBe(false);
    expect(sig.reason).toMatch(/does not verify/i);
    expect(verifyAmdAttestation(tampered, { vcek: c.vcek, ask: c.ask, ark: c.ark, rootFingerprint: c.arkFp }).ok).toBe(false);
  });

  it('fails a report signed by a key that is not the VCEK', () => {
    const c = buildTestChain();
    const wrong = p384();
    const body = Buffer.from(
      serializeSevSnpReport({ version: 3, policy: 0n, measurement: Buffer.from(MEASUREMENT, 'hex'), chip_id: Buffer.from(CHIP_HEX, 'hex') }),
    );
    const report = signReport(body, wrong.privateKey); // signed by a stranger, not the cert's VCEK
    const sig = verifySevSnpSignature(report, c.vcek);
    expect(sig.ok).toBe(false);
    expect(sig.reason).toMatch(/does not verify/i);
  });

  it('fails when the VCEK is signed by the wrong key', () => {
    const stranger = p384();
    const c = buildTestChain({ vcekSignedBy: stranger.privateKey });
    const chain = verifyAmdCertChain(c.vcek, c.ask, c.ark, { rootFingerprint: c.arkFp });
    expect(chain.ok).toBe(false);
    expect(chain.reason).toMatch(/VCEK is not signed by ASK/i);
  });

  it('fails a broken chain link (ASK not signed by ARK)', () => {
    const stranger = p384();
    const c = buildTestChain({ askSignedBy: stranger.privateKey });
    const chain = verifyAmdCertChain(c.vcek, c.ask, c.ark, { rootFingerprint: c.arkFp });
    expect(chain.ok).toBe(false);
    expect(chain.reason).toMatch(/ASK is not signed by ARK/i);
  });

  it('fails when the ARK does not match the pinned fingerprint', () => {
    const c = buildTestChain();
    const chain = verifyAmdCertChain(c.vcek, c.ask, c.ark, { rootFingerprint: '00'.repeat(48) });
    expect(chain.ok).toBe(false);
    expect(chain.reason).toMatch(/pinned AMD root|untrusted root/i);
    // and with the default (real Milan) pin, our synthetic ARK is likewise rejected:
    expect(verifyAmdCertChain(c.vcek, c.ask, c.ark).ok).toBe(false);
  });

  it('fails an expired certificate', () => {
    const c = buildTestChain({ vcekNotAfter: new Date(Date.now() - 24 * 3600 * 1000) });
    const chain = verifyAmdCertChain(c.vcek, c.ask, c.ark, { rootFingerprint: c.arkFp });
    expect(chain.ok).toBe(false);
    expect(chain.reason).toMatch(/validity period/i);
  });

  it('fails closed on a report that is too short to parse', () => {
    const c = buildTestChain();
    const r = verifySevSnpSignature(new Uint8Array(16), c.vcek);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/parse failed/i);
  });
});

describe('verifyFreshAttestedEAT — AMD hardware root wiring (higher tier)', () => {
  const now = 1_700_000_000_000;
  const policy = { endorsements: ends, referenceValues: refs };

  function eat(privateKey: KeyObject, nonce: string): string {
    return buildEAT({ issuer: ISS, nonce, channelId: CHANNEL, measured: measured(), sevsnp: evidence(), oemid: OEM, dbgstat: 'disabled', key: privateKey, now });
  }

  it('upgrades a verified AMD attestation to the affirming-hw-rooted tier (above plain affirming)', () => {
    const { publicKey, privateKey } = generateEatKeyPair();
    const nonce = issueNonce({ now }).value;
    const c = buildTestChain();

    // Without the AMD block: capped at affirming.
    const soft = verifyFreshAttestedEAT(eat(privateKey, nonce), { nonce, channelId: CHANNEL, policy, verifyKey: publicKey, now, issuer: ISS });
    expect(soft.ok).toBe(true);
    expect(soft.tier).toBe('affirming');

    // With a verified AMD block: strictly higher tier.
    const hard = verifyFreshAttestedEAT(eat(privateKey, nonce), {
      nonce, channelId: CHANNEL, policy, verifyKey: publicKey, now, issuer: ISS,
      amd: { rawReport: c.report, vcek: c.vcek, ask: c.ask, ark: c.ark, rootFingerprint: c.arkFp, requireDebugDisabled: true },
    });
    expect(hard.ok).toBe(true);
    expect(hard.tier).toBe('affirming-hw-rooted');
    expect(hard.reasons.join(' ')).toMatch(/hardware root verified/i);
    expect(hard.reasons.join(' ')).toMatch(/not post-quantum/i); // the honest classical-root label is surfaced
  });

  it('fails closed (contraindicated) when the AMD signature does not verify', () => {
    const { publicKey, privateKey } = generateEatKeyPair();
    const nonce = issueNonce({ now }).value;
    const c = buildTestChain();
    const tampered = Buffer.from(c.report);
    tampered[OFF_MEASUREMENT] = (tampered[OFF_MEASUREMENT]! ^ 0xff) & 0xff;
    const v = verifyFreshAttestedEAT(eat(privateKey, nonce), {
      nonce, channelId: CHANNEL, policy, verifyKey: publicKey, now, issuer: ISS,
      amd: { rawReport: tampered, vcek: c.vcek, ask: c.ask, ark: c.ark, rootFingerprint: c.arkFp },
    });
    expect(v.ok).toBe(false);
    expect(v.tier).toBe('contraindicated');
    expect(v.reasons.join(' ')).toMatch(/AMD hardware root verification failed/i);
  });

  it("fails closed when the report measurement disagrees with the EAT's claimed measurement", () => {
    const { publicKey, privateKey } = generateEatKeyPair();
    const nonce = issueNonce({ now }).value;
    const c = buildTestChain();
    // EAT claims a different launch measurement than the silicon report carries.
    const claimDifferent = buildEAT({ issuer: ISS, nonce, channelId: CHANNEL, measured: measured({ runtime_measurement: 'f'.repeat(96) }), sevsnp: evidence({ measurement: 'f'.repeat(96) }), oemid: OEM, dbgstat: 'disabled', key: privateKey, now });
    const v = verifyFreshAttestedEAT(claimDifferent, {
      nonce, channelId: CHANNEL, policy, verifyKey: publicKey, now, issuer: ISS,
      amd: { rawReport: c.report, vcek: c.vcek, ask: c.ask, ark: c.ark, rootFingerprint: c.arkFp },
    });
    expect(v.ok).toBe(false);
    expect(v.reasons.join(' ')).toMatch(/measurement does not match/i);
  });
});
