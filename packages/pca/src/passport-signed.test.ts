import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { HardwareAttestationVerifier, MeasuredIdentity } from './attestation';
import { setAssuranceLabel } from './assurance';
import { b64u, canonicalBytesStrict, utf8 } from './hash';
import { publicKeyOf, sign } from './keys';
import { DEFAULT_PASSPORT_EVIDENCE_AGE_MS, PASSPORT_SIG_DOMAIN, issuePassport, passportAssurance, passportEvidenceBinding, signPassport, verifyPassport, type SignedPassport, type VerifyPassportOptions } from './passport';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';
import { buildPassportVectors, PASSPORT_VECTOR_NOW } from './test-support/passport-vectors';
import { verifierFromConfig } from './test-support/attestation-wire';

const NOW = 1_800_000_000_000;
const ISS_SECRET = new Uint8Array(32).fill(1);
const ISS = b64u(publicKeyOf(ISS_SECRET));
const SUB = b64u(publicKeyOf(new Uint8Array(32).fill(2)));
const ident = { model_id: 'm1', weights_digest: 'w1', system_prompt_digest: 'sp', tool_manifest_digest: 'tm', runtime_measurement: '42', operator: 'acme', hardware_rooted: false, weights_measured: false, issued_at: NOW - 1 };
const opts = (over: Partial<VerifyPassportOptions> = {}): VerifyPassportOptions => ({ trustedIssuers: [ISS], now: NOW, revocation: () => false, ...over });
const soft = () => signPassport(issuePassport(ident), { issuerSecret: ISS_SECRET, subject: SUB, exp: NOW + 60_000 });
const deny = async (sp: unknown, reason: string, o = opts()) => expect(await verifyPassport(sp, o)).toMatchObject({ ok: false, reason });

const measured: MeasuredIdentity = { model_id: 'm1', weights_digest: 'w1', weights_measured: true, runtime_measurement: '42', operator: 'acme', system_prompt_digest: 'sp', tool_manifest_digest: 'tm' };
const hwVerifier = (over: { ok?: boolean; bound?: boolean; measured?: Partial<MeasuredIdentity> } = {}, seen: unknown[] = []): HardwareAttestationVerifier => ({
  verify: (input) => {
    seen.push(input.expected);
    return { ok: over.ok ?? true, bound: over.bound ?? true, measured: { ...measured, ...over.measured }, reason: 'hw says no' };
  },
});
/** Sign an arbitrary body the way an issuer would, bypassing signPassport's checks. */
const rawSign = (over: Record<string, unknown>) => {
  const body = { typ: 'atlas-pca/passport', ver: 1, passport: issuePassport(ident), iss: ISS, sub: SUB, iat: NOW - 1, nbf: NOW - 1, exp: NOW + 60_000, ...over };
  const d = canonicalBytesStrict(body);
  const m = new Uint8Array([...utf8(PASSPORT_SIG_DOMAIN), ...d]);
  return { ...body, sig: b64u(sign(ISS_SECRET, m)) };
};
const hwPassport = (id = ident) => {
  const p = issuePassport({ ...id, hardware_rooted: true, weights_measured: true });
  return signPassport(p, { issuerSecret: ISS_SECRET, subject: SUB, exp: NOW + 60_000, evidence: { document: { nonce: 'nonce-1' } as never } });
};

describe('signed passport: accept', () => {
  it('a software passport verifies and reports no hardware', async () => {
    const r = await verifyPassport(soft(), opts());
    expect(r).toMatchObject({ ok: true, hardware_verified: false, iss: ISS, sub: SUB, exp: NOW + 60_000 });
  });
  it('signing is deterministic and domain-separated', () => {
    expect(JSON.stringify(soft())).toBe(JSON.stringify(soft()));
    expect(PASSPORT_SIG_DOMAIN).toBe('atlas-pca/passport-sig/v1\0');
  });
  it('signPassport refuses hardware_rooted without evidence, a bad window and an inconsistent id', () => {
    const hw = issuePassport({ ...ident, hardware_rooted: true });
    expect(() => signPassport(hw, { issuerSecret: ISS_SECRET, subject: SUB, exp: NOW + 1 })).toThrow(/evidence/);
    expect(() => signPassport(issuePassport(ident), { issuerSecret: ISS_SECRET, subject: SUB, exp: NOW - 5 })).toThrow(/exp > nbf/);
    expect(() => signPassport({ ...issuePassport(ident), id: 'x' }, { issuerSecret: ISS_SECRET, subject: SUB, exp: NOW + 1 })).toThrow(/fingerprint/);
    expect(() => signPassport(issuePassport(ident), { issuerSecret: ISS_SECRET, subject: SUB, exp: NOW + 1, suite: { alg: 'nope' as never } })).toThrow(/^signPassport: unknown signature alg 'nope'$/);
    const id = issuePassport(ident);
    expect(() => signPassport(id, { issuerSecret: ISS_SECRET, subject: SUB, iat: 1.5, exp: NOW + 1 })).toThrow(/safe integers/);
    expect(() => signPassport(id, { issuerSecret: ISS_SECRET, subject: SUB, exp: Number.NaN })).toThrow(/safe integers/);
    expect(() => signPassport(id, { issuerSecret: ISS_SECRET, subject: SUB, nbf: NOW, exp: NOW })).toThrow(/safe integers/);
    expect(() => signPassport(id, { issuerSecret: ISS_SECRET, subject: SUB, nbf: NOW, exp: NOW + 1 })).not.toThrow();
  });
});

describe('signed passport: reason codes', () => {
  it('malformed: exact verdicts for every shape and field check', async () => {
    const exact = async (x: unknown, detail?: string) => expect(await verifyPassport(x, opts())).toEqual({ ok: false, reason: 'malformed', ...(detail ? { detail } : {}) });
    for (const x of [null, undefined, 'x', 5, [], {}, { ...soft(), typ: 'other' }, { ...soft(), passport: null }, { ...soft(), passport: undefined }, { ...soft(), passport: 'str' }]) await exact(x);
    const s = soft();
    for (const k of ['iss', 'sub', 'sig']) await exact({ ...s, [k]: '' });
    for (const k of ['id', 'model_id', 'operator']) await exact({ ...s, passport: { ...s.passport, [k]: '' } });
    await exact({ ...s, passport: { ...s.passport, hardware_rooted: 'yes' } });
    for (const k of ['iat', 'nbf', 'exp']) await exact({ ...s, [k]: 1.5 }, 'times');
    await exact({ ...s, exp: s.nbf }, 'times');
    await exact({ ...s, exp: s.nbf - 1 }, 'times');
    expect(await verifyPassport(s, opts({ now: 1.5 }))).toEqual({ ok: false, reason: 'malformed', detail: 'times' });
  });
  it('the outer guard turns an unexpected throw into malformed with its message (or "error")', async () => {
    const s = soft();
    const big = await verifyPassport({ ...s, extra: 2 ** 60 }, opts());
    expect(big).toMatchObject({ ok: false, reason: 'malformed' });
    expect(typeof (big as { detail?: unknown }).detail).toBe('string');
    expect((big as { detail?: string }).detail!.length).toBeGreaterThan(0);
    const thrower = { ...s };
    Object.defineProperty(thrower, 'iss', { get() { throw 'not an Error'; } });
    expect(await verifyPassport(thrower, opts())).toEqual({ ok: false, reason: 'malformed', detail: 'error' });
  });
  it('unsupported_version / unsupported_suite', async () => {
    await deny({ ...soft(), ver: 2 }, 'unsupported_version');
    await deny({ ...soft(), ver: undefined }, 'unsupported_version');
    await deny({ ...soft(), alg: 'rot13' }, 'unsupported_suite');
  });
  it('unknown_issuer (also when the trust list is empty or the key differs)', async () => {
    await deny(soft(), 'unknown_issuer', opts({ trustedIssuers: [] }));
    await deny(soft(), 'unknown_issuer', opts({ trustedIssuers: [SUB] }));
  });
  it('bad_signature for a re-signed-by-someone-else passport', async () => {
    const forged: SignedPassport = { ...soft(), iss: ISS, sig: signPassport(issuePassport(ident), { issuerSecret: new Uint8Array(32).fill(9), subject: SUB, exp: NOW + 60_000 }).sig };
    await deny(forged, 'bad_signature');
  });
  it('every signed field is covered: tampering any of them fails', async () => {
    const s = soft();
    const top: Record<string, unknown> = { iss: SUB, sub: ISS, iat: s.iat + 1, nbf: s.nbf + 1, exp: s.exp + 1, evidence: { document: { nonce: 'n' } } };
    for (const [k, val] of Object.entries(top)) {
      const r = await verifyPassport({ ...s, [k]: val }, opts({ trustedIssuers: [ISS, SUB] }));
      expect(r.ok, k).toBe(false);
      expect(r.ok ? '' : r.reason, k).toBe('bad_signature');
    }
    for (const [k, val] of Object.entries({ model_id: 'x', weights_digest: 'x', system_prompt_digest: 'x', tool_manifest_digest: 'x', runtime_measurement: '43', operator: 'x', hardware_rooted: true, weights_measured: true, issued_at: 5 })) {
      const r = await verifyPassport({ ...s, passport: { ...s.passport, [k]: val } }, opts());
      expect(r.ok, k).toBe(false);
    }
    // a signed field added after signing
    expect((await verifyPassport({ ...s, passport: { ...s.passport, extra: 1 } }, opts())).ok).toBe(false);
    // the sig itself
    await deny({ ...s, sig: s.sig.slice(0, -2) + (s.sig.endsWith('AA') ? 'BB' : 'AA') }, 'bad_signature');
    await deny({ ...s, sig: undefined }, 'malformed');
  });
  it('id_mismatch and hardware_evidence_missing: reachable only for an issuer that signed a bad body (hand-signed here)', async () => {
    const p = issuePassport(ident);
    await deny(rawSign({ passport: { ...p, id: 'not-the-fingerprint' } }), 'id_mismatch');
    const hwp = issuePassport({ ...ident, hardware_rooted: true });
    await deny(rawSign({ passport: hwp }), 'hardware_evidence_missing', opts({ attestationVerifier: hwVerifier() }));
    await deny(rawSign({ passport: hwp, evidence: { document: {} } }), 'hardware_evidence_missing', opts({ attestationVerifier: hwVerifier() }));
    expect((await verifyPassport(rawSign({ passport: p }), opts())).ok).toBe(true); // the helper itself is sound
  });
  it('not_yet_valid / expired with exact boundaries and skew', async () => {
    const early = signPassport(issuePassport(ident), { issuerSecret: ISS_SECRET, subject: SUB, nbf: NOW + 1000, exp: NOW + 9000 });
    await deny(early, 'not_yet_valid');
    expect((await verifyPassport(early, opts({ now: NOW + 1000 }))).ok).toBe(true);
    expect((await verifyPassport(early, opts({ clockSkewMs: 1000 }))).ok).toBe(true);
    await deny(early, 'not_yet_valid', opts({ clockSkewMs: 999 }));
    const s = soft();
    expect((await verifyPassport(s, opts({ now: NOW + 59_999 }))).ok).toBe(true);
    await deny(s, 'expired', opts({ now: NOW + 60_000 }));
    expect((await verifyPassport(s, opts({ now: NOW + 60_000, clockSkewMs: 1 }))).ok).toBe(true);
    // skew is capped at 60 s
    await deny(s, 'expired', opts({ now: NOW + 60_000 + 60_000, clockSkewMs: 10 ** 9 }));
    expect((await verifyPassport(s, opts({ now: NOW + 60_000 + 59_999, clockSkewMs: 10 ** 9 }))).ok).toBe(true);
  });
  it('subject_mismatch only when a subject is demanded', async () => {
    await deny(soft(), 'subject_mismatch', opts({ subject: ISS }));
    expect((await verifyPassport(soft(), opts({ subject: SUB }))).ok).toBe(true);
  });
  it('revoked, and an unavailable / missing / throwing revocation source denies', async () => {
    const id = issuePassport(ident).id;
    const seen: unknown[] = [];
    await deny(soft(), 'revoked', opts({ revocation: (x) => (seen.push(x), true) }));
    expect(seen).toEqual([{ id, iss: ISS, sub: SUB }]);
    await deny(soft(), 'revoked', opts({ revocation: async () => true }));
    expect(await verifyPassport(soft(), opts({ revocation: undefined }))).toEqual({ ok: false, reason: 'revocation_unavailable', detail: 'no revocation source' });
    expect(await verifyPassport(soft(), opts({ revocation: () => { throw new Error('down'); } }))).toEqual({ ok: false, reason: 'revocation_unavailable' });
  });
});

describe('signed passport: hardware_rooted', () => {
  it('rejects a forged flag (signed false->true by hand) and a flag with no evidence', async () => {
    const s = soft();
    await deny({ ...s, passport: { ...s.passport, hardware_rooted: true } }, 'bad_signature');
    const hw = hwPassport();
    const { evidence: _e, ...noEv } = hw;
    await deny(noEv, 'bad_signature'); // dropping the evidence invalidates the signature
  });
  it('accepts the evidence only through an attestation verifier; no verifier = reject, not downgrade', async () => {
    const hw = hwPassport();
    await deny(hw, 'hardware_verifier_missing');
    const seen: unknown[] = [];
    const r = await verifyPassport(hw, opts({ attestationVerifier: hwVerifier({}, seen) }));
    expect(r).toMatchObject({ ok: true, hardware_verified: true });
    expect(seen).toEqual([{ ...passportEvidenceBinding(hw.passport.id, SUB, 'nonce-1'), nonceIssuedAt: NOW }]);
    expect(passportEvidenceBinding('pid', 'sub', 'n')).toEqual({ holderPub: 'sub', grantRef: 'passport:pid', epoch: 0, nonce: 'n' });
  });
  it('rejects unverified, unbound or throwing evidence', async () => {
    const hw = hwPassport();
    await deny(hw, 'hardware_attestation_failed', opts({ attestationVerifier: hwVerifier({ ok: false }) }));
    await deny(hw, 'hardware_attestation_failed', opts({ attestationVerifier: hwVerifier({ bound: false }) }));
    await deny(hw, 'hardware_attestation_failed', opts({ attestationVerifier: { verify: () => { throw new Error('boom'); } } }));
    expect(await verifyPassport(hw, opts({ attestationVerifier: hwVerifier({ ok: false }) }))).toMatchObject({ detail: 'hw says no' });
  });
  it('rejects evidence whose measured identity differs from the claims (each field)', async () => {
    const hw = hwPassport();
    for (const m of [{ model_id: 'x' }, { operator: 'x' }, { weights_digest: 'x' }, { runtime_measurement: 'x' }, { system_prompt_digest: 'x' }, { tool_manifest_digest: 'x' }, { weights_measured: false }]) {
      await deny(hw, 'hardware_identity_mismatch', opts({ attestationVerifier: hwVerifier({ measured: m }) }));
    }
  });
  it('evidence for another subject: the verifier sees the passport subject, so a quote bound elsewhere fails there', async () => {
    const hw = hwPassport();
    const strict: HardwareAttestationVerifier = { verify: (i) => ({ ok: true, bound: i.expected.holderPub === 'someone-else', measured }) };
    await deny(hw, 'hardware_attestation_failed', opts({ attestationVerifier: strict }));
  });
  it('hardware evidence age is re-checked at verify time (exact boundaries, default 24 h, skew for the future)', async () => {
    const at = (a: number) => signPassport(issuePassport({ ...ident, hardware_rooted: true, weights_measured: true }), { issuerSecret: ISS_SECRET, subject: SUB, exp: NOW + 60_000, evidence: { document: { nonce: 'n' } as never, at: a } });
    const v = (over = {}) => opts({ attestationVerifier: hwVerifier(), ...over });
    expect(DEFAULT_PASSPORT_EVIDENCE_AGE_MS).toBe(24 * 3600_000);
    expect((await verifyPassport(at(NOW - DEFAULT_PASSPORT_EVIDENCE_AGE_MS), v())).ok).toBe(true);
    await deny(at(NOW - DEFAULT_PASSPORT_EVIDENCE_AGE_MS - 1), 'hardware_evidence_stale', v());
    expect((await verifyPassport(at(NOW - 500), v({ maxEvidenceAgeMs: 500 }))).ok).toBe(true);
    await deny(at(NOW - 501), 'hardware_evidence_stale', v({ maxEvidenceAgeMs: 500 }));
    await deny(at(NOW - 1), 'hardware_evidence_stale', v({ maxEvidenceAgeMs: -1 }));
    await deny(at(NOW - 1), 'hardware_evidence_stale', v({ maxEvidenceAgeMs: Number.NaN }));
    await deny(at(NOW + 1), 'hardware_evidence_stale', v());
    expect((await verifyPassport(at(NOW + 1000), v({ clockSkewMs: 1000 }))).ok).toBe(true);
    await deny(at(NOW + 1001), 'hardware_evidence_stale', v({ clockSkewMs: 1000 }));
    // staleness is decided before the verifier is asked, and before its absence is reported
    const seen: unknown[] = [];
    await deny(at(NOW - 10 ** 9), 'hardware_evidence_stale', opts({ attestationVerifier: hwVerifier({}, seen) }));
    expect(seen).toEqual([]);
    await deny(at(NOW - 10 ** 9), 'hardware_evidence_stale');
    // evidence.at defaults to iat when signing, and a non-integer at is refused / not trusted
    expect(hwPassport().evidence?.at).toBe(NOW - 1);
    expect(() => signPassport(issuePassport({ ...ident, hardware_rooted: true }), { issuerSecret: ISS_SECRET, subject: SUB, exp: NOW + 1, evidence: { document: {} as never, at: 1.5 } })).toThrow(/evidence.at/);
    await deny(rawSign({ passport: issuePassport({ ...ident, hardware_rooted: true }), evidence: { document: { nonce: 'n' } } }), 'hardware_evidence_missing', v());
    await deny(rawSign({ passport: issuePassport({ ...ident, hardware_rooted: true }), evidence: { document: { nonce: 'n' }, at: 1.5 } }), 'hardware_evidence_missing', v());
  });
  it('evidence checks: exact codes and details; a verifier that throws, throws a non-Error or returns nothing', async () => {
    const hwp = issuePassport({ ...ident, hardware_rooted: true });
    const ex = async (o: Record<string, unknown>, v = opts({ attestationVerifier: hwVerifier() })) => verifyPassport(rawSign({ passport: hwp, ...o }), v);
    expect(await ex({})).toEqual({ ok: false, reason: 'hardware_evidence_missing' });
    expect(await ex({ evidence: { at: NOW } })).toEqual({ ok: false, reason: 'hardware_evidence_missing' });
    expect(await ex({ evidence: { document: 'abc', at: NOW } })).toEqual({ ok: false, reason: 'hardware_evidence_missing' });
    expect(await ex({ evidence: { document: { nonce: 'n' } } })).toEqual({ ok: false, reason: 'hardware_evidence_missing', detail: 'evidence.at' });
    const good = { evidence: { document: { nonce: 'n' }, at: NOW } };
    expect(await ex(good)).toMatchObject({ ok: true });
    expect(await ex(good, opts({ attestationVerifier: { verify: () => { throw new Error('boom'); } } }))).toEqual({ ok: false, reason: 'hardware_attestation_failed', detail: 'boom' });
    expect(await ex(good, opts({ attestationVerifier: { verify: () => { throw 'str'; } } }))).toEqual({ ok: false, reason: 'hardware_attestation_failed', detail: 'error' });
    expect(await ex(good, opts({ attestationVerifier: { verify: () => undefined as never } }))).toEqual({ ok: false, reason: 'hardware_attestation_failed' });
    expect(await ex(good, opts({ attestationVerifier: { verify: () => ({ ok: true, bound: true }) } }))).toEqual({ ok: false, reason: 'hardware_identity_mismatch' });
    // maxEvidenceAgeMs 0 accepts a quote taken right now; a negative ceiling never accepts, even a future-dated one inside the skew
    expect(await ex(good, opts({ attestationVerifier: hwVerifier(), maxEvidenceAgeMs: 0 }))).toMatchObject({ ok: true });
    expect(await ex({ evidence: { document: { nonce: 'n' }, at: NOW + 20 } }, opts({ attestationVerifier: hwVerifier(), maxEvidenceAgeMs: -10, clockSkewMs: 60 }))).toEqual({ ok: false, reason: 'hardware_evidence_stale' });
  });
  it('the measured identity may carry more than the passport states (absent optional claims are not compared)', async () => {
    const lean = issuePassport({ model_id: 'm1', operator: 'acme', hardware_rooted: true, weights_measured: false, issued_at: NOW - 1 });
    const sp = signPassport(lean, { issuerSecret: ISS_SECRET, subject: SUB, exp: NOW + 60_000, evidence: { document: { nonce: 'n' } as never } });
    expect(await verifyPassport(sp, opts({ attestationVerifier: hwVerifier() }))).toMatchObject({ ok: true });
    // a passport that does not claim measured weights is not held to them
    expect(await verifyPassport(sp, opts({ attestationVerifier: hwVerifier({ measured: { weights_measured: false } }) }))).toMatchObject({ ok: true });
    // and each claimed optional field IS compared when present
    for (const k of ['weights_digest', 'runtime_measurement', 'system_prompt_digest', 'tool_manifest_digest'] as const) {
      const p = issuePassport({ model_id: 'm1', operator: 'acme', hardware_rooted: true, weights_measured: false, issued_at: NOW - 1, [k]: 'claimed' });
      const s2 = signPassport(p, { issuerSecret: ISS_SECRET, subject: SUB, exp: NOW + 60_000, evidence: { document: { nonce: 'n' } as never } });
      await deny(s2, 'hardware_identity_mismatch', opts({ attestationVerifier: hwVerifier({ measured: { [k]: 'other' } }) }));
      expect(await verifyPassport(s2, opts({ attestationVerifier: hwVerifier({ measured: { [k]: 'claimed' } }) }))).toMatchObject({ ok: true });
    }
  });
  it('assurance label: hardware only when verified, vendor from the verifier label', async () => {
    const v = setAssuranceLabel(hwVerifier(), { level: 'hardware', vendor: 'amd-sev-snp' });
    const r = await verifyPassport(hwPassport(), opts({ attestationVerifier: v }));
    if (!r.ok) throw new Error('x');
    expect(passportAssurance(r, v)).toEqual({ level: 'hardware', vendor: 'amd-sev-snp' });
    expect(passportAssurance(r, hwVerifier())).toEqual({ level: 'unknown' });
    const s = await verifyPassport(soft(), opts());
    if (!s.ok) throw new Error('x');
    expect(passportAssurance(s, v)).toEqual({ level: 'software' });
  });
});

describe('signed passport: suite agility (ml-dsa)', () => {
  const kp = mlDsa65Keygen(new Uint8Array(32).fill(5));
  const pq = encodeMlDsaPublicKey(kp.publicKey);
  const mk = (alg: 'ml-dsa-65' | 'hybrid-ed25519-ml-dsa-65') => signPassport(issuePassport(ident), { issuerSecret: ISS_SECRET, subject: SUB, exp: NOW + 60_000, suite: { alg, mlDsa: kp } });
  it.each(['ml-dsa-65', 'hybrid-ed25519-ml-dsa-65'] as const)('%s verifies only under a pinned PQ key', async (alg) => {
    const s = mk(alg);
    expect(s.alg).toBe(alg);
    expect((await verifyPassport(s, opts({ pqPins: { [ISS]: pq } }))).ok).toBe(true);
    await deny(s, 'bad_signature'); // no pin: the artifact's own key is not trusted
    expect((await verifyPassport(s, opts({ allowUnboundPq: true }))).ok).toBe(true); // explicit legacy opt-out
    await deny(s, 'bad_signature', opts({ pqPins: { [ISS]: encodeMlDsaPublicKey(mlDsa65Keygen(new Uint8Array(32).fill(6)).publicKey) } }));
    // downgrade: strip the suite fields
    const { alg: _a, pq_pk: _k, pq_sig: _s, ...stripped } = s;
    await deny(stripped, 'bad_signature', opts({ pqPins: { [ISS]: pq } }));
  });
});

describe('passport conformance vectors', () => {
  const FILE = join(__dirname, '..', 'conformance', 'passport-vectors.json');
  const doc = JSON.parse(readFileSync(FILE, 'utf8')) as Awaited<ReturnType<typeof buildPassportVectors>>;
  const expected: Record<string, string> = {
    ok: 'ok', 'ok-skew-nbf': 'ok', 'subject-ok': 'ok', 'not-an-object': 'malformed', 'wrong-version': 'unsupported_version', 'unknown-alg': 'unsupported_suite',
    'unknown-issuer': 'unknown_issuer', 'no-trusted-issuers': 'unknown_issuer', 'tampered-model': 'bad_signature', 'tampered-operator': 'bad_signature', 'tampered-subject': 'bad_signature',
    'tampered-exp': 'bad_signature', 'forged-hardware-flag': 'bad_signature', 'not-yet-valid': 'not_yet_valid', expired: 'expired', 'expired-at-boundary': 'expired',
    'subject-mismatch': 'subject_mismatch', revoked: 'revoked', 'hardware-rooted-without-evidence': 'hardware_evidence_missing', 'id-mismatch': 'id_mismatch', 'hardware-rooted-evidence-no-verifier': 'hardware_verifier_missing', 'hardware-evidence-stale': 'hardware_evidence_stale', 'hardware-evidence-stale-custom-max': 'hardware_evidence_stale', 'hardware-evidence-future': 'hardware_evidence_stale',
  };
  const hwExpected: Record<string, string> = {
    'hardware-ok': 'ok', 'hardware-ok-optional-claims': 'ok', 'hardware-runtime-mismatch': 'hardware_identity_mismatch', 'hardware-prompt-mismatch': 'hardware_identity_mismatch',
    'hardware-tools-mismatch': 'hardware_identity_mismatch', 'hardware-unbound': 'hardware_attestation_failed', 'hardware-refused': 'hardware_attestation_failed',
    'hardware-verifier-throws': 'hardware_attestation_failed', 'hardware-no-measured': 'hardware_identity_mismatch', 'hardware-model-mismatch': 'hardware_identity_mismatch',
    'hardware-operator-mismatch': 'hardware_identity_mismatch', 'hardware-weights-mismatch': 'hardware_identity_mismatch', 'hardware-weights-not-measured': 'hardware_identity_mismatch',
    'hardware-ok-but-stale': 'hardware_evidence_stale',
  };
  const SUITES = ['ml-dsa-65', 'hybrid-ed25519-ml-dsa-65', 'hybrid-nested-ed25519-ml-dsa-65', 'ml-dsa-87', 'hybrid-ed25519-ml-dsa-87', 'slh-dsa-sha2-128f', 'hybrid-ed25519-slh-dsa-sha2-128f', 'slh-dsa-sha2-256s', 'hybrid-ed25519-slh-dsa-sha2-256s', 'fn-dsa-512', 'fn-dsa-1024'];
  for (const a of SUITES) Object.assign(expected, { [`suite-${a}`]: 'ok', [`suite-${a}-unpinned`]: 'bad_signature', [`suite-${a}-wrong-pin`]: 'bad_signature' });
  Object.assign(expected, hwExpected, { 'suite-ml-dsa-65-tampered': 'bad_signature', 'suite-hybrid-nested-ed25519-ml-dsa-65-tampered': 'bad_signature', 'suite-downgrade-stripped': 'bad_signature' });
  it('the committed file is exactly what the reference generates (regenerate with scripts/gen-conformance-passport.ts)', async () => {
    expect(readFileSync(FILE, 'utf8')).toBe(`${JSON.stringify(await buildPassportVectors(), null, 2)}\n`);
  });
  it('pins the expected outcome of every vector (independent of the generator)', () => {
    expect(Object.fromEntries(doc.passport_vectors.map((v) => [v.name, v.expect.ok ? 'ok' : v.expect.reason]))).toEqual(expected);
    expect(PASSPORT_VECTOR_NOW).toBe(1_800_000_000_000);
    expect(doc.passport_vectors.length).toBe(Object.keys(expected).length);
  });
  it.each(doc.passport_vectors.map((v) => [v.name, v] as const))('%s', async (_n, v) => {
    const signed = v.signed_ref !== undefined ? doc.passport_vectors.find((x) => x.name === v.signed_ref)!.signed : v.signed;
    let seen: unknown;
    const attestationVerifier = v.hardware && {
      verify: (i: { expected: unknown }) => {
        seen = i.expected;
        if (v.hardware!.throws) throw new Error('down');
        return { ok: v.hardware!.ok, bound: v.hardware!.bound, ...(v.hardware!.measured ? { measured: v.hardware!.measured as never } : {}) };
      },
    };
    const r = await verifyPassport(signed, { trustedIssuers: v.trustedIssuers, now: v.now, clockSkewMs: v.clockSkewMs, maxEvidenceAgeMs: v.maxEvidenceAgeMs, subject: v.subject, pqPins: v.pqPins, attestationVerifier, revocation: ({ id }) => v.revoked.includes(id) });
    expect(r.ok ? { ok: true } : { ok: false, reason: r.reason }).toEqual(v.expect);
    if (v.expectBinding) expect(seen).toMatchObject(v.expectBinding);
  });
  it('the hardware vectors hand the verifier the subject key, the passport id, epoch 0 and the evidence nonce', () => {
    const ok = doc.passport_vectors.find((v) => v.name === 'hardware-ok')!;
    expect(ok.expectBinding).toEqual({ holderPub: (ok.signed as SignedPassport).sub, grantRef: `passport:${(ok.signed as SignedPassport).passport.id}`, epoch: 0, nonce: 'n-hw' });
  });
});

describe('passport conformance vectors: REAL vendor verifiers (passport_hardware_vectors)', () => {
  const FILE = join(__dirname, '..', 'conformance', 'passport-vectors.json');
  const doc = JSON.parse(readFileSync(FILE, 'utf8')) as Awaited<ReturnType<typeof buildPassportVectors>>;
  const VENDORS = ['amd-sev-snp', 'intel-tdx-dcap', 'azure-maa', 'gcp-confidential-space', 'nvidia-gpu-spdm'];
  const want: Record<string, string> = {};
  for (const v of VENDORS) {
    Object.assign(want, {
      [`hardware-${v}-ok`]: 'ok', [`hardware-${v}-identity-mismatch`]: 'hardware_identity_mismatch', [`hardware-${v}-bound-to-another-passport`]: 'hardware_attestation_failed',
      [`hardware-${v}-bound-to-another-subject`]: 'hardware_attestation_failed', [`hardware-${v}-nonce-differs`]: 'hardware_attestation_failed', [`hardware-${v}-no-evidence`]: 'hardware_attestation_failed',
      [`hardware-${v}-stale`]: 'hardware_evidence_stale', [`hardware-${v}-wrong-trust-pin`]: 'hardware_attestation_failed',
    });
  }
  it('pins the expected passport outcome of every vendor row (independent of the generator)', () => {
    expect(Object.fromEntries(doc.passport_hardware_vectors.map((v) => [v.name, v.expect.ok ? 'ok' : v.expect.reason]))).toEqual(want);
  });
  it.each(doc.passport_hardware_vectors.map((v) => [v.name, v] as const))('%s', async (_n, v) => {
    const hv = v.hardware_verifier!;
    const attestationVerifier = verifierFromConfig(hv.vendor, hv.config, hv.evidence);
    const r = await verifyPassport(v.signed, { trustedIssuers: v.trustedIssuers, now: v.now, attestationVerifier, revocation: ({ id }) => v.revoked.includes(id) });
    expect(r.ok ? { ok: true } : { ok: false, reason: r.reason }).toEqual(v.expect);
  });
  it('the vendor rows carry the evidence nonce the passport signed, and a hardware_verifier each', () => {
    for (const v of doc.passport_hardware_vectors) expect(v.hardware_verifier?.vendor).toBeDefined();
  });
});
