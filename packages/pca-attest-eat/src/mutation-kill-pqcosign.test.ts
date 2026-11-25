/** Mutation-kill suite for pqcosign.ts: exact canonical bytes, every refusal reason, gate boundaries. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPair, mlDsa65Keygen, mlDsa87Keygen, slhDsa128fKeygen, slhDsa256sKeygen, type SuiteSecretKeys } from '@atlasauth/pca';
import { type MeasuredIdentity } from '@atlasauth/pca/ext/attestation';
import {
  PQCOSIGN_DOMAIN,
  PQ_COSIGN_SUITES,
  canonicalVerdictBytes,
  coSignAttestation,
  isPqCoSignSuite,
  verdictFromAppraisal,
  verifyCoSignedAttestation,
  type AttestationVerdict,
  type PqCoSignedAttestation,
} from './pqcosign';
import type { AttestationResult, EatClaims } from './index';

const text = (b: Uint8Array): string => Buffer.from(b).toString('utf8');
const seed = (n: number): Uint8Array => new Uint8Array(32).fill(n);
const ML = (): SuiteSecretKeys => ({ mlDsa: mlDsa65Keygen(seed(1)) });
const HY = (): SuiteSecretKeys => ({ mlDsa: mlDsa65Keygen(seed(2)), edSecret: generateKeyPair().secretKey });
const NOW = 1_700_000_500_000;
const M: MeasuredIdentity = { model_id: 'm', weights_digest: 'w', weights_measured: true, runtime_measurement: 'r', operator: 'o', system_prompt_digest: 'sp', tool_manifest_digest: 'tm' };
const V: AttestationVerdict = { tier: 'affirming', trustworthy: true, measured: M, measurement: 'mm', nonce: 'nn', iat: 1700000000, issuer: 'ii' };

afterEach(() => vi.useRealTimers());

describe('canonicalVerdictBytes is byte-exact', () => {
  it('full verdict', () => {
    expect(text(canonicalVerdictBytes(V, 5))).toBe(
      `{"typ":"${PQCOSIGN_DOMAIN}","tier":"affirming","trustworthy":true,"measurement":"mm","measured":{"model_id":"m","weights_digest":"w","weights_measured":true,"runtime_measurement":"r","operator":"o","system_prompt_digest":"sp","tool_manifest_digest":"tm"},"nonce":"nn","iat":1700000000,"issuer":"ii","cosignedAt":5}`,
    );
  });
  it('empty verdict emits explicit nulls', () => {
    expect(text(canonicalVerdictBytes({ tier: 'rejected', trustworthy: false }, 7))).toBe(
      `{"typ":"${PQCOSIGN_DOMAIN}","tier":"rejected","trustworthy":false,"measurement":null,"measured":null,"nonce":null,"iat":null,"issuer":null,"cosignedAt":7}`,
    );
  });
  it('measured optionals: non-boolean / non-string become null, false is kept', () => {
    const odd = { ...M, weights_measured: 1, system_prompt_digest: 5, tool_manifest_digest: null } as unknown as MeasuredIdentity;
    const t = JSON.parse(text(canonicalVerdictBytes({ ...V, measured: odd }, 1))) as { measured: Record<string, unknown> };
    expect(t.measured).toEqual({ model_id: 'm', weights_digest: 'w', weights_measured: null, runtime_measurement: 'r', operator: 'o', system_prompt_digest: null, tool_manifest_digest: null });
    const f = JSON.parse(text(canonicalVerdictBytes({ ...V, measured: { ...M, weights_measured: false } }, 1))) as { measured: Record<string, unknown> };
    expect(f.measured.weights_measured).toBe(false);
    const noOpt = { model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o' } as MeasuredIdentity;
    const g = JSON.parse(text(canonicalVerdictBytes({ ...V, measured: noOpt }, 1))) as { measured: Record<string, unknown> };
    expect(g.measured).toEqual({ model_id: 'm', weights_digest: 'w', weights_measured: null, runtime_measurement: 'r', operator: 'o', system_prompt_digest: null, tool_manifest_digest: null });
  });
  it('non-conforming scalars are normalised: trustworthy only for true, others null', () => {
    const bad = { tier: 'x', trustworthy: 1, measurement: 5, nonce: 5, iat: '1', issuer: 5 } as unknown as AttestationVerdict;
    const t = JSON.parse(text(canonicalVerdictBytes(bad, 1))) as Record<string, unknown>;
    expect(t).toMatchObject({ trustworthy: false, measurement: null, nonce: null, iat: null, issuer: null });
    for (const iat of [NaN, Infinity, -Infinity]) expect((JSON.parse(text(canonicalVerdictBytes({ ...V, iat }, 1))) as { iat: unknown }).iat).toBeNull();
    expect((JSON.parse(text(canonicalVerdictBytes({ ...V, iat: 0 }, 1))) as { iat: unknown }).iat).toBe(0);
    expect((JSON.parse(text(canonicalVerdictBytes({ ...V, measurement: '' }, 1))) as { measurement: unknown }).measurement).toBe('');
  });
});

describe('verdictFromAppraisal', () => {
  const res: AttestationResult = { tier: 'affirming', trustworthy: true, reasons: [] };
  const base = { iss: 'iss', iat: 100 } as EatClaims;
  it('minimal claims', () => {
    expect(verdictFromAppraisal(res, base)).toEqual({ tier: 'affirming', trustworthy: true, iat: 100, issuer: 'iss' });
  });
  it('measured is copied; measurement prefers the runtime measurement, then sevsnp', () => {
    expect(verdictFromAppraisal(res, { ...base, measured: M })).toEqual({ tier: 'affirming', trustworthy: true, measured: M, measurement: 'r', iat: 100, issuer: 'iss' });
    const sev = { measurement: 'snp' } as EatClaims['sevsnp'];
    expect(verdictFromAppraisal(res, { ...base, sevsnp: sev }).measurement).toBe('snp');
    expect(verdictFromAppraisal(res, { ...base, measured: { ...M, runtime_measurement: '' }, sevsnp: sev }).measurement).toBe('snp');
    expect(verdictFromAppraisal(res, { ...base, measured: { ...M, runtime_measurement: '' } })).not.toHaveProperty('measurement');
    expect(verdictFromAppraisal(res, { ...base, sevsnp: { measurement: '' } as EatClaims['sevsnp'] })).not.toHaveProperty('measurement');
    expect(verdictFromAppraisal(res, { ...base, sevsnp: { measurement: 5 } as unknown as EatClaims['sevsnp'] })).not.toHaveProperty('measurement');
    expect(verdictFromAppraisal(res, { ...base, measured: { ...M, runtime_measurement: 'x' }, sevsnp: sev }).measurement).toBe('x');
    expect(verdictFromAppraisal(res, { ...base, measured: { ...M, runtime_measurement: undefined } as unknown as MeasuredIdentity, sevsnp: sev }).measurement).toBe('snp');
  });
  it('no measured claim leaves the property absent', () => {
    expect(Object.keys(verdictFromAppraisal(res, base)).sort()).toEqual(['iat', 'issuer', 'tier', 'trustworthy']);
  });
  it('nonce, iat, issuer only when well typed', () => {
    const v = verdictFromAppraisal(res, { iss: 5, iat: NaN, eat_nonce: 5 } as unknown as EatClaims);
    expect(v).toEqual({ tier: 'affirming', trustworthy: true });
    expect(verdictFromAppraisal(res, { ...base, eat_nonce: 'n' }).nonce).toBe('n');
    expect(verdictFromAppraisal(res, { ...base, eat_nonce: '' }).nonce).toBe('');
    expect(verdictFromAppraisal(res, { ...base, iat: Infinity })).not.toHaveProperty('iat');
    expect(verdictFromAppraisal(res, { ...base, iat: '5' } as unknown as EatClaims)).not.toHaveProperty('iat');
    expect(verdictFromAppraisal(res, { ...base, iat: 0 }).iat).toBe(0);
    expect(verdictFromAppraisal(res, { ...base, iss: '' }).issuer).toBe('');
    const rej = verdictFromAppraisal({ tier: 'rejected', trustworthy: false, reasons: [] }, base);
    expect(rej).toMatchObject({ tier: 'rejected', trustworthy: false });
  });
});

describe('suite registry', () => {
  it('only registered strings', () => {
    for (const s of PQ_COSIGN_SUITES) expect(isPqCoSignSuite(s)).toBe(true);
    expect(PQ_COSIGN_SUITES.length).toBe(9);
    for (const x of [5, null, undefined, {}, ['ml-dsa-65'], 'ML-DSA-65', 'ed25519', 'constructor', '__proto__', 'toString']) expect(isPqCoSignSuite(x)).toBe(false);
  });
});

describe('coSignAttestation configuration errors', () => {
  it('missing key material per suite names the right key', () => {
    const want: Record<string, string> = {
      'ml-dsa-65': 'mlDsa', 'ml-dsa-87': 'mlDsa87', 'slh-dsa-sha2-128f': 'slhDsa', 'slh-dsa-sha2-256s': 'slhDsa256s',
      'hybrid-ed25519-ml-dsa-65': 'mlDsa', 'hybrid-nested-ed25519-ml-dsa-65': 'mlDsa', 'hybrid-ed25519-ml-dsa-87': 'mlDsa87',
      'hybrid-ed25519-slh-dsa-sha2-128f': 'slhDsa', 'hybrid-ed25519-slh-dsa-sha2-256s': 'slhDsa256s',
    };
    for (const s of PQ_COSIGN_SUITES) {
      expect(() => coSignAttestation(V, { suite: s, secretKey: {} }), s).toThrow(new TypeError(`coSignAttestation: suite '${s}' requires ${want[s]} key material`));
    }
  });
  it('secretKey must be a record', () => {
    for (const k of [null, undefined, [], 'k', 5]) {
      expect(() => coSignAttestation(V, { secretKey: k as never }), String(k)).toThrow(new TypeError('coSignAttestation: secretKey material is required'));
    }
  });
  it('unknown / classical suites are range errors', () => {
    expect(() => coSignAttestation(V, { suite: 'ed25519' as never, secretKey: ML() })).toThrow(new RangeError("coSignAttestation: 'ed25519' is not an accepted post-quantum co-sign suite"));
  });
  it('hybrid needs edSecret', () => {
    expect(() => coSignAttestation(V, { suite: 'hybrid-ed25519-ml-dsa-65', secretKey: ML() })).toThrow(new TypeError("coSignAttestation: hybrid suite 'hybrid-ed25519-ml-dsa-65' requires edSecret"));
    expect(() => coSignAttestation(V, { suite: 'hybrid-ed25519-ml-dsa-65', secretKey: { ...ML(), edSecret: 'x' as never } })).toThrow(/requires edSecret/);
  });
});

describe('coSignAttestation output', () => {
  it('pure suite: no ed key, no pq_sig property at all; default now is the clock', () => {
    vi.useFakeTimers();
    vi.setSystemTime(123_456);
    const c = coSignAttestation(V, { secretKey: ML() });
    expect(c.suite).toBe('ml-dsa-65');
    expect(c.cosig.cosignedAt).toBe(123_456);
    expect(Object.keys(c.cosig).sort()).toEqual(['cosignedAt', 'sig']);
    expect(Object.keys(c.signer_pub)).toEqual(['pq']);
    expect(c.verdict).toBe(V);
  });
  it('now: NaN / Infinity / non-number fall back to the clock', () => {
    vi.useFakeTimers();
    vi.setSystemTime(99);
    for (const now of [NaN, Infinity, -Infinity, '5' as never, null as never]) expect(coSignAttestation(V, { secretKey: ML(), now }).cosig.cosignedAt, String(now)).toBe(99);
    expect(coSignAttestation(V, { secretKey: ML(), now: 0 }).cosig.cosignedAt).toBe(0);
  });
  it('hybrid suite: ed key and pq_sig present', () => {
    const c = coSignAttestation(V, { suite: 'hybrid-ed25519-ml-dsa-65', secretKey: HY(), now: NOW });
    expect(Object.keys(c.cosig).sort()).toEqual(['cosignedAt', 'pq_sig', 'sig']);
    expect(Object.keys(c.signer_pub).sort()).toEqual(['ed', 'pq']);
  });
});

describe('verifyCoSignedAttestation', () => {
  const good = (): PqCoSignedAttestation => coSignAttestation(V, { secretKey: ML(), now: NOW });
  const goodHy = (): PqCoSignedAttestation => coSignAttestation(V, { suite: 'hybrid-ed25519-ml-dsa-65', secretKey: HY(), now: NOW });
  const verify = (c: unknown, o = {}) => verifyCoSignedAttestation(c as never, { now: NOW + 1000, ...o });

  it('ok result carries suite, verdict, signer, timing', () => {
    const c = good();
    const r = verify(c);
    expect(r).toEqual({ ok: true, suite: 'ml-dsa-65', verdict: V, signer_pub: c.signer_pub, cosignedAt: NOW, ageMs: 1000 });
  });
  it('not an object / bad verdict / bad cosig / bad suite / bad signer', () => {
    for (const x of [null, undefined, 5, 'x', []]) expect(verify(x), String(x)).toEqual({ ok: false, reason: 'co-signed attestation is not an object' });
    const vr = 'verdict is missing or has a non-string tier / non-boolean trustworthy';
    for (const v of [undefined, null, [], 'x', { tier: 5, trustworthy: true }, { tier: 'a', trustworthy: 'yes' }, { trustworthy: true }, { tier: 'a' }]) {
      expect(verify({ ...good(), verdict: v }), JSON.stringify(v)).toEqual({ ok: false, reason: vr });
    }
    const cr = 'cosig is missing or has a non-numeric cosignedAt / non-string sig';
    const g = good();
    for (const c of [undefined, null, [], 'x', { ...g.cosig, cosignedAt: '1' }, { ...g.cosig, cosignedAt: NaN }, { ...g.cosig, cosignedAt: Infinity }, { ...g.cosig, sig: 5 }, { cosignedAt: 1 }, { sig: 'a' }]) {
      expect(verify({ ...g, cosig: c }), JSON.stringify(c)).toEqual({ ok: false, reason: cr });
    }
    expect(verify({ ...g, suite: 'ed25519' })).toEqual({ ok: false, reason: "suite 'ed25519' is not an accepted post-quantum co-sign suite" });
    expect(verify({ ...g, suite: undefined })).toEqual({ ok: false, reason: "suite 'undefined' is not an accepted post-quantum co-sign suite" });
    const sr = 'signer_pub is missing or has no post-quantum public key';
    for (const s of [undefined, null, [], 'x', {}, { pq: '' }, { pq: 5 }, { ed: 'x' }]) expect(verify({ ...g, signer_pub: s }), JSON.stringify(s)).toEqual({ ok: false, reason: sr });
  });
  it('the partial result of a failed verification exposes suite, verdict, signer, cosignedAt, ageMs', () => {
    const c = good();
    const r = verify({ ...c, verdict: { ...V, tier: 'rejected' } });
    expect(r).toEqual({
      ok: false, reason: 'post-quantum co-signature does not verify (tampered verdict, wrong key, or bad signature)', suite: 'ml-dsa-65',
      verdict: { ...V, tier: 'rejected' }, signer_pub: c.signer_pub, cosignedAt: NOW, ageMs: 1000,
    });
  });
  it('signer_pub with an empty ed is ignored', () => {
    const c = good();
    const r = verify({ ...c, signer_pub: { ...c.signer_pub, ed: '' } });
    expect(r.ok).toBe(true);
    expect(r.signer_pub).toEqual({ pq: c.signer_pub.pq });
    const h = goodHy();
    const rr = verify({ ...h, signer_pub: { ...h.signer_pub, ed: '' } });
    expect(rr.ok).toBe(false);
    expect(rr.signer_pub).toEqual({ pq: h.signer_pub.pq });
  });
  it('expectedSigner: string, pair, ed mismatch, missing ed, length mismatch', () => {
    const c = good();
    const wrong = 'AAAA';
    const reason = 'co-signer public key does not match the expected signer';
    expect(verify(c, { expectedSigner: c.signer_pub.pq }).ok).toBe(true);
    expect(verify(c, { expectedSigner: wrong })).toMatchObject({ ok: false, reason });
    expect(verify(c, { expectedSigner: c.signer_pub.pq.slice(0, -1) })).toMatchObject({ ok: false, reason });
    expect(verify(c, { expectedSigner: c.signer_pub.pq + 'A' })).toMatchObject({ ok: false, reason });
    expect(verify(c, { expectedSigner: { pq: c.signer_pub.pq } }).ok).toBe(true);
    expect(verify(c, { expectedSigner: { pq: wrong } })).toMatchObject({ ok: false, reason });
    expect(verify(c, { expectedSigner: { pq: 5 } as never })).toMatchObject({ ok: false, reason });
    // pure artifact has no ed: an expected ed cannot match
    expect(verify(c, { expectedSigner: { pq: c.signer_pub.pq, ed: 'x' } })).toMatchObject({ ok: false, reason });
    const h = goodHy();
    const ed = h.signer_pub.ed as string;
    expect(verify(h, { expectedSigner: { pq: h.signer_pub.pq, ed } }).ok).toBe(true);
    expect(verify(h, { expectedSigner: { pq: h.signer_pub.pq } }).ok).toBe(true);
    expect(verify(h, { expectedSigner: { pq: h.signer_pub.pq, ed: wrong } })).toMatchObject({ ok: false, reason });
    expect(verify(h, { expectedSigner: { pq: h.signer_pub.pq, ed: ed + 'A' } })).toMatchObject({ ok: false, reason });
    expect(verify(h, { expectedSigner: h.signer_pub.pq }).ok).toBe(true);
    expect(verify({ ...h, signer_pub: { pq: h.signer_pub.pq } }, { expectedSigner: { pq: h.signer_pub.pq, ed } })).toMatchObject({ ok: false, reason });
  });
  it('maxAgeMs: invalid values, future timestamps, boundary', () => {
    const c = good();
    for (const m of [0, -1, NaN, Infinity]) expect(verify(c, { maxAgeMs: m }), String(m)).toMatchObject({ ok: false, reason: 'invalid maxAgeMs' });
    expect(verify(c, { maxAgeMs: 1 }).ok).toBe(false);
    expect(verifyCoSignedAttestation(c, { now: NOW - 1, maxAgeMs: 1000 })).toMatchObject({ ok: false, reason: 'co-sign timestamp is in the future' });
    expect(verifyCoSignedAttestation(c, { now: NOW, maxAgeMs: 1000 }).ok).toBe(true);
    expect(verifyCoSignedAttestation(c, { now: NOW + 1000, maxAgeMs: 1000 }).ok).toBe(true);
    expect(verifyCoSignedAttestation(c, { now: NOW + 1001, maxAgeMs: 1000 })).toMatchObject({ ok: false, reason: 'co-signature is stale (older than maxAgeMs)' });
    // without maxAgeMs a future timestamp is not examined
    expect(verifyCoSignedAttestation(c, { now: NOW - 5 }).ok).toBe(true);
  });
  it('opts.now: non-finite falls back to the clock', () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW + 7);
    const c = good();
    for (const now of [NaN, Infinity, '5' as never, undefined]) expect(verifyCoSignedAttestation(c, { now }).ageMs, String(now)).toBe(7);
    expect(verifyCoSignedAttestation(c, { now: NOW + 3 }).ageMs).toBe(3);
    expect(verifyCoSignedAttestation(c).ageMs).toBe(7);
  });
  it('hybrid: both halves needed; a pure artifact with a spurious pq_sig is still accepted', () => {
    const h = goodHy();
    expect(verify(h).ok).toBe(true);
    expect(verify({ ...h, cosig: { cosignedAt: h.cosig.cosignedAt, sig: h.cosig.sig } }).ok).toBe(false);
    const { pq_sig: _p, ...rest } = h.cosig;
    void _p;
    expect(verify({ ...h, cosig: rest }).ok).toBe(false);
    const c = good();
    expect(verify({ ...c, cosig: { ...c.cosig, pq_sig: 'junk' } }).ok).toBe(true);
  });
  it('a verification that throws is reported fail closed with the message', () => {
    const c = good();
    const hostile = { ...c, get verdict(): never { throw new Error('boom'); } };
    expect(verifyCoSignedAttestation(hostile as never)).toEqual({ ok: false, reason: 'co-signature verification error (fail closed): boom' });
    const nonError = { ...c, get verdict(): never { throw 'str'; } };
    expect(verifyCoSignedAttestation(nonError as never)).toEqual({ ok: false, reason: 'co-signature verification error (fail closed): unknown' });
  });
  it('ml-dsa-87 co-sign round-trips', () => {
    const c = coSignAttestation(V, { suite: 'ml-dsa-87', secretKey: { mlDsa87: mlDsa87Keygen(seed(5)) }, now: NOW });
    expect(verify(c).ok).toBe(true);
    expect(verify({ ...c, suite: 'ml-dsa-65' }).ok).toBe(false);
  });
});

describe('SLH-DSA co-signing (key material accepted)', () => {
  it('slh-dsa-sha2-128f round-trips', () => {
    const c = coSignAttestation(V, { suite: 'slh-dsa-sha2-128f', secretKey: { slhDsa: slhDsa128fKeygen(new Uint8Array(48).fill(7)) }, now: NOW });
    expect(verifyCoSignedAttestation(c, { now: NOW + 1 }).ok).toBe(true);
  });
  it('slh-dsa-sha2-256s round-trips', () => {
    const c = coSignAttestation(V, { suite: 'slh-dsa-sha2-256s', secretKey: { slhDsa256s: slhDsa256sKeygen(new Uint8Array(96).fill(8)) }, now: NOW });
    expect(verifyCoSignedAttestation(c, { now: NOW + 1 }).ok).toBe(true);
  }, 120_000);
});
