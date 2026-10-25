/** 0.4.2 mutation kills: verifyAllowlistManifest option validation (never coerced), window / lifetime / version boundaries, exact reasons. */
import { describe, expect, it } from 'vitest';
import { type AllowlistManifestBody, createAllowlistManifest, signAllowlistManifest, verifyAllowlistManifest } from './attest-allowlist';
import { b64u } from './hash';
import { generateKeyPair } from './keys';

const T0 = Date.parse('2026-10-09T00:00:00Z');
const DAY = 86_400_000;
const ed = generateKeyPair();
const KEYS = { ops: { alg: 'ed25519' as const, keys: { edPub: b64u(ed.publicKey) } } };
const body = (over: Partial<AllowlistManifestBody> = {}): AllowlistManifestBody => ({
  version: 5, issuedAt: T0 - DAY, notBefore: T0 - DAY, expiresAt: T0 + DAY, entries: [{ kind: 'sev-snp-measurement', value: 'ab'.repeat(48), label: 'x' }], ...over,
});
const signed = (b = body()) => signAllowlistManifest(b, { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: ed.secretKey } });
const v = (o: Record<string, unknown> = {}, m: unknown = signed()) => verifyAllowlistManifest(m, { issuerKeys: KEYS, nowMs: T0, ...o } as never);
const fail = (r: ReturnType<typeof v>) => (r.ok ? 'ok' : `${r.code}: ${r.reason}`);

describe('option validation is refusal, never coercion', () => {
  it('each non-number / non-finite / non-integer option is malformed with its own reason', () => {
    for (const x of [Number.NaN, Infinity, '1', null]) expect(fail(v({ clockSkewMs: x })), String(x)).toBe('malformed: clockSkewMs must be a finite number');
    for (const x of [Number.NaN, Infinity, '1', null]) expect(fail(v({ maxLifetimeMs: x })), String(x)).toBe('malformed: maxLifetimeMs must be a finite number');
    for (const x of [1.5, Number.NaN, Infinity, '1', null]) expect(fail(v({ minVersion: x })), String(x)).toBe('malformed: minVersion must be an integer');
    for (const x of [1.5, Number.NaN, Infinity, '1', null]) expect(fail(v({ lastSeenVersion: x })), String(x)).toBe('malformed: lastSeenVersion must be an integer');
  });
  it('valid values (including 0 and negatives where allowed) are accepted', () => {
    expect(fail(v({ clockSkewMs: 0, maxLifetimeMs: 3 * DAY, minVersion: 0, lastSeenVersion: 0 }))).toBe('ok');
    expect(fail(v({ clockSkewMs: -5 }))).toBe('ok'); // a negative skew clamps to 0
    expect(fail(v({ nowMs: 1.5 }))).toBe('malformed: nowMs must be an integer');
  });
});

describe('boundaries', () => {
  it('lifetime is refused strictly above maxLifetimeMs (equal is fine)', () => {
    expect(fail(v({ maxLifetimeMs: 2 * DAY }))).toBe('ok');
    expect(fail(v({ maxLifetimeMs: 2 * DAY - 1 }))).toBe('lifetime-too-long: manifest lifetime exceeds maxLifetimeMs');
  });
  it('minVersion: refused strictly below (equal is fine) with the numbers in the reason', () => {
    expect(fail(v({ minVersion: 5 }))).toBe('ok');
    expect(fail(v({ minVersion: 6 }))).toBe('below-min-version: version 5 < minVersion 6');
  });
  it('lastSeenVersion: older is a rollback, equal with a different digest a conflict, equal with the same digest (or none) fine', () => {
    expect(fail(v({ lastSeenVersion: 6 }))).toBe('rollback: version 5 is older than last seen 6');
    expect(fail(v({ lastSeenVersion: 4 }))).toBe('ok');
    const d = (v() as { digest: string }).digest;
    expect(fail(v({ lastSeenVersion: 5, lastSeenDigest: d }))).toBe('ok');
    expect(fail(v({ lastSeenVersion: 5 }))).toBe('ok');
    expect(fail(v({ lastSeenVersion: 5, lastSeenDigest: 'x'.repeat(43) }))).toBe('conflict: same version as last seen but a different body');
  });
  it('the validity window: now + skew vs notBefore, now - skew vs expiresAt, both inclusive', () => {
    expect(fail(v({ nowMs: T0 - DAY }))).toBe('ok');
    expect(fail(v({ nowMs: T0 - DAY - 1 }))).toBe('not-yet-valid: manifest is not yet valid');
    expect(fail(v({ nowMs: T0 - DAY - 1, clockSkewMs: 1 }))).toBe('ok');
    expect(fail(v({ nowMs: T0 + DAY }))).toBe('ok');
    expect(fail(v({ nowMs: T0 + DAY + 1 }))).toBe('expired: manifest has expired');
    expect(fail(v({ nowMs: T0 + DAY + 1, clockSkewMs: 1 }))).toBe('ok');
  });
  it('issuer key expiry: refused strictly after notAfter', () => {
    const keys = { ops: { ...KEYS.ops, notAfter: T0 } };
    expect(fail(v({ issuerKeys: keys }))).toBe('ok');
    expect(fail(v({ issuerKeys: keys, nowMs: T0 + 1 }))).toBe('issuer-expired: issuer key is past its notAfter');
  });
});

describe('createAllowlistManifest / signing errors', () => {
  it('version and kind are validated with exact messages', () => {
    for (const version of [0, -1, 1.5, '1' as never]) expect(() => createAllowlistManifest(body({ version }))).toThrow('version must be a positive integer');
    expect(() => createAllowlistManifest(body({ entries: [{ kind: 'nope', value: 'ab'.repeat(48) } as never] }))).toThrow('entry 0: unknown kind');
    expect(() => createAllowlistManifest(body({ entries: [{ kind: 5, value: 'ab'.repeat(48) } as never] }))).toThrow('entry 0: unknown kind');
  });
  it('an unknown or non-string alg is refused', () => {
    const m = signed() as unknown as Record<string, unknown>;
    expect(fail(v({}, { ...m, alg: 'nope' }))).toBe('malformed: unknown signature alg');
    expect(fail(v({}, { ...m, alg: 5 }))).toBe('malformed: unknown signature alg');
  });
});
