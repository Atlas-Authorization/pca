/**
 * Fail-closed table for the signed allowlist manifest and its durable rollback state: "missing / invalid X => exact
 * result" (the whole result, code and reason). A row that stops denying, or denies for another reason, fails.
 */
import { describe, expect, it } from 'vitest';
import {
  type AllowlistIssuerKey, type AllowlistManifestBody, type VerifyAllowlistOptions,
  signAllowlistManifest, verifyAllowlistManifest, verifyAllowlistDurable,
} from './attest-allowlist';
import { generateKeyPair } from './keys';
import { b64u } from './hash';
import { createMemoryDurableKv } from './durable-state';

const T0 = Date.parse('2026-10-09T00:00:00Z');
const DAY = 86_400_000;
const ed = generateKeyPair();
const other = generateKeyPair();
const KEYS: Record<string, AllowlistIssuerKey> = { ops: { alg: 'ed25519', keys: { edPub: b64u(ed.publicKey) } } };
const body = (over: Partial<AllowlistManifestBody> = {}): AllowlistManifestBody => ({
  version: 5, issuedAt: T0 - DAY, notBefore: T0 - DAY, expiresAt: T0 + 7 * DAY,
  entries: [{ kind: 'tdx-mrtd', value: 'ab'.repeat(48), label: 'prod image' }], ...over,
});
const sign = (b = body(), secret = ed.secretKey) => signAllowlistManifest(b, { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: secret } });
const opts = (over: Partial<VerifyAllowlistOptions> = {}): VerifyAllowlistOptions => ({ issuerKeys: KEYS, nowMs: T0, ...over });
const bad = (code: string, reason: string) => ({ ok: false, code, reason });
const m = sign();

describe('verifyAllowlistManifest: missing or invalid X => exact result', () => {
  const rows: Array<[string, () => unknown, unknown]> = [
    ['a non-object manifest', () => verifyAllowlistManifest('x', opts()), bad('malformed', 'manifest has an unexpected shape')],
    ['an array manifest', () => verifyAllowlistManifest([], opts()), bad('malformed', 'manifest has an unexpected shape')],
    ['an extra top-level field', () => verifyAllowlistManifest({ ...m, extra: 1 }, opts()), bad('malformed', 'manifest has an unexpected shape')],
    ['no issuer keys registered for the issuer', () => verifyAllowlistManifest(m, opts({ issuerKeys: {} })), bad('unknown-issuer', "issuer 'ops' is not registered")],
    ['an inherited property name as issuer (prototype pollution probe)', () => verifyAllowlistManifest({ ...m, issuer: 'toString' }, opts()), bad('unknown-issuer', "issuer 'toString' is not registered")],
    ['registered for another algorithm', () => verifyAllowlistManifest(m, opts({ issuerKeys: { ops: { alg: 'ml-dsa-65', keys: { mlDsaPub: 'x' } } } })), bad('alg-mismatch', "issuer is registered for 'ml-dsa-65', manifest claims 'ed25519'")],
    ['an unknown algorithm', () => verifyAllowlistManifest({ ...m, alg: 'rot13' }, opts()), bad('malformed', 'unknown signature alg')],
    ['signed by another key', () => verifyAllowlistManifest(sign(body(), other.secretKey), opts()), bad('bad-signature', 'signature does not verify under the registered issuer key')],
    ['body edited after signing', () => verifyAllowlistManifest({ ...m, body: { ...m.body, version: 6 } }, opts()), bad('bad-signature', 'signature does not verify under the registered issuer key')],
    ['a missing signature', () => verifyAllowlistManifest({ ...m, sig: undefined }, opts()), bad('malformed', 'sig must be a string')],
    ['a pq_sig on an Ed25519 manifest', () => verifyAllowlistManifest({ ...m, pq_sig: 'x' }, opts()), bad('malformed', 'pq_sig presence does not match the suite')],
    ['the issuer key is past its notAfter', () => verifyAllowlistManifest(m, opts({ issuerKeys: { ops: { ...KEYS.ops!, notAfter: T0 - 1 } } })), bad('issuer-expired', 'issuer key is past its notAfter')],
    ['not yet valid', () => verifyAllowlistManifest(sign(body({ notBefore: T0 + 1 })), opts()), bad('not-yet-valid', 'manifest is not yet valid')],
    ['expired', () => verifyAllowlistManifest(sign(body({ expiresAt: T0 - 1 })), opts()), bad('expired', 'manifest has expired')],
    ['clock skew widens the window by exactly the skew (still expired one ms beyond)', () => verifyAllowlistManifest(sign(body({ expiresAt: T0 - 1001 })), opts({ clockSkewMs: 1000 })), bad('expired', 'manifest has expired')],
    ['a NaN clock skew is refused, not treated as no skew', () => verifyAllowlistManifest(m, opts({ clockSkewMs: NaN })), bad('malformed', 'clockSkewMs must be a finite number')],
    ['a NaN maxLifetimeMs', () => verifyAllowlistManifest(m, opts({ maxLifetimeMs: NaN })), bad('malformed', 'maxLifetimeMs must be a finite number')],
    ['a fractional minVersion', () => verifyAllowlistManifest(m, opts({ minVersion: 1.5 })), bad('malformed', 'minVersion must be an integer')],
    ['a fractional lastSeenVersion', () => verifyAllowlistManifest(m, opts({ lastSeenVersion: 1.5 })), bad('malformed', 'lastSeenVersion must be an integer')],
    ['lifetime longer than allowed', () => verifyAllowlistManifest(m, opts({ maxLifetimeMs: DAY })), bad('lifetime-too-long', 'manifest lifetime exceeds maxLifetimeMs')],
    ['below the shipped minimum version', () => verifyAllowlistManifest(m, opts({ minVersion: 6 })), bad('below-min-version', 'version 5 < minVersion 6')],
    ['older than the last seen version (rollback)', () => verifyAllowlistManifest(m, opts({ lastSeenVersion: 6 })), bad('rollback', 'version 5 is older than last seen 6')],
    ['same version, different body (conflict)', () => verifyAllowlistManifest(m, opts({ lastSeenVersion: 5, lastSeenDigest: 'other' })), bad('conflict', 'same version as last seen but a different body')],
    ['a non-integer clock', () => verifyAllowlistManifest(m, opts({ nowMs: 1.5 })), bad('malformed', 'nowMs must be an integer')],
    ['an entry with an uppercase measurement', () => verifyAllowlistManifest({ ...m, body: { ...m.body, entries: [{ kind: 'tdx-mrtd', value: 'AB'.repeat(48), label: 'x' }] } }, opts()), bad('malformed', 'entry 0: tdx-mrtd must be 96 lowercase hex chars')],
    ['an unknown entry kind', () => verifyAllowlistManifest({ ...m, body: { ...m.body, entries: [{ kind: 'trust-me', value: 'x', label: 'x' }] } }, opts()), bad('malformed', 'entry 0: unknown kind')],
    ['an extra body field', () => verifyAllowlistManifest({ ...m, body: { ...m.body, extra: 1 } }, opts()), bad('malformed', 'body must be an object with exactly version/issuedAt/notBefore/expiresAt/entries')],
    ['version 0', () => verifyAllowlistManifest({ ...m, body: { ...m.body, version: 0 } }, opts()), bad('malformed', 'version must be a positive integer')],
    ['a window that ends before it starts', () => verifyAllowlistManifest({ ...m, body: { ...m.body, notBefore: T0, expiresAt: T0 - 1 } }, opts()), bad('malformed', 'notBefore must be before expiresAt')],
  ];
  it.each(rows)('%s', (_n, run, want) => {
    expect(run()).toEqual(want);
  });

  it('the baseline verifies and returns the digest and version', () => {
    const r = verifyAllowlistManifest(m, opts());
    expect(r).toMatchObject({ ok: true, issuer: 'ops', alg: 'ed25519', version: 5 });
  });
});

describe('verifyAllowlistDurable: missing or corrupt state => exact result', () => {
  it('a fresh store accepts, then refuses an older manifest and a same-version different body', async () => {
    const kv = createMemoryDurableKv();
    const first = await verifyAllowlistDurable(m, { issuerKeys: KEYS, nowMs: T0 }, kv);
    expect(first.ok).toBe(true);
    const older = await verifyAllowlistDurable(sign(body({ version: 4 })), { issuerKeys: KEYS, nowMs: T0 }, kv);
    expect(older).toEqual(bad('rollback', 'version 4 is older than last seen 5'));
    const forked = await verifyAllowlistDurable(sign(body({ entries: [{ kind: 'tdx-mrtd', value: 'cd'.repeat(48), label: 'other' }] })), { issuerKeys: KEYS, nowMs: T0 }, kv);
    expect(forked).toEqual(bad('conflict', 'same version as last seen but a different body'));
  });
});
