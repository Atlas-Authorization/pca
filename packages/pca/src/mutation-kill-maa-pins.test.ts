/** Mutation-kill suite for attest-maa-pins.ts (the original attest-maa-pins.test.ts is excluded from the mutation run because it spawns the sign script). */
import { describe, expect, it } from 'vitest';
import { BUILTIN_CHAIN_LEAF_CN, BUILTIN_MAA_PINS_ISSUER_KEYS, loadBuiltinMaaPins, type BuiltinMaaPinsSource } from './attest-maa-pins';
import { BUILTIN_PINS_ISSUER_ID, BUILTIN_PINS_MANIFEST, BUILTIN_PINS_MIN_VERSION } from './attest-maa-pins.data';
import { hashCanonical, b64u } from './hash';
import { generateKeyPair } from './keys';
import { signAllowlistManifest, type AllowlistEntry, type AllowlistIssuerKey, type AllowlistManifestBody } from './attest-allowlist';

const DAY = 86_400_000;
const NB = Date.parse('2026-09-01T00:00:00Z');
const EXP = NB + 100 * DAY;
const WUS = 'https://sharedwus.wus.attest.azure.net';
const EUS = 'https://sharedeus.eus.attest.azure.net';
const H = (c: string) => c.repeat(64);
const op = generateKeyPair();
const KEYS: Record<string, AllowlistIssuerKey> = { rel: { alg: 'ed25519', keys: { edPub: b64u(op.publicKey) } } };
const entries = (over: Partial<Record<string, AllowlistEntry[]>> = {}, vantages = 3, method = 'a;b c'): AllowlistEntry[] => [
  ...(over['spki'] ?? [
    { kind: 'maa-signing-spki', value: H('1'), label: WUS },
    { kind: 'maa-signing-spki', value: H('2'), label: WUS },
    { kind: 'maa-signing-spki', value: H('3'), label: EUS },
  ]),
  ...(over['root'] ?? [{ kind: 'maa-chain-root-spki', value: H('a'), label: 'root' }]),
  ...(over['mid'] ?? [{ kind: 'maa-chain-intermediate-spki', value: H('b'), label: 'mid' }]),
  ...(over['corr'] ?? [{ kind: 'attest-corroboration', value: H('c'), label: `vantages=${vantages};method=${method}` }]),
  ...(over['extra'] ?? []),
];
const body = (o: Partial<AllowlistManifestBody> = {}): AllowlistManifestBody => ({ version: 3, issuedAt: NB, notBefore: NB, expiresAt: EXP, entries: entries(), ...o });
const sign = (b = body()) => signAllowlistManifest(b, { issuer: 'rel', alg: 'ed25519', secrets: { edSecret: op.secretKey } });
const src = (manifest: unknown, over: Partial<BuiltinMaaPinsSource> = {}): BuiltinMaaPinsSource => ({ manifest, issuerKeys: KEYS, ...over });
const NOW = NB + DAY;

describe('exports', () => {
  it('constants', () => {
    expect([...BUILTIN_CHAIN_LEAF_CN]).toEqual(['Microsoft Azure Attestation 2020']);
    expect(Object.keys(BUILTIN_MAA_PINS_ISSUER_KEYS)).toEqual([BUILTIN_PINS_ISSUER_ID]);
    expect(Object.isFrozen(BUILTIN_MAA_PINS_ISSUER_KEYS)).toBe(true);
  });
});

describe('loadBuiltinMaaPins: the shipped manifest', () => {
  it('verifies and exposes every field', () => {
    const nowMs = BUILTIN_PINS_MANIFEST.body.notBefore + DAY;
    const r = loadBuiltinMaaPins({ nowMs });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.version).toBe(BUILTIN_PINS_MANIFEST.body.version);
    expect(r.version).toBeGreaterThanOrEqual(BUILTIN_PINS_MIN_VERSION);
    expect(r.digest).toBe(hashCanonical(BUILTIN_PINS_MANIFEST.body));
    expect(r.expiresAt).toBe(BUILTIN_PINS_MANIFEST.body.expiresAt);
    expect(r.vantages).toBeGreaterThanOrEqual(3);
    expect(r.method.length).toBeGreaterThan(3);
    expect(Object.keys(r.maaSigningSpkis).length).toBeGreaterThan(0);
    expect(r.maaChainRootSpkis.length).toBeGreaterThan(0);
    expect(r.maaChainIntermediateSpkis.length).toBeGreaterThan(0);
    expect(r.revokedSigningSpkis).toBeTypeOf('object');
  });
  it('the validity window is rechecked on every call (memoised signature check)', () => {
    const b = BUILTIN_PINS_MANIFEST.body;
    expect(loadBuiltinMaaPins({ nowMs: b.notBefore }).ok).toBe(true);
    expect(loadBuiltinMaaPins({ nowMs: b.expiresAt }).ok).toBe(true);
    const early = loadBuiltinMaaPins({ nowMs: b.notBefore - 1 });
    expect(early).toEqual({ ok: false, reason: 'built-in pins are not yet valid (clock behind the release)' });
    const late = loadBuiltinMaaPins({ nowMs: b.expiresAt + 1 });
    expect(late).toEqual({ ok: false, reason: 'built-in pins expired; update the package or pass explicit initialPins' });
    expect(loadBuiltinMaaPins({ nowMs: b.notBefore + DAY }).ok).toBe(true);
  });
  it('nowMs must be a safe integer', () => {
    for (const nowMs of [1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '5' as never, undefined as never]) {
      expect(loadBuiltinMaaPins({ nowMs })).toEqual({ ok: false, reason: 'nowMs must be an integer' });
    }
  });
});

describe('loadBuiltinMaaPins: custom sources', () => {
  it('projects pins, revoked pins, chain pins, vantages and method', () => {
    const m = sign(
      body({
        entries: entries({
          extra: [
            { kind: 'maa-signing-spki', value: H('4'), label: WUS, revoked: true },
            { kind: 'maa-signing-spki', value: H('5'), label: EUS, revoked: true },
            { kind: 'maa-chain-root-spki', value: H('6'), label: 'oldroot', revoked: true },
            { kind: 'tdx-mrtd', value: 'a'.repeat(96), label: 'ignored' },
          ],
        }),
      }),
    );
    const r = loadBuiltinMaaPins({ nowMs: NOW, source: src(m) });
    expect(r).toEqual({
      ok: true,
      version: 3,
      digest: hashCanonical(m.body),
      expiresAt: EXP,
      maaSigningSpkis: { [WUS]: [H('1'), H('2')], [EUS]: [H('3')] },
      revokedSigningSpkis: { [WUS]: [H('4')], [EUS]: [H('5')] },
      maaChainRootSpkis: [H('a')],
      maaChainIntermediateSpkis: [H('b')],
      vantages: 3,
      method: 'a;b c',
    });
  });
  it('no revocations -> empty map', () => {
    const r = loadBuiltinMaaPins({ nowMs: NOW, source: src(sign()) });
    expect(r.ok && r.revokedSigningSpkis).toEqual({});
  });
  it('verification failures carry code and reason', () => {
    const m = sign();
    const forged = { ...m, body: { ...m.body, version: 4 } };
    const r = loadBuiltinMaaPins({ nowMs: NOW, source: src(forged) });
    expect(r).toEqual({ ok: false, reason: 'bad-signature: signature does not verify under the registered issuer key' });
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(null) })).toEqual({ ok: false, reason: 'malformed: manifest has an unexpected shape' });
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src({ issuer: 'rel' }) })).toMatchObject({ ok: false });
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(m, { issuerKeys: {} }) })).toEqual({ ok: false, reason: "unknown-issuer: issuer 'rel' is not registered" });
  });
  it('the signature is verified at the manifest notBefore (so a stale clock is a window error, not a signature error)', () => {
    const m = sign();
    expect(loadBuiltinMaaPins({ nowMs: EXP + 5 * DAY, source: src(m) })).toEqual({ ok: false, reason: 'built-in pins expired; update the package or pass explicit initialPins' });
    expect(loadBuiltinMaaPins({ nowMs: NB - 5 * DAY, source: src(m) })).toEqual({ ok: false, reason: 'built-in pins are not yet valid (clock behind the release)' });
    expect(loadBuiltinMaaPins({ nowMs: NB, source: src(m) }).ok).toBe(true);
    expect(loadBuiltinMaaPins({ nowMs: EXP, source: src(m) }).ok).toBe(true);
    expect(loadBuiltinMaaPins({ nowMs: EXP + 1, source: src(m) }).ok).toBe(false);
  });
  it('a manifest without a body.notBefore is verified at nowMs', () => {
    const bodyErr = 'malformed: body must be an object with exactly version/issuedAt/notBefore/expiresAt/entries';
    const shell = { issuer: 'rel', alg: 'ed25519', sig: 'x' };
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(shell) })).toEqual({ ok: false, reason: bodyErr });
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src({ ...shell, body: null }) })).toEqual({ ok: false, reason: bodyErr });
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src({ ...shell, body: { notBefore: 5, junk: 1 } }) })).toEqual({ ok: false, reason: bodyErr });
  });
  it('lifetime cap of 400 days', () => {
    const ok = sign(body({ expiresAt: NB + 400 * DAY }));
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(ok) }).ok).toBe(true);
    const long = sign(body({ expiresAt: NB + 400 * DAY + 1 }));
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(long) })).toEqual({ ok: false, reason: 'lifetime-too-long: manifest lifetime exceeds maxLifetimeMs' });
  });
  it('minVersion defaults to 1 for a custom source and is honoured', () => {
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(sign(body({ version: 1 }))) }).ok).toBe(true);
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(sign(body({ version: 3 })), { minVersion: 3 }) }).ok).toBe(true);
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(sign(body({ version: 2 })), { minVersion: 3 }) })).toEqual({ ok: false, reason: 'below-min-version: version 2 < minVersion 3' });
  });
  it('corroboration: exactly one record, at least 3 vantages', () => {
    const none = sign(body({ entries: entries({ corr: [] }) }));
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(none) })).toEqual({ ok: false, reason: 'manifest must carry exactly one attest-corroboration entry' });
    const two = sign(body({ entries: entries({ corr: [{ kind: 'attest-corroboration', value: H('c'), label: 'vantages=3;method=x' }, { kind: 'attest-corroboration', value: H('d'), label: 'vantages=4;method=y' }] }) }));
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(two) })).toEqual({ ok: false, reason: 'manifest must carry exactly one attest-corroboration entry' });
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(sign(body({ entries: entries({}, 2) }))) })).toEqual({ ok: false, reason: 'corroboration records 2 vantages < required 3' });
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(sign(body({ entries: entries({}, 1) }))) })).toEqual({ ok: false, reason: 'corroboration records 1 vantages < required 3' });
    const three = loadBuiltinMaaPins({ nowMs: NOW, source: src(sign(body({ entries: entries({}, 3) }))) });
    expect(three.ok && three.vantages).toBe(3);
    const nine = loadBuiltinMaaPins({ nowMs: NOW, source: src(sign(body({ entries: entries({}, 999, 'x') }))) });
    expect(nine.ok && nine.vantages).toBe(999);
    expect(nine.ok && nine.method).toBe('x');
  });
  it('pins required: a signing key and both chain pins', () => {
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(sign(body({ entries: entries({ spki: [] }) }))) })).toEqual({ ok: false, reason: 'manifest pins no MAA signing key' });
    const chain = 'manifest lacks the Microsoft chain root / intermediate pins';
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(sign(body({ entries: entries({ root: [] }) }))) })).toEqual({ ok: false, reason: chain });
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(sign(body({ entries: entries({ mid: [] }) }))) })).toEqual({ ok: false, reason: chain });
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(sign(body({ entries: entries({ root: [], mid: [] }) }))) })).toEqual({ ok: false, reason: chain });
  });
  it('a revoked signing key does not count as a pinned key', () => {
    const only = sign(body({ entries: entries({ spki: [{ kind: 'maa-signing-spki', value: H('1'), label: WUS, revoked: true }] }) }));
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: src(only) })).toEqual({ ok: false, reason: 'manifest pins no MAA signing key' });
  });
  it('per-entry expiry is evaluated at the manifest notBefore, not at the caller clock', () => {
    const m = sign(body({ entries: entries({ spki: [{ kind: 'maa-signing-spki', value: H('1'), label: WUS, notAfter: NB }] }) }));
    const r = loadBuiltinMaaPins({ nowMs: NOW, source: src(m) });
    expect(r.ok && r.maaSigningSpkis).toEqual({ [WUS]: [H('1')] });
  });
  it('per-entry notAfter earlier than the manifest notBefore drops that pin (evaluated at notBefore)', () => {
    const m = sign(body({ entries: entries({ spki: [{ kind: 'maa-signing-spki', value: H('1'), label: WUS, notAfter: NB - 1 }, { kind: 'maa-signing-spki', value: H('2'), label: WUS }] }) }));
    const r = loadBuiltinMaaPins({ nowMs: NOW, source: src(m) });
    expect(r.ok && r.maaSigningSpkis).toEqual({ [WUS]: [H('2')] });
  });
  it('the signature check is memoised per source object; failures are memoised too', () => {
    const m = sign();
    let reads = 0;
    const counting: BuiltinMaaPinsSource = {
      get manifest() {
        reads++;
        return m;
      },
      issuerKeys: KEYS,
    };
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: counting }).ok).toBe(true);
    const after1 = reads;
    expect(after1).toBeGreaterThan(0);
    expect(loadBuiltinMaaPins({ nowMs: NOW + 1, source: counting }).ok).toBe(true);
    expect(loadBuiltinMaaPins({ nowMs: EXP + 1, source: counting }).ok).toBe(false);
    expect(reads).toBe(after1);
    // a different source object is evaluated afresh
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: { manifest: m, issuerKeys: KEYS } }).ok).toBe(true);
    // failure memoised: second call returns the identical failure without re-reading
    let reads2 = 0;
    const failing: BuiltinMaaPinsSource = {
      get manifest() {
        reads2++;
        return null;
      },
      issuerKeys: KEYS,
    };
    const f1 = loadBuiltinMaaPins({ nowMs: NOW, source: failing });
    const n = reads2;
    const f2 = loadBuiltinMaaPins({ nowMs: NOW, source: failing });
    expect(f1.ok).toBe(false);
    expect(f2).toEqual(f1);
    expect(reads2).toBe(n);
  });
  it('never throws: an exploding source becomes a reason', () => {
    const boom: BuiltinMaaPinsSource = {
      get manifest(): unknown {
        throw new Error('kaput');
      },
      issuerKeys: KEYS,
    };
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: boom })).toEqual({ ok: false, reason: 'kaput' });
    const weird: BuiltinMaaPinsSource = {
      get manifest(): unknown {
        throw 'str';
      },
      issuerKeys: KEYS,
    };
    expect(loadBuiltinMaaPins({ nowMs: NOW, source: weird })).toEqual({ ok: false, reason: 'built-in pins error' });
  });
});
