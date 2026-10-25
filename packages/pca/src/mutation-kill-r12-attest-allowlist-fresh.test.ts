/**
 * 0.4.2 r12 mutation kills: the value patterns (HEX96, HEX64, IMAGE_DIGEST, DRIVER_VERSION, CORROBORATION_LABEL, ISSUER_URL)
 * and the ENTRY_KEYS member list of attest-allowlist.ts are module-level constants, built once when the module is first
 * imported. Under Stryker's mutant switching that import happens before any mutant is active, so the statically-importing
 * allowlist tests never saw these mutants. Each test here re-evaluates the module (vi.resetModules + dynamic import) and
 * drives the exported validator (createAllowlistManifest, which throws on the first violation) with valid and invalid values.
 */
import { describe, expect, it, vi } from 'vitest';

const H96 = 'ab'.repeat(48);
const H64 = 'cd'.repeat(32);

async function fresh() {
  vi.resetModules();
  const m = await import('./attest-allowlist');
  /** Validate a one-entry body; returns null when accepted, else the thrown message. */
  const check = (entry: Record<string, unknown>): string | null => {
    try {
      m.createAllowlistManifest({ version: 1, issuedAt: 0, notBefore: 0, expiresAt: 1000, entries: [entry] } as never);
      return null;
    } catch (e) {
      return (e as Error).message;
    }
  };
  const one = (kind: string, value: string, label = 'l') => check({ kind, value, label });
  return { m, check, one };
}

describe('96-hex measurement pattern (fresh module)', () => {
  it('accepts exactly 96 lowercase hex chars, anchored at both ends', async () => {
    const { one } = await fresh();
    for (const k of ['tdx-mrtd', 'tdx-rtmr', 'sev-snp-measurement', 'nvidia-measurement']) {
      expect(one(k, H96)).toBeNull();
      expect(one(k, `x${H96}`)).toBe(`entry 0: ${k} must be 96 lowercase hex chars`);
      expect(one(k, `${H96}x`)).toBe(`entry 0: ${k} must be 96 lowercase hex chars`);
      expect(one(k, `a${H96}`)).toBe(`entry 0: ${k} must be 96 lowercase hex chars`);
    }
  });
});

describe('64-hex SPKI pattern (fresh module)', () => {
  it('is anchored at both ends', async () => {
    const { one } = await fresh();
    for (const k of ['maa-chain-root-spki', 'maa-chain-intermediate-spki']) {
      expect(one(k, H64)).toBeNull();
      expect(one(k, `x${H64}`)).toBe(`entry 0: ${k} must be 64 lowercase hex chars`);
      expect(one(k, `${H64}x`)).toBe(`entry 0: ${k} must be 64 lowercase hex chars`);
    }
    expect(one('maa-signing-spki', `x${H64}`, 'https://a.example')).toBe('entry 0: maa-signing-spki must be 64 lowercase hex chars');
    expect(one('maa-signing-spki', `${H64}x`, 'https://a.example')).toBe('entry 0: maa-signing-spki must be 64 lowercase hex chars');
  });
});

describe('gcp image digest pattern (fresh module)', () => {
  it('is sha256:<64 lowercase hex>, anchored at both ends', async () => {
    const { one } = await fresh();
    const msg = 'entry 0: gcp-image-digest must be sha256:<64 lowercase hex>';
    expect(one('gcp-image-digest', `sha256:${H64}`)).toBeNull();
    expect(one('gcp-image-digest', `xsha256:${H64}`)).toBe(msg);
    expect(one('gcp-image-digest', `sha256:${H64}x`)).toBe(msg);
    expect(one('gcp-image-digest', 'sha256:a')).toBe(msg);
  });
});

describe('nvidia driver version pattern (fresh module)', () => {
  const msg = 'entry 0: nvidia-driver-version must be a dotted version of at most 16 chars';
  it('accepts 2..4 dotted components of 1..6 digits', async () => {
    const { one } = await fresh();
    expect(one('nvidia-driver-version', '535.10')).toBeNull();
    expect(one('nvidia-driver-version', '535.104.05')).toBeNull();
    expect(one('nvidia-driver-version', '1.2.3.4')).toBeNull();
    expect(one('nvidia-driver-version', '123456.1')).toBeNull();
  });
  it('rejects a prefix, a suffix, a non-digit and a missing component', async () => {
    const { one } = await fresh();
    expect(one('nvidia-driver-version', 'x535.10')).toBe(msg);
    expect(one('nvidia-driver-version', '535.10x')).toBe(msg);
    expect(one('nvidia-driver-version', 'a.10')).toBe(msg);
    expect(one('nvidia-driver-version', '535.x')).toBe(msg);
    expect(one('nvidia-driver-version', '535')).toBe(msg);
    expect(one('nvidia-driver-version', '1.2.3.4.5')).toBe(msg);
  });
});

describe('corroboration label pattern (fresh module)', () => {
  const msg = 'entry 0: attest-corroboration label must be vantages=<n>;method=<text>';
  it('accepts vantages=<1..999>;method=<printable ASCII>', async () => {
    const { one } = await fresh();
    expect(one('attest-corroboration', H64, 'vantages=3;method=quorum')).toBeNull();
    expect(one('attest-corroboration', H64, 'vantages=12;method=quorum')).toBeNull();
    expect(one('attest-corroboration', H64, 'vantages=999;method=a b')).toBeNull();
  });
  it('rejects a prefix and a non-ASCII tail', async () => {
    const { one } = await fresh();
    expect(one('attest-corroboration', H64, 'xvantages=3;method=quorum')).toBe(msg);
    expect(one('attest-corroboration', H64, 'vantages=3;method=quoré')).toBe(msg);
    expect(one('attest-corroboration', H64, 'vantages=1x;method=quorum')).toBe(msg);
  });
});

describe('MAA issuer URL label pattern (fresh module)', () => {
  const msg = 'entry 0: maa-signing-spki label must be the https issuer URL (no path, no trailing slash)';
  it('accepts an https origin with a one-char or dotted host and an optional 1..5 digit port', async () => {
    const { one } = await fresh();
    expect(one('maa-signing-spki', H64, 'https://a')).toBeNull();
    expect(one('maa-signing-spki', H64, 'https://sharedeus.eus.attest.azure.net')).toBeNull();
    expect(one('maa-signing-spki', H64, 'https://a.example:443')).toBeNull();
    expect(one('maa-signing-spki', H64, 'https://a.example:65535')).toBeNull();
  });
  it('rejects a prefix, a path, a trailing slash and a bad port', async () => {
    const { one } = await fresh();
    expect(one('maa-signing-spki', H64, 'xhttps://a.example')).toBe(msg);
    expect(one('maa-signing-spki', H64, 'https://a.example/')).toBe(msg);
    expect(one('maa-signing-spki', H64, 'https://a.example/x')).toBe(msg);
    expect(one('maa-signing-spki', H64, 'https://a.example:')).toBe(msg);
    expect(one('maa-signing-spki', H64, 'https://a.example:ab')).toBe(msg);
    expect(one('maa-signing-spki', H64, 'https://a.example:123456')).toBe(msg);
  });
});

describe('entry member set (fresh module)', () => {
  it('notAfter and revoked are allowed entry members and are carried through', async () => {
    const { m, check } = await fresh();
    expect(check({ kind: 'tdx-mrtd', value: H96, label: 'l', notAfter: 500 })).toBeNull();
    expect(check({ kind: 'tdx-mrtd', value: H96, label: 'l', revoked: true })).toBeNull();
    expect(check({ kind: 'tdx-mrtd', value: H96, label: 'l', other: 1 })).toBe('entry 0: unexpected shape');
    const b = m.createAllowlistManifest({ version: 1, issuedAt: 0, notBefore: 0, expiresAt: 1000, entries: [{ kind: 'tdx-mrtd', value: H96, label: 'l', notAfter: 500, revoked: true }] });
    expect(b.entries).toStrictEqual([{ kind: 'tdx-mrtd', value: H96, label: 'l', notAfter: 500, revoked: true }]);
  });
});
