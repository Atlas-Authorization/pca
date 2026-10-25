/**
 * r13 mutation kills for attestation.ts: the module-level domains and limits (fresh module, pinned against
 * independent values and an independent Ed25519 check of a dev-attestor signature), createDevAttestor without a suite,
 * the memory nonce store's re-consume ordering (an aged-out nonce must move to the end of the eviction order), and
 * anchorAttestationEvidence's clock / signing-error paths.
 */
import { describe, expect, it, vi } from 'vitest';
import { canonicalBytes, utf8 } from './hash';
import { verifyB64u } from './keys';

async function fresh() {
  vi.resetModules();
  return import('./attestation');
}
const SECRET = new Uint8Array(32).fill(3);
const claims = { model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o', nonce: 'n1', issued_at: 1, expires_at: 2 };

describe('attestation constants (fresh module)', () => {
  it('pins the exported domains and limits', async () => {
    const m = await fresh();
    expect(m.ATTEST_BIND_DOMAIN).toBe('atlas-pca/attest-bind/v1\0');
    expect(m.MAX_ATTESTATION_AGE_MS).toBe(300_000);
    expect(m.DEFAULT_NONCE_RETENTION_MS).toBe(3_600_000);
    expect(m.ATTEST_ANCHOR_DOMAIN).toBe('atlas-pca/attest-anchor/v1\0');
  });
  it('a dev attestor signs utf8("atlas-pca/attest/v1\\0") || canonical(body)', async () => {
    const m = await fresh();
    const a = m.createDevAttestor(SECRET);
    const doc = a.attest(claims);
    const { sig, ...body } = doc as unknown as { sig: string } & Record<string, unknown>;
    const d = canonicalBytes(body);
    const p = utf8('atlas-pca/attest/v1\0');
    const msg = new Uint8Array(p.length + d.length);
    msg.set(p);
    msg.set(d, p.length);
    expect(verifyB64u(a.publicKey, msg, sig)).toBe(true);
  });
  it('the default retention keeps a nonce for exactly one hour', async () => {
    const m = await fresh();
    let t = 0;
    const s = m.memoryNonceStore(10, { now: () => t });
    expect(s.consume('x')).toBe(true);
    t = 3_599_999;
    expect(s.consume('x')).toBe(false);
    t = 3_600_000;
    expect(s.consume('x')).toBe(true);
  });
});

describe('memoryNonceStore re-consume order', () => {
  it('an aged-out nonce consumed again moves behind older live entries', async () => {
    const m = await fresh();
    let t = 0;
    const s = m.memoryNonceStore(3, { retentionMs: 10, now: () => t });
    expect(s.consume('a')).toBe(true); // a@0
    t = 5;
    expect(s.consume('b')).toBe(true); // b@5
    t = 20;
    expect(s.consume('a')).toBe(true); // aged out: a@20, now after b
    t = 21;
    expect(s.consume('c')).toBe(true); // c@21, store full (b, a, c)
    t = 22;
    expect(s.consume('d')).toBe(true); // b@5 aged out is evicted first, making room
  });
});

describe('anchorAttestationEvidence', () => {
  const ev = {
    identity: { model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o', verifiedAt: 1 },
    binding: { holderPub: 'h', grantRef: 'g', epoch: 1, nonce: 'n' },
    verifiedAt: 1,
  } as never;
  it('does not read the clock when there is no guardian secret', async () => {
    const m = await fresh();
    const now = vi.fn(() => 5);
    const r = m.anchorAttestationEvidence(ev, { ledger: new (await import('./ledger')).TransparencyLedger('p'), now });
    expect(now).not.toHaveBeenCalled();
    expect(r.sth).toBeUndefined();
  });
  it('a non-Error signing failure is reported as unknown when anchoring is required', async () => {
    const m = await fresh();
    const opts = {
      ledger: new (await import('./ledger')).TransparencyLedger('p'),
      guardianSecret: SECRET,
      required: true,
      now: () => 5,
      get suite(): never {
        throw 'boom';
      },
    };
    expect(() => m.anchorAttestationEvidence(ev, opts as never)).toThrow(new Error('attestation anchoring (fail closed): tree-head signing failed: unknown'));
  });
});
