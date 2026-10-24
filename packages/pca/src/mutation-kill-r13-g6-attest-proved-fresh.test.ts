/**
 * r13 mutation kills for attest-proved.ts module-level constants (static mutants): the attestation signing domain, the
 * durable high-water-mark digest pattern, the anchored feed-entry digest pattern, and the isRec / afail helpers. Each
 * test re-evaluates the module graph (vi.resetModules + dynamic import).
 */
import { describe, expect, it, vi } from 'vitest';
import { b64u, canonicalBytes, utf8 } from './hash';
import { encodeKey, generateKeyPair, sign } from './keys';

async function fresh() {
  vi.resetModules();
  const attestation = await import('./attestation');
  const allowlist = await import('./attest-allowlist');
  const anchor = await import('./attest-allowlist-anchor');
  const durable = await import('./durable-state');
  const ledger = await import('./ledger');
  return { attestation, allowlist, anchor, durable, ledger };
}

const T = 5_000_000;
const NONCE = 'q3Vx8mZ0aT7bLk2RwYp9Hs';
const att = generateKeyPair();
const ATT_PUB = encodeKey(att.publicKey);
const NOW = Date.parse('2026-10-09T00:00:00Z');
const DAY = 86_400_000;
const ops = generateKeyPair();
const guardian = generateKeyPair();

describe('attestation signing domain (fresh module)', () => {
  it("a document signed over 'atlas-pca/attest/v1\\0' || canonical(body) verifies", async () => {
    const { attestation } = await fresh();
    const expected = { holderPub: 'h', grantRef: 'g', epoch: 1, nonce: NONCE };
    const b = { model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o', nonce: NONCE, issued_at: T - 1000, expires_at: T + 1000, attestor: ATT_PUB, mode: 'software', binding: attestation.attestationBindingB64u(expected) };
    const m = canonicalBytes(b);
    const p = utf8('atlas-pca/attest/v1\0');
    const msg = new Uint8Array(p.length + m.length);
    msg.set(p);
    msg.set(m, p.length);
    const document = { ...b, sig: b64u(sign(att.secretKey, msg)) } as never;
    const ctx = { pcactn: { grant_ref: 'g', attestation: { epoch: 1, quote_digest: NONCE } } } as never;
    const v = await attestation.verifyAttestation({ document, ctx, expected, nowMs: T, trustedAttestorKeys: [ATT_PUB] });
    expect(v).toMatchObject({ ok: true, present: true, bound: true });
  });
});

describe('durable high-water mark digest pattern and helpers (fresh module)', () => {
  const setup = async () => {
    const f = await fresh();
    const keys = { ops: { alg: 'ed25519' as const, keys: { edPub: b64u(ops.publicKey) } } };
    const signed = (version: number) =>
      f.allowlist.signAllowlistManifest({ version, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + 30 * DAY, entries: [{ kind: 'tdx-mrtd', value: 'ab'.repeat(48), label: `v${version}` }] }, { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: ops.secretKey } });
    const withStored = async (stored: unknown) => {
      const kv = f.durable.createMemoryDurableKv();
      await kv.set('allowlist/ops', stored);
      return f.allowlist.verifyAllowlistDurable(signed(2), { issuerKeys: keys, nowMs: NOW }, kv);
    };
    return { f, keys, signed, withStored };
  };
  const corrupt = { ok: false, code: 'malformed', reason: 'persisted allowlist high-water mark is corrupt' };
  it('a stored 43-character b64u digest is a valid mark; anything else is corrupt', async () => {
    const { withStored } = await setup();
    expect(await withStored({ version: 1, digest: 'A'.repeat(43) })).toMatchObject({ ok: true, version: 2 });
    expect(await withStored({ version: 1, digest: 'A'.repeat(44) })).toEqual(corrupt);
    expect(await withStored({ version: 1, digest: '!' + 'A'.repeat(43) })).toEqual(corrupt);
  });
  it('a fresh store accepts and records the mark; a non-string issuer is malformed with its exact reason', async () => {
    const { f, keys, signed } = await setup();
    const kv = f.durable.createMemoryDurableKv();
    expect(await f.allowlist.verifyAllowlistDurable(signed(1), { issuerKeys: keys, nowMs: NOW }, kv)).toMatchObject({ ok: true, version: 1 });
    expect(await f.allowlist.verifyAllowlistDurable({ ...signed(1), issuer: 5 }, { issuerKeys: keys, nowMs: NOW }, kv)).toEqual({ ok: false, code: 'malformed', reason: 'issuer must be a string' });
  });
});

describe('anchored feed-entry digest pattern (fresh module)', () => {
  it('a 43-character b64u digest is a valid entry; a 44-character or prefixed one is malformed', async () => {
    const { anchor, ledger } = await fresh();
    const trust = { logKey: b64u(guardian.publicKey), instanceId: 'inst-1', principal: 'allowlist-log' };
    const mk = (es: { issuer: string; version: number; digest: string }[]) => {
      const l = ledger.TransparencyLedger.fromEntries(es.map((e) => ({ commit: anchor.allowlistAnchorCommit(e) })), trust.principal);
      const head = ledger.signTreeHead(guardian.secretKey, { instance_id: trust.instanceId, principal: trust.principal, size: es.length, root: l.head().root, prev_root: '', timestamp: NOW });
      return { head, entries: es, proof: l.inclusionProof(0) };
    };
    const why = (e: { issuer: string; version: number; digest: string }) => {
      const r = anchor.verifyAllowlistAnchored({ ok: true, ...e } as never, mk([e]), { trust, nowMs: NOW });
      return r.ok ? 'ok' : `${r.code}: ${r.reason}`;
    };
    expect(why({ issuer: 'ops', version: 1, digest: 'A'.repeat(43) })).toBe('ok');
    expect(why({ issuer: 'ops', version: 1, digest: 'A'.repeat(44) })).toBe('feed-mismatch: entries do not match the signed tree size');
    expect(why({ issuer: 'ops', version: 1, digest: '!' + 'A'.repeat(43) })).toBe('feed-mismatch: entries do not match the signed tree size');
  });
});
