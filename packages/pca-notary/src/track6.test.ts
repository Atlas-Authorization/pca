import { describe, expect, it } from 'vitest';
import { generateKeyPair, b64u } from '@atlasauth/pca';
import {
  type NotaryAttestation,
  type NotaryKeyring,
  discloseField,
  evaluateAttestedFactCaveat,
  notarizeResponse,
  notaryKeyUsable,
  requireAttestedFact,
  verifyDisclosedField,
} from './index';

const NOW = 1_800_000_000_000;
const URL = 'https://api.shop.example/orders/42';
const body = { order: { id: 42, status: 'shipped', total: 1999 }, customer: { email: 'alice@example.com' } };
const run = (notaryKey = generateKeyPair(), observedAt = NOW) => {
  const r = notarizeResponse({ request: { method: 'GET', url: URL }, response: { status: 200, body } }, { notaryKey, observedAt });
  return { notaryKey, ...r };
};
const caveatFor = (k: ReturnType<typeof generateKeyPair>) => requireAttestedFact({ notary: k, path: ['order', 'status'], equals: 'shipped' });

describe('notary-trusted label', () => {
  it('an admitted fact is labelled notary-trusted; a refusal carries no trust label', () => {
    const { notaryKey, attestation, witness } = run();
    const d = discloseField(attestation, witness, ['order', 'status']);
    expect(evaluateAttestedFactCaveat(caveatFor(notaryKey), { attestation, disclosure: d })).toEqual({ ok: true, trust: 'notary-trusted' });
    const bad = evaluateAttestedFactCaveat(caveatFor(generateKeyPair()), { attestation, disclosure: d });
    expect(bad.ok).toBe(false);
    expect(bad.trust).toBeUndefined();
  });
});

describe('freshness', () => {
  const { notaryKey, attestation, witness } = run();
  const d = discloseField(attestation, witness, ['order', 'status']);
  const ev = (now: number, maxAgeMs: number) => evaluateAttestedFactCaveat(caveatFor(notaryKey), { attestation, disclosure: d }, { now, maxAgeMs });
  it('admits within the window, exactly at the edge', () => {
    expect(ev(NOW + 1000, 1000).ok).toBe(true);
  });
  it('refuses one ms past the window and an attestation from the future', () => {
    expect(ev(NOW + 1001, 1000)).toEqual({ ok: false, reason: 'attestation is stale or from the future' });
    expect(ev(NOW - 1, 1000)).toEqual({ ok: false, reason: 'attestation is stale or from the future' });
  });
  it('a NaN maxAge fails closed', () => {
    expect(ev(NOW, NaN).ok).toBe(false);
  });
});

describe('key rotation and revocation (keyring)', () => {
  const old = generateKeyPair();
  const next = generateKeyPair();
  const oldPub = b64u(old.publicKey);
  const nextPub = b64u(next.publicKey);
  const ring: NotaryKeyring = [
    { key: oldPub, notAfter: NOW + 1000 },
    { key: nextPub, notBefore: NOW + 1000 },
  ];
  const check = (k: ReturnType<typeof generateKeyPair>, observedAt: number, keyring: NotaryKeyring) => {
    const { attestation, witness } = run(k, observedAt);
    const d = discloseField(attestation, witness, ['order', 'status']);
    return evaluateAttestedFactCaveat(caveatFor(k), { attestation, disclosure: d }, { keyring });
  };
  it('each key is trusted only inside its window (rotation boundary is half-open)', () => {
    expect(check(old, NOW, ring).ok).toBe(true);
    expect(check(old, NOW + 1000, ring).ok).toBe(false);
    expect(check(next, NOW + 999, ring).ok).toBe(false);
    expect(check(next, NOW + 1000, ring).ok).toBe(true);
  });
  it('an unlisted key is refused with the exact reason', () => {
    expect(check(generateKeyPair(), NOW, ring)).toEqual({ ok: false, reason: 'notary key is not trusted for this observation time (unlisted, revoked or out of window)' });
  });
  it('a revoked key is refused for any observation time, including backdated ones', () => {
    const revoked = [{ key: oldPub, revoked: true }];
    expect(check(old, NOW - 10_000, revoked).ok).toBe(false);
    expect(check(old, NOW, revoked).ok).toBe(false);
  });
  it('a revoked duplicate entry wins over a live one', () => {
    expect(notaryKeyUsable([{ key: 'k' }, { key: 'k', revoked: true }], 'k', 5)).toBe(false);
  });
  it('a malformed ring or observation time fails closed', () => {
    expect(notaryKeyUsable(undefined as never, 'k', 5)).toBe(false);
    expect(notaryKeyUsable([{ key: 'k' }], 'k', NaN)).toBe(false);
  });
  it('without a keyring the signer is trusted via the caveat key only (unchanged)', () => {
    const { attestation, witness } = run(old);
    const d = discloseField(attestation, witness, ['order', 'status']);
    expect(evaluateAttestedFactCaveat(caveatFor(old), { attestation, disclosure: d }).ok).toBe(true);
  });
});

describe('selective redaction', () => {
  const { notaryKey, attestation, witness } = run();
  const d = discloseField(attestation, witness, ['order', 'status']);
  it('disclosure and attestation leak none of the other values or salts', () => {
    const wire = JSON.stringify({ attestation, d });
    for (const hidden of ['alice@example.com', '1999', ...witness.leaves.filter((l) => l.path[1] !== 'status' || l.path[0] !== 'order').map((l) => l.salt)]) {
      expect(wire).not.toContain(hidden);
    }
    expect(wire).toContain('shipped');
  });
  it('two notarizations of the same body commit to different roots (hiding salts)', () => {
    expect(run(notaryKey).attestation.session.responseBodyCommit.root).not.toBe(attestation.session.responseBodyCommit.root);
  });
  it('a disclosure of one field cannot be re-labelled as another path', () => {
    expect(verifyDisclosedField(attestation, { ...d, path: ['order', 'total'] }, { notaryKey })).toBe(false);
    expect(verifyDisclosedField(attestation, d, { notaryKey })).toBe(true);
  });
  it('a disclosure from another attestation of the same body does not verify under this one', () => {
    const other = run(notaryKey);
    const od = discloseField(other.attestation, other.witness, ['order', 'status']);
    expect(verifyDisclosedField(attestation, od, { notaryKey })).toBe(false);
  });
  it('a truncated or reordered proof fails', () => {
    expect(verifyDisclosedField(attestation, { ...d, proof: { ...d.proof, path: d.proof.path.slice(1) } }, { notaryKey })).toBe(false);
    expect(verifyDisclosedField(attestation, { ...d, proof: undefined as never }, { notaryKey })).toBe(false);
  });
  it('an attestation with a malformed session is refused', () => {
    const bad = { ...attestation, session: { ...attestation.session, observedAt: 1.5 } } as NotaryAttestation;
    expect(verifyDisclosedField(bad, d, { notaryKey })).toBe(false);
  });
});
