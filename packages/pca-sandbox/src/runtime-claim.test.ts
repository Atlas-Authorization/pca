import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import { authFixture, claimFixture } from './test-auth';
import { HandleTable, ReceiptLog, createSandbox, signRuntimeClaim, verifiedRuntimeClass, passportDigest, trustFromAttestation, evidenceDigest } from './index';

const op = { verb: 'notes.read', resource: 'notes', params: { id: 'n-7' } };

describe('runtime class is evidence, not an operator claim', () => {
  it('a valid claim proves its class', () => {
    for (const c of ['none', 'os_confined', 'egress_default_deny', 'wasi_no_ambient'] as const) {
      const f = claimFixture(c);
      expect(verifiedRuntimeClass(f.claim, f.trust)).toBe(c);
    }
  });

  it('everything that does not verify is none', () => {
    const f = claimFixture();
    const t = f.trust;
    const bad: [string, unknown, Partial<typeof t>?][] = [
      ['undefined', undefined],
      ['null', null],
      ['string', 'wasi_no_ambient'],
      ['wrong version', { ...f.claim, v: 2 }],
      ['unknown class', { ...f.claim, class: 'root' }],
      ['tampered class', { ...f.claim, class: 'os_confined' }],
      ['tampered passport', { ...f.claim, passport_digest: 'x' }],
      ['tampered sig', { ...f.claim, sig: f.claim.sig.slice(1) + 'A' }],
      ['missing sig', { ...f.claim, sig: undefined }],
      ['unpinned attestor', f.claim, { pinnedAttestors: [] }],
      ['other passport', f.claim, { passportDigest: passportDigest({ other: 1 }) }],
      ['not yet valid', f.claim, { now: -1 }],
      ['expired (exp is exclusive)', f.claim, { now: 10_000 }],
      ['non-integer time', { ...f.claim, iat: 0.5 }],
      ['evidence nobody verified', f.claim, { verifiedEvidenceDigests: [] }],
      ['evidence digest differs', f.claim, { verifiedEvidenceDigests: ['ev2'] }],
      ['extra member', { ...f.claim, extra: 1 }],
      ['array', [f.claim]],
    ];
    for (const [name, claim, over] of bad) expect(verifiedRuntimeClass(claim, { ...t, ...over }), name).toBe('none');
    // signed by a key that is pinned under another attestor's name
    const other = generateKeyPair();
    const forged = signRuntimeClaim(other.secretKey, other.publicKey, { class: 'wasi_no_ambient', passport_digest: t.passportDigest, evidence_digest: 'e', iat: 0, exp: 5 });
    expect(verifiedRuntimeClass({ ...forged, attestor: f.claim.attestor }, t)).toBe('none');
    expect(verifiedRuntimeClass(forged, t)).toBe('none');
  });

  it('a sandbox without verifiable evidence is class none and cannot mint where a class is required', async () => {
    const a = authFixture(['notes']);
    const ok = await a.allow(op);
    const noClaim = createSandbox({ executors: {} });
    expect(() => noClaim.table.mint(ok, op, { requires: 'wasi_no_ambient' })).toThrow(/runtime_class_too_weak/);
    const f = claimFixture('wasi_no_ambient');
    const bad = createSandbox({ executors: {}, runtimeClaim: { claim: f.claim, trust: { ...f.trust, passportDigest: 'someone-else' } } });
    expect(() => bad.table.mint(ok, op, { requires: 'os_confined' })).toThrow(/runtime_class_too_weak/);
    const good = createSandbox({ executors: {}, runtimeClaim: f.runtimeClaim });
    expect(good.table.mint(ok, op, { requires: 'wasi_no_ambient' })).toBe(1);
    expect(new HandleTable('none', new ReceiptLog(), {}).runtimeClass).toBe('none');
  });

  it('receipts carry the proven class', async () => {
    const a = authFixture(['notes']);
    const f = claimFixture('os_confined');
    const sb = createSandbox({ executors: { 'notes.read': () => Uint8Array.of(1) }, runtimeClaim: f.runtimeClaim });
    sb.table.mint(await a.allow(op), op);
    sb.table.use(1);
    expect(sb.log.entries[0]!.runtime_class).toBe('os_confined');
  });
});

describe('runtime claim vectors', () => {
  const file = path.join(__dirname, '../../pca/conformance/runtime-claim-vectors.json');
  // Fixed seed key so the vector is stable: a verifier in any language replays the same bytes.
  const secret = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
  it('are a fresh generation (UPDATE_VECTORS=1 rewrites)', async () => {
    const { publicKeyOf } = await import('@atlasauth/pca');
    const pub = publicKeyOf(secret);
    const passport = { agent: 'a1' };
    const pd = passportDigest(passport);
    const mk = (over = {}) => signRuntimeClaim(secret, pub, { class: 'wasi_no_ambient', passport_digest: pd, evidence_digest: 'ev1', iat: 100, exp: 200, ...over });
    const good = mk();
    const trust = { pinnedAttestors: [good.attestor], passportDigest: pd, verifiedEvidenceDigests: ['ev1'] };
    const cases = [
      { name: 'valid', claim: good, now: 150, expect: 'wasi_no_ambient' },
      { name: 'expired', claim: good, now: 200, expect: 'none' },
      { name: 'not_yet_valid', claim: good, now: 99, expect: 'none' },
      { name: 'tampered_class', claim: { ...good, class: 'os_confined' }, now: 150, expect: 'none' },
      { name: 'other_passport', claim: mk({ passport_digest: 'x' }), now: 150, expect: 'none' },
      { name: 'unverified_evidence', claim: mk({ evidence_digest: 'ev9' }), now: 150, expect: 'none' },
      { name: 'extra_member', claim: { ...good, extra: 1 }, now: 150, expect: 'none' },
      { name: 'unknown_class', claim: { ...good, class: 'root' }, now: 150, expect: 'none' },
    ];
    const fresh = `${JSON.stringify({ about: 'Runtime-class claim vectors: Ed25519 over the UTF-8 bytes of the domain string atlas-pca/runtime-class-claim/v1 followed by NUL, then the strict canonical JSON of the claim without sig; signer is the attestor member. The verifier pins attestors, the passport digest and the evidence digests it has itself verified; anything that does not verify, or has any member beyond the eight, is none.', trust, cases }, null, 1)}\n`;
    if (process.env.UPDATE_VECTORS === '1') fs.writeFileSync(file, fresh);
    expect(fs.readFileSync(file, 'utf8')).toBe(fresh);
    for (const c of cases) expect(verifiedRuntimeClass(c.claim, { ...trust, now: c.now }), c.name).toBe(c.expect);
  });
});

describe('evidence: a claim is valid only if the attestation verifies and its digest matches', () => {
  const doc = { kind: 'tdx', quote: 'q' } as never;
  const base = { document: doc, ctx: {} as never, expected: {} as never, nowMs: 5, pinnedAttestors: ['k'], passportDigest: 'p' };
  const v = (r: unknown) => ({ verify: async () => r }) as never;
  it('admits the digest only for ok and bound evidence', async () => {
    expect((await trustFromAttestation({ ...base, verifier: v({ ok: true, bound: true }) })).verifiedEvidenceDigests).toEqual([evidenceDigest(doc)]);
    for (const r of [{ ok: true, bound: false }, { ok: false, bound: true }, { ok: 'yes', bound: true }, null, undefined, {}]) {
      expect((await trustFromAttestation({ ...base, verifier: v(r) })).verifiedEvidenceDigests, JSON.stringify(r)).toEqual([]);
    }
    const throwing = { verify: async () => { throw new Error('x'); } } as never;
    expect((await trustFromAttestation({ ...base, verifier: throwing })).verifiedEvidenceDigests).toEqual([]);
  });
  it('end to end: a claim over verified evidence proves its class, over unverified evidence it is none', async () => {
    const kp = generateKeyPair();
    const claim = signRuntimeClaim(kp.secretKey, kp.publicKey, { class: 'wasi_no_ambient', passport_digest: 'p', evidence_digest: evidenceDigest(doc), iat: 0, exp: 100 });
    const good = await trustFromAttestation({ ...base, pinnedAttestors: [claim.attestor], verifier: v({ ok: true, bound: true }) });
    expect(verifiedRuntimeClass(claim, good)).toBe('wasi_no_ambient');
    const bad = await trustFromAttestation({ ...base, pinnedAttestors: [claim.attestor], verifier: v({ ok: true, bound: false }) });
    expect(verifiedRuntimeClass(claim, bad)).toBe('none');
  });
});
