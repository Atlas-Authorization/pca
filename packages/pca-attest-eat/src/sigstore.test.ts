// Track K9: offline Sigstore verification of a real public bundle (sigstore@5.0.0 on npm, SLSA v1 provenance) against the
// pinned public-good trusted root, every gate's refusal, and the join with runtime attestation: the artifact verifier signs
// a discharge only for the image the provenance describes.
import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { b64u, encodeKey, generateKeyPair, provenanceCaveat, verifyDischarge, type DischargeRequest } from '@atlasauth/pca';
import { buildEAT, issueNonce, verifyFreshAttestedEAT } from './index';
import { dssePae, parseTrustedRoot, verifySigstoreBundle, type PinnedRoots } from './sigstore';
import { issueArtifactDischarge, runtimeDigestFromEat } from './provenance';

const FIX = join(__dirname, '..', 'test-fixtures', 'sigstore');
const ROOT_JSON = JSON.parse(readFileSync(join(FIX, 'trusted_root.json'), 'utf8'));
const ATT = JSON.parse(readFileSync(join(FIX, 'npm-sigstore-5.0.0.attestations.json'), 'utf8')).attestations as { predicateType: string; bundle: any }[];
const SLSA = ATT.find((a) => a.predicateType === 'https://slsa.dev/provenance/v1')!.bundle;
const PUBLISH = ATT.find((a) => a.predicateType !== 'https://slsa.dev/provenance/v1')!.bundle;
const ROOTS = parseTrustedRoot(ROOT_JSON);
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const flipB64 = (s: string, at = 10): string => {
  const b = Buffer.from(s, 'base64');
  b[at] = b[at]! ^ 1;
  return b.toString('base64');
};
const TARBALL_SHA512 = Buffer.from('hJqJfoG/e4qFQaauQL00c6J6FrHLBGKtkFvW3JbTSIEFOhLrSjdSM/gWd/yUOfYo/gsERehTXGC1VZWX+9X4Dg==', 'base64').toString('hex');
const REPO = 'https://github.com/sigstore/sigstore-js';
const IDENT = `${REPO}/.github/workflows/release.yml@refs/heads/main`;
const GHA = 'https://token.actions.githubusercontent.com';
const BUILDER = 'https://github.com/actions/runner/github-hosted';

describe('verifySigstoreBundle (real public bundle, pinned roots, offline)', () => {
  it('establishes identity, issuer, source and subject from the certificate, the log and the statement', () => {
    const r = verifySigstoreBundle(SLSA, { roots: ROOTS });
    expect(r).toEqual({
      ok: true,
      facts: {
        v: 1,
        predicate_type: 'https://slsa.dev/provenance/v1',
        build_type: 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1',
        builder_id: BUILDER,
        subjects: [{ alg: 'sha512', digest: TARBALL_SHA512 }],
        identity: IDENT,
        oidc_issuer: GHA,
        source_repo: REPO,
        source_ref: 'refs/heads/main',
        source_digest: '7d2900eca1c22b3f87c13987c8d4b7c9a29b733a',
        provenance_source: { uri: `git+${REPO}@refs/heads/main`, git_commit: '7d2900eca1c22b3f87c13987c8d4b7c9a29b733a' },
        integrated_time: 1780347770,
        rekor_log_index: 1697019812,
      },
    });
  });

  const refuse = (b: unknown, code: string, roots: PinnedRoots = ROOTS) => {
    const r = verifySigstoreBundle(b, { roots });
    expect(r.ok ? 'ok' : `${r.code}: ${r.detail}`).toMatch(new RegExp(`^${code}:`));
  };
  it('refuses a public-key (not keyless) bundle', () => refuse(PUBLISH, 'not_keyless'));
  it('refuses an unknown or v0.1 media type', () => {
    refuse({ ...SLSA, mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1' }, 'media_type');
    refuse({ ...SLSA, mediaType: 'application/json' }, 'media_type');
  });
  it('refuses an envelope with two signatures, another payload type, or a message signature', () => {
    const b = clone(SLSA);
    b.dsseEnvelope.signatures.push(b.dsseEnvelope.signatures[0]);
    refuse(b, 'envelope');
    refuse({ ...SLSA, dsseEnvelope: { ...SLSA.dsseEnvelope, payloadType: 'application/json' } }, 'envelope');
    refuse({ ...SLSA, messageSignature: {} }, 'envelope');
  });
  it('refuses a payload changed after logging (the entry names another payload)', () => {
    const b = clone(SLSA);
    const st = JSON.parse(Buffer.from(b.dsseEnvelope.payload, 'base64').toString());
    st.subject[0].digest.sha512 = 'ee'.repeat(64);
    b.dsseEnvelope.payload = Buffer.from(JSON.stringify(st)).toString('base64');
    refuse(b, 'tlog_body');
  });
  it('refuses another signature than the logged one', () => {
    const b = clone(SLSA);
    b.dsseEnvelope.signatures[0].sig = flipB64(b.dsseEnvelope.signatures[0].sig, 20);
    refuse(b, 'tlog_body');
  });
  it('refuses a forged SET, a moved integrated time, and a bundle without a SET (no verified time)', () => {
    const b = clone(SLSA);
    b.verificationMaterial.tlogEntries[0].inclusionPromise.signedEntryTimestamp = flipB64(b.verificationMaterial.tlogEntries[0].inclusionPromise.signedEntryTimestamp, 12);
    refuse(b, 'tlog_set');
    const c = clone(SLSA);
    c.verificationMaterial.tlogEntries[0].integratedTime = String(Number(c.verificationMaterial.tlogEntries[0].integratedTime) - 3600);
    refuse(c, 'tlog_set');
    const d = clone(SLSA);
    delete d.verificationMaterial.tlogEntries[0].inclusionPromise;
    refuse(d, 'no_verified_time');
  });
  it('refuses a broken inclusion proof and a checkpoint not signed by the pinned log', () => {
    const b = clone(SLSA);
    b.verificationMaterial.tlogEntries[0].inclusionProof.hashes[3] = flipB64(b.verificationMaterial.tlogEntries[0].inclusionProof.hashes[3], 0);
    refuse(b, 'tlog_inclusion');
    const c = clone(SLSA);
    const env: string = c.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope;
    c.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope = env.replace(/(— \S+ )(\S+)/, (_m: string, a: string, s: string) => a + flipB64(s, 30));
    refuse(c, 'tlog_checkpoint');
    const d = clone(SLSA);
    d.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope = env.replace(/\n(\d+)\n/, (_m: string, n: string) => `\n${Number(n) + 1}\n`);
    refuse(d, 'tlog_checkpoint');
  });
  it('refuses an entry from a log the verifier did not pin, and more than one entry', () => {
    refuse(SLSA, 'tlog_key', { ...ROOTS, tlogs: [] });
    const b = clone(SLSA);
    b.verificationMaterial.tlogEntries.push(b.verificationMaterial.tlogEntries[0]);
    refuse(b, 'tlog_count');
  });
  it('refuses a certificate no pinned CA issued, or a CA pin not valid at the signing time', () => {
    refuse(SLSA, 'cert_chain', { ...ROOTS, cas: [ROOTS.cas[0]!] });
    refuse(SLSA, 'cert_chain', { ...ROOTS, cas: ROOTS.cas.map((c) => ({ ...c, valid: { start: c.valid.start, end: Date.parse('2026-01-01T00:00:00Z') } })) });
  });
  it('refuses when no pinned CT log signed the embedded SCT', () => {
    const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey as KeyObject;
    refuse(SLSA, 'sct', { ...ROOTS, ctlogs: ROOTS.ctlogs.map((l) => ({ ...l, key: other })) });
    // a root that pins no CT log is its owner's choice not to require SCTs
    expect(verifySigstoreBundle(SLSA, { roots: { ...ROOTS, ctlogs: [] } }).ok).toBe(true);
  });
  it('a certificate with one flipped byte is refused', () => {
    const b = clone(SLSA);
    b.verificationMaterial.certificate.rawBytes = flipB64(b.verificationMaterial.certificate.rawBytes, 400);
    const r = verifySigstoreBundle(b, { roots: ROOTS });
    expect(r.ok).toBe(false);
  });
  it('never throws on garbage', () => {
    for (const x of [null, 1, 'x', [], {}, { mediaType: SLSA.mediaType, verificationMaterial: {} }, { ...SLSA, verificationMaterial: { ...SLSA.verificationMaterial, tlogEntries: 'x' } }]) expect(verifySigstoreBundle(x, { roots: ROOTS }).ok).toBe(false);
  });
  it('the trusted root parser refuses a root without a CA, and a log id that is not the hash of its key', () => {
    expect(() => parseTrustedRoot({ ...ROOT_JSON, certificateAuthorities: [] })).toThrow();
    const v2 = clone(ROOT_JSON);
    v2.tlogs[1].baseUrl = 'https://other.example';
    expect(() => parseTrustedRoot(v2)).toThrow(/signed-note key hash/);
    const bad = clone(ROOT_JSON);
    bad.tlogs[0].logId.keyId = Buffer.alloc(32).toString('base64');
    expect(() => parseTrustedRoot(bad)).toThrow(/log id/);
    expect(() => parseTrustedRoot({ ...ROOT_JSON, mediaType: 'x' })).toThrow();
  });
  it('PAE is the DSSE v1 encoding', () => {
    expect(dssePae('t', new Uint8Array([104, 105])).toString()).toBe('DSSEv1 1 t 2 hi');
  });
});

// ------------------------------------------------------------------------------------------------ joined to runtime attestation
describe('artifact verifier: provenance joined to the running image', () => {
  const NOW_MS = 1_780_400_000_000;
  const eatKeys = generateKeyPairSync('ed25519');
  const launch = 'aa'.repeat(48);
  const nonce = issueNonce({ now: NOW_MS }).value;
  const eatFor = async (image: string) => {
    const eat = buildEAT({ issuer: 'https://attester.example', key: eatKeys.privateKey, nonce, channelId: 'chan-1', measurements: [{ type: 'launch', value: launch }, { type: 'image', value: image }], dbgstat: 'disabled', now: NOW_MS });
    return verifyFreshAttestedEAT(eat, { verifyKey: eatKeys.publicKey, nonce, channelId: 'chan-1', now: NOW_MS, policy: { endorsements: { issuers: ['https://attester.example'] }, referenceValues: { measurements: [launch], requireDebugDisabled: true } } });
  };
  const policy = { roots: [{ oidc_issuer: GHA, identity: IDENT, builder_id: BUILDER, level: 2 }], min_level: 2, source_repo: REPO, require_runtime: true };
  const issuer = generateKeyPair();
  const caveat = provenanceCaveat({ issuer: 'prov', min_level: 2, source_repo: REPO, bind: 'chain_hop' });
  const CAP = b64u(new Uint8Array(32).fill(9));
  const request: DischargeRequest = { v: 1, kind: 'pca-discharge-request', caveat_id: caveat.id, issuer: caveat.issuer, cap_hash: CAP, bind: 'chain_hop', require: caveat.require, ttl_ms: caveat.ttl_ms };
  const pins = [{ label: 'prov', class: 'artifact' as const, pk: encodeKey(issuer.publicKey) }];

  it('issues a discharge the caveat accepts for the image the provenance describes', async () => {
    const v = await eatFor(TARBALL_SHA512);
    expect(v.ok).toBe(true);
    const runtime = runtimeDigestFromEat(v, { alg: 'sha512' });
    expect(runtime).toEqual({ alg: 'sha512', digest: TARBALL_SHA512 });
    const r = issueArtifactDischarge({ bundle: SLSA, roots: ROOTS, policy, runtime, request, now: NOW_MS, issuerSecret: issuer.secretKey });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.discharge.claims).toMatchObject({ slsa_level: 2, source_repo: REPO, runtime_bound: true, subject_alg: 'sha512', subject_digest: TARBALL_SHA512, builder_id: BUILDER });
    expect(verifyDischarge(r.discharge, caveat, { now: NOW_MS, cap_hash: CAP, pins })).toMatchObject({ ok: true });
  });

  it('a swapped image gets no discharge', async () => {
    const runtime = runtimeDigestFromEat(await eatFor('ee'.repeat(64)), { alg: 'sha512' });
    expect(issueArtifactDischarge({ bundle: SLSA, roots: ROOTS, policy, runtime, request, now: NOW_MS, issuerSecret: issuer.secretKey })).toEqual({ ok: false, stage: 'gate', code: 'runtime_mismatch' });
  });

  it('an EAT that failed, or names no image, is no join', async () => {
    const v = await eatFor(TARBALL_SHA512);
    expect(runtimeDigestFromEat({ ...v, ok: false })).toBeNull();
    expect(runtimeDigestFromEat(v, { slot: 'missing', alg: 'sha512' })).toBeNull();
    expect(runtimeDigestFromEat(v, { alg: 'sha256' })).toBeNull();
    expect(runtimeDigestFromEat({ ...v, claims: { ...v.claims!, measurements: [...v.claims!.measurements!, { type: 'image', value: TARBALL_SHA512 }] } }, { alg: 'sha512' })).toBeNull();
    expect(issueArtifactDischarge({ bundle: SLSA, roots: ROOTS, policy, runtime: null, request, now: NOW_MS, issuerSecret: issuer.secretKey })).toEqual({ ok: false, stage: 'gate', code: 'no_runtime' });
  });

  it('the GitHub-hosted runner pinned at level 2 does not meet a level 3 policy; an unpinned identity meets nothing', async () => {
    const runtime = runtimeDigestFromEat(await eatFor(TARBALL_SHA512), { alg: 'sha512' });
    expect(issueArtifactDischarge({ bundle: SLSA, roots: ROOTS, policy: { ...policy, min_level: 3 }, runtime, request, now: NOW_MS, issuerSecret: issuer.secretKey })).toEqual({ ok: false, stage: 'gate', code: 'level' });
    expect(issueArtifactDischarge({ bundle: SLSA, roots: ROOTS, policy: { ...policy, roots: [{ ...policy.roots[0]!, identity: `${REPO}/.github/workflows/other.yml@refs/heads/main` }] }, runtime, request, now: NOW_MS, issuerSecret: issuer.secretKey })).toEqual({ ok: false, stage: 'gate', code: 'no_root' });
  });

  it('a tampered bundle stops at the Sigstore stage', async () => {
    const runtime = runtimeDigestFromEat(await eatFor(TARBALL_SHA512), { alg: 'sha512' });
    const b = clone(SLSA);
    b.dsseEnvelope.signatures[0].sig = flipB64(b.dsseEnvelope.signatures[0].sig, 20);
    expect(issueArtifactDischarge({ bundle: b, roots: ROOTS, policy, runtime, request, now: NOW_MS, issuerSecret: issuer.secretKey })).toMatchObject({ ok: false, stage: 'sigstore', code: 'tlog_body' });
  });
});
