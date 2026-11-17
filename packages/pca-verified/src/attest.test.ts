import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseTrustedRoot } from '@atlasauth/pca-attest-eat';
import { publicGoodRoots, subjectDigest, verifyCiAttestation } from './attest';

// A real public GitHub Actions bundle (SLSA v1 provenance, Sigstore public-good) from the attestation package's fixtures.
const FIX = join(__dirname, '..', '..', 'pca-attest-eat', 'test-fixtures', 'sigstore');
const ROOTS = parseTrustedRoot(JSON.parse(readFileSync(join(FIX, 'trusted_root.json'), 'utf8')));
const BUNDLE = (JSON.parse(readFileSync(join(FIX, 'npm-sigstore-5.0.0.attestations.json'), 'utf8')).attestations as { predicateType: string; bundle: unknown }[]).find((a) => a.predicateType === 'https://slsa.dev/provenance/v1')!.bundle;
const COSE = new TextEncoder().encode('some statement bytes');

describe('CI attestation', () => {
  it('the bundled public-good root parses', () => {
    expect(publicGoodRoots().tlogs.length).toBeGreaterThan(0);
  });
  it('a genuine bundle for a different artifact does not attest this statement (the digest is checked last, after identity and repository)', () => {
    const r = verifyCiAttestation(COSE, BUNDLE, { repo: 'sigstore/sigstore-js', workflow: 'release.yml', roots: ROOTS });
    expect(r).toMatchObject({ ok: false });
    expect((r as { reason: string }).reason).toContain('not among the attested subjects');
  });
  it('is refused for another repository, another workflow and another ref', () => {
    const reason = (p: Parameters<typeof verifyCiAttestation>[2]): string => (verifyCiAttestation(COSE, BUNDLE, { roots: ROOTS, ...p }) as { reason: string }).reason;
    expect(reason({ repo: 'someone/else' })).toContain('not a workflow of someone/else');
    expect(reason({ repo: 'sigstore/sigstore-js', workflow: 'other.yml' })).toContain('not workflow other.yml');
    expect(reason({ repo: 'sigstore/sigstore-js', ref: 'refs/heads/nope' })).toContain('not refs/heads/nope');
  });
  it('is refused without a root that contains the signing CA, and for anything that is not a bundle', () => {
    for (const b of [null, undefined, {}, 'x', { mediaType: 'x' }]) expect(verifyCiAttestation(COSE, b, { repo: 'a/b', roots: ROOTS }).ok).toBe(false);
    expect(verifyCiAttestation(COSE, BUNDLE, { repo: 'not a repo' }).ok).toBe(false);
    expect(verifyCiAttestation(COSE, BUNDLE, { repo: '' }).ok).toBe(false);
    expect(verifyCiAttestation(COSE, BUNDLE, { repo: 'a/b', workflow: '../x' }).ok).toBe(false);
  });
  it('the subject is the SHA-256 of the COSE bytes', () => {
    expect(subjectDigest(new Uint8Array(0))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});
