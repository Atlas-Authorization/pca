import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseTrustedRoot, verifySigstoreBundle, type PinnedRoots } from '@atlasauth/pca-attest-eat';

/** The two trust tiers of a statement. */
export type Tier = 'self-attested' | 'ci-attested';

export const GITHUB_ACTIONS_ISSUER = 'https://token.actions.githubusercontent.com';

/**
 * What a CI attestation must say for the statement to count as CI-attested. A Sigstore build-provenance bundle is made over the
 * statement file in a GitHub Actions run; verification is offline, against a pinned Sigstore trusted root.
 */
export interface CiPolicy {
  /** `owner/name` of the repository whose workflow ran the runner. Required: a CI attestation from an arbitrary repository proves nothing. */
  repo: string;
  /** Workflow file name (for example `verified.yml`). When given, the signing identity must be exactly that workflow of that repository. */
  workflow?: string;
  /** Exact git ref the run must have been on (for example `refs/tags/v1.0.0`). */
  ref?: string;
  /** Pinned Sigstore roots. Default: the public-good root bundled with this package (`trust/sigstore-public-good.json`). */
  roots?: PinnedRoots;
}

export interface CiAttestation {
  tier: 'ci-attested';
  /** The Fulcio certificate identity: the workflow that signed. */
  identity: string;
  repo: string;
  ref?: string;
  commit?: string;
  builder_id: string;
  rekor_log_index: number;
  /** Rekor integrated time, unix seconds. */
  integrated_time: number;
}

export type CiResult = { ok: true; attestation: CiAttestation } | { ok: false; reason: string };

let defaultRoots: PinnedRoots | undefined;
export function publicGoodRoots(): PinnedRoots {
  defaultRoots ??= parseTrustedRoot(JSON.parse(readFileSync(join(__dirname, '..', 'trust', 'sigstore-public-good.json'), 'utf8')));
  return defaultRoots;
}

/** The subject of a CI attestation: the SHA-256 (hex) of the COSE statement bytes. */
export const subjectDigest = (cose: Uint8Array): string => createHash('sha256').update(cose).digest('hex');

/**
 * Verify that `bundle` (a Sigstore bundle carrying SLSA build provenance) was made by the named repository's GitHub Actions workflow
 * over exactly these statement bytes: the bundle's signature, Fulcio chain, Rekor inclusion and timestamp (the existing offline
 * Sigstore verifier), then the signer, repository, workflow and ref, then that the statement digest is one of the signed subjects.
 * Fail-closed, never throws.
 */
export function verifyCiAttestation(cose: Uint8Array, bundle: unknown, policy: CiPolicy): CiResult {
  const no = (reason: string): CiResult => ({ ok: false, reason });
  try {
    if (!policy || typeof policy.repo !== 'string' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(policy.repo)) return no('a CI policy needs the repository as owner/name');
    const r = verifySigstoreBundle(bundle, { roots: policy.roots ?? publicGoodRoots() });
    if (!r.ok) return no(`sigstore bundle: ${r.code} (${r.detail})`);
    const f = r.facts;
    if (f.oidc_issuer !== GITHUB_ACTIONS_ISSUER) return no('the bundle was not signed by GitHub Actions');
    const wf = `https://github.com/${policy.repo}/.github/workflows/`;
    if (policy.workflow !== undefined) {
      if (!/^[A-Za-z0-9_.-]+$/.test(policy.workflow)) return no('workflow must be a file name');
      // the SAN is `<repo>/.github/workflows/<file>@<ref>`
      if (!f.identity.startsWith(`${wf}${policy.workflow}@`)) return no(`signed by ${f.identity}, not workflow ${policy.workflow} of ${policy.repo}`);
    } else if (!f.identity.startsWith(wf)) return no(`signed by ${f.identity}, not a workflow of ${policy.repo}`);
    if (f.source_repo !== undefined && f.source_repo !== `https://github.com/${policy.repo}`) return no('the certificate names a different source repository');
    if (policy.ref !== undefined && f.source_ref !== policy.ref) return no(`the run was on ${String(f.source_ref)}, not ${policy.ref}`);
    const want = subjectDigest(cose);
    if (!f.subjects.some((s) => s.alg === 'sha256' && s.digest === want)) return no('the statement is not among the attested subjects (its digest differs)');
    return {
      ok: true,
      attestation: {
        tier: 'ci-attested', identity: f.identity, repo: policy.repo, builder_id: f.builder_id, rekor_log_index: f.rekor_log_index, integrated_time: f.integrated_time,
        ...(f.source_ref !== undefined ? { ref: f.source_ref } : {}), ...(f.source_digest !== undefined ? { commit: f.source_digest } : {}),
      },
    };
  } catch (e) {
    return no(`unexpected: ${(e as Error).message}`);
  }
}
