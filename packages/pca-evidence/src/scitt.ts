import { signStatement, type SignStatementOpts } from '@atlasauth/pca-scitt';
import { evidenceDigest, type EvidenceBundle } from './bundle';
import { anchorCommit } from './verify';

/**
 * Registration of an evidence bundle (spec §3.11): its digest is anchored in the intent anchor log (kind `evidence`) and
 * can be registered with a SCITT Transparency Service as a COSE Signed Statement (RFC 9943) whose payload names the
 * bundle by digest. The bundle itself stays with the site (it holds personal data); only its reference is public.
 */

export const EVIDENCE_CONTENT_TYPE = 'application/pca-intent-evidence+json';

export interface EvidenceRef {
  kind: 'pca-intent-evidence-ref';
  digest: string;
  subject: EvidenceBundle['subject'];
}

export function evidenceRef(bundle: EvidenceBundle): EvidenceRef {
  return { kind: 'pca-intent-evidence-ref', digest: evidenceDigest(bundle), subject: { ...bundle.subject } };
}

/** A COSE Signed Statement over the bundle reference, ready to register with a SCITT service. */
export function evidenceSignedStatement(bundle: EvidenceBundle, opts: Omit<SignStatementOpts, 'contentType'>): Uint8Array {
  const ref = evidenceRef(bundle);
  return signStatement(ref, { ...opts, subject: opts.subject ?? ref.subject.pcactn_digest, contentType: EVIDENCE_CONTENT_TYPE });
}

/** The intent-anchor-log leaf for a bundle digest (`intentAnchorCommit` construction, kind `evidence`). */
export function evidenceAnchorCommit(digest: string): string {
  return anchorCommit('evidence', digest);
}
