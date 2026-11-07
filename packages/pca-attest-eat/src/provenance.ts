import { provenanceDischargeBody, provenanceGate, signDischarge, type Discharge, type DischargeRequest, type BuildProvenanceFacts, type ProvenanceGateCode, type SubjectDigest } from '@atlasauth/pca';
import { randomBytes } from 'node:crypto';
import type { FreshAttestedVerdict } from './index';
import { verifySigstoreBundle, type PinnedRoots, type SigstoreCode } from './sigstore';

/**
 * THE ARTIFACT ATTESTATION VERIFIER (track K9): Sigstore provenance joined to runtime attestation, issued as a K1 discharge.
 *
 * The verifier that holds the `artifact`-class key runs, for one discharge request:
 *   1. {@link verifySigstoreBundle}: the bundle against the pinned trust roots (offline);
 *   2. {@link runtimeDigestFromEat}: the digest of the image that is actually running, from an EAT this verifier already
 *      accepted (`verifyFreshAttestedEAT`: signature, nonce, channel, appraisal). Never a digest the caller states;
 *   3. `provenanceGate`: the verifier's own pins (signer-builder pairs and levels, source, age) and the join
 *      (the running digest must be a provenance subject);
 *   4. it signs the discharge the request asks for, with the gate's claims.
 * Any failure returns no discharge, so the caveat refuses: provenance can only remove authority.
 */

/**
 * The running image's digest from an ACCEPTED EAT: exactly one `measurements` entry labelled `slot` (default `image`),
 * lowercase hex of the algorithm's length. Null when the verdict is not ok, the slot is missing or repeated, or the value is
 * malformed (no case folding).
 */
export function runtimeDigestFromEat(verdict: FreshAttestedVerdict, o: { slot?: string; alg?: SubjectDigest['alg'] } = {}): SubjectDigest | null {
  if (!verdict || verdict.ok !== true || !verdict.claims) return null;
  const slot = o.slot ?? 'image';
  const alg = o.alg ?? 'sha256';
  const hits = (verdict.claims.measurements ?? []).filter((m) => m.type === slot);
  if (hits.length !== 1) return null;
  const v = hits[0]!.value;
  return typeof v === 'string' && (alg === 'sha256' ? /^[0-9a-f]{64}$/ : /^[0-9a-f]{128}$/).test(v) ? { alg, digest: v } : null;
}

export interface ArtifactDischargeInput {
  bundle: unknown;
  roots: PinnedRoots;
  /** The verifier's provenance policy (`provenanceGate`). */
  policy: unknown;
  /** From {@link runtimeDigestFromEat}; omit only when the policy does not require the join. */
  runtime?: SubjectDigest | null;
  /** The discharge request (`dischargeRequests` at the PEP). */
  request: DischargeRequest;
  /** Verifier clock, epoch ms. */
  now: number;
  /** The `artifact`-class issuer key. */
  issuerSecret: Uint8Array;
  /** Discharge lifetime, at most the request's `ttl_ms`. Default: the request's. */
  ttl_ms?: number;
}

export type ArtifactDischargeResult =
  | { ok: true; discharge: Discharge; facts: BuildProvenanceFacts; level: number }
  | { ok: false; stage: 'sigstore'; code: SigstoreCode; detail: string }
  | { ok: false; stage: 'gate'; code: ProvenanceGateCode | 'no_runtime' };

export function issueArtifactDischarge(i: ArtifactDischargeInput): ArtifactDischargeResult {
  const v = verifySigstoreBundle(i.bundle, { roots: i.roots });
  if (!v.ok) return { ok: false, stage: 'sigstore', code: v.code, detail: v.detail };
  // an EAT that yielded no digest is not "no runtime": it is a failed join
  if (i.runtime === null) return { ok: false, stage: 'gate', code: 'no_runtime' };
  const gate = provenanceGate({ facts: v.facts, policy: i.policy, ...(i.runtime !== undefined ? { runtime: i.runtime } : {}), now: Math.floor(i.now / 1000) });
  if (!gate.ok) return { ok: false, stage: 'gate', code: gate.code };
  const body = provenanceDischargeBody(i.request, gate, { iat: i.now, ttl_ms: i.ttl_ms ?? i.request.ttl_ms, nonce: randomBytes(16).toString('base64url') });
  return { ok: true, discharge: signDischarge(body, i.issuerSecret), facts: v.facts, level: gate.level };
}
