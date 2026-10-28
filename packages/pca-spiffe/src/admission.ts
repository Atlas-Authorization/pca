import { svidToHolder, verifyJwtSvid, verifyX509Svid, type SvidToHolderOptions, type VerifyJwtSvidOptions, type VerifyX509SvidOptions } from './index';

/**
 * SPIFFE EVIDENCE FOR BLUEPRINT ADMISSION (`@atlasauth/pca-grants` `admitWithEvidence`). A workload is admitted under its verified
 * SPIFFE ID: the SVID is verified against the trust bundle (X.509 chain, or JWT with signature/audience/expiry), then bound to the
 * INSTANCE KEY by `svidToHolder` (the SVID's own Ed25519 key, or a proof signed by the SVID key, or a JWT `cnf.jwk`). The identity
 * returned is `{ spiffe_id }` from the verified SVID. Anything unverifiable, unbound or for a different key is `ok: false`.
 */
export interface SpiffeAdmissionEvidenceResult {
  ok: boolean;
  bound: boolean;
  identity?: { spiffe_id: string };
  reason?: string;
}

export type SpiffeEvidence =
  | { kind: 'x509'; chain: string | readonly (string | Uint8Array)[]; verify: VerifyX509SvidOptions; bind?: SvidToHolderOptions }
  | { kind: 'jwt'; token: string; verify: VerifyJwtSvidOptions; bind?: SvidToHolderOptions };

export async function spiffeAdmissionEvidence(e: SpiffeEvidence, instanceKey: string): Promise<SpiffeAdmissionEvidenceResult> {
  try {
    const svid = e.kind === 'x509' ? verifyX509Svid(e.chain, e.verify) : await verifyJwtSvid(e.token, e.verify);
    const h = svidToHolder(svid, instanceKey, e.bind ?? {});
    if (h.holder !== instanceKey) return { ok: false, bound: false, reason: 'SVID is bound to a different key' };
    return { ok: true, bound: true, identity: { spiffe_id: h.spiffeId } };
  } catch (err) {
    const code = (err as { code?: unknown })?.code;
    return { ok: false, bound: false, reason: typeof code === 'string' ? code : err instanceof Error ? err.name : 'error' };
  }
}
