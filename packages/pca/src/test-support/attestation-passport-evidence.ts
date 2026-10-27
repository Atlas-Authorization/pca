// Synthetic vendor evidence bound to a passport (TEST/TOOLING ONLY): one (config, evidence) pair per vendor, minted under the
// test roots of the attestation-evidence vectors and fresh at the passport vector clock. `wrongPinConfig` is the same config
// with its trust pin replaced, so the chain no longer anchors.
import type { Vendor, JsonObject, WireBinding } from './attestation-wire';
import { snpSyn, snpSynConfig } from './attestation-vectors-snp';
import { dcapSyn, dcapSynConfig } from './attestation-vectors-dcap';
import { MAA_ISS, MAA_MEAS, MAA_MRTD, maaPayload, maaTdxClaims, maaWorld, mint } from './attestation-vectors-maa';
import { GCP_IMAGE, gcpClaims } from './attestation-vectors-gcp';
import { nvSyn, nvConfig } from './attestation-vectors-nvidia';
import { forgeRsaKey } from './forge-rsa';
import { GCP_CS_DEFAULT_ISSUER } from '../attest-gcp-confidential-space';

export interface PassportEvidence {
  config: JsonObject;
  evidence: JsonObject;
  wrongPinConfig: JsonObject;
}
const WRONG = '00'.repeat(32);

export function passportHardwareEvidence(vendor: Vendor, binding: WireBinding, now: number): PassportEvidence {
  switch (vendor) {
    case 'amd-sev-snp': {
      const s = snpSyn({ binding });
      return { config: snpSynConfig(s), evidence: s.evidence, wrongPinConfig: snpSynConfig(s, { trustAnchorArkSpkiSha384: '00'.repeat(48) }) };
    }
    case 'intel-tdx-dcap': {
      const s = dcapSyn({ binding }, now);
      return { config: dcapSynConfig(s), evidence: s.evidence, wrongPinConfig: dcapSynConfig(s, 'report-data', {}, { trustAnchorRootCaSpkiSha256: WRONG }) };
    }
    case 'azure-maa': {
      const W = maaWorld();
      const token = mint({ alg: 'ES256', typ: 'JWT', kid: 'kid-ec' }, maaPayload(now, maaTdxClaims(binding)), { kind: 'ec', key: W.ec.leafKey });
      const jwks: JsonObject = { keys: [{ kid: 'kid-ec', kty: 'EC', x5c: W.x5c(W.ec.leaf, W.ec.int, W.ec.root) }] };
      const cfg = (pin: string): JsonObject => ({ trustedIssuers: [MAA_ISS], trustAnchors: { rootSpkiSha256: [pin] }, policy: { tdxMrtds: [MAA_MRTD], sevSnpMeasurements: [MAA_MEAS], runtimeUserDataBinding: true } });
      return { config: cfg(W.ec.root.key.spkiSha256), evidence: { token, jwks }, wrongPinConfig: cfg(WRONG) };
    }
    case 'gcp-confidential-space': {
      const rsa = forgeRsaKey('gcp/rsa');
      const t = Math.floor(now / 1000);
      const token = mint({ alg: 'RS256', typ: 'JWT', kid: 'kid-rsa' }, gcpClaims(binding, { iat: t - 60, nbf: t - 60, exp: t + 3600 }), { kind: 'rsa', key: rsa });
      const cfg = (jwk: JsonObject): JsonObject => ({ trustedIssuers: [GCP_CS_DEFAULT_ISSUER], trustAnchors: { trustedJwks: { keys: [jwk] } }, policy: { imageDigests: [GCP_IMAGE], nonceHash: 'sha256' } });
      const other = forgeRsaKey('gcp/other-rsa');
      return { config: cfg({ ...rsa.jwk, kid: 'kid-rsa' }), evidence: { token }, wrongPinConfig: cfg({ ...other.jwk, kid: 'kid-rsa' }) };
    }
    case 'nvidia-gpu-spdm': {
      const n = nvSyn({ now: new Date(now) }, binding);
      const cfg = (root: string): JsonObject => ({ ...nvConfig(n, { collateral: {} }), rootSpkiSha256: [root] });
      return { config: cfg(n.s.deviceRootSpkiSha256), evidence: n.evidence, wrongPinConfig: cfg(WRONG) };
    }
  }
}
