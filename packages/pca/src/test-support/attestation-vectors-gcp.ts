// GCP Confidential Space rows of the attestation-evidence conformance vectors (TEST/TOOLING ONLY).
// The real Confidential Space captures are withheld from the public tree (they identify a cloud project), so every row is
// synthetic: tokens carry the claim shapes of the real captures, signed under test keys.
import { createHash } from 'node:crypto';
import { sha512 } from '@noble/hashes/sha512';
import { GCP_CS_DEFAULT_ISSUER } from '../attest-gcp-confidential-space';
import { type JsonObject, type WireBinding } from './attestation-wire';
import { Collector, SYN_BINDING, badBindings, bindingBytes, hexOf, relays } from './attestation-vectors-common';
import { forgeKey, forgeCert, ext, type ForgeKey } from './forge-x509';
import { forgeRsaKey } from './forge-rsa';
import { mint, type Signer } from './attestation-vectors-maa';

export const GCP_NOW = 1_790_000_000_000;
export const GCP_IMAGE = `sha256:${'b1'.repeat(32)}`;

const jwkEc = (k: ForgeKey, kid: string): JsonObject => ({ kid, kty: 'EC', crv: 'P-256', alg: 'ES256', x: Buffer.from(k.pub.subarray(1, 33)).toString('base64url'), y: Buffer.from(k.pub.subarray(33, 65)).toString('base64url') });

export function gcpClaims(binding: WireBinding, over: Record<string, unknown> = {}, hash: 'none' | 'sha256' | 'sha512' = 'sha256'): Record<string, unknown> {
  const b = bindingBytes(binding);
  const nonce = hash === 'sha256' ? createHash('sha256').update(b).digest() : hash === 'sha512' ? sha512(b) : b;
  return {
    iss: GCP_CS_DEFAULT_ISSUER, aud: 'https://sts.example', iat: Math.floor(GCP_NOW / 1000) - 60, nbf: Math.floor(GCP_NOW / 1000) - 60, exp: Math.floor(GCP_NOW / 1000) + 3600,
    swname: 'CONFIDENTIAL_SPACE', swversion: ['240500'], hwmodel: 'GCP_AMD_SEV', dbgstat: 'disabled-since-boot', eat_nonce: hexOf(nonce),
    submods: { confidential_space: { support_attributes: ['LATEST', 'STABLE'] }, container: { image_digest: GCP_IMAGE, image_reference: 'registry.example/workload:1' } }, ...over,
  };
}

export async function buildGcpVectors(c: Collector): Promise<void> {
  const rsa = forgeRsaKey('gcp/rsa');
  const ec = forgeKey('gcp/ec', 'P-256');
  const rogueEc = forgeKey('gcp/rogue', 'P-256');
  const rsaS: Signer = { kind: 'rsa', key: rsa };
  const ecS: Signer = { kind: 'ec', key: ec };
  const JW_RSA: JsonObject = { keys: [{ ...rsa.jwk, kid: 'kid-rsa', alg: 'RS256' }] };
  const JW_EC: JsonObject = { keys: [jwkEc(ec, 'kid-ec')] };
  const hdr = (alg: string, kid?: string, extra: Record<string, unknown> = {}) => ({ alg, typ: 'JWT', ...(kid ? { kid } : {}), ...extra });
  const tok = (claims: Record<string, unknown> = {}, o: { signer?: Signer; alg?: string; kid?: string; hash?: 'none' | 'sha256' | 'sha512'; binding?: WireBinding; header?: Record<string, unknown> } = {}) =>
    mint(o.header ?? hdr(o.alg ?? 'RS256', o.kid ?? 'kid-rsa'), gcpClaims(o.binding ?? SYN_BINDING, claims, o.hash ?? 'sha256'), o.signer ?? rsaS);
  const cfg = (over: JsonObject = {}, policy: JsonObject = {}): JsonObject => ({
    trustedIssuers: [GCP_CS_DEFAULT_ISSUER], trustAnchors: { trustedJwks: JW_RSA }, policy: { imageDigests: [GCP_IMAGE], nonceHash: 'sha256', ...policy }, ...over,
  });
  const syn = (id: string, intent: 'accept' | 'reject', description: string, token: string, o: { jwks?: JsonObject | null; cfg?: JsonObject; policy?: JsonObject; now?: number; binding?: WireBinding; tags?: string[] } = {}) =>
    c.add({
      id: `gcp-syn-${id}`, vendor: 'gcp-confidential-space', tags: ['synthetic', ...(o.tags ?? [])], intent, description, config: cfg(o.cfg, o.policy), now: o.now ?? GCP_NOW, binding: o.binding ?? SYN_BINDING,
      evidence: { token, ...(o.jwks ? { jwks: o.jwks } : {}) },
    });
  const T = tok();
  const [h0, p0, s0] = T.split('.') as [string, string, string];

  await syn('rs256-positive', 'accept', 'RS256 token verified under a pinned JWKS key (sev-snp hwmodel).', T);
  await syn('rs256-evidence-jwks-corroborated', 'accept', 'A key found only in the evidence JWKS but present by material in the pinned JWKS.', T, { jwks: JW_RSA });
  await syn('rs256-evidence-jwks-uncorroborated', 'reject', 'A key found only in the evidence JWKS with nothing pinned.', T, { jwks: JW_RSA, cfg: { trustAnchors: { trustedKeySpki: [forgeKey('x', 'P-256').spkiSha256] } } });
  await syn('rs256-spki-pin', 'accept', 'Evidence JWKS key anchored by an SPKI pin.', T, { jwks: JW_RSA, cfg: { trustAnchors: { trustedKeySpki: [rsa.spkiSha256.toUpperCase()] } } });
  await syn('es256-positive', 'accept', 'ES256 token under a pinned EC JWK.', tok({}, { signer: ecS, alg: 'ES256', kid: 'kid-ec' }), { cfg: { trustAnchors: { trustedJwks: JW_EC } } });
  await syn('es256-signature-wrong-length', 'reject', 'ES256 signature of 63 bytes.', ((): string => { const t = tok({}, { signer: ecS, alg: 'ES256', kid: 'kid-ec' }); const [a, b, sg] = t.split('.') as [string, string, string]; return `${a}.${b}.${Buffer.from(Buffer.from(sg, 'base64url').subarray(0, 63)).toString('base64url')}`; })(), { cfg: { trustAnchors: { trustedJwks: JW_EC } } });
  await syn('es256-rogue-signer', 'reject', 'Token signed by a key that is not pinned.', tok({}, { signer: { kind: 'ec', key: rogueEc }, alg: 'ES256', kid: 'kid-ec' }), { cfg: { trustAnchors: { trustedJwks: JW_EC } } });
  await syn('rs256-header-over-ec-key', 'reject', 'RS256 header with an EC key.', tok({}, { signer: ecS, alg: 'RS256', kid: 'kid-ec' }), { cfg: { trustAnchors: { trustedJwks: JW_EC } } });
  await syn('es256-header-over-rsa-key', 'reject', 'ES256 header with an RSA key.', tok({}, { signer: rsaS, alg: 'ES256' }));
  await syn('alg-none', 'reject', 'alg none.', tok({}, { alg: 'none' }));
  await syn('alg-hs256', 'reject', 'alg HS256.', tok({}, { alg: 'HS256' }));
  await syn('kid-not-found', 'reject', 'kid not in any JWKS.', tok({}, { kid: 'nope' }));
  await syn('no-kid-single-key', 'accept', 'No kid with exactly one pinned key.', mint(hdr('RS256'), gcpClaims(SYN_BINDING), rsaS));
  await syn('no-kid-two-keys', 'reject', 'No kid with two candidate keys.', mint(hdr('RS256'), gcpClaims(SYN_BINDING), rsaS), { cfg: { trustAnchors: { trustedJwks: { keys: [...(JW_RSA['keys'] as JsonObject[]), jwkEc(rogueEc, 'k2')] } } } });
  await syn('jwk-unusable', 'reject', 'A matching JWK that carries no key material.', T, { cfg: { trustAnchors: { trustedJwks: { keys: [{ kid: 'kid-rsa', kty: 'RSA' }] } } } });
  await syn('x5c-chain-root-cert', 'accept', 'Signing key in the evidence JWKS as an x5c chain to a configured root certificate.', T, (() => {
    const root = forgeKey('gcp/x5c-root', 'P-256');
    const rootCert = forgeCert({ subject: [['CN', 'gcp-root']], issuer: [['CN', 'gcp-root']], subjectKey: root, signer: root, serial: 1n, notBefore: new Date('2025-01-01Z'), notAfter: new Date('2035-01-01Z'), extensions: [ext.basicConstraints(true)] });
    const leaf = forgeCert({ subject: [['CN', 'gcp-leaf']], issuer: [['CN', 'gcp-root']], subjectKey: { ...ec, spki: rsa.spki } as ForgeKey, signer: root, serial: 2n, notBefore: new Date('2025-01-01Z'), notAfter: new Date('2035-01-01Z') });
    return { jwks: { keys: [{ kid: 'kid-rsa', kty: 'RSA', x5c: [Buffer.from(leaf.der).toString('base64')] }] } as JsonObject, cfg: { trustAnchors: { rootCertsPem: [rootCert.pem] } } as JsonObject };
  })());
  // claims
  await syn('iss-other', 'reject', 'Issuer not configured.', tok({ iss: 'https://evil.example' }));
  await syn('iss-missing', 'reject', 'No iss.', tok({ iss: undefined }));
  await syn('exp-missing', 'reject', 'No exp.', tok({ exp: undefined }));
  await syn('exp-passed', 'reject', 'Expired by one second.', tok({ exp: Math.floor(GCP_NOW / 1000) - 1 }));
  await syn('exp-equals-now', 'accept', 'exp equal to the current second.', tok({ exp: Math.floor(GCP_NOW / 1000) }));
  await syn('exp-skew', 'accept', 'Skew of 1000 ms admits exp one second past.', tok({ exp: Math.floor(GCP_NOW / 1000) - 1 }), { cfg: { clockSkewMs: 1000 } });
  await syn('nbf-future', 'reject', 'nbf one second ahead.', tok({ nbf: Math.floor(GCP_NOW / 1000) + 1 }));
  await syn('iat-future', 'reject', 'iat one second ahead.', tok({ iat: Math.floor(GCP_NOW / 1000) + 1, nbf: undefined }));
  await syn('nbf-iat-absent', 'accept', 'nbf and iat are optional.', tok({ nbf: undefined, iat: undefined }));
  await syn('no-confidential-space-submod', 'reject', 'submods without confidential_space.', tok({ submods: { container: { image_digest: GCP_IMAGE } } }));
  await syn('no-submods', 'reject', 'No submods.', tok({ submods: undefined }));
  await syn('swname-other', 'reject', 'swname differs.', tok({ swname: 'OTHER' }));
  await syn('swname-configured', 'accept', 'expectedSwName override.', tok({ swname: 'OTHER' }), { policy: { expectedSwName: 'OTHER' } });
  await syn('swversion-allowed', 'accept', 'swversion intersects the allowlist.', tok(), { policy: { allowedSwVersions: ['1', '240500'] } });
  await syn('swversion-not-allowed', 'reject', 'swversion outside the allowlist.', tok(), { policy: { allowedSwVersions: ['1'] } });
  await syn('swversion-string-form', 'accept', 'swversion as a plain string.', tok({ swversion: '240500' }), { policy: { allowedSwVersions: ['240500'] } });
  await syn('hwmodel-missing', 'reject', 'No hwmodel.', tok({ hwmodel: undefined }));
  await syn('hwmodel-unknown', 'reject', 'Unknown hwmodel.', tok({ hwmodel: 'GCP_ARM_X' }));
  await syn('hwmodel-tdx', 'accept', 'GCP_INTEL_TDX maps to tdx.', tok({ hwmodel: 'GCP_INTEL_TDX' }));
  await syn('hwmodel-snp-prefix', 'accept', 'Lenient GCP_AMD_SEV prefix.', tok({ hwmodel: 'GCP_AMD_SEV_NEXT' }));
  await syn('hwmodel-tdx-prefix', 'accept', 'Lenient GCP_INTEL_TDX prefix.', tok({ hwmodel: 'GCP_INTEL_TDX_V2' }));
  await syn('tee-pinned-tdx-sev-token', 'reject', 'A SEV token against a tdx-only pin.', tok(), { policy: { allowedTeeTypes: ['tdx'] } });
  await syn('tee-pinned-tdx-tdx-token', 'accept', 'A TDX token against a tdx-only pin.', tok({ hwmodel: 'GCP_INTEL_TDX' }), { policy: { allowedTeeTypes: ['tdx'] } });
  await syn('tee-pinned-empty', 'reject', 'An empty allowedTeeTypes refused at construction.', tok(), { policy: { allowedTeeTypes: [] } });
  await syn('dbgstat-enabled', 'reject', 'Debug image.', tok({ dbgstat: 'enabled' }));
  await syn('dbgstat-missing', 'reject', 'No dbgstat.', tok({ dbgstat: undefined }));
  await syn('dbgstat-enabled-allowed', 'accept', 'allowDebug.', tok({ dbgstat: 'enabled' }), { policy: { allowDebug: true } });
  await syn('image-not-allowed', 'reject', 'Image digest not allowlisted.', tok(), { policy: { imageDigests: [`sha256:${'00'.repeat(32)}`] } });
  await syn('image-uppercase', 'accept', 'Image digest compares case-insensitively.', tok(), { policy: { imageDigests: [GCP_IMAGE.toUpperCase()] } });
  await syn('image-missing', 'reject', 'No image_digest claim.', tok({ submods: { confidential_space: {}, container: {} } }));
  await syn('images-empty', 'reject', 'Empty image allowlist refused at construction.', tok(), { policy: { imageDigests: [] } });
  await syn('config-no-issuers', 'reject', 'No trusted issuers.', tok(), { cfg: { trustedIssuers: [] } });
  await syn('config-no-anchors', 'reject', 'No anchors.', tok(), { cfg: { trustAnchors: {} } });
  await syn('identity-default', 'accept', 'Default identity: runtime_measurement = image digest; hostAsserted carries hwmodel and image reference.', tok());
  await syn('identity-overrides', 'accept', 'identity_overrides.', tok(), { cfg: { identity_overrides: { model_id: 'm1', operator: 'acme' } } });
  // binding
  for (const [n, b] of relays(SYN_BINDING)) await syn(`relayed-${n}`, 'reject', `Another ${n}.`, T, { binding: b });
  for (const [n, b] of badBindings(SYN_BINDING)) await syn(`bad-binding-${n}`, 'reject', `Binding ${n}: not constructible.`, T, { binding: b });
  await syn('nonce-hash-none', 'accept', "nonceHash 'none': eat_nonce is the raw binding.", tok({}, { hash: 'none' }), { policy: { nonceHash: 'none' } });
  await syn('nonce-hash-sha512', 'accept', "nonceHash 'sha512'.", tok({}, { hash: 'sha512' }), { policy: { nonceHash: 'sha512' } });
  await syn('nonce-hash-mismatch', 'reject', 'Token hashed with sha256 but policy says none.', T, { policy: { nonceHash: 'none' } });
  await syn('nonce-array-any-matches', 'accept', 'eat_nonce as an array: any element may match.', tok({ eat_nonce: ['00', gcpClaims(SYN_BINDING)['eat_nonce']] }));
  await syn('nonce-array-none-match', 'reject', 'eat_nonce array without a match.', tok({ eat_nonce: ['00', '11'] }));
  await syn('nonce-missing', 'reject', 'No eat_nonce.', tok({ eat_nonce: undefined }));
  await syn('nonce-empty', 'reject', 'Empty eat_nonce.', tok({ eat_nonce: '' }));
  await syn('nonce-number', 'reject', 'Numeric eat_nonce.', tok({ eat_nonce: 5 }));
  await syn('nonce-base64', 'accept', 'eat_nonce as standard base64.', tok({ eat_nonce: createHash('sha256').update(bindingBytes(SYN_BINDING)).digest().toString('base64') }));
  await syn('nonce-upper-hex', 'accept', 'eat_nonce in upper-case hex.', tok({ eat_nonce: String(gcpClaims(SYN_BINDING)['eat_nonce']).toUpperCase() }));
  await syn('nonce-0x-prefix', 'accept', 'eat_nonce with a 0x prefix.', tok({ eat_nonce: `0x${String(gcpClaims(SYN_BINDING)['eat_nonce'])}` }));
  // token shape / canonical base64url
  const jsonSeg = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  await syn('token-empty', 'reject', 'Empty token.', '');
  await syn('token-two-segments', 'reject', 'Two segments.', `${h0}.${p0}`);
  await syn('token-four-segments', 'reject', 'Four segments.', `${T}.x`);
  await syn('token-empty-signature', 'reject', 'Empty signature segment.', `${h0}.${p0}.`);
  await syn('token-empty-payload', 'reject', 'Empty payload segment.', `${h0}..${s0}`);
  await syn('token-sig-stray-character', 'reject', 'Stray character in the signature.', `${h0}.${p0}.${s0}!`, { tags: ['strictness'] });
  await syn('token-sig-padding', 'reject', 'Padding on the signature.', `${h0}.${p0}.${s0}==`, { tags: ['strictness'] });
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  await syn('token-sig-trailing-bits', 'reject', 'Non-zero trailing bits in the signature.', `${h0}.${p0}.${s0.slice(0, -1)}${alphabet[alphabet.indexOf(s0.at(-1)!) ^ 1]}`, { tags: ['strictness'] });
  await syn('token-sig-whitespace', 'reject', 'Newline inside the signature.', `${h0}.${p0}.${s0.slice(0, 40)}\n${s0.slice(40)}`, { tags: ['strictness'] });
  await syn('token-sig-impossible-length', 'reject', 'Signature length 1 mod 4.', `${h0}.${p0}.${s0.slice(0, -1)}`, { tags: ['strictness'] });
  await syn('token-payload-stray-character', 'reject', 'Stray character in the payload.', `${h0}.${p0}!.${s0}`, { tags: ['strictness'] });
  await syn('token-header-padding', 'reject', 'Padding on the header.', `${h0}=.${p0}.${s0}`, { tags: ['strictness'] });
  await syn('token-header-not-json', 'reject', 'Header that is not JSON.', `${Buffer.from('nope').toString('base64url')}.${p0}.${s0}`);
  await syn('token-header-array', 'reject', 'Header JSON array.', `${jsonSeg([1])}.${p0}.${s0}`);
  await syn('token-payload-array', 'reject', 'Payload JSON array.', `${h0}.${jsonSeg([1])}.${s0}`);
  await syn('token-payload-tampered', 'reject', 'Payload edited after signing.', `${h0}.${jsonSeg({ ...gcpClaims(SYN_BINDING), dbgstat: 'enabled' })}.${s0}`);
  await syn('token-signature-flipped', 'reject', 'Signature edited.', `${h0}.${p0}.${s0.slice(0, 20)}${s0[20] === 'A' ? 'B' : 'A'}${s0.slice(21)}`);
}
