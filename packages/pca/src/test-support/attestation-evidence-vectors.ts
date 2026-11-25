/**
 * Builder of conformance/attestation-evidence-vectors.json (TEST/TOOLING ONLY). Every `expect` is produced by RUNNING the
 * real TypeScript verifier over the row's `(vendor, config, evidence, now, expected_binding)`; the generator fails when a
 * row's outcome is not what its `intent` says. Deterministic: seeded keys, RFC 6979 / seed-salted signatures, fixed clocks.
 */
import { createHash } from 'node:crypto';
import { VERIFIER_CONFIG_SCHEMA, type Json } from './attestation-wire';
import { Collector, type Vector } from './attestation-vectors-common';
import { buildSnpVectors } from './attestation-vectors-snp';
import { buildDcapVectors } from './attestation-vectors-dcap';
import { buildMaaVectors } from './attestation-vectors-maa';
import { buildGcpVectors } from './attestation-vectors-gcp';
import { buildNvidiaVectors } from './attestation-vectors-nvidia';
import { buildX509Vectors } from './attestation-vectors-x509';

export const DOC = {
  purpose: 'Language-neutral conformance vectors for the vendor attestation verifiers (AMD SEV-SNP, Intel TDX DCAP, Azure MAA, GCP Confidential Space, NVIDIA GPU SPDM) and for the strict X.509 readers they share. A native verifier passes when, for every row, it answers exactly `expect`.',
  generation: 'Every `expect` is produced by RUNNING the TypeScript verifier over the row; the generator fails when a row outcome contradicts its `intent`. Synthetic evidence is minted under test roots with seeded keys, so regeneration is byte-for-byte reproducible.',
  blobs: 'Any string inside `config` or `evidence` may be `{"$blob": "<id>"}`; replace it with `blobs[<id>]` before use. Real evidence is stored once.',
  encodings: 'Bytes are standard base64 (padded). Hex is lowercase. PEM and JSON documents are strings. u64 values above 2^53 are decimal strings. Times are epoch milliseconds.',
  attestation_vectors: 'Row: {id, vendor, tags, intent, description, config, now, expected_binding, evidence, expect}. Build the verifier with verifier_from_config(vendor, config) (keys in verifier_config_schema), hand it `evidence` as what its evidence resolver answers (null: no evidence for the action), run verify with clock `now` and `expected_binding` {holderPub, grantRef, epoch, nonce}. The binding the evidence must carry is attestationBinding(expected) = SHA-512("atlas-pca/attest-bind/v1" || 0x00 || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce)), lp(s) = u32be(len(utf8 s)) || utf8 s; an empty holderPub, grantRef or nonce, or an epoch that is not a non-negative safe integer, is not constructible. `expect` is the whole result: {ok, bound?, reason?, measured?, hostAsserted?} or {construct_error} when the factory must refuse the config.',
  reasons: '`expect.reason` is the exact TypeScript string. When `expect.reason_match` is "prefix", the reason embeds the message of an OpenSSL / node:crypto exception: compare only `reason_prefix` (the text before that message). Every other reason must match byte for byte.',
  intent: '`accept` rows have ok true; `reject` rows have ok false or a construct_error.',
  now: 'The verifier clock lives in each row (`now`), not in `config`, so the passport vectors can reuse `config` unchanged.',
  tags: 'strictness: a malleability or DER rule. real: genuine recorded evidence. synthetic: minted under a test root. collateral:* optional sub-features (Intel PCS collateral, NVIDIA RIM / CRL / OCSP).',
  x509_vectors: 'Row: {id, vendor: "x509", fn, tags, intent, description, input, expect}. fn is one of the functions of the strict DER readers; input members `cert`, `tbs`, `chain[]` are base64 DER. expect is {ok:true,value} or {ok:false,error}; error is the exact message of the TypeScript reader.',
  scope_notes: 'GCP rows are synthetic only: the real Confidential Space captures identify a cloud project and are not published.',
};

const BLOB_MIN = 200;
/** Move every long string of `config` / `evidence` into a shared table, referenced as `{"$blob": id}`. */
export function blobify(vectors: Vector[]): { blobs: Record<string, string>; vectors: Vector[] } {
  const blobs: Record<string, string> = {};
  const walk = (x: unknown): unknown => {
    if (typeof x === 'string') {
      if (x.length < BLOB_MIN) return x;
      const id = `b${createHash('sha256').update(x).digest('hex').slice(0, 20)}`;
      blobs[id] = x;
      return { $blob: id };
    }
    if (Array.isArray(x)) return x.map(walk);
    if (x !== null && typeof x === 'object') return Object.fromEntries(Object.entries(x).map(([k, v]) => [k, walk(v)]));
    return x;
  };
  const out = vectors.map((v) => ({ ...v, config: walk(v.config) as Vector['config'], evidence: walk(v.evidence) as Vector['evidence'] }));
  return { blobs: Object.fromEntries(Object.entries(blobs).sort(([a], [b]) => (a < b ? -1 : 1))), vectors: out };
}

export async function buildAttestationEvidenceVectors(): Promise<{ doc: Record<string, unknown>; suspicious: string[] }> {
  const c = new Collector();
  await buildSnpVectors(c);
  await buildDcapVectors(c);
  await buildMaaVectors(c);
  await buildGcpVectors(c);
  await buildNvidiaVectors(c);
  if (c.mismatches.length) throw new Error(`rows whose outcome contradicts their intent:\n${c.mismatches.join('\n')}`);
  const { blobs, vectors } = blobify(c.vectors);
  return {
    suspicious: c.suspicious,
    doc: { format: 1, suite: 'attestation-evidence', layer: 'proof', _doc: DOC, verifier_config_schema: VERIFIER_CONFIG_SCHEMA as unknown as Json, blobs, attestation_vectors: vectors, x509_vectors: buildX509Vectors() },
  };
}
