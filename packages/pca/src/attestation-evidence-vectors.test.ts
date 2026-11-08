/**
 * Replays conformance/attestation-evidence-vectors.json through the TypeScript verifiers and guards the file against drift.
 * Every row's `expect` was produced by the real verifier at generation time; here each row is run again from the COMMITTED bytes
 * (blobs hydrated) and must answer exactly `expect`. The Go, Rust and Python verifiers replay the same file.
 * Regenerate with `tsx scripts/gen-conformance-attestation.ts` (then `node scripts/gen-conformance-layers.mjs`).
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { hydrateBlobs, runAttestationVector, runX509Vector, VENDORS, VERIFIER_CONFIG_SCHEMA, type Vendor } from './test-support/attestation-wire';
import { buildAttestationEvidenceVectors } from './test-support/attestation-evidence-vectors';
import type { X509Vector } from './test-support/attestation-vectors-x509';
import type { Vector } from './test-support/attestation-vectors-common';

const FILE = join(__dirname, '..', 'conformance', 'attestation-evidence-vectors.json');
if (!existsSync(FILE)) throw new Error('conformance/attestation-evidence-vectors.json is missing: run `tsx scripts/gen-conformance-attestation.ts` and commit it');
const text = readFileSync(FILE, 'utf8');
const doc = JSON.parse(text) as { blobs: Record<string, string>; attestation_vectors: Vector[]; x509_vectors: X509Vector[]; verifier_config_schema: Record<string, unknown> };
const vectors = doc.attestation_vectors;
const byVendor = (v: Vendor) => vectors.filter((x) => x.vendor === v);

describe('attestation-evidence conformance vectors', () => {
  it('the committed file is exactly what the reference generates', async () => {
    const { doc: fresh, suspicious } = await buildAttestationEvidenceVectors();
    expect(suspicious).toEqual([]);
    expect(text).toBe(`${JSON.stringify(fresh, null, 1)}\n`);
  }, 600_000);

  it('documents the verifier configuration of every vendor (the schema the natives build their factories from)', () => {
    expect(Object.keys(doc.verifier_config_schema).sort()).toEqual([...VENDORS].sort());
    expect(doc.verifier_config_schema).toEqual(JSON.parse(JSON.stringify(VERIFIER_CONFIG_SCHEMA)));
  });

  it('has the agreed coverage: ids unique, every vendor, both intents, strictness rows, minimum counts', () => {
    expect(new Set(vectors.map((v) => v.id)).size).toBe(vectors.length);
    const min: Record<Vendor, number> = { 'amd-sev-snp': 200, 'intel-tdx-dcap': 250, 'azure-maa': 150, 'gcp-confidential-space': 88, 'nvidia-gpu-spdm': 70 };
    for (const v of VENDORS) {
      expect(byVendor(v).length).toBeGreaterThanOrEqual(min[v]);
      expect(byVendor(v).some((x) => x.intent === 'accept')).toBe(true);
      expect(byVendor(v).some((x) => x.intent === 'reject')).toBe(true);
      expect(byVendor(v).some((x) => x.tags.includes('strictness'))).toBe(true);
    }
    for (const v of ['amd-sev-snp', 'intel-tdx-dcap', 'azure-maa', 'nvidia-gpu-spdm'] as const) expect(byVendor(v).some((x) => x.tags.includes('real'))).toBe(true);
    expect(doc.x509_vectors.length).toBeGreaterThanOrEqual(90);
    expect(vectors.length).toBeGreaterThanOrEqual(750);
  });

  it('every row intent agrees with its recorded result', () => {
    for (const v of vectors) {
      const accepted = 'ok' in v.expect && v.expect.ok === true;
      expect([v.id, accepted]).toEqual([v.id, v.intent === 'accept']);
    }
    for (const v of doc.x509_vectors) expect([v.id, v.expect.ok]).toEqual([v.id, v.intent === 'accept']);
  });

  it.each(vectors.map((v) => [v.id, v] as const))('%s', async (_id, v) => {
    const h = hydrateBlobs(v, doc.blobs);
    const got = (await runAttestationVector({ vendor: h.vendor, config: h.config, evidence: h.evidence, now: h.now, expected_binding: h.expected_binding })) as Record<string, unknown>;
    const { reason_match, reason_prefix, ...want } = h.expect as Record<string, unknown>;
    if (reason_match === 'prefix') {
      expect(String(got['reason']).startsWith(String(reason_prefix))).toBe(true);
      expect({ ...got, reason: undefined }).toEqual({ ...want, reason: undefined });
    } else expect(got).toEqual(want);
  });

  it.each(doc.x509_vectors.map((v) => [v.id, v] as const))('%s', (_id, v) => {
    expect(runX509Vector(v.fn, v.input)).toEqual(v.expect);
  });
});
