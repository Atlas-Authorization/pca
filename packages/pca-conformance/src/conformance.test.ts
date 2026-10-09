import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { type PCActn, verifyPCActnCore } from '@atlasauth/pca';
import {
  CANONICAL_GRANT,
  CONFORMANCE_VERSION,
  type ConformanceVectorSet,
  VECTORS,
  coreVerify,
  firstFailedCheck,
  generateVectorSet,
  materializeEnforce,
  runConformance,
  serializeVectorSet,
} from './index';

const VECTORS_PATH = join(__dirname, '..', 'vectors.json');

describe('PCActn conformance vectors (TS reference verifier = @atlasauth/pca)', () => {
  it('has one canonical valid vector + exactly one per documented failure mode', () => {
    expect(VECTORS.map((v) => v.id)).toEqual([
      'valid',
      'bad_wire',
      'wrong_version',
      'audience_mismatch',
      'expired',
      'not_yet_valid',
      'grant_ref_not_root_id',
      'broken_cap_chain_sig',
      'plan_non_inclusion',
      'bad_leaf_signature',
      'counter_invalid',
      'stale_freshness',
      'taint_blocked',
      'missing_attestation',
    ]);
    // ids are unique
    expect(new Set(VECTORS.map((v) => v.id)).size).toBe(VECTORS.length);
    // exactly one vector verifies
    expect(VECTORS.filter((v) => v.expect.ok)).toHaveLength(1);
    expect(VECTORS.find((v) => v.expect.ok)?.id).toBe('valid');
  });

  // The CORE verifier must produce EXACTLY the authored per-check outcome for every vector.
  for (const v of VECTORS) {
    it(`${v.id}: ${v.description}`, async () => {
      const grant = v.pcactn.cap_chain[0] ?? CANONICAL_GRANT;
      const r = await verifyPCActnCore(v.pcactn, {
        grant,
        nowEpoch: v.verifyOptions.nowEpoch,
        audience: v.aud,
        ...(v.verifyOptions.enforce ? { enforce: materializeEnforce(v.verifyOptions.enforce) } : {}),
      });
      expect(r.allow).toBe(v.expect.ok);
      expect(r.checks).toEqual(v.expect.perCheck);
      expect(firstFailedCheck(r.checks)).toBe(v.expect.firstFailedCheck);
      // a wire failure is terminal: it is the ONLY check reported
      if (v.expect.firstFailedCheck === 'wire') expect(Object.keys(r.checks)).toEqual(['wire']);
    });
  }

  it('runConformance over the default core verifier: every vector matches its expectation', async () => {
    const report = await runConformance();
    expect(report.version).toBe(CONFORMANCE_VERSION);
    expect(report.total).toBe(VECTORS.length);
    expect(report.failed).toBe(0);
    expect(report.ok).toBe(true);
    for (const r of report.results) expect(r.divergences, `${r.id} diverged`).toEqual([]);
  });

  it('runConformance detects divergence from a non-conformant verifier', async () => {
    // A broken verifier that blindly allows everything with no per-check detail must diverge on EVERY
    // vector: the failure vectors on `allow`, and even `valid` on its per-check map (empty != full BASE).
    const report = await runConformance(() => ({ allow: true, checks: {} }));
    expect(report.ok).toBe(false);
    expect(report.passed).toBe(0);
    expect(report.failed).toBe(VECTORS.length);
    expect(report.results.find((r) => r.id === 'valid')?.matched).toBe(false);
  });
});

describe('vectors.json (the bytes non-TS SDKs load)', () => {
  it('round-trips: the committed file parses to exactly the generated vector set', () => {
    const onDisk = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as ConformanceVectorSet;
    expect(onDisk).toEqual(generateVectorSet());
  });

  it('is deterministic: regenerating yields byte-identical content to the committed file', () => {
    const regenerated = serializeVectorSet(generateVectorSet());
    expect(regenerated).toBe(readFileSync(VECTORS_PATH, 'utf8'));
  });

  it('regeneration is stable across repeated calls (no randomness / clock)', () => {
    expect(serializeVectorSet(generateVectorSet())).toBe(serializeVectorSet(generateVectorSet()));
  });

  it('every vector in the file is a structurally complete vector', () => {
    const set = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as ConformanceVectorSet;
    expect(set.version).toBe(CONFORMANCE_VERSION);
    for (const v of set.vectors) {
      expect(typeof v.id).toBe('string');
      expect(typeof v.description).toBe('string');
      expect(v.pcactn).toBeTypeOf('object');
      const p = v.pcactn as PCActn;
      expect(Array.isArray(p.cap_chain)).toBe(true);
      expect(v.expect).toBeTypeOf('object');
      expect(typeof v.expect.ok).toBe('boolean');
      expect(v.expect.perCheck).toBeTypeOf('object');
    }
  });

  it('the default coreVerify is a valid HarnessVerify over the parsed-from-disk bytes', async () => {
    const set = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as ConformanceVectorSet;
    const report = await runConformance(coreVerify, set.vectors);
    expect(report.ok).toBe(true);
  });
});
