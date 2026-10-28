import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { checkPcaGrantPresentation, parsePcaGrantDetails, pcaChainDigest, validatePcaGrantDetail, type PcaGrantDetail } from './pca-grant-details';
import { buildPcaGrantVectors } from './test-support/pca-grant-vectors';

const file = join(__dirname, '..', 'conformance', 'pca-grant-vectors.json');
const V = JSON.parse(readFileSync(file, 'utf8'));

describe('pca_grant authorization details (RFC 9396 profile) - T-580', () => {
  it('the committed vector file is exactly what the generator writes', () => {
    expect(readFileSync(file, 'utf8')).toBe(`${JSON.stringify(buildPcaGrantVectors(), null, 2)}\n`);
  });

  it('chain digests match the vectors', () => {
    for (const d of V.digest) expect(pcaChainDigest(d.ids)).toBe(d.digest);
  });

  for (const v of V.detail) {
    it(`detail: ${v.name}`, () => {
      const r = validatePcaGrantDetail(v.input);
      expect(r.ok).toBe(v.expect.ok);
      if (!r.ok) expect(r.code).toBe(v.expect.code);
    });
  }

  for (const v of V.array) {
    it(`array: ${v.name}`, () => {
      const r = parsePcaGrantDetails(v.input);
      expect(r.ok).toBe(v.expect.ok);
      if (r.ok) expect(r.details.length).toBe(v.expect.count);
      else expect(r.code).toBe(v.expect.code);
    });
  }

  for (const v of V.presentation) {
    it(`presentation: ${v.name}`, () => {
      const r = checkPcaGrantPresentation(v.details as PcaGrantDetail[], {
        resource: v.presented.resource,
        chainIds: v.presented.chain_ids,
        proofVerified: v.presented.proof_verified,
      });
      expect(r.allow).toBe(v.expect.allow);
      if (r.allow) expect(v.details.indexOf(r.detail)).toBe(v.expect.index);
      else expect(r.code).toBe(v.expect.code);
    });
  }

  it('a proofVerified of anything but true is a deny (a truthy string is not a verified proof)', () => {
    const d = V.presentation[0].details as PcaGrantDetail[];
    const r = checkPcaGrantPresentation(d, { resource: 'https://api.example.com', chainIds: ['capA'], proofVerified: 'yes' as unknown as boolean });
    expect(r).toEqual({ allow: false, code: 'proof_required' });
  });
});
