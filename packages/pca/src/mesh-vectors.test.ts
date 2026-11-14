import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { type MeshProof, type MeshTrust, verifyMeshProof } from './mesh';

// The shared mesh corpus (conformance/mesh-vectors.json). The Go and Rust verifiers replay the same file; here the
// reference must reproduce its own recorded verdicts, and the corpus must keep covering what it claims to.
const doc = JSON.parse(readFileSync(join(__dirname, '..', 'conformance', 'mesh-vectors.json'), 'utf8')) as {
  mesh: { name: string; requires?: string[]; proof: MeshProof; trust: MeshTrust; expect: { ok: boolean; reason?: string; hop?: number } }[];
};

describe('mesh conformance vectors', () => {
  it('the reference reproduces every recorded verdict exactly', () => {
    for (const v of doc.mesh) {
      const got = verifyMeshProof(structuredClone(v.proof), structuredClone(v.trust));
      expect({ ok: got.ok, ...(got.reason !== undefined ? { reason: got.reason } : {}), ...(got.hop !== undefined ? { hop: got.hop } : {}) }, v.name).toEqual(v.expect);
    }
  });
  it('covers acceptance, every kind of refusal and the pin vectors', () => {
    expect(doc.mesh.length).toBeGreaterThanOrEqual(130);
    expect(new Set(doc.mesh.map((v) => v.name)).size).toBe(doc.mesh.length);
    expect(doc.mesh.filter((v) => v.expect.ok).length).toBeGreaterThanOrEqual(15);
    const reasons = new Set(doc.mesh.map((v) => v.expect.reason?.split(':')[0]));
    for (const r of ['capability revoked (or revocation proof invalid)', 'unknown caveat type "mystery" (fail closed)', 'hop not included in the issuing domain log', 'malformed hop evidence', 'action is stale']) {
      expect(doc.mesh.some((v) => v.expect.reason === r) || reasons.has(r), r).toBe(true);
    }
    expect(doc.mesh.filter((v) => v.requires?.includes('pin_consistency')).length).toBeGreaterThanOrEqual(2);
  });
});
