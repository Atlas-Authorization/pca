/**
 * Replays the committed wire-level allowlist-anchor vectors against the TypeScript verifier and guards the file against
 * drift: the vectors are regenerated from the reference and must equal the committed file byte for byte. The native
 * verifiers (Go, Rust) replay the same file.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { verifyAllowlistAnchored, type AllowlistAnchorEvidence } from './attest-allowlist-anchor';
import type { VerifyAllowlistResult } from './attest-allowlist';
import { buildAnchorVectors, type AnchorVector } from './test-support/anchor-vectors';

const FILE = join(__dirname, '..', 'conformance', 'allowlist-anchor-vectors.json');
const doc = JSON.parse(readFileSync(FILE, 'utf8')) as ReturnType<typeof buildAnchorVectors>;

describe('allowlist-anchor conformance vectors', () => {
  it('the committed file is exactly what the reference generates (regenerate with scripts/gen-conformance-anchor.ts)', () => {
    expect(readFileSync(FILE, 'utf8')).toBe(`${JSON.stringify(buildAnchorVectors(), null, 2)}\n`);
  });

  it('covers every outcome code the verifier can reach, accept and deny', () => {
    const codes = new Set(doc.allowlist_anchor.map((v) => (v.expect.ok ? 'ok' : v.expect.code)));
    expect([...codes].sort()).toEqual(['anchored-rollback', 'bad-cache', 'bad-head', 'bad-proof', 'feed-mismatch', 'inconsistent-with-cache', 'log-conflict', 'log-rollback', 'missing-proof', 'ok', 'split-view', 'stale-head']);
    expect(doc.allowlist_anchor.length).toBeGreaterThanOrEqual(74);
    expect(new Set(doc.allowlist_anchor.map((v) => v.name)).size).toBe(doc.allowlist_anchor.length);
  });

  it.each(doc.allowlist_anchor.map((v) => [v.name, v] as const))('%s', (_n, v: AnchorVector) => {
    const verified = { ok: true, body: {}, issuer: v.manifest.issuer, alg: 'ed25519', version: v.manifest.version, digest: v.manifest.digest } as unknown as Extract<VerifyAllowlistResult, { ok: true }>;
    const r = verifyAllowlistAnchored(verified, (v.evidence ?? undefined) as AllowlistAnchorEvidence | undefined, {
      trust: doc.trust, nowMs: v.now,
      ...(v.maxHeadAgeMs !== undefined ? { maxHeadAgeMs: v.maxHeadAgeMs } : {}), ...(v.clockSkewMs !== undefined ? { clockSkewMs: v.clockSkewMs } : {}), ...(v.cachedHead ? { cachedHead: v.cachedHead } : {}),
    });
    expect(r.ok ? { ok: true, highestAnchoredVersion: r.highestAnchoredVersion } : { ok: false, code: r.code }).toEqual(v.expect);
  });
});
