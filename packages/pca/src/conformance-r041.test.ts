// Re-runs the 0.4.1 conformance sections against the reference (the generator asserted them when it wrote them).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { decodePcaHeader } from './adapters';
import { evaluateAgentCaveats, policyCaveats } from './policy-vm';

const corpus = JSON.parse(readFileSync(join(__dirname, '..', 'conformance', 'vectors.json'), 'utf8'));
type Ctx = { now: number; delegation_depth?: number; blast_radius?: number; reversibility_class?: string; recent_action_times?: number[]; action: Record<string, unknown> };

describe('conformance 0.4.1: caveat_eval (root caveats are policy)', () => {
  const cases: { name: string; grant: never; chain: never; context: Ctx; expect: { allow: boolean; failed: string[] } }[] = corpus.primitives.caveat_eval;
  it('carries the root max_spend DENY / ALLOW pair', () => {
    const by = new Map(cases.map((c) => [c.name, c]));
    expect(by.get('r041-root-max-spend-exceeded')?.expect.allow).toBe(false);
    expect(by.get('r041-root-max-spend-within')?.expect.allow).toBe(true);
    expect(cases.length).toBeGreaterThanOrEqual(40);
  });
  it.each(cases.map((c) => [c.name, c] as const))('%s', (_n, c) => {
    const x = c.context;
    const r = evaluateAgentCaveats(
      policyCaveats(c.grant, c.chain),
      {
        now: x.now,
        delegationDepth: x.delegation_depth,
        ...(x.blast_radius !== undefined ? { blastRadius: x.blast_radius } : {}),
        ...(x.reversibility_class !== undefined ? { reversibilityClass: x.reversibility_class } : {}),
        ...(x.recent_action_times !== undefined ? { recentActionTimes: x.recent_action_times } : {}),
      },
      { action: x.action as never },
    );
    expect({ allow: r.ok, failed: r.failed }).toEqual(c.expect);
  });
});

describe('conformance 0.4.1: pca_header (strict unpadded base64url)', () => {
  const cases: { name: string; input: string; valid: boolean; text?: string }[] = corpus.primitives.pca_header;
  it.each(cases.map((c) => [c.name, c] as const))('%s', (_n, c) => {
    let text: string | undefined;
    let valid = true;
    try {
      text = decodePcaHeader(c.input);
    } catch {
      valid = false;
    }
    expect(valid).toBe(c.valid);
    if (valid) expect(text).toBe(c.text);
  });
});

describe('conformance 0.4.1: per-suite share vectors are present', () => {
  it('pure ML-DSA-65 share positive + wrong-length negatives', () => {
    const names = new Set(corpus.vectors.map((v: { name: string }) => v.name));
    for (const n of ['r041-share-ml-dsa-65-carried', 'r041-share-ml-dsa-65-3308', 'r041-share-hybrid-missing-pq_sig', 'r041-share-unknown-alg']) expect(names.has(n)).toBe(true);
  });
});
