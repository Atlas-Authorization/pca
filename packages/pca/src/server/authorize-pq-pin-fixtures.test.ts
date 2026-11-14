import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createAuthorizer } from './authorize';
import { memoryPcaStore } from './require-pca';

const F = JSON.parse(readFileSync(join(__dirname, '..', '..', 'conformance', 'authorize-pq-pin-fixtures.json'), 'utf8'));

describe('server-side PQ pins inside authorize(): the shared fixtures replay on the reference', () => {
  it('has the format and the cases the natives replay (a real ML-DSA-65 grant among them)', () => {
    expect(F.format).toBe('pca-authorize-pq-pin-fixtures/1');
    expect(F.cases.length).toBeGreaterThanOrEqual(8);
    expect(F.cases.some((c: { grant: { alg?: string } }) => c.grant.alg === 'ml-dsa-65')).toBe(true);
    expect(F.cases.some((c: { grant: { alg?: string } }) => c.grant.alg === undefined)).toBe(true);
  });
  for (const c of F.cases) {
    it(c.name, async () => {
      const az = createAuthorizer({
        audience: F.audience, resolveGrant: async (r) => (r === c.grant.id ? c.grant : null), budgetStore: memoryPcaStore(), hooks: { revocation: () => ({ enforced: true, ok: true }) }, now: () => F.now,
        plan: 'single-step', risk: () => ({ blastRadius: 0, semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }),
        ...(c.pq_pins !== null ? { pqPins: c.pq_pins } : {}),
      });
      const r = await az({ operation: F.operation, pcactn: c.pcactn });
      const failed = Object.entries(r.verdict.checks).filter(([, v]) => v === 'fail').map(([k]) => k);
      expect({ allow: r.allow, decision: r.decision, status: r.status }).toEqual({ allow: c.expect.allow, decision: c.expect.decision, status: c.expect.status });
      for (const f of c.expect.failed_includes) expect(failed).toContain(f);
      if (c.expect.allow) expect(failed).toEqual([]);
      expect((r.verdict.checks as Record<string, string>)['pq_pin'] ?? 'absent').toBe(c.expect.checks.pq_pin);
      if (c.expect.reason !== undefined) expect(r.allow ? '' : r.reason).toContain(c.expect.reason);
    });
  }
});
