import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createAuthorizer } from './authorize';
import { memoryPcaStore } from './require-pca';
import { createProvenanceRecorder, principalDirectProvenance } from '../arg-provenance';

// provenance by default: every operation here comes straight from the principal (a principal-direct bundle under a pinned
// harness key), so the provenance gate passes and the recorded outcomes are those of the rules under test
const provKey = new Uint8Array(32).fill(1);
const provRec = () => createProvenanceRecorder({ mediator: 'conformance-harness', kid: 'k1', secretKey: provKey });
const PROV_PIN = provRec().pin;
const provOf = (o: { verb: string; resource: string; params?: Record<string, unknown> }) => principalDirectProvenance(provRec(), { verb: o.verb, resource: o.resource, params: o.params ?? {} });

const F = JSON.parse(readFileSync(join(__dirname, '..', '..', 'conformance', 'authorize-workflow-fixtures.json'), 'utf8'));

describe('workflow admission inside authorize(): the shared fixtures replay on the reference (C-308)', () => {
  it('has the format and the cases the natives replay', () => {
    expect(F.format).toBe('pca-authorize-workflow-fixtures/1');
    expect(F.cases.length).toBeGreaterThanOrEqual(14);
  });
  for (const c of F.cases) {
    it(c.name, async () => {
      const az = createAuthorizer({
        audience: F.audience, resolveGrant: async (r) => (r === F.grant.id ? F.grant : null), budgetStore: memoryPcaStore(), hooks: { revocation: () => ({ enforced: true, ok: true }) }, now: () => F.now,
        context: () => ({ plan: F.plan, planAuthorized: true }), risk: () => ({ blastRadius: 0, semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }),
        workflow: { principal: F.principal, rsSigner: F.rs_signer, required: c.required },
        provenance: { mediators: [PROV_PIN] },
      });
      for (const s of c.steps) {
        const w = s.workflow;
        const r = await az({ operation: s.operation, pcactn: s.pcactn, provenance: provOf(s.operation), ...(w ? { workflow: { commitment: w.commitment, receipts: w.receipts, step: w.step, units: w.units, goalDigest: w.goal_digest } } : {}) });
        const failed = Object.entries(r.verdict.checks).filter(([, v]) => v === 'fail').map(([k]) => k).sort();
        expect({ allow: r.allow, decision: r.decision, status: r.status, failed }).toEqual({ allow: s.expect.allow, decision: s.expect.decision, status: s.expect.status, failed: s.expect.failed });
        if (s.expect.reason !== undefined) expect(r.allow ? '' : r.reason).toContain(s.expect.reason);
      }
    });
  }
});
