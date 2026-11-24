/**
 * arg-provenance.ts builds its domains, its label lattice, the origin levels, the floor list, the read-safe traits and a few
 * small helpers (join, word test, sorted-unique, operation shape) at module load. These tests re-evaluate the module
 * (vi.resetModules + dynamic import) and check each through the public decision.
 */
import { describe, expect, it, vi } from 'vitest';

async function fresh() {
  vi.resetModules();
  return import('./arg-provenance');
}

const KEY = new Uint8Array(32).fill(3);
const OP = { verb: 'pay', resource: 'acct', params: { amount: 5 } };

async function world() {
  const a = await fresh();
  const rec = () => a.createProvenanceRecorder({ mediator: 'harness', kid: 'k1', secretKey: KEY, now: () => 1000 });
  const pin = rec().pin;
  return { a, rec, pin };
}

describe('published constants (fresh module)', () => {
  it('domains, header and read-safe traits are the normative strings', async () => {
    const a = await fresh();
    expect(a.PROV_RECEIPT_DOMAIN).toBe('atlas-pca/prov-receipt/v1\0');
    expect(a.PROV_RECEIPT_REF_DOMAIN).toBe('atlas-pca/prov-receipt-ref/v1');
    expect(a.PROV_ACTION_DOMAIN).toBe('atlas-pca/prov-action/v1');
    expect(a.PROV_HEADER).toBe('PCA-Provenance');
    expect(a.READ_SAFE_TRAITS).toEqual(['pca.financial_data_read', 'pca.pii_access', 'pca.regulated_data']);
  });
  it('each read-safe trait keeps a read-only action non-sensitive; any other trait makes it sensitive', async () => {
    const a = await fresh();
    for (const t of ['pca.financial_data_read', 'pca.pii_access', 'pca.regulated_data']) expect(a.isReadOnlyAction({ effects: ['read'], traits: [t] })).toBe(true);
    expect(a.isReadOnlyAction({ effects: ['read'], traits: ['pca.other'] })).toBe(false);
  });
});

describe('the label lattice and origin levels (fresh module)', () => {
  it('a principal-direct bundle is trusted: pass with a trusted control and labels', async () => {
    const { a, rec, pin } = await world();
    const d = a.decideArgProvenance({ bundle: a.principalDirectProvenance(rec(), OP), operation: OP, mediators: [pin] });
    expect(d.outcome).toBe('pass');
    expect(d.control).toBe('trusted');
    expect(d.labels).toEqual({ amount: 'trusted' });
    expect(d.tainted).toEqual([]);
  });
  it('an observation raises the context to its origin level (tool, retrieval -> tool; web -> web)', async () => {
    const { a, rec, pin } = await world();
    for (const [origin, level] of [['tool', 'tool'], ['retrieval', 'tool'], ['web', 'web']] as const) {
      const d = a.decideArgProvenance({ bundle: a.principalDirectProvenance(rec(), OP), operation: OP, mediators: [pin], observed: [{ origin, source: 's1' }] });
      expect(d.control).toBe(level);
      expect(d.labels).toEqual({ amount: 'trusted' }); // the principal typed the value itself
      expect(d.outcome).toBe('escalate');
      expect(d.path).toEqual([`${origin}:s1`]);
    }
  });
  it('a tool segment in the chain sets the context to tool; an untrusted value is tainted against the first_party floor', async () => {
    const { a, rec, pin } = await world();
    const r = rec();
    r.tool('search', 'result text');
    const op = { verb: 'pay', resource: 'acct', params: { payee: 'mallory' } };
    const d = a.decideArgProvenance({ bundle: r.forAction(op), operation: op, mediators: [pin], principalControl: true });
    expect(d.control).toBe('trusted');
    expect(d.labels).toEqual({ payee: 'tool' });
    expect(d.tainted).toEqual(['payee']);
    expect(d.outcome).toBe('escalate');
    expect(d.code).toBe('untrusted_args');
  });
  it('declared floors first_party, tool and agent are all accepted; another value is a malformed action', async () => {
    const { a, rec, pin } = await world();
    for (const f of ['first_party', 'tool', 'agent']) {
      const d = a.decideArgProvenance({ bundle: a.principalDirectProvenance(rec(), OP), operation: OP, mediators: [pin], action: { params: { amount: f as never } } });
      expect(d.outcome).toBe('pass');
    }
    const bad = a.decideArgProvenance({ bundle: a.principalDirectProvenance(rec(), OP), operation: OP, mediators: [pin], action: { params: { amount: 'web' as never } } });
    expect(bad.outcome).toBe('deny');
    expect(bad.code).toBe('malformed_action');
  });
  it('a well-formed operation is accepted (never malformed_operation)', async () => {
    const { a, pin } = await world();
    const d = a.decideArgProvenance({ operation: { verb: 'v', resource: 'r', params: {} }, mediators: [pin], principalControl: true });
    expect(d.outcome).toBe('pass');
  });
});

describe('token boundaries (fresh module)', () => {
  it('a needle inside a word is not a token; at word boundaries it is', async () => {
    const a = await fresh();
    expect(a.occursAsToken('xab', 'ab')).toBe(false);
    expect(a.occursAsToken('abx', 'ab')).toBe(false);
    expect(a.occursAsToken('9ab', 'ab')).toBe(false);
    expect(a.occursAsToken('Zab', 'ab')).toBe(false);
    expect(a.occursAsToken('_ab', 'ab')).toBe(false);
    expect(a.occursAsToken('éab', 'ab')).toBe(false);
    expect(a.occursAsToken('x ab.', 'ab')).toBe(true);
  });
});
