/**
 * r13 mutation kills for module-level constants of ledger.ts, semantic-threshold.ts and mesh.ts (static mutants; each
 * test re-evaluates the modules): the witness-head signature domain (checked with a plain Ed25519 verify), the STH and
 * STH-witness domains, the consistency-path bound (a real 3-element proof must verify), the semantic-judge domain, and
 * the witness memory export order (sorted by domain whatever the insertion order).
 */
import { describe, expect, it, vi } from 'vitest';
import { canonicalBytes, utf8 } from './hash';
import { verifyB64u } from './keys';

async function freshLedger() {
  vi.resetModules();
  return import('./ledger');
}
const settle = <T>(f: () => T) => {
  try {
    return { ok: true as const, value: f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};

describe('ledger constants (fresh module)', () => {
  it('STH domains', async () => {
    const l = await freshLedger();
    expect([l.STH_DOMAIN, l.STH_WITNESS_DOMAIN]).toEqual(['atlas-pca/sth/v1\0', 'atlas-pca/sth-witness/v2\0']);
  });
  it('a witnessed head is signed over utf8("atlas-pca/ledger-head/v1\\0") || canonical({principal, size, root})', async () => {
    const l = await freshLedger();
    const led = new l.TransparencyLedger('p');
    led.appendCommitment('c1');
    const wh = led.witnessHead(new Uint8Array(32).fill(5));
    const d = utf8('atlas-pca/ledger-head/v1\0');
    const b = canonicalBytes({ principal: 'p', size: 1, root: wh.root });
    const msg = new Uint8Array(d.length + b.length);
    msg.set(d);
    msg.set(b, d.length);
    expect(verifyB64u(wh.witness, msg, wh.sig)).toBe(true);
  });
  it('a real multi-element consistency proof verifies (the path bound admits it)', async () => {
    const l = await freshLedger();
    const led = new l.TransparencyLedger('p');
    for (let i = 0; i < 13; i++) led.appendCommitment(`c${i}`);
    const proof = led.consistencyProof(5, 13);
    expect(proof.path.length).toBeGreaterThanOrEqual(3);
    expect(settle(() => l.verifyLedgerConsistency(led.rootAt(5), led.rootAt(13), proof))).toEqual({ ok: true, value: true });
  });
});

describe('semantic-threshold constant (fresh module)', () => {
  it('judge domain', async () => {
    vi.resetModules();
    const s = await import('./semantic-threshold');
    expect(s.SEMANTIC_JUDGE_DOMAIN).toBe('atlas-pca/semantic-judge/v1\0');
  });
});

describe('mesh witness export order', () => {
  it('exportState is sorted by domain for any insertion order', async () => {
    vi.resetModules();
    const mesh = await import('./mesh');
    const ex = mesh.buildMeshExample();
    const w = ex.witnesses[0]!;
    const st = w.exportState();
    const domains = st.seen.map((s) => s.head.domain);
    expect(domains.length).toBeGreaterThanOrEqual(3);
    const sorted = [...domains].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    expect(domains).toEqual(sorted);
    const w2 = new mesh.MeshWitness(new Uint8Array(32).fill(7));
    w2.importState({ seen: [...st.seen].reverse() });
    expect(w2.exportState().seen.map((s) => s.head.domain)).toEqual(sorted);
    w2.importState({ seen: [st.seen[1]!, st.seen[2]!, st.seen[0]!] });
    expect(w2.exportState().seen.map((s) => s.head.domain)).toEqual(sorted);
  });
});
