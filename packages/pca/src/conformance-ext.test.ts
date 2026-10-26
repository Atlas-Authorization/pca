// The extension layer of the conformance corpus (conformance/LAYERS.md): optimistic-vectors.json and ledger-vectors.json.
// The generators computed `expect` from the reference with the same evaluation (scripts/conformance-ext.mjs), pinned to the
// intended outcome of every case; this test re-derives every verdict from SOURCE and re-generates the files byte for byte,
// so a change to a verifier that moves any verdict, or a vector file edited by hand, fails here.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import * as core from './index';
import * as opt from './ext/optimistic';
import * as led from './ext/ledger';

const CONF = join(__dirname, '..', 'conformance');
const text = (f: string) => readFileSync(join(CONF, f), 'utf8');
/* eslint-disable @typescript-eslint/no-explicit-any */
let X: any;
beforeAll(async () => {
  X = await import(pathToFileURL(join(__dirname, '..', 'scripts', 'conformance-ext.mjs')).href);
});
const optDoc = JSON.parse(text('optimistic-vectors.json'));
const ledDoc = JSON.parse(text('ledger-vectors.json'));

describe('extension layer: optimistic vectors', () => {
  const tables = ['optimistic_claim', 'optimistic_window', 'optimistic_fraud_proof', 'optimistic_settlement'] as const;
  for (const t of tables) {
    it(`${t}: every vector reproduces`, () => {
      const rows = optDoc[t] as any[];
      expect(rows.length).toBe(optDoc.counts[t]);
      expect(new Set(rows.map((r) => r.name)).size).toBe(rows.length);
      for (const v of rows) expect(X.evaluateOptimistic({ opt }, t, v), `${t}/${v.name}`).toEqual(v.expect);
    });
  }
  it('every check of every ordered list is the FIRST failure of at least one vector, and each table has accepts and rejects', () => {
    for (const [t, list] of Object.entries(optDoc.check_order as Record<string, string>)) {
      const order = list.split(',');
      const seen = new Set((optDoc[t] as any[]).map((v) => v.expect.check));
      for (const c of order) expect(seen.has(c), `${t}: ${c}`).toBe(true);
      expect(seen.has('ok'), `${t}: ok`).toBe(true);
    }
    const win = optDoc.optimistic_window as any[];
    expect(win.some((v) => v.expect.within)).toBe(true);
    expect(win.some((v) => !v.expect.within)).toBe(true);
  });
  it('the window boundary is inclusive: the last instant of the window is open, the next is finalized', () => {
    const at = (optDoc.optimistic_window as any[]).filter((v) => v.name.endsWith('-at-end'));
    expect(at.length).toBeGreaterThan(0);
    for (const v of at) expect(v.expect).toEqual({ end: v.now, within: true, phase: 'open' });
    for (const v of (optDoc.optimistic_window as any[]).filter((x) => x.name.endsWith('-after'))) expect(v.expect.phase).toBe('finalized');
  });
  it('a fraud proof filed by the reference passes the wire check, and each wire rule fails without its check', () => {
    // fileFraudProof is exercised end to end in optimistic.test.ts; here the wire rules are pinned by mutation of a valid proof
    const base = (optDoc.optimistic_fraud_proof as any[]).find((v) => v.name === 'ok-policy-denied');
    expect(opt.fraudProofWireCheck(base.claim, base.proof)).toBe('ok');
    expect(opt.fraudProofWireCheck(base.claim, { ...base.proof, decision: { ...base.proof.decision, releaseGuardianShare: true } })).toBe('consistency');
    expect(opt.fraudProofWireCheck(base.claim, { ...base.proof, kind: 'x' })).toBe('kind');
  });
  it('regenerates byte for byte from the reference', () => {
    expect(X.serializeExt(X.buildOptimistic({ opt, core }))).toBe(text('optimistic-vectors.json'));
  });
});

describe('extension layer: ledger vectors', () => {
  const tables = ['ledger_inclusion', 'ledger_consistency', 'ledger_tree_head', 'ledger_cosign', 'ledger_head_consistency', 'ledger_checkpoint_chain', 'ledger_witnessed_head', 'ledger_equivocation'] as const;
  for (const t of tables) {
    it(`${t}: every vector reproduces, with accepts and rejects`, () => {
      const rows = ledDoc[t] as any[];
      expect(rows.length).toBe(ledDoc.counts[t]);
      expect(new Set(rows.map((r) => r.name)).size).toBe(rows.length);
      for (const v of rows) expect(X.evaluateLedger({ led }, t, v), `${t}/${v.name}`).toEqual(v.expect);
      const verdicts = new Set(rows.map((v) => JSON.stringify(v.expect.ok ?? v.expect.equivocation)));
      expect(verdicts.size, t).toBe(2);
    });
  }
  it('the domains the natives must reproduce are the library constants', () => {
    expect(ledDoc.domains.sth).toBe(led.STH_DOMAIN);
    expect(ledDoc.domains.sth_witness).toBe(led.STH_WITNESS_DOMAIN);
    expect(ledDoc.empty_tree_root).toBe(led.EMPTY_TREE_ROOT);
  });
  it('regenerates byte for byte from the reference', () => {
    expect(X.serializeExt(X.buildLedger({ led, core }))).toBe(text('ledger-vectors.json'));
  });
});
