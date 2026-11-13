import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { admitStep, bindPromises, planRootAuthorized, receiptRef, valueDigest, workflowDigest } from './workflow';
import { checkSink, readChainLabels, readGrantDigest, readReceiptRef, redactRead } from './readside';
import { buildReadsideVectors, buildWorkflowVectors } from './test-support/k5-vectors';

const dir = join(__dirname, '..', 'conformance');
const read = (n: string) => readFileSync(join(dir, n), 'utf8');
const W = JSON.parse(read('workflow-vectors.json'));
const R = JSON.parse(read('readside-vectors.json'));

describe('K5 workflow admission shared vectors (T-720..T-727)', () => {
  it('the committed files are exactly what the generator writes', () => {
    expect(read('workflow-vectors.json')).toBe(`${JSON.stringify(buildWorkflowVectors(), null, 2)}\n`);
    expect(read('readside-vectors.json')).toBe(`${JSON.stringify(buildReadsideVectors(), null, 2)}\n`);
  });
  it('digests', () => {
    expect(workflowDigest(W.workflows.main.body)).toBe(W.digests.workflow);
    for (const v of W.digests.values) expect(valueDigest(v.value)).toBe(v.digest);
    expect(W.digests.receipt_refs).toHaveLength(4);
  });
  const run = (f: typeof admitStep, c: any) => f({ workflow: W.workflows[c.workflow], principal: c.principal, rsSigner: c.rs_signer, receipts: c.receipts, now: c.now, request: c.request });
  for (const c of W.admit) it(`admit: ${c.name}`, () => expect(run(admitStep, c)).toEqual(c.expect));
  for (const c of W.bind) it(`bind: ${c.name}`, () => expect(run(bindPromises, c)).toEqual(c.expect));
  for (const c of W.plan_root) it(`plan_root_authorized: ${c.name}`, () => expect(planRootAuthorized(W.workflows[c.workflow], c.principal, c.now, c.root)).toBe(c.expect));
  it('every denial code of the contract is exercised', () => {
    const seen = new Set<string>([...W.admit, ...W.bind].map((c: any) => c.expect.code).filter(Boolean));
    for (const code of ['bad_workflow', 'bad_dag', 'bad_signature', 'not_yet', 'expired', 'goal_mismatch', 'plan_root_mismatch', 'bad_receipt', 'unplanned_step', 'step_mismatch', 'params_mismatch', 'already_done', 'budget_exceeded', 'deps_unmet', 'dep_failed', 'stale_dep', 'edge_missing', 'edge_unit', 'edge_digest', 'edge_value', 'edge_relation', 'taint_flow', 'pipeline_unconstrained', 'taint_escalate']) {
      expect(seen.has(code), code).toBe(true);
    }
  });
  it('never throws on hostile input', () => {
    for (const x of [null, undefined, 1, 'x', [], {}, { body: null }, { body: {}, sig: 1 }]) {
      const r = admitStep({ workflow: x, principal: W.keys.principal, rsSigner: W.keys.rs, receipts: [], now: 1, request: x });
      expect(r.decision).toBe('deny');
    }
    expect(admitStep({ workflow: W.workflows.main, principal: W.keys.principal, rsSigner: W.keys.rs, receipts: 'x' as never, now: 1, request: {} }).decision).toBe('deny');
  });
  it('receipt refs', () => {
    expect(receiptRef).toBeTypeOf('function');
  });
});

describe('K5 read-side shared vectors (T-410..T-419)', () => {
  for (const c of R.redact) {
    it(`redact: ${c.name}`, () => expect(redactRead({ ...c.input, grant: R.grants[c.grant] })).toEqual(c.expect));
  }
  for (const c of R.sinks) {
    it(`sink: ${c.name}`, () => expect(checkSink({ grant: R.grants[c.grant], principal: c.principal, rsSigner: c.rs_signer, now: c.now, sink: c.sink, receipts: c.receipts })).toEqual(c.expect));
  }
  it('digests and chain labels', () => {
    expect(readGrantDigest(R.grants.main.body)).toBe(R.digests.grant);
    expect(readChainLabels(R.sinks.find((s: any) => s.name === 'chain-of-two-public-reads').receipts, R.keys.rs, R.digests.grant, 1_800_000_000_000)).toEqual(R.digests.chain_labels);
    expect(readReceiptRef).toBeTypeOf('function');
  });
  it('the masked view never contains a dropped value', () => {
    const c = R.redact.find((x: any) => x.name === 'support-view');
    const text = JSON.stringify(c.expect.view);
    for (const secret of ['sk_live_x', '123-45-6789', 'dev-1', 'c_77', 'not in the schema']) expect(text.includes(secret)).toBe(false);
  });
});

import { aggregateRead, detokenize, discreteLaplace, memoryVault, redactReadWithVault, seededDraws } from './read-vault';
import { buildVaultAggregateVectors } from './test-support/k5-vectors';
const VA = JSON.parse(read('vault-aggregate-vectors.json'));
describe('K5 vault and aggregate shared vectors (T-415..T-417)', () => {
  it('the committed file is exactly what the generator writes', () => {
    expect(read('vault-aggregate-vectors.json')).toBe(`${JSON.stringify(buildVaultAggregateVectors(), null, 2)}\n`);
  });
  it('sampler streams', () => {
    for (const u of VA.sampler.uniform) {
      const d = seededDraws(u.seed);
      expect(u.bounds.map((n: number) => d.uniform(n))).toEqual(u.draws);
    }
    for (const l of VA.sampler.laplace) {
      const d = seededDraws(l.seed);
      expect(Array.from({ length: l.values.length }, () => discreteLaplace(d, l.s, l.t))).toEqual(l.values);
    }
  });
  for (const c of VA.vault) {
    it(`vault: ${c.name}`, () => {
      const store = memoryVault();
      const red = redactReadWithVault({ ...c.redact, grant: VA.grants.vault[c.redact_grant] }, store);
      const token = c.token ?? red.view[c.field];
      expect(detokenize({ grant: VA.grants.vault[c.detok_grant], ...c.detok, token, store })).toEqual(c.expect);
    });
  }
  for (const c of VA.aggregate) {
    it(`aggregate: ${c.name}`, () => {
      let state = c.initial_state;
      for (const s of c.steps) {
        const r = aggregateRead({ principal: VA.keys.principal, now: 1_800_000_000_000, verb: 'orders.stats', resource: 'orders/eu', purpose: 'analytics', fn: 'sum', values: [10, 20, 500, -900], salt: 'a-per-read-secret-salt', noise: 'seeded', ...s.input, grant: VA.grants.aggregate[s.input.grant], state });
        expect(r).toEqual(s.expect);
        state = r.state;
      }
    });
  }
});
