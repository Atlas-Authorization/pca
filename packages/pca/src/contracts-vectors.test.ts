import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ContractEnforcer, signContractReset } from './contract-enforcer';
import { advanceContract, checkContract, validateContract, verifyContract, type Contract, type SignedContract } from './contracts';
import { createMemoryDurableKv } from './durable-state';
import type { ActionContext } from './predicates';
import { emptyState, stateDigest, type MonitorState } from './prohibitions';
import { buildContractsVectors } from './test-support/contracts-vectors';

const PATH = new URL('../conformance/contracts-vectors.json', import.meta.url);
const file = JSON.parse(readFileSync(PATH, 'utf8')) as {
  principal: string;
  validate: Array<{ name: string; contract: unknown; expect: { problems: string[] } }>;
  check: Array<{ name: string; contract: unknown; action: ActionContext; state: MonitorState; expect: unknown }>;
  advance: Array<{ name: string; contract: Contract; genesis_now: number; steps: Array<{ action: ActionContext; options?: { now?: number; expectedSeq?: number; stale_digest_of_genesis?: boolean }; expect: Record<string, unknown> }> }>;
  verify: Array<{ name: string; contract: unknown; principal?: string; expect: unknown }>;
  enforcer: [{ contract: SignedContract; principal: string; clock: number }, ...Array<{ name: string; options?: { latchOnViolation: boolean }; stored_document?: unknown; steps: Array<Record<string, unknown> & { op: string; expect: unknown }> }>];
};

describe('contracts-vectors.json', () => {
  it('is what the generator writes', async () => {
    expect(`${JSON.stringify(await buildContractsVectors(), null, 2)}\n`).toBe(readFileSync(PATH, 'utf8'));
  });
  it('has every table populated', () => {
    expect([file.validate.length, file.check.length, file.advance.length, file.verify.length, file.enforcer.length].every((n) => n > 4)).toBe(true);
  });
  it.each(file.validate)('validate: $name', (v) => expect(validateContract(v.contract)).toEqual(v.expect.problems));
  it.each(file.check)('check: $name', (v) => expect(checkContract(v.action, v.contract as Contract, v.state)).toEqual(v.expect));
  it.each(file.verify)('verify: $name', (v) => expect(verifyContract(v.contract as SignedContract, v.principal)).toEqual(v.expect));
  it.each(file.advance)('advance: $name', (v) => {
    let st = emptyState(v.genesis_now);
    for (const step of v.steps) {
      const o: { now?: number; expectedSeq?: number; expectedStateDigest?: string } = {};
      if (step.options?.now !== undefined) o.now = step.options.now;
      if (step.options?.expectedSeq !== undefined) o.expectedSeq = step.options.expectedSeq;
      if (step.options?.stale_digest_of_genesis) o.expectedStateDigest = stateDigest(emptyState(v.genesis_now));
      const r = advanceContract(st, step.action, v.contract, o);
      if (r.ok) st = r.next;
      expect({ ok: r.ok, decidedBy: r.decidedBy, violated: r.violated, reasons: r.reasons, seq: r.next.seq, deadlines: r.next.deadlines ?? {}, latched: Object.keys(r.next.latched).sort(), state_digest: stateDigest(r.next) }).toEqual(step.expect);
    }
  });
  const [head, ...scenarios] = file.enforcer;
  it.each(scenarios)('enforcer: $name', async (v) => {
    const kv = createMemoryDurableKv();
    let wall = head.clock;
    const e = ContractEnforcer.open(kv, head.contract, { principal: head.principal, now: () => wall, ...(v.options ?? {}) });
    if (v.stored_document !== undefined) await kv.set(`contract/${head.contract.id}`, v.stored_document);
    for (const st of v.steps) {
      if (st.op === 'check') {
        wall = (st['wall'] as number | undefined) ?? head.clock;
        expect(await e.check(st['action'] as ActionContext, st['permitted'] as boolean | undefined)).toEqual(st.expect);
      } else if (st.op === 'peek') expect(await e.peek(st['action'] as ActionContext)).toEqual(st.expect);
      else if (st.op === 'state') {
        const r = await e.state();
        expect(r === undefined ? null : { seq: r.state.seq, now: r.state.now, latched: r.latched, state_digest: stateDigest(r.state) }).toEqual(st.expect);
      } else {
        expect({ cleared: await e.reset(st['sig'] as string) }).toEqual(st.expect);
      }
    }
  });
  it('the reset signatures in the vectors are over this contract id and the stated seq (a signature for another contract does not clear)', async () => {
    const kv = createMemoryDurableKv();
    const e = ContractEnforcer.open(kv, head.contract, { principal: head.principal, now: () => head.clock });
    await e.check({ action: { verb: 'delete', resource: '/r' } });
    expect(await e.reset(signContractReset(new Uint8Array(32).fill(7), head.contract.id, 0))).toBe(false);
  });
});
