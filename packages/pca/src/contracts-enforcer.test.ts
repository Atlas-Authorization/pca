import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { runContractFlow } from './test-support/flow-contract-enforcer';
import { ContractEnforcer, ContractEnforcerError, signContractReset } from './contract-enforcer';
import { CONTRACT_VERSION, signContract, type Clause } from './contracts';
import { createMemoryDurableKv, openDurableState, type DurableKv } from './durable-state';
import { encodeKey, generateKeyPair } from './keys';
import type { ActionContext } from './predicates';

const P = generateKeyPair();
const PRIN = encodeKey(P.publicKey);
const act = (verb: string): ActionContext => ({ action: { verb, resource: '/r' } });
const clauses: Clause[] = [
  { id: 'no-delete', kind: 'never', p: { verb: 'delete' } },
  { id: 'review-first', kind: 'precedes', p: { verb: 'review' }, q: { verb: 'deploy' } },
];
const sc = signContract({ version: CONTRACT_VERSION, principal: PRIN, clauses }, P.secretKey);
const open = (kv: DurableKv, extra = {}) => ContractEnforcer.open(kv, sc, { principal: PRIN, now: () => 1_700_000_000_000, ...extra });

describe('open: only the pinned principal contract loads', () => {
  it('wrong pinned principal', () => expect(() => ContractEnforcer.open(createMemoryDurableKv(), sc, { principal: encodeKey(generateKeyPair().publicKey) })).toThrow('contract refused: principal mismatch'));
  it('tampered contract', () => expect(() => ContractEnforcer.open(createMemoryDurableKv(), { ...sc, clauses: [] }, { principal: PRIN })).toThrow('contract refused: id does not match content'));
  it('no principal pinned', () => expect(() => ContractEnforcer.open(createMemoryDurableKv(), sc, {} as never)).toThrow('a pinned principal is required'));
});

describe('check: exact outcomes', () => {
  it('admits in order and advances seq', async () => {
    const e = open(createMemoryDurableKv());
    expect(await e.check(act('review'))).toEqual({ allow: true, reason: 'ok', violated: [], reasons: [], seq: 1 });
    expect(await e.check(act('deploy'))).toMatchObject({ allow: true, seq: 2 });
  });
  it('permission denied: refused with reason permission, no latch, state unchanged', async () => {
    const e = open(createMemoryDurableKv());
    expect(await e.check(act('review'), false)).toMatchObject({ allow: false, reason: 'permission', violated: [], seq: 0 });
    expect(await e.check(act('review'))).toMatchObject({ allow: true, seq: 1 });
  });
  it('a violation is refused, names the clause, and latches: even a harmless action is then refused', async () => {
    const e = open(createMemoryDurableKv());
    expect(await e.check(act('deploy'))).toMatchObject({ allow: false, reason: 'violated', violated: ['review-first'] });
    expect(await e.check(act('review'))).toMatchObject({ allow: false, reason: 'latched', violated: ['review-first'] });
    expect((await e.state())?.latched).toBe(true);
  });
  it('with latchOnViolation false a violation is only denied', async () => {
    const e = open(createMemoryDurableKv(), { latchOnViolation: false });
    expect((await e.check(act('delete'))).reason).toBe('violated');
    expect((await e.check(act('review'))).allow).toBe(true);
  });
  it('reset needs the principal signature at the latched seq', async () => {
    const kv = createMemoryDurableKv();
    const e = open(kv);
    await e.check(act('review'));
    await e.check(act('delete'));
    expect(await e.reset(signContractReset(generateKeyPair().secretKey, sc.id, 1))).toBe(false);
    expect(await e.reset(signContractReset(P.secretKey, sc.id, 0))).toBe(false);
    expect((await e.check(act('review'))).reason).toBe('latched');
    expect(await e.reset(signContractReset(P.secretKey, sc.id, 1))).toBe(true);
    expect(await e.reset(signContractReset(P.secretKey, sc.id, 1))).toBe(false);
    expect((await e.check(act('deploy'))).allow).toBe(true);
  });
});

describe('fail closed', () => {
  it('a corrupt stored document denies with state-error', async () => {
    const kv = createMemoryDurableKv();
    const e = open(kv);
    await e.check(act('review'));
    await kv.set(`contract/${sc.id}`, { v: 1, contract_id: sc.id, state: { now: 'x' } });
    expect(await e.check(act('review'))).toMatchObject({ allow: false, reason: 'state-error', seq: 0 });
    await expect(e.state()).rejects.toThrow(ContractEnforcerError);
  });
  it('state of another contract is refused', async () => {
    const kv = createMemoryDurableKv();
    const e = open(kv);
    await e.check(act('review'));
    const doc = (await kv.get(`contract/${sc.id}`)) as Record<string, unknown>;
    await kv.set(`contract/${sc.id}`, { ...doc, contract_id: 'other' });
    expect((await e.check(act('review'))).reason).toBe('state-error');
  });
  it('a store error denies with store-error', async () => {
    const kv: DurableKv = { ...createMemoryDurableKv(), update: async () => { throw new Error('down'); } };
    expect(await open(kv).check(act('review'))).toMatchObject({ allow: false, reason: 'store-error' });
  });
});

describe('concurrency and restart', () => {
  it('two enforcers on one kv racing the same actions: each seq is admitted exactly once', async () => {
    const kv = createMemoryDurableKv();
    const a = open(kv);
    const b = open(kv);
    const rs = await Promise.all([a.check(act('review')), b.check(act('review')), a.check(act('review')), b.check(act('review'))]);
    expect(rs.every((r) => r.allow)).toBe(true);
    expect(rs.map((r) => r.seq).sort()).toEqual([1, 2, 3, 4]);
  });
  it('state and the latch survive a restart on file-backed state', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pca-contract-'));
    const e1 = open(await openDurableState({ dir, lockTimeoutMs: 30_000 }));
    await e1.check(act('review'));
    await e1.check(act('delete'));
    const e2 = open(await openDurableState({ dir, lockTimeoutMs: 30_000 }));
    expect((await e2.state())?.state.seq).toBe(1);
    expect(await e2.check(act('review'))).toMatchObject({ allow: false, reason: 'latched' });
  }, 60_000);
});

describe('the shipped example flow', () => {
  it('a permitted but contract-violating call is refused; a permitted compliant one passes', async () => {
    const out = await runContractFlow(['review', 'deploy', 'delete', 'review']);
    expect(out.map((o) => [o.verb, o.allow, o.reason])).toEqual([['review', true, 'ok'], ['deploy', true, 'ok'], ['delete', false, 'violated'], ['review', false, 'latched']]);
  });
});

describe('peek', () => {
  it('evaluates without advancing or latching', async () => {
    const e = open(createMemoryDurableKv());
    expect(await e.peek(act('delete'))).toMatchObject({ allow: false, reason: 'violated', violated: ['no-delete'] });
    expect(await e.state()).toBeUndefined();
    expect(await e.peek(act('review'))).toMatchObject({ allow: true, reason: 'ok', seq: 0 });
    expect(await e.state()).toBeUndefined();
  });
  it('reports a latched contract', async () => {
    const e = open(createMemoryDurableKv());
    await e.check(act('delete'));
    expect(await e.peek(act('review'))).toMatchObject({ allow: false, reason: 'latched' });
  });
});
