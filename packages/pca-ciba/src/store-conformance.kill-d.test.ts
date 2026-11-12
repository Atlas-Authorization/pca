import { AssertionError } from 'node:assert';
import { describe, expect, it } from 'vitest';
import { approvalBrokerCases, approvalStoreCases, type ApprovalStoreCase } from './store-conformance';
import { createMemoryApprovalStore } from './testing';
import type { ApprovalStore } from './approval';

type Op = { op: 'get'; key: string } | { op: 'cas'; key: string; expected: number; value: unknown };

/** A memory store that records every call made to it. */
function recording(): { store: ApprovalStore; ops: Op[] } {
  const inner = createMemoryApprovalStore();
  const ops: Op[] = [];
  const store: ApprovalStore = {
    get: (key) => {
      ops.push({ op: 'get', key });
      return inner.get(key);
    },
    cas: (key, expected, value) => {
      ops.push({ op: 'cas', key, expected, value: structuredClone(value) });
      return inner.cas(key, expected, value);
    },
  };
  return { store, ops };
}
const byName = (cases: ApprovalStoreCase[], name: string): ApprovalStoreCase => {
  const c = cases.find((x) => x.name === name);
  if (!c) throw new Error(`no case named ${name}`);
  return c;
};
const settle = async (p: Promise<void>): Promise<unknown> => p.then(() => 'passed', (e: unknown) => e);

const STORE_NAMES = [
  'an absent key reads undefined',
  'cas at version 0 creates the key at version 1 with the whole value',
  'cas at version 0 on an existing key is refused and changes nothing',
  'cas succeeds only at the current version and bumps it by exactly one',
  'cas on a key that does not exist at a non-zero version is refused and creates nothing',
  'keys are independent',
  'a read is a snapshot: changing the returned value does not change the store',
  'a written value is a snapshot: changing it after cas does not change the store',
  'exactly one of many concurrent creates wins',
  'exactly one of many concurrent updates at the same version wins',
  'a retry loop over concurrent writers loses no increment',
];
const BROKER_NAMES = [
  'concurrent resolves through separate brokers: exactly one wins and its decision stands',
  'an approval redeems once even when many brokers redeem at the same time',
  'a second broker over the same store sees the decision of the first',
];

describe('case names are the published contract', () => {
  it('store cases, with and without the durability case', () => {
    const s = createMemoryApprovalStore();
    expect(approvalStoreCases(() => s).map((c) => c.name)).toEqual(STORE_NAMES);
    expect(approvalStoreCases(() => s, (p) => p).map((c) => c.name)).toEqual([...STORE_NAMES, 'records and their versions survive reopening the store']);
  });
  it('broker cases', () => {
    expect(approvalBrokerCases(() => createMemoryApprovalStore()).map((c) => c.name)).toEqual(BROKER_NAMES);
  });
});

describe('each store case drives the store with its documented inputs', () => {
  const drive = async (name: string): Promise<Op[]> => {
    const { store, ops } = recording();
    await byName(approvalStoreCases(() => store), name).run();
    return ops;
  };
  it('absent key', async () => {
    expect(await drive(STORE_NAMES[0]!)).toEqual([{ op: 'get', key: 'nope' }]);
  });
  it('create stores the whole nested value', async () => {
    const ops = await drive(STORE_NAMES[1]!);
    expect(ops[0]).toEqual({ op: 'cas', key: 'k', expected: 0, value: { a: 1, nested: { b: ['x', 2, null] } } });
    expect(ops[1]).toEqual({ op: 'get', key: 'k' });
  });
  it('refused re-create', async () => {
    const ops = await drive(STORE_NAMES[2]!);
    expect(ops.filter((o) => o.op === 'cas').map((o) => (o as { value: unknown }).value)).toEqual(['first', 'second']);
  });
  it('non-zero version on a missing key', async () => {
    expect(await drive(STORE_NAMES[4]!)).toEqual([
      { op: 'cas', key: 'k', expected: 1, value: 'x' },
      { op: 'get', key: 'k' },
    ]);
  });
  it('independent keys', async () => {
    const ops = await drive(STORE_NAMES[5]!);
    expect(ops.filter((o) => o.op === 'cas').map((o) => (o as { key: string; value: unknown }).key + '=' + String((o as { value: unknown }).value))).toEqual(['a=A', 'b=B', 'a=A2']);
  });
  it('concurrent updates start from base', async () => {
    const ops = await drive(STORE_NAMES[9]!);
    expect(ops[0]).toEqual({ op: 'cas', key: 'k', expected: 0, value: 'base' });
    expect(ops.filter((o) => o.op === 'cas')).toHaveLength(33);
  });
  it('reopen case', async () => {
    const { store, ops } = recording();
    const cases = approvalStoreCases(() => store, (p) => p);
    await cases[cases.length - 1]!.run();
    const cas = ops.filter((o) => o.op === 'cas') as Array<{ expected: number; value: unknown }>;
    expect(cas.map((o) => o.value)).toEqual([{ v: 1 }, { v: 2 }, { v: 'stale' }, { v: 3 }]);
  });
});

describe('store cases detect broken stores', () => {
  const failing = (make: () => ApprovalStore, name: string) => settle(byName(approvalStoreCases(make), name).run());
  it('concurrent create case reports a store that forgets the winner as an assertion, not a crash', async () => {
    const make = (): ApprovalStore => {
      const inner = createMemoryApprovalStore();
      return { get: () => undefined, cas: (k, e, v) => inner.cas(k, e, v) };
    };
    expect(await failing(make, STORE_NAMES[8]!)).toBeInstanceOf(AssertionError);
    expect(await failing(make, STORE_NAMES[9]!)).toBeInstanceOf(AssertionError);
  });
});

describe('broker cases', () => {
  const run = (make: () => ApprovalStore, i: number) => settle(approvalBrokerCases(make)[i]!.run());

  it('pass over a correct store', async () => {
    for (let i = 0; i < 3; i++) expect(await run(() => createMemoryApprovalStore(), i), BROKER_NAMES[i]).toBe('passed');
  });

  it('concurrent resolves send approve for even deciders and deny for odd ones', async () => {
    const { store, ops } = recording();
    await run(() => store, 0);
    const decisions = new Map<string, unknown>();
    for (const o of ops) {
      const v = o.op === 'cas' ? (o.value as { decidedBy?: string; decision?: string }) : undefined;
      if (v?.decidedBy !== undefined) decisions.set(v.decidedBy, v.decision);
    }
    expect([...decisions.entries()].sort()).toEqual(
      Array.from({ length: 8 }, (_, i) => [`user-${i}`, i % 2 === 0 ? 'approve' : 'deny'] as [string, string]).sort(),
    );
  });

  it('the fixture step-up carries the documented goal', async () => {
    const { store, ops } = recording();
    await run(() => store, 0);
    const created = ops.find((o) => o.op === 'cas' && o.key.startsWith('a:'));
    const rec = (created as { value: { request: { binding_message: string; stepUpId: string } } }).value;
    expect(rec.request.binding_message).toBe(`Approve stripe.payout 80 USD to "bob" on acct:1 — because you asked your agent to 'pay suppliers'`);
  });

  it('a store that reports several winners fails the exactly-one check', async () => {
    // cas always claims success but only the first write is kept: every decision "wins", the stored one is the first
    const make = (): ApprovalStore => {
      const inner = createMemoryApprovalStore();
      return { get: (k) => inner.get(k), cas: (k, e, v) => (inner.cas(k, e, v), true) };
    };
    expect(await run(make, 0)).toBeInstanceOf(AssertionError);
  });

  it('the winner decides the final status, whether it is an odd or a later even decider', async () => {
    const blocking = (blocked: string[]) => (): ApprovalStore => {
      const inner = createMemoryApprovalStore();
      return {
        get: (k) => inner.get(k),
        cas: (k, e, v) => (blocked.includes((v as { decidedBy?: string }).decidedBy ?? '') ? false : inner.cas(k, e, v)),
      };
    };
    expect(await run(blocking(['user-0']), 0)).toBe('passed'); // user-1 wins and denies
    expect(await run(blocking(['user-0', 'user-1']), 0)).toBe('passed'); // user-2 wins and approves
  });

  it('a forgetful store is reported as an assertion failure', async () => {
    const make = (): ApprovalStore => {
      const inner = createMemoryApprovalStore();
      let writes = 0;
      return {
        get: (k) => (writes >= 3 ? undefined : inner.get(k)),
        cas: (k, e, v) => {
          const ok = inner.cas(k, e, v);
          if (ok) writes += 1;
          return ok;
        },
      };
    };
    expect(await run(make, 0)).toBeInstanceOf(AssertionError);
  });

  it('the late resolve is really attempted against the store', async () => {
    const { store, ops } = recording();
    expect(await run(() => store, 2)).toBe('passed');
    expect(ops.filter((o) => o.op === 'get')).toHaveLength(5);
  });

  it('a store that lets two brokers redeem is reported', async () => {
    const make = (): ApprovalStore => {
      const inner = createMemoryApprovalStore();
      return { get: (k) => inner.get(k), cas: (k, e, v) => (inner.cas(k, e, v), true) };
    };
    expect(await run(make, 1)).toBeInstanceOf(AssertionError);
  });
});
