/**
 * Conformance cases for an {@link ApprovalStore}, plus broker-level cases run over it. Run them against your store:
 *
 * ```ts
 * for (const c of approvalStoreCases(() => new MyStore(), reopen)) it(c.name, c.run);
 * ```
 *
 * Each case throws (an `AssertionError`) when the store breaks the contract: absent means version 0, `cas` writes only at
 * the expected version and bumps it by one, exactly one of many concurrent `cas` calls wins, returned values are
 * snapshots, and (with `reopen`) written records survive a restart. The broker cases check what the contract is for:
 * exactly one concurrent decision wins and an approval redeems once.
 */
import { deepStrictEqual, strictEqual } from 'node:assert';
import { agent, generateKeyPair, reviewAction } from '@atlasauth/pca';
import { createDurableCibaBroker, type ApprovalStore } from './approval';

export interface ApprovalStoreCase {
  name: string;
  run: () => Promise<void>;
}

/**
 * @param make a store over a fresh, empty backing location each call.
 * @param reopen for a persistent store: a NEW store object over the same backing location as `previous`, as after a
 *   restart. Omit to skip the durability case.
 */
export function approvalStoreCases(make: () => ApprovalStore, reopen?: (previous: ApprovalStore) => ApprovalStore): ApprovalStoreCase[] {
  const cases: ApprovalStoreCase[] = [
    {
      name: 'an absent key reads undefined',
      run: async () => {
        strictEqual(await make().get('nope'), undefined);
      },
    },
    {
      name: 'cas at version 0 creates the key at version 1 with the whole value',
      run: async () => {
        const s = make();
        const v = { a: 1, nested: { b: ['x', 2, null] } };
        strictEqual(await s.cas('k', 0, v), true);
        deepStrictEqual(await s.get('k'), { version: 1, value: v });
      },
    },
    {
      name: 'cas at version 0 on an existing key is refused and changes nothing',
      run: async () => {
        const s = make();
        await s.cas('k', 0, 'first');
        strictEqual(await s.cas('k', 0, 'second'), false);
        deepStrictEqual(await s.get('k'), { version: 1, value: 'first' });
      },
    },
    {
      name: 'cas succeeds only at the current version and bumps it by exactly one',
      run: async () => {
        const s = make();
        await s.cas('k', 0, 1);
        strictEqual(await s.cas('k', 1, 2), true);
        strictEqual(await s.cas('k', 1, 3), false); // stale
        strictEqual(await s.cas('k', 5, 4), false); // from the future
        strictEqual(await s.cas('k', 2, 5), true);
        deepStrictEqual(await s.get('k'), { version: 3, value: 5 });
      },
    },
    {
      name: 'cas on a key that does not exist at a non-zero version is refused and creates nothing',
      run: async () => {
        const s = make();
        strictEqual(await s.cas('k', 1, 'x'), false);
        strictEqual(await s.get('k'), undefined);
      },
    },
    {
      name: 'keys are independent',
      run: async () => {
        const s = make();
        await s.cas('a', 0, 'A');
        await s.cas('b', 0, 'B');
        await s.cas('a', 1, 'A2');
        deepStrictEqual(await s.get('a'), { version: 2, value: 'A2' });
        deepStrictEqual(await s.get('b'), { version: 1, value: 'B' });
      },
    },
    {
      name: 'a read is a snapshot: changing the returned value does not change the store',
      run: async () => {
        const s = make();
        await s.cas('k', 0, { list: [1] });
        const got = await s.get('k');
        (got?.value as { list: number[] }).list.push(2);
        deepStrictEqual(await s.get('k'), { version: 1, value: { list: [1] } });
      },
    },
    {
      name: 'a written value is a snapshot: changing it after cas does not change the store',
      run: async () => {
        const s = make();
        const v = { list: [1] };
        await s.cas('k', 0, v);
        v.list.push(2);
        deepStrictEqual(await s.get('k'), { version: 1, value: { list: [1] } });
      },
    },
    {
      name: 'exactly one of many concurrent creates wins',
      run: async () => {
        const s = make();
        const results = await Promise.all(Array.from({ length: 32 }, async (_, i) => (await Promise.resolve(), s.cas('k', 0, i))));
        strictEqual(results.filter((r) => r === true).length, 1);
        const stored = await s.get('k');
        strictEqual(stored?.version, 1);
        strictEqual(stored?.value, results.indexOf(true));
      },
    },
    {
      name: 'exactly one of many concurrent updates at the same version wins',
      run: async () => {
        const s = make();
        await s.cas('k', 0, 'base');
        const results = await Promise.all(Array.from({ length: 32 }, async (_, i) => (await Promise.resolve(), s.cas('k', 1, i))));
        strictEqual(results.filter((r) => r === true).length, 1);
        deepStrictEqual(await s.get('k'), { version: 2, value: results.indexOf(true) });
      },
    },
    {
      name: 'a retry loop over concurrent writers loses no increment',
      run: async () => {
        const s = make();
        await s.cas('n', 0, 0);
        const bump = async (): Promise<void> => {
          for (;;) {
            const cur = await s.get('n');
            if (cur && (await s.cas('n', cur.version, (cur.value as number) + 1))) return;
          }
        };
        await Promise.all(Array.from({ length: 24 }, bump));
        deepStrictEqual(await s.get('n'), { version: 25, value: 24 });
      },
    },
  ];
  if (reopen) {
    cases.push({
      name: 'records and their versions survive reopening the store',
      run: async () => {
        const s = make();
        await s.cas('k', 0, { v: 1 });
        await s.cas('k', 1, { v: 2 });
        const again = reopen(s);
        deepStrictEqual(await again.get('k'), { version: 2, value: { v: 2 } });
        strictEqual(await again.cas('k', 1, { v: 'stale' }), false);
        strictEqual(await again.cas('k', 2, { v: 3 }), true);
      },
    });
  }
  return cases;
}

/** Broker-level cases over a store: what the compare-and-set contract is for. */
export function approvalBrokerCases(make: () => ApprovalStore): ApprovalStoreCase[] {
  const stepUp = () => {
    const a = agent({ principal: generateKeyPair(), goal: 'pay suppliers', permissions: { stripe: ['payout'] }, limits: { payout: '$100' }, aud: 'ins_conformance', riskPolicy: { theta1: 0.3, theta2: 0.6 }, now: 0 });
    const r = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 80, currency: 'USD', payee: 'bob' }, { insecureUnboundApproval: true, now: 1, goal: 'pay suppliers' });
    if (r.kind !== 'step_up') throw new Error('conformance fixture did not produce a step-up');
    return r.request;
  };
  const brokers = (n: number) => {
    const store = make();
    return Array.from({ length: n }, () => createDurableCibaBroker({ store }));
  };
  return [
    {
      name: 'concurrent resolves through separate brokers: exactly one wins and its decision stands',
      run: async () => {
        const bs = brokers(8);
        const req = await bs[0]!.start(stepUp());
        const settled = await Promise.allSettled(bs.map((b, i) => b.resolve(req.auth_req_id, i % 2 === 0 ? 'approve' : 'deny', `user-${i}`)));
        const won = settled.flatMap((r, i) => (r.status === 'fulfilled' ? [i] : []));
        strictEqual(won.length, 1);
        const final = await bs[0]!.get(req.auth_req_id);
        strictEqual(final?.decidedBy, `user-${won[0]}`);
        strictEqual(final?.status, won[0]! % 2 === 0 ? 'approved' : 'denied');
      },
    },
    {
      name: 'an approval redeems once even when many brokers redeem at the same time',
      run: async () => {
        const bs = brokers(8);
        const req = await bs[0]!.start(stepUp());
        await bs[0]!.resolve(req.auth_req_id, 'approve', 'owner');
        const outs = await Promise.all(bs.map((b) => b.token(req.auth_req_id)));
        strictEqual(outs.filter((o) => o.ok).length, 1);
      },
    },
    {
      name: 'a second broker over the same store sees the decision of the first',
      run: async () => {
        const [a, b] = brokers(2);
        const req = await a!.start(stepUp());
        strictEqual((await b!.poll(req.auth_req_id)).status, 'pending');
        await a!.resolve(req.auth_req_id, 'approve', 'owner');
        strictEqual((await b!.poll(req.auth_req_id)).status, 'approved');
        await rejects(() => b!.resolve(req.auth_req_id, 'deny', 'late'));
      },
    },
  ];
}

async function rejects(fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
  } catch {
    return;
  }
  throw new Error('expected a rejection');
}
