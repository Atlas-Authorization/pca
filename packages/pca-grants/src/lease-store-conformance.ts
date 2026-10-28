import { b64u, publicKeyOf } from '@atlasauth/pca';
import {
  LeaseRegistry, checkLease, shardOf, signLease, signLeaseRevocation, type LeaseKv, type LeasePolicy, type NewLease,
} from './lease';

/**
 * CONFORMANCE KIT FOR LEASE STORAGE. Run it against any {@link LeaseKv} (the in-memory one, an opened durable state, or your own
 * database adapter) before trusting that store with leases:
 *
 *   await runLeaseStoreConformance({ open: async () => myFreshEmptyKv(), reopen: async (kv) => sameStoreOpenedAgain(kv) });
 *
 * It throws `Error('lease store conformance: <check>: <detail>')` on the first failure and returns the list of checks passed.
 * What it proves: leases spread over the shards; an update is atomic (of many concurrent renewals of one lease exactly one wins and
 * the rest are forks); different leases do not interfere; a prefix revocation lands in every shard and a lease revocation only in
 * its own; a store opened with another shard count is refused rather than silently empty; state survives a reopen (pass `reopen`);
 * a later-issued lease under a revoked prefix is a new lease; with a TTL ceiling, old revocations are pruned from every shard and
 * a longer `max_ttl` is refused.
 */
const SK = new Uint8Array(32).fill(61);
const AUTH = b64u(publicKeyOf(SK));
const T0 = 1_800_000_000_000;
const DAY = 86_400_000;
const mk = (id: string, over: Partial<NewLease> = {}): NewLease => ({
  lease_id: id, path: `svc/${id.length % 3}/${id}`, grant_ref: `g-${id}`, holder: 'agent', requester: 'alice', approvers: ['bob'], justification_digest: 'j1',
  seq: 1, issued_at: T0, renewed_at: T0, expires_at: T0 + 600_000, max_ttl: 3_600_000, ...over,
});
const fail = (check: string, detail: string): never => { throw new Error(`lease store conformance: ${check}: ${detail}`); };
const expectEq = (check: string, got: unknown, want: unknown): void => { if (JSON.stringify(got) !== JSON.stringify(want)) fail(check, `got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`); };

export interface LeaseStoreKit {
  /** A fresh, empty store. */
  open: () => LeaseKv | Promise<LeaseKv>;
  /** The same store opened again as a restarted process would (state kept). Omit to skip the restart check. */
  reopen?: (kv: LeaseKv) => LeaseKv | Promise<LeaseKv>;
  shards?: number;
}

export async function runLeaseStoreConformance(kit: LeaseStoreKit): Promise<string[]> {
  const passed: string[] = [];
  const shards = kit.shards ?? 16;
  const policy: LeasePolicy = { authorities: [AUTH] };
  const ok = (name: string): void => { passed.push(name); };

  // 1. spread
  {
    const kv = await kit.open();
    const reg = new LeaseRegistry(policy, kv, { shards });
    const ids = Array.from({ length: 256 }, (_, i) => `lease-${i}`);
    for (const id of ids) expectEq(`spread: issue ${id}`, (await reg.accept(signLease(SK, mk(id)))).ok, true);
    const per = new Array<number>(shards).fill(0);
    for (const id of ids) per[shardOf(id, shards)]!++;
    if (Math.max(...per) > ids.length / 4 || per.filter((n) => n > 0).length < shards / 2) fail('spread', `256 leases landed ${JSON.stringify(per)}`);
    for (const id of ids) if ((await reg.get(id))?.lease_id !== id) fail('spread', `${id} not found after issue`);
    ok('spread');
  }

  // 2. atomic update
  {
    const reg = new LeaseRegistry(policy, await kit.open(), { shards });
    await reg.accept(signLease(SK, mk('hot')));
    const rivals = Array.from({ length: 8 }, (_, i) => signLease(SK, mk('hot', { seq: 2, renewed_at: T0 + 1000, expires_at: T0 + 700_000 + i, justification_digest: `r${i}` })));
    const results = await Promise.all(rivals.map((r) => reg.accept(r)));
    expectEq('atomic: one winner', results.filter((r) => r.ok).length, 1);
    expectEq('atomic: the rest are forks', results.filter((r) => !r.ok && r.code === 'lease_fork').length, 7);
    expectEq('atomic: ledger length', (await reg.history('hot')).map((h) => h.seq), [1, 2]);
    ok('atomic update');
  }

  // 3. independence
  {
    const reg = new LeaseRegistry(policy, await kit.open(), { shards });
    const ids = Array.from({ length: 32 }, (_, i) => `ind-${i}`);
    await Promise.all(ids.map((id) => reg.accept(signLease(SK, mk(id)))));
    const renewed = await Promise.all(ids.map((id) => reg.accept(signLease(SK, mk(id, { seq: 2, renewed_at: T0 + 10, expires_at: T0 + 900_000, justification_digest: 'j2' })))));
    expectEq('independence', renewed.every((r) => r.ok), true);
    ok('independent leases');
  }

  // 4 + 5. revocation placement
  {
    const kv = await kit.open();
    const reg = new LeaseRegistry(policy, kv, { shards });
    const ids = Array.from({ length: 64 }, (_, i) => `rv-${i}`);
    for (const id of ids) await reg.accept(signLease(SK, mk(id, { path: 'db/prod/ro' })));
    const lone = signLease(SK, mk('lone', { path: 'other/x' }));
    await reg.accept(lone);
    const byLease = signLeaseRevocation(SK, { target: 'lease', value: 'lone', revoked_at: T0 + 5 });
    expectEq('revoke by lease', await reg.revoke(byLease), { ok: true, revoked: 1 });
    let holders = 0;
    for (let i = 0; i < shards; i++) if ((await reg.shardRevocations(i)).length > 0) holders++;
    expectEq('lease revocation lands in exactly one shard', holders, 1);
    expectEq('revoked lease is dead', (await checkLease(lone, reg, T0 + 6)).decision, 'deny');
    const byPrefix = signLeaseRevocation(SK, { target: 'prefix', value: 'db/prod', revoked_at: T0 + 10 });
    expectEq('revoke by prefix covers every lease in every shard', await reg.revoke(byPrefix), { ok: true, revoked: 64 });
    expectEq('revoke twice is idempotent', await reg.revoke(byPrefix), { ok: true, revoked: 64 });
    for (let i = 0; i < shards; i++) {
      const list = await reg.shardRevocations(i);
      if (!list.some((r) => r.sig === byPrefix.sig)) fail('prefix revocation in every shard', `shard ${i} lacks it`);
      expectEq(`no duplicate in shard ${i}`, list.filter((r) => r.sig === byPrefix.sig).length, 1);
    }
    for (const id of ids) {
      const cur = await reg.get(id);
      expectEq(`check ${id}`, (await checkLease(cur, reg, T0 + 11)).decision, 'deny');
      expectEq(`renewal of ${id} refused`, (await reg.accept(signLease(SK, mk(id, { path: 'db/prod/ro', seq: 2, renewed_at: T0 + 20, expires_at: T0 + 700_000, justification_digest: 'x' })))).ok, false);
    }
    const fresh = signLease(SK, mk('after', { path: 'db/prod/ro', issued_at: T0 + 100, renewed_at: T0 + 100, expires_at: T0 + 900_000 }));
    expectEq('a lease issued after the revocation is new', (await reg.accept(fresh)).ok, true);
    ok('revocation placement');
  }

  // 6. shard-count mismatch
  {
    const kv = await kit.open();
    await new LeaseRegistry(policy, kv, { shards }).accept(signLease(SK, mk('m1')));
    const other = new LeaseRegistry(policy, kv, { shards: shards * 2 });
    expectEq('shard mismatch accept', await other.accept(signLease(SK, mk('m2'))), { ok: false, code: 'store_unreachable' });
    expectEq('shard mismatch check', (await checkLease(signLease(SK, mk('m1')), other, T0 + 1)).decision, 'deny');
    ok('shard count is pinned');
  }

  // 7. restart
  if (kit.reopen) {
    const kv = await kit.open();
    const reg = new LeaseRegistry(policy, kv, { shards });
    const l = signLease(SK, mk('persist'));
    await reg.accept(l);
    await reg.accept(signLease(SK, mk('persist', { seq: 2, renewed_at: T0 + 5, expires_at: T0 + 800_000, justification_digest: 'j2' })));
    await reg.revoke(signLeaseRevocation(SK, { target: 'prefix', value: 'gone', revoked_at: T0 + 50 }));
    const again = new LeaseRegistry(policy, await kit.reopen(kv), { shards });
    expectEq('restart: renewal ledger', (await again.history('persist')).map((h) => h.seq), [1, 2]);
    expectEq('restart: revocation kept', (await again.shardRevocations(0)).length, 1);
    expectEq('restart: old record still superseded', (await checkLease(l, again, T0 + 6)).decision, 'deny');
    ok('state survives a restart');
  }

  // 8. ceiling and pruning
  {
    let now = T0;
    const reg = new LeaseRegistry({ authorities: [AUTH], maxTtlCeiling: DAY }, await kit.open(), { shards, clock: () => now });
    expectEq('ceiling refuses a longer max_ttl', await reg.accept(signLease(SK, mk('big', { max_ttl: DAY + 1, expires_at: T0 + 1000 }))), { ok: false, code: 'ttl_ceiling' });
    await reg.accept(signLease(SK, mk('small', { max_ttl: DAY })));
    await reg.revoke(signLeaseRevocation(SK, { target: 'prefix', value: 'svc', revoked_at: T0 }));
    for (let i = 0; i < shards; i++) expectEq(`kept before the ceiling passes (shard ${i})`, (await reg.shardRevocations(i)).length, 1);
    now = T0 + DAY + 1;
    await reg.accept(signLease(SK, mk('trigger', { issued_at: now, renewed_at: now, expires_at: now + 1000, max_ttl: 5000 })));
    await reg.revoke(signLeaseRevocation(SK, { target: 'prefix', value: 'zzz', revoked_at: now }));
    for (let i = 0; i < shards; i++) {
      const left = (await reg.shardRevocations(i)).map((r) => r.value);
      if (left.includes('svc')) fail('pruning', `shard ${i} still holds the expired revocation`);
      if (!left.includes('zzz')) fail('pruning', `shard ${i} lost the fresh revocation`);
    }
    ok('pruning bounds revocations');
  }
  return passed;
}
