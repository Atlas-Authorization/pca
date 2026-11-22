// Oracle: packages/pca/src/ha.ts (guardian-set high availability: liveness, quorum, degrade mode, signer selection, failover; the fenced leader lease and fence guard).
// Writes out/ref-ha.json.gz. No keys, no clock (every `now` is an argument; the lease store clock is an op).
// PORTING (results compared by JSON value; a reference throw = the native throws; "-0"/non-finite numbers: {"$num":..} as everywhere)
//   liveGuardians [set, now, opts|null]    -> [GuardianHealth] (opts {staleMs}); null opts = {}      quorumStatus [set, now, opts|null] -> {total, live, quorum, available, degraded}
//   degradeMode [status, policy|null]      -> 'normal'|'read-only'|'halt'                          selectSigners [set, now, opts|null] -> [id]       failoverPlan [set, now, opts|null] -> {primary|null, standbys}
//   validateGuardianSet [set]              -> string | null
//   fenceGuard [initial, epochs[]]         -> {admits: [bool], highest}      createFenceGuard(initial) then admit(e) for each e; highest() at the end
//   lease [ops]                            -> one result per op against ONE fresh in-memory store (KvLeaseStore over an in-memory DurableKv, store clock = the `clock` op, default 0)
//       ["clock", ms]                      sets the store clock (a non-finite value is allowed)
//       ["fault", kind]                    kind: none | read (read throws "boom") | now (now() throws "boom") | cas (cas throws "boom") | loseCas (the NEXT cas returns false, then back to normal)
//       ["raw", value]                     writes `value` straight into the store key (corrupt / hand-made records); returns null
//       ["read"]                           the stored record or null
//       ["acquire", ref, holder, opts]     -> LeaseResult; on ok the lease is remembered under `ref`
//       ["renew", leaseOrRef, opts]        -> LeaseResult (string = a remembered ref; object = a literal record, possibly malformed)
//       ["release", leaseOrRef]            -> LeaseResult (ok: the remembered ref is updated to the released record)
//       ["fence", tokenOrRef, skew|null]   -> {ok:true} | {ok:false, reason}
//       ["signer", leaseOrRef|null, skew|null, advanceMs, throwInSign]  -> fencedSigner(...)(): {ok:true, result:"signed", epoch} | {ok:false, reason:<FenceError.reason>} | {ok:false, error:"sign"}; advanceMs moves the store clock DURING the sign step
//   kvCas [prev|null, expected|null, next]    -> {ok, stored}: a raw KvLeaseStore.cas over a store holding `prev`   (a throw is {"$throws"})
//   constants []                           -> {MAX_LEASE_TTL_MS, DEFAULT_LEASE_SKEW_MS}   NOTE: MAX_LEASE_TTL_MS here is 3600000 (this module's); agent-native.ts exports a different constant of the same name
import { Oracle, refWrite } from './lib.mjs';
import { adder, nul } from './foundation.mjs';
const H: any = await import('../../../packages/pca/src/ha.ts');
const { createMemoryDurableKv }: any = await import('../../../packages/pca/src/durable-state.ts');
const o = new Oracle('ha', 'tools/pca-audit/oracles/ha.mts', 'TS-reference oracle for packages/pca/src/ha.ts.');
const KEY = 'ha/lease';
async function lease(ops: any[]) {
  let kv = createMemoryDurableKv(); let clock = 0; let fault = 'none'; let loseOnce = false;
  const kvs = new H.KvLeaseStore(kv, { now: () => clock });
  const store: any = {
    read: async () => { if (fault === 'read') throw new Error('boom'); return kvs.read(); },
    now: async () => { if (fault === 'now') throw new Error('boom'); return kvs.now(); },
    cas: async (e: any, n: any) => { if (fault === 'cas') throw new Error('boom'); if (loseOnce) { loseOnce = false; return false; } return kvs.cas(e, n); },
  };
  const refs = new Map<string, any>();
  const res = (x: any) => (typeof x === 'string' ? refs.get(x) : x);
  const out: any[] = [];
  for (const op of ops) {
    try {
      switch (op[0]) {
        case 'clock': clock = op[1]; out.push(null); break;
        case 'fault': if (op[1] === 'loseCas') loseOnce = true; else fault = op[1]; out.push(null); break;
        case 'raw': await kv.set(KEY, op[1]); out.push(null); break;
        case 'read': { const v = await kv.get(KEY); out.push(v === undefined ? null : v); break; }
        case 'acquire': { const r = await H.acquireLease(store, op[2], op[3]); if (r.ok) refs.set(op[1], r.lease); out.push(r); break; }
        case 'renew': { const r = await H.renewLease(store, res(op[1]), op[2]); if (r.ok && typeof op[1] === 'string') refs.set(op[1], r.lease); out.push(r); break; }
        case 'release': { const r = await H.releaseLease(store, res(op[1])); if (r.ok && typeof op[1] === 'string') refs.set(op[1], r.lease); out.push(r); break; }
        case 'fence': out.push(await H.assertFence(store, res(op[1]), op[2] === null ? undefined : op[2])); break;
        case 'signer': {
          const l = op[1] === null ? undefined : res(op[1]);
          const f = H.fencedSigner(store, () => l, () => { clock += op[3]; if (op[4]) throw new Error('sign'); return 'signed'; }, op[2] === null ? undefined : op[2]);
          try { const r = await f(); out.push({ ok: true, result: r.result, epoch: r.epoch }); } catch (e: any) { out.push(e instanceof H.FenceError ? { ok: false, reason: e.reason } : { ok: false, error: e.message }); }
          break;
        }
        default: throw new Error('bad op');
      }
    } catch (e: any) { out.push({ $err: e.message }); }
  }
  return out;
}
const REF: Record<string, (...a: any[]) => any> = {
  liveGuardians: (s, n, op) => H.liveGuardians(s, n, nul(op) ?? {}), quorumStatus: (s, n, op) => H.quorumStatus(s, n, nul(op) ?? {}), degradeMode: (st, p) => H.degradeMode(st, nul(p) ?? {}),
  selectSigners: (s, n, op) => H.selectSigners(s, n, nul(op) ?? {}), failoverPlan: (s, n, op) => H.failoverPlan(s, n, nul(op) ?? {}), validateGuardianSet: (s) => H.validateGuardianSet(s),
  fenceGuard: (init, es) => { const g = H.createFenceGuard(init); const admits = es.map((e: any) => g.admit(e)); return { admits, highest: g.highest() }; },
  lease, constants: () => ({ MAX_LEASE_TTL_MS: H.MAX_LEASE_TTL_MS, DEFAULT_LEASE_SKEW_MS: H.DEFAULT_LEASE_SKEW_MS }),
  kvCas: async (prev, exp, next) => { const kv = createMemoryDurableKv(); if (prev !== null) await kv.set(KEY, prev); const s = new H.KvLeaseStore(kv, { now: () => 0 }); const ok = await s.cas(exp === null ? undefined : exp, next); const st = await kv.get(KEY); return { ok, stored: st === undefined ? null : st }; },
};
const add = adder(o, REF);
const g = (id: any, healthy: any, lastSeen: any, weight?: any) => ({ id, healthy, lastSeen, ...(weight !== undefined ? { weight } : {}) });
const NOW = 1_000_000;
const SETS: [string, any][] = [
  ['basic', { quorum: 2, guardians: [g('a', true, NOW), g('b', true, NOW - 1000), g('c', false, NOW)] }],
  ['all-live', { quorum: 2, guardians: [g('a', true, NOW), g('b', true, NOW), g('c', true, NOW)] }],
  ['weights', { quorum: 2, guardians: [g('a', true, NOW, 1), g('b', true, NOW, 5), g('c', true, NOW, 3), g('d', true, NOW, 5)] }],
  ['tie-lastseen', { quorum: 2, guardians: [g('a', true, NOW - 5), g('b', true, NOW - 1), g('c', true, NOW - 1)] }],
  ['tie-id', { quorum: 2, guardians: [g('b', true, NOW), g('a', true, NOW), g('C', true, NOW), g('ä', true, NOW), g('Z', true, NOW)] }],
  ['weight-nan-inf', { quorum: 2, guardians: [g('a', true, NOW, { $num: 'NaN' }), g('b', true, NOW, { $num: 'Infinity' }), g('c', true, NOW, 'x'), g('d', true, NOW, -2)] }],
  ['stale-edge', { quorum: 1, guardians: [g('a', true, NOW - 30000), g('b', true, NOW - 30001), g('c', true, NOW + 1)] }],
  ['healthy-truthy', { quorum: 1, guardians: [g('a', 1, NOW), g('b', 'true', NOW), g('c', true, NOW)] }],
  ['lastseen-bad', { quorum: 1, guardians: [g('a', true, { $num: 'NaN' }), g('b', true, '5'), g('c', true, null), g('d', true, { $num: '-Infinity' }), g('e', true, -5)] }],
  ['below-quorum', { quorum: 3, guardians: [g('a', true, NOW), g('b', true, NOW), g('c', false, NOW)] }],
  ['none-live', { quorum: 1, guardians: [g('a', false, NOW), g('b', false, NOW)] }],
  ['empty', { quorum: 1, guardians: [] }], ['quorum-zero', { quorum: 0, guardians: [g('a', true, NOW)] }], ['quorum-frac', { quorum: 1.5, guardians: [g('a', true, NOW), g('b', true, NOW)] }], ['quorum-neg', { quorum: -1, guardians: [g('a', true, NOW)] }],
  ['quorum-str', { quorum: '1', guardians: [g('a', true, NOW)] }], ['quorum-missing', { guardians: [g('a', true, NOW)] }], ['quorum-nan', { quorum: { $num: 'NaN' }, guardians: [g('a', true, NOW)] }], ['quorum-big', { quorum: 5, guardians: [g('a', true, NOW)] }],
  ['guardians-missing', { quorum: 1 }], ['guardians-not-array', { quorum: 1, guardians: 'x' }], ['guardians-null-el', { quorum: 1, guardians: [null, g('a', true, NOW)] }], ['guardians-num-el', { quorum: 1, guardians: [5] }], ['guardians-array-el', { quorum: 1, guardians: [[]] }],
  ['dup-ids', { quorum: 1, guardians: [g('a', true, NOW), g('a', true, NOW)] }], ['id-empty', { quorum: 1, guardians: [g('', true, NOW)] }], ['id-num', { quorum: 1, guardians: [g(5, true, NOW)] }], ['id-missing', { quorum: 1, guardians: [{ healthy: true, lastSeen: NOW }] }],
  ['null', null], ['string', 'x'], ['array', []], ['number', 5], ['obj-empty', {}],
];
const OPTS: any[] = [null, {}, { staleMs: 0 }, { staleMs: 500 }, { staleMs: 30000 }, { staleMs: 1e9 }, { staleMs: -1 }, { staleMs: { $num: 'NaN' } }, { staleMs: { $num: 'Infinity' } }, { staleMs: '5' }, { staleMs: null }];
const NOWS: any[] = [NOW, NOW - 100000, NOW + 100000, 0, -1, { $num: 'NaN' }, { $num: 'Infinity' }, '5'];
for (const [sn, s] of SETS) {
  await add('validateGuardianSet', sn, [s]);
  for (const [ni, n] of NOWS.entries()) { if (ni > 2 && sn !== 'basic') continue; await add('liveGuardians', `${sn}/n${ni}`, [s, n, null]); await add('quorumStatus', `${sn}/n${ni}`, [s, n, null]); await add('selectSigners', `${sn}/n${ni}`, [s, n, null]); await add('failoverPlan', `${sn}/n${ni}`, [s, n, null]); }
  if (['basic', 'weights', 'stale-edge', 'lastseen-bad'].includes(sn)) for (const [oi, op] of OPTS.entries()) { await add('quorumStatus', `${sn}/o${oi}`, [s, NOW, op]); await add('selectSigners', `${sn}/o${oi}`, [s, NOW, op]); await add('failoverPlan', `${sn}/o${oi}`, [s, NOW, op]); await add('liveGuardians', `${sn}/o${oi}`, [s, NOW, op]); }
}
const STS: any[] = [{ available: true, live: 3, total: 3, quorum: 2, degraded: false }, { available: false, live: 1, total: 3, quorum: 2, degraded: true }, { available: false, live: 0, total: 3, quorum: 2, degraded: false }, { available: true, live: 0 }, { available: false, live: 1 }, { available: 1, live: 1 }, { live: 2 }, { available: false, live: { $num: 'NaN' } }, { available: false, live: -1 }, { available: false, live: 0.5 }];
for (const [i, st] of STS.entries()) for (const [pi, p] of [null, {}, { allowReadOnly: true }, { allowReadOnly: false }, { allowReadOnly: 0 }, { allowReadOnly: null }, { allowReadOnly: 'false' }].entries()) await add('degradeMode', `s${i}/p${pi}`, [st, p]);
for (const [i, [init, es]] of ([[0, [1, 2, 2, 1, 3]], [5, [4, 5, 6, 6, 5]], [-0, [0, 1]], [-3, [1]], [1.5, [1, 2]], [{ $num: 'NaN' }, [1]], [2 ** 53, [2 ** 53, 2 ** 53 - 1]], [0, [0, -1, 1.5, '2', null, { $num: 'NaN' }, { $num: 'Infinity' }, 2 ** 53, 2 ** 53 + 2, 3]], [0, []], ['3', [3, 4]], [null, [1]]] as any[]).entries()) await add('fenceGuard', `f${i}`, [init, es]);
await add('constants', 'all', []);

// ---- lease scenarios
const OK = { ttlMs: 10_000 }, SK = { ttlMs: 10_000, skewMs: 0 }, SK2 = { ttlMs: 10_000, skewMs: 2_000 };
const L = (name: string, ops: any[]) => add('lease', name, [ops]);
await L('acquire-first', [['clock', 100], ['acquire', 'a', 'node1', OK], ['read']]);
await L('acquire-held', [['clock', 100], ['acquire', 'a', 'n1', OK], ['clock', 5000], ['acquire', 'b', 'n2', OK], ['acquire', 'c', 'n1', OK]]);
await L('acquire-after-expiry-skew-edge', [['clock', 0], ['acquire', 'a', 'n1', OK], ['clock', 10_999], ['acquire', 'b', 'n2', OK], ['clock', 11_000], ['acquire', 'c', 'n2', OK]]);
await L('acquire-after-expiry-skew0', [['clock', 0], ['acquire', 'a', 'n1', SK], ['clock', 9_999], ['acquire', 'b', 'n2', SK], ['clock', 10_000], ['acquire', 'c', 'n2', SK]]);
await L('acquire-skew2', [['clock', 0], ['acquire', 'a', 'n1', SK2], ['clock', 11_999], ['acquire', 'b', 'n2', SK2], ['clock', 12_000], ['acquire', 'c', 'n2', SK2]]);
await L('epoch-increments', [['clock', 0], ['acquire', 'a', 'n1', OK], ['clock', 20_000], ['acquire', 'b', 'n2', OK], ['clock', 40_000], ['acquire', 'c', 'n1', OK], ['read']]);
await L('acquire-after-release', [['clock', 0], ['acquire', 'a', 'n1', OK], ['release', 'a'], ['acquire', 'b', 'n2', OK], ['read']]);
await L('acquire-invalid', [['acquire', 'a', '', OK], ['acquire', 'a', 5, OK], ['acquire', 'a', 'x'.repeat(257), OK], ['acquire', 'a', 'x'.repeat(256), OK], ['release', 'a'],
  ['acquire', 'b', 'n', { ttlMs: 1 }], ['acquire', 'b', 'n', { ttlMs: 2 }], ['release', 'b'], ['acquire', 'b', 'n', { ttlMs: 3_600_001 }], ['acquire', 'b', 'n', { ttlMs: 3_600_000 }], ['release', 'b'], ['acquire', 'b', 'n', { ttlMs: 1.5 }], ['acquire', 'b', 'n', { ttlMs: '10' }], ['acquire', 'b', 'n', {}], ['acquire', 'b', 'n', null],
  ['acquire', 'b', 'n', { ttlMs: 10, skewMs: 10 }], ['acquire', 'b', 'n', { ttlMs: 10, skewMs: 9 }], ['release', 'b'], ['acquire', 'b', 'n', { ttlMs: 10, skewMs: -1 }], ['acquire', 'b', 'n', { ttlMs: 10, skewMs: { $num: 'NaN' } }], ['acquire', 'b', 'n', { ttlMs: 10, skewMs: null }], ['acquire', 'b', 'n', { ttlMs: 10, skewMs: '1' }]]);
await L('acquire-lost-race', [['clock', 0], ['fault', 'loseCas'], ['acquire', 'a', 'n1', OK], ['acquire', 'b', 'n1', OK], ['read']]);
await L('acquire-store-errors', [['fault', 'read'], ['acquire', 'a', 'n1', OK], ['fault', 'now'], ['acquire', 'a', 'n1', OK], ['fault', 'cas'], ['acquire', 'a', 'n1', OK], ['fault', 'none'], ['acquire', 'a', 'n1', OK]]);
await L('acquire-bad-clock', [['clock', { $num: 'NaN' }], ['acquire', 'a', 'n1', OK], ['clock', { $num: 'Infinity' }], ['acquire', 'a', 'n1', OK], ['clock', -5], ['acquire', 'a', 'n1', OK], ['read']]);
await L('acquire-corrupt-store', [['raw', { holder: 'x' }], ['acquire', 'a', 'n1', OK], ['raw', 'junk'], ['acquire', 'a', 'n1', OK], ['raw', { holder: 'x', epoch: 0, expiresAt: 5 }], ['acquire', 'a', 'n1', OK], ['raw', { holder: 'x', epoch: 1.5, expiresAt: 5 }], ['acquire', 'a', 'n1', OK],
  ['raw', { holder: 'x', epoch: 1, expiresAt: { $num: 'NaN' } }], ['acquire', 'a', 'n1', OK], ['raw', { holder: 5, epoch: 1, expiresAt: 5 }], ['acquire', 'a', 'n1', OK], ['raw', { holder: 'x', epoch: 2 ** 53, expiresAt: 5 }], ['acquire', 'a', 'n1', OK], ['raw', { holder: 'x', epoch: 1, expiresAt: -5 }], ['acquire', 'a', 'n1', OK]]);
await L('acquire-expiresAt-zero-is-released', [['clock', 5], ['raw', { holder: 'x', epoch: 7, expiresAt: 0 }], ['acquire', 'a', 'n1', OK], ['read']]);
await L('acquire-extra-record-members', [['clock', 0], ['raw', { holder: 'x', epoch: 3, expiresAt: 100, extra: 1 }], ['clock', 5_000], ['acquire', 'a', 'n1', OK], ['read']]);
await L('renew-ok', [['clock', 0], ['acquire', 'a', 'n1', OK], ['clock', 5000], ['renew', 'a', OK], ['read'], ['clock', 14_000], ['renew', 'a', OK]]);
await L('renew-expired-edge', [['clock', 0], ['acquire', 'a', 'n1', OK], ['clock', 8_999], ['renew', 'a', OK], ['clock', 18_000], ['renew', 'a', OK], ['clock', 17_999], ['renew', 'a', OK]]);
await L('renew-expired-skew0', [['clock', 0], ['acquire', 'a', 'n1', SK], ['clock', 9_999], ['renew', 'a', SK], ['clock', 30_000], ['renew', 'a', SK]]);
await L('renew-stale', [['clock', 0], ['acquire', 'a', 'n1', OK], ['clock', 20_000], ['acquire', 'b', 'n2', OK], ['renew', 'a', OK], ['renew', 'b', OK], ['renew', { holder: 'n2', epoch: 1, expiresAt: 5 }, OK], ['renew', { holder: 'nX', epoch: 2, expiresAt: 5 }, OK]]);
await L('renew-no-store', [['renew', { holder: 'n1', epoch: 1, expiresAt: 100 }, OK]]);
await L('renew-invalid', [['clock', 0], ['acquire', 'a', 'n1', OK], ['renew', null, OK], ['renew', 'zzz', OK], ['renew', 5, OK], ['renew', { holder: 'n1', epoch: 0, expiresAt: 5 }, OK], ['renew', { holder: 'n1', epoch: 1 }, OK], ['renew', { holder: '', epoch: 1, expiresAt: 5 }, OK], ['renew', 'a', { ttlMs: 1 }], ['renew', 'a', null], ['renew', 'a', { ttlMs: 10, skewMs: 10 }]]);
await L('renew-lost-race', [['clock', 0], ['acquire', 'a', 'n1', OK], ['clock', 100], ['fault', 'loseCas'], ['renew', 'a', OK], ['renew', 'a', OK]]);
await L('renew-store-errors', [['clock', 0], ['acquire', 'a', 'n1', OK], ['fault', 'read'], ['renew', 'a', OK], ['fault', 'now'], ['renew', 'a', OK], ['fault', 'cas'], ['renew', 'a', OK]]);
await L('renew-after-release', [['clock', 0], ['acquire', 'a', 'n1', OK], ['release', 'a'], ['renew', 'a', OK]]);
await L('renew-keeps-epoch-extends-ttl', [['clock', 0], ['acquire', 'a', 'n1', OK], ['clock', 1000], ['renew', 'a', { ttlMs: 50_000 }], ['read'], ['clock', 2000], ['renew', 'a', { ttlMs: 3 }], ['read']]);
await L('release-ok', [['clock', 0], ['acquire', 'a', 'n1', OK], ['release', 'a'], ['read'], ['release', 'a']]);
await L('release-stale', [['clock', 0], ['acquire', 'a', 'n1', OK], ['clock', 20_000], ['acquire', 'b', 'n2', OK], ['release', 'a'], ['release', 'b'], ['release', { holder: 'n2', epoch: 2, expiresAt: 5 }]]);
await L('release-invalid', [['release', null], ['release', 5], ['release', 'zz'], ['release', { holder: 'x', epoch: 0, expiresAt: 1 }], ['release', { holder: 'x', epoch: 1, expiresAt: { $num: 'Infinity' } }]]);
await L('release-no-store', [['release', { holder: 'n1', epoch: 1, expiresAt: 100 }]]);
await L('release-errors', [['clock', 0], ['acquire', 'a', 'n1', OK], ['fault', 'read'], ['release', 'a'], ['fault', 'none'], ['fault', 'loseCas'], ['release', 'a'], ['fault', 'cas'], ['release', 'a']]);
await L('release-bad-clock-still-ok', [['clock', 0], ['acquire', 'a', 'n1', OK], ['clock', { $num: 'NaN' }], ['release', 'a']]);
await L('fence-ok-and-edges', [['clock', 0], ['acquire', 'a', 'n1', OK], ['clock', 8_999], ['fence', 'a', null], ['clock', 9_000], ['fence', 'a', null], ['fence', 'a', 0], ['clock', 9_999], ['fence', 'a', 0], ['clock', 10_000], ['fence', 'a', 0], ['fence', 'a', 5000]]);
await L('fence-stale', [['clock', 0], ['acquire', 'a', 'n1', OK], ['clock', 20_000], ['acquire', 'b', 'n2', OK], ['fence', 'a', null], ['fence', 'b', null], ['fence', { holder: 'n2', epoch: 2 }, null], ['fence', { holder: 'n2', epoch: 3 }, null], ['fence', { holder: 'n1', epoch: 2 }, null]]);
await L('fence-released', [['clock', 0], ['acquire', 'a', 'n1', OK], ['release', 'a'], ['fence', { holder: 'n1', epoch: 1 }, null]]);
await L('fence-no-store', [['fence', { holder: 'n1', epoch: 1 }, null]]);
await L('fence-bad-args', [['clock', 0], ['acquire', 'a', 'n1', OK], ['fence', null, null], ['fence', 5, null], ['fence', 'zz', null], ['fence', 'a', -1], ['fence', 'a', { $num: 'NaN' }], ['fence', 'a', { $num: 'Infinity' }], ['fence', { holder: 'n1' }, null], ['fence', 'a', '5']]);
await L('fence-errors', [['clock', 0], ['acquire', 'a', 'n1', OK], ['fault', 'read'], ['fence', 'a', null], ['fault', 'now'], ['fence', 'a', null], ['fault', 'none'], ['clock', { $num: 'NaN' }], ['fence', 'a', null], ['raw', 'junk'], ['clock', 0], ['fence', 'a', null]]);
await L('signer-ok', [['clock', 0], ['acquire', 'a', 'n1', OK], ['signer', 'a', null, 0, false], ['signer', 'a', 0, 0, false]]);
await L('signer-no-lease', [['signer', null, null, 0, false]]);
await L('signer-stale', [['clock', 0], ['acquire', 'a', 'n1', OK], ['clock', 20_000], ['acquire', 'b', 'n2', OK], ['signer', 'a', null, 0, false], ['signer', 'b', null, 0, false]]);
await L('signer-expired-before', [['clock', 0], ['acquire', 'a', 'n1', OK], ['clock', 9_500], ['signer', 'a', null, 0, false]]);
await L('signer-expires-during-sign', [['clock', 0], ['acquire', 'a', 'n1', OK], ['signer', 'a', null, 9_000, false], ['clock', 0], ['acquire', 'b', 'n1', OK], ['signer', 'b', null, 8_000, false], ['signer', 'b', null, 100, false]]);
await L('signer-sign-throws', [['clock', 0], ['acquire', 'a', 'n1', OK], ['signer', 'a', null, 0, true], ['signer', 'a', null, 20_000, true]]);
await L('signer-store-error', [['clock', 0], ['acquire', 'a', 'n1', OK], ['fault', 'read'], ['signer', 'a', null, 0, false]]);
await L('signer-stolen-during-sign', [['clock', 0], ['acquire', 'a', 'n1', OK], ['signer', 'a', 0, 11_000, false]]);
await L('bad-op', [['bogus'], ['clock', 5], ['read']]);
// KvLeaseStore.cas directly
const R = (h: string, e: number, x: number) => ({ holder: h, epoch: e, expiresAt: x });
for (const [n, prev, exp, next] of [
  ['empty-to-first', null, null, R('a', 1, 10)], ['match', R('a', 1, 10), R('a', 1, 10), R('a', 1, 20)], ['mismatch-holder', R('a', 1, 10), R('b', 1, 10), R('a', 1, 20)], ['mismatch-expires', R('a', 1, 10), R('a', 1, 11), R('a', 1, 20)],
  ['expect-undefined-but-present', R('a', 1, 10), null, R('b', 2, 20)], ['expect-present-but-empty', null, R('a', 1, 10), R('a', 1, 20)], ['epoch-regress', R('a', 5, 10), R('a', 5, 10), R('a', 4, 20)], ['epoch-same', R('a', 5, 10), R('a', 5, 10), R('b', 5, 20)], ['epoch-jump', R('a', 5, 10), R('a', 5, 10), R('b', 9, 20)],
  ['prev-corrupt', { holder: 'x' }, null, R('a', 1, 10)], ['prev-corrupt-match', 'junk', 'junk', R('a', 1, 10)], ['next-invalid-epoch', null, null, R('a', 0, 10)], ['next-invalid-holder', null, null, { holder: 5, epoch: 1, expiresAt: 1 }], ['next-invalid-expires', null, null, { holder: 'a', epoch: 1, expiresAt: { $num: 'NaN' } }], ['next-null', null, null, null],
  ['next-extra-members', null, null, { holder: 'a', epoch: 1, expiresAt: 5, extra: 1 }], ['match-ignores-extras', { holder: 'a', epoch: 1, expiresAt: 10, extra: 1 }, R('a', 1, 10), R('a', 1, 20)],
] as any[]) await add('kvCas', n, [prev, exp, next]);
refWrite(o, 'ha');
