// Oracle: the durable store sides of the core (TS reference): ledger-store.ts (KvLedgerStore, StoredLedger), bond-store.ts (KvBondStore),
// budget-ledger.ts (KvBudgetLedger, signed releases, scoped admission) and the mesh witness (MeshWitness / MemoryMeshWitnessStore).
// Every case is ONE deterministic scripted op sequence over a fresh in-memory store: args = [ops], out = [one result per op]. An op that
// throws records {"$err": code} (the typed store error code, "RangeError" for a range refusal, "Error" otherwise; the witness records its
// message). Sequences are scripted boundary cases plus seeded random walks that follow the state the reference returns.
// PORTING (net.atlasauth.pca: KvLedgerStore / StoredLedger / KvBondStore / KvBudgetLedger / Budgets / MeshWitness / MeshDomain, over MemoryAtomicKv):
//   ledgerStore(ops)  ops: ["size"] ["read",from,to] ["append",expected,[commits]] ["cpCount"] ["cps",from] ["appendCp",expected,cp] ["kvSet",rawDoc]
//                     -> outcome objects as the store's toJson(); lists as lists
//   storedLedger(ops) handles by name over ONE shared store: ["open",H] (a fresh StoredLedger, instance "inst", principal "pr", guardian seed "g",
//                     clock = 1_800_000_000_000 + 1000*calls), [H,"append",commit] [H,"checkpoint"] [H,"catchUp"] [H,"head"] [H,"size"] [H,"incl",i]
//                     [H,"consFrom",n] [H,"commits"] [H,"latest"] [H,"chain"] ["kvSet",rawDoc] ["kvGet"]
//   bondStore(ops)    ops: ["read",claimId,depositor|null] ["commit",plan,observedAt] ["deposit",account,amount] ["kvSet",raw] ["kvGet"]
//   budgetLedger(ops) ledger durable flag first: ["new",durable] then ["snapshot",key] ["reserve",key,req] ["start",key,id] ["commit",key,id] ["release",key,id,evidence|null]
//                     ["expire",key,now] ["signRelease",key,id,reason,at] ["verifyRelease",release,signer] ["scopeKey",scope,id]
//                     ["admit",{ids,accumulators,event,allow,expiresAt?}] (the verifier returns {allow}) ["start+settle",...] is not an op: use start/commit/release
//   meshWitness(ops)  ["store",S] ["witness",W,S|null,seedLabel] ["domain",D,seedLabel] ["record",D,label] ["revoke",D,id] ["publish",D,ts,[W..],threshold|null]
//                     ["lastSeen",W,domain] ["export",W] ["load",S] ["save",S,state] ["restart",W,S,seedLabel] ["publishRaw",W,req]
import { Oracle, refWrite, rng, jsonOut } from './lib.mjs';
import { createHash } from 'node:crypto';

const { createMemoryDurableKv } = await import('../../../packages/pca/src/durable-state.ts');
const L: any = await import('../../../packages/pca/src/ledger-store.ts');
const B: any = await import('../../../packages/pca/src/bond-store.ts');
const G: any = await import('../../../packages/pca/src/budget-ledger.ts');
const M: any = await import('../../../packages/pca/src/mesh.ts');
const { publicKeyOf } = await import('../../../packages/pca/src/keys.ts');
const seedOf = (l: string) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());

const o = new Oracle('core-stores-java', 'tools/pca-audit/oracles/core-stores-java.mts', 'TS-reference oracle for the durable core stores (ledger, stored ledger, bond, budget, mesh witness).');

const errName = (e: any, byMessage = false): string => (byMessage ? String(e?.message) : typeof e?.code === 'string' ? e.code : e instanceof RangeError ? 'RangeError' : 'Error');
async function step(fn: () => any, byMessage = false): Promise<any> {
  try {
    const v = jsonOut(await fn());
    return v === undefined ? null : v;
  } catch (e) {
    return { $err: errName(e, byMessage) };
  }
}

// ---------------------------------------------------------------- ledger store
const lcp = (size: number, root: string, prev = '', extra: any = {}) => ({ sth: { instance_id: 'i', principal: 'p', size, root, prev_root: prev, timestamp: 1, guardian: 'g', sig: 's' }, ...extra });
async function ledgerRun(ops: any[]): Promise<any[]> {
  const kv = createMemoryDurableKv();
  const s = new L.KvLedgerStore(kv);
  const out: any[] = [];
  for (const op of ops) {
    out.push(
      await step(async () => {
        switch (op[0]) {
          case 'size': return await s.size();
          case 'read': return await s.read(op[1], op[2]);
          case 'append': return await s.append(op[1], op[2]);
          case 'cpCount': return await s.checkpointCount();
          case 'cps': return await s.checkpoints(op[1]);
          case 'appendCp': return await s.appendCheckpoint(op[1], op[2]);
          case 'kvSet': return void (await kv.set('pca-ledger-store/v1', op[1]));
          default: throw new Error('op');
        }
      }),
    );
  }
  return out;
}
const ledgerCases: Array<[string, any[]]> = [];
ledgerCases.push(['basics', [['size'], ['cpCount'], ['read', 0, 0], ['append', 0, ['a', 'b']], ['size'], ['read', 0, 2], ['read', 1, 2], ['read', 2, 1], ['read', 0, 3], ['read', -1, 1], ['read', 0.5, 1], ['read', 2 ** 53, 2 ** 53], ['cps', 0], ['cps', 1], ['cps', -1]]]);
ledgerCases.push(['cas', [['append', 0, ['a']], ['append', 0, ['a']], ['append', 0, ['b']], ['append', 5, ['x']], ['append', 1, ['b', 'c']], ['append', 1, ['b', 'c']], ['append', 1, ['b']], ['append', 1, ['b', 'c', 'd']], ['append', 2, ['c', 'd']], ['append', 3, ['z']], ['size']]]);
ledgerCases.push(['bad-args', [['append', -1, ['a']], ['append', 1.5, ['a']], ['append', 0, []], ['append', 0, ['']], ['append', 0, ['a', '']], ['append', 0, ['a', 5]], ['append', 0, 'a'], ['append', 2 ** 53, ['a']], ['append', -0, ['a']], ['size'], ['appendCp', -1, lcp(0, 'r')], ['appendCp', 0.5, lcp(0, 'r')]]]);
ledgerCases.push(['checkpoints', [['append', 0, ['a', 'b', 'c']], ['appendCp', 0, lcp(2, 'r2')], ['appendCp', 0, lcp(2, 'r2')], ['appendCp', 0, lcp(3, 'r3')], ['appendCp', 2, lcp(3, 'r3')], ['appendCp', 1, lcp(2, 'r2')], ['appendCp', 1, lcp(1, 'r1')], ['appendCp', 1, lcp(2, 'other')], ['appendCp', 1, lcp(4, 'r4')], ['appendCp', 1, lcp(3, 'r3', 'r2', { proof: { oldSize: 2, newSize: 3, path: ['x'] } })], ['cpCount'], ['cps', 0], ['cps', 1], ['cps', 2], ['cps', 3]]]);
ledgerCases.push(['malformed-cp', [['append', 0, ['a']], ['appendCp', 0, {}], ['appendCp', 0, { sth: 5 }], ['appendCp', 0, { sth: { size: -1, root: 'r' } }], ['appendCp', 0, { sth: { size: 1.5, root: 'r' } }], ['appendCp', 0, { sth: { size: 1 } }], ['appendCp', 0, { sth: { size: 1, root: 7 } }], ['appendCp', 0, { sth: { size: -0, root: 'r' } }], ['appendCp', 0, { sth: { size: 0, root: 'r' } }], ['cpCount']]]);
ledgerCases.push(['corrupt', [['kvSet', { v: 2, commits: [], checkpoints: [] }], ['size'], ['kvSet', { v: 1, commits: [1], checkpoints: [] }], ['read', 0, 0], ['kvSet', { v: 1, commits: [''], checkpoints: [] }], ['append', 0, ['a']], ['kvSet', { v: 1, commits: [], checkpoints: [5] }], ['cpCount'], ['kvSet', { v: 1, commits: [], checkpoints: [{ sth: 1 }] }], ['cps', 0], ['kvSet', { v: 1, commits: 'x', checkpoints: [] }], ['size'], ['kvSet', [1]], ['size'], ['kvSet', { v: 1, commits: ['a'], checkpoints: [] }], ['size']]]);
for (let seed = 1; seed <= 60; seed++) {
  const r = rng(0x1ed9e0 + seed);
  const ops: any[] = [];
  let size = 0, cps = 0, lastCp: any = null;
  const content: string[] = [];
  // follow the reference state: replay each op on a shadow store to know size / cps
  const kv = createMemoryDurableKv();
  const s = new L.KvLedgerStore(kv);
  for (let i = 0; i < 40; i++) {
    const kind = r.pick(['append', 'append', 'append', 'appendCp', 'appendCp', 'read', 'size', 'cps', 'cpCount']);
    let op: any[];
    if (kind === 'append') {
      const exp = Math.max(0, size + r.pick([0, 0, 0, 0, -1, 1, -2, 2]));
      const n = r.int(1, 3);
      const cs = r.next() < 0.3 && content.length > 0 ? content.slice(Math.min(exp, content.length - 1), Math.min(exp, content.length - 1) + n) : Array.from({ length: n }, (_, k) => `c${seed}-${i}-${k}`);
      op = ['append', exp, cs.length ? cs : ['z']];
    } else if (kind === 'appendCp') {
      const exp = Math.max(0, cps + r.pick([0, 0, 0, -1, 1]));
      const sz = r.pick([size, size, Math.max(0, size - 1), size + 1, lastCp ? lastCp.sth.size : 0, 0]);
      const root = r.next() < 0.3 && lastCp ? lastCp.sth.root : `r${sz}`;
      op = ['appendCp', exp, lcp(sz, root, lastCp ? lastCp.sth.root : '')];
    } else if (kind === 'read') {
      const a = r.int(0, size + 1), b = r.int(0, size + 1);
      op = ['read', a, b];
    } else if (kind === 'cps') op = ['cps', r.int(0, cps + 1)];
    else op = [kind];
    ops.push(op);
    // shadow
    const res = await step(async () => {
      switch (op[0]) {
        case 'size': return await s.size();
        case 'read': return await s.read(op[1], op[2]);
        case 'append': return await s.append(op[1], op[2]);
        case 'cpCount': return await s.checkpointCount();
        case 'cps': return await s.checkpoints(op[1]);
        case 'appendCp': return await s.appendCheckpoint(op[1], op[2]);
      }
    });
    if (op[0] === 'append' && res.outcome === 'appended') { content.push(...op[2]); size = res.size; }
    if (op[0] === 'appendCp' && res.outcome === 'appended') { cps = res.count; lastCp = op[2]; }
  }
  ledgerCases.push([`walk${seed}`, ops]);
}
for (const [name, ops] of ledgerCases) await o.run('ledgerStore', name, ledgerRun, [ops]);

// ---------------------------------------------------------------- stored ledger
async function storedRun(ops: any[]): Promise<any[]> {
  const kv = createMemoryDurableKv();
  const store = new L.KvLedgerStore(kv);
  const handles = new Map<string, any>();
  let calls = 0;
  const clock = () => 1_800_000_000_000 + 1000 * calls++;
  const gsecret = seedOf('stored-ledger-guardian');
  const out: any[] = [];
  for (const op of ops) {
    out.push(
      await step(async () => {
        if (op[0] === 'open') {
          const h = await L.StoredLedger.open({ store, guardianSecret: op[2] === 'other-key' ? seedOf('other') : gsecret, instanceId: op[3] ?? 'inst', principal: 'pr', clock });
          handles.set(op[1], h);
          return { size: h.size, guardian: h.guardian };
        }
        if (op[0] === 'kvSet') return void (await kv.set('pca-ledger-store/v1', op[1]));
        if (op[0] === 'kvGet') return await kv.get('pca-ledger-store/v1');
        const h = handles.get(op[0]);
        switch (op[1]) {
          case 'append': return await h.append(op[2]);
          case 'checkpoint': return await h.checkpoint();
          case 'catchUp': return void (await h.catchUp());
          case 'head': return h.head();
          case 'size': return h.size;
          case 'incl': return h.inclusionProof(op[2]);
          case 'consFrom': return h.consistencyProofFrom(op[2]);
          case 'commits': return h.commits();
          case 'latest': return h.latestCheckpoint() ?? null;
          case 'chain': return h.checkpointChain();
          case 'guardian': return h.guardian;
        }
        throw new Error('op');
      }),
    );
  }
  return out;
}
{
  // build tamper docs by running the reference once
  const mk = async (n: number, cpAt: number[]) => {
    const ops: any[] = [['open', 'A']];
    for (let i = 0; i < n; i++) {
      ops.push(['A', 'append', `entry${i}`]);
      if (cpAt.includes(i + 1)) ops.push(['A', 'checkpoint']);
    }
    return ops;
  };
  const base = await mk(7, [2, 5, 7]);
  const baseOps = [...base, ['kvGet']];
  const baseOut = await storedRun(baseOps);
  const doc: any = baseOut[baseOut.length - 1];
  const edit = (f: (d: any) => void) => { const d = JSON.parse(JSON.stringify(doc)); f(d); return d; };
  const tails: Array<[string, any[]]> = [
    ['reopen', [['open', 'B'], ['B', 'head'], ['B', 'latest'], ['B', 'chain'], ['B', 'checkpoint'], ['B', 'incl', 3], ['B', 'consFrom', 2], ['B', 'consFrom', 7], ['B', 'consFrom', 8], ['B', 'commits']]],
    ['tamper-entry', [['kvSet', edit((d) => { d.commits[1] = 'tampered'; })], ['open', 'B']]],
    ['tamper-late', [['kvSet', edit((d) => { d.commits[6] = 'tampered'; })], ['open', 'B']]],
    ['rollback', [['kvSet', edit((d) => { d.commits.length = 4; })], ['open', 'B']]],
    ['rollback-to-zero', [['kvSet', edit((d) => { d.commits.length = 0; })], ['open', 'B']]],
    ['forged-sig', [['kvSet', edit((d) => { d.checkpoints[1].sth.sig = d.checkpoints[0].sth.sig; })], ['open', 'B']]],
    ['forged-root', [['kvSet', edit((d) => { d.checkpoints[1].sth.root = d.checkpoints[0].sth.root; })], ['open', 'B']]],
    ['other-log', [['kvSet', edit((d) => { d.checkpoints[0].sth.instance_id = 'elsewhere'; })], ['open', 'B']]],
    ['no-proof', [['kvSet', edit((d) => { delete d.checkpoints[1].proof; })], ['open', 'B']]],
    ['bad-proof', [['kvSet', edit((d) => { d.checkpoints[2].proof.path = d.checkpoints[2].proof.path.slice(1); })], ['open', 'B']]],
    ['wrong-key', [['open', 'B', 'other-key']]],
    ['wrong-instance', [['open', 'B', 'g', 'other-instance']]],
    ['corrupt-doc', [['kvSet', { v: 9 }], ['open', 'B']]],
    ['bad-size-type', [['kvSet', edit((d) => { d.checkpoints[0].sth.size = 1.5; })], ['open', 'B']]],
  ];
  for (const [n, t] of tails) await o.run('storedLedger', `tail-${n}`, storedRun, [[...baseOps, ...t]]);
  await o.run('storedLedger', 'fresh', storedRun, [[['open', 'A'], ['A', 'head'], ['A', 'checkpoint'], ['A', 'checkpoint'], ['A', 'latest'], ['A', 'append', 'x'], ['A', 'checkpoint'], ['A', 'checkpoint'], ['A', 'chain'], ['A', 'incl', 0], ['A', 'incl', 1], ['A', 'consFrom', 1], ['A', 'consFrom', 0], ['A', 'append', ''], ['A', 'guardian']]]);
  // two writers
  await o.run('storedLedger', 'two-writers', storedRun, [[['open', 'A'], ['open', 'B'], ['A', 'append', 'a1'], ['B', 'append', 'b1'], ['A', 'append', 'a2'], ['B', 'checkpoint'], ['A', 'checkpoint'], ['B', 'append', 'b2'], ['A', 'catchUp'], ['A', 'size'], ['B', 'size'], ['A', 'checkpoint'], ['B', 'catchUp'], ['B', 'chain'], ['A', 'commits']]]);
  // sizes: every log size 0..40 with checkpoints at a few points (consistency proofs of every shape)
  for (const n of [1, 2, 3, 5, 6, 7, 8, 9, 13, 16, 17, 31, 32, 33]) {
    const ops: any[] = [['open', 'A']];
    for (let i = 0; i < n; i++) { ops.push(['A', 'append', `leaf-${n}-${i}`]); if (i % 3 === 2) ops.push(['A', 'checkpoint']); }
    ops.push(['A', 'checkpoint'], ['A', 'head'], ['A', 'chain'], ['open', 'B'], ['B', 'size']);
    for (let k = 0; k <= n; k += Math.max(1, Math.floor(n / 5))) ops.push(['A', 'consFrom', k], ['A', 'incl', Math.min(k, n - 1)]);
    await o.run('storedLedger', `sizes${n}`, storedRun, [ops]);
  }
}

// ---------------------------------------------------------------- bond store
const rec = (claimId: string, action: string, amount: number, from: string, to: string, evidenceDigest = '', split?: any) => ({ claimId, action, amount, from, to, at: 1, evidenceDigest, ...(split ? { split } : {}), sig: 'sig' });
const openPlan = (id: string, dep: string, amount: number, caps: any = { maxOpenClaims: 100, maxOpenAmount: 1e9 }, window?: any) => ({
  claimId: id, expect: 'none', next: 'open', open: { amount, depositor: dep, ...caps, ...(window ? { window } : {}) },
  moves: [{ account: dep, op: 'debit', amount }, { account: 'escrow', op: 'credit', amount }], record: rec(id, 'open', amount, dep, 'escrow'),
});
const releasePlan = (id: string, dep: string, amount: number) => ({ claimId: id, expect: 'open', next: 'released', moves: [{ account: 'escrow', op: 'debit', amount }, { account: dep, op: 'credit', amount }], record: rec(id, 'release', amount, 'escrow', dep) });
const slashPlan = (id: string, amount: number, evidence = 'ev') => ({
  claimId: id, expect: 'open', next: 'slashed',
  moves: [{ account: 'escrow', op: 'debit', amount }, { account: 'chal', op: 'credit', amount: amount / 2 }, { account: 'treasury', op: 'credit', amount: amount / 2 }],
  record: rec(id, 'slash', amount, 'escrow', 'treasury', evidence, { amount, challengerReward: amount / 2, victimCompensation: 0, treasuryRemainder: amount / 2, challengerAccount: 'chal', victimAccount: 'pool', treasuryAccount: 'treasury' }),
});
async function bondRun(ops: any[]): Promise<any[]> {
  const kv = createMemoryDurableKv();
  const s = new B.KvBondStore(kv);
  const out: any[] = [];
  for (const op of ops) {
    out.push(
      await step(async () => {
        switch (op[0]) {
          case 'read': return await s.read({ claimId: op[1], ...(op[2] !== null && op[2] !== undefined ? { depositor: op[2] } : {}) });
          case 'commit': return await s.commit(op[1], op[2]);
          case 'deposit': return await s.deposit(op[1], op[2]);
          case 'kvSet': return void (await kv.set('pca-bond-store/v1', op[1]));
          case 'kvGet': return await kv.get('pca-bond-store/v1');
        }
        throw new Error('op');
      }),
    );
  }
  return out;
}
const win = { registeredAt: 5, windowMs: 1000, claimDigest: 'd1' };
const bondCases: Array<[string, any[]]> = [
  ['lifecycle', [['read', 'c1', 'alice'], ['deposit', 'alice', 100], ['commit', openPlan('c1', 'alice', 40), 10], ['read', 'c1', 'alice'], ['commit', openPlan('c1', 'alice', 40), 11], ['commit', releasePlan('c1', 'alice', 40), 20], ['commit', releasePlan('c1', 'alice', 40), 21], ['commit', slashPlan('c1', 40), 22], ['read', 'c1', 'alice'], ['read', 'c1', 'escrow']]],
  ['slash', [['deposit', 'alice', 100], ['commit', openPlan('c1', 'alice', 40), 10], ['commit', slashPlan('c1', 40), 20], ['commit', slashPlan('c1', 40), 21], ['commit', slashPlan('c1', 40, 'other'), 22], ['commit', releasePlan('c1', 'alice', 40), 23], ['read', 'c1', 'chal'], ['read', 'c1', 'treasury']]],
  ['overdraft', [['deposit', 'alice', 10], ['commit', openPlan('c1', 'alice', 40), 1], ['read', 'c1', 'alice'], ['commit', openPlan('c1', 'alice', 10), 2], ['commit', openPlan('c2', 'alice', 1), 3]]],
  ['caps', [['deposit', 'alice', 1000], ['commit', openPlan('a', 'alice', 10, { maxOpenClaims: 2, maxOpenAmount: 100 }), 1], ['commit', openPlan('b', 'alice', 10, { maxOpenClaims: 2, maxOpenAmount: 100 }), 2], ['commit', openPlan('c', 'alice', 10, { maxOpenClaims: 2, maxOpenAmount: 100 }), 3], ['commit', releasePlan('a', 'alice', 10), 4], ['commit', openPlan('c', 'alice', 10, { maxOpenClaims: 2, maxOpenAmount: 100 }), 5], ['commit', openPlan('d', 'alice', 95, { maxOpenClaims: 5, maxOpenAmount: 100 }), 6], ['read', 'a', 'alice']]],
  ['windows', [['deposit', 'alice', 100], ['commit', openPlan('w', 'alice', 5, undefined, win), 1], ['commit', openPlan('w', 'alice', 5, undefined, { ...win, registeredAt: 99 }), 2], ['commit', openPlan('w', 'alice', 5, undefined, { ...win, windowMs: 5 }), 3], ['commit', openPlan('w', 'alice', 5), 4], ['read', 'w', null]]],
  ['malformed', [['commit', { ...openPlan('m', 'alice', 1), open: undefined }, 1], ['commit', { ...openPlan('m', 'alice', 1), next: 'released' }, 1], ['commit', releasePlan('nope', 'alice', 1), 1], ['commit', { ...releasePlan('x', 'alice', 1), moves: [{ account: 'a', op: 'debit', amount: -1 }] }, 1]]],
  ['float-exact', [['deposit', 'alice', 0.1], ['deposit', 'alice', 0.2], ['read', 'x', 'alice'], ['deposit', 'bob', 1234567.891234], ['deposit', 'bob', 0.000001], ['deposit', 'bob', 1e-7], ['deposit', 'bob', 1e20], ['deposit', 'bob', 3], ['read', 'x', 'bob'], ['commit', openPlan('f', 'alice', 0.3), 1], ['read', 'f', 'alice'], ['commit', releasePlan('f', 'alice', 0.3), 2], ['read', 'f', 'alice']]],
  ['deposit-args', [['deposit', '', 1], ['deposit', 'a', 0], ['deposit', 'a', -1], ['deposit', 'a', 1e999 === Infinity ? 1 : 1], ['deposit', 'a', 0.5], ['read', 'z', 'a']]],
  ['highwater', [['deposit', 'alice', 10], ['commit', openPlan('h', 'alice', 1), 100], ['read', 'h', null], ['commit', releasePlan('h', 'alice', 1), 50], ['read', 'h', null], ['commit', openPlan('h2', 'alice', 1), -5], ['read', 'h2', null]]],
  ['corrupt', [['kvSet', { v: 2 }], ['read', 'a', null], ['kvSet', { v: 1, balances: [['a', -1]], bonds: [], highWater: 0 }], ['deposit', 'a', 1], ['kvSet', { v: 1, balances: [], bonds: [{}], highWater: 0 }], ['read', 'a', null], ['kvSet', { v: 1, balances: [], bonds: [], highWater: -1 }], ['read', 'a', null], ['kvSet', { v: 1, balances: [['a', 1], 5], bonds: [], highWater: 0 }], ['read', 'a', null], ['kvSet', { v: 1, balances: [['a', 1]], bonds: [], highWater: 3 }], ['read', 'a', 'a'], ['kvGet']]],
];
for (let seed = 1; seed <= 50; seed++) {
  const r = rng(0xb04d00 + seed);
  const ops: any[] = [];
  const ids = ['c1', 'c2', 'c3'], deps = ['alice', 'bob'];
  const amts = [1, 2.5, 10, 0.1, 0.2, 0.3, 7.25, 1234.567891, 3];
  const caps = [{ maxOpenClaims: 100, maxOpenAmount: 1e9 }, { maxOpenClaims: 2, maxOpenAmount: 20 }, { maxOpenClaims: 1, maxOpenAmount: 1e9 }];
  ops.push(['deposit', 'alice', 50], ['deposit', 'bob', 20.5]);
  let t = 10;
  for (let i = 0; i < 30; i++) {
    const id = r.pick(ids), dep = r.pick(deps), amt = r.pick(amts);
    const kind = r.pick(['open', 'open', 'release', 'slash', 'read', 'deposit']);
    t += r.pick([1, 5, -3]);
    if (kind === 'open') ops.push(['commit', openPlan(id, dep, amt, r.pick(caps), r.next() < 0.4 ? win : undefined), t]);
    else if (kind === 'release') ops.push(['commit', releasePlan(id, dep, amt), t]);
    else if (kind === 'slash') ops.push(['commit', slashPlan(id, amt, r.pick(['ev', 'ev2'])), t]);
    else if (kind === 'deposit') ops.push(['deposit', dep, amt]);
    else ops.push(['read', id, r.pick([dep, null])]);
  }
  bondCases.push([`walk${seed}`, ops]);
}
for (const [name, ops] of bondCases) await o.run('bondStore', name, bondRun, [ops]);

// ---------------------------------------------------------------- budget ledger
const CAP = 200;
const spend = (over: any = {}) => ({ id: 'spend', agg: 'sum', val: 'action.params.amount', sel: { verbs: ['pay'] }, win: { kind: 'task' }, key: null, domain_max: CAP, holder: { kind: 'site_local' }, scope: 'principal', ...over });
const countAcc = (over: any = {}) => ({ id: 'n', agg: 'count', sel: { verbs: ['pay', 'send'] }, win: { kind: 'task' }, key: null, domain_max: 5, holder: { kind: 'site_local' }, scope: 'principal', ...over });
const ev = (id: string, amount: number, t = 1000, verb = 'pay') => ({ id, verb, resource: 'r', params: { amount }, t });
const rq = (id: string, amount: number, extra: any = {}) => ({ event: ev(id, amount), accumulators: [spend()], ...extra });
const rkey = seedOf('release-signer');
async function budgetRun(ops: any[]): Promise<any[]> {
  const kv = createMemoryDurableKv();
  let ledger: any = null;
  const log = new L.KvLedgerStore(createMemoryDurableKv());
  const out: any[] = [];
  for (const op of ops) {
    out.push(
      await step(async () => {
        switch (op[0]) {
          case 'new': ledger = new G.KvBudgetLedger(kv, op[1]); return ledger.durable;
          case 'snapshot': return await ledger.snapshot(op[1]);
          case 'reserve': return await ledger.reserve(op[1], op[2]);
          case 'start': return await ledger.start(op[1], op[2]);
          case 'commit': return await ledger.commit(op[1], op[2]);
          case 'release': return await ledger.release(op[1], op[2], op[3] ?? undefined);
          case 'expire': return await ledger.expire(op[1], op[2]);
          case 'signRelease': return G.signRelease({ key: op[1], id: op[2], reason: op[3], at: op[4] }, rkey);
          case 'verifyRelease': return G.verifyRelease(op[1], op[2] === 'signer' ? Buffer.from(publicKeyOf(rkey)).toString('base64url') : op[2]);
          case 'releaseCommit': return [G.releaseDigest(op[1]), G.releaseCommit(op[1])];
          case 'anchor': return [await G.anchorRelease(log, op[1]), await log.size()];
          case 'scopeKey': return G.scopeKey(op[1], op[2]);
          case 'kvSet': return void (await kv.set(op[1], op[2]));
          case 'admit': {
            const a = op[1];
            const r = await G.admitAggregateAction(ledger, { ids: a.ids, accumulators: a.accumulators, event: a.event, verify: async (state: any) => ({ allow: a.allow, state }), expiresAt: a.expiresAt, maxAttempts: a.maxAttempts });
            return r;
          }
          case 'startAgg': return await G.startAggregate(ledger, op[1]);
          case 'settleAgg': return await G.settleAggregate(ledger, op[1], op[2]);
        }
        throw new Error('op');
      }),
    );
  }
  return out;
}
const K = 'principal/alice';
const budgetCases: Array<[string, any[]]> = [
  ['empty', [['new', true], ['snapshot', K], ['snapshot', ''], ['snapshot', 'a\u0001b'], ['expire', K, 5], ['commit', K, 'x'], ['start', K, 'x'], ['release', K, 'x', null]]],
  ['cap', [['new', true], ['reserve', K, rq('a', 150)], ['reserve', K, rq('b', 51)], ['reserve', K, rq('c', 50)], ['reserve', K, rq('d', 1)], ['snapshot', K], ['reserve', K, rq('a', 150)], ['reserve', K, rq('a', 10)], ['commit', K, 'a'], ['release', K, 'a', null], ['release', K, 'c', null], ['reserve', K, rq('e', 50)], ['commit', K, 'c'], ['snapshot', K]]],
  ['version-cas', [['new', true], ['reserve', K, rq('a', 10, { expectedVersion: 0 })], ['reserve', K, rq('b', 10, { expectedVersion: 0 })], ['reserve', K, rq('b', 10, { expectedVersion: 1 })], ['reserve', K, rq('a', 10, { expectedVersion: 0 })], ['reserve', K, rq('z', 1, { expectedVersion: -1 })], ['reserve', K, rq('z', 1, { expectedVersion: 1.5 })]]],
  ['phases', [['new', true], ['reserve', K, rq('a', 10)], ['start', K, 'a'], ['start', K, 'a'], ['expire', K, 10 ** 9], ['commit', K, 'a'], ['start', K, 'a'], ['commit', K, 'a'], ['release', K, 'a', null], ['reserve', K, rq('b', 10, { expiresAt: 50 })], ['expire', K, 49], ['expire', K, 50], ['start', K, 'b'], ['commit', K, 'b'], ['release', K, 'b', null], ['release', K, 'b', null], ['snapshot', K]]],
  ['expire-mix', [['new', true], ['reserve', K, rq('a', 10, { expiresAt: 10 })], ['reserve', K, rq('b', 10, { expiresAt: 20 })], ['reserve', K, rq('c', 10)], ['start', K, 'a'], ['reserve', K, rq('d', 10, { expiresAt: 5 })], ['commit', K, 'd'], ['expire', K, 100], ['expire', K, 100], ['expire', K, 1.5], ['snapshot', K]]],
  ['signed-release', [['new', true], ['reserve', K, rq('a', 10)], ['signRelease', K, 'a', 'effect_failed', 100], ['signRelease', K, 'b', 'bogus', 100], ['signRelease', K, 'a', 'rollback', 1.5], ['signRelease', '', 'a', 'rollback', 1], ['verifyRelease', { v: 1 }, 'signer'], ['snapshot', K]]],
  ['accumulator-kinds', [['new', true], ['reserve', K, { event: ev('a', 1), accumulators: [countAcc({ domain_max: 2 })] }], ['reserve', K, { event: ev('b', 1, 1000, 'send'), accumulators: [countAcc({ domain_max: 2 })] }], ['reserve', K, { event: ev('c', 1, 1000, 'send'), accumulators: [countAcc({ domain_max: 2 })] }], ['reserve', K, { event: ev('d', 1, 1000, 'other'), accumulators: [countAcc({ domain_max: 2 })] }], ['reserve', K, { event: ev('e', 1), accumulators: [spend({ domain_max: undefined })] }], ['reserve', K, { event: ev('f', 1), accumulators: 'x' }], ['reserve', K, { event: { id: '' }, accumulators: [] }], ['reserve', K, { event: ev('g', 1), accumulators: [{ ...spend(), agg: 'bogus' }] }], ['snapshot', K]]],
  ['corrupt', [['new', true], ['kvSet', 'pca-budget-ledger/v1/' + K, { v: 2 }], ['snapshot', K], ['kvSet', 'pca-budget-ledger/v1/' + K, { v: 1, ver: 1.5, events: [] }], ['snapshot', K], ['kvSet', 'pca-budget-ledger/v1/' + K, { v: 1, ver: 1, events: [{ id: 3 }] }], ['reserve', K, rq('a', 1)], ['kvSet', 'pca-budget-ledger/v1/' + K, { v: 1, ver: 4, events: [{ id: 'x', verb: 'pay', resource: 'r', params: { amount: 'oops' }, t: 1, status: 'reserved' }] }], ['reserve', K, rq('a', 1)], ['snapshot', K]]],
  ['scope-keys', [['scopeKey', 'principal', 'alice'], ['scopeKey', 'org', 'a b/c?d=é'], ['scopeKey', 'fleet', "x-_.!~*'()"], ['scopeKey', 'org', ''], ['scopeKey', 'org', 'x'.repeat(256)], ['scopeKey', 'org', 'x'.repeat(257)], ['scopeKey', 'org', 'a\u001fb'], ['scopeKey', 'org', '😀']]],
  ['not-durable', [['new', false], ['admit', { ids: { principal: 'alice' }, accumulators: [spend()], event: ev('a', 10), allow: true }], ['admit', { ids: {}, accumulators: [{ ...spend(), scope: 'session' }], event: ev('a', 10), allow: true }], ['snapshot', K]]],
  ['admit', [['new', true], ['admit', { ids: { principal: 'alice' }, accumulators: [spend()], event: ev('a', 150), allow: true }], ['admit', { ids: { principal: 'alice' }, accumulators: [spend()], event: ev('b', 60), allow: true }], ['admit', { ids: { principal: 'alice' }, accumulators: [spend()], event: ev('c', 60), allow: false }], ['admit', { ids: {}, accumulators: [spend()], event: ev('d', 1), allow: true }], ['admit', { ids: { principal: 'alice', org: 'acme' }, accumulators: [spend(), countAcc({ id: 'orgn', scope: 'org', domain_max: 1 })], event: ev('e', 10), allow: true }], ['admit', { ids: { principal: 'alice', org: 'acme' }, accumulators: [spend(), countAcc({ id: 'orgn', scope: 'org', domain_max: 1 })], event: ev('f', 10), allow: true }], ['snapshot', K], ['snapshot', 'org/acme'], ['admit', { ids: { principal: 'alice' }, accumulators: [spend()], event: ev('a', 150), allow: true }], ['startAgg', [{ key: K, id: 'a' }]], ['settleAgg', [{ key: K, id: 'a' }], 'committed'], ['settleAgg', [{ key: K, id: 'e' }], 'released']]],
];
for (let seed = 1; seed <= 50; seed++) {
  const r = rng(0xbd9e70 + seed);
  const ops: any[] = [['new', r.next() < 0.7]];
  const keys = ['principal/alice', 'principal/bob'];
  let n = 0;
  const live: string[] = [];
  for (let i = 0; i < 35; i++) {
    const key = r.pick(keys);
    const kind = r.pick(['reserve', 'reserve', 'reserve', 'start', 'commit', 'release', 'expire', 'snapshot', 'reserve-exp']);
    const id = live.length && r.next() < 0.8 ? r.pick(live) : `ghost${i}`;
    if (kind === 'reserve' || kind === 'reserve-exp') {
      const eid = r.next() < 0.15 && live.length ? r.pick(live) : `e${seed}-${n++}`;
      const amount = r.pick([10, 30, 50, 80, 120, 1]);
      ops.push(['reserve', key, rq(eid, amount, { ...(kind === 'reserve-exp' ? { expiresAt: r.int(10, 60) } : {}), ...(r.next() < 0.2 ? { expectedVersion: r.int(0, 6) } : {}) })]);
      live.push(eid);
    } else if (kind === 'start') ops.push(['start', key, id]);
    else if (kind === 'commit') ops.push(['commit', key, id]);
    else if (kind === 'release') ops.push(['release', key, id, null]);
    else if (kind === 'expire') ops.push(['expire', key, r.int(5, 80)]);
    else ops.push(['snapshot', key]);
  }
  budgetCases.push([`walk${seed}`, ops]);
}
for (const [name, ops] of budgetCases) await o.run('budgetLedger', name, budgetRun, [ops]);
// signed release: record bytes and anchoring, computed on the reference
{
  const rel = G.signRelease({ key: K, id: 'a', reason: 'effect_failed', at: 1234 }, rkey);
  const bad = { ...rel, reason: 'rollback' };
  const rel2 = G.signRelease({ key: K, id: 'a', reason: 'rollback', at: 1 }, rkey);
  await o.run('budgetLedger', 'release-verify', budgetRun, [[
    ['signRelease', K, 'a', 'effect_failed', 1234], ['verifyRelease', rel, 'signer'], ['verifyRelease', bad, 'signer'], ['verifyRelease', rel, 'someone-else'], ['verifyRelease', { ...rel, sig: 'AAAA' }, 'signer'], ['verifyRelease', { ...rel, extra: 1 }, 'signer'], ['verifyRelease', { ...rel, v: 2 }, 'signer'], ['verifyRelease', null, 'signer'],
    ['releaseCommit', rel], ['releaseCommit', rel2], ['anchor', rel], ['anchor', rel], ['anchor', rel2],
    ['new', true], ['reserve', K, rq('a', 10)], ['release', K, 'a', rel2], ['release', K, 'a', rel2], ['reserve', K, rq('b', 10)], ['release', K, 'b', rel], ['snapshot', K],
  ]]);
}

// ---------------------------------------------------------------- mesh witness
const cap = (label: string) => ({ id: label, caveats: [{ type: 'scope', actions: [label] }] });
async function meshRun(ops: any[]): Promise<any[]> {
  const stores = new Map<string, any>();
  const witnesses = new Map<string, any>();
  const domains = new Map<string, any>();
  const out: any[] = [];
  for (const op of ops) {
    out.push(
      await step(async () => {
        switch (op[0]) {
          case 'store': stores.set(op[1], new M.MemoryMeshWitnessStore()); return true;
          case 'witness': witnesses.set(op[1], new M.MeshWitness(seedOf(op[3]), op[2] ? { store: stores.get(op[2]) } : {})); return witnesses.get(op[1]).id;
          case 'witnessClock': witnesses.set(op[1], new M.MeshWitness(seedOf(op[2]), { clock: () => op[3], ...(op[4] !== null ? { maxClockSkewMs: op[4] } : {}) })); return true;
          case 'restart': witnesses.set(op[1], new M.MeshWitness(seedOf(op[3]), { store: stores.get(op[2]) })); return witnesses.get(op[1]).exportState();
          case 'domain': domains.set(op[1], new M.MeshDomain(op[1], seedOf(op[2]))); return domains.get(op[1]).id;
          case 'record': return domains.get(op[1]).record(cap(op[2]));
          case 'revoke': return void domains.get(op[1]).revoke(op[2]);
          case 'publish': return await domains.get(op[1]).publishHead(op[3].map((w: string) => witnesses.get(w)), op[2], op[4] === null ? {} : { threshold: op[4] });
          case 'lastSeen': return witnesses.get(op[1]).lastSeen(op[2]) ?? null;
          case 'export': return witnesses.get(op[1]).exportState();
          case 'import': return void witnesses.get(op[1]).importState(op[2]);
          case 'load': return stores.get(op[1]).load() ?? null;
          case 'save': return void stores.get(op[1]).save(op[2]);
          case 'domainId': return domains.get(op[1]).id;
        }
        throw new Error('op');
      }, true),
    );
  }
  return out;
}
const meshCases: Array<[string, any[]]> = [
  ['store-roundtrip', [['store', 'S'], ['load', 'S'], ['save', 'S', { seen: [{ head: { domain: 'd1', size: 0, root: '', rev_root: 'r', rev_size: 0, timestamp: 1 }, rev_ids: [] }] }], ['load', 'S'], ['save', 'S', { seen: [] }], ['load', 'S']]],
  ['persist-every-cosig', [['store', 'S'], ['witness', 'W', 'S', 'w'], ['domain', 'D', 'd'], ['record', 'D', 'a'], ['publish', 'D', 1000, ['W'], null], ['load', 'S'], ['export', 'W'], ['record', 'D', 'b'], ['publish', 'D', 2000, ['W'], null], ['load', 'S'], ['lastSeen', 'W', 'x'], ['restart', 'W2', 'S', 'w']]],
  ['rollback-fork', [['store', 'S'], ['witness', 'W', 'S', 'w'], ['domain', 'D', 'd'], ['domain', 'F', 'd'], ['record', 'D', 'a'], ['record', 'F', 'x'], ['publish', 'D', 1000, ['W'], null], ['record', 'D', 'b'], ['publish', 'D', 2000, ['W'], null], ['restart', 'W2', 'S', 'w'], ['record', 'F', 'y'], ['record', 'F', 'z'], ['publish', 'F', 3000, ['W2'], null], ['domain', 'R', 'd'], ['record', 'R', 'a'], ['publish', 'R', 3000, ['W2'], null], ['publish', 'D', 3000, ['W2'], null]]],
  ['revocations', [['witness', 'W', null, 'w'], ['domain', 'D', 'd'], ['record', 'D', 'a'], ['revoke', 'D', 'cap1'], ['publish', 'D', 1, ['W'], null], ['revoke', 'D', 'cap0'], ['publish', 'D', 2, ['W'], null], ['publish', 'D', 2, ['W'], null], ['publish', 'D', 1, ['W'], null], ['export', 'W']]],
  ['threshold', [['witness', 'W1', null, 'w1'], ['witness', 'W2', null, 'w2'], ['domain', 'D', 'd'], ['record', 'D', 'a'], ['publish', 'D', 10, ['W1'], null], ['record', 'D', 'b'], ['publish', 'D', 5, ['W1', 'W2'], null], ['publish', 'D', 5, ['W1', 'W2'], 1], ['publish', 'D', 20, ['W1', 'W2'], null], ['publish', 'D', 20, [], null], ['publish', 'D', 20, [], 0]]],
  ['clock', [['witnessClock', 'W', 'w', 1000, null], ['domain', 'D', 'd'], ['record', 'D', 'a'], ['publish', 'D', 1000, ['W'], null], ['publish', 'D', 61000, ['W'], null], ['publish', 'D', 61001, ['W'], null], ['witnessClock', 'W2', 'w', 1000, 5], ['publish', 'D', 1006, ['W2'], null], ['publish', 'D', 1005, ['W2'], null]]],
  ['malformed-state', [['witness', 'W', null, 'w'], ['import', 'W', { seen: [{ head: { domain: 'd', size: 1, root: '', rev_root: 'r', rev_size: 0, timestamp: 1 }, rev_ids: [] }] }], ['import', 'W', { seen: [{ head: { domain: 'd', size: 0, root: '', rev_root: 'bad', rev_size: 0, timestamp: 1 }, rev_ids: [] }] }], ['import', 'W', { seen: [{ head: { domain: 'd', size: 0, root: '', rev_root: 'x', rev_size: 0, timestamp: 1 }, rev_ids: [1] }] }], ['import', 'W', { seen: [] }], ['export', 'W']]],
  ['two-domains-sorted', [['witness', 'W', null, 'w'], ['domain', 'Z', 'zz'], ['domain', 'A', 'aa'], ['record', 'Z', 'a'], ['record', 'A', 'b'], ['publish', 'Z', 1, ['W'], null], ['publish', 'A', 1, ['W'], null], ['export', 'W']]],
  ['growth', [['witness', 'W', null, 'w'], ['domain', 'D', 'd'], ...Array.from({ length: 20 }, (_, i) => [['record', 'D', `c${i}`], ...(i % 3 === 0 ? [['publish', 'D', 100 + i, ['W'], null]] : [])]).flat(), ['publish', 'D', 200, ['W'], null], ['lastSeen', 'W', 'x']]],
];
for (const [name, ops] of meshCases) await o.run('meshWitness', name, meshRun, [ops]);

refWrite(o, 'core-stores-java');
