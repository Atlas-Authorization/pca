// Oracle: StoredLedger (ledger-store.ts) with post-quantum and hybrid checkpoint suites, TS reference. Written for the Java lane
// (StoredLedger.Options.suite / .pin); reusable by any native. Every case starts from a stored document the REFERENCE signed (hybrid, pure
// ML-DSA, a mix with Ed25519 checkpoints, or tampered), then reopens it under different pin / suite settings. Natives never need to reproduce
// PQ signature bytes: a checkpoint written after a reopen is summarised ({size, alg, pq}), not compared byte for byte.
//
// PORTING (net.atlasauth.pca StoredLedger): storedLedgerPq(pins, ops) -> one result per op over ONE shared memory store
//   pins = {good: {<guardian ed25519 b64u>: <ML-DSA-65 pk>}, wrong: {...}} (the reference's pin.pqPins)
//   guardian Ed25519 seed "stored-ledger-guardian"; ML-DSA-65 seed = 32 bytes of 0x07 (xi); instance "inst", principal "pr";
//   clock = 1_800_000_000_000 + 1000 * calls.
//   ["kvSet", doc]                       replace the stored document (the reference's raw doc)
//   ["open", H, {suite?: "hybrid"|"ml", pin?: "good"|"wrong"}] -> {size, guardian}; suite "hybrid" = hybrid-ed25519-ml-dsa-65, "ml" = ml-dsa-65 (no Ed25519 half)
//   [H, "append", commit] -> {index, commit};  [H, "checkpoint"] -> {size, alg|null, pq: bool, root, prev_root};  [H, "latest"] -> the checkpoint or null
//   [H, "chain"] -> [checkpoints];  [H, "head"] -> {size, root};  [H, "size"]
//   an op that throws records {"$err": code} (LedgerStoreError code, "Error" otherwise).
import { Oracle, refWrite, seed } from './lib.mjs';
import * as PCA0 from '@atlasauth/pca';

const P: any = (PCA0 as any).default ?? PCA0;
const { publicKeyOf, encodeKey, mlDsa65Keygen, encodeMlDsaPublicKey } = P;
const { createMemoryDurableKv } = await import('../../../packages/pca/src/durable-state.ts');
const L: any = await import('../../../packages/pca/src/ledger-store.ts');

const o = new Oracle('core-stored-ledger-pq-java', 'tools/pca-audit/oracles/core-stored-ledger-pq-java.mts', 'TS-reference oracle for StoredLedger post-quantum and hybrid checkpoint suites.');
const GS = seed('stored-ledger-guardian');
const GPK = encodeKey(publicKeyOf(GS));
const ml = mlDsa65Keygen(new Uint8Array(32).fill(7));
const mlWrong = mlDsa65Keygen(new Uint8Array(32).fill(9));
const pins = { good: { [GPK]: encodeMlDsaPublicKey(ml.publicKey) }, wrong: { [GPK]: encodeMlDsaPublicKey(mlWrong.publicKey) } };
const suiteOf = (m: any) => (m === 'hybrid' ? { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml } : m === 'ml' ? { alg: 'ml-dsa-65', mlDsa: ml } : undefined);
const pinOf = (m: any) => (m === 'good' ? { pqPins: pins.good } : m === 'wrong' ? { pqPins: pins.wrong } : undefined);
const errName = (e: any): string => (typeof e?.code === 'string' ? e.code : 'Error');
const KEY = 'pca-ledger-store/v1';

async function run(pn: any, ops: any[]): Promise<any[]> {
  const kv = createMemoryDurableKv();
  const store = new L.KvLedgerStore(kv);
  const hs = new Map<string, any>();
  let calls = 0;
  const clock = () => 1_800_000_000_000 + 1000 * calls++;
  const out: any[] = [];
  for (const op of ops) {
    try {
      let v: any = null;
      if (op[0] === 'kvSet') await kv.set(KEY, op[1]);
      else if (op[0] === 'open') {
        const c = op[2] ?? {};
        const h = await L.StoredLedger.open({ store, guardianSecret: GS, instanceId: 'inst', principal: 'pr', clock, suite: suiteOf(c.suite), pin: pinOf(c.pin) });
        hs.set(op[1], h);
        v = { size: h.size, guardian: h.guardian };
      } else {
        const h = hs.get(op[0]);
        switch (op[1]) {
          case 'append': v = await h.append(op[2]); break;
          case 'checkpoint': { const s = await h.checkpoint(); v = { size: s.size, alg: s.alg ?? null, pq: s.pq_sig !== undefined, root: s.root, prev_root: s.prev_root }; break; }
          case 'latest': v = h.latestCheckpoint() ?? null; break;
          case 'chain': v = h.checkpointChain(); break;
          case 'head': v = h.head(); break;
          case 'size': v = h.size; break;
          default: throw new Error('op');
        }
      }
      out.push(v === undefined ? null : JSON.parse(JSON.stringify(v)));
    } catch (e) {
      out.push({ $err: errName(e) });
    }
  }
  return out;
}

// build reference-signed documents
async function build(steps: Array<{ suite?: string; pin?: string; n: number }>): Promise<any> {
  const kv = createMemoryDurableKv();
  const store = new L.KvLedgerStore(kv);
  let i = 0, t = 1_800_000_000_000;
  for (const st of steps) {
    const h = await L.StoredLedger.open({ store, guardianSecret: GS, instanceId: 'inst', principal: 'pr', clock: () => (t += 1000), suite: suiteOf(st.suite), pin: pinOf(st.pin) });
    for (let k = 0; k < st.n; k++) await h.append(`entry${i++}`);
    await h.checkpoint();
  }
  return JSON.parse(JSON.stringify(await kv.get(KEY)));
}
const DOCS: Record<string, any> = {
  hybrid: await build([{ suite: 'hybrid', pin: 'good', n: 3 }, { suite: 'hybrid', pin: 'good', n: 3 }, { suite: 'hybrid', pin: 'good', n: 2 }]),
  pure: await build([{ suite: 'ml', pin: 'good', n: 2 }, { suite: 'ml', pin: 'good', n: 4 }]),
  mixed: await build([{ n: 2 }, { suite: 'hybrid', pin: 'good', n: 2 }, { n: 1, pin: 'good' }]),
  ed: await build([{ n: 2 }, { n: 3 }]),
  single: await build([{ suite: 'hybrid', pin: 'good', n: 1 }]),
};
const flip = (s?: string) => (s === undefined ? 'AAAA' : (s[0] === 'A' ? 'B' : 'A') + s.slice(1));
const edit = (doc: any, f: (d: any) => void) => { const d = JSON.parse(JSON.stringify(doc)); f(d); return d; };
const TAMPER: Array<[string, (d: any) => void]> = [
  ['pq_sig-flip', (d) => { d.checkpoints[1].sth.pq_sig = flip(d.checkpoints[1].sth.pq_sig); }],
  ['pq_sig-flip-last', (d) => { const c = d.checkpoints[d.checkpoints.length - 1].sth; c.pq_sig = flip(c.pq_sig); }],
  ['pq_sig-drop', (d) => { delete d.checkpoints[1].sth.pq_sig; }],
  ['pq_pk-wrong', (d) => { d.checkpoints[1].sth.pq_pk = encodeMlDsaPublicKey(mlWrong.publicKey); }],
  ['pq_pk-drop', (d) => { delete d.checkpoints[1].sth.pq_pk; }],
  ['alg-drop', (d) => { delete d.checkpoints[1].sth.alg; }],
  ['alg-ed', (d) => { d.checkpoints[1].sth.alg = 'ed25519'; }],
  ['alg-unknown', (d) => { d.checkpoints[1].sth.alg = 'rot13'; }],
  ['alg-ml', (d) => { d.checkpoints[1].sth.alg = 'ml-dsa-65'; }],
  ['sig-flip', (d) => { d.checkpoints[1].sth.sig = flip(d.checkpoints[1].sth.sig); }],
  ['root-edit', (d) => { d.checkpoints[0].sth.root = d.checkpoints[1].sth.root; }],
  ['size-edit', (d) => { d.checkpoints[1].sth.size += 1; }],
  ['guardian-edit', (d) => { d.checkpoints[1].sth.guardian = 'AAAA'; }],
  ['swap-cps', (d) => { const [a, b] = [d.checkpoints[0], d.checkpoints[1]]; d.checkpoints[0] = b; d.checkpoints[1] = a; }],
  ['commit-edit', (d) => { d.commits[1] = 'tampered'; }],
  ['truncate', (d) => { d.commits.length = 3; }],
];
const open = (H: string, c: any = {}) => ['open', H, c];
const reads = (H: string) => [[H, 'size'], [H, 'head'], [H, 'latest'], [H, 'chain']];
const opens = (): any[] => [open('A'), open('B', { pin: 'good' }), ...reads('B'), open('C', { pin: 'wrong' }), open('D', { suite: 'hybrid' }), open('D2', { suite: 'ml' }), open('E', { suite: 'hybrid', pin: 'good' }), ...reads('E'), open('F', { suite: 'ml', pin: 'good' }), open('G', { suite: 'hybrid', pin: 'wrong' })];
let n = 0;
const add = (name: string, ops: any[]) => o.run('storedLedgerPq', `c${n++}/${name}`, run, [pins, ops]);
for (const [dn, doc] of Object.entries(DOCS)) {
  await add(`${dn}/opens`, [['kvSet', doc], ...opens()]);
  await add(`${dn}/hybrid-continue`, [['kvSet', doc], open('H', { suite: 'hybrid', pin: 'good' }), ['H', 'append', 'x1'], ['H', 'append', 'x2'], ['H', 'checkpoint'], ['H', 'checkpoint'], ['H', 'append', 'x3'], ['H', 'checkpoint'], ...reads('H'), open('I', { pin: 'good' }), ...reads('I')]);
  await add(`${dn}/pure-continue`, [['kvSet', doc], open('H', { suite: 'ml', pin: 'good' }), ['H', 'append', 'y1'], ['H', 'checkpoint'], open('I', { suite: 'ml', pin: 'good' }), ...reads('I'), open('J', { suite: 'hybrid', pin: 'good' }), ['J', 'append', 'y2'], ['J', 'checkpoint']]);
  await add(`${dn}/ed-continue`, [['kvSet', doc], open('H', { pin: 'good' }), ['H', 'append', 'z1'], ['H', 'checkpoint'], ...reads('H'), open('I'), ['I', 'size']]);
  await add(`${dn}/wrong-pin-sign`, [['kvSet', doc], open('H', { suite: 'hybrid', pin: 'wrong' }), ['H', 'append', 'w1'], ['H', 'checkpoint'], ['H', 'size'], open('I', { pin: 'good' }), ['I', 'size']]);
}
await add('empty/pin-missing', [open('A', { suite: 'hybrid' }), open('B', { suite: 'ml' }), open('C', { suite: 'hybrid', pin: 'good' }), ['C', 'append', 'a'], ['C', 'checkpoint'], ['C', 'checkpoint'], ['C', 'latest'].slice(0, 2), open('D', { pin: 'good' }), ...reads('D'), open('E', { pin: 'wrong' }), open('F')]);
await add('empty/ed25519-no-pin', [open('A'), ['A', 'append', 'a'], ['A', 'checkpoint'], open('B'), ['B', 'latest']]);
await add('empty/pure-then-hybrid', [open('A', { suite: 'ml', pin: 'good' }), ['A', 'append', 'a'], ['A', 'checkpoint'], open('B', { suite: 'hybrid', pin: 'good' }), ['B', 'append', 'b'], ['B', 'checkpoint'], open('C', { pin: 'good' }), ...reads('C'), open('D'), open('E', { pin: 'wrong' })]);
for (const dn of ['hybrid', 'pure']) for (const [tn, f] of TAMPER) {
  const doc = edit(DOCS[dn], f);
  await add(`tamper/${dn}/${tn}`, [['kvSet', doc], open('A', { pin: 'good' }), open('B', { suite: dn === 'pure' ? 'ml' : 'hybrid', pin: 'good' }), open('C'), open('D', { pin: 'wrong' })]);
}
for (const [tn, f] of TAMPER.slice(0, 6)) await add(`tamper/mixed/${tn}`, [['kvSet', edit(DOCS.mixed, f)], open('A', { pin: 'good' }), open('B')]);
refWrite(o, 'core-stored-ledger-pq-java');
