// Oracle: the ISSUING side of mesh.ts (domain / witness lifecycle, the worked example, latency and size models) and the whole A2A
// FEDERATION half (cross-domain capability translation, federated budget tree, cross-reference commitments). The verifier side (verifyMeshProof,
// checkHeadAdvance, effectiveAuthority) is replayed from base-mesh / mesh-vectors.json; assembleMeshProof / signMeshAction and the MeshDomain
// enroll / evidence / pinProof / MeshWitness basics from ref-core-mesh-proof-java / ref-core-mesh-domain-java / the core-stores meshWitness section.
// This corpus covers every other exported name of mesh.ts and widens the witness / domain scripts.
// Deterministic: Ed25519 and ML-DSA-65 signing are deterministic. Secrets appear ONLY as seed labels: a {"$seed": "<label>"} value is the 32 bytes
// sha256("atlas-pca-conformance/" + label). In a meshIssue script the op label X is a seed label too, with the prefix by op: "domain" ops use
// "mesh-issue/d/X", "witness" / "witnessOpts" / "restart" ops use "mesh-issue/w/X" (so the script's seedLabel argument is the X after that prefix).
// A reference throw is {"$throws": message} for a plain function and {"$err": message} for one op of a script: the native must throw / refuse
// (a message is informative; compare it where the native's refusals use the same text).
// PORTING (fn(args) -> native entry point; compared by JSON value):
//   constants() -> {DEFAULT_MAX_HEAD_AGE_MS, DEFAULT_MAX_CLOCK_SKEW_MS, DEFAULT_MAX_CHAIN_LENGTH}
//   keyRevocationId(agentPublic) -> "key:" + agentPublic (JavaScript string coercion for a non-string)
//   effectiveAuthority(caveats) -> EffectiveAuthority | {error}
//   meshProofSize(proof) -> {total_bytes, chain_bytes, heads_bytes, rev_leaves_bytes, hops_bytes, uncompacted_bytes} (byte lengths of the canonical JSON) | {$throws}
//   revocationLatencyBound(p) -> {published_ms, unpinned_ms, pinned_ms, honest_provers_viable}   Infinity is {"$num": "Infinity"}
//   buildMeshExample(now) -> {trust, proof, evidence, chain, heads, bindings, domains: {A,B,C ids}, witnesses: [ids]} (no keys). NOTE the example's seed
//       keys are utf8(hashCanonical({seed: "atlas-pca/mesh-example/<label>"})).slice(0, 32): the first 32 BYTES OF THE HEX STRING, not a decoded digest.
//   demonstrateForkRejection() -> ForkDemo
//   meshIssue(ops) -> one result per op (script ops below)
//   translateCapability(chain, {fromGuardian, toGuardian, additionalCaveats?, bridgeSecret: {$seed}, issued_at, pqPins?}) -> TranslatedCapability | {$throws}
//   translatedEffectiveAuthority(tc) / verifyTranslatedCapability(tc, opts) -> EffectiveAuthority | {error} / TranslatedVerdict
//   createFederatedBudget(args) / allocateSub(state, args) / spendFederated(state, nodeId, c) -> {ok, state} | {ok:false, reason}; federatedSafetyBound(p) -> number
//   meshActionDigest(action) / crossReferenceCommit(x) -> string (throws on an unhashable value)
//   anchorCrossReference({$seed}, commit, seq) -> DomainAnchor;  verifyCrossReference(x, anchors) -> CrossRefVerdict
// SCRIPT OPS (state per case; names are scoped to the case; every op's result is one array element):
//   ["domain", D, label] -> id    ["witness", W, label] -> id    ["witnessOpts", W, label, {store: S|null, clock: ms|null, skew: ms|null}] -> id
//   ["store", S] -> true    ["failStore", S, failAfterSaves] -> true (a store whose save throws once that many saves happened)    ["storeLoad", S] -> state | undefined
//   ["record", D, label] -> index    ["revoke", D, id] -> null    ["publish", D, H, ts, [W..], threshold|null] -> the cosigned head (kept as H)
//   ["fork", H2, H, field, value] -> null (a copy of head H with one top-level member replaced)    ["forkHead", H2, H, field, value] -> null (same inside H.head)
//   ["cosign", W, H, consistency, revIds] -> the cosignature; consistency: null | "domain" (the domain's own proof from W's last-seen head) | a literal {oldSize,newSize,path}; revIds: "domain" | [..]
//   ["lastSeen", W, domainId|D] -> head | null    ["export", W] -> state    ["import", W, state | {"$export": W2}] -> null    ["restart", W, S, label] -> the new witness's exported state
//   ["consistency", D, oldSize, newSize|null] -> the proof    ["enroll", D, B, agent, role] -> binding    ["evidence", D, label, H, B|null] -> evidence
import * as M from '../../../packages/pca/src/mesh.ts';
import * as CAP0 from '../../../packages/pca/src/capability.ts';
import * as K0 from '../../../packages/pca/src/keys.ts';
import * as PQ0 from '../../../packages/pca/src/pq.ts';
import { Oracle, refWrite, seed, jsonOut, ser } from './lib.mjs';

const MM: any = (M as any).default ?? M;
const CAP: any = (CAP0 as any).mintRoot ? CAP0 : (CAP0 as any).default;
const K: any = (K0 as any).publicKeyOf ? K0 : (K0 as any).default;
const PQ: any = (PQ0 as any).mlDsa65Keygen ? PQ0 : (PQ0 as any).default;
const o = new Oracle('mesh-issue', 'tools/pca-audit/oracles/mesh-issue.mts', 'TS-reference oracle for the mesh issuing side and the A2A federation primitives.');
const uniq = (fn: string, name: string) => { let nm = name; for (let i = 2; o.names.has(`${fn}/${nm}`); i++) nm = `${name} #${i}`; return nm; };
const sd = (l: string) => seed('mesh-issue/' + l);
const un = (v: any): any => {
  if (Array.isArray(v)) return v.map(un);
  if (v !== null && typeof v === 'object') {
    if (typeof v.$seed === 'string' && Object.keys(v).length === 1) return seed(v.$seed);
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, un(x)]));
  }
  return v;
};
const S = (l: string) => ({ $seed: 'mesh-issue/' + l });
const run = (fn: string, name: string, f: (...a: any[]) => any, args: any[]) => {
  try { ser(args); } catch { return Promise.resolve(false); }
  return o.run(fn, uniq(fn, name), (...a: any[]) => f(...un(a)), args);
};
const pub = (l: string) => K.encodeKey(K.publicKeyOf(sd(l)));
const NOW = 1_800_000_000_000;

// ---------------------------------------------------------------------------------------------------------------- constants, keyRevocationId
await run('constants', 'defaults', () => ({ DEFAULT_MAX_HEAD_AGE_MS: MM.DEFAULT_MAX_HEAD_AGE_MS, DEFAULT_MAX_CLOCK_SKEW_MS: MM.DEFAULT_MAX_CLOCK_SKEW_MS, DEFAULT_MAX_CHAIN_LENGTH: MM.DEFAULT_MAX_CHAIN_LENGTH }), []);
for (const [i, v] of ['', 'abc', pub('a'), 'é', '\u{1F600}', 'a b', 'key:x', ' ', 'a'.repeat(300), 5, null, true, ['x']].entries()) await run('keyRevocationId', `v#${i}`, MM.keyRevocationId, [v]);

// ---------------------------------------------------------------------------------------------------------------- effectiveAuthority
const EA: Array<[string, unknown]> = [
  ['empty', []], ['scope', [{ type: 'scope', actions: ['b', 'a'] }]], ['scope intersect', [{ type: 'scope', actions: ['b', 'a', 'c'] }, { type: 'scope', actions: ['c', 'a', 'z'] }]], ['scope dup', [{ type: 'scope', actions: ['a', 'a', 'b'] }]],
  ['scope empty', [{ type: 'scope', actions: [] }]], ['scope disjoint', [{ type: 'scope', actions: ['a'] }, { type: 'scope', actions: ['b'] }]], ['scope non-array', [{ type: 'scope', actions: 'a' }]], ['scope junk', [{ type: 'scope', actions: ['a', 1] }]],
  ['resource', [{ type: 'resource', prefix: '/x' }, { type: 'resource', prefix: '/x/y' }]], ['resource empty prefix', [{ type: 'resource', prefix: '' }]], ['resource bad', [{ type: 'resource', prefix: 5 }]],
  ['max_amount min', [{ type: 'max_amount', max: 50 }, { type: 'max_amount', max: 20 }, { type: 'max_amount', max: 30 }]], ['max_amount neg', [{ type: 'max_amount', max: -5 }]], ['max_amount bad', [{ type: 'max_amount', max: '5' }]], ['max_amount null', [{ type: 'max_amount', max: null }]],
  ['expires min', [{ type: 'expires', at: 200 }, { type: 'expires', at: 100 }]], ['expires bad', [{ type: 'expires' }]], ['audience', [{ type: 'audience', domains: ['d1', 'd2'] }, { type: 'audience', domains: ['d2', 'd3'] }]], ['audience bad', [{ type: 'audience', domains: 'd' }]],
  ['max_hops', [{ type: 'max_hops', n: 5 }, { type: 'max_hops', n: 3 }]], ['max_hops bad', [{ type: 'max_hops', n: 'x' }]], ['max_hops zero', [{ type: 'max_hops', n: 0 }]],
  ['unknown type', [{ type: 'weird' }]], ['unknown after valid', [{ type: 'scope', actions: ['a'] }, { type: 'weird' }]], ['malformed before unknown', [{ type: 'scope', actions: 1 }, { type: 'weird' }]],
  ['all six', [{ type: 'scope', actions: ['a'] }, { type: 'resource', prefix: '/p' }, { type: 'max_amount', max: 9 }, { type: 'expires', at: 7 }, { type: 'audience', domains: ['d'] }, { type: 'max_hops', n: 2 }]],
  ['order of unicode', [{ type: 'scope', actions: ['é', 'z', 'a', '\u{1F600}', '～'] }]], ['first scope sorted', [{ type: 'scope', actions: ['b', 'a', 'b'] }, { type: 'resource', prefix: '/' }]],
  ['not an array', {}], ['null entry', [null]], ['string entry', ['scope']], ['no type', [{}]], ['type number', [{ type: 5 }]],
];
for (const [nm, c] of EA) await run('effectiveAuthority', nm, MM.effectiveAuthority, [c]);

// ---------------------------------------------------------------------------------------------------------------- the worked example
const exampleOut = (now: number) => {
  const ex = MM.buildMeshExample(now);
  return { trust: ex.trust, proof: ex.proof, evidence: ex.evidence, chain: ex.chain, heads: ex.heads, bindings: ex.bindings, domains: { A: ex.domains.A.id, B: ex.domains.B.id, C: ex.domains.C.id }, witnesses: ex.witnesses.map((w: any) => w.id) };
};
await run('buildMeshExample', 'default now', (now?: number) => exampleOut(now === null ? undefined as any : now), [null]);
for (const now of [NOW, 1_000_000_000_000, 1_900_000_000_123, 5_000]) await run('buildMeshExample', `now ${now}`, exampleOut, [now]);
await run('demonstrateForkRejection', 'demo', MM.demonstrateForkRejection, []);

const EXP = MM.buildMeshExample(NOW);
const baseProof = JSON.parse(ser(EXP.proof));
// ---------------------------------------------------------------------------------------------------------------- meshProofSize
const pz = (nm: string, p: unknown) => run('meshProofSize', nm, MM.meshProofSize, [p]);
await pz('example', baseProof);
{
  const c = (f: (p: any) => void) => { const p = JSON.parse(ser(baseProof)); f(p); return p; };
  await pz('no pin_proofs member', c((p) => { delete p.pin_proofs; }));
  await pz('with pin proofs', c((p) => { p.pin_proofs = [{ domain: 'd', proof: { oldSize: 1, newSize: 2, path: ['a'] } }]; }));
  await pz('one hop', c((p) => { p.hops = p.hops.slice(0, 1); p.chain = p.chain.slice(0, 1); }));
  await pz('no hops', c((p) => { p.hops = []; p.chain = []; p.heads = []; p.rev_leaves = []; }));
  await pz('leaf index out of range', c((p) => { p.hops[0].revocation.cap = { size: 3, lo: 999, hi: 998 }; }));
  await pz('leaf index negative', c((p) => { p.hops[0].revocation.cap = { size: 3, lo: -1 }; }));
  await pz('leaf index fraction', c((p) => { p.hops[0].revocation.cap = { size: 3, lo: 0.5 }; }));
  await pz('leaf index string', c((p) => { p.hops[0].revocation.cap = { size: 3, lo: '0' }; }));
  await pz('size only', c((p) => { p.hops[0].revocation.cap = { size: 0 }; p.hops[0].revocation.issuer_key = { size: 0 }; }));
  await pz('no rev_leaves', c((p) => { p.rev_leaves = []; }));
  await pz('head index out of range', c((p) => { p.hops[0].head = 99; }));
  await pz('head index missing', c((p) => { delete p.hops[0].head; }));
  await pz('hop revocation missing', c((p) => { delete p.hops[0].revocation; }));
  await pz('hop revocation cap missing', c((p) => { delete p.hops[0].revocation.cap; }));
  await pz('rev_leaves not array', c((p) => { p.rev_leaves = {}; }));
  await pz('hops not array', c((p) => { p.hops = {}; }));
  await pz('hops null', c((p) => { p.hops = null; }));
  await pz('chain null', c((p) => { p.chain = null; }));
  await pz('action unicode', c((p) => { p.action.resource = '/é/\u{1F600}'; }));
  await pz('action_sig missing', c((p) => { delete p.action_sig; }));
  await pz('action missing', c((p) => { delete p.action; }));
  await pz('heads duplicated', c((p) => { p.heads = [...p.heads, ...p.heads]; }));
  await pz('extra member', c((p) => { p.zz = [1, 2, 3]; }));
  for (const bad of [null, 5, 'x', [], {}, true]) await pz(`not a proof ${ser(bad)}`, bad);
}

// ---------------------------------------------------------------------------------------------------------------- revocationLatencyBound
{
  const nums: unknown[] = [0, 1, 1000, 59_999, 60_000, 300_000, 3_600_000, 1.5, -1, -0, 2 ** 53, 1e21, 1e308];
  let i = 0;
  for (const maxHeadAgeMs of [300_000, 60_000, 0, 1000]) for (const headIntervalMs of [10_000, 59_999, 60_000, 300_000, 0]) for (const maxClockSkewMs of [undefined, 0, 5_000, 60_000, 240_000]) for (const pinRefreshMs of [undefined, 0, 1000, 120_000, 10_000_000]) {
    const p: any = { maxHeadAgeMs, headIntervalMs };
    if (maxClockSkewMs !== undefined) p.maxClockSkewMs = maxClockSkewMs;
    if (pinRefreshMs !== undefined) p.pinRefreshMs = pinRefreshMs;
    if ((i++ % 3) === 0) await run('revocationLatencyBound', `grid ${ser(p)}`, MM.revocationLatencyBound, [p]);
  }
  for (const v of nums) for (const f of ['maxHeadAgeMs', 'headIntervalMs', 'maxClockSkewMs', 'pinRefreshMs']) {
    await run('revocationLatencyBound', `${f}=${ser(v)}`, MM.revocationLatencyBound, [{ maxHeadAgeMs: 300_000, headIntervalMs: 60_000, maxClockSkewMs: 1000, pinRefreshMs: 5000, [f]: v }]);
  }
  for (const f of ['maxHeadAgeMs', 'headIntervalMs']) await run('revocationLatencyBound', `${f} missing`, MM.revocationLatencyBound, [{ maxHeadAgeMs: 1, headIntervalMs: 1, [f]: undefined }]);
  for (const v of ['5', null, true, [], {}]) {
    await run('revocationLatencyBound', `maxHeadAgeMs=${ser(v)}`, MM.revocationLatencyBound, [{ maxHeadAgeMs: v, headIntervalMs: 1 }]);
    await run('revocationLatencyBound', `maxClockSkewMs=${ser(v)}`, MM.revocationLatencyBound, [{ maxHeadAgeMs: 10, headIntervalMs: 1, maxClockSkewMs: v }]);
    await run('revocationLatencyBound', `pinRefreshMs=${ser(v)}`, MM.revocationLatencyBound, [{ maxHeadAgeMs: 10, headIntervalMs: 1, pinRefreshMs: v }]);
  }
  for (const bad of [null, 5, 'x', [], {}]) await run('revocationLatencyBound', `not params ${ser(bad)}`, MM.revocationLatencyBound, [bad]);
}

// ---------------------------------------------------------------------------------------------------------------- the domain / witness script
const cap = (label: string) => ({ id: label, issuer: 'iss-' + label, holder: 'h', caveats: [{ type: 'scope', actions: [label] }] });
async function script(ops: any[]): Promise<any[]> {
  const doms = new Map<string, any>(), ws = new Map<string, any>(), heads = new Map<string, any>(), binds = new Map<string, any>(), evs = new Map<string, any>(), stores = new Map<string, any>();
  const out: any[] = [];
  const get = (m: Map<string, any>, k: string) => { if (!m.has(k)) throw new Error('unknown name ' + k); return m.get(k); };
  for (const op of ops) {
    try {
      let v: any = null;
      switch (op[0]) {
        case 'domain': { const d = new MM.MeshDomain(op[1], sd('d/' + op[2])); doms.set(op[1], d); v = d.id; break; }
        case 'witness': { const w = new MM.MeshWitness(sd('w/' + op[2])); ws.set(op[1], w); v = w.id; break; }
        case 'witnessOpts': {
          const x = op[3] ?? {};
          const opts: any = {};
          if (x.store) opts.store = get(stores, x.store);
          if (x.clock !== null && x.clock !== undefined) opts.clock = () => x.clock;
          if (x.skew !== null && x.skew !== undefined) opts.maxClockSkewMs = x.skew;
          const w = new MM.MeshWitness(sd('w/' + op[2]), opts); ws.set(op[1], w); v = w.id; break;
        }
        case 'store': stores.set(op[1], new MM.MemoryMeshWitnessStore()); v = true; break;
        case 'failStore': { const inner = new MM.MemoryMeshWitnessStore(); let saves = 0; stores.set(op[1], { load: () => inner.load(), save: (s: any) => { if (saves++ >= op[2]) throw new Error('disk'); inner.save(s); } }); v = true; break; }
        case 'storeLoad': v = get(stores, op[1]).load() ?? null; break;
        case 'record': v = get(doms, op[1]).record(cap(op[2])); break;
        case 'revoke': get(doms, op[1]).revoke(op[2]); break;
        case 'publish': { const h = get(doms, op[1]).publishHead(op[4].map((w: string) => get(ws, w)), op[3], op[5] === null ? {} : { threshold: op[5] }); heads.set(op[2], h); v = h; break; }
        case 'fork': heads.set(op[1], { ...get(heads, op[2]), [op[3]]: op[4] }); break;
        case 'forkHead': { const h = get(heads, op[2]); heads.set(op[1], { ...h, head: { ...h.head, [op[3]]: op[4] } }); break; }
        case 'cosign': {
          const w = get(ws, op[1]); const h = get(heads, op[2]);
          const d = [...doms.values()].find((x) => x.id === h.head?.domain);
          if (!d) throw new Error('no such domain');
          let consistency: any;
          if (op[3] === 'domain') { const prev = w.lastSeen(h.head.domain); consistency = prev ? d.consistencyProof(prev.size, h.head.size) : undefined; } else if (op[3] !== null) consistency = op[3];
          const rev_ids = op[4] === 'domain' ? d.rev.list() : op[4];
          v = w.cosign({ head: h, ...(consistency ? { consistency } : {}), rev_ids });
          break;
        }
        case 'lastSeen': { const id = doms.has(op[2]) ? doms.get(op[2]).id : op[2]; v = get(ws, op[1]).lastSeen(id) ?? null; break; }
        case 'export': v = get(ws, op[1]).exportState(); break;
        case 'import': get(ws, op[1]).importState(op[2] !== null && typeof op[2] === 'object' && '$export' in op[2] ? get(ws, op[2].$export).exportState() : op[2]); break;
        case 'restart': { const w = new MM.MeshWitness(sd('w/' + op[3]), { store: get(stores, op[2]) }); ws.set(op[1], w); v = w.exportState(); break; }
        case 'consistency': v = get(doms, op[1]).consistencyProof(op[2], op[3] === null ? undefined : op[3]); break;
        case 'enroll': { const b = get(doms, op[1]).enroll(op[3], op[4]); binds.set(op[2], b); v = b; break; }
        case 'evidence': { const e = get(doms, op[1]).evidence(cap(op[2]), get(heads, op[3]), op[4] === null ? undefined : get(binds, op[4])); evs.set(op[2] + '@' + op[3], e); v = e; break; }
        default: throw new Error('op');
      }
      out.push(jsonOut(v) ?? null);
    } catch (e) {
      out.push({ $err: e instanceof Error ? e.message : String(e) });
    }
  }
  return out;
}
const base = [['domain', 'A', 'a'], ['witness', 'W', 'w'], ['witness', 'W2', 'w2']];
const rec = (D: string, ...ls: string[]) => ls.map((l) => ['record', D, l]);
const SC: Array<[string, any[]]> = [
  ['publish-grows', [...base, ...rec('A', 'c0'), ['publish', 'A', 'H1', 1000, ['W', 'W2'], null], ...rec('A', 'c1', 'c2'), ['publish', 'A', 'H2', 2000, ['W', 'W2'], null], ['lastSeen', 'W', 'A'], ['lastSeen', 'W2', 'A'], ['lastSeen', 'W', 'nobody'], ['evidence', 'A', 'c1', 'H2', null]]],
  ['empty-log-head', [...base, ['publish', 'A', 'H0', 1, ['W'], null], ['lastSeen', 'W', 'A'], ...rec('A', 'c0'), ['publish', 'A', 'H1', 2, ['W'], null], ['consistency', 'A', 0, null], ['consistency', 'A', 1, null], ['consistency', 'A', 1, 1], ['consistency', 'A', 2, null], ['consistency', 'A', 1, 0]]],
  ['timestamp-regress', [...base, ...rec('A', 'c0'), ['publish', 'A', 'H1', 1000, ['W'], null], ['publish', 'A', 'H2', 999, ['W'], null], ['publish', 'A', 'H3', 1000, ['W'], null], ['publish', 'A', 'H4', 1001, ['W'], null]]],
  ['rollback', [...base, ...rec('A', 'c0', 'c1'), ['publish', 'A', 'H1', 1, ['W'], null], ['cosign', 'W', 'H1', null, 'domain'], ['domain', 'A2', 'a'], ['publish', 'A2', 'Hshort', 2, ['W'], null], ['lastSeen', 'W', 'A']]],
  ['fork-same-size', [...base, ...rec('A', 'c0', 'c1'), ['publish', 'A', 'H1', 1, ['W'], null], ['domain', 'F', 'a'], ...rec('F', 'x0', 'x1'), ['publish', 'F', 'HF', 2, ['W'], null]]],
  ['fork-grown', [...base, ...rec('A', 'c0', 'c1'), ['publish', 'A', 'H1', 1, ['W'], null], ['domain', 'F', 'a'], ...rec('F', 'x0', 'c1', 'x2'), ['publish', 'F', 'HF', 2, ['W'], null], ['lastSeen', 'W', 'A']]],
  ['revocation-superset', [...base, ...rec('A', 'c0'), ['revoke', 'A', 'r1'], ['publish', 'A', 'H1', 1, ['W'], null], ['revoke', 'A', 'r2'], ['publish', 'A', 'H2', 2, ['W'], null], ['cosign', 'W', 'H2', 'domain', ['r2']], ['cosign', 'W', 'H2', 'domain', ['r1', 'r2']], ['lastSeen', 'W', 'A']]],
  ['revocation-list-mismatch', [...base, ...rec('A', 'c0'), ['revoke', 'A', 'r1'], ['publish', 'A', 'H1', 1, ['W'], null], ['cosign', 'W2', 'H1', null, []], ['cosign', 'W2', 'H1', null, ['r1', 'extra']], ['cosign', 'W2', 'H1', null, ['r1']], ['cosign', 'W2', 'H1', null, [5]], ['cosign', 'W2', 'H1', null, 'x']]],
  ['malformed-head', [...base, ...rec('A', 'c0'), ['publish', 'A', 'H1', 1, ['W'], null], ['fork', 'X1', 'H1', 'sig', 'AAAA'], ['cosign', 'W2', 'X1', null, 'domain'], ['fork', 'X2', 'H1', 'sig', 5], ['cosign', 'W2', 'X2', null, 'domain'],
    ['forkHead', 'X3', 'H1', 'size', -1], ['cosign', 'W2', 'X3', null, 'domain'], ['forkHead', 'X4', 'H1', 'timestamp', '5'], ['cosign', 'W2', 'X4', null, 'domain'], ['forkHead', 'X5', 'H1', 'root', 5], ['cosign', 'W2', 'X5', null, 'domain'],
    ['forkHead', 'X6', 'H1', 'rev_size', 1.5], ['cosign', 'W2', 'X6', null, 'domain'], ['forkHead', 'X7', 'H1', 'domain', 'zz'], ['cosign', 'W2', 'X7', null, 'domain'], ['fork', 'X8', 'H1', 'head', null], ['cosign', 'W2', 'X8', null, 'domain'], ['cosign', 'W2', 'H1', null, 'domain']]],
  ['bad-consistency', [...base, ...rec('A', 'c0'), ['publish', 'A', 'H1', 1, ['W'], null], ...rec('A', 'c1', 'c2'), ['publish', 'A', 'H2', 2, ['W2'], null], ['cosign', 'W', 'H2', null, 'domain'], ['cosign', 'W', 'H2', { oldSize: 1, newSize: 3, path: [] }, 'domain'], ['cosign', 'W', 'H2', { oldSize: 2, newSize: 3, path: ['AAAA'] }, 'domain'], ['cosign', 'W', 'H2', 'domain', 'domain'], ['lastSeen', 'W', 'A']]],
  ['threshold', [...base, ...rec('A', 'c0'), ['publish', 'A', 'H1', 10, ['W', 'W2'], null], ...rec('A', 'c1'), ['publish', 'A', 'H2', 5, ['W', 'W2'], 0], ['publish', 'A', 'H3', 5, ['W', 'W2'], 1], ['publish', 'A', 'H4', 20, ['W', 'W2'], 2], ['publish', 'A', 'H5', 20, [], 0], ['publish', 'A', 'H6', 20, [], null]]],
  ['clock', [...base, ['witnessOpts', 'WC', 'wc', { store: null, clock: 10_000, skew: null }], ['witnessOpts', 'WS', 'ws', { store: null, clock: 10_000, skew: 500 }], ...rec('A', 'c0'),
    ['publish', 'A', 'Hok', 70_000, ['WC'], null], ['publish', 'A', 'Hfuture', 70_001, ['WC'], null], ['publish', 'A', 'Hs1', 10_500, ['WS'], null], ['publish', 'A', 'Hs2', 10_501, ['WS'], null], ['lastSeen', 'WC', 'A'], ['lastSeen', 'WS', 'A']]],
  ['store-restart', [...base, ['store', 'S'], ['witnessOpts', 'WP', 'wp', { store: 'S', clock: null, skew: null }], ...rec('A', 'c0'), ['publish', 'A', 'H1', 1, ['WP'], null], ['storeLoad', 'S'], ['restart', 'WR', 'S', 'wp'], ['lastSeen', 'WR', 'A'],
    ...rec('A', 'c1'), ['publish', 'A', 'H2', 2, ['WR'], null], ['storeLoad', 'S'], ['restart', 'WR2', 'S', 'wp'], ['export', 'WR2'], ['lastSeen', 'WR2', 'A']]],
  ['store-fails', [...base, ['failStore', 'S', 1], ['witnessOpts', 'WP', 'wp', { store: 'S', clock: null, skew: null }], ...rec('A', 'c0'), ['publish', 'A', 'H1', 1, ['WP'], null], ['lastSeen', 'WP', 'A'], ...rec('A', 'c1'), ['publish', 'A', 'H2', 2, ['WP'], null], ['lastSeen', 'WP', 'A'], ['storeLoad', 'S']]],
  ['store-fails-first', [...base, ['failStore', 'S', 0], ['witnessOpts', 'WP', 'wp', { store: 'S', clock: null, skew: null }], ...rec('A', 'c0'), ['publish', 'A', 'H1', 1, ['WP'], null], ['publish', 'A', 'H1', 1, ['W'], 1], ['lastSeen', 'WP', 'A'], ['export', 'WP'], ['storeLoad', 'S']]],
  ['empty-store', [...base, ['store', 'S'], ['storeLoad', 'S'], ['restart', 'WR', 'S', 'wp'], ['export', 'WR'], ['lastSeen', 'WR', 'A']]],
  ['export-import', [...base, ...rec('A', 'c0'), ['revoke', 'A', 'r1'], ['publish', 'A', 'H1', 1, ['W'], null], ['domain', 'B', 'b'], ...rec('B', 'd0'), ['publish', 'B', 'HB', 1, ['W'], null], ['export', 'W'], ['import', 'W2', { $export: 'W' }], ['lastSeen', 'W2', 'A'], ['lastSeen', 'W2', 'B'], ['export', 'W2'],
    ...rec('A', 'c1'), ['publish', 'A', 'H2', 2, ['W2'], null], ['import', 'W2', { seen: [] }], ['lastSeen', 'W2', 'A'], ['import', 'W2', {}], ['import', 'W2', null], ['export', 'W2']]],
  ['import-malformed', [...base, ...rec('A', 'c0'), ['publish', 'A', 'H1', 1, ['W'], null], ['import', 'W2', { seen: [{ head: null, rev_ids: [] }] }], ['import', 'W2', { seen: [{ head: { domain: 'x' }, rev_ids: [] }] }],
    ['import', 'W2', { seen: [{ head: { domain: 'x', size: 0, root: '', rev_root: 'nope', rev_size: 0, timestamp: 1 }, rev_ids: [] }] }], ['import', 'W2', { seen: [{ head: { domain: 'x', size: 0, root: '', rev_root: '', rev_size: 1, timestamp: 1 }, rev_ids: [5] }] }],
    ['import', 'W2', { seen: [5] }], ['import', 'W2', { seen: 'x' }], ['export', 'W2']]],
  ['import-replaces', [...base, ...rec('A', 'c0'), ['publish', 'A', 'H1', 1, ['W'], null], ['domain', 'B', 'b'], ['publish', 'B', 'HB', 1, ['W2'], null], ['import', 'W2', { $export: 'W' }], ['lastSeen', 'W2', 'A'], ['lastSeen', 'W2', 'B']]],
  ['bindings', [...base, ['enroll', 'A', 'B1', 'agent-1', 'tool'], ['enroll', 'A', 'B2', 'agent-1', 'tool'], ['enroll', 'A', 'B3', 'é', '\u{1F600}'], ['enroll', 'A', 'B4', '', '']]],
  ['evidence-with-revocation', [...base, ...rec('A', 'c0', 'c1', 'c2'), ['revoke', 'A', 'c1'], ['revoke', 'A', 'key:iss-c2'], ['publish', 'A', 'H1', 1, ['W'], null], ['evidence', 'A', 'c0', 'H1', null], ['evidence', 'A', 'c1', 'H1', null], ['evidence', 'A', 'c2', 'H1', null], ['evidence', 'A', 'zz', 'H1', null]]],
  ['unknown-names', [['record', 'Z', 'c'], ['publish', 'Z', 'H', 1, [], null], ['cosign', 'W', 'H', null, []], ['lastSeen', 'W', 'x'], ['export', 'W'], ['evidence', 'A', 'c', 'H', null], ['bogus']]],
  ['threshold-tolerates-refusal', [...base, ...rec('A', 'c0'), ['publish', 'A', 'H1', 10, ['W', 'W2'], null], ...rec('A', 'c1'), ['publish', 'A', 'Hb', 5, ['W'], null], ['publish', 'A', 'H2', 20, ['W', 'W2'], 2], ['lastSeen', 'W', 'A'], ['lastSeen', 'W2', 'A']]],
];
for (const [name, ops] of SC) await o.run('meshIssue', uniq('meshIssue', name), script, [ops]);

// ---------------------------------------------------------------------------------------------------------------- translation
const caveatOf = (name: string) => ({ type: 'scope', actions: [name] });
const KEY = (l: string) => sd('cap/' + l);
const PUBK = (l: string) => K.encodeKey(K.publicKeyOf(KEY(l)));
const root = CAP.mintRoot({ principalSecret: KEY('human'), principalPublic: PUBK('human'), holder: PUBK('orch'), caveats: [{ type: 'scope', actions: ['read', 'write', 'pay'] }, { type: 'max_amount', max: 500 }, { type: 'expires', at: NOW + 3_600_000 }, { type: 'resource', prefix: '/orders/' }] });
const c1 = CAP.delegate(root, PUBK('tool'), [{ type: 'scope', actions: ['read', 'pay'] }, { type: 'max_amount', max: 100 }], KEY('orch'));
const c2 = CAP.delegate(c1, PUBK('leaf'), [{ type: 'resource', prefix: '/orders/42' }], KEY('tool'));
const CH = [root, c1, c2];
const J = (x: any) => JSON.parse(ser(x));
const targs = (over: Record<string, unknown> = {}) => ({ fromGuardian: pub('gA'), toGuardian: pub('gB'), additionalCaveats: [{ type: 'max_amount', max: 40 }], bridgeSecret: S('cap/bridge'), issued_at: NOW, ...over });
const tr = (name: string, chain: unknown, a: unknown) => run('translateCapability', name, MM.translateCapability, [chain, a]);
await tr('append narrowing', J(CH), targs());
await tr('no additional', J(CH), targs({ additionalCaveats: undefined }));
await tr('empty additional', J(CH), targs({ additionalCaveats: [] }));
await tr('several additional', J(CH), targs({ additionalCaveats: [{ type: 'scope', actions: ['read'] }, { type: 'resource', prefix: '/orders/42/line' }, { type: 'expires', at: NOW + 1000 }, { type: 'audience', domains: [pub('gB')] }, { type: 'max_hops', n: 2 }] }));
await tr('one-hop chain', J([root]), targs());
await tr('two-hop chain', J([root, c1]), targs({ bridgeSecret: S('cap/bridge2'), issued_at: 0 }));
await tr('same guardians', J(CH), targs({ toGuardian: pub('gA') }));
await tr('widening additional is just appended', J(CH), targs({ additionalCaveats: [{ type: 'max_amount', max: 99999 }, { type: 'scope', actions: ['admin'] }] }));
await tr('unknown additional type is appended', J(CH), targs({ additionalCaveats: [{ type: 'weird', x: 1 }] }));
await tr('additional with extra members', J(CH), targs({ additionalCaveats: [{ type: 'max_amount', max: 7, note: 'n', nested: { a: [1, 2] } }] }));
await tr('unicode guardians', J(CH), targs({ fromGuardian: 'é', toGuardian: '\u{1F600}' }));
await tr('issued_at fraction', J(CH), targs({ issued_at: 1.5 }));
for (const [nm, ac] of [['not array', {}], ['string', 'x'], ['null', null], ['caveat not object', [5]], ['caveat no type', [{ max: 1 }]], ['type number', [{ type: 5 }]], ['null entry', [null]], ['array entry', [[]]]] as [string, any][]) await tr(`additional ${nm}`, J(CH), targs({ additionalCaveats: ac }));
await tr('empty chain', [], targs());
await tr('chain not array', {}, targs());
await tr('chain null', null, targs());
{
  const bad = J(CH);
  bad[1].sig = bad[1].sig.slice(0, -2) + (bad[1].sig.endsWith('AA') ? 'BB' : 'AA');
  await tr('tampered signature', bad, targs());
  const wid = J(CH); wid[2].caveats = wid[2].caveats.slice(1); await tr('dropped caveat', wid, targs());
  const rev = J(CH).reverse(); await tr('reversed chain', rev, targs());
  await tr('wrong parent', J([root, c2]), targs());
}
for (const [nm, k] of [['null key', null], ['string', 'abc'], ['number', 5]] as [string, any][]) await tr(`bridge ${nm}`, J(CH), targs({ bridgeSecret: k }));
// a hybrid PQ root: refused without a pin, accepted with the pin that equals its pq_pk, refused with a different pin
const mlKp = PQ.mlDsa65Keygen(sd('cap/pq-root'));
const pqRoot = CAP.mintRoot({ principalSecret: KEY('human'), principalPublic: PUBK('human'), holder: PUBK('orch'), caveats: [{ type: 'scope', actions: ['read', 'pay'] }, { type: 'max_amount', max: 500 }], suite: { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: mlKp } });
const pqPin = PQ.encodeMlDsaPublicKey(mlKp.publicKey);
const pqOther = PQ.encodeMlDsaPublicKey(PQ.mlDsa65Keygen(sd('cap/pq-other')).publicKey);
await tr('hybrid root without pin', J([pqRoot]), targs());
await tr('hybrid root with pin', J([pqRoot]), targs({ pqPins: { [PUBK('human')]: pqPin } }));
await tr('hybrid root with wrong pin', J([pqRoot]), targs({ pqPins: { [PUBK('human')]: pqOther } }));
await tr('hybrid root with pin for another issuer', J([pqRoot]), targs({ pqPins: { [PUBK('orch')]: pqPin } }));
await tr('ed25519 root ignores pins', J(CH), targs({ pqPins: { [PUBK('human')]: pqPin } }));

// ---- verifyTranslatedCapability / translatedEffectiveAuthority over generated translations
const mk = (over: Record<string, unknown> = {}, chain: any[] = CH) => J(MM.translateCapability(chain, un(targs(over))));
const TC = mk();
const TC1 = mk({ additionalCaveats: [] });
const TCWIDE = mk({ additionalCaveats: [{ type: 'scope', actions: ['admin'] }, { type: 'max_amount', max: 99999 }] });
const TCUNK = mk({ additionalCaveats: [{ type: 'weird' }] });
const TCEXP = mk({ additionalCaveats: [{ type: 'expires', at: NOW + 1000 }] });
const TCPQ = mk({ pqPins: { [PUBK('human')]: pqPin } }, [pqRoot]);
const ver = (name: string, tc: unknown, opts?: unknown) => run('verifyTranslatedCapability', name, MM.verifyTranslatedCapability, opts === undefined ? [tc] : [tc, opts]);
const G = { fromGuardian: pub('gA'), toGuardian: pub('gB') };
await ver('ok', TC);
await ver('ok, empty opts', TC, {});
await ver('ok, all pins', TC, { ...G, bridge: PUBK('bridge'), rootIssuer: PUBK('human'), now: NOW });
await ver('ok, no additional', TC1);
await ver('ok, wide additional narrows nothing but ANDs', TCWIDE);
await ver('unknown additional caveat', TCUNK);
await ver('expiry at the boundary', TCEXP, { now: NOW + 1000 });
await ver('expiry one past', TCEXP, { now: NOW + 1001 });
await ver('expiry far before', TCEXP, { now: 0 });
await ver('now with no expiry caveat in the translation (source expiry applies)', TC, { now: NOW + 3_600_000 });
await ver('now past the source expiry', TC, { now: NOW + 3_600_001 });
await ver('now null', TC, { now: null });
await ver('now string', TC, { now: '5' });
await ver('hybrid root, pin supplied', TCPQ, { pqPins: { [PUBK('human')]: pqPin } });
await ver('hybrid root, no pin', TCPQ);
await ver('hybrid root, wrong pin', TCPQ, { pqPins: { [PUBK('human')]: pqOther } });
for (const [nm, opts] of [
  ['from mismatch', { fromGuardian: pub('x') }], ['to mismatch', { toGuardian: pub('x') }], ['bridge mismatch', { bridge: PUBK('x') }], ['root issuer mismatch', { rootIssuer: PUBK('x') }], ['root issuer ok', { rootIssuer: PUBK('human') }],
  ['from swapped', { fromGuardian: pub('gB'), toGuardian: pub('gA') }], ['from ok only', { fromGuardian: pub('gA') }], ['to ok only', { toGuardian: pub('gB') }], ['bridge ok only', { bridge: PUBK('bridge') }],
  ['from number', { fromGuardian: 5 }], ['bridge null', { bridge: null }], ['opts null', null], ['opts string', 'x'], ['opts array', []],
] as [string, any][]) await ver(`opts ${nm}`, TC, opts);
const mut = (f: (t: any) => void) => { const t = J(TC); f(t); return t; };
const MUTS: Array<[string, any]> = [
  ['sig flipped', mut((t) => { t.sig = t.sig.slice(0, -2) + (t.sig.endsWith('AA') ? 'BB' : 'AA'); })], ['sig empty', mut((t) => { t.sig = ''; })], ['sig number', mut((t) => { t.sig = 5; })], ['sig missing', mut((t) => { delete t.sig; })],
  ['bridge other', mut((t) => { t.bridge = PUBK('other'); })], ['bridge number', mut((t) => { t.bridge = 5; })], ['bridge empty', mut((t) => { t.bridge = ''; })], ['bridge missing', mut((t) => { delete t.bridge; })],
  ['source_tip other', mut((t) => { t.source_tip = 'x'; })], ['source_tip of the root', mut((t) => { t.source_tip = MM && CAP.capHash(CH[0]); })], ['source_tip missing', mut((t) => { delete t.source_tip; })],
  ['fromGuardian = toGuardian', mut((t) => { t.toGuardian = t.fromGuardian; })], ['fromGuardian changed', mut((t) => { t.fromGuardian = 'zz'; })], ['toGuardian changed', mut((t) => { t.toGuardian = 'zz'; })],
  ['fromGuardian number', mut((t) => { t.fromGuardian = 5; })], ['toGuardian missing', mut((t) => { delete t.toGuardian; })],
  ['issued_at changed', mut((t) => { t.issued_at += 1; })], ['issued_at string', mut((t) => { t.issued_at = '1'; })], ['issued_at null', mut((t) => { t.issued_at = null; })], ['issued_at missing', mut((t) => { delete t.issued_at; })],
  ['caveats dropped one', mut((t) => { t.caveats = t.caveats.slice(1); })], ['caveats dropped last', mut((t) => { t.caveats = t.caveats.slice(0, -1); })], ['caveats reordered', mut((t) => { t.caveats = [t.caveats[1], t.caveats[0], ...t.caveats.slice(2)]; })],
  ['caveat edited', mut((t) => { t.caveats[0] = { type: 'scope', actions: ['read', 'write', 'pay', 'admin'] }; })], ['caveats emptied', mut((t) => { t.caveats = []; })], ['caveats not array', mut((t) => { t.caveats = {}; })], ['caveats null', mut((t) => { t.caveats = null; })],
  ['caveat without type', mut((t) => { t.caveats.push({ x: 1 }); })], ['caveat type number', mut((t) => { t.caveats.push({ type: 5 }); })], ['caveat null', mut((t) => { t.caveats.push(null); })],
  ['widening max_amount appended, re-signed is not possible: sig breaks', mut((t) => { t.caveats.push({ type: 'max_amount', max: 99999 }); })],
  ['source emptied', mut((t) => { t.source = []; })], ['source not array', mut((t) => { t.source = {}; })], ['source one hop', mut((t) => { t.source = t.source.slice(0, 1); })], ['source reversed', mut((t) => { t.source = [...t.source].reverse(); })],
  ['source sig flipped', mut((t) => { t.source[1].sig = t.source[1].sig.slice(0, -2) + (t.source[1].sig.endsWith('AA') ? 'BB' : 'AA'); })], ['source tip caveat widened', mut((t) => { t.source[2].caveats = t.source[2].caveats.slice(0, -1); })],
  ['source root issuer swapped', mut((t) => { t.source[0].issuer = PUBK('other'); })], ['source null entry', mut((t) => { t.source[1] = null; })],
  ['extra member', mut((t) => { t.zz = 1; })], ['all members removed', {}], ['null', null], ['string', 'x'], ['array', []], ['number', 5],
];
for (const [nm, t] of MUTS) await ver(`mut ${nm}`, t);
for (const k of ['source', 'fromGuardian', 'toGuardian', 'bridge', 'source_tip', 'caveats', 'issued_at', 'sig']) for (const h of [null, true, 0, '', 'x', [], {}, 1.5]) await ver(`member ${k} = ${ser(h)}`, mut((t) => { t[k] = h; }));
// translation whose source tip has an unknown caveat (fail closed on the source side) and one whose sig is valid but authority widens: build by signing directly
{
  const odd = CAP.delegate(c1, PUBK('leaf'), [{ type: 'weird' }], KEY('tool'));
  await ver('source tip unknown caveat', J(MM.translateCapability([root, c1, odd], un(targs()))));
  const hops = CAP.delegate(c1, PUBK('leaf'), [{ type: 'max_hops', n: 1 }], KEY('tool'));
  await ver('max_hops narrows', J(MM.translateCapability([root, c1, hops], un(targs({ additionalCaveats: [{ type: 'max_hops', n: 1 }] })))));
}
for (const [nm, tc] of [['ok', TC], ['wide', TCWIDE], ['unknown', TCUNK], ['empty caveats', { caveats: [] }], ['no caveats', {}], ['null', null], ['caveats not array', { caveats: 'x' }], ['caveat no type', { caveats: [{ max: 1 }] }],
  ['two scopes', { caveats: [{ type: 'scope', actions: ['a', 'b'] }, { type: 'scope', actions: ['b', 'c'] }] }], ['malformed max', { caveats: [{ type: 'max_amount', max: 'x' }] }], ['array', []], ['string', 'x'], ['number', 5],
  ['all six', { caveats: [{ type: 'scope', actions: ['a'] }, { type: 'resource', prefix: '/p' }, { type: 'max_amount', max: 9 }, { type: 'expires', at: 7 }, { type: 'audience', domains: ['d'] }, { type: 'max_hops', n: 2 }] }]] as [string, any][]) {
  await run('translatedEffectiveAuthority', nm, MM.translatedEffectiveAuthority, [tc]);
}

// ---------------------------------------------------------------------------------------------------------------- federated budget
const FB = (over: Record<string, unknown> = {}) => ({ rootId: 'root', rootDomain: 'dA', B0: 100, kappa: 2, bMax: 100, ...over });
const cfb = (name: string, a: unknown) => run('createFederatedBudget', name, MM.createFederatedBudget, [a]);
await cfb('ok', FB());
await cfb('B0 below bMax', FB({ B0: 40 }));
await cfb('B0 zero', FB({ B0: 0 }));
await cfb('bMax zero', FB({ B0: 0, bMax: 0 }));
await cfb('fractions', FB({ B0: 0.5, bMax: 1.5, kappa: 0.25 }));
await cfb('unicode ids', FB({ rootId: 'é', rootDomain: '\u{1F600}' }));
await cfb('empty ids', FB({ rootId: '', rootDomain: '' }));
await cfb('__proto__ root', FB({ rootId: '__proto__' }));
for (const [nm, a] of [
  ['B0 above bMax', FB({ B0: 101 })], ['kappa 0', FB({ kappa: 0 })], ['kappa negative', FB({ kappa: -1 })], ['kappa string', FB({ kappa: '2' })], ['kappa null', FB({ kappa: null })], ['kappa -0', FB({ kappa: -0 })], ['kappa tiny', FB({ kappa: 1e-300 })],
  ['bMax negative', FB({ bMax: -1 })], ['bMax string', FB({ bMax: '100' })], ['B0 negative', FB({ B0: -1 })], ['B0 -0', FB({ B0: -0 })], ['B0 string', FB({ B0: '1' })], ['B0 missing', FB({ B0: undefined })], ['rootId number', FB({ rootId: 5 })],
  ['rootDomain missing', FB({ rootDomain: undefined })], ['null', null], ['array', []], ['string', 'x'], ['huge', FB({ B0: 1e300, bMax: 1e300 })], ['2^53', FB({ B0: 2 ** 53, bMax: 2 ** 53 })],
] as [string, any][]) await cfb(nm, a);

const root0 = MM.createFederatedBudget(FB()).state;
const al = (name: string, s: unknown, a: unknown) => run('allocateSub', name, MM.allocateSub, [s, a]);
const sp = (name: string, s: unknown, id: unknown, c: unknown) => run('spendFederated', name, MM.spendFederated, [s, id, c]);
const AL = (over: Record<string, unknown> = {}) => ({ id: 'child', domain: 'dB', parent: 'root', alloc: 50, ...over });
await al('ok', root0, AL());
await al('alloc all', root0, AL({ alloc: 100 }));
await al('alloc zero', root0, AL({ alloc: 0 }));
await al('alloc over', root0, AL({ alloc: 100.0001 }));
await al('alloc negative', root0, AL({ alloc: -1 }));
await al('alloc -0', root0, AL({ alloc: -0 }));
await al('alloc string', root0, AL({ alloc: '5' }));
await al('alloc null', root0, AL({ alloc: null }));
await al('alloc fraction', root0, AL({ alloc: 0.1 }));
await al('duplicate id', root0, AL({ id: 'root' }));
await al('unknown parent', root0, AL({ parent: 'nope' }));
await al('proto parent', root0, AL({ parent: '__proto__' }));
await al('constructor parent', root0, AL({ parent: 'constructor' }));
await al('proto id', root0, AL({ id: '__proto__' }));
await al('toString id', root0, AL({ id: 'toString' }));
await al('id number', root0, AL({ id: 5 }));
await al('domain missing', root0, AL({ domain: undefined }));
await al('args null', root0, null);
await al('args array', root0, []);
// state tree scripted: root(100) -> a(60, dB) -> b(30, dC) ; root -> c(100)
const T0 = (() => { let s = root0; for (const a of [AL({ id: 'a', alloc: 60 }), AL({ id: 'b', domain: 'dC', parent: 'a', alloc: 30 }), AL({ id: 'c', domain: 'dD', alloc: 100 })]) s = MM.allocateSub(s, un(a)).state; return J(s); })();
await al('alloc under a child', T0, AL({ id: 'd', parent: 'a', alloc: 60 }));
await al('alloc above the child ceiling', T0, AL({ id: 'd', parent: 'a', alloc: 61 }));
await al('alloc under leaf', T0, AL({ id: 'd', parent: 'b', alloc: 30.5 }));
await al('duplicate under tree', T0, AL({ id: 'b', parent: 'c' }));
for (const [nm, s] of [
  ['null', null], ['no nodes', { root: 'root', kappa: 2, bMax: 100 }], ['nodes null', { nodes: null, root: 'root', kappa: 2, bMax: 100 }], ['root unknown', { ...root0, root: 'zz' }], ['kappa 0', { ...root0, kappa: 0 }], ['bMax negative', { ...root0, bMax: -1 }],
  ['node B negative', { ...root0, nodes: { root: { domain: 'dA', B: -1 } } }], ['node B string', { ...root0, nodes: { root: { domain: 'dA', B: '1' } } }], ['node domain missing', { ...root0, nodes: { root: { B: 1 } } }], ['node parent number', { ...root0, nodes: { root: { domain: 'dA', B: 1, parent: 5 } } }],
  ['node null', { ...root0, nodes: { root: null } }], ['nodes array', { ...root0, nodes: [] }], ['string', 'x'], ['array', []],
] as [string, any][]) {
  await al(`state ${nm}`, s, AL());
  await sp(`state ${nm}`, s, 'root', 1);
}
await sp('root spend', root0, 'root', 30);
await sp('root spend all', root0, 'root', 100);
await sp('root overspend', root0, 'root', 100.5);
await sp('root zero', root0, 'root', 0);
await sp('child spend', T0, 'a', 20);
await sp('grandchild spend debits every ancestor', T0, 'b', 25);
await sp('grandchild spend to its ceiling', T0, 'b', 30);
await sp('grandchild over its ceiling', T0, 'b', 30.5);
await sp('child c', T0, 'c', 100);
await sp('child c over', T0, 'c', 100.5);
await sp('negative spend', T0, 'b', -1);
await sp('-0 spend', T0, 'b', -0);
await sp('string spend', T0, 'b', '5');
await sp('null spend', T0, 'b', null);
await sp('unknown node', T0, 'zz', 1);
await sp('proto node', T0, '__proto__', 1);
await sp('node number', T0, 5, 1);
await sp('node null', T0, null, 1);
// ancestor with less budget than the spender: a(10) -> b(60 allocated before a was drawn down)
{
  let s = MM.createFederatedBudget(FB()).state;
  s = MM.allocateSub(s, { id: 'a', domain: 'dB', parent: 'root', alloc: 60 }).state;
  s = MM.allocateSub(s, { id: 'b', domain: 'dC', parent: 'a', alloc: 60 }).state;
  s = MM.spendFederated(s, 'a', 50).state;
  await sp('ancestor budget insufficient', J(s), 'b', 20);
  await sp('ancestor budget just enough', J(s), 'b', 10);
  await sp('ancestor budget one over', J(s), 'b', 10.5);
  s = MM.allocateSub(s, { id: 'c', domain: 'dC', parent: 'b', alloc: 5 }).state;
  await sp('three deep', J(s), 'c', 5);
  await sp('three deep insufficient', J(s), 'c', 5.5);
}
// cycles and strays in a hand-built state
const cyc = { nodes: { root: { domain: 'dA', B: 10 }, a: { domain: 'dB', parent: 'b', B: 5 }, b: { domain: 'dB', parent: 'a', B: 5 } }, root: 'root', kappa: 1, bMax: 10 };
await sp('cycle', cyc, 'a', 1);
await sp('stray not rooted', { nodes: { root: { domain: 'dA', B: 10 }, s: { domain: 'dB', B: 5 } }, root: 'root', kappa: 1, bMax: 10 }, 's', 1);
await sp('dangling parent', { nodes: { root: { domain: 'dA', B: 10 }, s: { domain: 'dB', parent: 'gone', B: 5 } }, root: 'root', kappa: 1, bMax: 10 }, 's', 1);
{
  const nodes: any = { root: { domain: 'd', B: 100 } };
  for (let i = 1; i <= 70; i++) nodes['n' + i] = { domain: 'd', parent: i === 1 ? 'root' : 'n' + (i - 1), B: 50 };
  await sp('depth 64', { nodes, root: 'root', kappa: 1, bMax: 100 }, 'n63', 1);
  await sp('depth 65 is too deep', { nodes, root: 'root', kappa: 1, bMax: 100 }, 'n64', 1);
  await sp('depth 70', { nodes, root: 'root', kappa: 1, bMax: 100 }, 'n70', 1);
}
for (const p of [{ bMax: 100, kappa: 2 }, { bMax: 100, kappa: 0.5 }, { bMax: 0, kappa: 1 }, { bMax: 1, kappa: 3 }, { bMax: 7, kappa: 0 }, { bMax: 7, kappa: -1 }, { bMax: -7, kappa: 1 }, { bMax: '7', kappa: 1 }, { bMax: 7 }, { kappa: 1 }, {}, null, 5, 'x', [],
  { bMax: 1e308, kappa: 1e-308 }, { bMax: 2 ** 53, kappa: 3 }, { bMax: 100, kappa: 2, extra: 1 }, root0]) await run('federatedSafetyBound', ser(p), MM.federatedSafetyBound, [p]);

// ---------------------------------------------------------------------------------------------------------------- cross reference
const ACT = { type: 'payments.refund', resource: '/orders/42', amount: 25, service_domain: pub('gB'), nonce: 'n1', at: NOW };
const mad = (name: string, a: unknown) => run('meshActionDigest', name, MM.meshActionDigest, [a]);
await mad('full', ACT);
await mad('no amount', { ...ACT, amount: undefined });
await mad('amount zero', { ...ACT, amount: 0 });
await mad('amount fraction', { ...ACT, amount: 0.1 });
await mad('member order', { at: NOW, nonce: 'n1', service_domain: pub('gB'), amount: 25, resource: '/orders/42', type: 'payments.refund' });
await mad('unicode', { ...ACT, resource: '/é/\u{1F600}' });
await mad('extra member', { ...ACT, extra: [1, { a: null }] });
await mad('empty', {});
for (const [nm, v] of [['null', null], ['string', 'x'], ['array', []], ['-0 amount', { ...ACT, amount: -0 }], ['2^53 amount', { ...ACT, amount: 2 ** 53 }], ['lone surrogate', { ...ACT, resource: '\ud800' }], ['1e21', { ...ACT, amount: 1e21 }], ['tiny', { ...ACT, amount: 1e-7 }]] as [string, any][]) await mad(nm, v);
const XR = { action_digest: MM.meshActionDigest(ACT), fromGuardian: pub('gA'), toGuardian: pub('gB'), nonce: 'x1', at: NOW };
const crc = (name: string, x: unknown) => run('crossReferenceCommit', name, MM.crossReferenceCommit, [x]);
await crc('ok', XR);
await crc('member order', { at: NOW, nonce: 'x1', toGuardian: pub('gB'), fromGuardian: pub('gA'), action_digest: XR.action_digest });
await crc('other nonce', { ...XR, nonce: 'x2' });
await crc('at zero', { ...XR, at: 0 });
await crc('unicode', { ...XR, nonce: 'é\u{1F600}' });
await crc('extra member ignored', { ...XR, extra: 1 });
await crc('missing members', {});
await crc('same guardians (no check here)', { ...XR, toGuardian: XR.fromGuardian });
for (const [nm, v] of [['null', null], ['string', 'x'], ['at -0', { ...XR, at: -0 }], ['at 2^53', { ...XR, at: 2 ** 53 }], ['lone surrogate', { ...XR, nonce: '\ud800' }], ['at string', { ...XR, at: '5' }], ['digest number', { ...XR, action_digest: 5 }]] as [string, any][]) await crc(nm, v);
const COMMIT = MM.crossReferenceCommit(XR);
const anc = (name: string, k: unknown, commit: unknown, seq: unknown) => run('anchorCrossReference', name, MM.anchorCrossReference, [k, commit, seq]);
await anc('A seq 0', S('gA'), COMMIT, 0);
await anc('A seq 7', S('gA'), COMMIT, 7);
await anc('B seq 7', S('gB'), COMMIT, 7);
await anc('other commit', S('gA'), 'zz', 1);
await anc('empty commit', S('gA'), '', 1);
await anc('seq 2^53-1', S('gA'), COMMIT, 2 ** 53 - 1);
await anc('seq fraction (signs, verify refuses)', S('gA'), COMMIT, 1.5);
await anc('seq negative', S('gA'), COMMIT, -1);
await anc('seq -0', S('gA'), COMMIT, -0);
await anc('seq string', S('gA'), COMMIT, '1');
await anc('seq null', S('gA'), COMMIT, null);
await anc('commit number', S('gA'), 5, 1);
await anc('null key', null, COMMIT, 1);
const ANC_A = J(MM.anchorCrossReference(sd('gA'), COMMIT, 7));
const ANC_B = J(MM.anchorCrossReference(sd('gB'), COMMIT, 3));
const vx = (name: string, x: unknown, a: unknown) => run('verifyCrossReference', name, MM.verifyCrossReference, [x, a]);
const ANCS = { from: ANC_A, to: ANC_B };
await vx('ok', XR, ANCS);
await vx('ok, other seqs', XR, { from: J(MM.anchorCrossReference(sd('gA'), COMMIT, 0)), to: J(MM.anchorCrossReference(sd('gB'), COMMIT, 99)) });
await vx('swapped anchors', XR, { from: ANC_B, to: ANC_A });
await vx('same guardians', { ...XR, toGuardian: XR.fromGuardian }, { from: ANC_A, to: ANC_A });
await vx('wrong commit in from', XR, { from: J(MM.anchorCrossReference(sd('gA'), 'other', 7)), to: ANC_B });
await vx('wrong commit in to', XR, { from: ANC_A, to: J(MM.anchorCrossReference(sd('gB'), 'other', 3)) });
await vx('both wrong commits', XR, { from: J(MM.anchorCrossReference(sd('gA'), 'other', 7)), to: J(MM.anchorCrossReference(sd('gB'), 'other', 3)) });
await vx('anchor signed by a stranger', XR, { from: { ...ANC_A, sig: J(MM.anchorCrossReference(sd('stranger'), COMMIT, 7)).sig }, to: ANC_B });
await vx('to signed by a stranger', XR, { from: ANC_A, to: { ...ANC_B, sig: J(MM.anchorCrossReference(sd('stranger'), COMMIT, 3)).sig } });
await vx('seq edited after signing', XR, { from: { ...ANC_A, seq: 8 }, to: ANC_B });
await vx('to seq edited', XR, { from: ANC_A, to: { ...ANC_B, seq: 4 } });
await vx('different action', { ...XR, nonce: 'x2' }, ANCS);
await vx('different at', { ...XR, at: NOW + 1 }, ANCS);
await vx('different digest', { ...XR, action_digest: 'z' }, ANCS);
await vx('guardians swapped in x', { ...XR, fromGuardian: XR.toGuardian, toGuardian: XR.fromGuardian }, ANCS);
await vx('from domain mismatch', { ...XR, fromGuardian: pub('gZ') }, ANCS);
await vx('to domain mismatch', { ...XR, toGuardian: pub('gZ') }, ANCS);
for (const k of ['domain', 'commit', 'seq', 'sig']) for (const h of [null, '', 5, -1, 1.5, [], {}, true]) {
  await vx(`from.${k} = ${ser(h)}`, XR, { from: { ...ANC_A, [k]: h }, to: ANC_B });
}
for (const k of ['action_digest', 'fromGuardian', 'toGuardian', 'nonce', 'at']) for (const h of [null, 5, [], {}, true, undefined]) {
  await vx(`x.${k} = ${ser(h ?? null)}${h === undefined ? ' (deleted)' : ''}`, { ...XR, [k]: h }, ANCS);
}
for (const [nm, a] of [['null', null], ['empty', {}], ['no to', { from: ANC_A }], ['no from', { to: ANC_B }], ['from null', { from: null, to: ANC_B }], ['array', []], ['string', 'x']] as [string, any][]) await vx(`anchors ${nm}`, XR, a);
for (const [nm, x] of [['null', null], ['string', 'x'], ['array', []], ['empty', {}]] as [string, any][]) await vx(`x ${nm}`, x, ANCS);
await vx('extra members ignored', { ...XR, extra: 1 }, { from: { ...ANC_A, extra: 1 }, to: ANC_B, extra: 1 });
await vx('seq 0 and 2^53-1', XR, { from: J(MM.anchorCrossReference(sd('gA'), COMMIT, 0)), to: J(MM.anchorCrossReference(sd('gB'), COMMIT, 2 ** 53 - 1)) });
await vx('seq 2^53 (not a natural)', XR, { from: { ...ANC_A, seq: 2 ** 53 }, to: ANC_B });

refWrite(o, 'mesh-issue');
void TCUNK;
