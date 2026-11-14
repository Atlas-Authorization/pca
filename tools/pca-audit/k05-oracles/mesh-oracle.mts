// k05 differential oracle: the cross-domain agent mesh (packages/pca/src/mesh.ts) and the Merkle primitives it rests on
// (ledger.ts verifyLedgerConsistency, revocation.ts verifyNonMembership). Drives the TypeScript reference over: the shared
// conformance vectors, structural mutations of a whole signed proof and of the trust, a clock grid at every freshness
// boundary, seeded random caveat chains with re-signed actions (effective authority / admission / reason text with
// JavaScript number formatting), revocation sets of every small size, and pinned heads at every (old, new) log size pair
// with each consistency-proof element flipped. Writes out/k05-mesh.json.gz. Deterministic (Ed25519 keys from fixed seeds).
//
//   packages/pca/node_modules/tsx/dist/cli.mjs --tsconfig tools/pca-audit/k05-oracles/tsconfig.json tools/pca-audit/k05-oracles/mesh-oracle.mts
import * as M from '../../../packages/pca/src/mesh.ts';
import * as L from '../../../packages/pca/src/ledger.ts';
import * as RV from '../../../packages/pca/src/revocation.ts';
import * as P from '../../../packages/pca/src/index.ts';
import { readFileSync } from 'node:fs';
import { Oracle, ROOT, clone, jsonOut, reparse, rng, seed, variants } from './lib.mjs';

const ns = (m: any, k: string) => (m[k] ? m : m.default);
const mesh: any = ns(M, 'verifyMeshProof'), ledger: any = ns(L, 'verifyLedgerConsistency'), rev: any = ns(RV, 'verifyNonMembership'), pca: any = ns(P, 'mintRoot');
const O = new Oracle('mesh', 'tools/pca-audit/k05-oracles/mesh-oracle.mts',
  'TS-reference oracle for Mesh (mesh.ts verifyMeshProof / checkHeadAdvance / effectiveAuthority) + verifyLedgerConsistency + verifyNonMembership. Case = {fn, name, args, out}; see tools/pca-audit/k05-oracles/README.md.');
function run(fn: string, name: string, ref: (...a: any[]) => unknown, args: unknown[]) {
  const a = reparse(args);
  let out: unknown;
  try { out = jsonOut(ref(...a)); } catch (e) { out = { $throws: e instanceof Error ? e.message : String(e) }; }
  let n = name;
  for (let i = 2; O.names.has(`${fn}/${n}`); i++) n = `${name} #${i}`;
  return O.add(fn, n, a, out);
}
/** The verdict natives compare: ok, reason, hop (trace / root_principal / leaf are TS-only extras). */
const verdict = (p: unknown, t: unknown) => { const v = mesh.verifyMeshProof(p, t); return { ok: v.ok, ...(v.reason !== undefined ? { reason: v.reason } : {}), ...(v.hop !== undefined ? { hop: v.hop } : {}) }; };
const VM = (name: string, p: unknown, t: unknown) => run('verifyMeshProof', name, verdict, [p, t]);

const NOW = 1_800_000_000_000;
const pub = (s: Uint8Array) => pca.b64u(pca.publicKeyOf(s));
const K = (l: string) => seed(`k05-mesh/${l}`);

// ---- a parametrised copy of buildMeshExample (4 hops, 3 domains, 3 witnesses) ------------------------------------------
interface BuildOpts { cav?: any[][]; action?: any; revoke?: Partial<Record<'A' | 'B' | 'C', string[]>>; fillA?: number; now?: number }
function build(o: BuildOpts = {}) {
  const now = o.now ?? NOW;
  const keys = { human: K('human'), orchestrator: K('orch'), tool: K('tool'), service: K('service'), leaf: K('leaf') };
  const A = new mesh.MeshDomain('org-A', K('dA')), B = new mesh.MeshDomain('org-B', K('dB')), C = new mesh.MeshDomain('org-C', K('dC'));
  const witnesses = [1, 2, 3].map((i) => new mesh.MeshWitness(K(`w${i}`)));
  const cav = o.cav ?? [
    [{ type: 'scope', actions: ['payments.refund', 'payments.read', 'orders.read'] }, { type: 'resource', prefix: '/orders/' }, { type: 'max_amount', max: 500 }, { type: 'expires', at: now + 3_600_000 }, { type: 'audience', domains: [C.id] }],
    [{ type: 'scope', actions: ['payments.refund', 'payments.read'] }, { type: 'max_amount', max: 100 }],
    [{ type: 'resource', prefix: '/orders/42' }, { type: 'max_hops', n: 4 }],
    [{ type: 'scope', actions: ['payments.refund'] }, { type: 'max_amount', max: 50 }],
  ];
  const root = pca.mintRoot({ principalSecret: keys.human, principalPublic: pub(keys.human), holder: pub(keys.orchestrator), caveats: cav[0] });
  const c1 = pca.delegate(root, pub(keys.tool), cav[1], keys.orchestrator);
  const c2 = pca.delegate(c1, pub(keys.service), cav[2], keys.tool);
  const c3 = pca.delegate(c2, pub(keys.leaf), cav[3], keys.service);
  const chain = [root, c1, c2, c3];
  for (let i = 0; i < (o.fillA ?? 0); i++) A.record(pca.mintRoot({ principalSecret: keys.human, principalPublic: pub(keys.human), holder: pub(K(`filler${i}`)), caveats: [] }));
  for (const [d, dom] of [['A', A], ['B', B], ['C', C]] as const) for (const id of o.revoke?.[d] ?? []) dom.revoke(id);
  A.record(root);
  const hA0 = A.publishHead(witnesses, now - 2_000);
  A.record(c1);
  const hA = A.publishHead(witnesses, now - 1_000);
  B.record(c2);
  C.record(c3);
  const hB = B.publishHead(witnesses, now - 1_000);
  const hC = C.publishHead(witnesses, now - 1_000);
  const bOrch = A.enroll(pub(keys.orchestrator), 'orchestrator'), bTool = B.enroll(pub(keys.tool), 'tool-agent'), bSvc = C.enroll(pub(keys.service), 'service-agent');
  const evidence = [A.evidence(root, hA), A.evidence(c1, hA, bOrch), B.evidence(c2, hB, bTool), C.evidence(c3, hC, bSvc)];
  const action = o.action ?? { type: 'payments.refund', resource: '/orders/42/line/1', amount: 25, service_domain: C.id, nonce: 'n-0001', at: now };
  const proof = mesh.assembleMeshProof({ chain, hops: evidence, action, leafSecret: keys.leaf });
  const trust = { humanPrincipal: pub(keys.human), witnesses: witnesses.map((w: any) => w.id), threshold: 2, now, allowedDomains: [A.id, B.id, C.id], rootDomain: A.id };
  return { proof, trust, keys, chain, A, B, C, witnesses, heads: { A0: hA0, A: hA, B: hB, C: hC }, evidence, bindings: { bOrch, bTool, bSvc } };
}
const BASE = build();
const T0 = BASE.trust;

// =====================================================================================================================
// verifyMeshProof
// =====================================================================================================================
if (!process.env.K05_MESH_SKIP_VM) { // (skip switch: a quick dry run of the cheap sections only; never for the committed output)
  // 1. the shared conformance vectors (whole proofs with every reason of the gen-conformance-mesh.ts suite)
  const conf = JSON.parse(readFileSync(ROOT + 'packages/pca/conformance/mesh-vectors.json', 'utf8'));
  for (const v of conf.mesh) VM('conf ' + v.name, v.proof, v.trust);
  VM('base', BASE.proof, T0);

  // 2. trust: structural mutation + every optional member at every hostile / boundary value
  for (const [l, v] of variants(T0)) VM('trust var ' + l, BASE.proof, v);
  const nums = [0, -0, 1, -1, 0.5, 1.5, 999, 1000, 1001, 60_000, 300_000, 2 ** 53, null, '1', true, [], {}];
  for (const k of ['maxHeadAgeMs', 'maxClockSkewMs', 'maxActionAgeMs', 'maxChainLength', 'threshold', 'now']) for (const x of nums) VM(`trust ${k}=${JSON.stringify(x)}${Object.is(x, -0) ? '(-0)' : ''}`, BASE.proof, { ...T0, [k]: x });
  for (const n of [1, 2, 3, 4, 5, 64, 65]) VM(`trust maxChainLength ${n}`, BASE.proof, { ...T0, maxChainLength: n });
  for (const [l, v] of [['dup witnesses th2', { witnesses: [T0.witnesses[0], T0.witnesses[0], T0.witnesses[1]], threshold: 2 }], ['dup witnesses th3', { witnesses: [T0.witnesses[0], T0.witnesses[0], T0.witnesses[1]], threshold: 3 }],
    ['one witness th1', { witnesses: [T0.witnesses[2]], threshold: 1 }], ['witness junk', { witnesses: [T0.witnesses[0], 5] }], ['witnesses unpinned + 1 pinned th1', { witnesses: [T0.witnesses[0], pub(K('x'))], threshold: 1 }],
    ['witnesses unpinned + 1 pinned th2', { witnesses: [T0.witnesses[0], pub(K('x'))], threshold: 2 }], ['allowed dup', { allowedDomains: [...T0.allowedDomains, T0.allowedDomains[0]] }], ['allowed junk', { allowedDomains: [...T0.allowedDomains, 5] }],
    ['rootDomain B', { rootDomain: BASE.B.id }], ['issuerDomains ok', { issuerDomains: { [pub(BASE.keys.orchestrator)]: BASE.A.id, [pub(BASE.keys.tool)]: BASE.B.id, [pub(BASE.keys.service)]: BASE.C.id } }],
    ['issuerDomains tool->C', { issuerDomains: { [pub(BASE.keys.tool)]: BASE.C.id } }], ['issuerDomains human->B (hop 0 exempt)', { issuerDomains: { [pub(BASE.keys.human)]: BASE.B.id } }], ['issuerDomains array', { issuerDomains: [] }], ['issuerDomains null', { issuerDomains: null }],
    ['issuerDomains __proto__ key', { issuerDomains: JSON.parse(`{"__proto__":"${BASE.B.id}"}`) }], ['pinnedHeads null', { pinnedHeads: null }], ['pinnedHeads {}', { pinnedHeads: {} }], ['pinnedHeads A = 0', { pinnedHeads: { [BASE.A.id]: 0 } }], ['pinnedHeads A = false', { pinnedHeads: { [BASE.A.id]: false } }],
    ['pinnedHeads A = ""', { pinnedHeads: { [BASE.A.id]: '' } }], ['pinnedHeads A = 1', { pinnedHeads: { [BASE.A.id]: 1 } }], ['pinnedHeads A = {}', { pinnedHeads: { [BASE.A.id]: {} } }], ['pinnedHeads A = []', { pinnedHeads: { [BASE.A.id]: [] } }],
    ['pinnedHeads other domain', { pinnedHeads: { [pub(K('x'))]: BASE.heads.A.head } }], ['pinnedHeads __proto__', { pinnedHeads: JSON.parse('{"__proto__":{"domain":"x"}}') }],
    ['pqPins junk', { pqPins: { a: 5 } }], ['pqPins human', { pqPins: { [pub(BASE.keys.human)]: 'AAAA' } }]] as [string, any][]) VM(`trust ${l}`, BASE.proof, { ...T0, ...v });

  // 3. clock grid: head age, future skew, action skew / age, capability expiry
  const hts = NOW - 1000;
  for (const age of [999, 1000, 1001]) for (const dn of [-1, 0, 1]) VM(`clock maxHeadAge ${age} now ${dn}`, BASE.proof, { ...T0, now: NOW + dn, maxHeadAgeMs: age });
  for (const skew of [0, 1, 60_000]) for (const d of [-1, 0, 1]) VM(`clock head future skew ${skew} d ${d}`, BASE.proof, { ...T0, now: hts - skew + d, maxClockSkewMs: skew });
  for (const skew of [0, 5]) for (const d of [-1, 0, 1]) VM(`clock action future skew ${skew} d ${d}`, BASE.proof, { ...T0, now: NOW - skew + d, maxClockSkewMs: skew, maxHeadAgeMs: 10 ** 9 });
  for (const age of [0, 9, 10, 11]) for (const dn of [9, 10, 11]) VM(`clock action age ${age} now +${dn}`, BASE.proof, { ...T0, now: NOW + dn, maxActionAgeMs: age });
  for (const dn of [3_599_999, 3_600_000, 3_600_001]) VM(`clock expiry now +${dn}`, BASE.proof, { ...T0, now: NOW + dn, maxHeadAgeMs: 10 ** 9 });
  for (const x of [NOW + 0.5, NOW - 0.5, hts + 300_000.5]) VM(`clock fractional now ${x}`, BASE.proof, { ...T0, now: x });

  // 4. structural mutation of the whole signed proof (smaller palette: every node, every type)
  const PAL = [null, -1, 1.5, '', 'x', [], {}];
  for (const [l, v] of variants(BASE.proof, { hostile: PAL })) VM('proof var ' + l, v, T0);

  // 5. seeded random caveat chains (append-only per hop) x random signed actions
  const r = rng(0x3e54);
  const C_ID = BASE.C.id, B_ID = BASE.B.id;
  const AMTS = [0, -0, 1, 25, 49.5, 50, 50.5, 51, 100, 500, -5, 1e21, 0.001, 0.1, 2 ** 53, 2 ** 53 + 2, 123456789.125];
  const cav = (): any => r.pick([
    { type: 'scope', actions: r.sub(['payments.refund', 'payments.read', 'orders.read', 'x']) },
    { type: 'resource', prefix: r.pick(['/orders/', '/orders/42', '/orders/42/', '', '/x', '/orders/42/line/1']) },
    { type: 'max_amount', max: r.pick(AMTS) },
    { type: 'expires', at: r.pick([NOW - 1, NOW, NOW + 1, NOW + 3_600_000, NOW + 0.5]) },
    { type: 'audience', domains: r.pick([[C_ID], [B_ID], [], [C_ID, B_ID], ['x', C_ID]]) },
    { type: 'max_hops', n: r.pick([0, 3, 4, 5, 3.5, 4.5, -1, 1e21]) },
    r.pick([{ type: 'mystery' }, { type: 'scope', actions: 'x' }, { type: 'scope', actions: [1] }, { type: 'resource', prefix: 5 }, { type: 'max_amount', max: '5' }, { type: 'expires', at: null }, { type: 'audience', domains: [5] }, { type: 'max_hops', n: '4' },
      { type: 5 }, { type: null }, { type: ['a', ['b']] }, { type: { a: 1 } }, { type: true }, { type: 1.5 }, { type: 1e21 }, { type: -0 }, { type: '' }, { type: [null, 'x'] }]),
  ]);
  const act = () => ({
    type: r.pick(['payments.refund', 'payments.read', 'orders.read', 'x']),
    resource: r.pick(['/orders/42/line/1', '/orders/42', '/orders/4', '/orders/', '/x']),
    ...(r.next() < 0.85 ? { amount: r.pick(AMTS) } : {}),
    service_domain: r.pick([C_ID, C_ID, B_ID, 'x']),
    nonce: `n-${r.int(0, 999)}`,
    at: r.pick([NOW, NOW, NOW - 1, NOW + 60_000, NOW + 60_001]),
  });
  let built = 0;
  for (let i = 0; i < 260; i++) {
    const lists = [0, 1, 2, 3].map((h) => Array.from({ length: r.int(h === 0 ? 1 : 0, 3) }, cav));
    let b: any;
    try { b = build({ cav: lists, action: act() }); } catch { continue; }
    built++;
    VM(`rand chain ${i}`, b.proof, b.trust);
    try { VM(`rand chain ${i} other action`, mesh.assembleMeshProof({ chain: b.chain, hops: b.evidence, action: act(), leafSecret: b.keys.leaf }), b.trust); } catch { /* an action the canonical form cannot sign */ }
  }
  console.log(`mesh: ${built} random chains built`);

  // 6. revocation: unrelated revoked ids around the capability / key ids, and the revoked ones themselves
  const capIds = BASE.chain.map((c: any) => c.id);
  const keyIds = [BASE.keys.orchestrator, BASE.keys.tool, BASE.keys.service].map((k) => mesh.keyRevocationId(pub(k)));
  const near = (id: string) => [id.slice(0, -1) + (id.endsWith('A') ? 'B' : 'A'), id + 'x', id.slice(0, -1), '', '\u0000', '~', 'zzzz', 'A'];
  for (const n of [1, 2, 3, 5, 8]) for (const d of ['A', 'B', 'C'] as const) {
    const ids = Array.from({ length: n }, (_, i) => near(capIds[d === 'A' ? 0 : d === 'B' ? 2 : 3])[i % 8] + (i >= 8 ? i : ''));
    const b = build({ revoke: { [d]: ids } });
    VM(`revoke ${d} unrelated x${n}`, b.proof, b.trust);
  }
  // (a revoked capability / key cannot get honest evidence; those refusals are the conformance revocation/* vectors above)
  void keyIds;
  // revocation leaves mutated inside a valid proof with a non-empty set
  const RB = build({ revoke: { A: near(capIds[0]).slice(0, 4), B: near(capIds[2]).slice(0, 3), C: ['A', 'zzzz'] } });
  VM('revoke rich base', RB.proof, RB.trust);
  for (const [l, v] of variants({ rev_leaves: RB.proof.rev_leaves, hops: RB.proof.hops.map((h: any) => h.revocation) }, { hostile: [null, -1, 0, 1, 1.5, 99, '', 'A', {}] })) {
    if (v === null || typeof v !== 'object' || Array.isArray(v)) continue;
    const p = clone(RB.proof);
    p.rev_leaves = v.rev_leaves;
    if (Array.isArray(v.hops)) v.hops.forEach((x: any, i: number) => { if (p.hops[i]) p.hops[i].revocation = x; });
    VM('revoke rich var ' + l, p, RB.trust);
  }

  // 7. pinned heads: A's log grows from m to n entries; pin at m, present n, with / without / broken consistency proofs
  for (const fill of [0, 1, 2, 3, 5, 6, 7, 14]) {
    const b = build({ fillA: fill });
    const n = b.heads.A.head.size;
    const pins: [string, any][] = [['A0', b.heads.A0.head]];
    const pinOk = b.A.pinProof(b.heads.A0.head, b.heads.A);
    const t = { ...b.trust, pinnedHeads: { [b.A.id]: b.heads.A0.head } };
    VM(`pin fill ${fill} no proof`, b.proof, t);
    VM(`pin fill ${fill} proof`, { ...b.proof, pin_proofs: [pinOk] }, t);
    pinOk.proof.path.forEach((_: unknown, i: number) => {
      const bad = clone(pinOk);
      bad.proof.path[i] = pca.b64u(new Uint8Array(32).fill(i + 1));
      VM(`pin fill ${fill} path[${i}] flipped`, { ...b.proof, pin_proofs: [bad] }, t);
    });
    for (const [l, f] of [['path +junk', (q: any) => q.proof.path.push(q.proof.path[0])], ['path -last', (q: any) => q.proof.path.pop()], ['path empty', (q: any) => (q.proof.path = [])], ['oldSize+1', (q: any) => q.proof.oldSize++],
      ['newSize-1', (q: any) => q.proof.newSize--], ['newSize+1', (q: any) => q.proof.newSize++], ['domain other', (q: any) => (q.domain = b.B.id)], ['path non-canonical b64', (q: any) => (q.proof.path[0] = q.proof.path[0] + '=')], ['path 31 bytes', (q: any) => (q.proof.path[0] = pca.b64u(new Uint8Array(31)))],
      ['two proofs bad first', (q: any) => q], ['path 129', (q: any) => (q.proof.path = Array(129).fill(q.proof.path[0] ?? 'A'))]] as [string, (q: any) => any][]) {
      const q = clone(pinOk);
      f(q);
      const pp = l === 'two proofs bad first' ? [{ domain: b.A.id, proof: { oldSize: 0, newSize: 0, path: [] } }, pinOk] : [q];
      VM(`pin fill ${fill} ${l}`, { ...b.proof, pin_proofs: pp }, t);
    }
    VM(`pin fill ${fill} pin = presented`, b.proof, { ...b.trust, pinnedHeads: { [b.A.id]: b.heads.A.head } });
    VM(`pin fill ${fill} pin larger`, b.proof, { ...b.trust, pinnedHeads: { [b.A.id]: { ...b.heads.A.head, size: n + 1 } } });
    VM(`pin fill ${fill} pin same size other root`, b.proof, { ...b.trust, pinnedHeads: { [b.A.id]: { ...b.heads.A.head, root: b.heads.A0.head.root } } });
    VM(`pin fill ${fill} pin rev larger`, b.proof, { ...b.trust, pinnedHeads: { [b.A.id]: { ...b.heads.A.head, rev_size: 1 } } });
    VM(`pin fill ${fill} pin same rev size other rev root`, b.proof, { ...b.trust, pinnedHeads: { [b.A.id]: { ...b.heads.A.head, rev_root: b.heads.A.head.root } } });
    VM(`pin fill ${fill} pin malformed`, b.proof, { ...b.trust, pinnedHeads: { [b.A.id]: { ...b.heads.A.head, size: -1 } } });
    VM(`pin fill ${fill} pin other domain`, b.proof, { ...b.trust, pinnedHeads: { [b.A.id]: { ...b.heads.A.head, domain: b.B.id } } });
    void pins;
  }
}

// =====================================================================================================================
// checkHeadAdvance and verifyLedgerConsistency over every (m, n) with 1 <= m <= n <= 17 (and 0 -> n for checkHeadAdvance)
// =====================================================================================================================
const CHA = (name: string, prev: unknown, next: unknown, proof?: unknown) => run('checkHeadAdvance', name, mesh.checkHeadAdvance, proof === undefined ? [prev, next] : [prev, next, proof]);
const VLC = (name: string, a: unknown, b: unknown, proof: unknown) => run('verifyLedgerConsistency', name, ledger.verifyLedgerConsistency, [a, b, proof]);
{
  const D = new mesh.MeshDomain('org-L', K('dL'));
  const heads: any[] = [];
  const caps: any[] = [];
  for (let i = 0; i < 17; i++) caps.push(pca.mintRoot({ principalSecret: K('human'), principalPublic: pub(K('human')), holder: pub(K(`h${i}`)), caveats: [] }));
  heads.push(D.publishHead([], NOW, { threshold: 0 }).head);
  for (const c of caps) { D.record(c); heads.push(D.publishHead([], NOW, { threshold: 0 }).head); }
  const r = rng(0xc0451);
  for (let m = 1; m <= 17; m++) for (let n = m; n <= 17; n++) {
    const pf = D.consistencyProof(m, n);
    const tag = `${m}->${n}`;
    CHA(`${tag} ok`, heads[m], heads[n], pf);
    VLC(`${tag} ok`, heads[m].root, heads[n].root, pf);
    pf.path.forEach((_: unknown, i: number) => {
      const bad = clone(pf);
      bad.path[i] = heads[1 + ((i + m) % 17)].root;
      CHA(`${tag} path[${i}] swapped`, heads[m], heads[n], bad);
      VLC(`${tag} path[${i}] swapped`, heads[m].root, heads[n].root, bad);
    });
    for (const [l, f] of [['drop last', (q: any) => q.path.pop()], ['drop first', (q: any) => q.path.shift()], ['extra', (q: any) => q.path.push(heads[1].root)], ['reversed', (q: any) => q.path.reverse()],
      ['oldSize-1', (q: any) => q.oldSize--], ['newSize+1', (q: any) => q.newSize++], ['sizes swapped', (q: any) => ([q.oldSize, q.newSize] = [q.newSize, q.oldSize])]] as [string, (q: any) => void][]) {
      const q = clone(pf);
      f(q);
      if (JSON.stringify(q) === JSON.stringify(pf)) continue;
      VLC(`${tag} ${l}`, heads[m].root, heads[n].root, q);
      if (r.next() < 0.5) CHA(`${tag} ${l}`, heads[m], heads[n], q);
    }
    if (m < n) {
      VLC(`${tag} roots swapped`, heads[n].root, heads[m].root, pf);
      VLC(`${tag} old root of m-1`, heads[m - 1]?.root || ledger.EMPTY_TREE_ROOT, heads[n].root, pf);
      CHA(`${tag} no proof`, heads[m], heads[n]);
      CHA(`${tag} rollback`, heads[n], heads[m], pf);
      CHA(`${tag} next rev rolls back`, { ...heads[m], rev_size: 1 }, heads[n], pf);
      CHA(`${tag} rev grows`, heads[m], { ...heads[n], rev_size: 1, rev_root: 'x' }, pf);
      CHA(`${tag} other domain`, heads[m], { ...heads[n], domain: 'x' }, pf);
    }
  }
  // the size-0 boundary of the ledger primitive (an empty mesh head has root '', the ledger's empty root is sha256(''))
  const E = ledger.EMPTY_TREE_ROOT;
  for (const [l, a, b, pf] of [['0->0', E, E, { oldSize: 0, newSize: 0, path: [] }], ['0->0 other new', E, heads[1].root, { oldSize: 0, newSize: 0, path: [] }], ['0->3 vacuous', E, heads[3].root, { oldSize: 0, newSize: 3, path: [] }],
    ['0->3 old not empty', heads[1].root, heads[3].root, { oldSize: 0, newSize: 3, path: [] }], ['0->3 with path', E, heads[3].root, { oldSize: 0, newSize: 3, path: [heads[1].root] }], ['0->0 old ""', '', '', { oldSize: 0, newSize: 0, path: [] }],
    ['3->3 equal', heads[3].root, heads[3].root, { oldSize: 3, newSize: 3, path: [] }], ['3->3 path', heads[3].root, heads[3].root, { oldSize: 3, newSize: 3, path: [heads[1].root] }], ['3->3 differ', heads[3].root, heads[4].root, { oldSize: 3, newSize: 3, path: [] }],
    ['-1', heads[1].root, heads[2].root, { oldSize: -1, newSize: 2, path: [] }], ['1.5', heads[1].root, heads[2].root, { oldSize: 1.5, newSize: 2, path: [] }], ['path not array', heads[1].root, heads[2].root, { oldSize: 1, newSize: 2, path: 'x' }],
    ['path 129', heads[2].root, heads[3].root, { oldSize: 2, newSize: 3, path: Array(129).fill(heads[1].root) }], ['roots non-string', 5, null, { oldSize: 1, newSize: 2, path: [] }], ['proof null', heads[1].root, heads[2].root, null],
    ['path item number', heads[2].root, heads[3].root, { oldSize: 2, newSize: 3, path: [5] }], ['path item 31 bytes', heads[2].root, heads[3].root, { oldSize: 2, newSize: 3, path: [pca.b64u(new Uint8Array(31))] }]] as [string, unknown, unknown, unknown][]) {
    VLC(`edge ${l}`, a, b, pf);
  }
  // heads: shape and equivocation rules without a proof
  const h3 = heads[3];
  for (const [l, v] of variants(h3, { hostile: [null, -1, 0, 1.5, '', 'x', [], {}, true, 2 ** 53] })) { CHA(`prev var ${l}`, v, h3); CHA(`next var ${l}`, h3, v); }
  // an empty head (size 0, root '') advances to any n with the (vacuous) 0 -> n proof: its RFC 9162 root is EMPTY_TREE_ROOT (fixed in 0.5)
  for (let n = 1; n <= 17; n++) {
    const pf = D.consistencyProof(0, n);
    CHA(`0->${n} ok`, heads[0], heads[n], pf);
    CHA(`0->${n} no proof`, heads[0], heads[n]);
    CHA(`0->${n} with path`, heads[0], heads[n], { ...pf, path: [heads[1].root] });
    CHA(`0->${n} oldSize 1`, heads[0], heads[n], { ...pf, oldSize: 1 });
  }
  CHA('empty -> empty', heads[0], heads[0]);
  CHA('equal', h3, h3);
  CHA('equal rev root differs', h3, { ...h3, rev_root: 'other' });
  CHA('size 0 with root', { ...heads[0], root: h3.root }, h3);
  CHA('size 3 root empty', { ...h3, root: '' }, h3);
}

// =====================================================================================================================
// verifyNonMembership: sets of 0..9 ids, every gap, with each proof member mutated
// =====================================================================================================================
const VNM = (name: string, root: unknown, nm: unknown, id: unknown) => run('verifyNonMembership', name, rev.verifyNonMembership, [root, nm, id]);
{
  const POOL = ['b', 'd', 'f', 'h', 'j', 'l', 'n', 'p', 'r'];
  const QUERY = ['a', 'c', 'e', 'g', 'i', 'k', 'm', 'o', 'q', 's', '', 'b\u0000', 'é'];
  for (let n = 0; n <= 9; n++) {
    const set = new rev.RevocationSet(POOL.slice(0, n));
    for (const q of QUERY) {
      if (set.has(q)) continue;
      const nm = set.nonMembershipProof(q);
      VNM(`n${n} ${JSON.stringify(q)} ok`, set.root, nm, q);
      for (const p of POOL.slice(0, n)) VNM(`n${n} proof for ${JSON.stringify(q)} used for revoked ${p}`, set.root, nm, p);
      if (n > 0 && (q === 'a' || q === 'e' || q === 's')) {
        for (const [l, v] of variants(nm, { hostile: [null, -1, 0, 1, 1.5, 99, '', 'A', {}, []], depth: 5 })) {
          // a JSON non-object lo / hi is never reached from verifyMeshProof (expandNM resolves indices to rev_leaves records)
          if (v === null || typeof v !== 'object' || Array.isArray(v) || ['lo', 'hi'].some((k) => k in v && (v[k] === null || typeof v[k] !== 'object' || Array.isArray(v[k])))) continue;
          VNM(`n${n} ${JSON.stringify(q)} var ${l}`, set.root, v, q);
        }
      }
      VNM(`n${n} ${JSON.stringify(q)} other root`, new rev.RevocationSet(POOL.slice(0, n + 1)).root, nm, q);
    }
  }
  VNM('size 0 with lo', new rev.RevocationSet([]).root, { size: 0, lo: new rev.RevocationSet(['a']).nonMembershipProof('b').lo }, 'c');
  VNM('size 0 wrong root', new rev.RevocationSet(['a']).root, { size: 0 }, 'c');
  VNM('no lo no hi', new rev.RevocationSet(['a']).root, { size: 1 }, 'c');
  VNM('proof null', new rev.RevocationSet(['a']).root, null, 'c');
}

// =====================================================================================================================
// effectiveAuthority: conjunction of random caveat lists (exact members, intersections sorted, min of numbers)
// =====================================================================================================================
{
  const r = rng(0xeff3c7);
  const EA = (name: string, cs: unknown) => run('effectiveAuthority', name, mesh.effectiveAuthority, [cs]);
  const one = (): any => r.pick([
    { type: 'scope', actions: r.sub(['b', 'a', 'c', 'a', 'é', 'Z']) }, { type: 'scope', actions: [] }, { type: 'resource', prefix: r.pick(['/a', '', '/b']) },
    { type: 'max_amount', max: r.pick([0, -0, 1, 1.5, -1, 1e21, 2 ** 53, 1e-7]) }, { type: 'expires', at: r.pick([0, NOW, 1.5]) }, { type: 'audience', domains: r.sub(['x', 'y', 'x']) }, { type: 'max_hops', n: r.pick([0, 1, 3.5, -1]) },
    { type: 'mystery' }, { type: 'scope', actions: 'a' }, { type: 'scope', actions: ['a', 1] }, { type: 'resource' }, { type: 'max_amount', max: '1' }, { type: 'expires' }, { type: 'audience', domains: null }, { type: 'max_hops', n: null }, { type: 5 }, { type: null },
  ]);
  for (let i = 0; i < 500; i++) EA(`rand ${i}`, Array.from({ length: r.int(0, 5) }, one));
}

O.write();
