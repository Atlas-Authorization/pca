// Oracle: mesh.ts assembleMeshProof and signMeshAction over scripted multi-domain sequences, TS reference. Written for the Java lane; reusable by any native.
// Every case is ONE deterministic op sequence: args = [ops], out = [one result per op]; an op that throws records {"$err": "Error"}.
// Keys come from seed("mesh-proof/<label>"); capabilities are plain objects built from a label: {id: label, issuer: "iss-"+label, holder: "h",
// caveats: [{type: "scope", actions: [label]}]} (only id, issuer and the canonical hash matter). Ed25519 signatures are deterministic: results compare in full.
// PORTING (net.atlasauth.pca Mesh.assembleMeshProof / Mesh.signMeshAction + MeshDomain, MeshWitness):
//   ["domain", D, seedLabel] -> id    ["witness", W, seedLabel] -> id    ["record", D, label] -> index    ["revoke", D, id] -> null
//   ["publish", D, H, ts, [W..], threshold|null] -> the cosigned head (kept under H)
//   ["subcos", H2, H, [i..]] -> null (a copy of head H keeping only the cosignatures at those indices, kept under H2)
//   ["fork", H2, H, field, value] -> null (a copy of head H with one top-level field replaced)    ["forkHead", H2, H, field, value] -> null (same, a member of H.head replaced)
//   ["enroll", D, B, agent, role] -> binding (kept under B)
//   ["ev", D, E, label, H, B|null] -> the uncompacted hop evidence (kept under E)    ["setEv", E2, E, field, value|{"$del":true}] -> null (a copy of evidence E with a member replaced or deleted; a string value for "head" naming a stored head is that head)
//   ["pinProofAs", D, P, pin, H] -> {domain, proof} (kept under P; pin as in the domain oracle: a head name or a literal {size})
//   ["assemble", [capLabel..], [E..], action, leafSeedLabel, [P..]|null] -> the proof (chain = the plain caps of those labels, in order)
//   ["sign", [capLabel..], action, leafSeedLabel] -> the action signature (b64u)
import { Oracle, refWrite, seed, jsonOut } from './lib.mjs';
const M: any = await import('../../../packages/pca/src/mesh.ts');
const o = new Oracle('core-mesh-proof-java', 'tools/pca-audit/oracles/core-mesh-proof-java.mts', 'TS-reference oracle for assembleMeshProof and signMeshAction.');
const cap = (label: string) => ({ id: label, issuer: 'iss-' + label, holder: 'h', caveats: [{ type: 'scope', actions: [label] }] });
const sd = (l: string) => seed('mesh-proof/' + l);
async function run(ops: any[]): Promise<any[]> {
  const doms = new Map<string, any>(), ws = new Map<string, any>(), store = new Map<string, any>();
  const out: any[] = [];
  const get = (n: string) => { if (!store.has(n)) throw new Error('unknown ' + n); return store.get(n); };
  for (const op of ops) {
    try {
      let v: any = null;
      switch (op[0]) {
        case 'domain': { const d = new M.MeshDomain(op[1], sd(op[2])); doms.set(op[1], d); v = d.id; break; }
        case 'witness': { const w = new M.MeshWitness(sd(op[2])); ws.set(op[1], w); v = w.id; break; }
        case 'record': v = doms.get(op[1]).record(cap(op[2])); break;
        case 'revoke': doms.get(op[1]).revoke(op[2]); break;
        case 'publish': { const h = doms.get(op[1]).publishHead(op[4].map((w: string) => ws.get(w)), op[3], op[5] === null ? {} : { threshold: op[5] }); store.set(op[2], h); v = h; break; }
        case 'subcos': { const h = get(op[2]); store.set(op[1], { ...h, cosigs: op[3].map((i: number) => h.cosigs[i]) }); break; }
        case 'fork': store.set(op[1], { ...get(op[2]), [op[3]]: op[4] }); break;
        case 'forkHead': { const h = get(op[2]); store.set(op[1], { ...h, head: { ...h.head, [op[3]]: op[4] } }); break; }
        case 'enroll': { const b = doms.get(op[1]).enroll(op[3], op[4]); store.set(op[2], b); v = b; break; }
        case 'ev': { const e = doms.get(op[1]).evidence(cap(op[3]), get(op[4]), op[5] === null ? undefined : get(op[5])); store.set(op[2], e); v = e; break; }
        case 'setEv': { const e = { ...get(op[2]) }; if (op[4] && typeof op[4] === 'object' && op[4].$del) delete e[op[3]]; else if (op[3] === 'head' && typeof op[4] === 'string' && store.has(op[4])) e.head = store.get(op[4]); else e[op[3]] = op[4]; store.set(op[1], e); break; }
        case 'pinProofAs': { const p = doms.get(op[1]).pinProof(typeof op[3] === 'string' ? get(op[3]).head : op[3], get(op[4])); store.set(op[2], p); v = p; break; }
        case 'assemble': v = M.assembleMeshProof({ chain: op[1].map(cap), hops: op[2].map(get), action: op[3], leafSecret: sd(op[4]), ...(op[5] === null ? {} : { pinProofs: op[5].map(get) }) }); break;
        case 'sign': v = M.signMeshAction(op[1].map(cap), op[2], sd(op[3])); break;
        default: throw new Error('op');
      }
      out.push(jsonOut(v) ?? null);
    } catch {
      out.push({ $err: 'Error' });
    }
  }
  return out;
}
const base = [['domain', 'A', 'a'], ['domain', 'B', 'b'], ['witness', 'W', 'w'], ['witness', 'W2', 'w2'], ['witness', 'W3', 'w3']];
const rec = (D: string, ...ls: string[]) => ls.map((l) => ['record', D, l]);
const act = (extra: any = {}) => ({ type: 'pay', resource: 'acct:1', amount: 10, service_domain: 'svc', nonce: 'n1', at: 1_800_000_000_000, ...extra });
const A1 = act();
const cases: Array<[string, any[]]> = [
  ['single-domain', [...base, ...rec('A', 'c0', 'c1', 'c2'), ['publish', 'A', 'H1', 1000, ['W'], null], ['ev', 'A', 'E0', 'c0', 'H1', null], ['enroll', 'A', 'B1', 'ag', 'tool'], ['ev', 'A', 'E1', 'c1', 'H1', 'B1'], ['ev', 'A', 'E2', 'c2', 'H1', 'B1'],
    ['assemble', ['c0', 'c1', 'c2'], ['E0', 'E1', 'E2'], A1, 'leaf', null], ['assemble', ['c0', 'c1', 'c2'], ['E0', 'E1', 'E2'], A1, 'leaf', []], ['assemble', ['c0'], ['E0'], A1, 'other', null]]],
  ['shared-leaves', [...base, ...rec('A', 'c0', 'c1', 'c2', 'c3'), ...['rb', 'rd', 'rf', 'rh', 'key:zz'].map((r) => ['revoke', 'A', r]), ['publish', 'A', 'H1', 5, ['W', 'W2'], null],
    ['ev', 'A', 'E0', 'c0', 'H1', null], ['ev', 'A', 'E1', 'c1', 'H1', null], ['ev', 'A', 'E2', 'c2', 'H1', null], ['ev', 'A', 'E3', 'c3', 'H1', null], ['assemble', ['c0', 'c1', 'c2', 'c3'], ['E0', 'E1', 'E2', 'E3'], act({ amount: 1.5 }), 'leaf', null]]],
  ['two-domains', [...base, ...rec('A', 'c0', 'c1'), ...rec('B', 'c2'), ['revoke', 'A', 'x1'], ['revoke', 'B', 'x1'], ['revoke', 'B', 'x2'], ['publish', 'A', 'HA', 10, ['W'], null], ['publish', 'B', 'HB', 11, ['W', 'W2'], null],
    ['enroll', 'A', 'BA', 'ag', 'orchestrator'], ['enroll', 'B', 'BB', 'ag2', 'tool'], ['ev', 'A', 'E0', 'c0', 'HA', null], ['ev', 'A', 'E1', 'c1', 'HA', 'BA'], ['ev', 'B', 'E2', 'c2', 'HB', 'BB'],
    ['assemble', ['c0', 'c1', 'c2'], ['E0', 'E1', 'E2'], act({ service_domain: 'B' }), 'leaf', null],
    ...rec('A', 'c9'), ['publish', 'A', 'HA2', 20, ['W'], null], ['pinProofAs', 'A', 'PA', 'HA', 'HA2'], ['pinProofAs', 'A', 'PB', { size: 1 }, 'HA2'], ['ev', 'A', 'E9', 'c9', 'HA2', null],
    ['assemble', ['c0', 'c9'], ['E0', 'E9'], A1, 'leaf', ['PA']], ['assemble', ['c0', 'c9'], ['E0', 'E9'], A1, 'leaf', ['PA', 'PB']], ['assemble', ['c0', 'c9'], ['E0', 'E9'], A1, 'leaf', []]]],
  ['cosig-merge', [...base, ...rec('A', 'c0', 'c1', 'c2', 'c3'), ['publish', 'A', 'H1', 7, ['W', 'W2', 'W3'], null], ['subcos', 'F0', 'H1', [0]], ['subcos', 'F1', 'H1', [1]], ['subcos', 'F01', 'H1', [0, 1]], ['subcos', 'F2', 'H1', [2, 0]], ['subcos', 'FN', 'H1', []],
    ['ev', 'A', 'E0', 'c0', 'F0', null], ['ev', 'A', 'E1', 'c1', 'F1', null], ['ev', 'A', 'E2', 'c2', 'F01', null], ['ev', 'A', 'E3', 'c3', 'F2', null], ['ev', 'A', 'E4', 'c3', 'FN', null], ['ev', 'A', 'E5', 'c0', 'H1', null],
    ['assemble', ['c0', 'c1', 'c2', 'c3'], ['E0', 'E1', 'E2', 'E3'], A1, 'leaf', null], ['assemble', ['c0', 'c1'], ['E0', 'E0'], A1, 'leaf', null], ['assemble', ['c3', 'c0'], ['E4', 'E5'], A1, 'leaf', null], ['assemble', ['c3', 'c0', 'c1'], ['E4', 'E1', 'E3'], A1, 'leaf', null]]],
  ['distinct-heads', [...base, ...rec('A', 'c0', 'c1'), ['publish', 'A', 'H1', 7, ['W'], null], ['forkHead', 'HX', 'H1', 'timestamp', 8], ['fork', 'HY', 'H1', 'sig', 'AAAA'], ['ev', 'A', 'E0', 'c0', 'H1', null], ['ev', 'A', 'E1', 'c1', 'H1', null],
    ['setEv', 'E1x', 'E1', 'head', 'HX'], ['setEv', 'E1y', 'E1', 'head', 'HY'], ['assemble', ['c0', 'c1'], ['E0', 'E1'], A1, 'leaf', null], ['assemble', ['c0', 'c1'], ['E0', 'E1x'], A1, 'leaf', null], ['assemble', ['c0', 'c1'], ['E0', 'E1y'], A1, 'leaf', null]]],
  ['at-boundaries', [...base, ...rec('A', 'c0'), ['publish', 'A', 'H1', 1, ['W'], null], ['ev', 'A', 'E0', 'c0', 'H1', null],
    ...[act({ amount: undefined }), act({ amount: 0 }), act({ amount: -3 }), act({ amount: 2 ** 53 - 1 }), act({ at: 0 }), act({ nonce: '' }), act({ resource: 'é☃\u{1F600}' }), act({ type: 'a"b\\c' }), act({ extra: { n: [1, null] } }), act({ amount: 1e21 }), act({ at: 1.5 }), act({ at: 2 ** 53 }), {}, { type: 'x' }].flatMap((a, i) => [['sign', ['c0'], a, 'leaf'], ['assemble', ['c0'], ['E0'], a, 'leaf', null]])]],
  ['sign-chains', [...base, ['sign', [], A1, 'leaf'], ['sign', ['c0'], A1, 'leaf'], ['sign', ['c0', 'c1'], A1, 'leaf'], ['sign', ['c1', 'c0'], A1, 'leaf'], ['sign', ['c0', 'c1'], A1, 'leaf2'], ['sign', ['é'], A1, 'leaf'], ['sign', ['c0'], act({ nonce: 'n2' }), 'leaf']]],
  ['hostile-evidence', [...base, ...rec('A', 'c0', 'c1'), ['publish', 'A', 'H1', 1, ['W'], null], ['ev', 'A', 'E0', 'c0', 'H1', null], ['ev', 'A', 'E1', 'c1', 'H1', null],
    ['setEv', 'N1', 'E1', 'revocation', null], ['setEv', 'N2', 'E1', 'head', { $del: true }], ['setEv', 'N3', 'E1', 'inclusion', { $del: true }], ['setEv', 'N4', 'E1', 'domain', { $del: true }], ['setEv', 'N5', 'E1', 'binding', null], ['setEv', 'N6', 'E1', 'binding', { agent: 'x' }],
    ['setEv', 'N7', 'E1', 'revocation', { cap: { size: 0 }, issuer_key: { size: 0 } }], ['setEv', 'N8', 'E1', 'revocation', { cap: { size: 1, lo: { a: 1, b: 2 }, hi: { b: 2, a: 1 } }, issuer_key: { size: 2, lo: null, hi: { b: 2, a: 1 } } }], ['setEv', 'N9', 'E1', 'revocation', { cap: {}, issuer_key: { size: 'x' } }],
    ...['N1', 'N2', 'N3', 'N4', 'N5', 'N6', 'N7', 'N8', 'N9'].map((n) => ['assemble', ['c0', 'c1'], ['E0', n], A1, 'leaf', null]), ['assemble', ['c0'], ['nope'], A1, 'leaf', null], ['assemble', ['c0', 'c1'], [], A1, 'leaf', null], ['assemble', [], ['E0'], A1, 'leaf', null], ['assemble', [], [], A1, 'leaf', null]]],
];
for (const [name, ops] of cases) await o.run('meshProof', name, run, [ops]);
refWrite(o, 'core-mesh-proof-java');
