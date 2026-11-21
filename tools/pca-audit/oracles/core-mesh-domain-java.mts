// Oracle: the issuing side of the mesh (mesh.ts MeshDomain): enroll, evidence, pinProof, over scripted sequences, TS reference.
// Written for the Java lane (MeshDomain.enroll / evidence / pinProof, RevocationSet.nonMembershipProof); reusable by any native.
// Every case is ONE deterministic op sequence: args = [ops], out = [one result per op]; an op that throws records {"$err": "Error"}.
// Keys come from seed("mesh-domain/<label>"); capabilities are plain objects built from a label: {id: label, issuer: "iss-"+label, holder: "h",
// caveats: [{type: "scope", actions: [label]}]} (only id, issuer and the canonical hash matter to the domain).
// PORTING (net.atlasauth.pca MeshDomain / MeshWitness / RevocationSet):
//   ["domain", D, seedLabel] -> id    ["witness", W, seedLabel] -> id    ["record", D, label] -> index    ["revoke", D, id] -> null
//   ["publish", D, H, ts, [W..], threshold|null] -> the cosigned head (also kept under the name H)
//   ["fork", H2, H, field, value] -> null (a copy of head H with one top-level field replaced, kept under H2)
//   ["enroll", D, B, agent, role] -> the binding (kept under the name B)
//   ["evidence", D, label, H, B|null] -> the hop evidence;  ["pinProof", D, pin, H] where pin is a head name or a literal {size} -> {domain, proof}
//   ["nonMembership", D, id] -> the domain's CURRENT revocation set's non-membership proof for id
import { Oracle, refWrite, seed } from './lib.mjs';
const M: any = await import('../../../packages/pca/src/mesh.ts');
const o = new Oracle('core-mesh-domain-java', 'tools/pca-audit/oracles/core-mesh-domain-java.mts', 'TS-reference oracle for the mesh domain evidence, enroll and pinProof.');
const { encodeKey, publicKeyOf } = await import('../../../packages/pca/src/keys.ts');
const { jsonOut } = await import('./lib.mjs');
const cap = (label: string) => ({ id: label, issuer: 'iss-' + label, holder: 'h', caveats: [{ type: 'scope', actions: [label] }] });
async function run(ops: any[]): Promise<any[]> {
  const doms = new Map<string, any>(), ws = new Map<string, any>(), heads = new Map<string, any>(), binds = new Map<string, any>();
  const out: any[] = [];
  for (const op of ops) {
    try {
      let v: any = null;
      switch (op[0]) {
        case 'domain': { const d = new M.MeshDomain(op[1], seed('mesh-domain/' + op[2])); doms.set(op[1], d); v = d.id; break; }
        case 'witness': { const w = new M.MeshWitness(seed('mesh-domain/' + op[2])); ws.set(op[1], w); v = w.id; break; }
        case 'record': v = doms.get(op[1]).record(cap(op[2])); break;
        case 'revoke': doms.get(op[1]).revoke(op[2]); break;
        case 'publish': { const h = doms.get(op[1]).publishHead(op[4].map((w: string) => ws.get(w)), op[3], op[5] === null ? {} : { threshold: op[5] }); heads.set(op[2], h); v = h; break; }
        case 'fork': heads.set(op[1], { ...heads.get(op[2]), [op[3]]: op[4] }); break;
        case 'enroll': { const b = doms.get(op[1]).enroll(op[3], op[4]); binds.set(op[2], b); v = b; break; }
        case 'evidence': v = doms.get(op[1]).evidence(cap(op[2]), heads.get(op[3]), op[4] === null ? undefined : binds.get(op[4])); break;
        case 'pinProof': v = doms.get(op[1]).pinProof(typeof op[2] === 'string' ? heads.get(op[2]).head : op[2], heads.get(op[3])); break;
        case 'nonMembership': v = doms.get(op[1]).rev.nonMembershipProof(op[2]); break;
        default: throw new Error('op');
      }
      out.push(jsonOut(v) ?? null);
    } catch {
      out.push({ $err: 'Error' });
    }
  }
  return out;
}
const base = [['domain', 'A', 'a'], ['witness', 'W', 'w'], ['witness', 'W2', 'w2']];
const rec = (...ls: string[]) => ls.map((l) => ['record', 'A', l]);
const cases: Array<[string, any[]]> = [
  ['basic', [...base, ...rec('c0', 'c1', 'c2'), ['publish', 'A', 'H1', 1000, ['W'], null], ['enroll', 'A', 'B1', 'agent-1', 'tool'], ['evidence', 'A', 'c0', 'H1', null], ['evidence', 'A', 'c1', 'H1', 'B1'], ['evidence', 'A', 'c2', 'H1', 'B1']]],
  ['all-sizes', [...base, ...Array.from({ length: 9 }, (_, i) => [['record', 'A', 'c' + i], ['publish', 'A', 'H' + i, 1000 + i, ['W'], null], ...Array.from({ length: i + 1 }, (_, j) => ['evidence', 'A', 'c' + j, 'H' + i, null])]).flat()]],
  ['not-in-head', [...base, ...rec('c0'), ['publish', 'A', 'H1', 1, ['W'], null], ...rec('c1'), ['evidence', 'A', 'c1', 'H1', null], ['publish', 'A', 'H2', 2, ['W'], null], ['evidence', 'A', 'c1', 'H2', null], ['evidence', 'A', 'c0', 'H1', null], ['evidence', 'A', 'zz', 'H2', null]]],
  ['unknown-head', [...base, ...rec('c0'), ['publish', 'A', 'H1', 1, ['W'], null], ['fork', 'HX', 'H1', 'sig', 'AAAA'], ['evidence', 'A', 'c0', 'HX', null], ['pinProof', 'A', { size: 0 }, 'HX'], ['fork', 'HY', 'H1', 'cosigs', []], ['evidence', 'A', 'c0', 'HY', null]]],
  ['revoked-cap', [...base, ...rec('c0', 'c1', 'c2', 'c3'), ['revoke', 'A', 'c1'], ['publish', 'A', 'H1', 1, ['W'], null], ['evidence', 'A', 'c0', 'H1', null], ['evidence', 'A', 'c1', 'H1', null], ['evidence', 'A', 'c2', 'H1', null], ['evidence', 'A', 'c3', 'H1', null]]],
  ['revoked-after', [...base, ...rec('c0', 'c1'), ['publish', 'A', 'H1', 1, ['W'], null], ['revoke', 'A', 'c0'], ['evidence', 'A', 'c0', 'H1', null], ['publish', 'A', 'H2', 2, ['W'], null], ['evidence', 'A', 'c0', 'H2', null], ['evidence', 'A', 'c1', 'H2', null], ['evidence', 'A', 'c1', 'H1', null]]],
  ['revoked-key', [...base, ...rec('c0', 'c1', 'c2'), ['revoke', 'A', 'key:iss-c1'], ['revoke', 'A', 'zzz'], ['revoke', 'A', ''], ['publish', 'A', 'H1', 1, ['W'], null], ['evidence', 'A', 'c0', 'H1', null], ['evidence', 'A', 'c1', 'H1', null], ['evidence', 'A', 'c2', 'H1', null]]],
  ['many-revocations', [...base, ...rec('m', 'n'), ...Array.from({ length: 11 }, (_, i) => ['revoke', 'A', 'r' + String.fromCharCode(97 + ((i * 7) % 11))]), ['revoke', 'A', 'key:other'], ['revoke', 'A', 'é'], ['revoke', 'A', 'z\u{1F600}'], ['revoke', 'A', '～'], ['publish', 'A', 'H1', 1, ['W'], null], ['evidence', 'A', 'm', 'H1', null], ['evidence', 'A', 'n', 'H1', null], ['nonMembership', 'A', 'a'], ['nonMembership', 'A', 'rb'], ['nonMembership', 'A', 'rz'], ['nonMembership', 'A', 'zz'], ['nonMembership', 'A', 'é'], ['nonMembership', 'A', 'ê'], ['nonMembership', 'A', '']]],
  ['nonMembership-small', [...base, ['nonMembership', 'A', 'x'], ['revoke', 'A', 'm'], ['nonMembership', 'A', 'a'], ['nonMembership', 'A', 'm'], ['nonMembership', 'A', 'z'], ['revoke', 'A', 'b'], ['nonMembership', 'A', 'c'], ['nonMembership', 'A', 'a'], ['nonMembership', 'A', 'n']]],
  ['enroll', [...base, ['enroll', 'A', 'B1', 'agent-1', 'tool'], ['enroll', 'A', 'B2', 'agent-1', 'tool'], ['enroll', 'A', 'B3', 'agent-2', 'orchestrator'], ['enroll', 'A', 'B4', '', ''], ['enroll', 'A', 'B5', 'é\u0000', 'r\u{1F600}']]],
  ['enroll-two-domains', [...base, ['domain', 'B', 'b'], ['enroll', 'A', 'B1', 'agent-1', 'tool'], ['enroll', 'B', 'B2', 'agent-1', 'tool']]],
  ['pinProof', [...base, ...rec('c0', 'c1'), ['publish', 'A', 'H1', 1, ['W'], null], ...rec('c2', 'c3', 'c4'), ['publish', 'A', 'H2', 2, ['W'], null], ...rec('c5'), ['publish', 'A', 'H3', 3, ['W'], null], ['pinProof', 'A', 'H1', 'H2'], ['pinProof', 'A', 'H1', 'H3'], ['pinProof', 'A', 'H2', 'H3'], ['pinProof', 'A', 'H3', 'H3'], ['pinProof', 'A', 'H3', 'H2'], ['pinProof', 'A', { size: 0 }, 'H3'], ['pinProof', 'A', { size: 1 }, 'H3'], ['pinProof', 'A', { size: 4 }, 'H3'], ['pinProof', 'A', { size: 6 }, 'H3'], ['pinProof', 'A', { size: 7 }, 'H3'], ['pinProof', 'A', { size: -1 }, 'H3'], ['pinProof', 'A', { size: 1.5 }, 'H3'], ['pinProof', 'A', { size: 'x' }, 'H3'], ['pinProof', 'A', { }, 'H3']]],
  ['pinProof-empty', [...base, ['publish', 'A', 'H0', 1, ['W'], null], ...rec('c0'), ['publish', 'A', 'H1', 2, ['W'], null], ['pinProof', 'A', 'H0', 'H1'], ['pinProof', 'A', 'H1', 'H0'], ['pinProof', 'A', 'H0', 'H0']]],
  ['two-domains', [...base, ['domain', 'B', 'b'], ...rec('c0'), ['record', 'B', 'c0'], ['record', 'B', 'd0'], ['publish', 'A', 'HA', 1, ['W'], null], ['publish', 'B', 'HB', 1, ['W'], null], ['evidence', 'A', 'c0', 'HA', null], ['evidence', 'A', 'c0', 'HB', null], ['evidence', 'B', 'c0', 'HB', null], ['evidence', 'B', 'd0', 'HB', null], ['pinProof', 'A', 'HA', 'HB'], ['pinProof', 'B', 'HB', 'HB']]],
  ['threshold', [...base, ...rec('c0'), ['publish', 'A', 'H1', 10, ['W', 'W2'], null], ...rec('c1'), ['publish', 'A', 'H2', 5, ['W', 'W2'], 1], ['publish', 'A', 'H3', 20, ['W', 'W2'], null], ['evidence', 'A', 'c1', 'H2', null], ['evidence', 'A', 'c1', 'H3', null]]],
  ['publish-fails-no-snapshot', [...base, ...rec('c0', 'c1'), ['publish', 'A', 'H1', 10, ['W'], null], ['publish', 'A', 'H2', 5, ['W'], null], ['evidence', 'A', 'c0', 'H2', null], ['evidence', 'A', 'c0', 'H1', null], ['record', 'A', 'c0'], ['publish', 'A', 'H2', 11, ['W'], null], ['evidence', 'A', 'c0', 'H2', null]]],
  ['rebind-head', [...base, ...rec('c0'), ['publish', 'A', 'H1', 1, ['W'], null], ['enroll', 'A', 'B1', 'a', 'r'], ['publish', 'A', 'H1b', 1, ['W'], null], ['evidence', 'A', 'c0', 'H1b', 'B1'], ['evidence', 'A', 'c0', 'H1', 'B1'], ['evidence', 'A', 'c0', 'H1', 'nope']]],
  ['evidence-binding-other', [...base, ['domain', 'B', 'b'], ...rec('c0'), ['publish', 'A', 'H1', 1, ['W'], null], ['enroll', 'B', 'BB', 'x', 'y'], ['evidence', 'A', 'c0', 'H1', 'BB']]],
];
for (const [name, ops] of cases) await o.run('meshDomain', name, run, [ops]);
refWrite(o, 'core-mesh-domain-java');
