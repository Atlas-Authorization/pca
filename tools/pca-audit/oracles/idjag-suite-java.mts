// Oracle (java extra): idJagToCapability with a post-quantum / hybrid ROOT hop (opts.suite). PQ signatures are not compared byte for byte: each case
// reports the capability without its signature members, the signature byte lengths and the verdict of the reference chain verifier under the matching pin.
// PORTING (fn(args) -> native entry point; compared by JSON value; a reference throw requires the native to throw):
//   idJagToCapabilitySuite(grant, edLabel, alg, pqSeedB64u, principalPublic?)   IdJag.idJagToCapability(grant, {principalSecret: seed(edLabel), principalPublic, holder, suite: Keys.suite(alg, edFromSeed, pqFromSeed(prim, pqSeed))})
//       (edLabel: sha256 of "atlas-pca-conformance/<label>"; principalPublic defaults to that seed's public key; holder is fixed in the corpus)
//   output {capability: root without sig/pq_sig, sig_len, pq_sig_len, principal, scopes, ok}
import * as M0 from '@atlasauth/pca-idjag';
import * as K0 from '../../../packages/pca/src/keys';
import * as C0 from '../../../packages/pca/src/capability';
import * as Q0 from '../../../packages/pca/src/pq';
import { Oracle, seed, refWrite } from './lib.mjs';

const M: any = (M0 as any).default ?? M0;
const K: any = { ...((K0 as any).default ?? K0), ...((Q0 as any).default ?? Q0) };
const C: any = (C0 as any).default ?? C0;
const o = new Oracle('idjag-suite-java', 'tools/pca-audit/oracles/idjag-suite-java.mts', 'TS-reference oracle for the post-quantum root capability of an ID-JAG.');
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const un = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const HOLDER = b64(K.publicKeyOf(seed('idjag/holder')));
const grant: any = { iss: 'https://idp.example.com', sub: 'alice', actor: { sub: 'agent-1' }, agent: 'agent-1', audience: 'https://rs.example.com', scopes: ['read', 'write'], iat: 1_700_000_000, exp: 4_000_000_000, jti: 'jti-1',
  oidcClaims: { iss: 'https://idp.example.com', sub: 'alice', aud: 'https://rs.example.com', iat: 1_700_000_000, exp: 4_000_000_000 } };
const suiteOf = (alg: string, pq: string) => (alg === 'ed25519' ? { alg } : alg.endsWith('ml-dsa-87') ? { alg, mlDsa87: K.mlDsa87Keygen(un(pq)) } : { alg, mlDsa: K.mlDsa65Keygen(un(pq)) });
const len = (v: any) => (typeof v === 'string' ? Buffer.from(v, 'base64url').length : null);
const f = (gr: any, label: string, alg: string, pq: string, pub?: string) => {
  const sk = seed(label);
  const principalPublic = pub ?? b64(K.publicKeyOf(sk));
  const r = M.idJagToCapability(gr, { principalSecret: sk, principalPublic, holder: HOLDER, suite: suiteOf(alg, pq) });
  const { sig, pq_sig, ...capability } = r.capability;
  const pins = capability.pq_pk === undefined ? {} : { pqPins: { [principalPublic]: capability.pq_pk } };
  const ok = C.verifyChain([r.capability], principalPublic, pins).ok === true;
  return { capability, sig_len: len(sig), pq_sig_len: len(pq_sig), principal: r.principal, scopes: r.scopes, ok };
};
const PQ = [b64(seed('ijs/pq1')), b64(seed('ijs/pq2'))];
let n = 0;
for (const alg of ['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65', 'hybrid-nested-ed25519-ml-dsa-65', 'ml-dsa-87', 'hybrid-ed25519-ml-dsa-87'])
  for (const [i, label] of ['idjag/principal', 'idjag/principal2'].entries()) await o.run('idJagToCapabilitySuite', `${alg}#${n++}`, f, [grant, label, alg, PQ[i]]);
await o.run('idJagToCapabilitySuite', 'no-scopes', f, [{ ...grant, scopes: [] }, 'idjag/principal', 'ml-dsa-65', PQ[0]]);
refWrite(o, 'idjag-suite-java');
