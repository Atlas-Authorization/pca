// k05 differential oracle: build provenance as a K1 discharge (packages/pca/src/provenance-gate.ts).
// Natives: Java ProvenanceGate.java (and every port). See README.md for the per-fn porting note.
//   packages/pca/node_modules/tsx/dist/cli.mjs --tsconfig tools/pca-audit/k05-oracles/tsconfig.json tools/pca-audit/k05-oracles/provgate-oracle.mts
import { createHash } from 'node:crypto';
import * as P from '../../../packages/pca/src/index.ts';
import { Oracle, variants, rng, around } from './lib.mjs';

const p: any = (P as any).provenanceGate ? P : (P as any).default;
const O = new Oracle('provgate', 'tools/pca-audit/k05-oracles/provgate-oracle.mts', 'TS-reference oracle for ProvenanceGate: facts / policy shape, the gate (every refusal code), RFC 9162 inclusion proofs (real and tampered), the leaf hash and the caveat builder.');
const used = new Map<string, number>();
const run = (fn: string, n: string, ref: any, a: any[]) => { const k = `${fn}/${n}`; const c = used.get(k) ?? 0; used.set(k, c + 1); return O.run(fn, c ? `${n} #${c}` : n, ref, a); };

const hex = (l: string, n = 64) => createHash(n === 64 ? 'sha256' : 'sha512').update(`k05provgate/${l}`).digest('hex');
const S256 = { alg: 'sha256', digest: hex('img') };
const S512 = { alg: 'sha512', digest: hex('img512', 128) };
const REPO = 'https://github.com/acme/app';
const FACTS = {
  v: 1, predicate_type: 'https://slsa.dev/provenance/v1', build_type: 'https://actions.github.io/buildtypes/workflow/v1', builder_id: 'https://github.com/actions/runner/github-hosted',
  subjects: [S256], identity: 'https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v1', oidc_issuer: 'https://token.actions.githubusercontent.com',
  source_repo: REPO, source_ref: 'refs/tags/v1', source_digest: hex('commit').slice(0, 40), provenance_source: { uri: `git+${REPO}@refs/tags/v1`, git_commit: hex('commit').slice(0, 40) },
  integrated_time: 1_792_929_000, rekor_log_index: 123456,
};
const ROOT = { oidc_issuer: FACTS.oidc_issuer, identity_prefix: 'https://github.com/acme/', builder_id: FACTS.builder_id, level: 3 };
const POLICY = { roots: [ROOT], min_level: 2, source_repo: REPO, source_ref_prefix: 'refs/tags/', build_types: [FACTS.build_type], max_age_s: 3600, require_runtime: false };
const NOW = 1_792_929_600;

// ---------------------------------------------------------------- shapes
for (const [l, v] of variants(FACTS, { lens: [2048, 2049] })) await run('provenanceFactsError', l, p.provenanceFactsError, [v]);
for (const k of ['predicate_type', 'build_type', 'builder_id', 'identity', 'oidc_issuer', 'source_repo', 'source_ref', 'source_digest'])
  for (const s of around(2048)) await run('provenanceFactsError', `${k} ${Buffer.byteLength(s)}B/${s.length}u`, p.provenanceFactsError, [{ ...FACTS, [k]: s }]);
for (const n of [0, 1, 63, 64, 65]) await run('provenanceFactsError', `subjects ${n}`, p.provenanceFactsError, [{ ...FACTS, subjects: Array.from({ length: n }, () => S256) }]);
const subj: [string, any][] = [['sha512', S512], ['upper hex', { alg: 'sha256', digest: hex('x').toUpperCase() }], ['63 hex', { alg: 'sha256', digest: hex('x').slice(1) }], ['65 hex', { alg: 'sha256', digest: hex('x') + 'a' }],
  ['128 for sha256', { alg: 'sha256', digest: hex('x', 128) }], ['64 for sha512', { alg: 'sha512', digest: hex('x') }], ['g char', { alg: 'sha256', digest: 'g' + hex('x').slice(1) }], ['alg SHA256', { alg: 'SHA256', digest: hex('x') }],
  ['alg sha384', { alg: 'sha384', digest: hex('x') }], ['extra member', { ...S256, x: 1 }], ['no digest', { alg: 'sha256' }], ['digest number', { alg: 'sha256', digest: 5 }], ['array', [S256]], ['null', null], ['non-ascii hex', { alg: 'sha256', digest: '١' + hex('x').slice(1) }]];
for (const [l, s] of subj) await run('provenanceFactsError', `subject ${l}`, p.provenanceFactsError, [{ ...FACTS, subjects: [S256, s] }]);
for (const [l, ps] of [['uri only', { uri: 'git+x' }], ['empty uri', { uri: '' }], ['commit empty', { uri: 'u', git_commit: '' }], ['extra', { uri: 'u', x: 1 }], ['null', null], ['array', []], ['uri 2049', { uri: 'u'.repeat(2049) }]] as const)
  await run('provenanceFactsError', `provenance_source ${l}`, p.provenanceFactsError, [{ ...FACTS, provenance_source: ps }]);
for (const [l, v] of variants(POLICY, { lens: [2048, 2049, 9, 10] })) await run('provenancePolicyError', l, p.provenancePolicyError, [v]);
for (const n of [0, 1, 32, 33]) await run('provenancePolicyError', `roots ${n}`, p.provenancePolicyError, [{ ...POLICY, roots: Array.from({ length: n }, () => ROOT) }]);
for (const n of [0, 1, 16, 17]) await run('provenancePolicyError', `build_types ${n}`, p.provenancePolicyError, [{ ...POLICY, build_types: Array.from({ length: n }, (_, i) => `b${i}`) }]);
const rootV: [string, any][] = [['identity exact', { oidc_issuer: 'i', identity: 'x', builder_id: 'b', level: 1 }], ['both', { ...ROOT, identity: 'x' }], ['neither', { oidc_issuer: 'i', builder_id: 'b', level: 1 }],
  ['prefix 9', { ...ROOT, identity_prefix: 'https://a' }], ['prefix 10', { ...ROOT, identity_prefix: 'https://ab' }], ['prefix 10 units 4-byte', { ...ROOT, identity_prefix: '😀'.repeat(5) }], ['prefix 9 units multibyte', { ...ROOT, identity_prefix: 'é'.repeat(9) }],
  ['identity empty', { oidc_issuer: 'i', identity: '', builder_id: 'b', level: 1 }], ['identity null', { oidc_issuer: 'i', identity: null, builder_id: 'b', level: 1 }], ['prefix null', { ...ROOT, identity_prefix: null }],
  ['level 0', { ...ROOT, level: 0 }], ['level 4', { ...ROOT, level: 4 }], ['level 2.0', { ...ROOT, level: 2.0 }], ['level 2.5', { ...ROOT, level: 2.5 }], ['level "2"', { ...ROOT, level: '2' }], ['level -0', { ...ROOT, level: -0 }],
  ['issuer empty', { ...ROOT, oidc_issuer: '' }], ['builder num', { ...ROOT, builder_id: 1 }], ['extra', { ...ROOT, x: 1 }], ['array', [ROOT]]];
for (const [l, r] of rootV) await run('provenancePolicyError', `root ${l}`, p.provenancePolicyError, [{ ...POLICY, roots: [ROOT, r] }]);
for (const ml of [0, 1, 2, 3, 4, 1.5, '2', null, -0]) await run('provenancePolicyError', `min_level ${JSON.stringify(ml)}`, p.provenancePolicyError, [{ ...POLICY, min_level: ml }]);
for (const ma of [0, 1, -1, 1.5, 2 ** 53 - 1, 2 ** 53, '60']) await run('provenancePolicyError', `max_age_s ${JSON.stringify(ma)}`, p.provenancePolicyError, [{ ...POLICY, max_age_s: ma }]);
await run('provenancePolicyError', 'source_ref and prefix', p.provenancePolicyError, [{ ...POLICY, source_ref: 'refs/tags/v1' }]);
await run('provenancePolicyError', 'source_ref alone', p.provenancePolicyError, [{ roots: [ROOT], min_level: 1, source_ref: 'refs/tags/v1' }]);
await run('provenancePolicyError', 'source_ref empty', p.provenancePolicyError, [{ roots: [ROOT], min_level: 1, source_ref: '' }]);
await run('provenancePolicyError', 'minimal', p.provenancePolicyError, [{ roots: [ROOT], min_level: 1 }]);

// ---------------------------------------------------------------- the gate
const gate = p.provenanceGate;
const G = (o: any = {}) => ({ facts: FACTS, policy: POLICY, now: NOW, ...o });
await run('provenanceGate', 'pass', gate, [G()]);
for (const [l, v] of variants(G({ runtime: S256 }), { maxPaths: 120, depth: 3 })) await run('provenanceGate', `struct ${l}`, gate, [v]);
const F = (o: any) => ({ ...FACTS, ...o });
const PO = (o: any) => ({ ...POLICY, ...o });
const gcases: [string, any][] = [
  ['predicate v0.2', G({ facts: F({ predicate_type: 'https://slsa.dev/provenance/v0.2' }) })],
  ['future by 1', G({ facts: F({ integrated_time: NOW + 1 }) })], ['now exactly', G({ facts: F({ integrated_time: NOW }) })],
  ['age = max', G({ facts: F({ integrated_time: NOW - 3600 }) })], ['age = max+1', G({ facts: F({ integrated_time: NOW - 3601 }) })], ['no max age, ancient', G({ facts: F({ integrated_time: 0 }), policy: PO({ max_age_s: undefined }) })],
  ['now negative', G({ now: -1 })], ['now fraction', G({ now: NOW + 0.5 })], ['now string', G({ now: String(NOW) })], ['now missing', { facts: FACTS, policy: POLICY }], ['input null', null], ['input array', []],
  ['bad policy and facts', G({ policy: {}, facts: {} })], ['bad facts only', G({ facts: {} })],
  ['no root: issuer', G({ facts: F({ oidc_issuer: 'https://other' }) })], ['no root: builder', G({ facts: F({ builder_id: 'b' }) })], ['no root: identity prefix', G({ facts: F({ identity: 'https://github.com/evil/app' }) })],
  ['exact identity root', G({ policy: PO({ roots: [{ oidc_issuer: FACTS.oidc_issuer, identity: FACTS.identity, builder_id: FACTS.builder_id, level: 2 }] }) })],
  ['exact identity off by one', G({ policy: PO({ roots: [{ oidc_issuer: FACTS.oidc_issuer, identity: FACTS.identity + 'x', builder_id: FACTS.builder_id, level: 2 }] }) })],
  ['level below min', G({ policy: PO({ roots: [{ ...ROOT, level: 1 }] }) })], ['level = min', G({ policy: PO({ roots: [{ ...ROOT, level: 2 }] }) })],
  ['highest of matching roots', G({ policy: PO({ roots: [{ ...ROOT, level: 1 }, { ...ROOT, level: 3 }, { ...ROOT, level: 2 }] }) })], ['non-matching high root', G({ policy: PO({ roots: [{ ...ROOT, level: 1 }, { ...ROOT, builder_id: 'x', level: 3 }] }) })],
  ['commit mismatch', G({ facts: F({ source_digest: hex('other').slice(0, 40) }) })], ['commit absent in prov', G({ facts: F({ provenance_source: { uri: `git+${REPO}@refs/tags/v1` } }) })], ['digest absent in cert', G({ facts: F({ source_digest: undefined }) })],
  ['uri equal repo', G({ facts: F({ provenance_source: { uri: `git+${REPO}` } }) })], ['uri other repo', G({ facts: F({ provenance_source: { uri: `git+${REPO}-evil@refs/tags/v1` } }) })], ['uri repo prefix no @', G({ facts: F({ provenance_source: { uri: `git+${REPO}x` } }) })],
  ['uri without git+', G({ facts: F({ provenance_source: { uri: REPO } }) })], ['no provenance_source', G({ facts: F({ provenance_source: undefined }) })], ['no cert repo', G({ facts: F({ source_repo: undefined }), policy: PO({ source_repo: undefined }) })],
  ['policy repo mismatch', G({ policy: PO({ source_repo: REPO + '2' }) })], ['policy repo, facts none', G({ facts: F({ source_repo: undefined, provenance_source: undefined }) })],
  ['ref exact ok', G({ policy: PO({ source_ref_prefix: undefined, source_ref: 'refs/tags/v1' }) })], ['ref exact mismatch', G({ policy: PO({ source_ref_prefix: undefined, source_ref: 'refs/tags/v2' }) })],
  ['ref prefix mismatch', G({ policy: PO({ source_ref_prefix: 'refs/heads/' }) })], ['ref prefix, facts none', G({ facts: F({ source_ref: undefined }) })], ['ref exact, facts none', G({ facts: F({ source_ref: undefined }), policy: PO({ source_ref_prefix: undefined, source_ref: 'refs/tags/v1' }) })],
  ['build type not listed', G({ policy: PO({ build_types: ['x'] }) })], ['build types absent', G({ policy: PO({ build_types: undefined }) })],
  ['runtime match', G({ runtime: S256 })], ['runtime other', G({ runtime: { alg: 'sha256', digest: hex('other') } })], ['runtime alg differs same hex', G({ runtime: { alg: 'sha512', digest: hex('img512', 128) }, facts: F({ subjects: [S256, { alg: 'sha256', digest: hex('img512', 128).slice(0, 64) }] }) })],
  ['runtime malformed', G({ runtime: { alg: 'sha256', digest: 'x' } })], ['runtime null', G({ runtime: null })], ['runtime required, absent', G({ policy: PO({ require_runtime: true }) })], ['runtime required, present', G({ policy: PO({ require_runtime: true }), runtime: S256 })],
  ['two subjects, no runtime', G({ facts: F({ subjects: [S256, S512] }) })], ['two subjects, runtime second', G({ facts: F({ subjects: [S256, S512] }), runtime: S512 })], ['dup subjects, runtime', G({ facts: F({ subjects: [S256, S256] }), runtime: S256 })],
  ['claim identity 256', G({ facts: F({ identity: 'https://github.com/acme/' + 'a'.repeat(256 - 24) }) })], ['claim identity 257', G({ facts: F({ identity: 'https://github.com/acme/' + 'a'.repeat(257 - 24) }) })],
  ['claim builder 257', G({ facts: F({ builder_id: 'b'.repeat(257) }), policy: PO({ roots: [{ ...ROOT, builder_id: 'b'.repeat(257) }] }) })], ['claim ref 257 multibyte', G({ facts: F({ source_ref: 'refs/tags/' + 'é'.repeat(124) }) })],
  ['claim build_type 257', G({ facts: F({ build_type: 't'.repeat(257) }), policy: PO({ build_types: undefined }) })], ['claim digest 257 (not checked by facts)', G({ facts: F({ source_digest: 'd'.repeat(257), provenance_source: undefined }) })],
  ['level 1 min 1', G({ policy: PO({ min_level: 1, roots: [{ ...ROOT, level: 1 }] }) })],
];
for (const [l, g] of gcases) await run('provenanceGate', l, gate, [g]);
// a seeded random walk over the gate's input space
const R = rng(0x9a7e);
const pick = R.pick;
for (let i = 0; i < 1500; i++) {
  const facts: any = F({
    predicate_type: pick([FACTS.predicate_type, FACTS.predicate_type, 'x']), oidc_issuer: pick([FACTS.oidc_issuer, 'https://o']), builder_id: pick([FACTS.builder_id, 'B']),
    identity: pick([FACTS.identity, 'https://github.com/acme/x', 'https://github.com/other/x', 'https://github.com/acme']), integrated_time: NOW - pick([0, 1, 3599, 3600, 3601, -1, 100000]),
    subjects: pick([[S256], [S512], [S256, S512], [S512, S256]]), source_repo: pick([REPO, REPO, undefined, REPO + 'x']), source_ref: pick(['refs/tags/v1', 'refs/heads/main', undefined]),
    source_digest: pick([FACTS.source_digest, undefined, 'abc']), provenance_source: pick([FACTS.provenance_source, undefined, { uri: `git+${REPO}` }, { uri: 'git+x', git_commit: 'abc' }]),
  });
  for (const k of Object.keys(facts)) if (facts[k] === undefined) delete facts[k];
  const roots = Array.from({ length: R.int(1, 3) }, () => {
    const r: any = { oidc_issuer: pick([FACTS.oidc_issuer, 'https://o']), builder_id: pick([FACTS.builder_id, 'B']), level: pick([1, 2, 3]) };
    if (R.next() < 0.5) r.identity = pick([FACTS.identity, 'https://github.com/acme/x']);
    else r.identity_prefix = pick(['https://github.com/acme/', 'https://github.com/', 'https://github.com/acme/x']);
    return r;
  });
  const policy: any = { roots, min_level: pick([1, 2, 3]) };
  if (R.next() < 0.5) policy.source_repo = pick([REPO, REPO + 'x']);
  const rr = R.int(0, 2);
  if (rr === 1) policy.source_ref = pick(['refs/tags/v1', 'refs/heads/main']);
  if (rr === 2) policy.source_ref_prefix = pick(['refs/tags/', 'refs/']);
  if (R.next() < 0.4) policy.build_types = pick([[FACTS.build_type], ['x'], ['x', FACTS.build_type]]);
  if (R.next() < 0.6) policy.max_age_s = pick([1, 3600, 100000]);
  if (R.next() < 0.4) policy.require_runtime = pick([true, false]);
  const g: any = { facts, policy, now: NOW };
  if (R.next() < 0.5) g.runtime = pick([S256, S512, { alg: 'sha256', digest: hex('z') }]);
  await run('provenanceGate', `walk ${i}`, gate, [g]);
}

// ---------------------------------------------------------------- RFC 9162 inclusion
const sha = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest());
const leafH = (d: Uint8Array) => sha(Buffer.concat([Buffer.from([0]), d]));
const nodeH = (l: Uint8Array, r: Uint8Array) => sha(Buffer.concat([Buffer.from([1]), l, r]));
const kpow = (n: number) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
function mth(ls: Uint8Array[]): Uint8Array { if (ls.length === 1) return ls[0]!; const k = kpow(ls.length); return nodeH(mth(ls.slice(0, k)), mth(ls.slice(k))); }
function path(m: number, ls: Uint8Array[]): Uint8Array[] { if (ls.length === 1) return []; const k = kpow(ls.length); return m < k ? [...path(m, ls.slice(0, k)), mth(ls.slice(k))] : [...path(m - k, ls.slice(k)), mth(ls.slice(0, k))]; }
const b = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const ub = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
// wire form: (leaf b64u, index, size, [proof b64u], root b64u)
const incl = (leaf: string, index: number, size: number, proof: string[], root: string) => p.verifyRfc9162Inclusion(ub(leaf), index, size, proof.map(ub), ub(root));
const flip = (u: Uint8Array, i = 0) => { const c = new Uint8Array(u); c[i % c.length] ^= 1; return c; };
for (const n of [1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 16, 17, 31, 33, 100]) {
  const leaves = Array.from({ length: n }, (_, i) => leafH(new TextEncoder().encode(`leaf ${i}`)));
  const root = mth(leaves);
  const idxs = n <= 17 ? [...Array(n).keys()] : [0, 1, n >> 1, n - 2, n - 1];
  for (const m of idxs) {
    const pf = path(m, leaves);
    const t = `n${n} m${m}`;
    await run('verifyRfc9162Inclusion', `${t} ok`, incl, [b(leaves[m]!), m, n, pf.map(b), b(root)]);
    for (let j = 0; j < pf.length; j++) await run('verifyRfc9162Inclusion', `${t} sibling ${j} flipped`, incl, [b(leaves[m]!), m, n, pf.map((x, i) => b(i === j ? flip(x, j * 7) : x)), b(root)]);
    if (n <= 9 || m === 0) {
      await run('verifyRfc9162Inclusion', `${t} index+1`, incl, [b(leaves[m]!), m + 1, n, pf.map(b), b(root)]);
      await run('verifyRfc9162Inclusion', `${t} index-1`, incl, [b(leaves[m]!), m - 1, n, pf.map(b), b(root)]);
      await run('verifyRfc9162Inclusion', `${t} size+1`, incl, [b(leaves[m]!), m, n + 1, pf.map(b), b(root)]);
      await run('verifyRfc9162Inclusion', `${t} size-1`, incl, [b(leaves[m]!), m, n - 1, pf.map(b), b(root)]);
      await run('verifyRfc9162Inclusion', `${t} proof truncated`, incl, [b(leaves[m]!), m, n, pf.slice(0, -1).map(b), b(root)]);
      await run('verifyRfc9162Inclusion', `${t} proof extended`, incl, [b(leaves[m]!), m, n, [...pf, root].map(b), b(root)]);
      await run('verifyRfc9162Inclusion', `${t} proof reversed`, incl, [b(leaves[m]!), m, n, [...pf].reverse().map(b), b(root)]);
      await run('verifyRfc9162Inclusion', `${t} leaf flipped`, incl, [b(flip(leaves[m]!, 31)), m, n, pf.map(b), b(root)]);
      await run('verifyRfc9162Inclusion', `${t} root flipped`, incl, [b(leaves[m]!), m, n, pf.map(b), b(flip(root, 5))]);
      await run('verifyRfc9162Inclusion', `${t} other leaf`, incl, [b(leaves[(m + 1) % n]!), m, n, pf.map(b), b(root)]);
      await run('verifyRfc9162Inclusion', `${t} size doubled`, incl, [b(leaves[m]!), m, 2 * n, pf.map(b), b(root)]);
    }
  }
}
{ // shape limits
  const L = leafH(new Uint8Array([1]));
  const z = new Uint8Array(32);
  for (const [l, a] of [
    ['size 0', [b(L), 0, 0, [], b(L)]], ['index = size', [b(L), 1, 1, [], b(L)]], ['index -1', [b(L), -1, 1, [], b(L)]], ['size 1 leaf=root', [b(L), 0, 1, [], b(L)]], ['size 1 leaf!=root', [b(L), 0, 1, [], b(z)]],
    ['size 1 with proof', [b(L), 0, 1, [b(z)], b(L)]], ['leaf 31 bytes', [b(L.slice(1)), 0, 1, [], b(L)]], ['leaf 33 bytes', [b(new Uint8Array([...L, 0])), 0, 1, [], b(L)]], ['root 31', [b(L), 0, 1, [], b(L.slice(1))]],
    ['proof elem 31', [b(L), 0, 2, [b(z.slice(1))], b(L)]], ['proof elem 33', [b(L), 0, 2, [b(new Uint8Array(33))], b(L)]], ['proof 64 elems', [b(L), 0, 2 ** 52, Array.from({ length: 64 }, () => b(z)), b(L)]],
    ['proof 65 elems', [b(L), 0, 2 ** 52, Array.from({ length: 65 }, () => b(z)), b(L)]], ['size 2^53-1', [b(L), 0, 2 ** 53 - 1, [], b(L)]], ['size 2^53', [b(L), 0, 2 ** 53, [], b(L)]], ['empty leaf', ['', 0, 1, [], b(L)]],
  ] as const) await run('verifyRfc9162Inclusion', `shape ${l}`, incl, a as any);
  // a deep right-edge path in a huge tree (BigInt range): size 2^40+1, last index
  const big = 2 ** 40 + 1;
  let r = L;
  const pf: Uint8Array[] = [];
  // index big-1 is the lone right child at the top: the proof is the single left subtree root
  const left = sha(new TextEncoder().encode('left subtree'));
  pf.push(left);
  r = nodeH(left, L);
  await run('verifyRfc9162Inclusion', 'size 2^40+1 last', incl, [b(L), big - 1, big, pf.map(b), b(r)]);
  await run('verifyRfc9162Inclusion', 'size 2^40+1 last, index-1', incl, [b(L), big - 2, big, pf.map(b), b(r)]);
}
for (const d of ['', 'AA', b(new Uint8Array(32)), b(new TextEncoder().encode('hello'))]) await run('rfc9162LeafHash', `data ${d.length}`, (x: string) => p.rfc9162LeafHash(ub(x)), [d]);

// ---------------------------------------------------------------- caveat builder
const cav: [string, any][] = [['minimal', { issuer: 'slsa', min_level: 2 }], ['all', { id: 'prov', issuer: 'slsa', min_level: 3, source_repo: REPO, builder_ids: ['b1', 'b2'], oidc_issuer: 'https://o', require_runtime: true, bind: 'chain_hop', ttl_ms: 60000 }],
  ['runtime off', { issuer: 'slsa', min_level: 1, require_runtime: false }], ['bind action ttl 1', { issuer: 'slsa', min_level: 1, bind: 'action', ttl_ms: 1 }]];
for (const [l, o] of cav) await run('provenanceCaveat', l, p.provenanceCaveat, [o]);

O.write();
