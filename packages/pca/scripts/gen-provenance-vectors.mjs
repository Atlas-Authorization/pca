// conformance/provenance-vectors.json: build provenance gates (track K9).
//
// ONE generator owns the file. Every `expect` is computed by the TypeScript reference (provenance-gate.ts) AND asserted
// against what the vector is meant to show (`want`). The Go, Rust, Python, Ruby, PHP, Java, Kotlin, .NET and Swift
// verifiers replay it and must reproduce every expectation exactly.
//
//   primitives.merkle_inclusion  RFC 9162 section 2.1.3.2 over hex inputs:
//                                { leaf_hex (the raw leaf data), index, size, proof_hex[], root_hex } -> { ok }
//                                The real entry is a Rekor v1 inclusion proof taken from a public Sigstore bundle; the small
//                                trees are built here by the recursive MTH / PATH definitions of RFC 9162 section 2.1, not by
//                                the verifier under test.
//   primitives.gate              provenanceGate({ facts, policy, runtime?, now }) -> { ok: true, level, claims } | { ok: false, code }
//   primitives.model_path        isModelDerivedPath(path) -> { model } (env.detect.* is model-derived, rule 21)
// Deterministic.
//
//     node packages/pca/scripts/gen-provenance-vectors.mjs [--check]                 (reads ../dist)
//     PCA_SRC=1 packages/pca/node_modules/.bin/tsx packages/pca/scripts/gen-provenance-vectors.mjs  (reads ../src)
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { confDir, serializeCorpus } from './conformance-io.mjs';

const pca = process.env.PCA_SRC ? await import('../src/index.ts') : await import('../dist/index.js');
const OUT = join(confDir, 'provenance-vectors.json');
const here = dirname(fileURLToPath(import.meta.url));
const FIX = join(here, '..', '..', 'pca-attest-eat', 'test-fixtures', 'sigstore', 'npm-sigstore-5.0.0.attestations.json');

const hex = (b) => Buffer.from(b).toString('hex');
const unhex = (h) => new Uint8Array(Buffer.from(h, 'hex'));
const sha = (...parts) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return new Uint8Array(h.digest()); };

// ------------------------------------------------------------------ merkle_inclusion
const merkle = [];
function mi(name, description, v, want) {
  const ok = pca.verifyRfc9162Inclusion(pca.rfc9162LeafHash(unhex(v.leaf_hex)), v.index, v.size, v.proof_hex.map(unhex), unhex(v.root_hex));
  if (ok !== want) throw new Error(`${name}: reference says ${ok}, vector wants ${want}`);
  merkle.push({ name, description, input: v, expect: { ok } });
}
// independent tree: RFC 9162 2.1.1 MTH and 2.1.3.1 PATH, recursive
const leafH = (d) => sha(Buffer.from([0]), d);
const nodeH = (l, r) => sha(Buffer.from([1]), l, r);
const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
const mth = (D) => (D.length === 1 ? leafH(D[0]) : nodeH(mth(D.slice(0, split(D.length))), mth(D.slice(split(D.length)))));
const path = (m, D) => {
  if (D.length === 1) return [];
  const k = split(D.length);
  return m < k ? [...path(m, D.slice(0, k)), mth(D.slice(k))] : [...path(m - k, D.slice(k)), mth(D.slice(0, k))];
};
{
  const bundle = JSON.parse(readFileSync(FIX, 'utf8')).attestations.find((a) => a.predicateType === 'https://slsa.dev/provenance/v1').bundle;
  const t = bundle.verificationMaterial.tlogEntries[0];
  const p = t.inclusionProof;
  const real = { leaf_hex: hex(Buffer.from(t.canonicalizedBody, 'base64')), index: Number(p.logIndex), size: Number(p.treeSize), proof_hex: p.hashes.map((h) => hex(Buffer.from(h, 'base64'))), root_hex: hex(Buffer.from(p.rootHash, 'base64')) };
  mi('rekor-real', 'a Rekor v1 inclusion proof from a public Sigstore bundle (index and size above 2^30)', real, true);
  mi('rekor-leaf-tampered', 'one byte of the entry body changed', { ...real, leaf_hex: real.leaf_hex.replace(/^../, (c) => (c === '7b' ? '7c' : '7b')) }, false);
  mi('rekor-index-plus-one', 'the right proof at the wrong index', { ...real, index: real.index + 1 }, false);
  mi('rekor-size-plus-one', 'the same path shape at size + 1 still verifies: a proof alone does not bind the size, the signed checkpoint does', { ...real, size: real.size + 1 }, true);
  mi('rekor-size-halved', 'a size that changes the path shape', { ...real, size: Math.floor(real.size / 2) + 1, index: Math.floor(real.size / 2) }, false);
  mi('rekor-root-flipped', 'another root', { ...real, root_hex: real.root_hex.replace(/.$/, (c) => (c === '0' ? '1' : '0')) }, false);
  mi('rekor-proof-truncated', 'the last hash dropped', { ...real, proof_hex: real.proof_hex.slice(0, -1) }, false);
  mi('rekor-proof-extended', 'one hash too many', { ...real, proof_hex: [...real.proof_hex, real.root_hex] }, false);
  mi('rekor-proof-swapped', 'two hashes swapped', { ...real, proof_hex: [real.proof_hex[1], real.proof_hex[0], ...real.proof_hex.slice(2)] }, false);
  mi('rekor-index-eq-size', 'index equal to size', { ...real, index: real.size }, false);
}
for (const n of [1, 2, 3, 5, 7, 8]) {
  const D = Array.from({ length: n }, (_, i) => new Uint8Array(Buffer.from(`leaf-${n}-${i}`)));
  const root = hex(mth(D));
  for (let m = 0; m < n; m++) mi(`tree-${n}-${m}`, `RFC 9162 tree of ${n} leaves, leaf ${m}`, { leaf_hex: hex(D[m]), index: m, size: n, proof_hex: path(m, D).map(hex), root_hex: root }, true);
  if (n > 1) mi(`tree-${n}-wrong-leaf`, `tree of ${n}: leaf 0 presented with the path of leaf ${n - 1}`, { leaf_hex: hex(D[0]), index: n - 1, size: n, proof_hex: path(n - 1, D).map(hex), root_hex: root }, false);
}
mi('size-zero', 'an empty tree has no leaf', { leaf_hex: '00', index: 0, size: 0, proof_hex: [], root_hex: hex(sha(Buffer.alloc(0))) }, false);
mi('one-leaf-extra-hash', 'a one-leaf tree with a non-empty proof', { leaf_hex: hex(Buffer.from('x')), index: 0, size: 1, proof_hex: [hex(sha(Buffer.from('y')))], root_hex: hex(leafH(Buffer.from('x'))) }, false);
mi('short-hash', 'a proof hash of 31 bytes', { leaf_hex: hex(Buffer.from('leaf-2-0')), index: 0, size: 2, proof_hex: [hex(sha(Buffer.from('z'))).slice(2)], root_hex: hex(sha(Buffer.from('r'))) }, false);

// ------------------------------------------------------------------ gate
const gate = [];
const NOW = 1_780_400_000;
const REPO = 'https://github.com/acme/tool';
const IDENT = `${REPO}/.github/workflows/release.yml@refs/tags/v1.2.3`;
const GHA = 'https://token.actions.githubusercontent.com';
const BUILDER = 'https://github.com/actions/runner/github-hosted';
const REUSABLE = 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0';
const D256 = 'ab'.repeat(32);
const D512 = 'cd'.repeat(64);
const COMMIT = '7d2900eca1c22b3f87c13987c8d4b7c9a29b733a';
const facts = (o = {}) => ({
  v: 1, predicate_type: 'https://slsa.dev/provenance/v1', build_type: 'https://actions.github.io/buildtypes/workflow/v1', builder_id: BUILDER,
  subjects: [{ alg: 'sha256', digest: D256 }], identity: IDENT, oidc_issuer: GHA, source_repo: REPO, source_ref: 'refs/tags/v1.2.3', source_digest: COMMIT,
  provenance_source: { uri: `git+${REPO}@refs/tags/v1.2.3`, git_commit: COMMIT }, integrated_time: NOW - 3600, rekor_log_index: 1697019812, ...o,
});
const root2 = { oidc_issuer: GHA, identity_prefix: `${REPO}/.github/workflows/release.yml@refs/tags/`, builder_id: BUILDER, level: 2 };
const root3 = { oidc_issuer: GHA, identity_prefix: 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v', builder_id: REUSABLE, level: 3 };
const policy = (o = {}) => ({ roots: [root2, root3], min_level: 2, source_repo: REPO, ...o });
function g(name, description, raw, want) {
  const input = JSON.parse(JSON.stringify(raw)); // an undefined member means absent, as on the wire
  const r = pca.provenanceGate(input);
  const expect = r.ok ? { ok: true, level: r.level, claims: r.claims } : { ok: false, code: r.code };
  if (want.ok !== expect.ok || (want.code !== undefined && want.code !== expect.code) || (want.level !== undefined && want.level !== expect.level)) throw new Error(`${name}: reference ${JSON.stringify(expect)} vs want ${JSON.stringify(want)}`);
  gate.push({ name, description, input, expect });
}
const rt = { alg: 'sha256', digest: D256 };
g('ok-runtime-bound', 'a pinned pair, level 2, the running image digest is the subject', { facts: facts(), policy: policy(), runtime: rt, now: NOW }, { ok: true, level: 2 });
g('ok-no-runtime-one-subject', 'no runtime digest and one subject: not runtime bound', { facts: facts(), policy: policy(), now: NOW }, { ok: true, level: 2 });
g('ok-level3-reusable', 'the reusable SLSA generator workflow is pinned at level 3', { facts: facts({ builder_id: REUSABLE, identity: `${root3.identity_prefix}2.1.0` }), policy: policy({ min_level: 3 }), runtime: rt, now: NOW }, { ok: true, level: 3 });
g('ok-exact-identity', 'an exact identity root', { facts: facts(), policy: policy({ roots: [{ oidc_issuer: GHA, identity: IDENT, builder_id: BUILDER, level: 2 }] }), runtime: rt, now: NOW }, { ok: true, level: 2 });
g('ok-highest-matching-level', 'two matching roots: the higher level wins', { facts: facts(), policy: policy({ roots: [root2, { ...root2, level: 1 }] }), runtime: rt, now: NOW }, { ok: true, level: 2 });
g('ok-sha512-subject', 'a sha512 subject joined to a sha512 runtime digest', { facts: facts({ subjects: [{ alg: 'sha256', digest: D256 }, { alg: 'sha512', digest: D512 }] }), policy: policy(), runtime: { alg: 'sha512', digest: D512 }, now: NOW }, { ok: true });
g('ok-no-source-pin', 'a policy without a source pin', { facts: facts(), policy: policy({ source_repo: undefined }), runtime: rt, now: NOW }, { ok: true });
g('ok-ref-prefix', 'a tag prefix', { facts: facts(), policy: policy({ source_ref_prefix: 'refs/tags/v' }), runtime: rt, now: NOW }, { ok: true });
g('ok-age-boundary', 'exactly max_age_s old', { facts: facts(), policy: policy({ max_age_s: 3600 }), runtime: rt, now: NOW }, { ok: true });
g('ok-build-type', 'an allowed build type', { facts: facts(), policy: policy({ build_types: ['https://actions.github.io/buildtypes/workflow/v1'] }), runtime: rt, now: NOW }, { ok: true });
g('ok-no-provenance-source', 'the provenance names no resolved dependency', { facts: facts({ provenance_source: undefined }), policy: policy(), runtime: rt, now: NOW }, { ok: true });
g('ok-integrated-now', 'integrated exactly now', { facts: facts({ integrated_time: NOW }), policy: policy(), runtime: rt, now: NOW }, { ok: true });
g('swapped-image', 'the running image is not the one the provenance describes', { facts: facts(), policy: policy(), runtime: { alg: 'sha256', digest: 'ee'.repeat(32) }, now: NOW }, { ok: false, code: 'runtime_mismatch' });
g('runtime-alg-mismatch', 'the right hex under another algorithm', { facts: facts({ subjects: [{ alg: 'sha512', digest: D512 }] }), policy: policy(), runtime: { alg: 'sha256', digest: D512.slice(0, 64) }, now: NOW }, { ok: false, code: 'runtime_mismatch' });
g('runtime-required', 'require_runtime without a runtime digest', { facts: facts(), policy: policy({ require_runtime: true }), now: NOW }, { ok: false, code: 'runtime_required' });
g('subject-ambiguous', 'two subjects and no runtime digest', { facts: facts({ subjects: [{ alg: 'sha256', digest: D256 }, { alg: 'sha256', digest: 'ef'.repeat(32) }] }), policy: policy(), now: NOW }, { ok: false, code: 'subject_ambiguous' });
g('runtime-uppercase', 'an uppercase runtime digest is malformed (no case folding)', { facts: facts(), policy: policy(), runtime: { alg: 'sha256', digest: D256.toUpperCase() }, now: NOW }, { ok: false, code: 'malformed_runtime' });
g('runtime-unknown-alg', 'sha1 runtime digest', { facts: facts(), policy: policy(), runtime: { alg: 'sha1', digest: 'ab'.repeat(20) }, now: NOW }, { ok: false, code: 'malformed_runtime' });
g('no-root-builder', 'a builder id nobody pinned', { facts: facts({ builder_id: 'https://ci.example/builder' }), policy: policy(), runtime: rt, now: NOW }, { ok: false, code: 'no_root' });
g('no-root-issuer', 'the right builder signed under another OIDC issuer', { facts: facts({ oidc_issuer: 'https://accounts.example' }), policy: policy(), runtime: rt, now: NOW }, { ok: false, code: 'no_root' });
g('no-root-identity', 'another repository workflow signed it', { facts: facts({ identity: 'https://github.com/evil/tool/.github/workflows/release.yml@refs/tags/v1.2.3' }), policy: policy(), runtime: rt, now: NOW }, { ok: false, code: 'no_root' });
g('no-root-exact-identity', 'an exact identity root and a branch build', { facts: facts({ identity: `${REPO}/.github/workflows/release.yml@refs/heads/main` }), policy: policy({ roots: [{ oidc_issuer: GHA, identity: IDENT, builder_id: BUILDER, level: 2 }] }), runtime: rt, now: NOW }, { ok: false, code: 'no_root' });
g('level-too-low', 'the GitHub-hosted runner is pinned at level 2, the policy asks for 3', { facts: facts(), policy: policy({ min_level: 3 }), runtime: rt, now: NOW }, { ok: false, code: 'level' });
g('source-repo', 'built from another repository than pinned', { facts: facts({ source_repo: 'https://github.com/acme/other', provenance_source: undefined }), policy: policy(), runtime: rt, now: NOW }, { ok: false, code: 'source_repo' });
g('source-repo-absent', 'the certificate carries no source repository and the policy pins one', { facts: facts({ source_repo: undefined, provenance_source: undefined }), policy: policy(), runtime: rt, now: NOW }, { ok: false, code: 'source_repo' });
g('source-commit-mismatch', 'the provenance names another commit than the certificate', { facts: facts({ provenance_source: { uri: `git+${REPO}@refs/tags/v1.2.3`, git_commit: '0'.repeat(40) } }), policy: policy(), runtime: rt, now: NOW }, { ok: false, code: 'source_mismatch' });
g('source-uri-mismatch', 'the provenance names another repository than the certificate', { facts: facts({ provenance_source: { uri: 'git+https://github.com/acme/tool-fork@refs/tags/v1.2.3', git_commit: COMMIT } }), policy: policy(), runtime: rt, now: NOW }, { ok: false, code: 'source_mismatch' });
g('source-ref', 'an exact ref pin and another ref', { facts: facts(), policy: policy({ source_ref: 'refs/heads/main' }), runtime: rt, now: NOW }, { ok: false, code: 'source_ref' });
g('source-ref-prefix', 'a tag prefix and a branch', { facts: facts({ source_ref: 'refs/heads/main' }), policy: policy({ source_ref_prefix: 'refs/tags/' }), runtime: rt, now: NOW }, { ok: false, code: 'source_ref' });
g('build-type', 'a build type the policy does not allow', { facts: facts(), policy: policy({ build_types: ['https://example/other'] }), runtime: rt, now: NOW }, { ok: false, code: 'build_type' });
g('stale', 'one second older than max_age_s', { facts: facts(), policy: policy({ max_age_s: 3599 }), runtime: rt, now: NOW }, { ok: false, code: 'stale' });
g('future', 'integrated after now', { facts: facts({ integrated_time: NOW + 1 }), policy: policy(), runtime: rt, now: NOW }, { ok: false, code: 'future' });
g('predicate-v02', 'SLSA v0.2 provenance is refused', { facts: facts({ predicate_type: 'https://slsa.dev/provenance/v0.2' }), policy: policy(), runtime: rt, now: NOW }, { ok: false, code: 'predicate_type' });
g('claim-too-long', 'a builder id longer than a K1 claim may be', { facts: facts({ builder_id: `${BUILDER}/${'x'.repeat(300)}` }), policy: policy({ roots: [{ ...root2, builder_id: `${BUILDER}/${'x'.repeat(300)}` }] }), runtime: rt, now: NOW }, { ok: false, code: 'claim_too_long' });
g('facts-unknown-member', 'a member the facts do not define', { facts: { ...facts(), slsa_level: 3 }, policy: policy(), runtime: rt, now: NOW }, { ok: false, code: 'malformed_facts' });
g('facts-no-subject', 'no subjects', { facts: facts({ subjects: [] }), policy: policy(), runtime: rt, now: NOW }, { ok: false, code: 'malformed_facts' });
g('facts-float-time', 'a fractional integrated time', { facts: facts({ integrated_time: NOW - 0.5 }), policy: policy(), runtime: rt, now: NOW }, { ok: false, code: 'malformed_facts' });
g('bad-clock', 'a fractional verifier clock', { facts: facts(), policy: policy(), runtime: rt, now: NOW + 0.5 }, { ok: false, code: 'malformed_facts' });
g('policy-level-zero', 'min_level 0 would accept anything signed', { facts: facts(), policy: policy({ min_level: 0 }), runtime: rt, now: NOW }, { ok: false, code: 'malformed_policy' });
g('policy-no-roots', 'no trusted pairs', { facts: facts(), policy: policy({ roots: [] }), runtime: rt, now: NOW }, { ok: false, code: 'malformed_policy' });
g('policy-both-identities', 'a root with identity and identity_prefix', { facts: facts(), policy: policy({ roots: [{ ...root2, identity: IDENT }] }), runtime: rt, now: NOW }, { ok: false, code: 'malformed_policy' });
g('policy-short-prefix', 'an identity prefix that pins nothing', { facts: facts(), policy: policy({ roots: [{ ...root2, identity_prefix: 'https:' }] }), runtime: rt, now: NOW }, { ok: false, code: 'malformed_policy' });
g('policy-level-4', 'a root claiming level 4', { facts: facts(), policy: policy({ roots: [{ ...root2, level: 4 }] }), runtime: rt, now: NOW }, { ok: false, code: 'malformed_policy' });
g('policy-both-refs', 'source_ref and source_ref_prefix together', { facts: facts(), policy: policy({ source_ref: 'refs/tags/v1.2.3', source_ref_prefix: 'refs/tags/' }), runtime: rt, now: NOW }, { ok: false, code: 'malformed_policy' });
g('policy-unknown-member', 'a policy member nobody defined (a self-asserted level field)', { facts: facts(), policy: { ...policy(), trust_level_claim: true }, runtime: rt, now: NOW }, { ok: false, code: 'malformed_policy' });

// ------------------------------------------------------------------ model_path (rule 21 roots)
const modelPath = [];
for (const [p, want] of [['env.detect.lakera', true], ['env.detect', true], ['env.detect.flagged.x', true], ['env.class.tone', true], ['env.detector.x', false], ['action.params.detect', false], ['env.risk', false]]) {
  const model = pca.isModelDerivedPath(p);
  if (model !== want) throw new Error(`model_path ${p}`);
  modelPath.push({ name: `mp-${p}`, input: { path: p }, expect: { model } });
}

const corpus = {
  format: 'pca-provenance-vectors',
  ver: 1,
  description: 'Generated by packages/pca/scripts/gen-provenance-vectors.mjs from the TypeScript reference (provenance-gate.ts, decision.ts); do not edit.',
  primitives: { merkle_inclusion: merkle, gate, model_path: modelPath },
};
const text = serializeCorpus(corpus);
if (process.argv.includes('--check')) {
  if (readFileSync(OUT, 'utf8') !== text) { console.error(`${OUT} is stale: regenerate it`); process.exit(1); }
  console.log(`${OUT} is current`);
} else {
  writeFileSync(OUT, text);
  console.log(`wrote ${OUT}: merkle_inclusion=${merkle.length} gate=${gate.length} model_path=${modelPath.length}`);
}
