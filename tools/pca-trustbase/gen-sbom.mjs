#!/usr/bin/env node
// gen-sbom.mjs [--check]  -> sbom/pca-verified-core.cdx.json  (CycloneDX 1.5, deterministic: no timestamp, sorted)
// Components: (1) runtime dependency closure of @atlasauth/pca-verified-core from pnpm-lock.yaml with the lockfile's sha512 integrity,
// (2) the shipped generated artifact (sha256), (3) the PRIMITIVE libraries the glue (packages/pca) trusts (lock-pinned), (4) the proof
// toolchain from formal/dafny/TOOLCHAIN.lock (Dafny, Boogie, Z3, .NET), (5) dev/test dependencies marked scope=excluded.
// --check fails if the committed SBOM differs from a fresh generation (use in CI).
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const lock = readFileSync(join(ROOT, 'pnpm-lock.yaml'), 'utf8');
const tl = Object.fromEntries(readFileSync(join(ROOT, 'formal/dafny/TOOLCHAIN.lock'), 'utf8').split('\n').filter((l) => /^[A-Za-z0-9_]+=/.test(l)).map((l) => { const i = l.indexOf('='); return [l.slice(0, i), l.slice(i + 1).replace(/\s+#.*$/, '').replace(/^"|"$/g, '')]; }));
const pkgJson = JSON.parse(readFileSync(join(ROOT, 'packages/pca-verified-core/package.json'), 'utf8'));

// ---- minimal pnpm-lock parsing (importer block, packages block, snapshots block) -----------------------------------
function block(name) { const m = lock.match(new RegExp(`^${name}:\\n([\\s\\S]*?)(?=^\\S|$(?![\\s\\S]))`, 'm')); return m ? m[1] : ''; }
const importers = block('importers'), packagesBlk = block('packages'), snapshots = block('snapshots');
function importer(path) { const i = importers.indexOf(`\n  ${path}:\n`); if (i < 0) throw new Error(`no importer ${path}`); const rest = importers.slice(i + 1); const m = rest.slice(rest.indexOf('\n') + 1).match(/^(?! {4})[\s\S]*?$/m); const end = rest.slice(1).search(/\n {2}\S/); return end < 0 ? rest : rest.slice(0, end + 1); }
function deps(section, text) { const out = []; const m = text.match(new RegExp(`^ {4}${section}:\\n((?: {6}.*\\n?)*)`, 'm')); if (!m) return out; for (const mm of m[1].matchAll(/^ {6}'?([^':\n]+)'?:\n {8}specifier: (.+)\n {8}version: (\S+?)(?:\(|$)/gm)) out.push({ name: mm[1], spec: mm[2], version: mm[3] }); return out; }
function integrity(name, version) { const key = `${name}@${version}`; const re = new RegExp(`^  '?${key.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}'?:\\n    resolution: \\{integrity: (sha512-[^,}]+)`, 'm'); const m = packagesBlk.match(re); return m ? m[1] : undefined; }
function snapDeps(name, version) { const key = `${name}@${version}`; const re = new RegExp(`^  '?${key.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}'?(?:\\(.*\\))?:(?: \\{\\})?\\n((?:    .*\\n?)*)`, 'm'); const m = snapshots.match(re); if (!m) return []; const dm = m[1].match(/^ {4}dependencies:\n((?: {6}.*\n?)*)/m); if (!dm) return []; return [...dm[1].matchAll(/^ {6}'?([^':\n]+)'?: (\S+?)(?:\(|$)/gm)].map((x) => ({ name: x[1], version: x[2] })); }
const hex = (sri) => (sri ? Buffer.from(sri.replace(/^sha512-/, ''), 'base64').toString('hex') : undefined);
const purl = (n, v) => `pkg:npm/${n.replace(/^@/, '%40')}@${v}`;
const comp = (name, version, scope, extra = {}) => { const ig = integrity(name, version); return { type: 'library', 'bom-ref': purl(name, version), name, version, scope, purl: purl(name, version), ...(ig ? { hashes: [{ alg: 'SHA-512', content: hex(ig) }] } : {}), ...extra }; };

const comps = new Map(); const addTree = (name, version, scope, seen = new Set()) => { const k = `${name}@${version}`; if (seen.has(k)) return; seen.add(k); if (!comps.has(k)) comps.set(k, comp(name, version, scope)); for (const d of snapDeps(name, version)) addTree(d.name, d.version, scope, seen); };

const imp = importer('packages/pca-verified-core');
for (const d of deps('dependencies', imp)) addTree(d.name, d.version, 'required');
const runtimeKeys = new Set(comps.keys());

// primitives the GLUE trusts (packages/pca direct crypto deps)
const impPca = importer('packages/pca');
const PRIM = ['@noble/curves', '@noble/hashes', '@noble/post-quantum', '@noble/ciphers'];
for (const d of deps('dependencies', impPca)) if (PRIM.includes(d.name)) { addTree(d.name, d.version, 'required'); const c = comps.get(`${d.name}@${d.version}`); c.properties = [{ name: 'pca:role', value: 'cryptographic primitive trusted by the glue (not by the Dafny proofs)' }]; }
for (const d of deps('devDependencies', imp)) { const k = `${d.name}@${d.version}`; if (!comps.has(k)) comps.set(k, comp(d.name, d.version, 'excluded', { properties: [{ name: 'pca:role', value: 'dev/test only; not shipped' }] })); }

const generated = join(ROOT, 'packages/pca-verified-core/generated/pca_core.js');
const sha = (f) => createHash('sha256').update(readFileSync(f)).digest('hex');
const toolchain = [
  { type: 'application', 'bom-ref': 'tool:dafny', name: 'dafny', version: tl.DAFNY_VERSION, scope: 'excluded', description: 'proof checker + JS compiler (build-time; trusted for soundness of the proofs and for the generated JS)', purl: `pkg:github/dafny-lang/dafny@${tl.DAFNY_RELEASE_TAG}`, hashes: [{ alg: 'SHA-256', content: tl.DAFNY_ZIP_ubuntu_22_04_x64_SHA256 }], properties: [{ name: 'commit', value: tl.DAFNY_COMMIT }, { name: 'tree-sha256', value: tl.DAFNY_TREE_SHA256 }, { name: 'asset', value: tl.DAFNY_ZIP_ubuntu_22_04_x64 }] },
  { type: 'application', 'bom-ref': 'tool:z3', name: 'z3', version: tl.Z3_DEFAULT_VERSION, scope: 'excluded', description: 'SMT solver bundled with Dafny, used for every proof (build-time)', hashes: [{ alg: 'SHA-256', content: tl.Z3_4_12_1_SHA256 }] },
  { type: 'application', 'bom-ref': 'tool:boogie', name: 'boogie', version: tl.BOOGIE_VERSION, scope: 'excluded', description: 'verification-condition generator bundled with Dafny (build-time)', hashes: [{ alg: 'SHA-256', content: tl.DLL_BoogieCore_SHA256 }] },
  { type: 'framework', 'bom-ref': 'tool:dotnet', name: '.NET runtime', version: tl.DOTNET_RUNTIME_RECORDED, scope: 'excluded', description: 'runs Dafny (build-time); distro package, not byte-pinned' },
];
const art = { type: 'file', 'bom-ref': 'file:generated/pca_core.js', name: 'packages/pca-verified-core/generated/pca_core.js', version: '0.4.0', scope: 'required', description: 'Dafny-compiled JavaScript shipped in the package', hashes: existsSync(generated) ? [{ alg: 'SHA-256', content: sha(generated) }] : [] };
const dfy = ['Common', 'Chain', 'Caveats', 'Threshold', 'Replay', 'Verdict'].map((n) => ({ type: 'file', 'bom-ref': `file:formal/dafny/${n}.dfy`, name: `formal/dafny/${n}.dfy`, scope: 'excluded', description: 'proved source', hashes: [{ alg: 'SHA-256', content: sha(join(ROOT, `formal/dafny/${n}.dfy`)) }] }));

const all = [art, ...[...comps.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version)), ...toolchain, ...dfy];
const bom = {
  bomFormat: 'CycloneDX', specVersion: '1.5', version: 1,
  metadata: { component: { type: 'library', 'bom-ref': 'root', name: pkgJson.name, version: pkgJson.version, purl: purl(pkgJson.name, pkgJson.version), licenses: [{ license: { id: pkgJson.license } }] },
    properties: [{ name: 'pca:generator', value: 'tools/pca-trustbase/gen-sbom.mjs' }, { name: 'pca:note', value: 'deterministic: no timestamp; regenerate after any lockfile, .dfy or generated-JS change' }] },
  components: all,
  dependencies: [{ ref: 'root', dependsOn: [...runtimeKeys].map((k) => { const [n, v] = [k.slice(0, k.lastIndexOf('@')), k.slice(k.lastIndexOf('@') + 1)]; return purl(n, v); }).sort() }],
};
const out = JSON.stringify(bom, null, 2) + '\n';
const dest = join(ROOT, 'tools/pca-trustbase/sbom/pca-verified-core.cdx.json');
if (process.argv.includes('--check')) { const cur = existsSync(dest) ? readFileSync(dest, 'utf8') : ''; if (cur !== out) { console.error('SBOM is stale: run node tools/pca-trustbase/gen-sbom.mjs'); process.exit(1); } console.log('SBOM up to date'); }
else { mkdirSync(dirname(dest), { recursive: true }); writeFileSync(dest, out); console.log(`wrote ${dest}: ${all.length} components (${runtimeKeys.size} runtime-closure, ${all.filter((c) => c.scope === 'required').length} required)`); }
