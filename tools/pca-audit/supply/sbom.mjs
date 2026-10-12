#!/usr/bin/env node
/**
 * Supply-chain audit for the PCA npm packages, driven purely by pnpm-lock.yaml + the installed store:
 *   1. a CycloneDX 1.5 SBOM per publishable packages/pca* package (production closure: dependencies + optionalDependencies);
 *   2. lockfile integrity: every registry package carries a sha512 integrity hash and resolves from the npm registry (no git /
 *      tarball-URL / missing-hash escapes);
 *   3. install scripts: any package in a PCA production closure declaring preinstall / install / postinstall;
 *   4. npm provenance readiness per package (repository, license, files whitelist, publishConfig, engines).
 * Usage: node sbom.mjs [--out /tmp/pca-sbom] [--json summary.json]
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../../..');
const req = createRequire(join(here, '../package.json'));
const yaml = req('js-yaml');
const arg = (n, d) => (process.argv.includes(`--${n}`) ? process.argv[process.argv.indexOf(`--${n}`) + 1] : d);
const outDir = arg('out', '/tmp/pca-sbom');
mkdirSync(outDir, { recursive: true });

const lock = yaml.load(readFileSync(join(root, 'pnpm-lock.yaml'), 'utf8'));
const importers = lock.importers;
const packages = lock.packages ?? {};
const snapshots = lock.snapshots ?? {};
const base = (k) => k.replace(/\(.*$/, '');
const splitNV = (nv) => {
  const i = nv.lastIndexOf('@');
  return [nv.slice(0, i), nv.slice(i + 1)];
};
const purl = (name, ver) => `pkg:npm/${name.startsWith('@') ? '%40' + name.slice(1) : name}@${ver}`;
const hexOfIntegrity = (i) => (i?.startsWith('sha512-') ? Buffer.from(i.slice(7), 'base64').toString('hex') : undefined);

const pcaDirs = readdirSync(join(root, 'packages')).filter((d) => d === 'pca' || d.startsWith('pca-'));
const report = { packages: [], lockfile: {}, installScripts: [], provenance: [] };

// ---- lockfile integrity ------------------------------------------------------------------------------------------
{
  let total = 0;
  const bad = [];
  for (const [k, v] of Object.entries(packages)) {
    total++;
    const r = v.resolution ?? {};
    if (r.type === 'git' || r.tarball || r.type === 'directory') bad.push({ pkg: k, why: r.type ?? 'tarball-url', detail: r.tarball ?? r.repo });
    else if (!r.integrity) bad.push({ pkg: k, why: 'no-integrity' });
    else if (!r.integrity.startsWith('sha512-')) bad.push({ pkg: k, why: `weak-integrity ${r.integrity.slice(0, 8)}` });
  }
  report.lockfile = { lockfileVersion: lock.lockfileVersion, registryPackages: total, nonRegistryOrUnhashed: bad };
}

const closure = (dir) => {
  const imp = importers[`packages/${dir}`];
  if (!imp) return null;
  const seen = new Map();
  const st = [];
  const wk = [];
  for (const sec of ['dependencies', 'optionalDependencies']) {
    for (const [n, v] of Object.entries(imp[sec] ?? {})) {
      const ver = typeof v === 'string' ? v : v.version;
      if (ver.startsWith('link:')) wk.push(n);
      else st.push(`${n}@${ver}`);
    }
  }
  while (st.length) {
    const k = st.pop();
    if (seen.has(k)) continue;
    seen.set(k, true);
    const s = snapshots[k] ?? {};
    for (const sec of ['dependencies', 'optionalDependencies']) for (const [n, v] of Object.entries(s[sec] ?? {})) st.push(`${n}@${v}`);
  }
  return { comps: [...seen.keys()], workspace: wk };
};

const storeDir = join(root, 'node_modules/.pnpm');
const pkgJsonOf = (name, ver) => {
  const p = join(storeDir, `${name.replace('/', '+')}@${ver.replace(/\(.*$/, '')}`, 'node_modules', name, 'package.json');
  try {
    return JSON.parse(readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
};
const installFlag = new Map();

for (const dir of pcaDirs) {
  const pj = JSON.parse(readFileSync(join(root, 'packages', dir, 'package.json'), 'utf8'));
  if (pj.private) continue;
  const c = closure(dir);
  if (!c) continue;
  const components = c.comps.map((nv) => {
    const [name, ver] = splitNV(nv);
    const meta = packages[base(nv)] ?? {};
    const inst = pkgJsonOf(name, ver);
    const scripts = inst?.scripts ?? {};
    const hasInstall = ['preinstall', 'install', 'postinstall'].filter((s) => scripts[s]);
    if (hasInstall.length) installFlag.set(nv, { pkg: nv, scripts: Object.fromEntries(hasInstall.map((s) => [s, scripts[s]])), requiredBy: new Set() });
    installFlag.get(nv)?.requiredBy.add(pj.name);
    const hex = hexOfIntegrity(meta.resolution?.integrity);
    return {
      type: 'library',
      'bom-ref': purl(name, base(ver)),
      name,
      version: base(ver),
      purl: purl(name, base(ver)),
      ...(hex ? { hashes: [{ alg: 'SHA-512', content: hex }] } : {}),
      ...(inst?.license ? { licenses: [{ license: { id: typeof inst.license === 'string' ? inst.license : inst.license.type } }] } : {}),
    };
  });
  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: { components: [{ type: 'application', name: 'pca-audit/sbom.mjs', version: '1' }] },
      component: { type: 'library', 'bom-ref': purl(pj.name, pj.version), name: pj.name, version: pj.version, purl: purl(pj.name, pj.version) },
    },
    components,
    dependencies: [{ ref: purl(pj.name, pj.version), dependsOn: [...components.map((x) => x['bom-ref']), ...c.workspace.map((w) => `workspace:${w}`)] }],
  };
  writeFileSync(join(outDir, `${pj.name.replace('@', '').replace('/', '__')}.cdx.json`), JSON.stringify(bom, null, 1));
  report.packages.push({ name: pj.name, version: pj.version, components: components.length, workspaceDeps: c.workspace.length });

  // provenance readiness
  const missing = [];
  if (!pj.repository) missing.push('repository');
  if (!pj.license) missing.push('license');
  if (!pj.files) missing.push('files-whitelist');
  if (pj.publishConfig?.access !== 'public') missing.push('publishConfig.access=public');
  if (!pj.engines?.node) missing.push('engines.node');
  if (!existsSync(join(root, 'packages', dir, 'README.md'))) missing.push('README');
  report.provenance.push({ name: pj.name, ready: missing.length === 0, missing });
}
report.installScripts = [...installFlag.values()].map((x) => ({ ...x, requiredBy: [...x.requiredBy] }));
const js = arg('json', join(outDir, 'summary.json'));
writeFileSync(js, JSON.stringify(report, null, 2));
const notReady = report.provenance.filter((p) => !p.ready);
console.log(`SBOMs: ${report.packages.length} packages -> ${outDir}`);
console.log(`lockfile v${report.lockfile.lockfileVersion}: ${report.lockfile.registryPackages} packages, ${report.lockfile.nonRegistryOrUnhashed.length} non-registry/unhashed`);
console.log(`install scripts in PCA production closures: ${report.installScripts.length}`);
for (const i of report.installScripts) console.log(`  ${i.pkg} ${JSON.stringify(i.scripts)} <- ${i.requiredBy.slice(0, 4).join(', ')}${i.requiredBy.length > 4 ? ` (+${i.requiredBy.length - 4})` : ''}`);
console.log(`provenance readiness: ${report.provenance.length - notReady.length}/${report.provenance.length} ready${notReady.length ? '; gaps: ' + [...new Set(notReady.flatMap((p) => p.missing))].join(', ') : ''}`);
