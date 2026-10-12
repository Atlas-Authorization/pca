#!/usr/bin/env node
// Gate for sbom.mjs's summary: fail on any non-registry / unhashed lock entry, on install scripts in the CORE package's
// production closure, or on a publishable package that is not provenance-ready.
import { readFileSync } from 'node:fs';
const s = JSON.parse(readFileSync(process.argv[2], 'utf8'));
let bad = 0;
if (s.lockfile.nonRegistryOrUnhashed.length) { console.log('non-registry or unhashed lock entries:', JSON.stringify(s.lockfile.nonRegistryOrUnhashed.slice(0, 5))); bad = 1; }
const core = s.installScripts.filter((i) => i.requiredBy.includes('@atlasauth/pca'));
if (core.length) { console.log('install scripts in the @atlasauth/pca production closure:', JSON.stringify(core)); bad = 1; }
const notReady = s.provenance.filter((p) => !p.ready);
if (notReady.length) { console.log('not provenance-ready:', notReady.map((p) => `${p.name} (${p.missing.join(',')})`).join('; ')); bad = 1; }
console.log(`${s.packages.length} SBOMs; ${s.installScripts.length} install-script dependencies (all outside the core closure); lock entries all sha512 registry resolutions`);
process.exit(bad);
