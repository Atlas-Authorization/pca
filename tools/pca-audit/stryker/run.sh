#!/usr/bin/env bash
# env PKG=<package dir under packages/> (default pca). Usage: stryker/run.sh <name> <src-file> [<src-file>...]   (paths relative to packages/pca)
# Runs Stryker (vitest runner, perTest coverage) over the given modules; report -> /tmp/pca-audit-stryker/<name>.json.
# The sandbox (.stryker-tmp, ~100MB x concurrency) is deleted afterwards.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/../../.." && pwd)"
PKG="${PKG:-pca}"
name="$1"; shift
mkdir -p /tmp/pca-audit-stryker
mut=$(printf '"%s",' "$@"); mut="[${mut%,}]"
cfg="/tmp/pca-audit-stryker/$name.conf.json"
node -e '
const b=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));
b.mutate=JSON.parse(process.argv[3]);
b.plugins=[process.argv[4]+"/tools/pca-audit/node_modules/@stryker-mutator/vitest-runner/dist/src/index.js"];
b.jsonReporter={fileName:"/tmp/pca-audit-stryker/"+process.argv[2]+".json"};
b.tempDirName=".stryker-tmp-"+process.argv[2];
b.ignorePatterns=(b.ignorePatterns||[]).concat([".stryker-tmp*"]);
delete b["$schema"];
if(process.env.NO_RELATED)b.vitest={related:false};
if(process.env.VITEST_CONFIG){b.vitest=Object.assign(b.vitest||{},{configFile:process.env.VITEST_CONFIG});}
if(process.env.COVERAGE_OFF){b.coverageAnalysis="off";b.ignoreStatic=false;} // tests that run the code in child processes: perTest coverage never sees it
if(process.env.INPLACE){b.inPlace=true;b.concurrency=1;}
if(process.env.EXTRA_IGNORE)b.ignorePatterns=b.ignorePatterns.concat(process.env.EXTRA_IGNORE.split(","));
if(process.env.ONLY_TESTS){const fs=require("fs"),path=require("path");const keep=new Set(process.env.ONLY_TESTS.split(","));const dir=path.join(process.argv[4],"packages",process.env.PKG||"pca");const walk=(d)=>fs.readdirSync(d,{withFileTypes:true}).flatMap((e)=>e.name==="node_modules"||e.name===".stryker-tmp"||e.name==="dist"?[]:e.isDirectory()?walk(path.join(d,e.name)):[path.join(d,e.name)]);b.ignorePatterns=b.ignorePatterns.concat(walk(path.join(dir,"src")).filter((f)=>/\.test\.ts$/.test(f)).map((f)=>path.relative(dir,f)).filter((f)=>!keep.has(f)));}
require("fs").writeFileSync(process.argv[5],JSON.stringify(b,null,1));
' "$here/stryker.base.json" "$name" "$mut" "$root" "$cfg"
cd "$root/packages/$PKG"
"$root/tools/pca-audit/node_modules/.bin/stryker" run "$cfg" || true
rm -rf "$root/packages/$PKG/.stryker-tmp-$name"
