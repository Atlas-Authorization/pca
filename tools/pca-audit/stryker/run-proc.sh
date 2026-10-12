#!/usr/bin/env bash
# run-proc.sh <name> <test-file> <src-file>...   (paths relative to packages/$PKG, default pca-mpc)
# Stryker for modules that run in CHILD PROCESSES (pca-mpc net/party-main.ts, net/launch-local.ts): coverageAnalysis "off", so every
# mutant runs the given test file in full (per-test coverage cannot see code executed in a spawned process); the test file forwards the
# active mutant id to its children through __STRYKER_ACTIVE_MUTANT__. Report -> /tmp/pca-audit-stryker/<name>.json; sandbox deleted.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/../../.." && pwd)"
PKG="${PKG:-pca-mpc}"
name="$1"; test="$2"; shift 2
mkdir -p /tmp/pca-audit-stryker
cfg="/tmp/pca-audit-stryker/$name.conf.json"
node -e '
const fs=require("fs"),path=require("path");
const [base,name,test,root,out,pkg,...mut]=process.argv.slice(1);
const b=JSON.parse(fs.readFileSync(base,"utf8"));
delete b["$schema"];
b.mutate=mut;
b.coverageAnalysis="off";
b.ignoreStatic=false;
b.timeoutMS=Number(process.env.TIMEOUT_MS||180000);
b.concurrency=Number(process.env.CONCURRENCY||2);
b.plugins=[root+"/tools/pca-audit/node_modules/@stryker-mutator/vitest-runner/dist/src/index.js"];
b.jsonReporter={fileName:"/tmp/pca-audit-stryker/"+name+".json"};
b.tempDirName=".stryker-tmp-"+name;
b.vitest={related:false};
const dir=path.join(root,"packages",pkg);
const walk=(d)=>fs.readdirSync(d,{withFileTypes:true}).flatMap((e)=>e.name==="node_modules"||e.name.startsWith(".")||e.name==="dist"?[]:e.isDirectory()?walk(path.join(d,e.name)):[path.join(d,e.name)]);
b.ignorePatterns=(b.ignorePatterns||[]).concat([".stryker-tmp*",".nettest-build-*"]).concat(walk(path.join(dir,"src")).filter((f)=>/\.test\.ts$/.test(f)).map((f)=>path.relative(dir,f)).filter((f)=>f!==test));
fs.writeFileSync(out,JSON.stringify(b,null,1));
' "$here/stryker.base.json" "$name" "$test" "$root" "$cfg" "$PKG" "$@"
cd "$root/packages/$PKG"
"$root/tools/pca-audit/node_modules/.bin/stryker" run "$cfg" || true
rm -rf "$root/packages/$PKG/.stryker-tmp-$name"
