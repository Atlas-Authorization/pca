#!/usr/bin/env node
// Every shipped Rust source file must be in the mutation plan. Walks the whole src tree, subdirectories included, and fails when a
// tracked .rs file is neither visited by cargo-mutants nor declared as a #[cfg(test)] module.
//   node file-guard.mjs --pkg=<crate> --dir=<crate dir> [--win-only=src/a.rs,src/b.rs]      (run from the repo root)
// --win-only: the files only Windows compiles (declared under #[cfg(windows)] / #[cfg(not(unix))]). Linux never builds them, so they
// are left out of the Linux plan and mutated on windows-latest; the list must equal the declarations found in the tree.
//   node file-guard.mjs --self-test
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';

const relSrc = (p) => p.slice(p.lastIndexOf('src/'));

// A module declared directly under #[cfg(test)]: `mod x;` or `#[path = "x.rs"] mod y;`, either attribute first.
export function testModules(sources) {
  const names = new Set();
  for (const text of sources) {
    let attrs = [];
    for (const raw of text.split('\n')) {
      const t = raw.trim();
      if (t.startsWith('#[')) { attrs.push(t); continue; }
      const m = t.match(/^(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;/);
      if (m && attrs.some((a) => /^#\[cfg\((?:all\()?test\b/.test(a))) {
        const p = attrs.map((a) => a.match(/path\s*=\s*"([^"]+)"/)).find(Boolean);
        names.add(p ? basename(p[1]) : `${m[1]}.rs`);
      }
      if (t && !t.startsWith('//')) attrs = [];
    }
  }
  return names;
}

// The src-relative files of modules declared directly under #[cfg(windows)] or #[cfg(not(unix))]: files maps each src-relative
// path to its text. `#[path = "x.rs"] mod m;` in src/a/b.rs is src/a/x.rs; `mod m;` is src/a/b/m.rs (src/a/m.rs from lib.rs or
// mod.rs).
export function windowsModules(files) {
  const out = new Set();
  for (const [file, text] of Object.entries(files)) {
    const d = file.slice(0, file.lastIndexOf('/') + 1), stem = basename(file, '.rs');
    let attrs = [];
    for (const raw of text.split('\n')) {
      const t = raw.trim();
      if (t.startsWith('#[')) { attrs.push(t); continue; }
      const m = t.match(/^(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;/);
      if (m && attrs.some((a) => /^#\[cfg\((?:windows|not\(unix\))\)\]$/.test(a))) {
        const p = attrs.map((a) => a.match(/path\s*=\s*"([^"]+)"/)).find(Boolean);
        out.add(p ? d + p[1] : ['lib', 'main', 'mod'].includes(stem) ? `${d}${m[1]}.rs` : `${d}${stem}/${m[1]}.rs`);
      }
      if (t && !t.startsWith('//')) attrs = [];
    }
  }
  return [...out].sort();
}

// tracked and visited are src-relative paths; sources is the text of every tracked file.
export function missing(tracked, visited, sources) {
  const seen = new Set(visited);
  const tests = testModules(sources);
  return tracked.filter((f) => !seen.has(f) && !tests.has(basename(f)));
}

// A file with no `fn` once comments are stripped (mod/use/pub use declarations, consts, data tables) has nothing cargo-mutants can mutate.
export function declOnly(text) {
  return !/\bfn\b/.test(text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, ''));
}

function selfTest() {
  const tracked = ['src/lib.rs', 'src/attest/mod.rs', 'src/attest/x509.rs', 'src/a_test.rs', 'src/attest/b_test.rs'];
  const sources = ['#[cfg(test)]\n#[path = "a_test.rs"]\nmod t;\n', '#[path = "b_test.rs"]\n#[cfg(test)]\nmod b;\npub mod x509;\n'];
  const eq = (a, b) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${JSON.stringify(a)} != ${JSON.stringify(b)}`); };
  const all = ['src/lib.rs', 'src/attest/mod.rs', 'src/attest/x509.rs'];
  eq(missing(tracked, all, sources), []);
  eq(missing(tracked, ['src/lib.rs'], sources), ['src/attest/mod.rs', 'src/attest/x509.rs']); // a subdirectory dropped from the plan
  eq(missing([...tracked, 'src/orphan.rs'], all, sources), ['src/orphan.rs']); // no mod declares it
  // a test name alone is not enough: a non-test declaration does not exempt the file
  eq(missing(['src/c_test.rs'], [], ['mod c_test;\n']), ['src/c_test.rs']);
  // an attribute on an earlier item does not carry over
  eq(missing(['src/d.rs'], [], ['#[cfg(test)]\nfn f() {}\nmod d;\n']), ['src/d.rs']);
  eq(declOnly('//! fn docs\npub mod a;\npub use b::c;\nconst T: &[u8] = &[1];\n'), true);
  eq(declOnly('pub mod a;\npub(crate) fn f() {}\n'), false); // real code stays under the zero-mutant check
  eq(windowsModules({
    'src/lib.rs': '#[cfg(unix)]\npub mod ds;\n#[cfg(not(unix))]\n#[path = "ds_stub.rs"]\npub mod ds;\n#[cfg(windows)]\nmod w;\n',
    'src/pf.rs': '// why\n#[cfg(windows)]\n#[path = "pf_windows.rs"]\nmod win;\n#[cfg(windows)]\nuse win::f as g;\n#[cfg(windows)]\nfn h() {}\nmod n;\n',
    'src/a/b.rs': '#[cfg(not(unix))]\nmod c;\n#[cfg(not(any(unix, windows)))]\nmod d;\n',
  }), ['src/a/b/c.rs', 'src/ds_stub.rs', 'src/pf_windows.rs', 'src/w.rs']);
  console.log('file-guard self-test ok');
}

if (process.argv.includes('--self-test')) { selfTest(); process.exit(0); }

const opt = (n) => process.argv.find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3);
const pkg = opt('pkg'), dir = opt('dir');
// --exclude-dir=src/bin: a proven exclusion (a fixture generator, demos): those files are left out of cargo-mutants and printed
const exDir = opt('exclude-dir');
if (!pkg || !dir) { console.error('usage: file-guard.mjs --pkg=<crate> --dir=<crate dir> [--exclude-dir=src/bin]'); process.exit(2); }
const winOnly = (opt('win-only') || '').split(',').filter(Boolean).sort();
const excl = [...(exDir ? ['--exclude', `${dir}/${exDir}/**`] : []), ...winOnly.flatMap((f) => ['--exclude', `${dir}/${f}`])];

const git = spawnSync('git', ['ls-files', '--', `${dir}/src`], { encoding: 'utf8', maxBuffer: 1 << 26 });
if (git.status !== 0) { console.error(git.stderr); process.exit(1); }
const all = git.stdout.split('\n').filter((p) => p.endsWith('.rs'));
// the Windows-only list is exactly what the tree declares: a new cfg(windows) file cannot be silently left to Linux, and a stale
// entry cannot hide a file from the Linux plan
const declared = windowsModules(Object.fromEntries(all.map((p) => [relSrc(p), readFileSync(p, 'utf8')])));
if (JSON.stringify(declared) !== JSON.stringify(winOnly)) {
  console.error(`::error::--win-only (${winOnly.join(', ') || 'none'}) differs from the Windows-only modules the tree declares (${declared.join(', ') || 'none'})`);
  process.exit(1);
}
for (const f of winOnly) console.log(`Windows-only (left out of the Linux plan, mutated on windows-latest by both tools): ${dir}/${f}`);
const paths = all.filter((p) => (!exDir || !relSrc(p).startsWith(exDir + '/')) && !winOnly.includes(relSrc(p)));
for (const p of all.filter((p) => !paths.includes(p))) console.log(`excluded (proven, listed in the status file): ${p}`);
const list = spawnSync('cargo', ['mutants', '-p', pkg, '--all-features', ...excl, '--list-files', '--json'], { encoding: 'utf8', maxBuffer: 1 << 26 });
if (list.status !== 0) { console.error(list.stderr); process.exit(1); }
// cargo-mutants 27 `--list-files --json`: [{package, path}]; an entry with no path is a listing we do not understand
const visited = JSON.parse(list.stdout).map((f) => {
  const p = typeof f === 'string' ? f : f.path ?? f.name;
  if (typeof p !== 'string') { console.error(`::error::unreadable --list-files entry: ${JSON.stringify(f)}`); process.exit(1); }
  return relSrc(p);
});
const tracked = paths.map(relSrc);
const bad = missing(tracked, visited, paths.map((p) => readFileSync(p, 'utf8')));
const subdirs = new Set(visited.filter((f) => f.split('/').length > 2).map((f) => f.split('/')[1]));
console.log(`file guard: ${tracked.length} tracked, ${visited.length} visited by cargo-mutants, subdirectories: ${[...subdirs].join(', ') || 'none'}`);
// no file, or no subdirectory while the tree has one, means the listing itself is wrong
if (visited.length === 0 || (tracked.some((f) => f.split('/').length > 2) && subdirs.size === 0)) {
  console.error('::error::the mutation file listing looks empty or flat');
  process.exit(1);
}
if (bad.length) {
  for (const f of bad) console.error(`::error::${dir}/${f} is shipped but not in the mutation plan`);
  process.exit(1);
}
// zero-mutant check: a visited file that holds no cargo-mutants mutant is not mutated at all
const ml = spawnSync('cargo', ['mutants', '-p', pkg, '--all-features', ...excl, '--list', '--json'], { encoding: 'utf8', maxBuffer: 1 << 29 });
if (ml.status !== 0) { console.error(ml.stderr); process.exit(1); }
const held = new Set(JSON.parse(ml.stdout).map((m) => relSrc(m.file)));
// declaration-only files (module lists, re-exports, data tables) legitimately hold none; any file with a fn must
const empty = visited.filter((f) => !held.has(f) && !declOnly(readFileSync(`${dir}/${f}`, 'utf8')));
for (const f of empty) console.error(`::error::${dir}/${f} is in the plan but holds no mutant`);
if (empty.length) process.exit(1);
console.log(`file guard: every planned file holds a mutant (${held.size} files)`);
