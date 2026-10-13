// p50/p95 wall time per DoS vector per language (one driver process per run), for the caveat-size vectors.
//   node tools/pca-diff-fuzz/bench-caveat-dos.mjs [--runs 15] [--langs ts,ruby,java] [--out DIR] [--match regex]
// Run it on an IDLE box (lease EXCLUSIVE=1). Reports total wall ms and EXCESS over the control vector's median (process startup).
// Every driver binary is the one built by `scripts/pca-conformance-all.mjs --out DIR` (DIR/go-driver, dotnet-bin, rust-target, java-classes; bcprov on PCA_BC_JAR).
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname, delimiter } from 'node:path';
import { loadavg } from 'node:os';
import { fileURLToPath } from 'node:url';
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../..');
const a = process.argv.slice(2);
const opt = (k, d) => { const i = a.indexOf(k); return i >= 0 ? a[i + 1] : d; };
const RUNS = Number(opt('--runs', 15));
const OUT = opt('--out', '/tmp/bench-caveat-dos');
const MATCH = new RegExp(opt('--match', 'caveat|atten-|chain-17|artifact-size|bomb-.*-over-cap|bomb-open-brackets-1MiB'));
const LANGS = opt('--langs', 'ts,go,python,ruby,php,dotnet,rust,java').split(',');
mkdirSync(OUT, { recursive: true });
const dosFile = join(OUT, 'dos.jsonl');
const g = spawnSync('node', [join(ROOT, 'tools/pca-diff-fuzz/gen/dos.mjs'), dosFile], { encoding: 'utf8' });
if (g.status !== 0) { console.error(g.stderr); process.exit(2); }
const vecs = readFileSync(dosFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const ctl = vecs.at(-1);
const sel = vecs.slice(0, -1).filter((v) => MATCH.test(v.name));
const DRV = join(ROOT, 'tools/pca-diff-fuzz/drivers');
const BC = process.env.PCA_BC_JAR ?? '';
const cmds = {
  ts: (i, o) => [join(ROOT, 'packages/pca/node_modules/.bin/tsx'), join(ROOT, 'packages/pca-conformance/adversarial/ref-driver.ts'), i, o],
  ruby: (i, o) => ['ruby', join(DRV, 'ruby/driver.rb'), i, o],
  go: (i, o) => [join(OUT, 'go-driver'), i, o],
  php: (i, o) => ['php', join(DRV, 'php/driver.php'), i, o],
  dotnet: (i, o) => ['dotnet', join(OUT, 'dotnet-bin/Driver.dll'), i, o],
  rust: (i, o) => [join(OUT, 'rust-target/release/pcadriver'), i, o],
  python: (i, o) => ['python3', '-I', join(DRV, 'python/driver.py'), i, o],
  java: (i, o) => ['java', '-Xss4m', '-cp', `${join(OUT, 'java-classes')}${delimiter}${BC}`, 'Driver', i, o],
};
const q = (xs, p) => { const s = [...xs].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.ceil(p * s.length) - 1)]; };
let n = 0;
const once = (cmd, v) => {
  const i = join(OUT, `i${++n}.jsonl`), o = join(OUT, `o${n}.jsonl`);
  writeFileSync(i, JSON.stringify({ id: v.id, kind: v.kind, raw: v.raw, grant: v.grant, now: v.now, aud: v.aud }) + '\n');
  const [c, ...r] = cmd(i, o); const t = Date.now();
  spawnSync(c, r, { cwd: ROOT, timeout: 120000, killSignal: 'SIGKILL' });
  const ms = Date.now() - t;
  let verdict = '?'; try { const x = JSON.parse(readFileSync(o, 'utf8').split('\n')[0]); verdict = x.allow ? 'A' : x.error ? 'E' : 'R'; } catch {}
  return { ms, verdict };
};
for (const lang of LANGS) {
  if (!cmds[lang]) continue;
  once(cmds[lang], ctl);
  const base = q(Array.from({ length: RUNS }, () => once(cmds[lang], ctl).ms), 0.5);
  console.log(`\n${lang}: control (startup) median ${base} ms   loadavg ${loadavg().map((x) => x.toFixed(2)).join('/')}`);
  console.log('vector'.padEnd(52), 'verdict', 'p50', 'p95', 'max', ' excess-p50', 'excess-p95');
  for (const v of sel) {
    once(cmds[lang], v);
    const rs = Array.from({ length: RUNS }, () => once(cmds[lang], v));
    const ms = rs.map((r) => r.ms);
    console.log(v.name.padEnd(52), rs[0].verdict.padEnd(7), String(q(ms, 0.5)).padStart(4), String(q(ms, 0.95)).padStart(4), String(Math.max(...ms)).padStart(4), String(q(ms, 0.5) - base).padStart(10), String(q(ms, 0.95) - base).padStart(10));
  }
}
