// Shared by schema-build.mjs and schema-run.mjs: a command in its own process group under the per-process memory cap, and the
// outcome classification the cargo-mutants and statement shards use (stmt-run.mjs).
import fs from 'node:fs';
import { spawn } from 'node:child_process';

// cargo <args> with extra env, output appended to `log`; a timeout kills the whole process group
export function run(args, env, log, limitS) {
  return new Promise((res) => {
    const fd = fs.openSync(log, 'a'), t0 = Date.now(), kb = process.env.CARRY_ULIMIT_KB;
    const e = { ...process.env, ...env };
    for (const [k, v] of Object.entries(env)) if (v === undefined) delete e[k];
    const c = spawn('bash', ['-c', `${kb ? `ulimit -v ${Number(kb)}; ` : ''}exec "$@"`, 'bash', 'cargo', ...args], { detached: true, stdio: ['ignore', fd, fd], env: e });
    let timedOut = false;
    const kill = () => { try { process.kill(-c.pid, 'SIGKILL'); } catch {} };
    const timer = limitS ? setTimeout(() => { timedOut = true; kill(); }, limitS * 1000) : null;
    c.on('exit', (code, sig) => { if (timer) clearTimeout(timer); fs.closeSync(fd); kill(); res({ code: code ?? 128, sig, timedOut, s: (Date.now() - t0) / 1000 }); });
  });
}

export const plainFail = (txt) => /^\s*(?:TRY \d+ )?FAIL\s+\[/m.test(txt);
export const signals = (txt) => [...new Set([...txt.matchAll(/^\s*(?:TRY \d+ )?(SIG[A-Z0-9]+|ABORT)\s+\[/gm)].map((x) => x[1]))];
export const evidence = (txt) => (txt.match(/memory allocation of \d+ bytes failed|has overflowed its stack/) || [''])[0];

// nextest's per-test result lines: "PASS [   0.123s] (12/2084) atlas-pca::all mod::test"
export function durations(txt) {
  const d = new Map();
  for (const m of txt.matchAll(/^\s*PASS \[\s*([\d.]+)s\]\s+(?:\(\s*\d+\/\s*\d+\)\s+)?(\S+)\s+(\S+)\s*$/gm)) d.set(`${m[2]}\t${m[3]}`, Number(m[1]));
  return d;
}

// a nextest filterset naming exactly these tests: [[binary-id, test name], ...]
export function filterOf(tests) {
  const by = new Map();
  for (const [b, t] of tests) { if (!by.has(b)) by.set(b, []); by.get(b).push(t); }
  return [...by].map(([b, ts]) => `(binary_id(=${b}) & (${ts.map((t) => `test(=${t})`).join(' | ')}))`).join(' | ');
}

const lines = new Map();
export function srcLine(file, n) {
  if (!lines.has(file)) lines.set(file, fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split('\n') : []);
  return (lines.get(file)[n - 1] || '').trim();
}
export const parseName = (name) => { const p = /^(.+?):(\d+):(\d+): (.*)$/.exec(name); if (!p) throw new Error('unparsed: ' + name); return { file: p[1], line: +p[2], desc: p[4] }; };
