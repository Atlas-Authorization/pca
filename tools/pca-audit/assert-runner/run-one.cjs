// run-one.cjs <workspace pkg dir> <src> <mutants.jsonl> <out.jsonl> <timeoutMs> -- <tests...>   (one worker; used by assert-runner.sh)
const fs = require('fs'), cp = require('child_process'), path = require('path');
const a = process.argv.slice(2); const dd = a.indexOf('--'); const tests = a.slice(dd + 1); const [pkg, src, mf, out, tmo] = a;
const sp = path.join(pkg, src); const orig = fs.readFileSync(sp, 'utf8'); const L = orig.split('\n');
const ms = fs.readFileSync(mf, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
const done = new Set(fs.existsSync(out) ? fs.readFileSync(out, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l).id) : []);
function locate(m) {
  for (let d = 0; d < 400; d++) for (const s of [m.line - 1 + d, m.line - 1 - d]) {
    if (s < 0 || s >= L.length || L[s] !== m.lineText) continue;
    const sl = s, el = m.eline - 1 + (s - (m.line - 1));
    const o = sl === el ? L[sl].slice(m.col - 1, m.ecol - 1) : [L[sl].slice(m.col - 1), ...L.slice(sl + 1, el), L[el].slice(0, m.ecol - 1)].join('\n');
    if (o === m.orig) return { sl, el };
  }
  return null;
}
try {
  for (const m of ms) {
    if (fs.existsSync(out + '.STOP')) break;
    if (done.has(m.id)) continue;
    const loc = locate(m); let r;
    if (!loc) r = { id: m.id, result: 'NOLOC' };
    else {
      const before = L.slice(0, loc.sl).join('\n') + (loc.sl ? '\n' : '') + L[loc.sl].slice(0, m.col - 1);
      const after = L[loc.el].slice(m.ecol - 1) + (loc.el < L.length - 1 ? '\n' : '') + L.slice(loc.el + 1).join('\n');
      fs.writeFileSync(sp, before + m.repl + after);
      const t0 = Date.now();
      const rep = path.join(path.dirname(out), `.vjson-${process.pid}.json`);
      const p = cp.spawnSync('./node_modules/.bin/vitest', ['run', '--pool=forks', '--poolOptions.forks.singleFork', '--reporter=json', `--outputFile=${rep}`, ...tests], { cwd: pkg, timeout: +tmo, encoding: 'utf8', env: { ...process.env, CI: '1' } });
      fs.writeFileSync(sp, orig);
      let result, assertFails = [], errorFails = [];
      if (p.signal) result = 'TIMEOUT';
      else {
        let j = null; try { j = JSON.parse(fs.readFileSync(rep, 'utf8')); } catch { /* no report */ }
        fs.rmSync(rep, { force: true });
        if (!j) result = p.status === 0 ? 'SURVIVED' : 'CRASH';
        else {
          for (const f of j.testResults ?? []) {
            if (f.status === 'failed' && (f.assertionResults ?? []).length === 0) errorFails.push(`${path.relative(pkg, f.name)} (suite): ${(f.message ?? '').split('\n')[0].slice(0, 160)}`);
            for (const t of f.assertionResults ?? []) {
              if (t.status !== 'failed') continue;
              const msg = (t.failureMessages ?? []).join('\n').replace(/\u001b\[[0-9;]*m/g, '');
              const name = `${path.relative(pkg, f.name)} > ${t.fullName}`;
              if (/Test timed out/.test(msg)) errorFails.push(`${name}: TIMEOUT`);
              else if (/^AssertionError/m.test(msg)) assertFails.push(`${name}: ${msg.split('\n')[0].slice(0, 160)}`);
              else errorFails.push(`${name}: ${msg.split('\n')[0].slice(0, 160)}`);
            }
          }
          result = assertFails.length ? 'KILLED_ASSERT' : errorFails.length ? (errorFails.every((x) => x.endsWith('TIMEOUT')) ? 'TIMEOUT' : 'KILLED_ERROR') : p.status === 0 ? 'SURVIVED' : 'CRASH';
        }
      }
      r = { id: m.id, line: loc.sl + 1, mutator: m.mutator, orig: m.orig.slice(0, 120), repl: m.repl.slice(0, 120), result, ms: Date.now() - t0, assert: assertFails.slice(0, 3), error: errorFails.slice(0, 3) };
    }
    fs.appendFileSync(out, JSON.stringify(r) + '\n');
  }
} finally { fs.writeFileSync(sp, orig); }
