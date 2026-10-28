import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const run = fileURLToPath(new URL('../run.mjs', import.meta.url));
const exec = (...args) => spawnSync(process.execPath, [run, ...args], { encoding: 'utf8', timeout: 60_000 });

test('the demo plays all nine outcomes as specified and exits 0', () => {
  const r = exec('--json');
  assert.equal(r.status, 0, r.stderr);
  const doc = JSON.parse(r.stdout);
  assert.equal(doc.ok, true);
  const by = Object.fromEntries(doc.rows.map((x) => [String(x.step), x]));
  const expect = {
    1: 'VERIFIED', 2: 'ALLOWED', 3: 'DENIED', '4a': 'DENIED', '4b': 'REFUSED', '4c': 'ALLOWED', 5: 'DENIED',
    '6a': 'DENIED', '6b': 'DENIED', '6c': 'DENIED', '7a': 'ALLOWED', '7b': 'DENIED', '8a': 'ALLOWED',
    '8b': 'DENIED', '8c': 'DENIED', 9: 'VERIFIED', '9b': 'REFUSED',
  };
  for (const [step, outcome] of Object.entries(expect)) {
    assert.ok(by[step], `missing step ${step}`);
    assert.equal(by[step].actual, outcome, `step ${step}: ${by[step].reason}`);
    assert.equal(by[step].ok, true, `step ${step} deviated: ${by[step].reason}`);
  }
  assert.equal(doc.rows.length, Object.keys(expect).length);
  // Denials must be for the RIGHT reason, not just any reason.
  assert.match(by[3].reason, /plan/);
  assert.match(by[5].reason, /replay/);
  assert.match(by['7b'].reason, /budget/);
  assert.match(by['8b'].reason, /delegat/);
});

test('the colorized walkthrough prints the summary table', () => {
  const r = exec('--no-color');
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /Summary/);
  assert.match(r.stdout, /All 17 outcomes matched expectations/);
});

test('a deviation makes the demo exit nonzero (--break uses a mis-configured server)', () => {
  const r = exec('--json', '--break');
  assert.equal(r.status, 1);
  assert.equal(JSON.parse(r.stdout).ok, false);
});

test('--step does not hang when stdin is not a terminal', () => {
  const r = exec('--step', '--no-color');
  assert.equal(r.status, 0, r.stderr);
});
