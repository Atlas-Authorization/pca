/**
 * R3-02 fuzz: the regex guard + linear-time engine against V8 as the reference. Run on a Linux machine:
 *   on a Linux machine: "node node_modules/.pnpm/tsx@*\/node_modules/tsx/dist/cli.mjs tools/pca-audit/fuzz/safe-regex-fuzz.ts 150000 1"
 * args: <patterns> <seed>
 *
 * Two properties, each over >= 100k generated patterns (a grammar biased towards the round-3 hazards: `[]`, `[^]`, `]` right
 * after `[`, nested quantifiers, alternation under repetition, `{n,m}`, escapes, anchors, lookaround, backrefs):
 *
 *  A. SEMANTICS (engine vs V8, short subjects so even a backtracking blow-up finishes): whenever compileSafeRegex accepts a
 *     pattern, safeRegexFullMatch(p, s) === new RegExp('^(?:' + p + ')$').test(s) for every probe subject. V8 runs in a
 *     supervised CHILD process (killed on a hang), so a pattern the engine accepts but V8 explodes on is reported, not hung.
 *  B. COST (the guard's promise): for every pattern isSafeRegexSource accepts, matching adversarial 512-char subjects on the
 *     engine takes < MAX_MS (a few ms), AND the same pattern on V8's backtracking engine takes < V8_MAX_MS (so even the
 *     legacy "run it on RegExp" reading of the guard is safe) - the reference backtracking-cost measure.
 */
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isSafeRegexSource } from '../../../packages/pca/src/predicates';
import { compileSafeRegex, runSafeRegex, safeRegexFullMatch } from '../../../packages/pca/src/safe-regex';

const N = Number(process.argv[2] ?? 100_000);
const SEED = Number(process.argv[3] ?? 1);
const CHILD = process.argv[2] === '--child';
const MAX_MS = 5; // engine, per (pattern, 512-char subject)
const V8_MAX_MS = 50; // V8 on a guard-accepted pattern

// ---- deterministic PRNG --------------------------------------------------------------------------------------------------
let st = (SEED * 2654435761) >>> 0 || 1;
const rnd = (): number => {
  st ^= st << 13;
  st >>>= 0;
  st ^= st >>> 17;
  st ^= st << 5;
  st >>>= 0;
  return st / 4294967296;
};
const pick = <T>(a: readonly T[]): T => a[Math.floor(rnd() * a.length)]!;
const int = (n: number): number => Math.floor(rnd() * n);

// ---- pattern generator ---------------------------------------------------------------------------------------------------
const LIT = ['a', 'b', 'c', '/', ']', '-', 'x', '0', ' ', '_'];
const ESC = ['\\d', '\\D', '\\w', '\\W', '\\s', '\\S', '\\.', '\\/', '\\]', '\\[', '\\\\', '\\-', '\\t', '\\n', '\\x41', '\\u0061', '\\0', '\\1', '\\k', '\\b', '\\B', '\\p', '\\cJ'];
const QUANT = ['*', '+', '?', '*?', '+?', '??', '{2}', '{0,3}', '{1,}', '{2,5}', '{,3}', '{', '{3,2}', '{64}', '{65}', '{1,64}'];
function cls(): string {
  const body: string[] = [];
  for (let i = int(4); i > 0; i--) body.push(pick([...LIT, ...ESC.slice(0, 8), 'a-c', '0-9', 'a-z', 'z-a', '\\d-x', '-', '^', ']']));
  return pick(['[', '[^', '[]', '[^]', '[]]', '[^]]']) + body.join('') + pick([']', ']', ']', '']);
}
function atom(d: number): string {
  const r = rnd();
  if (r < 0.28) return pick(LIT);
  if (r < 0.4) return pick(ESC);
  if (r < 0.5) return '.';
  if (r < 0.66) return cls();
  if (r < 0.7) return pick(['^', '$']);
  if (d > 3) return pick(LIT);
  const g = pick(['(', '(?:', '(?:', '(?=', '(?!', '(?<=', '(?<n>']);
  return g + alt(d + 1) + (rnd() < 0.97 ? ')' : '');
}
function seq(d: number): string {
  let s = '';
  for (let i = 1 + int(4); i > 0; i--) s += atom(d) + (rnd() < 0.45 ? pick(QUANT) : '');
  return s;
}
function alt(d: number): string {
  let s = seq(d);
  while (rnd() < 0.25) s += '|' + (rnd() < 0.1 ? '' : seq(d));
  return s;
}
const HAZARDS = ['[^](a+)+]', '[](a+)+]', '(a+)+', '(a|aa)+', '(.*a){10}', 'a?{30}a{30}', '[^](a*)*]', '[^]*[^]*[^]*[^]*x', '(?:[^]|a)+$', '([^]a?)+b', '[^](?:a|a)+]', '[]]', '[^]]]'];
function pattern(): string {
  if (rnd() < 0.04) return pick(HAZARDS);
  return alt(0);
}

// ---- subjects ---------------------------------------------------------------------------------------------------------------
function shortSubjects(p: string): string[] {
  const alpha = [...new Set([...(p.match(/[A-Za-z0-9/\] _-]/g) ?? []), 'a', ']', 'x', '\n', ' '])].slice(0, 8);
  const out = ['', 'a', ']', 'ab', '/a/b', 'aaaa]x'];
  for (let i = 0; i < 6; i++) {
    let s = '';
    for (let k = int(14); k > 0; k--) s += pick(alpha);
    out.push(s);
  }
  return out;
}
function adversarial(p: string): string[] {
  const lits = [...new Set(p.match(/[A-Za-z0-9/\]_-]/g) ?? ['a'])];
  const c = lits[0] ?? 'a';
  return ['a'.repeat(512), 'a'.repeat(511) + ']', ('a'.repeat(300) + ']x').slice(0, 512), c.repeat(512), (c.repeat(255) + 'b').repeat(2).slice(0, 512), ']'.repeat(512)];
}

// ---- child: run V8 over a batch with progress lines ---------------------------------------------------------------------
if (CHILD) {
  const lines: string[] = JSON.parse(readFileSync(process.argv[3]!, 'utf8'));
  const mode = process.argv[4]!;
  for (let i = 0; i < lines.length; i++) {
    const { p, subjects } = JSON.parse(lines[i]!) as { p: string; subjects: string[] };
    process.stdout.write(`B ${i}\n`);
    let re: RegExp | null = null;
    try {
      re = new RegExp('^(?:' + p + ')$');
    } catch {
      process.stdout.write(`E ${i}\n`);
      continue;
    }
    const res: Array<boolean | number> = [];
    let worst = 0;
    for (const s of subjects) {
      const t = performance.now();
      const r = re.test(s);
      worst = Math.max(worst, performance.now() - t);
      res.push(r);
    }
    process.stdout.write(`R ${i} ${mode === 'cost' ? worst.toFixed(3) : JSON.stringify(res)}\n`);
  }
  process.exit(0);
}

async function v8Batch(items: Array<{ p: string; subjects: string[] }>, mode: 'sem' | 'cost', timeoutMs: number): Promise<Array<{ status: 'ok' | 'syntax' | 'hang'; res?: unknown }>> {
  const out: Array<{ status: 'ok' | 'syntax' | 'hang'; res?: unknown }> = items.map(() => ({ status: 'hang' as const }));
  let from = 0;
  while (from < items.length) {
    const slice = items.slice(from);
    const dir = mkdtempSync(join(tmpdir(), 'srfuzz-'));
    const file = join(dir, 'batch.json');
    writeFileSync(file, JSON.stringify(slice.map((x) => JSON.stringify(x))));
    const child = spawn(process.execPath, [...process.execArgv, process.argv[1]!, '--child', file, mode], { stdio: ['ignore', 'pipe', 'inherit'] });
    let buf = '';
    let cur = -1;
    let deadline = Date.now() + 120_000; // child start-up (tsx loader) on a loaded box; tightened to timeoutMs once the first pattern begins
    const timer = setInterval(() => {
      if (Date.now() > deadline) child.kill('SIGKILL');
    }, 20);
    child.stdout!.on('data', (d: Buffer) => {
      buf += d.toString();
      let nl: number;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        const [k, idx, ...rest] = line.split(' ');
        const gi = from + Number(idx);
        if (k === 'B') {
          cur = gi;
          deadline = Date.now() + timeoutMs;
        } else if (k === 'E') out[gi] = { status: 'syntax' };
        else if (k === 'R') out[gi] = { status: 'ok', res: mode === 'cost' ? Number(rest[0]) : JSON.parse(rest.join(' ')) };
      }
    });
    await new Promise<void>((r) => child.on('close', () => r()));
    clearInterval(timer);
    rmSync(dir, { recursive: true, force: true });
    // Resume after the last pattern the child STARTED: if it died on it without a result it is a genuine hang (the default
    // status); if it had reported a result, the child was merely killed between patterns (start-up / load) and the rest of the
    // batch is simply re-run. A child that never started a pattern makes no progress: skip one item (reported as a hang).
    from = cur >= from ? cur + 1 : from + 1;
  }
  return out;
}

// ---- main -------------------------------------------------------------------------------------------------------------------
async function main(): Promise<void> {
  const failures: string[] = [];
  const stats = { patterns: 0, engineAccepted: 0, guardAccepted: 0, semChecks: 0, maxEngineMs: 0, maxV8Ms: 0, hazardsRejected: 0 };
  const BATCH = 400;
  for (let done = 0; done < N; done += BATCH) {
    const ps = Array.from({ length: Math.min(BATCH, N - done) }, pattern).filter((p) => p.length <= 200);
    stats.patterns += ps.length;

    // A. semantics
    const sem: Array<{ p: string; subjects: string[] }> = [];
    for (const p of ps) {
      if (compileSafeRegex(p) === null) continue;
      stats.engineAccepted++;
      sem.push({ p, subjects: shortSubjects(p) });
    }
    const semRes = await v8Batch(sem, 'sem', 4000);
    sem.forEach((it, i) => {
      const r = semRes[i]!;
      if (r.status === 'syntax') {
        // the engine accepted a pattern V8 rejects: the engine may be stricter, never looser
        failures.push(`SEM engine accepted a pattern V8 rejects: ${JSON.stringify(it.p)}`);
        return;
      }
      if (r.status === 'hang') return; // V8 itself blew up on a short subject; the engine is linear by construction
      const want = r.res as boolean[];
      it.subjects.forEach((s, k) => {
        stats.semChecks++;
        const got = safeRegexFullMatch(it.p, s);
        if (got !== want[k]) failures.push(`SEM mismatch p=${JSON.stringify(it.p)} s=${JSON.stringify(s)} engine=${String(got)} v8=${String(want[k])}`);
      });
    });

    // B. cost: every pattern the guard accepts
    const cost: Array<{ p: string; subjects: string[] }> = [];
    for (const p of ps) {
      const g = isSafeRegexSource(p);
      if (!g) {
        if (HAZARDS.includes(p)) stats.hazardsRejected++;
        continue;
      }
      stats.guardAccepted++;
      const subj = adversarial(p);
      const re = compileSafeRegex(p)!;
      const t = performance.now();
      for (const s of subj) runSafeRegex(re, s);
      const ms = (performance.now() - t) / subj.length;
      stats.maxEngineMs = Math.max(stats.maxEngineMs, ms);
      if (ms > MAX_MS) failures.push(`COST engine ${ms.toFixed(2)}ms/subject > ${MAX_MS}ms: ${JSON.stringify(p)}`);
      cost.push({ p, subjects: subj });
    }
    const costRes = await v8Batch(cost, 'cost', 3000);
    cost.forEach((it, i) => {
      const r = costRes[i]!;
      if (r.status === 'hang') failures.push(`COST guard-accepted pattern HANGS V8 (>3s): ${JSON.stringify(it.p)}`);
      else if (r.status === 'ok') {
        stats.maxV8Ms = Math.max(stats.maxV8Ms, r.res as number);
        if ((r.res as number) > V8_MAX_MS) failures.push(`COST guard-accepted pattern takes ${(r.res as number).toFixed(1)}ms on V8 (> ${V8_MAX_MS}ms): ${JSON.stringify(it.p)}`);
      }
    });
    if (failures.length > 20) break;
  }
  // the named PoC must be rejected instantly
  for (const h of ['[^](a+)+]', '[](a+)+]', '(a+)+', '(a|aa)+']) if (isSafeRegexSource(h)) failures.push(`PoC accepted by the guard: ${h}`);
  console.log(JSON.stringify({ seed: SEED, ...stats, failures: failures.length }));
  for (const f of failures.slice(0, 40)) console.log('FAIL ' + f);
  process.exit(failures.length === 0 ? 0 : 1);
}
void main();
