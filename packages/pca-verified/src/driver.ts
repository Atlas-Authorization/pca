import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isObj, type Json } from './util';

export interface DriverSpec {
  /** Shell command. `{in}` and `{out}` are replaced by the (quoted) file paths; with neither present they are appended as two arguments. */
  command: string;
  /** `files`: `<in.jsonl> <out.jsonl>` paths (the reference drivers). `stdio`: JSONL on stdin, JSONL on stdout. */
  io?: 'files' | 'stdio';
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  /** Time budget for ONE item; a batch gets this plus 100 ms per item. An item that exceeds it is a hang. Default 15000. */
  caseTimeoutMs?: number;
  /** Items per driver process (default 200; producer items 8: some signatures take seconds). */
  batchSize?: number;
}

export interface Fault {
  fault: 'hang' | 'crash' | 'missing' | 'no_output';
}
export const isFault = (a: unknown): a is Fault => isObj(a) && typeof (a as Fault).fault === 'string' && Object.keys(a).length === 1;

export interface DriverRun {
  answers: Map<string, Json | Fault>;
  /** Lines the protocol forbids: not JSON, not an object with a string id, an id nobody asked for, an id answered twice. */
  violations: string[];
  /** The tail of the driver's stderr from the last failing process, for the human log only (never part of a report). */
  stderrTail: string;
}

const q = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`;

interface Once {
  answers: Map<string, Json>;
  timedOut: boolean;
  code: number | null;
  stderr: string;
  violations: string[];
}

function execOnce(spec: DriverSpec, batch: Record<string, Json>[], timeoutMs: number): Promise<Once> {
  const dir = mkdtempSync(join(tmpdir(), 'pca-verified-'));
  const inp = join(dir, 'in.jsonl');
  const outp = join(dir, 'out.jsonl');
  const text = batch.map((l) => JSON.stringify(l)).join('\n') + '\n';
  const stdio = spec.io === 'stdio';
  let command = spec.command;
  if (!stdio) {
    writeFileSync(inp, text);
    if (command.includes('{in}') || command.includes('{out}')) command = command.split('{in}').join(q(inp)).split('{out}').join(q(outp));
    else command = `${command} ${q(inp)} ${q(outp)}`;
  }
  return new Promise<Once>((resolve) => {
    // detached: the shell and the driver below it form one process group, so a hang is killed as a whole
    const child = spawn(command, { shell: true, cwd: spec.cwd, env: { ...process.env, ...(spec.env ?? {}) }, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    child.stdout.on('data', (d: Buffer) => { if (stdio && stdout.length < 1 << 28) stdout += d.toString('utf8'); });
    child.stderr.on('data', (d: Buffer) => { stderr = (stderr + d.toString('utf8')).slice(-600); });
    child.stdin.on('error', () => undefined);
    if (stdio) child.stdin.end(text);
    else child.stdin.end();
    const timer = setTimeout(() => {
      timedOut = true;
      try { process.kill(-(child.pid as number), 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch { /* already gone */ } }
    }, timeoutMs);
    let finished = false;
    const done = (code: number | null): void => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      const ids = new Set(batch.map((l) => String(l.id)));
      const answers = new Map<string, Json>();
      const violations: string[] = [];
      let body = stdout;
      if (!stdio) {
        try { body = readFileSync(outp, 'utf8'); } catch { body = ''; }
      }
      rmSync(dir, { recursive: true, force: true });
      for (const l of body.split('\n')) {
        if (!l) continue;
        let o: Json;
        try { o = JSON.parse(l); } catch { violations.push('line is not JSON'); continue; }
        if (!isObj(o) || typeof o.id !== 'string') { violations.push('line has no string id'); continue; }
        if (!ids.has(o.id)) { violations.push('answer for an id that was not asked'); continue; }
        if (answers.has(o.id)) { violations.push('id answered twice'); continue; }
        answers.set(o.id, o);
      }
      resolve({ answers, timedOut, code, stderr, violations });
    };
    child.on('error', () => done(null));
    child.on('close', (code) => done(code));
  });
}

/**
 * Run every line through the driver. Items the driver does not answer (it hung, crashed or skipped them) are isolated by
 * bisection and come back as faults; a driver that starts but answers nothing is classified without a full bisection.
 */
export async function runDriver(spec: DriverSpec, lines: Record<string, Json>[], batchSize = spec.batchSize ?? 200): Promise<DriverRun> {
  const budget = spec.caseTimeoutMs ?? 15000;
  const answers = new Map<string, Json | Fault>();
  const violations: string[] = [];
  let stderrTail = '';
  const go = async (batch: Record<string, Json>[]): Promise<void> => {
    if (!batch.length) return;
    const r = await execOnce(spec, batch, budget + batch.length * 100);
    violations.push(...r.violations);
    for (const [k, v] of r.answers) if (!answers.has(k)) answers.set(k, v);
    const missing = batch.filter((l) => !r.answers.has(String(l.id)));
    if (!missing.length) return;
    if (r.stderr) stderrTail = r.stderr;
    if (batch.length === 1) {
      answers.set(String(batch[0]!.id), { fault: r.timedOut ? 'hang' : r.answers.size === 0 && r.code !== 0 ? 'crash' : 'missing' });
      return;
    }
    if (r.answers.size === 0 && !r.timedOut) {
      // nothing answered and no hang: probe the first and the last item alone; if both fail the driver is broken for all of them
      const probes = [batch[0]!, batch[batch.length - 1]!];
      const res = await Promise.all(probes.map((p) => execOnce(spec, [p], budget + 100)));
      if (res.every((x) => x.answers.size === 0 && !x.timedOut)) {
        for (const m of missing) answers.set(String(m.id), { fault: 'no_output' });
        return;
      }
      for (const x of res) for (const [k, v] of x.answers) if (!answers.has(k)) answers.set(k, v);
    }
    const rest = missing.filter((l) => !answers.has(String(l.id)));
    const mid = rest.length >> 1;
    await go(rest.slice(0, mid));
    await go(rest.slice(mid));
  };
  for (let i = 0; i < lines.length; i += batchSize) await go(lines.slice(i, i + batchSize));
  return { answers, violations, stderrTail };
}
