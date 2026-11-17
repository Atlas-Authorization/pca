/** Apply a plan: preflight, then write. Key material is written last, with 0600, never over an existing file. */
import { chmodSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { gitState } from './git';
import { renderChange } from './diff';
import type { InitDeps, InitResult, Plan } from './types';

export function renderPlan(p: Plan): string {
  const d = p.detection;
  const out: string[] = [
    `Detected: ${d.language}${d.framework ? ` / ${d.framework}` : ''}${d.agents.length ? `; agents: ${d.agents.join(', ')}` : ''}${d.mcpServers.length ? `; MCP servers: ${d.mcpServers.map((s) => s.name).join(', ')}` : ''}`,
    `Mode: ${p.mode}${p.mode === 'observe' ? ' (records, never blocks)' : ' (verifies; refuses what is not proven)'}${p.proxy ? '; via pca-proxy (no code changes)' : ''}`,
    '',
  ];
  if (p.changes.length === 0) out.push('Nothing to change: this project is already set up.');
  for (const c of p.changes) out.push(renderChange(c), '');
  if (p.install.length > 0) out.push('Then run:', ...p.install.map((c) => `  ${c}`), '');
  for (const s of p.snippets) out.push(`Paste this: ${s.title}`, `  at: ${s.where}`, ...s.code.split('\n').map((l) => `    ${l}`), '');
  for (const n of p.notes) out.push(`Note: ${n}`);
  return out.join('\n').replace(/\n+$/, '');
}

export function renderNext(p: Plan): string {
  return ['What next:', ...p.nextSteps.map((s, i) => `  ${i + 1}. ${s}`)].join('\n');
}

export function applyPlan(p: Plan, deps: InitDeps, o: { force: boolean }): InitResult {
  const dir = p.detection.dir;
  if (p.blockers.length > 0) return { ok: false, text: `Refusing to apply:\n${p.blockers.map((b) => `  - ${b}`).join('\n')}` };
  const writes = p.changes.filter((c) => c.generated !== undefined || c.before !== c.after);
  if (writes.length > 0 && p.dirty && !o.force) {
    return { ok: false, text: 'Refusing to apply: the git working tree has uncommitted changes, so you could not review or undo what init does. Commit or stash first, or pass --force.' };
  }
  const put = (c: { path: string; after: string; mode?: number }, exclusive = false): void => {
    const abs = join(dir, c.path);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, c.after, { ...(c.mode !== undefined ? { mode: c.mode } : {}), ...(exclusive ? { flag: 'wx' } : {}) });
    if (c.mode !== undefined) chmodSync(abs, c.mode);
  };
  const plain = writes.filter((c) => c.generated === undefined);
  // .gitignore first: the key is only written once git agrees it is ignored
  for (const c of plain.filter((x) => x.path === '.gitignore')) put(c);
  const state = gitState(deps.git, dir);
  if (state.repo) {
    for (const c of writes.filter((x) => x.generated === 'secret')) {
      if (deps.git(dir, ['check-ignore', '-q', '--', c.path]).code !== 0) {
        return { ok: false, text: `Refusing to write ${c.path}: git does not ignore it (a negation rule in a .gitignore re-includes it). Fix that rule and run again.` };
      }
    }
  }
  for (const c of plain.filter((x) => x.path !== '.gitignore')) put(c);
  const wrote = plain.map((c) => c.path);
  const keys = writes.filter((c) => c.generated !== undefined);
  if (keys.length > 0) {
    const pairs = new Map<string, { secret: string; publicKey: string }>();
    for (const c of keys) {
      if (existsSync(join(dir, c.path))) continue;
      const g = c.group ?? 'dev';
      if (!pairs.has(g)) pairs.set(g, deps.newKey());
      const k = pairs.get(g)!;
      put({ path: c.path, after: `${c.generated === 'secret' ? k.secret : k.publicKey}\n`, ...(c.mode !== undefined ? { mode: c.mode } : {}) }, true);
      wrote.push(c.path);
    }
  }
  return { ok: true, text: `Wrote ${wrote.length} file${wrote.length === 1 ? '' : 's'}: ${wrote.join(', ')}` };
}
