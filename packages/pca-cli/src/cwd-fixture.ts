// Test fixture: run code "from" another working directory without process.chdir(), which worker threads do not support.
// The CLI resolves relative paths against the working directory, so the fs functions it uses are wrapped to resolve
// relative string paths against the directory set by inCwd(), and process.cwd() reports it.
import { resolve } from 'node:path';

const G = globalThis as { __pcaCliTestCwd?: string }; // global: vi.resetModules() would otherwise give each import its own state
const PATH_FNS = ['existsSync', 'mkdirSync', 'readFileSync', 'readdirSync', 'statSync', 'writeFileSync'] as const;

/** Wrap an fs module so relative paths resolve against the directory set by inCwd(). */
export function withVirtualCwd<T extends object>(fs: T): T {
  const out = { ...fs } as Record<string, unknown>;
  for (const n of PATH_FNS) {
    const f = (fs as Record<string, unknown>)[n] as (...a: unknown[]) => unknown;
    out[n] = (p: unknown, ...rest: unknown[]) => f(typeof p === 'string' && G.__pcaCliTestCwd !== undefined ? resolve(G.__pcaCliTestCwd, p) : p, ...rest);
  }
  return out as unknown as T;
}

export function inCwd<R>(dir: string, run: () => R): R {
  const prev = G.__pcaCliTestCwd;
  const real = process.cwd.bind(process);
  G.__pcaCliTestCwd = dir;
  process.cwd = () => dir;
  const restore = (): void => { G.__pcaCliTestCwd = prev; process.cwd = real; };
  let r: R;
  try { r = run(); } catch (e) { restore(); throw e; }
  if (r instanceof Promise) return r.finally(restore) as R;
  restore();
  return r;
}
