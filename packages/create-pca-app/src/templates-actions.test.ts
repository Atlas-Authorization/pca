import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { scaffold } from './index';

const REPO = (() => {
  let dir = __dirname;
  for (let i = 0; i < 8; i++) {
    if (existsSync(join(dir, 'pnpm-workspace.yaml'))) return dir;
    dir = dirname(dir);
  }
  throw new Error('monorepo root not found');
})();
const STORE = join(REPO, 'node_modules', '.pnpm');
const store = (prefix: RegExp, inner: string): string => {
  const hit = readdirSync(STORE).filter((d) => prefix.test(d)).sort().pop();
  if (!hit) throw new Error(`store package ${prefix} missing`);
  return join(STORE, hit, 'node_modules', inner);
};

describe('template actions', () => {
  const target = join(mkdtempSync(join(tmpdir(), 'tpl-actions-')), 'app');
  scaffold({ dir: target, template: 'actions', name: 'my-actions' });
  const nm = join(target, 'node_modules');
  mkdirSync(join(nm, '@atlasauth'), { recursive: true });
  mkdirSync(join(nm, '@types'), { recursive: true });
  for (const dep of ['pca-actions', 'pca-cli']) symlinkSync(join(REPO, 'packages', dep), join(nm, '@atlasauth', dep));
  for (const d of readdirSync(STORE)) {
    if (!d.startsWith('@types+')) continue;
    const typesDir = join(STORE, d, 'node_modules', '@types');
    if (!existsSync(typesDir)) continue;
    for (const name of readdirSync(typesDir)) if (!existsSync(join(nm, '@types', name))) symlinkSync(join(typesDir, name), join(nm, '@types', name));
  }
  const cli = (...args: string[]): string => execFileSync(process.execPath, [join(REPO, 'packages', 'pca-cli', 'dist', 'cli.js'), ...args], { cwd: target, encoding: 'utf8' });

  it('pins the toolchain to ^0.5.0 and names the project', () => {
    const pkg = JSON.parse(readFileSync(join(target, 'package.json'), 'utf8')) as { name: string; dependencies: Record<string, string> };
    expect(pkg.name).toBe('my-actions');
    expect(pkg.dependencies).toEqual({ '@atlasauth/pca-actions': '^0.5.0', '@atlasauth/pca-cli': '^0.5.0' });
  });
  it('the scaffolded project lints (strict), passes its examples and builds', () => {
    expect(cli('actions', 'lint', '--strict')).toMatch(/0 errors, 0 warnings/);
    expect(cli('actions', 'test')).toMatch(/PASS {2}acme\.invoice\.send example 1: expected allow, got allow/);
    expect(cli('actions', 'build')).toMatch(/built 1 action/);
    expect(existsSync(join(target, '.pca', 'pack.json'))).toBe(true);
  }, 120_000);
  it('the TypeScript builder type-checks and has the digest of the YAML', () => {
    const ts = store(/^typescript@5\./, 'typescript');
    execFileSync(process.execPath, [join(ts, 'bin', 'tsc'), '-p', join(target, 'tsconfig.json'), '--noEmit'], { cwd: target, stdio: 'pipe' });
    const tsx = store(/^tsx@4\./, 'tsx');
    const out = execFileSync(process.execPath, [join(tsx, 'dist', 'cli.mjs'), 'builder.ts'], { cwd: target, encoding: 'utf8' });
    expect(out).toMatch(/same digest/);
  }, 120_000);
});
