import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { scaffold } from './index';

/**
 * The golden-path templates RUN, not only type-check: each is scaffolded, linked to the workspace packages, executed with
 * tsx, and must exit 0 and print its closing line (every scripted outcome as expected).
 */
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

describe('golden-path templates run to completion', () => {
  for (const t of ['payments', 'delegation', 'goal'] as const) {
    it(`${t}: npm start exits 0 with every outcome as expected`, () => {
      const target = join(mkdtempSync(join(tmpdir(), `run-${t}-`)), 'app');
      scaffold({ dir: target, template: t });
      const nm = join(target, 'node_modules');
      mkdirSync(join(nm, '@atlasauth'), { recursive: true });
      const pkg = JSON.parse(readFileSync(join(target, 'package.json'), 'utf8')) as { dependencies: Record<string, string> };
      for (const dep of Object.keys(pkg.dependencies)) {
        if (dep.startsWith('@atlasauth/')) symlinkSync(join(REPO, 'packages', dep.slice('@atlasauth/'.length)), join(nm, dep));
      }
      const tsx = store(/^tsx@4\./, 'tsx');
      const out = execFileSync(process.execPath, [join(tsx, 'dist', 'cli.mjs'), 'src/index.ts'], { cwd: target, encoding: 'utf8' });
      expect(out).toMatch(/All outcomes as expected\./);
      expect(out).not.toMatch(/FAIL/);
    }, 120_000);
  }

  for (const t of ['payments', 'delegation', 'goal'] as const) {
    it(`examples/pca-${t} mirrors the ${t} template source`, () => {
      const tpl = join(__dirname, '..', 'templates', t, 'src', 'index.ts');
      const ex = join(REPO, 'examples', `pca-${t}`, 'src', 'index.ts');
      expect(readFileSync(ex, 'utf8')).toBe(readFileSync(tpl, 'utf8'));
    });
  }
});
