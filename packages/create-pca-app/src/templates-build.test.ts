import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { TEMPLATES, scaffold } from './index';

/**
 * The templates build and pass against the WORKSPACE packages (the 0.5.0 lineup, which carries requirePCA's operation binding, the `ext` subpaths,
 * allowedSuites / pqPins and the fail-closed deriveDecideInput), and every @atlasauth dependency range is ^0.5.0 so a
 * scaffolded app never resolves an older published release without those APIs.
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

describe('templates: ^0.5.0 and they build against the workspace packages', () => {
  it('every template (and the examples it mirrors) pins @atlasauth/* to ^0.5.0', () => {
    expect(TEMPLATES).toHaveLength(7);
    expect(TEMPLATES).toContain('actions');
    const files = [...TEMPLATES.map((t) => join(__dirname, '..', 'templates', t, 'package.json')), join(REPO, 'examples/pca-quickstart/package.json'), join(REPO, 'examples/pca-demo/package.json')];
    for (const f of files) {
      const pkg = JSON.parse(readFileSync(f, 'utf8')) as { dependencies?: Record<string, string> };
      const deps = Object.entries(pkg.dependencies ?? {}).filter(([k]) => k.startsWith('@atlasauth/'));
      expect(deps.length, f).toBeGreaterThan(0);
      for (const [k, v] of deps) expect(v, `${f} ${k}`).toBe('^0.5.0');
    }
  });

  for (const t of ['express-rs', 'node-quickstart', 'pca-quickstart'] as const) {
    it(`${t}: the scaffold type-checks with tsc against the workspace @atlasauth packages`, () => {
      const target = join(mkdtempSync(join(tmpdir(), `tpl-${t}-`)), 'app');
      scaffold({ dir: target, template: t });
      const nm = join(target, 'node_modules');
      mkdirSync(join(nm, '@atlasauth'), { recursive: true });
      mkdirSync(join(nm, '@types'), { recursive: true });
      const pkg = JSON.parse(readFileSync(join(target, 'package.json'), 'utf8')) as { dependencies: Record<string, string> };
      for (const dep of Object.keys(pkg.dependencies)) {
        if (dep.startsWith('@atlasauth/')) {
          const ws = join(REPO, 'packages', dep.slice('@atlasauth/'.length));
          expect(existsSync(join(ws, 'dist', 'index.d.ts')), `${dep} dist`).toBe(true);
          symlinkSync(ws, join(nm, dep));
        }
      }
      if (pkg.dependencies['express']) symlinkSync(store(/^express@5\./, 'express'), join(nm, 'express'));
      const ts = store(/^typescript@5\./, 'typescript');
      for (const d of readdirSync(STORE)) {
        if (!d.startsWith('@types+')) continue;
        const typesDir = join(STORE, d, 'node_modules', '@types');
        if (!existsSync(typesDir)) continue;
        for (const name of readdirSync(typesDir)) if (!existsSync(join(nm, '@types', name))) symlinkSync(join(typesDir, name), join(nm, '@types', name));
      }
      execFileSync(process.execPath, [join(ts, 'bin', 'tsc'), '-p', join(target, 'tsconfig.json'), '--noEmit'], { cwd: target, stdio: 'pipe' });
    }, 120_000);
  }
});
