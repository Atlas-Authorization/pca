import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import {
  DEFAULT_TEMPLATE,
  NAME_TOKEN,
  TEMPLATES,
  defaultTemplatesDir,
  dirIsEmpty,
  isTemplateName,
  scaffold,
} from './index';

const freshDir = (slug = 'app'): string => join(mkdtempSync(join(tmpdir(), 'cpa-')), slug);

/** Walk up from here to the monorepo root (the dir holding pnpm-workspace.yaml). null if not found. */
function findRepoRoot(): string | null {
  let dir = __dirname;
  for (let i = 0; i < 8; i++) {
    if (existsSync(join(dir, 'pnpm-workspace.yaml'))) return dir;
    const up = dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return null;
}

/** First match of `<repoRoot>/node_modules/.pnpm/<prefix>@<ver>/node_modules/<inner>`, or null. */
function storePkg(repoRoot: string, prefix: string, inner: string): string | null {
  const store = join(repoRoot, 'node_modules', '.pnpm');
  if (!existsSync(store)) return null;
  const hit = readdirSync(store).find((d) => d.startsWith(`${prefix}@`));
  if (!hit) return null;
  const p = join(store, hit, 'node_modules', inner);
  return existsSync(p) ? p : null;
}

describe('create-pca-app scaffold', () => {
  it('ships the seven documented templates on disk', () => {
    expect([...TEMPLATES]).toEqual(['pca-demo', 'pca-quickstart', 'node-quickstart', 'express-rs', 'mcp', 'attacks', 'actions']);
    for (const t of TEMPLATES) {
      expect(existsSync(join(defaultTemplatesDir(), t, 'package.json'))).toBe(true);
    }
    expect(isTemplateName(DEFAULT_TEMPLATE)).toBe(true);
    expect(DEFAULT_TEMPLATE).toBe('pca-demo');
    expect(isTemplateName('nope')).toBe(false);
  });

  it('scaffolds the default (pca-quickstart): the full agent + requirePCA server loop', () => {
    const target = freshDir('my-pca-app');
    const res = scaffold({ dir: target, template: 'pca-quickstart' });

    expect(res.template).toBe('pca-quickstart');
    expect(res.name).toBe('my-pca-app');
    expect(res.files).toEqual([
      '.gitignore',
      'README.md',
      'package.json',
      'src/agent.ts',
      'src/run.ts',
      'src/server.ts',
      'tsconfig.json',
    ]);

    const agent = readFileSync(join(target, 'src/agent.ts'), 'utf8');
    expect(agent).toContain("from '@atlasauth/pca'");
    expect(agent).toContain('agent({'); // the facade one-liner
    expect(agent).toContain('.act(');

    const server = readFileSync(join(target, 'src/server.ts'), 'utf8');
    expect(server).toContain("from '@atlasauth/pca-express'");
    expect(server).toContain('pcaExpress('); // requirePCA() for Express

    const pkg = JSON.parse(readFileSync(join(target, 'package.json'), 'utf8')) as {
      name: string;
      dependencies: Record<string, string>;
    };
    expect(pkg.name).toBe('my-pca-app');
    expect(pkg.dependencies['@atlasauth/pca']).toBeDefined();
    expect(pkg.dependencies['@atlasauth/pca-express']).toBeDefined();
    expect(pkg.dependencies.express).toBeDefined();
    // the placeholder token must be fully substituted everywhere
    expect(readFileSync(join(target, 'package.json'), 'utf8')).not.toContain(NAME_TOKEN);
    expect(readFileSync(join(target, 'README.md'), 'utf8')).toContain('# my-pca-app');
  });

  it('honours an explicit name override', () => {
    const target = freshDir('whatever');
    const res = scaffold({ dir: target, name: 'custom-name', template: 'pca-quickstart' });
    const pkg = JSON.parse(readFileSync(join(res.dir, 'package.json'), 'utf8')) as { name: string };
    expect(pkg.name).toBe('custom-name');
  });

  it("renames the template's `gitignore` to `.gitignore` on write (npm would strip a real one)", () => {
    const target = freshDir();
    scaffold({ dir: target });
    expect(existsSync(join(target, '.gitignore'))).toBe(true);
    expect(existsSync(join(target, 'gitignore'))).toBe(false);
    expect(readFileSync(join(target, '.gitignore'), 'utf8')).toContain('node_modules');
  });

  it('scaffolds node-quickstart: the one-file authF loop (allow then tampered-deny)', () => {
    const target = freshDir();
    const res = scaffold({ dir: target, template: 'node-quickstart' });
    expect(res.template).toBe('node-quickstart');
    const src = readFileSync(join(target, 'src/index.ts'), 'utf8');
    expect(src).toContain("from '@atlasauth/pca'");
    for (const api of ['agent', 'generateKeyPair', 'decodePCActn', 'verifyPCActn(']) {
      expect(src).toContain(api);
    }
    expect(src).toContain('.act(');
    expect(src).toContain('tampered.action.resource');
  });

  it('scaffolds express-rs: a verifying server + a valid-vs-tampered client', () => {
    const target = freshDir('my-server');
    const res = scaffold({ dir: target, template: 'express-rs' });
    expect(res.template).toBe('express-rs');
    expect(res.files).toContain('src/server.ts');
    expect(res.files).toContain('src/client.ts');

    const server = readFileSync(join(target, 'src/server.ts'), 'utf8');
    expect(server).toContain('createGuard');
    expect(server).toContain("req.header('PCA-Action')");
    expect(server).not.toContain('PCA-Grant');
    const guard = readFileSync(join(target, 'src/guard.ts'), 'utf8');
    expect(guard).toContain("from '@atlasauth/pca'");
    expect(guard).toContain('requirePCA(');
    expect(guard.replace(/\/\*[\s\S]*?\*\//g, '')).not.toContain('verifyPCActnCore');

    const client = readFileSync(join(target, 'src/client.ts'), 'utf8');
    expect(client).toContain('fetch(');
    expect(client).toContain('tampered.action.resource');
  });

  it('scaffolds mcp: an MCP server whose tools require a PCActn, and an agent that sends one', () => {
    const target = freshDir('my-mcp');
    const res = scaffold({ dir: target, template: 'mcp' });
    expect(res.template).toBe('mcp');
    for (const f of ['.gitignore', 'README.md', 'package.json', 'tsconfig.json', 'src/agent.ts', 'src/demo.ts', 'src/server.ts', 'src/store.ts', 'src/tools.ts']) {
      expect(res.files).toContain(f);
    }
    const pkg = JSON.parse(readFileSync(join(target, 'package.json'), 'utf8')) as { name: string; dependencies: Record<string, string> };
    expect(pkg.name).toBe('my-mcp');
    expect(Object.keys(pkg.dependencies)).toEqual(expect.arrayContaining(['@atlasauth/pca', '@atlasauth/pca-mcp', '@atlasauth/pca-mcp-rs', '@modelcontextprotocol/sdk']));
    expect(readFileSync(join(target, 'src/agent.ts'), 'utf8')).toContain('pcaFetch(');
    expect(readFileSync(join(target, 'src/server.ts'), 'utf8')).toContain('authorizeToolCall(');
  });

  it('refuses to scaffold into a non-empty directory', () => {
    const target = freshDir();
    scaffold({ dir: target }); // first time ok -> now non-empty
    expect(() => scaffold({ dir: target })).toThrow(/non-empty directory/);
    // an existing but empty dir is fine
    const empty = freshDir('empty');
    expect(dirIsEmpty(empty)).toBe(true);
    expect(() => scaffold({ dir: empty })).not.toThrow();
  });

  it('rejects an unknown template name', () => {
    const target = freshDir();
    expect(() => scaffold({ dir: target, template: 'django' })).toThrow(/unknown template/);
  });

  it('the generated quickstart sources are suppression-free (no any / ts-ignore / eslint-disable)', () => {
    const target = freshDir();
    scaffold({ dir: target, template: 'pca-quickstart' });
    for (const rel of ['src/agent.ts', 'src/server.ts', 'src/run.ts']) {
      const src = readFileSync(join(target, rel), 'utf8');
      expect(src).not.toMatch(/:\s*any\b/);
      expect(src).not.toContain('@ts-ignore');
      expect(src).not.toContain('@ts-expect-error');
      expect(src).not.toContain('eslint-disable');
      const opens = (src.match(/\{/g) ?? []).length;
      const closes = (src.match(/\}/g) ?? []).length;
      expect(opens).toBe(closes);
    }
    expect(readFileSync(join(target, 'src/run.ts'), 'utf8')).toContain('main().catch');
  });

  it('is byte-stable: scaffolding the same template twice yields identical file contents', () => {
    const a = freshDir();
    const b = freshDir();
    scaffold({ dir: a, name: 'same', template: 'pca-quickstart' });
    scaffold({ dir: b, name: 'same', template: 'pca-quickstart' });
    for (const rel of ['package.json', 'src/agent.ts', 'src/server.ts', 'src/run.ts', 'tsconfig.json']) {
      expect(readFileSync(join(a, rel), 'utf8')).toBe(readFileSync(join(b, rel), 'utf8'));
    }
    writeFileSync(join(a, 'marker'), 'x');
    expect(existsSync(join(a, 'marker'))).toBe(true);
  });

  // The real proof the scaffold is wired correctly: compile the generated project with `tsc` against
  // the actual @atlasauth/pca + @atlasauth/pca-express type declarations. Resolves everything from the
  // monorepo store (mirrors what `npm install` links). Skips cleanly if the workspace/built dist is not
  // present (e.g. a stripped checkout), so it never fails spuriously.
  it('type-checks the generated pca-quickstart with tsc against the real declarations', () => {
    const repoRoot = findRepoRoot();
    if (!repoRoot) {
      console.warn('[skip] monorepo root not found; cannot type-check the scaffold');
      return;
    }
    const need: Record<string, string | null> = {
      pca: existsSync(join(repoRoot, 'packages/pca/dist/index.d.ts')) ? join(repoRoot, 'packages/pca') : null,
      pcaExpress: existsSync(join(repoRoot, 'packages/pca-express/dist/index.d.ts')) ? join(repoRoot, 'packages/pca-express') : null,
      express: storePkg(repoRoot, 'express', 'express'),
      typescript: storePkg(repoRoot, 'typescript', 'typescript'),
    };
    if (Object.values(need).some((v) => v === null)) {
      console.warn('[skip] built packages / store deps not present; cannot type-check the scaffold');
      return;
    }

    const target = freshDir('tc');
    scaffold({ dir: target, template: 'pca-quickstart' });
    const nm = join(target, 'node_modules');
    mkdirSync(join(nm, '@atlasauth'), { recursive: true });
    mkdirSync(join(nm, '@types'), { recursive: true });
    symlinkSync(need.pca as string, join(nm, '@atlasauth/pca'));
    symlinkSync(need.pcaExpress as string, join(nm, '@atlasauth/pca-express'));
    symlinkSync(need.express as string, join(nm, 'express'));
    symlinkSync(need.typescript as string, join(nm, 'typescript'));
    // Link every @types/* the store carries (covers @types/node, @types/express and its transitive deps).
    const store = join(repoRoot, 'node_modules', '.pnpm');
    for (const d of readdirSync(store)) {
      if (!d.startsWith('@types+')) continue;
      const typesDir = join(store, d, 'node_modules', '@types');
      if (!existsSync(typesDir)) continue;
      for (const name of readdirSync(typesDir)) {
        const link = join(nm, '@types', name);
        if (!existsSync(link)) symlinkSync(join(typesDir, name), link);
      }
    }

    const tsc = join(need.typescript as string, 'bin', 'tsc');
    // Throws (failing the test) on any type error; stdout/stderr surface the diagnostics.
    execFileSync(process.execPath, [tsc, '-p', join(target, 'tsconfig.json'), '--noEmit'], {
      cwd: target,
      stdio: 'pipe',
    });
  }, 120_000);

  it('scaffolds pca-demo (the default): the nine-outcome story, runnable and in sync with examples/pca-demo', () => {
    const target = freshDir('my-demo');
    const res = scaffold({ dir: target });
    expect(res.template).toBe('pca-demo');
    expect(res.files).toEqual(['.gitignore', 'README.md', 'load.mjs', 'package.json', 'run.mjs', 'story.mjs']);
    expect(readFileSync(join(target, 'package.json'), 'utf8')).not.toContain(NAME_TOKEN);

    const repoRoot = findRepoRoot();
    if (!repoRoot) return;
    // The template is a copy of the repo's runnable example: keep them byte-identical.
    const example = join(repoRoot, 'examples/pca-demo');
    if (existsSync(example)) {
      for (const f of ['run.mjs', 'story.mjs', 'load.mjs']) {
        expect(readFileSync(join(target, f), 'utf8')).toBe(readFileSync(join(example, f), 'utf8'));
      }
    }
    // Run it for real against the built workspace packages (what `npm install` would link).
    const pca = join(repoRoot, 'packages/pca');
    const fetchPkg = join(repoRoot, 'packages/pca-fetch');
    if (!existsSync(join(pca, 'dist/index.js')) || !existsSync(join(fetchPkg, 'dist/index.js'))) {
      console.warn('[skip] built packages not present; cannot run the scaffolded demo');
      return;
    }
    const nm = join(target, 'node_modules/@atlasauth');
    mkdirSync(nm, { recursive: true });
    symlinkSync(pca, join(nm, 'pca'));
    symlinkSync(fetchPkg, join(nm, 'pca-fetch'));
    const out = execFileSync(process.execPath, [join(target, 'run.mjs'), '--json'], { cwd: target, encoding: 'utf8' });
    const doc = JSON.parse(out) as { ok: boolean; rows: { ok: boolean }[] };
    expect(doc.ok).toBe(true);
    expect(doc.rows.length).toBeGreaterThanOrEqual(9);
  }, 60_000);
});
