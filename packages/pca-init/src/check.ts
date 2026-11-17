/** `pca init --check`: verify an existing integration. Read-only. The doctor runs for the live parts (suites; clock and proxy with --url). */
import { existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { runDoctor, type CheckResult } from '@atlasauth/pca-doctor';
import { AppChoiceError, findApp, listFiles, read } from './detect';
import { gitState } from './git';
import { InitError, readInitConfig, type InitConfig } from './plan';
import type { InitDeps, InitOptions, InitResult } from './types';
import { INIT_CONFIG } from './wiring';

const TOKEN: Record<string, { manifest: RegExp; code: RegExp; exts: string[] }> = {
  python: { manifest: /atlas[-_]pca/i, code: /atlas_pca/, exts: ['.py'] },
  ruby: { manifest: /atlas-pca/, code: /AtlasPca/, exts: ['.rb'] },
  go: { manifest: /pca-go/, code: /pca-go/, exts: ['.go'] },
  java: { manifest: /pca-spring|net\.atlasauth/, code: /PcaFilter|PcaInterceptor|net\.atlasauth\.pca/, exts: ['.java', '.kt', '.yml', '.yaml', '.properties'] },
  dotnet: { manifest: /AtlasPca/, code: /UsePca|PcaProtect/, exts: ['.cs'] },
  php: { manifest: /atlas-auth\/atlas-pca/, code: /Atlas\\Pca|Protect::protect/, exts: ['.php'] },
  rust: { manifest: /atlas-pca/, code: /atlas_pca/, exts: ['.rs'] },
  swift: { manifest: /AtlasPCA/, code: /AtlasPCAVapor|PcaMiddleware/, exts: ['.swift'] },
};

const row = (id: string, status: CheckResult['status'], detail: string, remediation?: string): CheckResult => ({ id, status, detail, ...(remediation !== undefined ? { remediation } : {}) });

export async function checkInit(o: InitOptions, deps: InitDeps): Promise<InitResult> {
  let dir: string;
  try {
    dir = findApp(o.cwd, o.app).dir;
  } catch (e) {
    if (e instanceof AppChoiceError) return { ok: false, text: e.message };
    throw e;
  }
  const r: CheckResult[] = [];
  let cfg: InitConfig | null = null;
  try {
    cfg = readInitConfig(dir);
  } catch (e) {
    r.push(row('config', 'fail', e instanceof InitError ? e.message : String(e), `Fix ${INIT_CONFIG}, or delete it and run \`pca init\` again.`));
  }
  if (cfg === null) {
    if (!r.some((x) => x.id === 'config')) r.push(row('config', 'fail', `${INIT_CONFIG} not found: PCA has not been initialized here`, 'Run `npx @atlasauth/pca-cli init --yes`.'));
    return report(r);
  }
  r.push(row('config', 'pass', `${INIT_CONFIG} is valid (via ${cfg.via}, ${cfg.language}${cfg.framework ? `/${cfg.framework}` : ''})`));
  r.push(cfg.mode === 'enforce' ? row('mode', 'pass', 'enforce: requests without a valid proof are refused') : row('mode', 'warn', 'observe: PCA records but does not protect yet', `Observe, review, then \`npx @atlasauth/pca-cli init --mode enforce\`.`));

  if (cfg.via === 'proxy') {
    const files = readdirSync(dir).filter((n) => /^pca-proxy(\..+)?\.yaml$/.test(n));
    if (files.length === 0) r.push(row('proxy', 'fail', 'no pca-proxy*.yaml found', 'Run `npx @atlasauth/pca-cli init --proxy --yes`.'));
    const { parseConfigText } = await import('@atlasauth/pca-proxy');
    for (const f of files) {
      try {
        const c = parseConfigText(read(join(dir, f)) ?? '', 'yaml');
        r.push(row(`proxy.${f}`, 'pass', `valid, mode ${c.mode}`));
      } catch (e) {
        r.push(row(`proxy.${f}`, 'fail', e instanceof Error ? e.message : String(e), `Fix ${f}; the proxy will not start on it.`));
      }
    }
  } else if (cfg.language === 'js') {
    const pj = read(join(dir, 'package.json'));
    let deps2: Record<string, string> = {};
    try {
      const p = JSON.parse(pj ?? '{}') as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
      deps2 = { ...p.dependencies, ...p.devDependencies };
    } catch {
      /* reported below as missing */
    }
    const need = ['@atlasauth/pca', ...(cfg.framework && ['express', 'fastify', 'hono', 'next'].includes(cfg.framework) ? [`@atlasauth/pca-${cfg.framework}`] : [])];
    const missing = need.filter((n) => deps2[n] === undefined);
    r.push(missing.length === 0 ? row('package', 'pass', `${need.join(', ')} in package.json`) : row('package', 'fail', `${missing.join(', ')} missing from package.json`, 'Run `npx @atlasauth/pca-cli init --yes`, then install.'));
    if (cfg.wiring === null) r.push(row('registered', 'warn', 'no generated wiring recorded for this framework', 'Wire the guard by hand (see the @atlasauth/pca README) or use `pca init --proxy`.'));
    else if (!existsSync(join(dir, cfg.wiring))) r.push(row('registered', 'fail', `${cfg.wiring} is missing`, 'Run `npx @atlasauth/pca-cli init --yes`.'));
    else {
      const use = /\b(registerPca\(|withPca\(|new PcaGuard\()/;
      const users = listFiles(dir, ['.ts', '.js', '.mjs', '.cjs', '.mts', '.tsx']).filter((f) => !f.endsWith(cfg!.wiring!) && use.test(read(f) ?? ''));
      r.push(users.length > 0 ? row('registered', 'pass', `registered in ${users.length} file${users.length === 1 ? '' : 's'}`) : row('registered', 'fail', `${cfg.wiring} exists but nothing calls it`, 'Add the one-line registration `pca init` printed (registerPca(app), withPca(handler) or app.useGlobalGuards(new PcaGuard())).'));
    }
  } else {
    const t = TOKEN[cfg.language];
    const manifests = ['pyproject.toml', 'requirements.txt', 'Gemfile', 'go.mod', 'pom.xml', 'build.gradle', 'build.gradle.kts', 'composer.json', 'Cargo.toml', 'Package.swift'].map((f) => read(join(dir, f)) ?? '').join('\n') + readdirSync(dir).filter((n) => n.endsWith('.csproj')).map((n) => read(join(dir, n)) ?? '').join('\n');
    if (t === undefined) r.push(row('package', 'warn', `no checks for ${cfg.language}`));
    else {
      r.push(t.manifest.test(manifests) ? row('package', 'pass', `the ${cfg.language} PCA package is in the project manifest`) : row('package', 'fail', `the ${cfg.language} PCA package is not in the project manifest`, 'Install it with the command `pca init` printed.'));
      const used = listFiles(dir, t.exts).some((f) => t.code.test(read(f) ?? ''));
      r.push(used ? row('registered', 'pass', 'the guard is referenced in the source') : row('registered', 'fail', 'the guard is not referenced in the source', 'Paste the snippet `pca init` printed.'));
    }
  }

  const keyAbs = join(dir, cfg.keyFile);
  const git = gitState(deps.git, dir);
  if (!existsSync(keyAbs)) r.push(row('keys', 'warn', `${cfg.keyFile} not found (a dev key is only needed to sign your first grant)`, 'Run `npx @atlasauth/pca-cli init --yes` to create one.'));
  else {
    r.push(git.tracked(cfg.keyFile) ? row('keys.tracked', 'fail', `${cfg.keyFile} is tracked by git`, `git rm --cached ${cfg.keyFile}, commit, and replace the key: it is leaked.`) : row('keys.tracked', 'pass', `${cfg.keyFile} is not tracked`));
    if (git.repo) r.push(deps.git(dir, ['check-ignore', '-q', '--', cfg.keyFile]).code === 0 ? row('keys.ignored', 'pass', 'git ignores the key file') : row('keys.ignored', 'fail', 'git does not ignore the key file', `Add ${cfg.keyFile} to .gitignore.`));
    const perm = statSync(keyAbs).mode & 0o077;
    if (process.platform !== 'win32') r.push(perm === 0 ? row('keys.permissions', 'pass', 'only you can read the key file') : row('keys.permissions', 'warn', 'the key file is readable by other users', `chmod 600 ${cfg.keyFile}`));
  }
  if (cfg.mode === 'enforce' && cfg.via === 'sdk') {
    r.push(existsSync(join(dir, cfg.grantFile)) ? row('grant', 'pass', `${cfg.grantFile} present`) : row('grant', 'fail', `${cfg.grantFile} is missing: enforce mode cannot start`, 'Create it with `pca autopilot review ... --grant-out`.'));
    r.push(...(await runDoctor({ verifier: {} }, ['suites'])));
  }
  if (o.url !== undefined) r.push(...(await runDoctor({ url: o.url }, ['clock', 'proxy'])));
  return report(r);
}

function report(r: CheckResult[]): InitResult {
  const bad = r.filter((x) => x.status === 'fail').length;
  const lines = r.map((x) => `[${x.status}] ${x.id}: ${x.detail}${x.remediation ? `\n       fix: ${x.remediation}` : ''}`);
  return { ok: bad === 0, text: [...lines, '', bad === 0 ? 'The integration looks sound.' : `${bad} check${bad === 1 ? '' : 's'} failed.`].join('\n') };
}
