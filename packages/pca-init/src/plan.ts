/** Plan: read the project, decide every change, touch nothing. `apply.ts` writes the plan; `cli.ts` prints it first. */
import { existsSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { editEntry, findAppVars } from './ast';
import { GrantOverlay } from '@atlasauth/pca-proxy';
import { AppChoiceError, findApp, listFiles, read } from './detect';
import { gitState } from './git';
import { importActions } from './imports';
import { nativeGuide } from './native';
import { planProxy, ProxyError } from './proxy';
import type { Detection, FileChange, InitDeps, InitOptions, Plan, Snippet } from './types';
import { CONNECT_FILE, GRANT_FILE, INIT_CONFIG, KEY_FILE, OBSERVED_LOG, PCA_RANGE, ROUTES_FILE, SOURCE_KEY_FILE, jsWiring } from './wiring';

export class InitError extends Error {}

export interface InitConfig {
  version: 1;
  mode: 'observe' | 'enforce';
  via: 'sdk' | 'proxy';
  ns: string;
  aud: string;
  language: string;
  framework: string | null;
  /** The generated wiring module, relative to the project (null for the proxy and for non-JS languages). */
  wiring: string | null;
  /** Observed events are reported to the control plane (set by --connect). */
  connect?: boolean;
  /** The guardian key that signs issued grants (pinned at connect, or given with --signer): enforce verifies the grant under it. */
  signer?: string;
  /** Parameters (safe integers and booleans) whose values may be reported to the control plane, so proposals can bound amounts. */
  includeParams?: string[];
  keyFile: string;
  observedLog: string;
  grantFile: string;
}

const SIGNER_RE = /^[A-Za-z0-9_-]{43}$/;
const PARAM_RE = /^[A-Za-z0-9_.]{1,64}$/;
const NS_RE = /^[a-z][a-z0-9_]{0,31}$/;
const CONFIG_KEYS = ['version', 'mode', 'via', 'ns', 'aud', 'language', 'framework', 'wiring', 'connect', 'signer', 'includeParams', 'keyFile', 'observedLog', 'grantFile'];
export const PUB_FILE = `${KEY_FILE}.pub`;
/** What is never committed: key material, the learned log, and the proxy's state and audit log. */
export const SOURCE_PUB_FILE = `${SOURCE_KEY_FILE}.pub`;
export const IGNORED = [KEY_FILE, PUB_FILE, SOURCE_KEY_FILE, SOURCE_PUB_FILE, CONNECT_FILE, OBSERVED_LOG, `${GRANT_FILE}.goal-salt`, '.pca/proxy-state/', '.pca/proxy-audit.jsonl', '.pca/proxy-audit.jsonl.params.jsonl'];

/** Parse `pca.init.json`, or return why it is not valid. */
export function parseInitConfig(text: string): InitConfig | string {
  let o: Record<string, unknown>;
  try {
    o = JSON.parse(text) as Record<string, unknown>;
  } catch (e) {
    return `${INIT_CONFIG} is not JSON: ${(e as Error).message}`;
  }
  if (o === null || typeof o !== 'object' || Array.isArray(o)) return `${INIT_CONFIG} must be an object`;
  for (const k of Object.keys(o)) if (!CONFIG_KEYS.includes(k)) return `${INIT_CONFIG}: unknown member '${k}'`;
  if (o.version !== 1) return `${INIT_CONFIG}: version must be 1`;
  if (o.mode !== 'observe' && o.mode !== 'enforce') return `${INIT_CONFIG}: mode must be observe or enforce`;
  if (o.via !== 'sdk' && o.via !== 'proxy') return `${INIT_CONFIG}: via must be sdk or proxy`;
  if (typeof o.ns !== 'string' || !NS_RE.test(o.ns)) return `${INIT_CONFIG}: ns must be a lowercase identifier`;
  for (const k of ['aud', 'language', 'keyFile', 'observedLog', 'grantFile']) if (typeof o[k] !== 'string' || (o[k] as string).length === 0 || (o[k] as string).length > 256) return `${INIT_CONFIG}: ${k} must be a string`;
  for (const k of ['keyFile', 'observedLog', 'grantFile']) if ((o[k] as string).startsWith('/') || (o[k] as string).split(/[\\/]/).includes('..')) return `${INIT_CONFIG}: ${k} must be a path inside the project`;
  if (o.framework !== null && typeof o.framework !== 'string') return `${INIT_CONFIG}: framework must be a string or null`;
  if (o.connect !== undefined && typeof o.connect !== 'boolean') return `${INIT_CONFIG}: connect must be true or false`;
  if (o.signer !== undefined && (typeof o.signer !== 'string' || !SIGNER_RE.test(o.signer))) return `${INIT_CONFIG}: signer must be an Ed25519 public key (43 base64url characters)`;
  if (o.includeParams !== undefined && (!Array.isArray(o.includeParams) || o.includeParams.length > 32 || !o.includeParams.every((x) => typeof x === 'string' && PARAM_RE.test(x)))) return `${INIT_CONFIG}: includeParams must be a list of up to 32 parameter names`;
  if (o.wiring !== null && typeof o.wiring !== 'string') return `${INIT_CONFIG}: wiring must be a string or null`;
  return o as unknown as InitConfig;
}

export function readInitConfig(dir: string): InitConfig | null {
  const t = read(join(dir, INIT_CONFIG));
  if (t === null) return null;
  const r = parseInitConfig(t);
  if (typeof r === 'string') throw new InitError(`${r}. Fix it, or delete the file and run \`pca init\` again.`);
  return r;
}

const sortKeys = (o: Record<string, string>): Record<string, string> => Object.fromEntries(Object.entries(o).sort(([a], [b]) => a.localeCompare(b)));

/** package.json with the packages added (kept if already listed), indentation preserved. Null when it already has them all. */
export function addDependencies(text: string, names: string[]): string | null {
  const pkg = JSON.parse(text) as { dependencies?: Record<string, string> };
  const deps = { ...(pkg.dependencies ?? {}) };
  let changed = false;
  for (const n of names) {
    if (deps[n] === undefined) {
      deps[n] = PCA_RANGE;
      changed = true;
    }
  }
  if (!changed) return null;
  pkg.dependencies = sortKeys(deps);
  const indent = /^(\s+)"/m.exec(text)?.[1] ?? '  ';
  return JSON.stringify(pkg, null, indent) + (text.endsWith('\n') ? '\n' : '');
}

function gitignoreChange(before: string | null): FileChange | null {
  const have = new Set((before ?? '').split('\n').map((l) => l.trim()));
  const missing = IGNORED.filter((l) => !have.has(l));
  if (missing.length === 0) return null;
  const base = before === null || before === '' ? '' : before.endsWith('\n') ? before : `${before}\n`;
  const after = `${base}${base === '' ? '' : '\n'}# pca: keys and local observation logs are never committed\n${missing.join('\n')}\n`;
  return { path: '.gitignore', before, after, why: 'keep keys and local logs out of git' };
}

const EXTS = ['.ts', '.mts', '.js', '.mjs', '.cjs'];

/** The file that creates the app, or the candidates when it is not unique. */
function findEntry(d: Detection, spec: Parameters<typeof findAppVars>[2]): { entry: string | null; candidates: string[] } {
  const first = spec.callees[0]!.split('.')[0]!;
  const hits: string[] = [];
  for (const f of listFiles(d.dir, EXTS)) {
    const t = read(f);
    if (t === null || !t.includes(first)) continue;
    const v = findAppVars(t, f, spec);
    if (v !== null && v.length > 0) hits.push(relative(d.dir, f));
  }
  const rank = (p: string): number => {
    const i = ['server', 'app', 'index', 'main'].indexOf(p.replace(/^.*[\\/]/, '').replace(/\.\w+$/, ''));
    return (i < 0 ? 9 : i) * 100 + p.split(/[\\/]/).length;
  };
  hits.sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
  if (hits.length === 1 || (hits.length > 1 && rank(hits[0]!) < rank(hits[1]!))) return { entry: hits[0]!, candidates: hits };
  return { entry: null, candidates: hits };
}

const importSpec = (d: Detection, from: string, to: string): string => {
  let rel = relative(dirname(isAbsolute(from) ? from : join(d.dir, from)), to).split('\\').join('/').replace(/\.(ts|mts|js|mjs|cjs)$/, '');
  if (!rel.startsWith('.')) rel = `./${rel}`;
  const tsconfig = read(join(d.dir, 'tsconfig.json')) ?? '';
  const ext = d.typescript ? /"module(Resolution)?"\s*:\s*"(node16|nodenext)"/i.test(tsconfig) : d.esm;
  return ext ? `${rel}.js` : rel;
};

const runCommand = (d: Detection): string => {
  const pm = d.packageManager ?? 'npm';
  switch (d.language) {
    case 'js': {
      const scripts = ((): Record<string, string> => {
        try {
          return (JSON.parse(read(join(d.dir, 'package.json')) ?? '{}') as { scripts?: Record<string, string> }).scripts ?? {};
        } catch {
          return {};
        }
      })();
      return scripts.dev !== undefined ? `${pm} run dev` : scripts.start !== undefined ? `${pm} start` : 'node .';
    }
    case 'python': return d.framework === 'fastapi' ? 'uvicorn main:app --reload' : d.framework === 'flask' ? 'flask run' : d.framework === 'django' ? 'python manage.py runserver' : 'python .';
    case 'ruby': return d.framework === 'rails' ? 'bin/rails server' : 'ruby app.rb';
    case 'go': return 'go run .';
    case 'java': return existsSync(join(d.dir, 'pom.xml')) ? './mvnw spring-boot:run' : './gradlew bootRun';
    case 'dotnet': return 'dotnet run';
    case 'php': return d.framework === 'laravel' ? 'php artisan serve' : 'php -S localhost:8000 -t public';
    case 'rust': return 'cargo run';
    case 'swift': return 'swift run';
  }
};

const AP = 'npx @atlasauth/pca-cli autopilot';

function nextSteps(d: Detection, o: { via: 'sdk' | 'proxy'; observeLog: string; commands: string[]; mcp: boolean; nativeSdk: boolean }): string[] {
  const learn = [
    `Learn from it:           ${AP} observe ${o.observeLog}`,
    `Propose the tightest grant, then replay it against what was seen:\n       ${AP} propose autopilot.traces.json\n       ${AP} verify autopilot.proposal.json autopilot.traces.json`,
    `Review it and sign once: ${AP} review autopilot.proposal.json autopilot.report.json --reviewer-key=@${KEY_FILE} --holder "$(cat ${PUB_FILE})" --goal "${d.ns} agent" --grant-out ${GRANT_FILE} --yes`,
  ];
  if (o.via === 'proxy') {
    return [
      `Run the proxy (observe mode, nothing is refused):\n       ${o.commands.join('\n       ')}\n       ${o.mcp ? 'Then make your MCP client launch that command instead of the server.' : 'Then point your callers at the proxy address.'}`,
      ...learn,
      `Switch to enforce: pin what the proxy may call (${o.mcp ? 'npx @atlasauth/pca-proxy init mcp --out pca-proxy.yaml -- <your server command>' : 'decide each route in pca-proxy.yaml'}), set \`mode: enforce\` in pca-proxy.yaml, and run it again.`,
    ];
  }
  if (o.nativeSdk) {
    return [
      `Paste the snippet above, install the dependency, and run your app: ${runCommand(d)}. The ${d.language} guard has no observe mode: it is registered only when PCA_MODE=enforce, so nothing changes yet.`,
      `To observe first, with no code: npx @atlasauth/pca-cli init --proxy, then run what it prints.`,
      ...learn.slice(0, 3),
      `Switch to enforce: run with PCA_MODE=enforce (the guard needs ${GRANT_FILE}).`,
    ];
  }
  return [
    `Install, then run your app: ${runCommand(d)}\n       Observe mode records each successful request to ${OBSERVED_LOG} and never blocks.`,
    ...learn,
    `Switch to enforce:       npx @atlasauth/pca-cli init --mode enforce   (or start with PCA_MODE=enforce)`,
    `Check the integration at any time: npx @atlasauth/pca-cli init --check`,
  ];
}

export async function makePlan(o: InitOptions, deps: InitDeps): Promise<Plan> {
  let d: Detection;
  try {
    d = findApp(o.cwd, o.app);
  } catch (e) {
    if (e instanceof AppChoiceError) throw new InitError(e.message);
    throw e;
  }
  const existing = readInitConfig(d.dir);
  const ns = o.ns ?? existing?.ns ?? d.ns;
  if (!NS_RE.test(ns)) throw new InitError('--ns must be a lowercase identifier (a-z, 0-9, _; at most 32 characters)');
  const aud = existing?.aud ?? ns;
  const mode = o.mode ?? existing?.mode ?? 'observe';
  const via: 'sdk' | 'proxy' = o.proxy ? 'proxy' : existing?.via ?? 'sdk';
  const at = (rel: string): string | null => read(join(d.dir, rel));
  const changes: FileChange[] = [];
  const notes: string[] = [];
  const snippets: Snippet[] = [];
  const install: string[] = [];
  const blockers: string[] = [];
  const connect = o.connect !== undefined || existing?.connect === true;
  if (o.connect !== undefined && !/^[A-Za-z0-9._~-]{16,512}$/.test(o.connect)) throw new InitError('--connect: that does not look like a setup token (create one in the dashboard under Agents, Get started)');
  if (connect && via === 'proxy') throw new InitError('--connect reports from the generated wiring; for the proxy, report its audit log with `pca-control-plane report`');
  if (connect && d.language !== 'js') throw new InitError('--connect needs the JavaScript/TypeScript wiring: the native SDK middleware has no observe mode to report from yet');
  const imp = o.noImport ? { changes: [] as FileChange[], notes: [] as string[], routes: [] } : importActions(d, { aud, ns });
  const routes = existsSync(join(d.dir, ROUTES_FILE)) || imp.routes.length > 0;

  // the signer pinned at connect (or given), and the parameters allowed to leave the process
  let connected: { signer?: unknown } = {};
  try {
    connected = JSON.parse(at(CONNECT_FILE) ?? '{}') as typeof connected;
  } catch {
    /* an unreadable connect file pins nothing */
  }
  const signer = o.signer ?? existing?.signer ?? (typeof connected.signer === 'string' ? connected.signer : undefined);
  if (signer !== undefined && !SIGNER_RE.test(signer)) throw new InitError('--signer must be the Ed25519 public key of the guardian that signs grants (43 base64url characters)');
  const includeParams = o.includeParams ?? existing?.includeParams;
  if (o.includeParams !== undefined && !o.includeParams.every((x) => PARAM_RE.test(x))) throw new InitError('--include-params takes parameter names (letters, digits, _ and .)');
  const grantFile = existing?.grantFile ?? GRANT_FILE;
  if (mode === 'enforce') {
    if (via === 'proxy') blockers.push('enforce for the proxy is a decision about each tool or route: pin them (npx @atlasauth/pca-proxy init mcp ...), then set `mode: enforce` in pca-proxy.yaml');
    else {
      // an issued grant (--grant FILE) replaces the one in place; either way it must verify under the pinned signer when there is one
      const src = o.grant !== undefined ? resolve(o.cwd, o.grant) : join(d.dir, grantFile);
      const text = read(src);
      if (text === null) blockers.push(o.grant !== undefined ? `--grant ${o.grant}: cannot read the grant file` : `enforce needs a signed grant at ${grantFile}: observe first, then \`${AP} review ... --grant-out ${GRANT_FILE}\``);
      else if (o.grant !== undefined && signer === undefined) blockers.push('--grant needs the pinned signer: run `pca init --connect` first (it saves the signer), or pass --signer KEY');
      else if (signer !== undefined) {
        try {
          GrantOverlay.load(src, signer);
        } catch (e) {
          blockers.push(`the grant is refused: ${e instanceof Error ? e.message : String(e)}`);
        }
      }
      if (text !== null && o.grant !== undefined && at(grantFile) !== text) changes.push({ path: grantFile, before: at(grantFile), after: text, why: 'the issued grant, verified under the pinned signer; the wiring enforces exactly this and can only tighten' });
    }
  }

  // keys: generated at apply, never overwritten, never tracked
  const state = gitState(deps.git, d.dir);
  if (state.tracked(KEY_FILE)) blockers.push(`${KEY_FILE} is tracked by git. Refusing to write key material next to a tracked file: run \`git rm --cached ${KEY_FILE}\`, commit, and treat that key as leaked (init generates a new one).`);
  if (!existsSync(join(d.dir, KEY_FILE))) {
    changes.push({ path: KEY_FILE, before: null, after: '', generated: 'secret', mode: 0o600, why: 'a local dev key (Ed25519 seed). It is gitignored and is the reviewer key for your first grant' });
    changes.push({ path: PUB_FILE, before: null, after: '', generated: 'public', why: 'its public half' });
  }
  if (connect) {
    if (state.tracked(SOURCE_KEY_FILE)) blockers.push(`${SOURCE_KEY_FILE} is tracked by git: run \`git rm --cached ${SOURCE_KEY_FILE}\`, commit, and treat that key as leaked.`);
    if (!existsSync(join(d.dir, SOURCE_KEY_FILE))) {
      changes.push({ path: SOURCE_KEY_FILE, before: null, after: '', generated: 'secret', group: 'source', mode: 0o600, why: 'the key that signs the events this app reports; only its public half is sent to the control plane' });
      changes.push({ path: SOURCE_PUB_FILE, before: null, after: '', generated: 'public', group: 'source', why: 'its public half' });
    }
    notes.push(`Applying will register the source key with the control plane${o.connectUrl ? ` at ${o.connectUrl}` : ''} using your single-use setup token (the token is never written to disk) and write ${CONNECT_FILE} (gitignored).`);
  }
  const gi = gitignoreChange(at('.gitignore'));
  if (gi !== null) changes.push(gi);

  let wiring: string | null = null;
  let nativeSdk = false;
  let proxyCommands: string[] = [];
  let hasMcp = false;
  if (via === 'proxy') {
    try {
      const px = await planProxy(d, { ns, ...(o.server !== undefined ? { server: o.server } : {}), ...(o.upstream !== undefined ? { upstream: o.upstream } : {}), read: at });
      changes.push(...px.changes.filter((c) => c.before !== c.after));
      proxyCommands = px.commands;
      hasMcp = d.mcpServers.length > 0;
      notes.push(...px.notes);
    } catch (e) {
      if (e instanceof ProxyError) throw new InitError(e.message);
      throw e;
    }
  } else if (d.language === 'js') {
    const w = jsWiring(d, { routes, connect });
    if (w === null) {
      notes.push(d.framework === null ? 'No web framework found: wrap your tool or request handlers by hand, or put the proxy in front with `pca init --proxy`.' : `No automatic wiring for ${d.framework}${d.framework === 'nest' ? ' without TypeScript' : ''}: see the @atlasauth/pca guard (requireAuthorized), or use \`pca init --proxy\`.`);
      install.push(depsInstall(d, ['@atlasauth/pca'], changes, at));
    } else {
      let entry: string | null = null;
      let candidates: string[] = [];
      if (w.spec !== null) ({ entry, candidates } = findEntry(d, w.spec));
      const srcDir = existsSync(join(d.dir, 'src')) ? 'src' : '.';
      const dirOf = entry !== null ? dirname(entry) : srcDir;
      wiring = join(dirOf, w.file);
      const have = at(wiring);
      if (have === null) changes.push({ path: wiring, before: null, after: w.content, why: `the PCA wiring (${d.framework}); mode comes from ${INIT_CONFIG}` });
      else if (have !== w.content) notes.push(`${wiring} already exists and was kept (you may have edited it)`);
      if (w.spec !== null && entry !== null) {
        const text = at(entry)!;
        const r = editEntry(text, entry, w.spec, importSpec(d, entry, join(d.dir, wiring)), d.esm);
        if (!r.ok) snippets.push(registerSnippet(w.spec.binding, w.usage, importSpec(d, join(d.dir, dirOf, 'x'), join(d.dir, wiring)), entry, r.reason));
        else if (r.changed) changes.push({ path: entry, before: text, after: r.text, why: 'one import and one registration line' });
      } else if (w.spec !== null) {
        snippets.push(registerSnippet(w.spec.binding, w.usage, importSpec(d, join(d.dir, dirOf, 'x'), join(d.dir, wiring)), candidates.length > 0 ? candidates.join(' or ') : 'the file that creates your app', candidates.length > 1 ? `the app is created in more than one place (${candidates.join(', ')})` : 'no line creating the app was found'));
      } else {
        const routeFile = listFiles(d.dir, EXTS).map((f) => relative(d.dir, f)).find((f) => /(^|[\\/])route\.(ts|js|mjs)$/.test(f));
        snippets.push({ title: 'Wrap each route handler', where: `${routeFile ?? 'app/api/**/route.ts'} (replace the exported handler)`, code: `import { withPca } from '${importSpec(d, join(d.dir, routeFile ?? 'app/api/x/route.ts'), join(d.dir, wiring))}';\n${w.usage}` });
      }
      install.push(depsInstall(d, ['@atlasauth/pca', ...w.packages, ...(routes || connect ? ['@atlasauth/pca-proxy'] : []), ...(connect ? ['@atlasauth/pca-control-plane'] : [])], changes, at));
    }
  } else {
    nativeSdk = true;
    const g = nativeGuide(d, aud);
    if (g === null) notes.push(`No ${d.language}${d.framework ? `/${d.framework}` : ''} integration to wire automatically. Use \`pca init --proxy\` to put pca-proxy in front, or see the ${d.language} SDK README.`);
    else {
      install.push(...g.install);
      snippets.push(g.snippet);
    }
  }

  const cfg: InitConfig = { version: 1, mode, via, ns, aud, language: d.language, framework: d.framework, ...(connect ? { connect: true } : {}), ...(mode === 'enforce' && signer !== undefined ? { signer } : {}), ...(includeParams !== undefined && includeParams.length > 0 ? { includeParams } : {}), wiring: wiring === null ? null : wiring.split('\\').join('/'), keyFile: KEY_FILE, observedLog: via === 'proxy' ? '.pca/proxy-audit.jsonl' : OBSERVED_LOG, grantFile: GRANT_FILE };
  const cfgText = JSON.stringify(cfg, null, 2) + '\n';
  const cfgBefore = at(INIT_CONFIG);
  if (cfgBefore !== cfgText) changes.push({ path: INIT_CONFIG, before: cfgBefore, after: cfgText, why: `the PCA mode (${mode}), the action namespace and the file locations` });

  changes.push(...imp.changes);
  notes.push(...imp.notes);
  if (routes) notes.push(`Verbs: each request is named by the action definition of its route (${ROUTES_FILE}); a route with no definition is logged as unmapped in observe mode and denied in enforce mode.`);
  if (d.agents.length > 0) notes.push(`Agent code found (${d.agents.join(', ')}): its tool calls reach your app or MCP server, so they are covered by the guard or the proxy.`);
  if (d.framework === null && via === 'sdk' && d.mcpServers.length > 0) notes.push(`MCP servers found (${d.mcpServers.map((s) => s.name).join(', ')}): run \`pca init --proxy\` to put pca-proxy in front of them with no code.`);

  return {
    detection: d,
    proxy: via === 'proxy',
    ns,
    mode,
    changes: changes.filter((c) => c.generated !== undefined || c.before !== c.after),
    install: install.filter((x) => x !== ''),
    snippets,
    notes,
    keyPath: KEY_FILE,
    blockers,
    dirty: state.dirty,
    nextSteps: nextSteps(d, { via, observeLog: cfg.observedLog, commands: proxyCommands, mcp: hasMcp, nativeSdk }),
  };
}

function registerSnippet(binding: string, usage: string, spec: string, where: string, reason: string): Snippet {
  return { title: `Register the guard (${reason})`, where, code: binding === 'PcaGuard' ? `import { PcaGuard } from '${spec}';\n${usage}` : `import { ${binding} } from '${spec}';\n${usage}   // right after the line that creates the app` };
}

/** Queue the package.json edit and return the install command. */
function depsInstall(d: Detection, names: string[], changes: FileChange[], at: (rel: string) => string | null): string {
  const pj = at('package.json');
  if (pj !== null) {
    const after = addDependencies(pj, names);
    if (after !== null) changes.push({ path: 'package.json', before: pj, after, why: `add ${names.join(', ')}` });
    else return '';
  }
  const pm = d.packageManager ?? 'npm';
  return pm === 'yarn' ? 'yarn install' : `${pm} install`;
}
