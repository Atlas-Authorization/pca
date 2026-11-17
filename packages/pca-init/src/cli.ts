/** `pca init`: the argument surface. The pca CLI hands argv here; the working directory and git come in through `io`. */
import { applyPlan, renderNext, renderPlan } from './apply';
import { checkInit } from './check';
import { connectSource } from './connect';
import { realDeps } from './git';
import { InitError, makePlan } from './plan';
import type { InitDeps, InitOptions, InitResult } from './types';

export const INIT_USAGE = `pca init: add Proof-Carrying Authority to this app

  pca init [--app DIR] [--ns NAME] [--no-import]
      Detect the language and framework, and print the plan as a diff. Writes nothing.
  pca init --yes [--force]
      Apply it: the PCA package, a wiring file plus one registration line (JavaScript and TypeScript) or the exact snippet to paste
      (other languages), a gitignored dev key, pca.init.json in observe mode, and draft actions from your OpenAPI file, MCP tool list
      or routes. Refuses on a dirty git tree without --force, and never writes a key into a tracked path.
  pca init --proxy [--server NAME] [--upstream URL] [--yes]
      No code: write a pca-proxy config in front of your MCP servers (or your HTTP service) and print the one command that runs it.
  pca init --yes --connect TOKEN [--connect-url URL]
      Also register a locally generated source key with the control plane using a single-use setup token, and report observed events
      to it (JavaScript and TypeScript wiring).
  pca init --enforce --grant FILE [--signer KEY]
      Switch the wiring to enforce with a grant a human signed. The grant must verify under the signer saved at connect (or --signer);
      a tampered grant or the wrong signer is refused. It can only tighten what the wiring allows.
  pca init --observe
      Switch back to observe (the grant stays in place).
  pca init --include-params a,b
      With --connect, let these parameters (safe integers and booleans) be reported so proposals can carry amount caps.
  pca init --mode enforce|observe
      Switch mode. enforce needs the signed grant (autopilot.grant.json).
  pca init --check [--url URL]
      Verify an existing integration: package, registration, config, key safety, mode. With --url the doctor also checks the live app.

Without --yes it is always a dry run, so in CI it never changes anything unless you pass --yes. In a monorepo with several apps, name one with --app.
`;

const BOOL = new Set(['yes', 'y', 'dry-run', 'force', 'proxy', 'check', 'no-import', 'help', 'h', 'enforce', 'observe']);
const VALUE = new Set(['app', 'mode', 'ns', 'server', 'upstream', 'url', 'connect', 'connect-url', 'grant', 'signer', 'include-params']);

export function parseInitArgs(argv: string[], cwd: string): InitOptions | string {
  const f = new Map<string, string | true>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const m = /^--?([a-z-]+)(?:=(.*))?$/.exec(a);
    if (m === null) return `unexpected argument '${a}'`;
    const k = m[1]!;
    if (BOOL.has(k)) {
      if (m[2] !== undefined) return `--${k} takes no value`;
      f.set(k, true);
    } else if (VALUE.has(k)) {
      const v = m[2] ?? argv[++i];
      if (v === undefined || v.startsWith('--')) return `--${k} needs a value`;
      f.set(k, v);
    } else return `unknown option '${a}'`;
  }
  if (f.has('help') || f.has('h')) return INIT_USAGE;
  let mode = f.get('mode');
  if (mode !== undefined && mode !== 'observe' && mode !== 'enforce') return '--mode must be observe or enforce';
  if (f.has('enforce') && f.has('observe')) return '--enforce and --observe cannot be combined';
  const sugar = f.has('enforce') ? 'enforce' : f.has('observe') ? 'observe' : undefined;
  if (sugar !== undefined) {
    if (mode !== undefined && mode !== sugar) return `--${sugar} contradicts --mode ${mode}`;
    mode = sugar;
  }
  if (f.has('enforce') && !f.has('grant')) return '--enforce needs --grant FILE: enforcement starts from a grant a human signed (use --mode enforce to enforce the grant already in place)';
  if (f.has('grant') && mode !== 'enforce') return '--grant goes with --enforce';
  const names = typeof f.get('include-params') === 'string' ? (f.get('include-params') as string).split(',').map((x) => x.trim()).filter(Boolean) : undefined;
  const str = (k: string): string | undefined => (typeof f.get(k) === 'string' ? (f.get(k) as string) : undefined);
  return {
    cwd,
    proxy: f.has('proxy'),
    yes: f.has('yes') || f.has('y'),
    dryRun: f.has('dry-run'),
    force: f.has('force'),
    check: f.has('check'),
    noImport: f.has('no-import'),
    ...(str('app') !== undefined ? { app: str('app')! } : {}),
    ...(mode !== undefined ? { mode: mode as 'observe' | 'enforce' } : {}),
    ...(str('ns') !== undefined ? { ns: str('ns')! } : {}),
    ...(str('server') !== undefined ? { server: str('server')! } : {}),
    ...(str('upstream') !== undefined ? { upstream: str('upstream')! } : {}),
    ...(str('url') !== undefined ? { url: str('url')! } : {}),
    ...(str('grant') !== undefined ? { grant: str('grant')! } : {}),
    ...(str('signer') !== undefined ? { signer: str('signer')! } : {}),
    ...(names !== undefined ? { includeParams: names } : {}),
    ...(str('connect') !== undefined ? { connect: str('connect')! } : {}),
    ...(str('connect-url') !== undefined ? { connectUrl: str('connect-url')! } : {}),
  };
}

export async function runInit(argv: string[], io: { cwd: string; deps?: InitDeps }): Promise<InitResult> {
  const o = parseInitArgs(argv, io.cwd);
  if (typeof o === 'string') return { ok: o === INIT_USAGE, text: o === INIT_USAGE ? o : `pca init: ${o}\n\n${INIT_USAGE}` };
  const deps = io.deps ?? realDeps;
  try {
    if (o.check) return await checkInit(o, deps);
    const plan = await makePlan(o, deps);
    const shown = renderPlan(plan);
    if (!o.yes || o.dryRun) {
      const blocked = plan.blockers.length > 0 ? `\n\nCannot be applied:\n${plan.blockers.map((b) => `  - ${b}`).join('\n')}` : '';
      const dirty = plan.dirty && plan.changes.length > 0 ? '\n\nThe git working tree has uncommitted changes: applying will need --force.' : '';
      return { ok: plan.blockers.length === 0, text: `${shown}${blocked}${dirty}\n\nDry run: nothing was written. Re-run with --yes to apply.` };
    }
    const r = applyPlan(plan, deps, { force: o.force });
    if (!r.ok) return { ok: false, text: `${shown}\n\n${r.text}` };
    let tail = '';
    if (o.connect !== undefined) {
      const c = await connectSource(plan, { token: o.connect, ...(o.connectUrl !== undefined ? { url: o.connectUrl } : {}), ns: plan.ns }, deps);
      if (!c.ok) return { ok: false, text: `${shown}\n\n${r.text}\n\n${c.text}` };
      tail = `\n\n${c.text}`;
    }
    return { ok: true, text: `${shown}\n\n${r.text}${tail}\n\n${renderNext(plan)}` };
  } catch (e) {
    if (e instanceof InitError) return { ok: false, text: `pca init: ${e.message}` };
    throw e;
  }
}
