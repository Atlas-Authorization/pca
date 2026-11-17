/**
 * The generated wiring module for JavaScript and TypeScript apps (`pca.setup.ts` / `pca.setup.js`). It exports one function (or, for Next.js
 * and NestJS, one wrapper) that the entry file calls in a single line.
 *
 * Observe mode records every request that succeeded to `.pca/observed.jsonl` in the format `pca autopilot observe` reads and never
 * blocks anything. Enforce mode runs the real adapter with `protect()` from `@atlasauth/pca` (default deny, bound to the operation the
 * route executes) against the grant in `autopilot.grant.json`, and refuses to start without it.
 */
import type { Detection } from './types';
import type { RegSpec } from './ast';

export const PCA_RANGE = '^0.5.0';
export const INIT_CONFIG = 'pca.init.json';
export const OBSERVED_LOG = '.pca/observed.jsonl';
export const GRANT_FILE = 'autopilot.grant.json';
export const KEY_FILE = '.pca/dev.key';
export const ROUTES_FILE = 'pca.routes.json';
export const SOURCE_KEY_FILE = '.pca/source.key';
export const CONNECT_FILE = '.pca/connect.json';

export interface WiringFeatures {
  /** pca.routes.json exists: resolve verbs through the imported action definitions. */
  routes: boolean;
  /** --connect was used: also report observed events to the control plane. */
  connect: boolean;
}

export interface JsWiring {
  file: string;
  content: string;
  /** Null when the registration cannot be a single edited line (Next.js wraps each route; a Nest app needs TypeScript). */
  spec: RegSpec | null;
  /** npm packages to add besides `@atlasauth/pca`. */
  packages: string[];
  /** The snippet to print when the entry file is not edited. */
  usage: string;
}

const ADAPTER: Record<string, { pkg: string; fn: string }> = {
  express: { pkg: '@atlasauth/pca-express', fn: 'pcaExpress' },
  fastify: { pkg: '@atlasauth/pca-fastify', fn: 'pcaFastify' },
  hono: { pkg: '@atlasauth/pca-hono', fn: 'pcaHono' },
  next: { pkg: '@atlasauth/pca-next', fn: 'withPCA' },
};

export const JS_FRAMEWORKS = ['express', 'fastify', 'hono', 'next', 'nest'] as const;


/** The generated code that reports observed events to the control plane (init --connect). Strings, not templates: it is emitted verbatim. */
function connectBlock(T: (s: string) => string): string {
  return [
    '',
    '// Reporting to the control plane (init --connect). The source key never leaves this machine; each batch is signed with it.',
    `const reportQueue${T(': any[]')} = [];`,
    'let reportSeq = 0;',
    `let reportTimer${T(': any')} = null;`,
    `const link${T(': any')} = (() => {`,
    '  try {',
    `    const c = JSON.parse(readFileSync(join(dir, '${CONNECT_FILE}'), 'utf8'));`,
    `    return { ...c, secret: unb64u(readFileSync(join(dir, '${SOURCE_KEY_FILE}'), 'utf8').trim()) };`,
    '  } catch {',
    '    return null;',
    '  }',
    '})();',
    `async function flush()${T(': Promise<void>')} {`,
    '  if (link === null || reportQueue.length === 0) return;',
    '  const events = reportQueue.splice(0, 200);',
    '  reportSeq = Math.max(reportSeq + 1, Date.now() * 1000);',
    '  try {',
    '    const envelope = signIngest(link.secret, { source: link.source, seq: reportSeq, sent_at: Date.now(), events });',
    "    const res = await fetch(link.url.replace(/\\/+$/, '') + '/v1/pca/control/events', {",
    "      method: 'POST',",
    "      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + link.ingestKey, 'idempotency-key': link.source + '-' + reportSeq },",
    '      body: JSON.stringify({ envelope }),',
    '    });',
    '    if (res.status >= 500 && reportQueue.length < 800) reportQueue.unshift(...events);',
    '  } catch {',
    '    if (reportQueue.length < 800) reportQueue.unshift(...events);',
    '  }',
    '}',
    '// Amount caps: only the parameters the operator named (config.includeParams) leave the process, and only safe integers and booleans.',
    '// Everything else is listed by NAME in `omitted`. The digest binds the line to the event, as the proxy does with its receipts.',
    "const NEVER_NAME = /(secret|token|passw|credential|api[_-]?key|private|ssn|e[_-]?mail|phone|card|iban|auth)/i;",
    'let obsSeq = 0;',
    `function observedOf(op${T(': any')}, body${T(': unknown')})${T(': any')} {`,
    '  const include = Array.isArray(config.includeParams) ? config.includeParams : [];',
    '  if (include.length === 0) return undefined;',
    `  const params${T(': Record<string, number | boolean>')} = {};`,
    `  const omitted${T(': string[]')} = [];`,
    "  if (body !== null && typeof body === 'object' && !Array.isArray(body)) {",
    `    for (const [k, v] of Object.entries(body${T(' as Record<string, unknown>')})) {`,
    '      if (!/^[A-Za-z0-9_.]{1,64}$/.test(k)) continue;',
    "      const ok = include.includes(k) && !NEVER_NAME.test(k) && ((typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0)) || typeof v === 'boolean');",
    `      if (ok && Object.keys(params).length < 32) params[k] = v${T(' as number | boolean')};`,
    '      else if (omitted.length < 32) omitted.push(k);',
    '    }',
    '  }',
    '  obsSeq = Math.max(obsSeq + 1, Date.now() * 1000);',
    '  return { seq: obsSeq, params, omitted, digest: observedContentDigest({ seq: obsSeq, verb: op.verb, resource: op.resource, params, omitted }) };',
    '}',
    `function report(op${T(': any')}, via${T(': string')}, body${T(': unknown')})${T(': void')} {`,
    '  if (link === null) return;',
    '  const obs = observedOf(op, body);',
    "  if (reportQueue.length < 1000) reportQueue.push({ id: randomUUID(), at: Date.now(), agent: config.ns, verb: op.verb, resource: op.resource, outcome: 'auto', r: 0.1, mode: via, ...(obs !== undefined ? { observed: obs } : {}) });",
    '  if (reportTimer === null) {',
    '    reportTimer = setInterval(() => { void flush(); }, 5000);',
    '    reportTimer.unref?.();',
    '  }',
    '}',
    '',
  ].join('\n');
}

export function jsWiring(d: Detection, f: WiringFeatures = { routes: false, connect: false }): JsWiring | null {
  const fw = d.framework;
  if (fw === null || !(JS_FRAMEWORKS as readonly string[]).includes(fw)) return null;
  if (fw === 'nest' && !d.typescript) return null;
  const ts = d.typescript;
  const esm = ts || d.esm;
  const T = (s: string): string => (ts ? s : '');
  const adapter = ADAPTER[fw];
  const imports: [string, string][] = [
    ['appendFileSync, mkdirSync, readFileSync', 'node:fs'],
    ['join', 'node:path'],
    [`${fw === 'nest' ? 'protect, requireAuthorized' : 'protect'}, verifyChain${f.connect ? ', unb64u' : ''}`, '@atlasauth/pca'],
    ...(f.routes || f.connect ? ([[[...(f.routes ? ['matchRoute', 'templateOf'] : []), ...(f.connect ? ['observedContentDigest'] : [])].join(', '), '@atlasauth/pca-proxy']] as [string, string][]) : []),
    ...(f.connect ? ([['signIngest', '@atlasauth/pca-control-plane'], ['randomUUID', 'node:crypto']] as [string, string][]) : []),
    ...(adapter ? ([[adapter.fn, adapter.pkg]] as [string, string][]) : []),
    ...(fw === 'nest' ? ([['HttpException, Injectable', '@nestjs/common']] as [string, string][]) : []),
  ];
  const head = imports.map(([names, from]) => (esm ? `import { ${names} } from '${from}';` : `const { ${names} } = require('${from}');`)).join('\n');

  const common = `
// The folder that holds pca.init.json, the grant and the .pca folder. Run the app from its own folder, or set PCA_DIR.
const dir = process.env.PCA_DIR ?? process.cwd();
const config = JSON.parse(readFileSync(join(dir, '${INIT_CONFIG}'), 'utf8'));
// observe (the default) records and never blocks; enforce verifies. PCA_MODE overrides the file.
const mode${T(': string')} = process.env.PCA_MODE ?? config.mode;

// Numbers and booleans only: a string can carry personal data, so it is neither logged nor learned.
function paramsOf(body${T(': unknown')})${T(': Record<string, number | boolean>')} {
  const out${T(': Record<string, number | boolean>')} = Object.create(null);
  if (body !== null && typeof body === 'object' && !Array.isArray(body)) {
    for (const [k, v] of Object.entries(body${T(' as Record<string, unknown>')})) {
      if (/^[A-Za-z0-9_]{1,64}$/.test(k) && ((typeof v === 'number' && Number.isFinite(v)) || typeof v === 'boolean')) out[k] = v;
    }
  }
  return out;
}

// The verb of each route comes from the action definitions init imported (pca.routes.json), matched with the proxy's own route
// matcher, so a request is named exactly as its action is. A route with no definition falls back to <ns>.<method>.
const routeEntries${T(': any[]')} = ${f.routes ? `(() => {
  try {
    return JSON.parse(readFileSync(join(dir, '${ROUTES_FILE}'), 'utf8')).map((r${T(': any')}) => ({ verb: r.verb, route: { method: r.method, template: r.template, segments: templateOf(r.template) } }))
      // the more literal a template, the earlier it is tried, as in the proxy: /accounts/me beats /accounts/{id}
      .sort((a${T(': any')}, z${T(': any')}) => z.route.segments.filter((x${T(': any')}) => 'literal' in x).length - a.route.segments.filter((x${T(': any')}) => 'literal' in x).length);
  } catch {
    return [];
  }
})()` : '[]'};
const pathOf = (url${T(': string | undefined')})${T(': string')} => new URL(url ?? '/', 'http://localhost').pathname;
function mappedVerb(method${T(': string | undefined')}, url${T(': string | undefined')})${T(': string | null')} {
  ${f.routes ? "const m = matchRoute(routeEntries, String(method ?? 'GET').toUpperCase(), pathOf(url));\n  return m ? m.entry.verb : null;" : 'return null;'}
}
// With a route map, a route that has no action definition is denied in enforce mode and logged as unmapped in observe mode.
const unmapped = (method${T(': string | undefined')}, url${T(': string | undefined')})${T(': boolean')} => routeEntries.length > 0 && mappedVerb(method, url) === null;
const UNMAPPED = 'unmapped route: no action definition for it (default deny)';

// The operation THIS request executes, from the method and the path, never from the proof.
function operation(req${T(': { method?: string; url?: string; body?: unknown }')}) {
  return { verb: mappedVerb(req.method, req.url) ?? \`\${config.ns}.\${String(req.method ?? 'GET').toLowerCase()}\`, resource: pathOf(req.url), params: paramsOf(req.body) };
}
${f.connect ? connectBlock(T) : ''}
// Observe mode. Only requests that succeeded are recorded: a failed or refused request must never widen what is learned.
function record(method${T(': string')}, url${T(': string')}, status${T(': number')}, body${T(': unknown')}, via${T(': string')} = 'observe')${T(': void')} {
  if (status >= 400) return;
  try {
    const op = operation({ method, url, body });
    if (via === 'observe') {
      mkdirSync(join(dir, '.pca'), { recursive: true });
      appendFileSync(join(dir, '${OBSERVED_LOG}'), JSON.stringify({ at: Date.now(), ...op, outcome: 'allow', ...(unmapped(method, url) ? { unmapped: true } : {}) }) + '\\n');
    }
    ${f.connect ? 'report(op, via, body);' : ''}
  } catch {
    /* observing must never break the app */
  }
}

// Enforce mode only. Fails closed at startup when the signed grant is missing.
function options() {
  let grant${T(': any')};
  try {
    grant = JSON.parse(readFileSync(join(dir, config.grantFile), 'utf8'));
  } catch {
    throw new Error(\`PCA enforce mode needs \${config.grantFile}. Create it with: pca autopilot review ... --grant-out \${config.grantFile}\`);
  }
  if (typeof config.signer === 'string') {
    // the grant must verify under the signer pinned at connect: a tampered grant, or one signed by another key, is refused
    const v = verifyChain([grant], config.signer);
    if (!v.ok) throw new Error(\`the issued grant does not verify under the pinned signer: \${v.reason ?? 'refused'}\`);
  }
  return protect({ audience: config.aud, grants: [grant], operation });
}
`;

  let body: string;
  let spec: RegSpec | null;
  let usage: string;
  let exp: string[];
  if (fw === 'express') {
    body = `
export function registerPca(app${T(': any')})${T(': void')} {
  if (mode === 'enforce') {
    app.use((req${T(': any')}, res${T(': any')}, next${T(': () => void')}) => {
      if (unmapped(req.method, req.originalUrl ?? req.url)) res.status(403).json({ error: UNMAPPED });
      else next();
    });
    ${f.connect ? `app.use((req${T(': any')}, res${T(': any')}, next${T(': () => void')}) => {
      res.on('finish', () => record(req.method, req.originalUrl ?? req.url, res.statusCode, req.body, 'enforce'));
      next();
    });
    ` : ''}app.use(pcaExpress(options().options));
    return;
  }
  app.use((req${T(': any')}, res${T(': any')}, next${T(': () => void')}) => {
    res.on('finish', () => record(req.method, req.originalUrl ?? req.url, res.statusCode, req.body));
    next();
  });
}
`;
    exp = ['registerPca'];
    spec = { callees: ['express'], statement: (v) => `registerPca(${v});`, binding: 'registerPca' };
    usage = 'registerPca(app);';
  } else if (fw === 'fastify') {
    body = `
export function registerPca(app${T(': any')})${T(': void')} {
  if (mode === 'enforce') {
    app.addHook('preHandler', async (req${T(': any')}, reply${T(': any')}) => {
      if (unmapped(req.method, req.url)) return reply.code(403).send({ error: UNMAPPED });
    });
    ${f.connect ? `app.addHook('onResponse', async (req${T(': any')}, reply${T(': any')}) => record(req.method, req.url, reply.statusCode, req.body, 'enforce'));
    ` : ''}app.addHook('preHandler', pcaFastify(options().options));
    return;
  }
  app.addHook('onResponse', async (req${T(': any')}, reply${T(': any')}) => record(req.method, req.url, reply.statusCode, req.body));
}
`;
    exp = ['registerPca'];
    spec = { callees: ['fastify', 'Fastify'], statement: (v) => `registerPca(${v});`, binding: 'registerPca' };
    usage = 'registerPca(app);';
  } else if (fw === 'hono') {
    body = `
export function registerPca(app${T(': any')})${T(': void')} {
  if (mode === 'enforce') {
    app.use('*', async (c${T(': any')}, next${T(': () => Promise<void>')}) => {
      if (unmapped(c.req.method, c.req.url)) return c.json({ error: UNMAPPED }, 403);
      await next();
    });
    ${f.connect ? `app.use('*', async (c${T(': any')}, next${T(': () => Promise<void>')}) => {
      await next();
      record(c.req.method, c.req.url, c.res.status, undefined, 'enforce');
    });
    ` : ''}app.use('*', pcaHono(options().options));
    return;
  }
  app.use('*', async (c${T(': any')}, next${T(': () => Promise<void>')}) => {
    await next();
    record(c.req.method, c.req.url, c.res.status, undefined);
  });
}
`;
    exp = ['registerPca'];
    spec = { callees: ['Hono'], statement: (v) => `registerPca(${v});`, binding: 'registerPca' };
    usage = 'registerPca(app);';
  } else if (fw === 'next') {
    body = `
// Wrap each Route Handler: export const POST = withPca(async (req) => Response.json({ ok: true }));
export function withPca(handler${T(': (req: Request, ctx: any) => Response | Promise<Response>')})${T(': (req: Request, ctx?: any) => Promise<Response>')} {
  let guarded${T(': any')};
  return async (req${T(': Request')}, ctx${T('?: any')}) => {
    if (mode === 'enforce') {
      if (unmapped(req.method, req.url)) return Response.json({ error: UNMAPPED }, { status: 403 });
      guarded ??= withPCA(options().options, handler);
      const out = await guarded(req, ctx);
      ${f.connect ? "record(req.method, req.url, out.status, undefined, 'enforce');" : ''}
      return out;
    }
    const res = await handler(req, ctx);
    record(req.method, req.url, res.status, undefined);
    return res;
  };
}
`;
    exp = ['withPca'];
    spec = null;
    usage = "export const POST = withPca(async (req) => { /* your handler */ });";
  } else {
    body = `
@Injectable()
export class PcaGuard {
  private readonly guard${T(': any')} = mode === 'enforce' ? requireAuthorized(options().options) : null;
  async canActivate(ctx${T(': any')})${T(': Promise<boolean>')} {
    const http = ctx.switchToHttp();
    const req = http.getRequest();
    const res = http.getResponse();
    const url = req.originalUrl ?? req.url;
    if (this.guard === null) {
      const raw = res.raw ?? res;
      raw.on?.('finish', () => record(req.method, url, raw.statusCode, req.body));
      return true;
    }
    if (unmapped(req.method, url)) throw new HttpException(UNMAPPED, 403);
    const r = await this.guard({ headers: req.headers, body: req.body, method: req.method, url });
    if (r.ok) {
      ${f.connect ? "const raw = res.raw ?? res;\n      raw.on?.('finish', () => record(req.method, url, raw.statusCode, req.body, 'enforce'));" : ''}
      return true;
    }
    throw new HttpException(r.verdict.reasons?.[0] ?? 'forbidden', r.status);
  }
}
`;
    exp = ['PcaGuard'];
    spec = { callees: ['NestFactory.create'], statement: (v) => `${v}.useGlobalGuards(new PcaGuard());`, binding: 'PcaGuard' };
    usage = 'app.useGlobalGuards(new PcaGuard());';
  }
  const tail = esm ? '' : `\nmodule.exports = { ${exp.join(', ')} };\n`;
  const banner = '// Generated by `pca init`. Safe to edit. See pca.init.json for the mode, the namespace and the grant file.\n';
  const content = `${banner}${head}\n${common}${body.replace(/^export /gm, esm ? 'export ' : '')}${tail}`;
  return { file: `pca.setup.${ts ? 'ts' : 'js'}`, content, spec, packages: adapter ? [adapter.pkg] : [], usage };
}
