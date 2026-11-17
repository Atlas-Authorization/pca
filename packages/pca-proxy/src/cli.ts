#!/usr/bin/env node
/**
 * pca-proxy: put PCA in front of any MCP server or HTTP API.
 *
 *   pca-proxy init mcp  [--ns NAME] [--trust-read-only-hints] [--out FILE] (-- COMMAND [ARGS...] | --upstream URL)
 *   pca-proxy mcp       [--config FILE] [--observe|--enforce] [--audit FILE] [--ns NAME] [--listen HOST:PORT] [--upstream URL | -- COMMAND [ARGS...]]
 *   pca-proxy review    --config FILE [--accept NAME,NAME | --accept-changed] [--add NAME,NAME]
 *   pca-proxy http      --config FILE [--listen HOST:PORT] [--observe|--enforce]
 *   pca-proxy approvals list|approve|deny [ID] --config FILE [--by NAME]
 *   pca-proxy audit verify FILE
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { extname } from 'node:path';
import { createDurableCibaBroker, createFileApprovalStore } from '@atlasauth/pca-ciba';
import { parseDocument, stringify } from 'yaml';
import { promptDigest, resourceDigest, templateDigest, toolDigest, type McpToolDef } from './actions';
import { readReceipts, verifyAuditFile } from './audit';
import { readLines, verifyObserved } from './observed';
import { openProxyState } from './state';
import { ConfigError, loadConfig, parseConfig, type McpConfig, type ProxyConfig } from './config';
import { Engine } from './engine';
import { HttpProxy } from './http';
import { McpHttpServer } from './mcp-http';
import { Reporter, connect, type Connection } from './connect';
import { McpProxy, handshake, loadRegs, openUpstream, runStdio, type Regs } from './mcp';

const USAGE = `pca-proxy: put Proof-Carrying Authority in front of any MCP server or HTTP API, with no SDK and no code change.

  pca-proxy init mcp [--ns NAME] [--trust-read-only-hints] [--out FILE] (--upstream URL | -- COMMAND [ARGS...])
      Connect to the server, list its tools and write a starting config. Every tool starts as policy "approve", effect "write",
      pinned to the definition it has now. You then mark the tools that only read as "allow" and delete the ones you never want.
  pca-proxy mcp [--config FILE] [--observe | --enforce] [--audit FILE] [--ns NAME] [--listen HOST:PORT] [--upstream URL | -- COMMAND [ARGS...]]
      Run as an MCP server on stdio (what Claude Desktop, Claude Code and Cursor launch), or over streamable HTTP for remote clients when the config has mcp.listen. With no --config it runs in observe mode
      and only reports what enforce mode would refuse.
  pca-proxy review --config FILE [--accept NAME,...] [--accept-changed] [--add NAME,...]
      Compare the server's tools with the reviewed pins. --accept re-pins named tools after you read the change.
  pca-proxy http --config FILE [--listen HOST:PORT] [--observe | --enforce]
      Run the HTTP reverse proxy.
  Either of those takes --connect TOKEN (the setup token from the dashboard's "Get started with agents"; later runs: --connect alone):
      the proxy makes its own source key, registers it with the token, and reports every decision (and, in observe mode, the observed
      parameters that cannot carry content; --include-params amount,... names the money-like ones to record) to your instance. Needs
      no config for MCP: it lists the server's tools and pins them. --connect-dir DIR keeps the key (default ./pca-proxy-connect).
  Either of those takes --grant FILE [--signer KEY]: enforce the human-signed grant the guided setup issued. A call the grant does not
      admit is refused; one it admits needs no further approval. --signer defaults to the one saved by --connect. With no --config
      (MCP) it implies --enforce over the server's pinned tools.
  pca-proxy approvals list|approve|deny [ID] --config FILE [--by NAME]
      Decide the calls that are waiting for a human.
  pca-proxy audit verify FILE [--params FILE]
      Check that an audit log is an intact hash chain, and with --params that the observed-parameters log is intact and bound to it.
  pca-proxy taint list|clear [NAME] --config FILE
      Show or clear the persisted taint flags. A session that saw untrusted content stays tainted across restarts until you clear it.
`;

interface Args {
  cmd: string[];
  flags: Map<string, string | true>;
  rest: string[];
}

const VALUE_FLAGS = new Set(['params', 'config', 'audit', 'ns', 'upstream', 'out', 'listen', 'accept', 'add', 'by', 'grant', 'signer', 'include-params', 'connect-dir']);
const BOOL_FLAGS = new Set(['observe', 'enforce', 'trust-read-only-hints', 'accept-changed', 'help']);

export function parseArgs(argv: readonly string[]): Args {
  const a: Args = { cmd: [], flags: new Map(), rest: [] };
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i]!;
    if (t === '--') {
      a.rest = argv.slice(i + 1);
      break;
    }
    if (t.startsWith('--')) {
      const eq = t.indexOf('=');
      const name = t.slice(2, eq < 0 ? undefined : eq);
      if (name === 'connect') {
        // the token is optional: `--connect` alone resumes the saved connection
        const v = eq >= 0 ? t.slice(eq + 1) : argv[i + 1] !== undefined && argv[i + 1]!.startsWith('pcs1.') ? argv[++i]! : true;
        a.flags.set(name, v);
      } else if (BOOL_FLAGS.has(name)) a.flags.set(name, true);
      else if (VALUE_FLAGS.has(name)) {
        const v = eq >= 0 ? t.slice(eq + 1) : argv[++i];
        if (v === undefined || v === '') throw new ConfigError(`--${name} needs a value`);
        a.flags.set(name, v);
      } else throw new ConfigError(`unknown option --${name}`);
    } else a.cmd.push(t);
  }
  return a;
}

const flag = (a: Args, n: string): string | undefined => {
  const v = a.flags.get(n);
  return typeof v === 'string' ? v : undefined;
};
const err = (s: string): void => void process.stderr.write(`${s}\n`);
const log = (s: string): void => void process.stderr.write(`[pca-proxy] ${s}\n`);

function upstreamOf(a: Args, cfg: ProxyConfig | undefined): NonNullable<McpConfig['upstream']> {
  const url = flag(a, 'upstream');
  if (url !== undefined) return { url };
  if (a.rest.length > 0) return { command: a.rest[0]!, args: a.rest.slice(1) };
  const u = cfg?.mcp?.upstream;
  if (u === undefined) throw new ConfigError('name the server: --upstream URL, or -- COMMAND [ARGS...], or mcp.upstream in the config');
  return u;
}

async function loadOtel(): Promise<{ tracer?: never; meter?: never }> {
  try {
    const name = '@opentelemetry/api';
    const api = (await import(name)) as { trace: { getTracer(n: string): never }; metrics: { getMeter(n: string): never } };
    return { tracer: api.trace.getTracer('pca-proxy'), meter: api.metrics.getMeter('pca-proxy') };
  } catch {
    log('otel is on but @opentelemetry/api is not installed; no telemetry will be sent');
    return {};
  }
}

function applyFlags(cfg: ProxyConfig, a: Args): void {
  if (a.flags.has('observe')) cfg.mode = 'observe';
  if (a.flags.has('enforce')) cfg.mode = 'enforce';
  const audit = flag(a, 'audit');
  if (audit !== undefined) cfg.audit.path = audit;
}

/** `--connect` and `--grant`: register or resume the connection, switch on parameter recording while watching, and pin the grant's signer. */
async function connectFlags(a: Args, cfg: ProxyConfig): Promise<{ reporter?: Reporter; conn?: Connection }> {
  const c = a.flags.get('connect');
  let out: { reporter?: Reporter; conn?: Connection } = {};
  if (c !== undefined) {
    const conn = await connect({ ...(typeof c === 'string' ? { token: c } : {}), dir: flag(a, 'connect-dir') ?? './pca-proxy-connect', log });
    out = { conn, reporter: new Reporter(conn, { log }) };
    if (cfg.mode === 'observe') {
      cfg.audit.path ??= './pca-proxy.audit.jsonl';
      const inc = flag(a, 'include-params');
      cfg.audit.observedParams = { enabled: true, include: inc !== undefined ? inc.split(',').map((x) => x.trim()).filter(Boolean) : (cfg.audit.observedParams?.include ?? []) };
    } else if (cfg.audit.observedParams?.enabled === true) cfg.audit.observedParams = { enabled: false, include: [] }; // written only while watching
  }
  const grant = flag(a, 'grant');
  if (grant !== undefined) {
    const signer = flag(a, 'signer') ?? out.conn?.signer ?? cfg.agent.issuedGrant?.signer;
    if (signer === undefined || signer === '') throw new ConfigError('--grant needs the key that signed it: --signer KEY (or --connect, which saved it)');
    cfg.agent.issuedGrant = { file: grant, signer };
  }
  return out;
}

async function cmdMcp(a: Args): Promise<number> {
  const cf = flag(a, 'config');
  let cfg: ProxyConfig;
  if (cf !== undefined) cfg = loadConfig(cf);
  else if (a.flags.has('connect') || flag(a, 'grant') !== undefined) {
    // the guided setup: no config to write. List the server's tools and pin them (each held for a human until a signed grant admits it)
    const ns = flag(a, 'ns') ?? 'mcp';
    const up0 = upstreamOf(a, undefined);
    const rules = await starterRules(up0, ns, false);
    const enforce = a.flags.has('enforce') || (flag(a, 'grant') !== undefined && !a.flags.has('observe'));
    cfg = parseConfig({ mode: enforce ? 'enforce' : 'observe', mcp: { ns, upstream: up0, ...rules }, state: enforce ? { dir: './pca-proxy-state' } : { backend: 'memory' }, audit: { path: './pca-proxy.audit.jsonl' }, approvals: { store: './pca-proxy.approvals.json' } });
  } else {
    if (a.flags.has('enforce')) throw new ConfigError('enforce mode needs a --config that says what is allowed (or --grant, the signed grant from the guided setup)');
    // no rules: everything is unmapped, so observe mode reports each call as one enforce mode would refuse (state is in memory: a trial)
    cfg = parseConfig({ mode: 'observe', mcp: { ns: flag(a, 'ns') ?? 'mcp', tools: {} }, state: { backend: 'memory' }, audit: {} });
  }
  applyFlags(cfg, a);
  const conn = await connectFlags(a, cfg);
  if (cfg.mcp === undefined) throw new ConfigError('the config has no mcp section');
  if (!cfg.state.backend || cfg.state.backend === 'memory') log('state is in memory (development): the budget, the counters and the taint do not survive a restart');
  const up = upstreamOf(a, cfg);
  const otel = cfg.otel ? await loadOtel() : {};
  const listen = flag(a, 'listen');
  if (listen !== undefined || cfg.mcp.listen !== undefined) {
    if (conn.reporter !== undefined) throw new ConfigError('--connect is for the stdio proxy and the HTTP reverse proxy; mcp.listen is not supported with it yet');
    if (cfg.mcp.listen === undefined) throw new ConfigError('--listen needs mcp.listen in the config (the named clients and their token variables)');
    if (listen !== undefined) {
      const m = /^(.*):(\d{1,5})$/.exec(listen);
      if (m === null) throw new ConfigError('--listen expects HOST:PORT');
      cfg.mcp.listen = { ...cfg.mcp.listen, host: m[1] || cfg.mcp.listen.host, port: Number(m[2]) };
    }
    const server = await McpHttpServer.create({ cfg, makeUpstream: () => openUpstream(up, cfg.limits), log });
    const http = await server.listen();
    const addr = http.address();
    log(`${cfg.mode} mode, MCP over HTTP on ${typeof addr === 'object' && addr ? `${addr.address}:${addr.port}` : String(addr)}${cfg.mcp.listen.path}`);
    await new Promise<void>((resolve) => {
      process.once('SIGINT', resolve);
      process.once('SIGTERM', resolve);
    });
    http.close();
    await server.closeAll();
    return 0;
  }
  const upstream = openUpstream(up, cfg.limits);
  const proxy = new McpProxy({
    cfg,
    upstream,
    send: (m) => void process.stdout.write(`${JSON.stringify(m)}\n`),
    log,
    makeEngine: async (c, candidates) => {
      const e = await Engine.create({ cfg: c, candidates, ...otel });
      if (conn.reporter) e.onReceipt = conn.reporter.push;
      return e;
    },
  });
  const onClose = upstream.onClose;
  upstream.onClose = (why) => {
    onClose(why);
    setTimeout(() => process.exit(1), 200);
  };
  log(`${cfg.mode} mode${Object.keys(cfg.mcp.tools).length === 0 ? ' (no rules: every tool is reported as unmapped)' : ''}`);
  await runStdio(proxy);
  await conn.reporter?.close();
  return 0;
}

async function cmdHttp(a: Args): Promise<number> {
  const cf = flag(a, 'config');
  if (cf === undefined) throw new ConfigError('http needs --config');
  const cfg = loadConfig(cf);
  applyFlags(cfg, a);
  const conn = await connectFlags(a, cfg);
  const listen = flag(a, 'listen');
  if (listen !== undefined) {
    const m = /^(.*):(\d{1,5})$/.exec(listen);
    if (m === null) throw new ConfigError('--listen expects HOST:PORT');
    cfg.http!.listen = { host: m[1] || '127.0.0.1', port: Number(m[2]) };
  }
  if (cfg.http === undefined) throw new ConfigError('the config has no http section');
  const otel = cfg.otel ? await loadOtel() : {};
  const proxy = await HttpProxy.create({ cfg, telemetry: otel });
  if (conn.reporter) proxy.engine.onReceipt = conn.reporter.push;
  const server = await proxy.listen();
  const addr = server.address();
  log(`${cfg.mode} mode, ${cfg.http.mode}, listening on ${typeof addr === 'object' && addr ? `${addr.address}:${addr.port}` : String(addr)}, upstream ${cfg.http.upstream}`);
  await new Promise<void>((resolve) => {
    process.once('SIGINT', resolve);
    process.once('SIGTERM', resolve);
  });
  server.close();
  await conn.reporter?.close();
  return 0;
}

// ---- init and review ----------------------------------------------------------------------------------------------------

async function withRegs<T>(up: NonNullable<McpConfig['upstream']>, cfg: McpConfig, fn: (r: Regs) => Promise<T>): Promise<T> {
  const limits = parseConfig({ mcp: { ns: 'x' } }).limits;
  const u = openUpstream(up, limits);
  try {
    await handshake(u, limits.upstreamTimeoutMs);
    let n = 0;
    return await fn(await loadRegs(u, cfg, limits.upstreamTimeoutMs, () => `pcap-init-${++n}`));
  } finally {
    await u.close();
  }
}

/** Every tool, resource and prompt the server lists, held for a human ("approve") and pinned to its definition now. */
async function starterRules(up: NonNullable<McpConfig['upstream']>, ns: string, trust: boolean) {
  const regs = await withRegs(up, parseConfig({ mcp: { ns } }).mcp!, async (r) => r);
  const tools: Record<string, Record<string, unknown>> = {};
  for (const t of regs.tools.tools.values()) {
    const ann = (t.annotations ?? {}) as Record<string, unknown>;
    const readOnly = trust && ann.readOnlyHint === true && ann.destructiveHint !== true;
    tools[t.name] = { policy: readOnly ? 'allow' : 'approve', effect: readOnly ? 'read' : 'write', pin: toolDigest(t) };
  }
  const resources: Record<string, Record<string, unknown>> = {};
  for (const r of regs.listed.resources.values()) resources[r.uri] = { policy: 'approve', effect: 'read', pin: resourceDigest(r) };
  for (const r of regs.listed.templates.values()) resources[r.uriTemplate] = { policy: 'approve', effect: 'read', pin: templateDigest(r) };
  const prompts: Record<string, Record<string, unknown>> = {};
  for (const p of regs.listed.prompts.values()) prompts[p.name] = { policy: 'approve', effect: 'read', pin: promptDigest(p) };
  return { tools, resources, prompts };
}

async function cmdInit(a: Args): Promise<number> {
  if (a.cmd[1] !== 'mcp') throw new ConfigError('init supports: init mcp (for an HTTP API, write the config by hand from the quickstart)');
  const ns = flag(a, 'ns') ?? 'mcp';
  const up = upstreamOf(a, undefined);
  const trust = a.flags.has('trust-read-only-hints');
  const { tools, resources, prompts } = await starterRules(up, ns, trust);
  const header = `# Written by pca-proxy init. Every tool, resource and prompt is held for a human ("approve") unless you change it.\n# Mark the tools that only read as policy: allow, effect: read. Delete the entries you never want.\n# One whose definition changes upstream is held until you run: pca-proxy review --config <this file>\n`;
  const doc = {
    mode: 'enforce',
    mcp: { upstream: up, ns, tools, ...(Object.keys(resources).length ? { resources } : {}), ...(Object.keys(prompts).length ? { prompts } : {}) },
    state: { dir: './pca-proxy-state' },
    audit: { path: './pca-proxy.audit.jsonl' },
    approvals: { store: './pca-proxy.approvals.json' },
  };
  const text = header + stringify(doc, { lineWidth: 0 });
  const out = flag(a, 'out');
  if (out !== undefined) writeFileSync(out, text, { mode: 0o600 });
  else process.stdout.write(text);
  log(`${Object.keys(tools).length} tools, ${Object.keys(resources).length} resources, ${Object.keys(prompts).length} prompts listed${trust ? " (read-only hints trusted for the tools that declare them: you are relying on the server's own claim)" : ''}`);
  return 0;
}

type Section = 'tools' | 'resources' | 'prompts';

function updateConfigText(path: string, updates: Array<{ section: Section; key: string; patch: Record<string, unknown> }>): void {
  const ext = extname(path).toLowerCase();
  const text = readFileSync(path, 'utf8');
  if (ext === '.json') {
    const doc = JSON.parse(text) as { mcp: Record<Section, Record<string, Record<string, unknown>>> };
    for (const u of updates) {
      doc.mcp[u.section] ??= {};
      doc.mcp[u.section][u.key] = { ...(doc.mcp[u.section][u.key] ?? {}), ...u.patch };
    }
    writeFileSync(path, `${JSON.stringify(doc, null, 2)}\n`);
    return;
  }
  const doc = parseDocument(text);
  for (const u of updates) for (const [k, v] of Object.entries(u.patch)) doc.setIn(['mcp', u.section, u.key, k], v);
  writeFileSync(path, String(doc));
}

async function cmdReview(a: Args): Promise<number> {
  const cf = flag(a, 'config');
  if (cf === undefined) throw new ConfigError('review needs --config');
  const cfg = loadConfig(cf);
  if (cfg.mcp === undefined) throw new ConfigError('the config has no mcp section');
  const mcp = cfg.mcp;
  const regs = await withRegs(upstreamOf(a, cfg), mcp, async (r) => r);
  const accept = new Set((flag(a, 'accept') ?? '').split(',').filter(Boolean));
  const add = new Set((flag(a, 'add') ?? '').split(',').filter(Boolean));
  const acceptAll = a.flags.has('accept-changed');
  const updates: Array<{ section: Section; key: string; patch: Record<string, unknown> }> = [];
  const kinds: Array<{ section: Section; label: string; rules: Record<string, { pin?: string }>; items: Array<[string, string]>; defaults: Record<string, unknown> }> = [
    { section: 'tools', label: 'tool', rules: mcp.tools, items: [...regs.tools.tools.values()].map((t) => [t.name, toolDigest(t)]), defaults: { policy: 'approve', effect: 'write' } },
    { section: 'resources', label: 'resource', rules: mcp.resources, items: [...[...regs.listed.resources.values()].map((r): [string, string] => [r.uri, resourceDigest(r)]), ...[...regs.listed.templates.values()].map((r): [string, string] => [r.uriTemplate, templateDigest(r)])], defaults: { policy: 'approve', effect: 'read' } },
    { section: 'prompts', label: 'prompt', rules: mcp.prompts, items: [...regs.listed.prompts.values()].map((p): [string, string] => [p.name, promptDigest(p)]), defaults: { policy: 'approve', effect: 'read' } },
  ];
  for (const k of kinds) {
    const listed = new Set<string>();
    for (const [key, digest] of k.items) {
      listed.add(key);
      const rule = Object.prototype.hasOwnProperty.call(k.rules, key) ? k.rules[key] : undefined;
      if (rule === undefined) {
        if (add.has(key)) {
          updates.push({ section: k.section, key, patch: { ...k.defaults, pin: digest } });
          console.log(`added   ${k.label} ${key} (policy approve)`);
        } else console.log(`new     ${k.label} ${key}: not mapped, so it is denied (add it with --add ${key})`);
      } else if (rule.pin === undefined || rule.pin !== digest) {
        const changed = rule.pin !== undefined;
        const take = accept.has(key) || acceptAll;
        console.log(`${changed ? 'CHANGED' : 'no pin '} ${k.label} ${key}: ${changed ? 'the definition differs from the one reviewed' : 'it has no pin'}${take ? ' (re-pinned)' : ` (held until re-pinned: --accept ${key})`}`);
        if (take) updates.push({ section: k.section, key, patch: { pin: digest } });
      } else console.log(`ok      ${k.label} ${key}`);
    }
    for (const key of Object.keys(k.rules)) if (!listed.has(key)) console.log(`gone    ${k.label} ${key}: the server no longer lists it`);
  }
  if (updates.length > 0) {
    updateConfigText(cf, updates);
    log(`updated ${cf}; restart the proxy to load it`);
  }
  return 0;
}

// ---- approvals and audit ------------------------------------------------------------------------------------------------

async function cmdApprovals(a: Args): Promise<number> {
  const cf = flag(a, 'config');
  if (cf === undefined) throw new ConfigError('approvals needs --config');
  const cfg = loadConfig(cf);
  const store = cfg.approvals.store;
  if (store === undefined) throw new ConfigError('approvals.store is not set: approvals are in memory and cannot be decided from another process');
  const broker = createDurableCibaBroker({ store: createFileApprovalStore(store) });
  const sub = a.cmd[1];
  if (sub === 'list') {
    const all = JSON.parse(readFileSync(store, 'utf8')) as Record<string, { value?: { request?: { auth_req_id: string; binding_message: string; authorization_details?: Array<{ render?: { fields?: Array<{ id: string; value: unknown }> } }> } } }>;
    let shown = 0;
    for (const [k, v] of Object.entries(all)) {
      if (!k.startsWith('a:') || v.value?.request === undefined) continue;
      const s = await broker.get(v.value.request.auth_req_id);
      if (s?.status !== 'pending') continue;
      shown++;
      console.log(`${s.auth_req_id}  ${v.value.request.binding_message}`);
      for (const f of v.value.request.authorization_details?.[0]?.render?.fields ?? []) console.log(`    ${f.id} = ${JSON.stringify(f.value)}`);
    }
    if (shown === 0) console.log('nothing is waiting');
    return 0;
  }
  if (sub !== 'approve' && sub !== 'deny') throw new ConfigError('approvals: list, approve ID or deny ID');
  const id = a.cmd[2];
  if (id === undefined) throw new ConfigError(`approvals ${sub} needs the request id (pca-proxy approvals list)`);
  const s = await broker.resolve(id, sub, flag(a, 'by') ?? process.env.USER ?? 'operator');
  console.log(`${s.auth_req_id}: ${s.status}`);
  return 0;
}

async function cmdTaint(a: Args): Promise<number> {
  const cf = flag(a, 'config');
  if (cf === undefined) throw new ConfigError('taint needs --config');
  const cfg = loadConfig(cf);
  const state = await openProxyState(cfg);
  const keys = (await state.kv.keys()).filter((k) => k.startsWith('taint:'));
  const sub = a.cmd[1];
  if (sub === 'list') {
    for (const k of keys) console.log(`${(await state.kv.get(k)) === true ? 'tainted' : 'clear  '} ${k.slice('taint:'.length)}`);
    if (keys.length === 0) console.log('nothing is tainted');
    return 0;
  }
  if (sub !== 'clear') throw new ConfigError('taint: list, or clear [NAME] (a session as session:NAME or a client as client:NAME)');
  const name = a.cmd[2];
  let n = 0;
  for (const k of keys) {
    if (name !== undefined && k !== `taint:${name}`) continue;
    if ((await state.kv.get(k)) === true) {
      await state.kv.set(k, false);
      n++;
    }
  }
  console.log(`cleared ${n}; a running proxy keeps what it has seen until it restarts. Clear only when the conversation that saw the content is over.`);
  return 0;
}

function cmdAudit(a: Args): number {
  if (a.cmd[1] !== 'verify' || a.cmd[2] === undefined) throw new ConfigError('audit verify FILE [--params FILE]');
  const r = verifyAuditFile(a.cmd[2]);
  console.log(r.ok ? `intact: ${r.count} receipts, head ${r.head}` : `BROKEN at receipt ${r.brokenAt}: ${r.reason}`);
  const pf = flag(a, 'params');
  if (!r.ok || pf === undefined) return r.ok ? 0 : 1;
  const o = verifyObserved(readReceipts(a.cmd[2]), readLines(pf));
  console.log(o.ok ? `parameters log intact and bound to the receipts: ${o.lines} lines` : `PARAMETERS LOG REFUSED: ${o.reason}`);
  return o.ok ? 0 : 1;
}

export async function main(argv: readonly string[]): Promise<number> {
  try {
    const a = parseArgs(argv);
    const c = a.cmd[0];
    if (c === undefined || a.flags.has('help') || c === 'help') {
      process.stdout.write(USAGE);
      return c === undefined ? 2 : 0;
    }
    switch (c) {
      case 'mcp':
        return await cmdMcp(a);
      case 'http':
        return await cmdHttp(a);
      case 'init':
        return await cmdInit(a);
      case 'review':
        return await cmdReview(a);
      case 'approvals':
        return await cmdApprovals(a);
      case 'audit':
        return cmdAudit(a);
      case 'taint':
        return await cmdTaint(a);
      default:
        err(`unknown command '${c}'\n`);
        process.stdout.write(USAGE);
        return 2;
    }
  } catch (e) {
    err(`pca-proxy: ${e instanceof Error ? e.message : String(e)}`);
    return e instanceof ConfigError ? 2 : 1;
  }
}

if (require.main === module) void main(process.argv.slice(2)).then((code) => process.exit(code));

