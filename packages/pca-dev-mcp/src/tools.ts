/**
 * The tools. Every tool is read-only: it inspects, plans, explains or checks, and returns structured data. The coding agent
 * makes the edits. The one exception, `pca_apply_step`, exists only when the server was started with --allow-write, and it
 * writes a single new file or appends to .gitignore inside the project; it never runs a command.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { compilePolicy, decodePCActn, explainRefusal, unb64u, verifyPCActnCore } from '@atlasauth/pca';
import { simulate } from '@atlasauth/pca/ext/research';
import { explainVerification } from '@atlasauth/pca-explain';
import { lint, summarize } from '@atlasauth/pca-policy-ci';
import { CHECK_GROUPS, configFromEnv, formatResults, mergeConfig, runDoctor, verdictOf, type CheckGroup, type DoctorConfig } from '@atlasauth/pca-doctor';
import { CORE_REGISTRY, DEFAULT_RULES, IMPORTERS, applySuggestion, defsToYaml, rulesDigest, suggestWithRules } from '@atlasauth/pca-actions';
import { defaultDocsDir, searchDocs } from './docs';
import type { Detection, Integration, ProjectInspector } from './detect';
import { initInspector } from './init-adapter';
import { initPlanner, type Plan, type Planner } from './plan';
import type { ToolDef } from './rpc';

export interface ToolOptions {
  /** The project the tools default to (the server's working directory). */
  root: string;
  /** Project detection (default: pca init's own detector). */
  inspector?: ProjectInspector;
  /** Plan generation (default: pca init's own makePlan). */
  planner?: Planner;
  docsDir?: string;
  allowWrite?: boolean;
}

type Args = Record<string, unknown>;
const str = (a: Args, k: string): string | undefined => { const v = a[k]; if (v === undefined) return undefined; if (typeof v !== 'string') throw new Error(`${k} must be a string`); return v; };
const need = (a: Args, k: string): string => { const v = str(a, k); if (v === undefined || v === '') throw new Error(`${k} is required`); return v; };
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const asJson = (v: unknown, label: string): unknown => {
  if (typeof v !== 'string') return v;
  try { return JSON.parse(v) as unknown; } catch (e) { throw new Error(`${label}: invalid JSON: ${(e as Error).message}`); }
};
const INTEGRATIONS: readonly Integration[] = ['proxy-mcp', 'proxy-http', 'sdk-guard', 'agent-side'];

/** `p` resolved against the root, and it must stay inside it. */
function inside(root: string, p: string): string {
  const abs = isAbsolute(p) ? resolve(p) : resolve(root, p);
  const rel = relative(root, abs);
  if (rel.startsWith('..') || isAbsolute(rel)) throw new Error(`path escapes the project: ${p}`);
  return abs;
}

function parsePCActn(input: string): ReturnType<typeof decodePCActn> {
  const t = input.trim();
  if (!t) throw new Error('empty pcactn');
  if (t.startsWith('{')) return decodePCActn(t);
  return decodePCActn(new TextDecoder('utf-8', { fatal: true }).decode(unb64u(t)));
}

export function createTools(o: ToolOptions): ToolDef[] {
  const inspector = o.inspector ?? initInspector;
  const planner = o.planner ?? initPlanner();
  const docsDir = o.docsDir ?? defaultDocsDir();
  const rootOf = (a: Args): string => { const p = str(a, 'path'); return p === undefined ? o.root : inside(o.root, p); };
  const detect = async (a: Args): Promise<Detection> => inspector.detect(rootOf(a));
  const pathProp = { path: { type: 'string', description: 'Project directory, relative to the server root (default: the root).' } };

  const tools: ToolDef[] = [
    {
      name: 'pca_detect',
      description: 'Inspect the project (read-only): languages, frameworks, whether it is or contains an MCP server, OpenAPI documents, whether PCA is already present, which coding-agent harnesses are configured, and which PCA integration fits (proxy-mcp, proxy-http, sdk-guard or agent-side) with the reasons. Call this first.',
      inputSchema: { type: 'object', properties: pathProp },
      run: detect,
    },
    {
      name: 'pca_plan_integration',
      description: 'The exact file changes and commands to add PCA to this project, as structured steps. It is the plan `npx @atlasauth/pca-cli init` prints (same code), so both always agree. Read-only: you apply the steps, or run the one apply command. Steps marked human:true need the developer to decide or sign; stop and ask. Follow plan.rules. Never write key material yourself.',
      inputSchema: { type: 'object', properties: { ...pathProp, integration: { type: 'string', enum: INTEGRATIONS, description: 'Override the recommended integration (proxy-mcp, proxy-http and agent-side use the proxy; sdk-guard wires the SDK).' }, namespace: { type: 'string', description: 'Action namespace (lowercase identifier).' }, mode: { type: 'string', enum: ['observe', 'enforce'] } } },
      run: async (a): Promise<{ detection: Detection; plan: Plan }> => {
        const integration = str(a, 'integration');
        if (integration !== undefined && !(INTEGRATIONS as readonly string[]).includes(integration)) throw new Error(`integration must be one of ${INTEGRATIONS.join(', ')}`);
        const ns = str(a, 'namespace');
        if (ns !== undefined && !/^[a-z][a-z0-9_]{0,31}$/.test(ns)) throw new Error('namespace must be a lowercase identifier (a-z, 0-9, _)');
        const mode = str(a, 'mode');
        if (mode !== undefined && mode !== 'observe' && mode !== 'enforce') throw new Error('mode must be observe or enforce');
        const detection = await detect(a);
        if (detection.ambiguous) throw new Error(detection.ambiguous.replace('--app DIR', 'a `path` argument').replace(/--app /g, 'path: '));
        return { detection, plan: await planner(detection.root, detection, { ...(integration ? { integration: integration as Integration } : {}), ...(ns ? { namespace: ns } : {}), ...(mode ? { mode: mode as 'observe' | 'enforce' } : {}) }) };
      },
    },
    {
      name: 'pca_explain',
      description: 'Explain a PCActn (JSON or base64url) by running the real verifier check by check, or explain a refusal reason (for example "audience: the proof is for ins_a, this server is ins_b", or a proxy audit line) with what it means and how to fix it.',
      inputSchema: { type: 'object', properties: { pcactn: { type: 'string', description: 'A PCActn as JSON text or base64url.' }, audience: { type: 'string', description: "This verifier's audience (omit to accept any)." }, denial: { type: 'string', description: 'A refusal reason, or a JSON audit/receipt line containing "reason".' } } },
      run: async (a) => {
        const pc = str(a, 'pcactn');
        const denial = str(a, 'denial');
        if (pc === undefined && denial === undefined) throw new Error('give pcactn or denial');
        const out: Record<string, unknown> = {};
        if (denial !== undefined) {
          let reason = denial;
          try { const j = JSON.parse(denial) as unknown; if (isObj(j) && typeof j.reason === 'string') reason = j.reason; } catch { /* plain text */ }
          out.refusal = { reason, ...explainRefusal(reason) };
        }
        if (pc !== undefined) {
          const p = parsePCActn(pc);
          const grant = Array.isArray(p.cap_chain) ? p.cap_chain[0] : undefined;
          if (!grant) throw new Error('the PCActn has an empty capability chain (no root grant)');
          const aud = str(a, 'audience');
          const result = await verifyPCActnCore(p, { insecureSkipPlanRootCheck: true, grant, grantFromArtifact: true, audience: aud ?? null });
          const ex = explainVerification(p, result);
          out.verification = { verb: p.action.verb, resource: p.action.resource, audience: p.aud, verdict: ex.verdict, summary: ex.summary, failed: ex.failed, notEnforced: ex.notEnforced, checks: ex.checks.map((c) => ({ name: c.name, status: c.status, detail: c.detail, ...(c.remedy ? { fix: c.remedy } : {}) })), text: ex.toText(), note: 'Local, grant-relative view: the resource server (replay store, revocation, its own audience) decides.' };
          if (result.reason) out.refusal = { reason: result.reason, ...explainRefusal(result.reason) };
        }
        return out;
      },
    },
    {
      name: 'pca_lint_policy',
      description: 'Lint a PCA policy (a grant, an envelope, a compiled policy, a delegation chain array, or a { permissions, limits } spec) for over-broad grants, privilege escalation, redundant caveats and a missing safety floor. Findings only; a clean result is not an authorization.',
      inputSchema: { type: 'object', properties: { policy: { description: 'The policy as an object or JSON text.' } }, required: ['policy'] },
      run: (a) => {
        let p = asJson(a.policy, 'policy');
        if (p === undefined) throw new Error('policy is required');
        if (isObj(p) && isObj(p.permissions)) p = compilePolicy(p as Parameters<typeof compilePolicy>[0]);
        const findings = lint(p);
        return { findings, summary: summarize([{ label: 'policy', findings }]) };
      },
    },
    {
      name: 'pca_simulate',
      description: 'Replay actions against a { permissions, limits } policy offline: each action is auto, step_up or deny, with the budget left. Nothing is signed or sent.',
      inputSchema: { type: 'object', properties: { policy: { description: '{ permissions: { connector: [action] }, limits?: { action: "$500/day" } } as an object or JSON text.' }, actions: { type: 'array', items: { type: 'object' }, description: '[{ verb, resource, params?, at? }]' } }, required: ['policy', 'actions'] },
      run: (a) => {
        const spec = asJson(a.policy, 'policy');
        const acts = asJson(a.actions, 'actions');
        if (!isObj(spec) || !isObj(spec.permissions)) throw new Error('policy must be { permissions: { connector: [action, ...] }, limits? }');
        if (!Array.isArray(acts) || acts.some((x) => !isObj(x) || typeof x.verb !== 'string' || typeof x.resource !== 'string')) throw new Error('actions must be an array of { verb, resource, params?, at? }');
        const policy = compilePolicy(spec as Parameters<typeof compilePolicy>[0]);
        const report = simulate(policy, acts as Parameters<typeof simulate>[1]);
        return { results: report.results.map((r) => ({ verb: r.action.verb, resource: r.action.resource, outcome: r.outcome, budgetAfter: r.budgetAfter })), auto: report.auto, stepUp: report.stepUp, deny: report.deny, endBudget: report.endBudget, peakRisk: report.peakRisk, lints: lint(policy) };
      },
    },
    {
      name: 'pca_actions_import',
      description: `Draft PCA actions from an OpenAPI 3 document, an MCP tool list (the tools/list result), GraphQL, gRPC, AsyncAPI or JSON Schema. Returns YAML. Every drafted action is UNREVIEWED: it escalates to a human until one confirms it (pca actions confirm). Never mark one reviewed yourself. Sources: ${Object.keys(IMPORTERS).sort().join(', ')}.`,
      inputSchema: { type: 'object', properties: { from: { type: 'string', description: 'mcp | openapi | graphql | grpc | asyncapi | jsonschema' }, ns: { type: 'string', description: 'Namespace (lowercase identifier).' }, source: { description: 'The document inline (object or text).' }, path: { type: 'string', description: 'Or a file inside the project.' }, uri: { type: 'string' }, verb: { type: 'string' } }, required: ['from', 'ns'] },
      run: (a) => {
        const from = need(a, 'from');
        const ns = need(a, 'ns');
        const imp = IMPORTERS[from];
        if (!imp) throw new Error(`unknown source '${from}' (${Object.keys(IMPORTERS).sort().join(', ')})`);
        if (!/^[a-z][a-z0-9_]{0,31}$/.test(ns)) throw new Error('ns must be a lowercase identifier (a-z, 0-9, _)');
        let src: unknown = a.source;
        const p = str(a, 'path');
        if (src === undefined && p !== undefined) src = readFileSync(inside(o.root, p), 'utf8');
        if (src === undefined) throw new Error('give source or path');
        const text = from === 'graphql' || from === 'grpc';
        const doc = typeof src === 'string' && !(text && !src.trimStart().startsWith('{')) ? asJson(src, 'source') : src;
        const r = imp(doc as never, { ns, ...(str(a, 'uri') ? { uri: str(a, 'uri')! } : {}), ...(str(a, 'verb') ? { verb: str(a, 'verb')! } : {}) });
        const defs = r.defs.map((d) => { const sg = suggestWithRules(d, DEFAULT_RULES, CORE_REGISTRY); return applySuggestion(d, sg, { rules: { version: DEFAULT_RULES.version, digest: rulesDigest(DEFAULT_RULES), fired: sg.fired } }); });
        return { actions: defs.length, yaml: defsToYaml(ns, defs), todo: r.todo, note: 'All actions are unreviewed (treated as the most dangerous kind) until a human confirms them.' };
      },
    },
    {
      name: 'pca_doctor',
      description: 'Check a deployment\'s PCA assumptions: clock skew, replay-store atomicity, trusted-proxy config, suite / PQ-pin policy, root-caveat enforcement. Reports pass / warn / fail / skip with a fix for each. Pass the deployment settings you know; the checks that need what you did not pass are skipped, never passed. May send requests to config.url and the clock reference URL.',
      inputSchema: { type: 'object', properties: { config: { type: 'object', description: 'pca-doctor config: { url, clock, store, proxy, verifier }.' }, only: { type: 'array', items: { type: 'string', enum: [...CHECK_GROUPS] } }, strict: { type: 'boolean' } } },
      run: async (a) => {
        const cfg = a.config === undefined ? {} : (isObj(a.config) ? (a.config as DoctorConfig) : (() => { throw new Error('config must be an object'); })());
        // a store adapter is a module path the doctor imports and runs: only the builtin adapters unless writes (and so local code) were allowed
        const adapter = cfg.store?.adapter;
        if (adapter !== undefined && !adapter.startsWith('builtin:') && o.allowWrite !== true) throw new Error('store.adapter must be builtin:<name> unless the server was started with --allow-write (an adapter module runs as code)');
        const only = a.only === undefined ? CHECK_GROUPS : (Array.isArray(a.only) && a.only.every((g) => (CHECK_GROUPS as readonly string[]).includes(String(g))) ? (a.only as CheckGroup[]) : (() => { throw new Error(`only must list: ${CHECK_GROUPS.join(', ')}`); })());
        const merged = mergeConfig(configFromEnv(process.env), cfg);
        const results = await runDoctor(merged, only);
        const strict = a.strict === true;
        return { verdict: verdictOf(results, strict), results, text: formatResults(results, merged.url, strict) };
      },
    },
    {
      name: 'pca_docs_search',
      description: 'Search the PCA documentation bundled with this server (local, offline). Returns the best-matching sections with file, heading and a snippet.',
      inputSchema: { type: 'object', properties: { query: { type: 'string' }, limit: { type: 'integer', minimum: 1, maximum: 20 } }, required: ['query'] },
      run: (a) => ({ hits: searchDocs(need(a, 'query'), docsDir, typeof a.limit === 'number' ? a.limit : 5) }),
    },
  ];

  if (o.allowWrite === true) {
    tools.push({
      name: 'pca_apply_step',
      writes: true,
      description: 'Apply one file step of the integration plan (step "change:<path>"): a new file is created (never over an existing one), an edit is written only if the file is exactly as the plan saw it. Key material is never written here (use the plan\'s apply command). Refused when the plan has blockers or the git tree is dirty. Never runs a command and never signs anything.',
      inputSchema: { type: 'object', properties: { ...pathProp, step: { type: 'string', description: 'A step id from pca_plan_integration, like change:pca.init.json' }, integration: { type: 'string', enum: INTEGRATIONS } }, required: ['step'] },
      run: async (a) => {
        const stepId = need(a, 'step');
        const integration = str(a, 'integration');
        const d = await detect(a);
        if (d.ambiguous) throw new Error(d.ambiguous);
        const plan = await planner(d.root, d, integration ? { integration: integration as Integration } : {});
        if (plan.blockers.length > 0) throw new Error(`the plan has blockers: ${plan.blockers.join('; ')}`);
        if (plan.dirty) throw new Error('the git working tree has uncommitted changes: commit or stash first, so the change can be reviewed and undone');
        const step = plan.steps.find((s) => s.id === stepId);
        if (!step || !step.id.startsWith('change:') || step.path === undefined || step.content === undefined) throw new Error(`the plan has no writable file step '${stepId}'`);
        const file = inside(d.root, step.path);
        if (step.beforeDigest === undefined) {
          if (existsSync(file)) throw new Error(`${step.path} already exists; not overwriting`);
        } else if (!existsSync(file) || createHash('sha256').update(readFileSync(file, 'utf8')).digest('hex') !== step.beforeDigest) {
          throw new Error(`${step.path} is not as the plan saw it; plan again`);
        }
        mkdirSync(dirname(file), { recursive: true });
        writeFileSync(file, step.content);
        return { wrote: step.path };
      },
    });
  }
  return tools;
}
