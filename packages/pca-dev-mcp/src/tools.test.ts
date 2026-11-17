import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { agent, generateKeyPair } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { AGENT_ONLY, EXPRESS_OPENAPI, FASTAPI, GIN, MCP_TS, fakeInitDeps, project } from './test-support/fixture';
import { initPlanner } from './plan';
import { createServer } from './server';
import { createTools } from './tools';

async function call(root: string, name: string, args: Record<string, unknown> = {}, o: { allowWrite?: boolean; docsDir?: string } = {}): Promise<any> {
  const r = await createServer({ root, planner: initPlanner(fakeInitDeps), ...o }).handle({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
  if (r!.error) throw new Error(r!.error.message);
  const res = r!.result as { isError?: boolean; structuredContent?: unknown; content: Array<{ text: string }> };
  if (res.isError) throw new Error(res.content[0]!.text);
  return res.structuredContent;
}

const names = (root: string, allowWrite?: boolean): string[] => createTools({ root, ...(allowWrite ? { allowWrite } : {}) }).map((t) => t.name);

describe('tool list', () => {
  it('is read-only by default: no tool that writes', () => {
    const root = project({});
    expect(names(root)).toEqual(['pca_detect', 'pca_plan_integration', 'pca_explain', 'pca_lint_policy', 'pca_simulate', 'pca_actions_import', 'pca_doctor', 'pca_docs_search']);
    expect(createTools({ root }).some((t) => t.writes)).toBe(false);
  });
  it('--allow-write adds exactly pca_apply_step', () => {
    expect(names(project({}), true).slice(8)).toEqual(['pca_apply_step']);
  });
});

describe('pca_detect', () => {
  it('golden: MCP server project', async () => {
    const out = await call(project(MCP_TS), 'pca_detect');
    expect(out).toMatchObject({ languages: ['typescript'], mcpServer: true, recommendation: { integration: 'proxy-mcp' } });
    expect(out.frameworks).toContain('MCP SDK');
  });
  it('a path outside the root is refused', async () => {
    await expect(call(project(MCP_TS), 'pca_detect', { path: '../..' })).rejects.toThrow(/escapes the project/);
  });
  it('a subdirectory is inspected', async () => {
    const root = project({ 'svc/requirements.txt': 'fastapi\n' });
    expect((await call(root, 'pca_detect', { path: 'svc' })).httpFrameworks).toEqual(['fastapi']);
  });
});

describe('pca_plan_integration (produced from pca init\'s own plan)', () => {
  it('golden: MCP proxy plan: one apply command, the proxy config, the human steps marked', async () => {
    const { plan } = await call(project(MCP_TS), 'pca_plan_integration');
    expect(plan.integration).toBe('proxy-mcp');
    expect(plan.mode).toBe('observe');
    expect(plan.steps[0]).toMatchObject({ id: 'apply', kind: 'command' });
    expect(plan.steps[0].command).toBe('npx @atlasauth/pca-cli init --proxy --yes');
    const cfg = plan.steps.find((s: { id: string }) => s.id === 'change:pca-proxy.yaml');
    expect(cfg).toMatchObject({ kind: 'create', appliedBy: 'apply' });
    expect(cfg.content).toContain('mode: observe');
    expect(plan.steps.some((s: { human?: boolean }) => s.human)).toBe(true);
    expect(plan.rules.join(' ')).toMatch(/Never disable/);
  });
  it('key material is a generated step with no content', async () => {
    const { plan } = await call(project(MCP_TS), 'pca_plan_integration');
    const key = plan.steps.find((s: { id: string }) => s.id === 'change:.pca/dev.key');
    expect(key).toMatchObject({ kind: 'create', appliedBy: 'apply' });
    expect(key.content).toBeUndefined();
    expect(JSON.stringify(plan)).not.toContain('c2VjcmV0LXNlZWQ');
  });
  it('golden: an API with an OpenAPI document gets the HTTP proxy plan', async () => {
    const { plan } = await call(project(EXPRESS_OPENAPI), 'pca_plan_integration');
    expect(plan.integration).toBe('proxy-http');
    expect(plan.steps[0].command).toContain('--proxy');
    expect(plan.steps.find((s: { id: string }) => s.id === 'change:pca-proxy.yaml').content).toContain('openapi');
  });
  it('the SDK guard plan wires the framework (sdk-guard)', async () => {
    const { plan } = await call(project(FASTAPI), 'pca_plan_integration');
    expect(plan.integration).toBe('sdk-guard');
    expect(plan.steps[0].command).toBe('npx @atlasauth/pca-cli init --yes');
    const root = project(GIN);
    expect((await call(root, 'pca_plan_integration')).plan.integration).toBe('sdk-guard');
  });
  it('the integration and namespace can be overridden; bad ones are refused', async () => {
    const { plan, detection } = await call(project(AGENT_ONLY), 'pca_plan_integration', { namespace: 'tools', integration: 'sdk-guard' });
    expect(detection.recommendation.integration).toBe('agent-side');
    expect(plan.integration).toBe('sdk-guard');
    expect(plan.steps.find((s: { id: string }) => s.id === 'change:pca.init.json').content).toContain('"ns": "tools"');
    await expect(call(project({}), 'pca_plan_integration', { integration: 'nope' })).rejects.toThrow(/integration must be/);
    await expect(call(project({}), 'pca_plan_integration', { namespace: 'Bad-NS' })).rejects.toThrow(/namespace/);
    await expect(call(project({}), 'pca_plan_integration', { mode: 'loud' })).rejects.toThrow(/mode must be/);
  });
  it('enforce without a signed grant is a blocker, reported in the plan', async () => {
    const { plan } = await call(project(FASTAPI), 'pca_plan_integration', { mode: 'enforce' });
    expect(plan.blockers.join(' ')).toMatch(/signed grant/);
  });
  it('a monorepo asks for a path instead of guessing', async () => {
    const root = project({ 'a/package.json': JSON.stringify({ name: 'a', dependencies: { express: '1' } }), 'b/package.json': JSON.stringify({ name: 'b', dependencies: { fastify: '1' } }) });
    await expect(call(root, 'pca_plan_integration')).rejects.toThrow(/more than one app/);
    expect((await call(root, 'pca_plan_integration', { path: 'a' })).detection.httpFrameworks).toEqual(['express']);
  });
  it('an injected planner replaces plan generation', async () => {
    const planner = async () => ({ integration: 'sdk-guard' as const, language: null, mode: 'observe' as const, steps: [], notes: ['x'], blockers: [], dirty: false, verify: [], rules: [], docs: [] });
    const t = createTools({ root: project(FASTAPI), planner }).find((x) => x.name === 'pca_plan_integration')!;
    expect(((await t.run({})) as { plan: { notes: string[] } }).plan.notes).toEqual(['x']);
  });
});

describe('pca_explain', () => {
  const mint = (aud: string) => agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud }).act('stripe.refund', 'charge:ch_1', { amount: 10, currency: 'usd' }, { counter: 1 });
  it('golden: a valid proof is explained check by check and allowed for its own audience', async () => {
    const { pcactn } = mint('ins_a');
    const out = await call(project({}), 'pca_explain', { pcactn: JSON.stringify(pcactn), audience: 'ins_a' });
    expect(out.verification).toMatchObject({ verb: 'stripe.refund', resource: 'charge:ch_1', audience: 'ins_a', verdict: 'allow', failed: [] });
    expect(out.verification.checks.map((c: { name: string }) => c.name)).toContain('leaf_signature');
    expect(out.refusal).toBeUndefined();
  });
  it('golden: the wrong audience is denied, the failing check is named and a fix is given', async () => {
    const { pcactn } = mint('ins_a');
    const out = await call(project({}), 'pca_explain', { pcactn: JSON.stringify(pcactn), audience: 'ins_b' });
    expect(out.verification).toMatchObject({ verdict: 'deny', failed: ['audience'] });
    expect(out.refusal.check).toBe('audience');
    expect(out.refusal.fix).toMatch(/same audience/);
  });
  it('explains a refusal reason, and a proxy audit line', async () => {
    const r = await call(project({}), 'pca_explain', { denial: 'replay: counter 3 is not greater than 3' });
    expect(r.refusal).toMatchObject({ check: 'replay', reason: 'replay: counter 3 is not greater than 3' });
    const line = await call(project({}), 'pca_explain', { denial: JSON.stringify({ code: 'x', reason: 'audience: the proof is for a, this server is b' }) });
    expect(line.refusal.check).toBe('audience');
  });
  it('an unknown reason still gets an answer; garbage input is an error', async () => {
    expect((await call(project({}), 'pca_explain', { denial: 'something odd' })).refusal.check).toBe('unknown');
    await expect(call(project({}), 'pca_explain', {})).rejects.toThrow(/pcactn or denial/);
    await expect(call(project({}), 'pca_explain', { pcactn: '{not json' })).rejects.toThrow();
  });
});

describe('pca_lint_policy and pca_simulate', () => {
  const spec = { permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' } };
  it('lints a spec and returns findings plus a summary', async () => {
    const out = await call(project({}), 'pca_lint_policy', { policy: spec });
    expect(Array.isArray(out.findings)).toBe(true);
    expect(out.summary).toMatchObject({ counts: expect.any(Object) });
  });
  it('a malformed policy is a finding, not a crash', async () => {
    const out = await call(project({}), 'pca_lint_policy', { policy: { nonsense: true } });
    expect(out.findings[0]).toMatchObject({ rule: 'malformed-policy', severity: 'error' });
    await expect(call(project({}), 'pca_lint_policy', {})).rejects.toThrow(/policy is required/);
  });
  it('golden: simulate replays actions and counts outcomes; an unpermitted verb is denied', async () => {
    const out = await call(project({}), 'pca_simulate', { policy: spec, actions: [{ verb: 'stripe.refund', resource: 'charge:1', params: { amount: 10 } }, { verb: 'stripe.delete_customer', resource: 'cus:1' }] });
    expect(out.results).toHaveLength(2);
    expect(out.results[1]).toMatchObject({ verb: 'stripe.delete_customer', outcome: 'deny' });
    expect(out.auto + out.stepUp + out.deny).toBe(2);
  });
  it('validates its input', async () => {
    await expect(call(project({}), 'pca_simulate', { policy: spec, actions: [{ verb: 1 }] })).rejects.toThrow(/actions must be/);
    await expect(call(project({}), 'pca_simulate', { policy: { x: 1 }, actions: [] })).rejects.toThrow(/permissions/);
  });
});

describe('pca_actions_import', () => {
  const tools = { tools: [{ name: 'search_issues', description: 'Search issues', inputSchema: { type: 'object', properties: { q: { type: 'string' } } } }, { name: 'delete_repo', description: 'Delete a repository', inputSchema: { type: 'object', properties: { name: { type: 'string' } } } }] };
  it('golden: an MCP tool list becomes unreviewed actions as YAML', async () => {
    const out = await call(project({}), 'pca_actions_import', { from: 'mcp', ns: 'github', source: tools });
    expect(out.actions).toBe(2);
    expect(out.yaml).toContain('search_issues');
    expect(out.yaml).toContain('delete_repo');
    expect(out.note).toMatch(/unreviewed/);
  });
  it('reads a file inside the project, and refuses one outside it', async () => {
    const root = project({ 'tools.json': JSON.stringify(tools) });
    expect((await call(root, 'pca_actions_import', { from: 'mcp', ns: 'github', path: 'tools.json' })).actions).toBe(2);
    await expect(call(root, 'pca_actions_import', { from: 'mcp', ns: 'github', path: '../../etc/passwd' })).rejects.toThrow(/escapes the project/);
  });
  it('refuses a bad source kind, namespace or a missing document', async () => {
    await expect(call(project({}), 'pca_actions_import', { from: 'nope', ns: 'a', source: {} })).rejects.toThrow(/unknown source/);
    await expect(call(project({}), 'pca_actions_import', { from: 'mcp', ns: 'Bad', source: tools })).rejects.toThrow(/lowercase identifier/);
    await expect(call(project({}), 'pca_actions_import', { from: 'mcp', ns: 'a' })).rejects.toThrow(/source or path/);
  });
});

describe('pca_doctor', () => {
  it('golden: the suite and caveat checks run offline and produce results with a verdict', async () => {
    const out = await call(project({}), 'pca_doctor', { only: ['suites'], config: { verifier: { allowedSuites: ['ed25519'] } } });
    expect(['pass', 'warn', 'fail']).toContain(out.verdict);
    expect(out.results.length).toBeGreaterThan(0);
    expect(out.text).toContain('pca-doctor');
  });
  it('refuses a store adapter module unless writes were allowed, and bad groups', async () => {
    await expect(call(project({}), 'pca_doctor', { config: { store: { adapter: './evil.js' } } })).rejects.toThrow(/builtin:/);
    await expect(call(project({}), 'pca_doctor', { only: ['nope'] })).rejects.toThrow(/only must list/);
  });
});

describe('pca_docs_search', () => {
  const docs = project({ 'guides/mcp-quickstart.md': '---\ntitle: x\n---\n# MCP quickstart\n\n## Observe mode\n\nRun pca-proxy with --observe to record what enforce would refuse.\n', 'reference/refusals.md': '# Refusals\n\n## audience\n\nThe proof was signed for a different server.\n', 'specs/internal.md': '# Internal\n\nobserve observe observe\n' });
  it('golden: ranks the matching section first, with file, heading and anchor', async () => {
    const out = await call(project({}), 'pca_docs_search', { query: 'observe mode', limit: 3 }, { docsDir: docs });
    expect(out.hits[0]).toMatchObject({ file: 'guides/mcp-quickstart.md', heading: 'Observe mode', anchor: 'observe-mode' });
    expect(out.hits[0].snippet).toContain('--observe');
  });
  it('does not search internal specs, and an empty query or missing docs is an error', async () => {
    const out = await call(project({}), 'pca_docs_search', { query: 'observe' }, { docsDir: docs });
    expect(out.hits.every((h: { file: string }) => !h.file.startsWith('specs'))).toBe(true);
    await expect(call(project({}), 'pca_docs_search', { query: '!!' }, { docsDir: docs })).rejects.toThrow(/at least one word/);
    await expect(call(project({}), 'pca_docs_search', { query: 'x' }, { docsDir: '/no/such/dir' })).rejects.toThrow(/not bundled/);
  });
  it('finds things in the real repository docs when run from a checkout', async () => {
    const out = await call(project({}), 'pca_docs_search', { query: 'refusal audience replay' });
    expect(out.hits.length).toBeGreaterThan(0);
  });
});

describe('pca_apply_step (--allow-write)', () => {
  it('creates a planned file once, and never over an existing one', async () => {
    const root = project(MCP_TS);
    const out = await call(root, 'pca_apply_step', { step: 'change:pca-proxy.yaml' }, { allowWrite: true });
    expect(out.wrote).toBe('pca-proxy.yaml');
    expect(readFileSync(join(root, 'pca-proxy.yaml'), 'utf8')).toContain('mode: observe');
    await expect(call(root, 'pca_apply_step', { step: 'change:pca-proxy.yaml' }, { allowWrite: true })).rejects.toThrow(/already exists|no writable/);
  });
  it('edits only a file that is exactly as the plan saw it, and never writes key material', async () => {
    const root = project({ ...MCP_TS, '.gitignore': 'node_modules\n' });
    expect((await call(root, 'pca_apply_step', { step: 'change:.gitignore' }, { allowWrite: true })).wrote).toBe('.gitignore');
    expect(readFileSync(join(root, '.gitignore'), 'utf8').startsWith('node_modules\n')).toBe(true);
    expect(readFileSync(join(root, '.gitignore'), 'utf8')).toContain('.pca/dev.key');
    await expect(call(root, 'pca_apply_step', { step: 'change:.pca/dev.key' }, { allowWrite: true })).rejects.toThrow(/no writable file step/);
    expect(existsSync(join(root, '.pca/dev.key'))).toBe(false);
  });
  it('is not callable without the flag, and refuses a command step or a step that is not in the plan', async () => {
    const root = project(MCP_TS);
    await expect(call(root, 'pca_apply_step', { step: 'change:pca-proxy.yaml' })).rejects.toThrow(/unknown tool/);
    await expect(call(root, 'pca_apply_step', { step: 'apply' }, { allowWrite: true })).rejects.toThrow(/no writable file step/);
    await expect(call(root, 'pca_apply_step', { step: 'change:../../etc/x' }, { allowWrite: true })).rejects.toThrow(/no writable file step/);
    expect(existsSync(join(root, 'pca-proxy.yaml'))).toBe(false);
  });
  it('refuses when the git tree is dirty or the plan has blockers', async () => {
    const dirty = { git: (_c: string, a: string[]) => (a[0] === 'status' ? { code: 0, out: ' M x\n' } : { code: a[0] === 'rev-parse' ? 0 : 1, out: '' }), newKey: fakeInitDeps.newKey };
    const root = project(MCP_TS);
    const t = createTools({ root, allowWrite: true, planner: initPlanner(dirty) }).find((x) => x.name === 'pca_apply_step')!;
    await expect(t.run({ step: 'change:pca-proxy.yaml' })).rejects.toThrow(/uncommitted/);
    expect(existsSync(join(root, 'pca-proxy.yaml'))).toBe(false);
  });
});
