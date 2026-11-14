import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { CORE_REGISTRY, lintText, runDefTests, testText, type Finding } from '@atlasauth/pca-actions';
import { cmdActionExplain, cmdBuild, cmdInit, cmdSign, cmdSync, cmdTest, loadProject } from './actions';

// Failure paths of the library calls that a loaded project cannot reach by itself (its inputs were validated at load):
// the library functions are wrapped so a test can make one of them fail once.
const hooks = vi.hoisted(() => ({
  rules: null as Error | null,
  explain: null as Error | null,
  build: null as Error | null,
  floor: null as string | null,
  lint: null as unknown[] | null,
  loadFirst: null as string | null,
  loads: 0,
}));
vi.mock('@atlasauth/pca-actions', async (orig) => {
  const actual = await orig<typeof import('@atlasauth/pca-actions')>();
  return {
    ...actual,
    runRuleExamples: (...a: Parameters<typeof actual.runRuleExamples>) => { if (hooks.rules) throw hooks.rules; return actual.runRuleExamples(...a); },
    explainBusinessRules: (...a: Parameters<typeof actual.explainBusinessRules>) => { if (hooks.explain) throw hooks.explain; return actual.explainBusinessRules(...a); },
    buildArtifacts: (...a: Parameters<typeof actual.buildArtifacts>) => { if (hooks.build) throw hooks.build; return actual.buildArtifacts(...a); },
    schemaFloorError: (...a: Parameters<typeof actual.schemaFloorError>) => (hooks.floor !== null ? hooks.floor : actual.schemaFloorError(...a)),
    loadActionsText: (...a: Parameters<typeof actual.loadActionsText>) => {
      hooks.loads += 1;
      if (hooks.loadFirst !== null && hooks.loads === 1) return { defs: [], notes: [], errors: [{ message: hooks.loadFirst }], locs: {}, rules: {} };
      return actual.loadActionsText(...a);
    },
    lintDefs: (...a: Parameters<typeof actual.lintDefs>) => (hooks.lint !== null ? hooks.lint : actual.lintDefs(...a)),
  };
});
afterEach(() => { hooks.rules = null; hooks.explain = null; hooks.build = null; hooks.floor = null; hooks.lint = null; hooks.loadFirst = null; hooks.loads = 0; });

const tmp = (): string => mkdtempSync(join(tmpdir(), 'pcacli-seam-'));
const NOTE = '\n1 of 1 action is not confirmed by a pinned reviewer: it is treated as the most dangerous kind of action (every high-risk trait, step-up) until confirmed (pca actions confirm)';
const RULES = '    rules:\n      required: [note]\n';

function project(withRules = false) {
  const root = tmp();
  const dir = join(root, 'actions');
  expect(cmdInit({ dir, ns: 'acme' }).ok).toBe(true);
  if (withRules) { const f = join(dir, 'acme.yaml'); writeFileSync(f, readFileSync(f, 'utf8').replace(/\n    examples:\n/, `\n${RULES}    examples:\n`)); }
  return { dir, out: join(root, '.pca') };
}

describe('a rules block that fails when it is run or explained', () => {
  it('cmdTest prints a FAIL line for the action, fails the run and still prints the rest', () => {
    const { dir } = project(true);
    hooks.rules = new Error('boom');
    const r = cmdTest([dir]);
    expect(r.ok).toBe(false);
    expect(r.text).toBe(`${testText(runDefTests(loadProject([dir]).defs, CORE_REGISTRY))}\nFAIL  acme.invoice.send rules: boom${NOTE}`);
  });
  it('cmdActionExplain refuses with the action and the reason', () => {
    const { dir } = project(true);
    hooks.explain = new Error('bad block');
    expect(cmdActionExplain([dir], 'acme.invoice.send')).toEqual({ ok: false, text: 'business rules of acme.invoice.send: bad block' });
  });
});

describe('cmdBuild when the builder refuses', () => {
  it('reports the reason and writes nothing', () => {
    const { dir, out } = project();
    hooks.build = new Error('cannot build this');
    expect(cmdBuild([dir], { out })).toEqual({ ok: false, text: 'cannot build this' });
    expect(existsSync(out)).toBe(false);
  });
});

describe('cmdSign when the schema or the pack lint refuses', () => {
  const built = () => {
    const p = project();
    expect(cmdBuild([p.dir], { out: p.out }).ok).toBe(true);
    return p;
  };
  const key = (): string => b64u(generateKeyPair().secretKey);

  it('a schema whose floors are inconsistent is not signed, and the reason is named', () => {
    const { dir, out } = built();
    hooks.floor = 'acme.invoice.send: floors below the traits';
    expect(cmdSign([dir], { out, kid: 'k', key: key() })).toEqual({ ok: false, text: 'not signing: acme.invoice.send: floors below the traits' });
    expect(existsSync(join(out, 'pca-actions.json'))).toBe(false);
  });
  it('a lint error in the pack is listed and stops the signature', () => {
    const { dir, out } = built();
    const f: Finding[] = [{ rule: 'LD-001', severity: 'error', verb: 'acme.invoice.send', message: 'a problem' }];
    hooks.lint = f;
    expect(cmdSign([dir], { out, kid: 'k', key: key() })).toEqual({ ok: false, text: `${lintText(f)}\nnot signing: fix the errors above` });
    expect(existsSync(join(out, 'pack.signed.json'))).toBe(false);
  });
  it('a lint warning alone does not stop a draft pack', () => {
    const { dir, out } = built();
    hooks.lint = [{ rule: 'LW-001', severity: 'warning', verb: 'acme.invoice.send', message: 'a nit' }];
    expect(cmdSign([dir], { out, kid: 'k', key: key() }).ok).toBe(true);
  });
});

describe('cmdSync when the imported actions do not load back', () => {
  it('the source is named with the first load error', async () => {
    const root = tmp();
    const dir = join(root, 'actions');
    expect(cmdInit({ dir, ns: 'shop' }).ok).toBe(true);
    writeFileSync(join(root, 'api.json'), JSON.stringify({ openapi: '3.0.0', paths: { '/orders/{id}': { parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', maxLength: 40 } }], get: { operationId: 'getOrder', summary: 'Get an order' } } } }));
    const cfg = JSON.parse(readFileSync(join(dir, 'pca.config.json'), 'utf8'));
    writeFileSync(join(dir, 'pca.config.json'), JSON.stringify({ ...cfg, sources: [{ name: 'api', from: 'openapi', file: '../api.json' }] }));
    hooks.loadFirst = 'imported problem';
    expect(await cmdSync([dir])).toEqual({ ok: false, text: 'api: imported problem' });
    expect(existsSync(join(dir, 'api.sync.yaml'))).toBe(false);
  });
});
