/**
 * Differential tests: the translators against the real engines.
 *
 * `differential/fixtures/*.jsonl` hold generated policy sets and requests together with the decision the
 * REAL engine returned (Cedar: the `cedar-policy` crate; Rego: the `opa` binary). They are produced by
 * `differential/run.sh`, which also pins the engine versions (`fixtures/ENGINES.json`). These tests replay
 * every request through the bridge and require, for every request:
 *
 *   1. SOUND: the bridge never allows what the engine denies (a translation may refuse more, never less);
 *   2. EXACT: when the translation reported nothing skipped and no errors, the bridge equals the engine.
 *
 * Constructs the bridge does not model must show up in the report; they are never approximated.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { cedarToPca, decide, openfgaToPca, regoToPca } from './index';

const dir = join(__dirname, '..', 'differential', 'fixtures');
const load = (f: string): any[] =>
  readFileSync(join(dir, f), 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l));

type Tally = { total: number; exact: number; refusedMore: number; allows: number; denies: number };

/** Cases whose bridge/engine difference is a known, documented limit (id -> request index -> why). */
const KNOWN: Record<string, string> = {};

function check(bridgeAllow: boolean, engine: string, comparable: boolean, label: string, t: Tally, problems: string[]) {
  t.total++;
  if (engine !== 'Allow' && engine !== 'Deny') return void problems.push(`${label}: engine did not decide (${engine})`);
  if (engine === 'Allow') t.allows++;
  else t.denies++;
  if (bridgeAllow && engine !== 'Allow') problems.push(`UNSOUND ${label}: bridge allowed what the engine denied`);
  else if (comparable) {
    t.exact++;
    if ((bridgeAllow ? 'Allow' : 'Deny') !== engine) problems.push(`INEXACT ${label}: bridge ${bridgeAllow ? 'allowed' : 'denied'}, engine ${engine}`);
  } else if (!bridgeAllow && engine === 'Allow') t.refusedMore++;
}

const show = (problems: string[]) => `${problems.length} divergences; first:\n${problems.slice(0, 3).join('\n---\n')}`;

describe('Cedar: bridge vs the cedar-policy engine', () => {
  const cases = load('cedar.jsonl');
  const t: Tally = { total: 0, exact: 0, refusedMore: 0, allows: 0, denies: 0 };
  const problems: string[] = [];
  it('replays every generated request', () => {
    for (const c of cases) {
      const r = cedarToPca(c.policies);
      const comparable = r.report.errors.length === 0 && r.report.skipped.length === 0;
      const attrs = new Map<string, Record<string, unknown>>();
      const parents: Record<string, string[]> = {};
      for (const e of c.entities) {
        const key = `${e.uid.type}::${e.uid.id}`;
        attrs.set(key, e.attrs);
        parents[key] = e.parents.map((p: any) => `${p.type}::${p.id}`);
      }
      const uid = (s: string) => s.replace(/"/g, '');
      c.requests.forEach((q: any, i: number) => {
        const p = uid(q.principal), rs = uid(q.resource);
        const label = `${c.id}#${i}`;
        if (KNOWN[label]) return;
        const out = decide(r, {
          subject: { id: p, ...(attrs.get(p) ?? {}) },
          action: { verb: uid(q.action).split('::')[1], resource: rs },
          env: { ...q.context, resource: attrs.get(rs) ?? {}, entity_parents: parents },
        } as never);
        check(out.allowed, c.expected[i], comparable, `${label}\n${c.policies}`, t, problems);
      });
    }
    expect(problems.length, show(problems)).toBe(0);
  });
  it('the corpus is large and mixed enough to mean something', () => {
    expect(t.total).toBeGreaterThanOrEqual(3000);
    expect(t.exact).toBeGreaterThanOrEqual(1000);
    expect(t.allows).toBeGreaterThanOrEqual(300);
    expect(t.denies).toBeGreaterThanOrEqual(300);
  });
});

describe('Rego: bridge vs the opa engine', () => {
  const cases = load('rego.jsonl');
  const t: Tally = { total: 0, exact: 0, refusedMore: 0, allows: 0, denies: 0 };
  const problems: string[] = [];
  it('replays every generated request', () => {
    for (const c of cases) {
      const r = regoToPca(c.module);
      const comparable = r.report.errors.length === 0 && r.report.skipped.length === 0;
      c.inputs.forEach((input: any, i: number) => {
        const { action, resource, ...rest } = input;
        const label = `${c.id}#${i}`;
        if (KNOWN[label]) return;
        const out = decide(r, { subject: { id: 's' }, action: { verb: action, resource }, env: rest } as never);
        check(out.allowed, c.expected[i], comparable, `${label}\n${c.module}`, t, problems);
      });
    }
    expect(problems.length, show(problems)).toBe(0);
  });
  it('the corpus is large and mixed enough to mean something', () => {
    expect(t.total).toBeGreaterThanOrEqual(3000);
    expect(t.exact).toBeGreaterThanOrEqual(1000);
    expect(t.allows).toBeGreaterThanOrEqual(300);
    expect(t.denies).toBeGreaterThanOrEqual(300);
  });
});

describe('OpenFGA: bridge vs the openfga server', () => {
  const cases = load('openfga.jsonl');
  const t: Tally = { total: 0, exact: 0, refusedMore: 0, allows: 0, denies: 0 };
  const problems: string[] = [];
  it('replays every generated check', () => {
    for (const c of cases) {
      const r = openfgaToPca(c.model, c.tuples);
      const comparable = r.report.errors.length === 0 && r.report.skipped.length === 0;
      c.checks.forEach((k: any, i: number) => {
        const label = `${c.id}#${i} ${k.user} ${k.relation} ${k.object}`;
        const out = decide(r, { subject: { id: k.user }, action: { verb: k.relation, resource: k.object } } as never);
        check(out.allowed, c.expected[i], comparable, `${label}\n${JSON.stringify(c.model.type_definitions[2].relations)}\n${JSON.stringify(c.tuples)}`, t, problems);
      });
    }
    expect(problems.length, show(problems)).toBe(0);
  });
  it('the corpus is large and mixed enough to mean something', () => {
    expect(t.total).toBeGreaterThanOrEqual(10000);
    expect(t.exact).toBeGreaterThanOrEqual(1000);
    expect(t.allows).toBeGreaterThanOrEqual(1000);
    expect(t.denies).toBeGreaterThanOrEqual(1000);
  });
});
