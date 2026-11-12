import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { LINT_RULES, lintDefs, lintFails, lintRulesDigest, lintText, toSarif, loadActionsValue } from '../src';
import { FIXTURES, clean, d } from './lint-fixtures';

describe('the lint rule list', () => {
  it('has 24 stable rules: 14 errors LD-001..014 and 10 warnings LW-001..010', () => {
    expect(LINT_RULES.map((r) => r.id)).toEqual([...Array(14)].map((_, i) => `LD-${String(i + 1).padStart(3, '0')}`).concat([...Array(10)].map((_, i) => `LW-${String(i + 1).padStart(3, '0')}`)));
    expect(LINT_RULES.filter((r) => r.severity === 'error')).toHaveLength(14);
    expect(LINT_RULES.filter((r) => r.severity === 'warning')).toHaveLength(10);
  });
  it('the rule list digest is pinned (changing a rule is a versioned change)', () => {
    expect(lintRulesDigest()).toBe('MaOaAIzmycgee91gIpXwIAPK6fzmi1yXDPQ_znCJ2PQ');
    // the pin file that pca-policy-ci enforces says the same
    expect(readFileSync(join(__dirname, '..', 'lint-rules.digest'), 'utf8').trim()).toBe(lintRulesDigest());
  });
  it('every rule has a fixture file entry with positive and negative cases', () => {
    expect(Object.keys(FIXTURES).sort()).toEqual(LINT_RULES.map((r) => r.id).sort());
    for (const f of Object.values(FIXTURES)) { expect(f.bad.length).toBeGreaterThan(0); expect(f.good.length).toBeGreaterThan(0); }
  });
});

describe('lint rules: every rule has a fixture that triggers it and one that does not', () => {
  it('the clean def has no findings of any kind', () => {
    expect(lintDefs([clean()], { ns: 'acme', stability: 'stable' })).toEqual([]);
  });
  for (const rule of LINT_RULES) {
    const fx = FIXTURES[rule.id]!;
    fx.bad.forEach((c, i) => {
      it(`${rule.id} fires on bad case ${i + 1}`, () => {
        const fs = lintDefs(c.defs, c.opts);
        expect(fs.map((f) => f.rule), JSON.stringify(fs)).toContain(rule.id);
        expect(fs.find((f) => f.rule === rule.id)!.severity).toBe(rule.severity);
      });
    });
    fx.good.forEach((c, i) => {
      it(`${rule.id} stays quiet on good case ${i + 1}, and the case has no errors`, () => {
        const fs = lintDefs(c.defs, c.opts);
        expect(fs.filter((f) => f.rule === rule.id), JSON.stringify(fs)).toEqual([]);
        expect(fs.filter((f) => f.severity === 'error'), JSON.stringify(fs)).toEqual([]);
      });
    });
  }
});

describe('lint output', () => {
  it('a structurally malformed def is reported as LD-000 and linted no further', () => {
    const fs = lintDefs([d({ extra_member: 1 })]);
    expect(fs).toHaveLength(1);
    expect(fs[0]).toMatchObject({ rule: 'LD-000', severity: 'error', verb: 'acme.invoice.send' });
  });
  it('findings are sorted and stable across runs and input order', () => {
    const defs = [d({ verb: 'acme.b.go', title: 'going' }), d({ verb: 'acme.a.go', title: 'going' })];
    const a = lintDefs(defs);
    const b = lintDefs([...defs].reverse());
    expect(a).toEqual(b);
    expect(a.map((f) => f.verb)).toEqual([...a.map((f) => f.verb)].sort());
  });
  it('errors fail a run; warnings fail only under strict', () => {
    const w = lintDefs([d({ since: undefined })]);
    expect(w.every((f) => f.severity === 'warning')).toBe(true);
    expect(lintFails(w)).toBe(false);
    expect(lintFails(w, true)).toBe(true);
    expect(lintFails(lintDefs([d({ resource: { type: 'acme.invoice', id: '*', scope: 'one' } })]))).toBe(true);
  });
  it('text output: counts and one line per finding', () => {
    expect(lintText([])).toBe('0 errors, 0 warnings');
    const t = lintText(lintDefs([d({ since: undefined })]));
    expect(t).toMatch(/warning LW-010 {2}acme.invoice.send: since is missing/);
    expect(t).toMatch(/0 errors, 1 warning$/);
  });
  it('SARIF 2.1.0: every rule is described and every finding is a result with its rule id', () => {
    const fs = lintDefs([d({ since: undefined })]).map((f) => ({ ...f, file: 'actions/acme.yaml', line: 7, column: 5 }));
    const s = toSarif(fs, { version: '0.5.0' }) as any;
    expect(s.version).toBe('2.1.0');
    const ids = s.runs[0].tool.driver.rules.map((r: any) => r.id);
    for (const r of LINT_RULES) expect(ids).toContain(r.id);
    expect(ids).toContain('LD-000');
    expect(s.runs[0].results[0]).toMatchObject({ ruleId: 'LW-010', level: 'warning' });
    expect(s.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('actions/acme.yaml');
    expect(s.runs[0].results[0].locations[0].physicalLocation.region).toEqual({ startLine: 7, startColumn: 5 });
  });
  it('the loader note and the lint agree: an auto-added idempotency key is a note, not a finding', () => {
    const r = loadActionsValue({ ns: 'acme', actions: [{ verb: 'acme.invoice.send', effects: 'send', resource: 'acme.invoice:inv_*', params: { to: 'email' } }] });
    expect(r.errors).toEqual([]);
    expect(r.notes).toEqual([{ verb: 'acme.invoice.send', message: 'idempotency_key auto-added' }]);
  });
});
