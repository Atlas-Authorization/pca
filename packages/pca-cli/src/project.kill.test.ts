import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { b64u, publicKeyOf, sha256, unb64u, utf8 } from '@atlasauth/pca';
import { CORE_REGISTRY, defsToYaml, extendRegistry, loadActionsText, type TraitDef } from '@atlasauth/pca-actions';
import { ACTION_TEMPLATES, cmdConfirm, cmdLint, cmdTest, k9Findings, loadProject, parseConfig, type Config } from './actions';

const tmp = (): string => mkdtempSync(join(tmpdir(), 'pcacli-proj-'));
const put = (dir: string, name: string, text: string): string => { const f = join(dir, name); writeFileSync(f, text); return f; };
const HELLO = ACTION_TEMPLATES.minimal!('acme');
const CONFIG = { ns: 'acme', version: '0.1.0', stability: 'draft', site: 'https://acme.example.com', aud: 'acme-api' };
const cfgOf = (extra: Record<string, unknown> = {}): Config => { const c = parseConfig(JSON.stringify({ ...CONFIG, ...extra })); if (typeof c === 'string') throw new Error(c); return c; };
const RULES_A = `    rules:
      recipients: {param: to, domains: [b.com]}
      required: [note]
`;
const RULES_B = `    rules:
      recipients: {param: to, domains: [b.com, c.com]}
`;
const withRules = (rules: string): string => HELLO.replace(/\n    examples:\n/, `\n${rules}    examples:\n`);

describe('loadProject', () => {
  it('a JSON file is parsed as JSON, not as YAML', () => {
    const dir = tmp();
    const f = put(dir, 'a.json', '{ns: acme, actions: []}');
    const l = loadProject([dir]);
    expect(l.findings).toHaveLength(1);
    const e = loadActionsText('{ns: acme, actions: []}', 'json').errors[0]!;
    expect(e.message).toMatch(/^not JSON: /);
    expect(l.findings[0]).toStrictEqual({ rule: 'LD-000', severity: 'error', file: f, message: e.message, line: 1, column: 1 });
    // the same text in a YAML file is fine
    const dir2 = tmp();
    put(dir2, 'a.yaml', '{ns: acme, actions: []}');
    expect(loadProject([dir2]).findings).toEqual([]);
    // a .yml file is YAML too
    const dir3 = tmp();
    put(dir3, 'a.yml', '{ns: acme, actions: []}');
    expect(loadProject([dir3]).findings).toEqual([]);
  });
  it('a valid JSON action file loads with the ns and positions', () => {
    const dir = tmp();
    const doc = { ns: 'acme', since: '0.1.0', actions: [{ verb: 'acme.row.get', title: 'Read a row', description: 'Reads one row.', effects: ['read'], resource: 'acme.row:row_*', params: { row: 'id:acme.row' } }] };
    put(dir, 'a.json', JSON.stringify(doc, null, 2));
    const l = loadProject([dir]);
    expect(l.findings.filter((f) => f.severity === 'error')).toEqual([]);
    expect(l.defs.map((d) => d.verb)).toEqual(['acme.row.get']);
    expect(l.ns).toBe('acme');
  });
  it('a load error becomes an LD-000 finding with the verb and the position when it has them, and neither when it has not', () => {
    const dir = tmp();
    const bad = put(dir, 'a.yaml', 'ns: acme\nactions:\n  - verb: acme.bad.thing\n    title: Bad\n');
    const seq = put(dir, 'b.yaml', '- 1\n');
    const nsBad = put(dir, 'c.yaml', 'ns: Bad\n');
    const l = loadProject([dir]);
    const eBad = loadActionsText(readFileSync(bad, 'utf8')).errors[0]!;
    const eSeq = loadActionsText(readFileSync(seq, 'utf8')).errors[0]!;
    expect(eBad.verb).toBe('acme.bad.thing');
    expect(eBad.line).toBe(3);
    expect(eBad.column).toBe(5);
    expect(eSeq.line).toBeUndefined();
    expect(eSeq.verb).toBeUndefined();
    expect(l.findings).toStrictEqual([
      { rule: 'LD-000', severity: 'error', file: bad, verb: 'acme.bad.thing', message: eBad.message, line: 3, column: 5 },
      { rule: 'LD-000', severity: 'error', file: seq, message: eSeq.message },
      { rule: 'LD-000', severity: 'error', file: nsBad, message: 'ns must be a lowercase identifier', line: 1, column: 1 },
    ]);
    expect(l.defs).toEqual([]);
  });
  it('a load note becomes an LN-001 finding at the action', () => {
    const dir = tmp();
    const f = put(dir, 'a.yaml', HELLO);
    const l = loadProject([dir]);
    const r = loadActionsText(HELLO);
    expect(r.notes).toEqual([{ verb: 'acme.invoice.send', message: 'idempotency_key auto-added' }]);
    const at = r.locs['acme.invoice.send']!;
    expect(at.column).toBe(5);
    expect(l.findings).toStrictEqual([{ rule: 'LN-001', severity: 'note', file: f, verb: 'acme.invoice.send', message: 'idempotency_key auto-added', line: at.line, column: at.column }]);
    expect(l.locs.get('acme.invoice.send')).toEqual(at);
    expect(l.files.get('acme.invoice.send')).toBe(f);
  });
  it('the namespace is the files\' common one, and a file without one does not unset it', () => {
    const dir = tmp();
    put(dir, 'a.yaml', HELLO);
    put(dir, 'b.yaml', ACTION_TEMPLATES.db!('acme'));
    expect(loadProject([dir]).ns).toBe('acme');
    put(dir, 'c.yaml', '- 1\n');
    expect(loadProject([dir]).ns).toBe('acme');
    const mixed = tmp();
    put(mixed, 'a.yaml', HELLO);
    put(mixed, 'b.yaml', ACTION_TEMPLATES.db!('other'));
    expect(loadProject([mixed]).ns).toBeUndefined();
    expect(loadProject([tmp()]).ns).toBeUndefined();
  });
  it('the first file that defines a verb keeps its file, position and rules', () => {
    const dir = tmp();
    const a = put(dir, 'a.yaml', withRules(RULES_A));
    put(dir, 'b.yaml', '# padding\n# padding\n' + withRules(RULES_B));
    put(dir, 'c.yaml', '\n\n\n\n' + HELLO);
    const l = loadProject([dir]);
    expect(l.defs).toHaveLength(3);
    expect(l.files.get('acme.invoice.send')).toBe(a);
    expect(l.locs.get('acme.invoice.send')).toEqual(loadActionsText(withRules(RULES_A)).locs['acme.invoice.send']);
    expect(Object.keys(l.rules)).toEqual(['acme.invoice.send']);
    expect(l.rules['acme.invoice.send']).toEqual(loadActionsText(withRules(RULES_A)).rules['acme.invoice.send']);
  });
  it('a verb with no rules block in the first file takes the rules of the next file that has one', () => {
    const dir = tmp();
    put(dir, 'a.yaml', HELLO);
    put(dir, 'b.yaml', withRules(RULES_B));
    expect(loadProject([dir]).rules['acme.invoice.send']).toEqual(loadActionsText(withRules(RULES_B)).rules['acme.invoice.send']);
    const none = tmp();
    put(none, 'a.yaml', HELLO);
    expect(Object.keys(loadProject([none]).rules)).toEqual([]);
  });
});

describe('lint without a config and with a broken one', () => {
  it('a project with no config lints under the defaults', () => {
    const dir = tmp();
    put(dir, 'a.yaml', HELLO);
    const r = cmdLint([dir]);
    expect(r.ok).toBe(true);
    expect(r.text).toMatch(/^note {4}LN-001 {2}.+a\.yaml:5:5: acme\.invoice\.send: idempotency_key auto-added\n0 errors, 0 warnings, 1 note$/);
  });
  it('a file namespace that differs from a verb namespace is an LW-008 warning', () => {
    const dir = tmp();
    put(dir, 'a.yaml', HELLO.replace('ns: acme', 'ns: zed'));
    const r = cmdLint([dir]);
    expect(r.text).toMatch(/warning LW-008 {2}.+a\.yaml:\d+:5: acme\.invoice\.send: verb namespace 'acme' differs from the file namespace 'zed'/);
  });
  it('a rules block is linted as well as loaded', () => {
    const dir = tmp();
    put(dir, 'a.yaml', withRules('    rules:\n      rate: [{max: 10, per: hour}, {max: 5, per: day}]\n'));
    const r = cmdLint([dir]);
    expect(r.text).toMatch(/warning LR-003 {2}.+a\.yaml:\d+:5: acme\.invoice\.send: rules\.rate: the daily limit is not above the hourly one, so the hourly limit never fires/);
    expect(r.ok).toBe(true);
    expect(cmdLint([dir], { strict: true }).ok).toBe(false);
  });
  it('a parameter finding carries the position of the parameter, an action finding the position of the action', () => {
    const dir = tmp();
    put(dir, 'a.yaml', 'ns: acme\nactions:\n  - verb: acme.invoice.get\n    title: Read an invoice\n    description: Reads it.\n    effects: [read]\n    resource: acme.invoice:inv_*\n    params:\n      invoice: id:acme.invoice\n      memo: text(10)\n');
    const l = cmdLint([dir]);
    const lines = l.text.split('\n');
    expect(lines.some((x) => /:3:5: acme\.invoice\.get/.test(x))).toBe(true);
    expect(lines.filter((x) => / \[\w+\]: /.test(x)).every((x) => /:(9|10):7: acme\.invoice\.get \[/.test(x))).toBe(true);
  });
});

describe('custom traits that do not build', () => {
  const badTrait = { id: 'pca.mine', implies: [] } as unknown as TraitDef;
  const dirWithBadTraits = (extra: Record<string, unknown> = {}): string => {
    const dir = tmp();
    put(dir, 'a.yaml', HELLO);
    put(dir, 'pca.config.json', JSON.stringify({ ...CONFIG, traits: [badTrait], ...extra }));
    return dir;
  };
  it('test refuses with the registry message, and lint reports it as a finding without throwing', () => {
    let msg = '';
    try { extendRegistry(CORE_REGISTRY, [badTrait]); } catch (e) { msg = (e as Error).message; }
    expect(msg.length).toBeGreaterThan(0);
    const dir = dirWithBadTraits();
    expect(cmdTest([dir])).toEqual({ ok: false, text: `custom traits: ${msg}` });
    const l = cmdLint([dir]);
    expect(l.ok).toBe(false);
    expect(l.text).toContain(`invalid custom traits: ${msg}`);
    for (const line of l.text.split('\n').slice(0, -1)) expect(line).toMatch(/^(error|warning|note) {1,4}[A-Z]{2}-\d{3} {2}/);
  });
  it('pinned reviewers do not change that', () => {
    const pk = b64u(publicKeyOf(unb64u(b64u(sha256(utf8('cli-reviewer'))))));
    const dir = dirWithBadTraits({ reviewers: { keys: [{ kid: 'rev-1', pk, roles: ['reviewer'] }] } });
    const l = cmdLint([dir]);
    expect(l.ok).toBe(false);
    expect(l.text).toMatch(/invalid custom traits/);
  });
});

describe('the unconfirmed note', () => {
  const NOTE = ' not confirmed by a pinned reviewer';
  const TAIL = 'treated as the most dangerous kind of action (every high-risk trait, step-up) until confirmed (pca actions confirm)';
  const sk = b64u(sha256(utf8('cli-reviewer')));
  const pk = b64u(publicKeyOf(unb64u(sk)));
  const pin = (dir: string): void => { put(dir, 'pca.config.json', JSON.stringify({ ...CONFIG, reviewers: { keys: [{ kid: 'rev-1', pk, roles: ['reviewer'] }] } })); };
  const confirmed = (text: string, verbs: string[]): string => { const r = cmdConfirm(text, { verbs, kid: 'rev-1', secret: sk, yes: true, ts: 1_700_000_000 }); expect(r.ok, r.text).toBe(true); return r.yaml; };
  const ROW = 'ns: acme\nsince: 0.1.0\nactions:\n  - verb: acme.row.get\n    title: Read a row\n    description: Reads one row by its key.\n    effects: [read]\n    resource: acme.row:row_*\n    params:\n      row: id:acme.row\n';
  const noteOf = (dir: string): string => { const t = cmdTest([dir]).text; const i = t.indexOf('\n', t.lastIndexOf('passed,')); return t.slice(i + 1); };

  it('one action is singular, several are plural', () => {
    const one = tmp();
    put(one, 'pca.config.json', JSON.stringify(CONFIG));
    put(one, 'a.yaml', HELLO);
    expect(noteOf(one)).toBe(`1 of 1 action is${NOTE}: it is ${TAIL}`);
    expect(cmdTest([one]).text.endsWith(`\n1 of 1 action is${NOTE}: it is ${TAIL}`)).toBe(true);
    const three = tmp();
    put(three, 'pca.config.json', JSON.stringify(CONFIG));
    put(three, 'a.yaml', HELLO);
    put(three, 'b.yaml', ACTION_TEMPLATES.db!('acme'));
    expect(cmdTest([three]).text.endsWith(`\n3 of 3 actions are${NOTE}: they are ${TAIL}`)).toBe(true);
  });
  it('counts only the unconfirmed ones, and says nothing once all are confirmed', () => {
    const dir = tmp();
    put(dir, 'a.yaml', confirmed(HELLO, ['acme.invoice.send']));
    put(dir, 'b.yaml', ROW);
    pin(dir);
    expect(cmdTest([dir]).text.endsWith(`\n1 of 2 actions are${NOTE}: it is ${TAIL}`)).toBe(true);
    const dir3 = tmp();
    put(dir3, 'a.yaml', confirmed(HELLO, ['acme.invoice.send']));
    put(dir3, 'b.yaml', ACTION_TEMPLATES.db!('acme'));
    pin(dir3);
    expect(cmdTest([dir3]).text.endsWith(`\n2 of 3 actions are${NOTE}: they are ${TAIL}`)).toBe(true);
    const all = tmp();
    put(all, 'a.yaml', confirmed(HELLO, ['acme.invoice.send']));
    put(all, 'b.yaml', confirmed(ROW, ['acme.row.get']));
    pin(all);
    const r = cmdTest([all]);
    expect(r.text).not.toContain('pinned reviewer');
    expect(r.text.endsWith('\n')).toBe(false);
    expect(r.text).toMatch(/\d+ passed, \d+ failed$/);
  });
  it('a stable pack whose actions are confirmed by a pinned reviewer lints clean of the unreviewed warning', () => {
    const dir = tmp();
    put(dir, 'a.yaml', confirmed(HELLO, ['acme.invoice.send']));
    put(dir, 'pca.config.json', JSON.stringify({ ...CONFIG, version: '1.0.0', stability: 'stable', provenance: { oidc_issuer: 'https://issuer.example.com', identity: 'https://ci.example.com/release', builder_id: 'https://ci.example.com/builder' }, reviewers: { keys: [{ kid: 'rev-1', pk, roles: ['reviewer'] }] } }));
    const r = cmdLint([dir], { strict: true });
    expect(r.text).not.toMatch(/LW-004/);
    // LW-004 reads the def's review state: a def still `unreviewed` (as an import leaves it) in a stable pack is flagged
    const unreviewed = tmp();
    put(unreviewed, 'a.yaml', defsToYaml('acme', loadActionsText(HELLO).defs.map((d) => ({ ...d, review: { state: 'unreviewed' as const } }))));
    put(unreviewed, 'pca.config.json', JSON.stringify({ ...CONFIG, version: '1.0.0', stability: 'stable', provenance: { oidc_issuer: 'https://issuer.example.com', identity: 'https://ci.example.com/release', builder_id: 'https://ci.example.com/builder' } }));
    expect(cmdLint([unreviewed], { strict: true }).text).toMatch(/LW-004/);
  });
});

describe('k9Findings', () => {
  const defsOf = (...texts: string[]) => { const dir = tmp(); texts.forEach((t, i) => put(dir, `f${i}.yaml`, t)); return loadProject([dir]).defs; };
  const reader = (name: string, traits: string): string => `ns: acme\nsince: 0.1.0\nactions:\n  - verb: acme.${name}.read\n    title: Read ${name}\n    description: Reads ${name}.\n    effects: [read]\n${traits}    resource: acme.${name}:${name.slice(0, 2)}_*\n    params:\n      ${name}: id:acme.${name}\n`;
  const PII = '    traits: [pca.pii_access]\n';

  it('a beta or stable pack without a pinned builder identity gets LP-001, a draft or pinned one does not', () => {
    const defs = defsOf(HELLO);
    const pinned = { oidc_issuer: 'https://issuer.example.com', identity: 'https://ci.example.com/release', builder_id: 'https://ci.example.com/builder' };
    for (const stability of ['beta', 'stable']) {
      expect(k9Findings(defs, cfgOf({ stability }), CORE_REGISTRY)).toStrictEqual([{ rule: 'LP-001', severity: 'warning', message: `a ${stability} pack must pin the identity that builds it: add provenance {oidc_issuer, identity | identity_prefix, builder_id} to pca.config.json` }]);
      expect(k9Findings(defs, cfgOf({ stability, provenance: pinned }), CORE_REGISTRY)).toEqual([]);
    }
    expect(k9Findings(defs, cfgOf({ stability: 'draft' }), CORE_REGISTRY)).toEqual([]);
    expect(k9Findings(defs, null, CORE_REGISTRY)).toEqual([]);
    expect(k9Findings(defs, cfgOf(), CORE_REGISTRY)).toEqual([]);
  });
  it('a trace rule that is not shaped <id>: ... is an LT-000 error and stops the check', () => {
    const defs = defsOf(HELLO);
    const r = k9Findings(defs, cfgOf({ stability: 'beta', trace: { rules: ['nonsense'] } }), CORE_REGISTRY);
    expect(r).toStrictEqual([
      { rule: 'LP-001', severity: 'warning', message: expect.stringMatching(/^a beta pack must pin/) },
      { rule: 'LT-000', severity: 'error', message: "'nonsense' must be '<id>: never <B> after <A> within <duration>'" },
    ]);
    const bad = k9Findings(defs, cfgOf({ trace: { rules: ['Bad_Id: never tool:acme.invoice.send after tool:acme.invoice.send within 1h'] } }), CORE_REGISTRY);
    expect(bad).toHaveLength(1);
    expect(bad[0]!.rule).toBe('LT-000');
    expect(bad[0]!.message).toMatch(/^'Bad_Id: never .+' must be '<id>: never/);
  });
  it('a rule may omit the space after the colon, and the id may have 40 characters', () => {
    const defs = defsOf(HELLO);
    const rule = (id: string, sep: string) => `${id}:${sep}never tool:acme.invoice.send after tool:acme.invoice.send within 1h`;
    for (const sep of ['', ' ', '   ']) expect(k9Findings(defs, cfgOf({ trace: { rules: [rule('r', sep)] } }), CORE_REGISTRY).filter((f) => f.rule === 'LT-000')).toEqual([]);
    expect(k9Findings(defs, cfgOf({ trace: { rules: [rule('a'.repeat(40), '')] } }), CORE_REGISTRY).filter((f) => f.rule === 'LT-000')).toEqual([]);
    expect(k9Findings(defs, cfgOf({ trace: { rules: [rule('a'.repeat(41), '')] } }), CORE_REGISTRY).map((f) => f.rule)).toContain('LT-000');
    expect(k9Findings(defs, cfgOf({ trace: { rules: [rule('1a', '')] } }), CORE_REGISTRY).map((f) => f.rule)).toContain('LT-000');
  });
  it('the later action of a rule may name a trait: an unconfirmed action carries every trait', () => {
    const defs = defsOf(HELLO);
    const r = k9Findings(defs, cfgOf({ trace: { rules: ['r: never trait:pca.money_moving after tool:acme.invoice.send within 1h'] } }), CORE_REGISTRY);
    expect(r.filter((f) => f.rule === 'LT-000')).toEqual([]);
  });
  it('the lethal trifecta lists every leg, sorted, in the finding', () => {
    const defs = defsOf(HELLO, reader('news', ''), reader('feed', ''), reader('cust', PII), reader('mail', PII));
    const cfg = cfgOf({ trace: { rules: [], untrusted: ['acme.news.read', 'acme.feed.read'] } });
    const r = k9Findings(defs, cfg, CORE_REGISTRY);
    expect(r).toStrictEqual([{
      rule: 'LT-001', severity: 'warning', verb: 'acme.invoice.send',
      message: "untrusted content (acme.feed.read, acme.news.read) and private data (acme.cust.read, acme.invoice.send, acme.mail.read) can reach this send: add a trace rule 'never tool:acme.invoice.send after tool:acme.feed.read within <duration>' (or cut the private leg)",
    }]);
    // without the untrusted list there is no untrusted leg, and a rule cutting the first untrusted source leaves the finding open on the others
    expect(k9Findings(defs, cfgOf({ trace: { rules: [] } }), CORE_REGISTRY)).toEqual([]);
    expect(k9Findings(defs, cfgOf(), CORE_REGISTRY)).toEqual([]);
    expect(k9Findings(defs, null, CORE_REGISTRY)).toEqual([]);
    const cut = k9Findings(defs, cfgOf({ trace: { rules: ['r1: never tool:acme.invoice.send after tool:acme.feed.read within 1h', 'r2: never tool:acme.invoice.send after tool:acme.news.read within 1h'], untrusted: cfg.trace!.untrusted! } }), CORE_REGISTRY);
    expect(cut).toEqual([]);
  });
});
