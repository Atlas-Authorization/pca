import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { inCwd } from './cwd-fixture';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { actionSchemaDigest, actionSchemaKeyOf } from '@atlasauth/pca/ext/intent';
import {
  CORE_REGISTRY, businessRulesDigest, defDigest, diffPacks, explainBusinessRules, explainDef, extendRegistry, lintText, loadActionsText, packKeyOf, runDefTests, runRuleExamples, testText,
  type RulesDoc, type RulesReview, type TraitDef,
} from '@atlasauth/pca-actions';
import {
  cmdActionExplain, cmdBuild, cmdConfirm, cmdDiff, cmdInit, cmdPublish, cmdSign, cmdSync, cmdTest, loadProject, projectDir, writeRulesReviews,
} from './actions';

vi.mock('node:fs', async (orig) => (await import('./cwd-fixture')).withVirtualCwd(await orig<typeof import('node:fs')>()));

const tmp = (): string => mkdtempSync(join(tmpdir(), 'pcacli-wf-'));
const put = (dir: string, name: string, text: string): string => { const f = join(dir, name); writeFileSync(f, text); return f; };
const read = (...p: string[]): string => readFileSync(join(...p), 'utf8');
const CONFIG = { ns: 'acme', version: '0.1.0', stability: 'draft', site: 'https://acme.example.com', aud: 'acme-api' };
const NOTE_TAIL = 'treated as the most dangerous kind of action (every high-risk trait, step-up) until confirmed (pca actions confirm)';

function project(template = 'minimal', ns = 'acme') {
  const root = tmp();
  const dir = join(root, 'actions');
  expect(cmdInit({ dir, ns, template }).ok).toBe(true);
  return { root, dir, out: join(root, '.pca') };
}

const RULES = `    rules:
      recipients: {param: to, domains: [b.com]}
      required: [note]
      rate: [{max: 10, per: hour}]
      examples:
        - {params: {invoice: inv_12345678, to: a@b.com, note: hi, idempotency_key: k_12345678}, expect: allow}
        - {params: {invoice: inv_12345678, to: a@example.net, note: hi, idempotency_key: k_12345678}, expect: deny}
        - {params: {invoice: inv_12345678, to: a@b.com, note: hi, idempotency_key: k_12345678}, recent: {"0": 10}, expect: deny}
`;
function rulesProject(rules = RULES) {
  const p = project();
  const f = join(p.dir, 'acme.yaml');
  writeFileSync(f, read(f).replace(/\n    examples:\n/, `\n${rules}    examples:\n`));
  return { ...p, file: f };
}

// ---- configs that every command refuses ------------------------------------------------------------------------------------------

describe('a config that does not load or build is refused by every command, with its own message', () => {
  const badTrait = { id: 'pca.mine', implies: [] } as unknown as TraitDef;
  let registryMsg = '';
  try { extendRegistry(CORE_REGISTRY, [badTrait]); } catch (e) { registryMsg = (e as Error).message; }
  const sources = [{ name: 'api', from: 'openapi', file: 'api.json' }];

  const all = (dir: string, other: string): Array<[string, () => Promise<{ ok: boolean; text: string }> | { ok: boolean; text: string }]> => [
    ['test', () => cmdTest([dir])],
    ['explain', () => cmdActionExplain([dir], 'acme.invoice.send')],
    ['diff', () => cmdDiff([other], [dir])],
    ['build', () => cmdBuild([dir], { out: join(dir, '..', 'o') })],
    ['sign', () => cmdSign([dir], { out: join(dir, '..', 'o'), kid: 'k', key: 'x' })],
    ['publish', () => cmdPublish([dir], { out: join(dir, '..', 'o') })],
    ['sync', () => cmdSync([dir])],
  ];
  it('an invalid config document', async () => {
    const { dir } = project();
    const other = project().dir;
    put(dir, 'pca.config.json', JSON.stringify({ ns: 'acme', sources }));
    const want = 'pca.config.json: version must be a semantic version';
    for (const [name, run] of all(dir, other)) expect(await run(), name).toEqual({ ok: false, text: want });
  });
  it('custom traits that do not build', async () => {
    const { dir } = project();
    const other = project().dir;
    put(dir, 'pca.config.json', JSON.stringify({ ...CONFIG, traits: [badTrait], sources }));
    expect(registryMsg.length).toBeGreaterThan(0);
    for (const [name, run] of all(dir, other)) expect(await run(), name).toEqual({ ok: false, text: `custom traits: ${registryMsg}` });
  });
});

// ---- cmdTest -------------------------------------------------------------------------------------------------------------------

describe('cmdTest', () => {
  it('a project that does not load reports only the load errors', () => {
    const { dir } = project();
    put(dir, 'broken.yaml', 'ns: acme\nactions: *oops\n');
    const errs = loadProject([dir]).findings.filter((f) => f.severity === 'error');
    expect(errs).toHaveLength(1);
    expect(cmdTest([dir])).toEqual({ ok: false, text: lintText(errs) });
  });
  it('without rules the text is the example run and the unconfirmed note, and nothing else', () => {
    const { dir } = project();
    const defs = loadProject([dir]).defs;
    const r = cmdTest([dir]);
    expect(r.ok).toBe(true);
    expect(r.text).toBe(`${testText(runDefTests(defs, CORE_REGISTRY))}\n1 of 1 action is not confirmed by a pinned reviewer: it is ${NOTE_TAIL}`);
  });
  it('rules examples are listed one line each, in order, between the run and the note', () => {
    const p = rulesProject();
    const l = loadProject([p.dir]);
    const d = l.defs[0]!;
    const ex = runRuleExamples(d, l.rules[d.verb]!);
    expect(ex).toHaveLength(3);
    const lines = ex.map((x) => `${x.ok ? 'PASS' : 'FAIL'}  ${d.verb} rules example ${x.index + 1}: expected ${x.expect}, got ${x.got} (${x.why})`);
    const r = cmdTest([p.dir]);
    expect(r.ok).toBe(true);
    expect(r.text).toBe(`${testText(runDefTests(l.defs, CORE_REGISTRY))}\n${lines.join('\n')}\n1 of 1 action is not confirmed by a pinned reviewer: it is ${NOTE_TAIL}`);
    expect(lines[0]).toMatch(/^PASS {2}acme\.invoice\.send rules example 1: expected allow, got allow/);
  });
  it('a failing rules example fails the run and prints FAIL for that line only', () => {
    const p = rulesProject(RULES.replace('expect: allow}', 'expect: deny}'));
    const r = cmdTest([p.dir]);
    expect(r.ok).toBe(false);
    const rl = r.text.split('\n').filter((l) => / rules example \d/.test(l));
    expect(rl.map((l) => l.slice(0, 4))).toEqual(['FAIL', 'PASS', 'PASS']);
    expect(rl[0]).toMatch(/^FAIL {2}acme\.invoice\.send rules example 1: expected deny, got allow/);
  });
});

// ---- cmdActionExplain ---------------------------------------------------------------------------------------------------------

describe('cmdActionExplain', () => {
  it('an unknown action names every path searched', () => {
    const a = project().dir;
    const b = project().dir;
    expect(cmdActionExplain([a, b], 'acme.nope')).toEqual({ ok: false, text: `no action 'acme.nope' in ${a}, ${b}` });
    expect(cmdActionExplain([a], 'Stryker was here').ok).toBe(false);
  });
  it('an alias finds the action', () => {
    const { dir } = project();
    put(dir, 'acme.yaml', read(dir, 'acme.yaml').replace('    title: Send an invoice\n', '    aliases: [acme.invoice.mail]\n    title: Send an invoice\n'));
    const canonical = cmdActionExplain([dir], 'acme.invoice.send');
    expect(canonical.ok).toBe(true);
    expect(cmdActionExplain([dir], 'acme.invoice.mail')).toEqual(canonical);
  });
  it('the text is the plain explanation, followed by one bullet per business rule when there are rules', () => {
    const plain = project();
    const d0 = loadProject([plain.dir]).defs[0]!;
    expect(cmdActionExplain([plain.dir], d0.verb)).toEqual({ ok: true, text: explainDef(d0, CORE_REGISTRY, {}) });
    const p = rulesProject();
    const l = loadProject([p.dir]);
    const d = l.defs[0]!;
    const bullets = explainBusinessRules(d, l.rules[d.verb]!);
    expect(bullets.length).toBeGreaterThan(1);
    expect(cmdActionExplain([p.dir], d.verb)).toEqual({ ok: true, text: `${explainDef(d, CORE_REGISTRY, {})}\nbusiness rules:\n${bullets.map((x) => `  - ${x}`).join('\n')}` });
  });
});

// ---- cmdDiff -------------------------------------------------------------------------------------------------------------------

describe('cmdDiff', () => {
  const mirror = (aDir: string, bDir: string): { ok: boolean; text: string } => {
    const rows = diffPacks(loadProject([aDir]).defs, loadProject([bDir]).defs, CORE_REGISTRY);
    const worst = rows.some((r) => r.class === 'widen' || r.class === 'incomparable' || r.class === 'removed');
    const lines = rows.map((r) => `${r.class.padEnd(12)} ${r.verb}${r.breaking ? '  (breaking)' : ''}${r.reasons.length ? '\n' + r.reasons.map((x) => `    ${x}`).join('\n') : ''}`);
    return { ok: !worst, text: `${lines.join('\n') || 'no actions'}\n${worst ? 'widens authority (needs re-approval)' : 'no widening'}` };
  };
  const pair = (edit: (y: string) => string) => {
    const a = project('saas');
    const b = project('saas');
    put(b.dir, 'acme.yaml', edit(read(b.dir, 'acme.yaml')));
    return { a: a.dir, b: b.dir };
  };

  it('identical projects are equal and widen nothing', () => {
    const { a, b } = pair((y) => y);
    const r = cmdDiff([a], [b]);
    expect(r).toEqual(mirror(a, b));
    expect(r.ok).toBe(true);
    expect(r.text).toMatch(/^equal {8}acme\.charge\.refund$/m);
    expect(r.text.endsWith('\nno widening')).toBe(true);
  });
  it('a widened ceiling fails and lists the reason under the action', () => {
    const { a, b } = pair((y) => y.replace('max=100000', 'max=999999'));
    const r = cmdDiff([a], [b]);
    expect(r).toEqual(mirror(a, b));
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/^widen {8}acme\.charge\.refund(  \(breaking\))?\n {4}widen: param amount: max 100000 to 999999$/m);
    expect(r.text.endsWith('\nwidens authority (needs re-approval)')).toBe(true);
  });
  it('a removed action alone fails the diff', () => {
    const { a, b } = pair((y) => y.split('  - verb: acme.customer.delete')[0]!);
    const r = cmdDiff([a], [b]);
    expect(r).toEqual(mirror(a, b));
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/^removed {6}acme\.customer\.delete/m);
    expect(r.text).not.toMatch(/^(widen|incomparable) /m);
  });
  it('an incomparable change alone fails the diff', () => {
    const { a, b } = pair((y) => y.replace('money(USD, max=100000)', 'money(EUR, max=100000)'));
    const rows = diffPacks(loadProject([a]).defs, loadProject([b]).defs, CORE_REGISTRY);
    expect(rows.map((x) => x.class).filter((c) => c !== 'equal')).toEqual(['incomparable']);
    const r = cmdDiff([a], [b]);
    expect(r).toEqual(mirror(a, b));
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/^incomparable {1}acme\.charge\.refund/m);
  });
  it('a narrowed ceiling is fine', () => {
    const { a, b } = pair((y) => y.replace('max=100000', 'max=1000'));
    const r = cmdDiff([a], [b]);
    expect(r).toEqual(mirror(a, b));
    expect(r.ok).toBe(true);
    expect(r.text).toMatch(/^narrow {7}acme\.charge\.refund/m);
  });
  it('two projects with no actions say so', () => {
    const a = tmp();
    const b = tmp();
    put(a, 'pca.config.json', JSON.stringify(CONFIG));
    put(b, 'pca.config.json', JSON.stringify(CONFIG));
    expect(cmdDiff([a], [b])).toEqual({ ok: true, text: 'no actions\nno widening' });
  });
  it('load errors on either side stop the diff and are listed, old side first', () => {
    const good = project().dir;
    const oldBad = project().dir;
    const newBad = project().dir;
    put(oldBad, 'broken.yaml', 'ns: acme\nactions: *oops\n');
    put(newBad, 'broken.yaml', 'ns: acme\nactions: [unterminated\n');
    const errsOf = (d: string) => loadProject([d]).findings.filter((f) => f.severity === 'error');
    expect(errsOf(oldBad)).toHaveLength(1);
    expect(errsOf(newBad)).toHaveLength(1);
    expect(cmdDiff([oldBad], [good])).toEqual({ ok: false, text: lintText(errsOf(oldBad)) });
    expect(cmdDiff([good], [newBad])).toEqual({ ok: false, text: lintText(errsOf(newBad)) });
    expect(cmdDiff([oldBad], [newBad])).toEqual({ ok: false, text: lintText([...errsOf(oldBad), ...errsOf(newBad)]) });
  });
});

// ---- cmdBuild, the rules document and the project directory -----------------------------------------------------------------

describe('cmdBuild', () => {
  it('without a config it names every path it looked at', () => {
    const a = tmp();
    const b = tmp();
    expect(cmdBuild([a, b])).toEqual({ ok: false, text: `no pca.config.json next to ${a}, ${b} (run pca actions init)` });
  });
  it('reports what it built, with the right plural, and writes pretty JSON files plus the typings', () => {
    const { dir, out } = project();
    const r = cmdBuild([dir], { out });
    const root = JSON.parse(read(out, 'pack.json')).root as string;
    expect(r).toEqual({ ok: true, text: `built 1 action into ${out} (pack root ${root})\n1 of 1 action is not confirmed by a pinned reviewer: it is ${NOTE_TAIL}` });
    for (const f of ['schema.json', 'pack.json', 'cards.json', 'ontology.json', 'mcp.json', 'rules.json']) {
      const t = read(out, f);
      expect(t.endsWith('}\n') || t.endsWith(']\n'), f).toBe(true);
      expect(t, f).toBe(JSON.stringify(JSON.parse(t), null, 2) + '\n');
    }
    expect(read(out, 'types.d.ts').startsWith('"')).toBe(false);
    expect(read(out, 'types.d.ts')).toMatch(/export interface AcmeInvoiceSendParams/);
    const p2 = project('saas');
    expect(cmdBuild([p2.dir], { out: p2.out }).text).toMatch(/^built 3 actions into /);
  });
  it('the rules document carries every action\'s rules, and only the reviews that still match the def and the rules', () => {
    const p = rulesProject();
    const text = read(p.file);
    const kp = generateKeyPair();
    const c = cmdConfirm(text, { verbs: ['acme.invoice.send'], kid: 'rev-1', secret: b64u(kp.secretKey), yes: true, ts: 1_700_000_000 });
    expect(c.ok, c.text).toBe(true);
    writeFileSync(p.file, c.yaml);
    const review = c.rulesReviews!['acme.invoice.send']!;
    const rulesOf = (): RulesDoc => JSON.parse(read(p.out, 'rules.json')) as RulesDoc;

    writeRulesReviews(p.dir, { 'acme.invoice.send': review });
    expect(cmdBuild([p.dir], { out: p.out }).ok).toBe(true);
    expect(rulesOf().kind).toBe('pca-action-rules');
    expect(rulesOf().rules['acme.invoice.send']).toEqual(loadActionsText(c.yaml).rules['acme.invoice.send']);
    expect(rulesOf().reviews?.['acme.invoice.send']?.sig).toBe(review.sig);

    const def = loadActionsText(c.yaml).defs[0]!;
    expect(review.def_digest).toBe(defDigest(def));
    expect(review.rules_digest).toBe(businessRulesDigest(def.verb, loadActionsText(c.yaml).rules[def.verb]!));
    // a review of another def version is dropped even though the rules still match
    writeRulesReviews(p.dir, { 'acme.invoice.send': { ...review, def_digest: review.rules_digest } });
    expect(cmdBuild([p.dir], { out: p.out }).ok).toBe(true);
    expect(rulesOf().reviews).toBeUndefined();
    // and so is a review of other rules
    writeRulesReviews(p.dir, { 'acme.invoice.send': { ...review, rules_digest: review.def_digest } });
    expect(cmdBuild([p.dir], { out: p.out }).ok).toBe(true);
    expect(rulesOf().reviews).toBeUndefined();
    // a reviews file that is not JSON is ignored
    put(p.dir, 'pca.rules-reviews.json', '{nope');
    expect(cmdBuild([p.dir], { out: p.out }).ok).toBe(true);
    expect(rulesOf().reviews).toBeUndefined();
    expect(rulesOf().rules['acme.invoice.send']).toBeDefined();
  });
});

describe('writeRulesReviews', () => {
  const rev = (verb: string, sig: string): RulesReview => ({ verb, def_digest: 'd', rules_digest: 'r', reviewer_kid: 'k', ts: 1, sig } as unknown as RulesReview);

  it('writes pretty JSON next to the project and merges with what is there, a later review of a verb replacing the earlier', () => {
    const dir = tmp();
    const f = writeRulesReviews(dir, { 'a.x.y': rev('a.x.y', 's1') });
    expect(f).toBe(join(dir, 'pca.rules-reviews.json'));
    expect(readFileSync(f, 'utf8')).toBe(JSON.stringify({ 'a.x.y': rev('a.x.y', 's1') }, null, 2) + '\n');
    writeRulesReviews(dir, { 'a.x.z': rev('a.x.z', 's2') });
    writeRulesReviews(dir, { 'a.x.y': rev('a.x.y', 's3') });
    expect(JSON.parse(readFileSync(f, 'utf8'))).toEqual({ 'a.x.y': rev('a.x.y', 's3'), 'a.x.z': rev('a.x.z', 's2') });
  });
  it('a reviews file that is not JSON is replaced', () => {
    const dir = tmp();
    put(dir, 'pca.rules-reviews.json', '{nope');
    writeRulesReviews(dir, { 'a.x.y': rev('a.x.y', 's1') });
    expect(JSON.parse(read(dir, 'pca.rules-reviews.json'))).toEqual({ 'a.x.y': rev('a.x.y', 's1') });
  });
});

describe('projectDir', () => {
  it('is the directory itself, or the directory of a file, existing or not', () => {
    const dir = tmp();
    const f = put(dir, 'a.yaml', 'x');
    expect(projectDir([dir])).toBe(dir);
    expect(projectDir([f])).toBe(dir);
    expect(projectDir([join(dir, 'missing.yaml')])).toBe(dir);
    expect(projectDir([join(dir, 'missing')])).toBe(dir);
    expect(projectDir([dir, tmp()])).toBe(dir);
  });
  it('defaults to ./actions', () => {
    const root = tmp();
    mkdirSync(join(root, 'actions'));
    expect(inCwd(root, () => projectDir([]))).toBe('actions');
  });
});

// ---- cmdSign -------------------------------------------------------------------------------------------------------------------

describe('cmdSign', () => {
  const built = (template = 'minimal') => {
    const p = project(template);
    const b = cmdBuild([p.dir], { out: p.out });
    expect(b.ok, b.text).toBe(true);
    return p;
  };
  const rawKey = () => generateKeyPair().secretKey;

  it('without a config it names every path it looked at', () => {
    const a = tmp();
    const b = tmp();
    expect(cmdSign([a, b], { kid: 'k', key: 'x' })).toEqual({ ok: false, text: `no pca.config.json next to ${a}, ${b}` });
  });
  it('writes the signed schema, the signed pack and the key list, and says where the keys are', () => {
    const { dir, out } = built();
    const sk = rawKey();
    const r = cmdSign([dir], { out, kid: 'site-1', key: b64u(sk) });
    expect(r.ok, r.text).toBe(true);
    const signedText = read(out, 'pca-actions.json');
    const signed = JSON.parse(signedText);
    const root = JSON.parse(read(out, 'pack.json')).root as string;
    expect(r.text).toBe(`signed schema ${actionSchemaDigest(signed)} and pack ${root}\nkeys: ${join(out, 'keys.json')} (list them under intent.schema_keys in your discovery document)`);
    for (const f of ['pca-actions.json', 'pack.signed.json', 'keys.json']) {
      const t = read(out, f);
      expect(t, f).toBe(JSON.stringify(JSON.parse(t), null, 2) + '\n');
    }
    expect(JSON.parse(read(out, 'keys.json'))).toEqual([actionSchemaKeyOf('site-1', sk)]);
  });
  it('lists the registry key too when the pack has its own key or its own key id', () => {
    const sk = rawKey();
    const psk = rawKey();
    const cases: Array<[Record<string, string>, unknown[]]> = [
      [{}, [actionSchemaKeyOf('site', sk)]],
      [{ packKey: b64u(psk) }, [actionSchemaKeyOf('site', sk), packKeyOf('site', psk)]],
      [{ packKid: 'reg' }, [actionSchemaKeyOf('site', sk), packKeyOf('reg', sk)]],
      [{ packKid: 'reg', packKey: b64u(psk) }, [actionSchemaKeyOf('site', sk), packKeyOf('reg', psk)]],
    ];
    for (const [extra, keys] of cases) {
      const { dir, out } = built();
      const r = cmdSign([dir], { out, kid: 'site', key: b64u(sk), ...extra });
      expect(r.ok, r.text).toBe(true);
      expect(JSON.parse(read(out, 'keys.json')), JSON.stringify(Object.keys(extra))).toEqual(keys);
    }
  });
  it('a key given as @file is read from the file, trailing newline and all', async () => {
    const { dir, out, root } = { ...built(), root: tmp() };
    const kf = put(root, 'site.key', b64u(rawKey()) + '\n');
    const r = cmdSign([dir], { out, kid: 'k', key: `@${kf}` });
    expect(r.ok, r.text).toBe(true);
    const missing = cmdSign([dir], { out, kid: 'k', key: `@${join(root, 'nope.key')}` });
    expect(missing.ok).toBe(false);
    expect(missing.text).toMatch(/^not signing: /);
    const short = put(root, 'short.key', b64u(new Uint8Array(16)));
    expect(cmdSign([dir], { out, kid: 'k', key: `@${short}` })).toEqual({ ok: false, text: 'not signing: a signing key must be a base64url 32-byte Ed25519 secret' });
    expect((await cmdPublish([dir], { out })).ok).toBe(true);
  });
  it('a pack with custom traits signs under the config\'s own traits', () => {
    const { dir, out } = project('ecommerce', 'store');
    const b = cmdBuild([dir], { out });
    expect(b.ok, b.text).toBe(true);
    const r = cmdSign([dir], { out, kid: 'k', key: b64u(rawKey()) });
    expect(r.ok, r.text).toBe(true);
  });
  it('warnings do not stop a draft pack from signing', () => {
    const { dir, out } = project();
    put(dir, 'warn.yaml', 'ns: acme\nactions:\n  - {verb: acme.invoice.get, title: Read an invoice, effects: read, resource: "acme.invoice:inv_*", params: {invoice: "id:acme.invoice"}}\n');
    expect(cmdBuild([dir], { out }).ok).toBe(true);
    const r = cmdSign([dir], { out, kid: 'k', key: b64u(rawKey()) });
    expect(r.ok, r.text).toBe(true);
    expect(existsSync(join(out, 'pack.signed.json'))).toBe(true);
  });
});
