import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { b64u, generateKeyPair, publicKeyOf } from '@atlasauth/pca';
import { STARTER_TEMPLATES, businessRulesDigest, defDigest, loadActionsText, rulesReviewError, type RulesDoc } from '@atlasauth/pca-actions';
import { cmdActionExplain, cmdBuild, cmdConfirm, cmdInit, cmdLint, cmdSync, cmdTest, collectFiles, parseConfig, publishToRegistry, writeRulesReviews, type SourceFetch } from './actions';

const roots: string[] = [];
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'pca-rules-')); roots.push(d); return d; };
afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });
const read = (...p: string[]): string => readFileSync(join(...p), 'utf8');

const RULES = `    rules:
      recipients: {param: to, domains: [b.com]}
      required: [note]
      rate: [{max: 10, per: hour}]
      examples:
        - {params: {invoice: inv_12345678, to: a@b.com, note: hi, idempotency_key: k_12345678}, expect: allow}
        - {params: {invoice: inv_12345678, to: a@example.net, note: hi, idempotency_key: k_12345678}, expect: deny}
        - {params: {invoice: inv_12345678, to: a@b.com, note: hi, idempotency_key: k_12345678}, recent: {"0": 10}, expect: deny}
`;

/** The hello-world project with a business rules block on its action. */
function rulesProject(rules = RULES) {
  const root = tmp();
  const dir = join(root, 'actions');
  expect(cmdInit({ dir, ns: 'acme' }).ok).toBe(true);
  const f = join(dir, 'acme.yaml');
  writeFileSync(f, read(f).replace(/\n    examples:\n/, `\n${rules}    examples:\n`));
  return { root, dir, file: f, out: join(root, '.pca') };
}

describe('pca actions: business rules', () => {
  it('lint, test and explain read the rules block; a rewrite keeps it', () => {
    const p = rulesProject();
    const l = loadActionsText(read(p.file));
    expect(l.errors).toEqual([]);
    expect(Object.keys(l.rules)).toEqual(['acme.invoice.send']);
    const lint = cmdLint([p.dir]);
    expect(lint.ok, lint.text).toBe(true);
    const t = cmdTest([p.dir]);
    expect(t.ok, t.text).toBe(true);
    expect(t.text).toMatch(/PASS {2}acme\.invoice\.send rules example 2: expected deny, got deny/);
    expect(t.text).toMatch(/PASS {2}acme\.invoice\.send rules example 3: expected deny, got deny/);
    const ex = cmdActionExplain([p.dir], 'acme.invoice.send');
    expect(ex.ok).toBe(true);
    expect(ex.text).toMatch(/\nbusiness rules:\n {2}- /);
    expect(ex.text).toMatch(/b\.com/);
  });

  it('a failing rules example fails the test run; a malformed block is an LR-001 error', () => {
    const bad = rulesProject(RULES.replace('expect: allow}', 'expect: deny}'));
    const t = cmdTest([bad.dir]);
    expect(t.ok).toBe(false);
    expect(t.text).toMatch(/FAIL {2}acme\.invoice\.send rules example 1: expected deny, got allow/);
    const broken = rulesProject('    rules:\n      recipients: {param: nope, domains: [b.com]}\n');
    expect(cmdLint([broken.dir]).ok).toBe(false);
  });

  it('confirm signs a rules review with the reviewer key; build carries only the reviews that still match', () => {
    const p = rulesProject();
    const kp = generateKeyPair();
    const r = cmdConfirm(read(p.file), { verbs: ['acme.invoice.send'], kid: 'rev-1', secret: b64u(kp.secretKey), yes: true, ts: 1_700_000_000 });
    expect(r.ok, r.text).toBe(true);
    expect(r.text).toMatch(/and the business rules of 1/);
    // the rewritten file keeps the rules block
    expect(loadActionsText(r.yaml).rules['acme.invoice.send']).toBeDefined();
    writeFileSync(p.file, r.yaml);
    const review = r.rulesReviews!['acme.invoice.send']!;
    const def = loadActionsText(r.yaml).defs[0]!;
    const rules = loadActionsText(r.yaml).rules['acme.invoice.send']!;
    expect(review).toMatchObject({ verb: 'acme.invoice.send', def_digest: defDigest(def), rules_digest: businessRulesDigest(def.verb, rules), reviewer_kid: 'rev-1' });
    const pins = { keys: [{ kid: 'rev-1', pk: b64u(publicKeyOf(kp.secretKey)), roles: ['reviewer' as const] }] };
    expect(rulesReviewError(review, def, rules, pins)).toBeNull();
    // a key pinned in another role never counts
    expect(rulesReviewError(review, def, rules, { keys: [{ kid: 'rev-1', pk: b64u(publicKeyOf(kp.secretKey)), roles: ['importer' as never] }] })).not.toBeNull();

    writeRulesReviews(p.dir, r.rulesReviews!);
    expect(collectFiles([p.dir]).some((f) => f.endsWith('pca.rules-reviews.json'))).toBe(false);
    expect(cmdBuild([p.dir], { out: p.out }).ok).toBe(true);
    const doc = JSON.parse(read(p.out, 'rules.json')) as RulesDoc;
    expect(doc).toMatchObject({ v: 1, kind: 'pca-action-rules', ns: 'acme' });
    expect(doc.reviews?.['acme.invoice.send']?.sig).toBe(review.sig);

    // edit the rules: the old review no longer matches and is dropped from the build (the registry will ask for a new one)
    writeFileSync(p.file, read(p.file).replace('max: 10', 'max: 5')); // tighter, so the rule examples still hold
    expect(cmdBuild([p.dir], { out: p.out }).ok).toBe(true);
    expect((JSON.parse(read(p.out, 'rules.json')) as RulesDoc).reviews).toBeUndefined();
  });

  it('publishToRegistry names the actions a refused publish needs reviewed', async () => {
    const fetchImpl = async () => ({ status: 409, json: async () => ({ errors: [{ message: 'Widening without review', meta: { reason_code: 'widen_unreviewed', verbs: ['acme.invoice.send'] } }] }) });
    const r = await publishToRegistry({ api: 'https://api.example.com', sk: 'sk_test', pack: { ns: 'acme', version: '0.2.0' } as never, fetchImpl });
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/409 widen_unreviewed/);
    expect(r.text).toMatch(/needs a reviewer: acme\.invoice\.send/);
  });
});

const API = (ops: Record<string, unknown>) => JSON.stringify({ openapi: '3.0.0', paths: ops });
const getOrder = { '/orders/{id}': { parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', maxLength: 40 } }], get: { operationId: 'getOrder', summary: 'Get an order' } } };
const cancelOrder = { '/orders/{id}/cancel': { parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', maxLength: 40 } }], post: { operationId: 'cancelOrder', summary: 'Cancel an order' } } };

function syncProject(spec: string) {
  const root = tmp();
  const dir = join(root, 'actions');
  expect(cmdInit({ dir, ns: 'shop' }).ok).toBe(true);
  rmSync(join(dir, 'shop.yaml'));
  writeFileSync(join(root, 'openapi.json'), spec);
  const cfg = JSON.parse(read(dir, 'pca.config.json'));
  writeFileSync(join(dir, 'pca.config.json'), JSON.stringify({ ...cfg, sources: [{ name: 'api', from: 'openapi', file: '../openapi.json' }] }));
  return { root, dir };
}

describe('pca actions sync', () => {
  it('config sources are validated', () => {
    const base = { ns: 'a', version: '1.0.0', stability: 'draft', site: 's', aud: 'a' };
    expect(parseConfig(JSON.stringify({ ...base, sources: [{ name: 'api', from: 'openapi', url: 'http://x.example/o.json' }] }))).toMatch(/https URL/);
    expect(parseConfig(JSON.stringify({ ...base, sources: [{ name: 'api', from: 'openapi' }] }))).toMatch(/exactly one of file \/ url/);
    expect(parseConfig(JSON.stringify({ ...base, sources: [{ name: 'api', from: 'soap', file: 'x' }] }))).toMatch(/from must be/);
    expect(parseConfig(JSON.stringify({ ...base, sources: [{ name: 'a', from: 'jsonschema', file: 'x' }] }))).toMatch(/verb is required/);
    expect(parseConfig(JSON.stringify({ ...base, sources: [{ name: 'a', from: 'openapi', file: 'x' }, { name: 'a', from: 'openapi', file: 'y' }] }))).toMatch(/unique/);
    expect(typeof parseConfig(JSON.stringify({ ...base, sources: [{ name: 'api', from: 'openapi', url: 'https://x.example/o.json' }] }))).toBe('object');
  });

  it('first sync adds unreviewed actions; a later change lands unreviewed, a removal leaves the file; --check fails on change', async () => {
    const p = syncProject(API(getOrder));
    const first = await cmdSync([p.dir], { now: 1_700_000_000_000 });
    expect(first.ok, first.text).toBe(true);
    expect(first.text).toMatch(/1 added, 0 changed, 0 removed/);
    expect(existsSync(join(p.dir, 'api.sync.yaml'))).toBe(true);
    expect(existsSync(join(p.dir, 'pca.sync.json'))).toBe(true);
    const l1 = loadActionsText(read(p.dir, 'api.sync.yaml'));
    expect(l1.defs.length).toBe(1);
    expect(l1.defs.every((d) => d.review.state !== 'confirmed')).toBe(true);
    // the project still lints (the lock is not an action file)
    expect(cmdLint([p.dir]).text).not.toMatch(/pca\.sync\.json/);

    // unchanged source: nothing to do, and --check passes
    expect((await cmdSync([p.dir], { check: true })).ok).toBe(true);

    // a new operation and the old one removed
    writeFileSync(join(p.root, 'openapi.json'), API(cancelOrder));
    const before = [read(p.dir, 'api.sync.yaml'), read(p.dir, 'pca.sync.json')];
    const chk = await cmdSync([p.dir], { check: true });
    expect(chk.ok).toBe(false);
    expect(chk.text).toMatch(/the sources changed/);
    expect([read(p.dir, 'api.sync.yaml'), read(p.dir, 'pca.sync.json')]).toEqual(before); // --check wrote nothing
    const second = await cmdSync([p.dir], { now: 1_700_000_100_000 });
    expect(second.ok, second.text).toBe(true);
    expect(second.text).toMatch(/1 added, 0 changed, 1 removed \(deprecated\)/);
    const l2 = loadActionsText(read(p.dir, 'api.sync.yaml'));
    expect(l2.defs.map((d) => d.verb)).not.toEqual(l1.defs.map((d) => d.verb));
    expect(l2.defs.every((d) => d.review.state !== 'confirmed')).toBe(true);
  });

  it('an https source is fetched without redirects and with a size cap', async () => {
    const p = syncProject(API(getOrder));
    const cfg = JSON.parse(read(p.dir, 'pca.config.json'));
    writeFileSync(join(p.dir, 'pca.config.json'), JSON.stringify({ ...cfg, sources: [{ name: 'api', from: 'openapi', url: 'https://api.example.com/openapi.json' }] }));
    const seen: Array<{ url: string; redirect: string }> = [];
    const ok: SourceFetch = async (url, init) => { seen.push({ url, redirect: init.redirect }); return { ok: true, status: 200, headers: { get: () => null }, text: async () => API(getOrder) }; };
    expect((await cmdSync([p.dir], { fetchImpl: ok })).ok).toBe(true);
    expect(seen).toEqual([{ url: 'https://api.example.com/openapi.json', redirect: 'error' }]);
    const big: SourceFetch = async () => ({ ok: true, status: 200, headers: { get: (k) => (k === 'content-length' ? String(64 * 1024 * 1024) : null) }, text: async () => '' });
    expect((await cmdSync([p.dir], { fetchImpl: big })).text).toMatch(/larger than/);
    const down: SourceFetch = async () => ({ ok: false, status: 503, headers: { get: () => null }, text: async () => '' });
    expect((await cmdSync([p.dir], { fetchImpl: down })).text).toMatch(/answered 503/);
  });
});

describe('pca actions init --template <business type>', () => {
  it.each(STARTER_TEMPLATES.map((t) => t.id))('%s scaffolds a lint-clean, test-passing, unreviewed project with its custom traits', (id) => {
    const root = tmp();
    const dir = join(root, 'actions');
    const r = cmdInit({ dir, ns: 'acme_co', template: id });
    expect(r.ok, r.text).toBe(true);
    expect(r.text).toMatch(/unreviewed/);
    const cfg = JSON.parse(read(dir, 'pca.config.json'));
    expect(cfg.traits.length).toBeGreaterThan(0);
    expect(cfg.traits.every((t: { id: string }) => t.id.startsWith('acme_co.'))).toBe(true);
    const lint = cmdLint([dir]);
    expect(lint.ok, lint.text).toBe(true);
    expect(lint.text).toMatch(/0 errors, 0 warnings/);
    const t = cmdTest([dir]);
    expect(t.ok, t.text).toBe(true);
    expect(t.text).toMatch(/rules example/);
    expect(t.text).toMatch(/not confirmed by a pinned reviewer/);
    expect(loadActionsText(read(dir, 'acme_co.yaml')).defs.every((d) => d.review.state !== 'confirmed')).toBe(true);
  });
  it('an unknown template lists the choices', () => {
    expect(cmdInit({ dir: join(tmp(), 'a'), ns: 'x', template: 'bank' }).text).toMatch(/ecommerce, fintech, healthcare, saas_admin, devtools/);
  });
});
