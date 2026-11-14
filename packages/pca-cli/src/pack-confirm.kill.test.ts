import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { inCwd } from './cwd-fixture';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { CORE_REGISTRY, defsToYaml, loadActionsText, prepareReview, reviewQueueOrder, type ActionDef } from '@atlasauth/pca-actions';
import { ACTION_TEMPLATES, cmdConfirm, packText } from './actions';

vi.mock('node:fs', async (orig) => (await import('./cwd-fixture')).withVirtualCwd(await orig<typeof import('node:fs')>()));

const tmp = (): string => mkdtempSync(join(tmpdir(), 'pcacli-pack-'));

describe('packText', () => {
  // round-tripped through JSON like the pack files: the template shares one `len` array between defs, which the YAML writer would turn into an alias
  const defsOf = (ns: string): ActionDef[] => JSON.parse(JSON.stringify(loadActionsText(ACTION_TEMPLATES.db!(ns)).defs)) as ActionDef[];
  const writePack = (dir: string, m: unknown, shards: Record<string, string>): void => {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'pack.json'), JSON.stringify(m));
    for (const [f, t] of Object.entries(shards)) writeFileSync(join(dir, f), t);
  };
  const jsonl = (defs: ActionDef[]): string => defs.map((d) => JSON.stringify(d)).join('\n') + '\n';

  it('a pack directory is read directly, shard by shard, skipping blank lines', () => {
    const [a, b] = defsOf('shop') as [ActionDef, ActionDef];
    const dir = join(tmp(), 'mypack');
    writePack(dir, { ns: ['shop', 'other'], shards: [{ file: 's1.jsonl' }, { file: 's2.jsonl' }] }, { 's1.jsonl': `\n${JSON.stringify(a)}\n\n`, 's2.jsonl': `${JSON.stringify(b)}\n\n` });
    expect(packText(dir, join(tmp(), 'unused'))).toStrictEqual({ ok: true, text: defsToYaml('shop', [a, b]), ns: 'shop' });
  });
  it('a string ns is taken as it is', () => {
    const defs = defsOf('shop');
    const dir = join(tmp(), 'p');
    writePack(dir, { ns: 'shop', shards: [{ file: 's.jsonl' }] }, { 's.jsonl': jsonl(defs) });
    expect(packText(dir)).toStrictEqual({ ok: true, text: defsToYaml('shop', defs), ns: 'shop' });
  });
  it('a name under the packs directory resolves to its newest version that has a pack.json', () => {
    const root = tmp();
    const base = join(root, 'cat', 'shop');
    const defs = defsOf('shop');
    for (const v of ['1.9.0', '1.3.0', '1.7.0', '1.1.0', '1.5.0', '1.8.0']) writePack(join(base, v), { ns: ['shop'], shards: [{ file: 's.jsonl' }] }, { 's.jsonl': jsonl(v === '1.9.0' ? defs : defs.slice(0, 1)) });
    mkdirSync(join(base, 'zz-not-a-version'));
    expect(packText('shop', join(root, 'cat'))).toStrictEqual({ ok: true, text: defsToYaml('shop', defs), ns: 'shop' });
  });
  it('the packs directory defaults to ./packs', () => {
    const root = tmp();
    const defs = defsOf('shop');
    writePack(join(root, 'packs', 'shop', '0.1.0'), { ns: ['shop'], shards: [{ file: 's.jsonl' }] }, { 's.jsonl': jsonl(defs) });
    inCwd(root, () => {
      expect(packText('shop')).toStrictEqual({ ok: true, text: defsToYaml('shop', defs), ns: 'shop' });
      expect(packText('nope')).toStrictEqual({ ok: false, text: "no pack 'nope' (a pack directory, or a name under packs)" });
    });
  });
  it('an unknown name, or a name with no versions, is refused and names the directory searched', () => {
    const root = tmp();
    expect(packText('nope', root)).toStrictEqual({ ok: false, text: `no pack 'nope' (a pack directory, or a name under ${root})` });
    mkdirSync(join(root, 'empty', 'v1'), { recursive: true });
    expect(packText('empty', root)).toStrictEqual({ ok: false, text: `no pack 'empty' (a pack directory, or a name under ${root})` });
  });
  it('an unreadable pack says so with the reason', () => {
    const dir = join(tmp(), 'p');
    writePack(dir, { ns: ['shop'], shards: [{ file: 'missing.jsonl' }] }, {});
    const r = packText(dir);
    expect(r.ok).toBe(false);
    expect(Object.keys(r)).toEqual(['ok', 'text']);
    expect(r.text).toMatch(new RegExp(`^cannot read pack '${dir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}': .+`));
    const bad = join(tmp(), 'p');
    writePack(bad, { ns: ['shop'], shards: [{ file: 's.jsonl' }] }, { 's.jsonl': '{nope\n' });
    expect(packText(bad).text).toMatch(/^cannot read pack '.+': .+/);
  });
});

describe('cmdConfirm review output and signing', () => {
  const UNION_BOTH = ['pca.money_moving', 'pca.destructive'];
  const def = (verb: string, union: string[], traits: string[] = union): ActionDef => ({
    v: 1, kind: 'pca-action-def', verb, title: 'Create a refund', description: 'Creates a refund.', effects: ['create'],
    resource: { type: 'acme.refund', id: '*', scope: 'set' },
    params: { note: { type: 'string', max_len: 100 }, idempotency_key: { type: 'string', max_len: 64, required: false } },
    reversibility: 'irreversible', idempotency: { mode: 'key_param', param: 'idempotency_key' },
    traits: [...traits], review: { state: 'authored', ...(union.length ? { provenance: { union: [...union] } } : {}) }, since: '0.5.0',
  });
  const base = { verbs: [] as string[], kid: 'rev-1', yes: false, ts: 1_700_000_000 };
  const sk = (): string => b64u(generateKeyPair().secretKey);
  const three = defsToYaml('acme', [def('acme.a.create', ['pca.money_moving']), def('acme.d.create', UNION_BOTH), def('acme.c.create', [])]);

  const reviewLines = (d: ActionDef): string[] => {
    const v = prepareReview(d, CORE_REGISTRY);
    const u = d.review.provenance?.union ?? [];
    return [
      `${d.verb}  [${v.state}]  risk ${v.card.risk}, ${v.card.escalation}, ${v.card.reversibility}`,
      `  ${v.card.text}`,
      `  declared: ${v.declared_traits.join(', ') || '-'}`,
      `  implied: ${v.implied_traits.join(', ') || '-'}`,
      `  suggested: ${v.suggested.traits.join(', ') || '-'}`,
      ...(u.length ? [`  added from the suggestion rules (union): ${u.join(', ')}`] : []),
    ];
  };

  it('prints each def as five or six lines, riskiest first, and nothing signed', () => {
    const loaded = loadActionsText(three).defs;
    const r = cmdConfirm(three, { ...base, origin: 'any' });
    expect(r.ok).toBe(true);
    expect(r.yaml).toBe('');
    expect(r.text).toBe(reviewQueueOrder(loaded, CORE_REGISTRY).flatMap(reviewLines).join('\n') + '\n(nothing signed: pass --yes with --reviewer-key to confirm)');
    expect(r.text).toContain('  added from the suggestion rules (union): pca.money_moving, pca.destructive\n');
    expect(r.text).toContain('acme.c.create  [');
    const cLines = reviewLines(loaded.find((d) => d.verb === 'acme.c.create')!);
    expect(cLines).toHaveLength(5);
    expect(cLines[2]).toBe('  declared: -');
    expect(r.text).toContain(cLines.join('\n') + '\n');
    const a = loaded.find((d) => d.verb === 'acme.a.create')!;
    expect(reviewLines(a)[2]).toBe('  declared: pca.money_moving');
  });
  it('--origin union without a trait takes every def with any union-added trait, and no other', () => {
    const r = cmdConfirm(three, { ...base, origin: 'union' });
    expect(r.ok).toBe(true);
    expect(r.text).toContain('acme.a.create  [');
    expect(r.text).toContain('acme.d.create  [');
    expect(r.text).not.toContain('acme.c.create');
    const only = cmdConfirm(three, { ...base, origin: 'union', trait: 'destructive' });
    expect(only.text).toContain('acme.d.create  [');
    expect(only.text).not.toContain('acme.a.create');
  });
  it('a verb list narrows the selection, and an unknown verb among known ones is the only one named', () => {
    const r = cmdConfirm(three, { ...base, verbs: ['acme.a.create'], origin: 'any' });
    expect(r.text).toContain('acme.a.create  [');
    expect(r.text).not.toContain('acme.c.create');
    expect(r.text).not.toContain('acme.d.create');
    expect(cmdConfirm(three, { ...base, verbs: ['acme.a.create', 'zz.nope'] })).toEqual({ ok: false, yaml: '', text: 'no such verb: zz.nope' });
    expect(cmdConfirm(three, { ...base, verbs: ['acme.a.create'] }).text).toContain('acme.a.create  [');
    expect(cmdConfirm(three, { ...base, verbs: ['acme.a.create'] }).text).not.toContain('acme.d.create');
  });
  const many = (n: number, union: string[]): string => defsToYaml('acme', Array.from({ length: n }, (_, i) => def(`acme.n${String(i).padStart(2, '0')}.create`, union)));
  const shown = (text: string): number => text.split('\n').filter((l) => /^acme\.n\d\d\.create {2}\[/.test(l)).length;

  it('a whole pack prints the first 40 defs and the count of the rest', () => {
    const r45 = cmdConfirm(many(45, []), { ...base, origin: 'any' });
    expect(shown(r45.text)).toBe(40);
    expect(r45.text.endsWith('\n... and 5 more (45 in all)\n(nothing signed: pass --yes with --reviewer-key to confirm)')).toBe(true);
    const r41 = cmdConfirm(many(41, []), { ...base, origin: 'any' });
    expect(shown(r41.text)).toBe(40);
    expect(r41.text).toContain('\n... and 1 more (41 in all)\n');
    const r40 = cmdConfirm(many(40, []), { ...base, origin: 'any' });
    expect(shown(r40.text)).toBe(40);
    expect(r40.text).not.toContain('more (');
  });
  it('only a whole pack is cut: a union selection or a verb list prints every def', () => {
    const u = cmdConfirm(many(45, ['pca.money_moving']), { ...base, origin: 'union' });
    expect(shown(u.text)).toBe(45);
    expect(u.text).not.toContain('more (');
    const verbs = Array.from({ length: 45 }, (_, i) => `acme.n${String(i).padStart(2, '0')}.create`);
    const v = cmdConfirm(many(45, []), { ...base, verbs });
    expect(shown(v.text)).toBe(45);
    expect(v.text).not.toContain('more (');
  });
  it('confirming a pack reports every def, though only 40 were shown', () => {
    const r = cmdConfirm(many(45, []), { ...base, origin: 'any', yes: true, secret: sk() });
    expect(r.ok, r.text).toBe(true);
    expect(r.text).toBe('45 confirmed by rev-1 (the attestation is valid only against the reviewer keys your registry pins)');
    expect(loadActionsText(r.yaml).defs.filter((d) => d.review.state === 'confirmed')).toHaveLength(45);
  });
  it('dismissing one trait keeps the others and records the reason, which may itself contain "="', () => {
    const r = cmdConfirm(three, { ...base, yes: true, secret: sk(), origin: 'union', dismiss: ['pca.money_moving=lookup only = no payment'] });
    expect(r.ok, r.text).toBe(true);
    const d = loadActionsText(r.yaml).defs.find((x) => x.verb === 'acme.d.create')!;
    expect(d.review.state).toBe('confirmed');
    expect(d.traits).toContain('pca.destructive');
    expect(d.traits ?? []).not.toContain('pca.money_moving');
    expect(d.review.attestation?.dismissed).toEqual([{ trait: 'pca.money_moving', reason: 'lookup only = no payment' }]);
    const a = loadActionsText(r.yaml).defs.find((x) => x.verb === 'acme.a.create')!;
    expect(a.traits ?? []).not.toContain('pca.money_moving');
    expect(loadActionsText(r.yaml).defs.find((x) => x.verb === 'acme.c.create')!.review.state).toBe('authored');
  });
  it('--final replaces the traits', () => {
    const r = cmdConfirm(three, { ...base, yes: true, secret: sk(), verbs: ['acme.d.create'], final: ['pca.destructive'], dismiss: ['pca.money_moving=not a payment'] });
    expect(r.ok, r.text).toBe(true);
    const d = loadActionsText(r.yaml).defs.find((x) => x.verb === 'acme.d.create')!;
    expect(d.traits).toEqual(['pca.destructive']);
  });
  it('a refused confirmation returns the reason and no yaml', () => {
    const r = cmdConfirm(three, { ...base, yes: true, secret: sk(), origin: 'union', trait: 'money_moving', final: [] });
    expect(r.ok).toBe(false);
    expect(r.yaml).toBe('');
    expect(Object.keys(r).sort()).toEqual(['ok', 'text', 'yaml']);
    expect(r.text.length).toBeGreaterThan(0);
  });
  it('a document without a namespace is written back under "ns"; the success text names the count and the reviewer', () => {
    const raw = JSON.stringify(def('acme.a.create', ['pca.money_moving']));
    expect(loadActionsText(raw).ns).toBeUndefined();
    const r = cmdConfirm(raw, { ...base, kid: 'k-9', yes: true, secret: sk(), verbs: ['acme.a.create'] });
    expect(r.ok, r.text).toBe(true);
    expect(r.text).toBe('1 confirmed by k-9 (the attestation is valid only against the reviewer keys your registry pins)');
    expect(r.rulesReviews).toEqual({});
    expect(loadActionsText(r.yaml).ns).toBe('ns');
  });
  it('the business rules of the confirmed actions are signed too and counted', () => {
    const hello = ACTION_TEMPLATES.minimal!('acme').replace(/\n    examples:\n/, '\n    rules:\n      required: [note]\n    examples:\n');
    const r = cmdConfirm(hello, { ...base, verbs: ['acme.invoice.send'], yes: true, secret: sk() });
    expect(r.ok, r.text).toBe(true);
    expect(r.text).toBe('1 confirmed by rev-1 (and the business rules of 1) (the attestation is valid only against the reviewer keys your registry pins)');
    expect(Object.keys(r.rulesReviews!)).toEqual(['acme.invoice.send']);
    expect(loadActionsText(r.yaml).ns).toBe('acme');
    expect(loadActionsText(r.yaml).rules['acme.invoice.send']).toEqual({ required: ['note'] });
  });
});
