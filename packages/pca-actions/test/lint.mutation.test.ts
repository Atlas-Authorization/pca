// lint.mutation.test.ts - exact messages, parameters, ordering and formatting of the lint output, rule by rule.
import { describe, expect, it, vi } from 'vitest';
import { CORE_REGISTRY, LINT_RULES, NOTE_RULE, STRUCTURE_RULE, defDigest, lintDefs, lintFails, lintText, p, toSarif, traitsDigest, type ActionDef, type Finding, type TraitDef } from '../src';
import { clean, d } from './lint-fixtures';

type Raw = Record<string, unknown>;
const ONE = { type: 'acme.invoice', id: { prefix: 'inv_', class: 'alnum', len: [8, 32] }, scope: 'one' };
const CH = { type: 'acme.charge', id: { prefix: 'ch_', class: 'alnum', len: [8, 32] }, scope: 'one' };
const o = (verb: string, patch: Raw = {}): Raw => d({ verb, resource: ONE, ...patch });
const withParams = (extra: Raw): Raw => ({ ...(clean().params as unknown as Raw), ...extra });
const ofRule = (fs: Finding[], rule: string): Finding[] => fs.filter((f) => f.rule === rule);
const msgs = (fs: Finding[], rule: string): string[] => ofRule(fs, rule).map((f) => f.message);
const upd = (patch: Raw = {}): Raw => d({ verb: 'acme.invoice.update', title: 'Update an invoice', effects: ['update'], ...patch });
const rd = (patch: Raw = {}): Raw => d({ verb: 'acme.invoice.get', title: 'Read an invoice', description: 'Reads an invoice.', effects: ['read'], params: { invoice: p.id('acme.invoice') }, ...patch });
const del = (patch: Raw = {}): Raw => d({
  verb: 'acme.invoice.delete', title: 'Delete an invoice', description: 'Deletes an invoice.', effects: ['delete'],
  params: { invoice: p.id('acme.invoice') }, examples: [{ params: { invoice: 'inv_12345678' }, expect: 'escalate' }], ...patch,
});
const pay = (extra: Raw = {}, patch: Raw = {}): Raw => d({
  verb: 'acme.charge.refund', title: 'Refund a charge', description: 'Returns money.', effects: ['pay'], resource: CH,
  params: { charge: p.id('acme.charge'), idempotency_key: { type: 'string', max_len: 64 }, ...extra },
  idempotency: { mode: 'key_param', param: 'idempotency_key' },
  examples: [{ params: { charge: 'ch_12345678', amount: 100, idempotency_key: 'k' }, expect: 'escalate' }], ...patch,
});
const att = (dismissed: { trait: string; reason: string }[] = []): Raw => ({ def_digest: 'AAAA', traits_digest: 'AAAA', facts_digest: 'AAAA', final_traits: [], dismissed, reviewer_kid: 'rev-1', ts: 1, sig: 'c2ln' });
const attested = (): Raw => {
  const base = d();
  return { ...base, review: { state: 'confirmed', attestation: { ...att(), def_digest: defDigest(base as unknown as ActionDef), traits_digest: traitsDigest(CORE_REGISTRY) } } };
};
const badTraits = [{ id: 'pca.destructive', implies: [], floor: {}, card_phrase: 'x' }] as unknown as TraitDef[];
const BAD_VERB = 'verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)';

describe('lint: structural and vocabulary findings carry exact text and the verb', () => {
  it('a value that is not an object is one LD-000 with no verb and no param member', () => {
    expect(lintDefs([null, 42])).toStrictEqual([
      { rule: 'LD-000', severity: 'error', message: 'def must be an object' },
      { rule: 'LD-000', severity: 'error', message: 'def must be an object' },
    ]);
  });
  it('a member that is missing or of the wrong shape is reported, not thrown', () => {
    const noEffects = d(); delete noEffects.effects;
    expect(lintDefs([noEffects])).toStrictEqual([{ rule: 'LD-000', severity: 'error', verb: 'acme.invoice.send', message: 'effects must be 1..12 distinct known effects' }]);
    const noParams = d(); delete noParams.params;
    expect(lintDefs([noParams])).toStrictEqual([{ rule: 'LD-000', severity: 'error', verb: 'acme.invoice.send', message: 'params must be an object' }]);
    const nullParam = d(); nullParam.params = { a: null };
    expect(lintDefs([nullParam])).toStrictEqual([{ rule: 'LD-000', severity: 'error', verb: 'acme.invoice.send', message: 'a: declaration must be an object' }]);
    expect(lintDefs([d({ traits: [5] })])).toStrictEqual([{ rule: 'LD-000', severity: 'error', verb: 'acme.invoice.send', message: 'traits must be distinct trait ids' }]);
  });
  it('a verb that is not a string is not reported as a verb', () => {
    expect(lintDefs([d({ verb: 5 })])).toStrictEqual([{ rule: 'LD-000', severity: 'error', message: BAD_VERB }]);
  });
  it('every vocabulary problem is an LD-007 with the verb and the exact text', () => {
    const fs = lintDefs([d({
      effects: ['teleport'], context: ['teleport'], traits: ['acme.nope'],
      params: withParams({ x: { type: 'string', role: 'party.nobody', max_len: 5 }, y: { type: 'string', format: 'zip', max_len: 5 } }),
    })]);
    const v = 'acme.invoice.send';
    const known = 'approval_ref, dry_run_first, fresh_revocation, idempotency, revocable, sandbox_attested';
    expect(fs).toStrictEqual([
      { rule: 'LD-007', severity: 'error', verb: v, message: `unknown context key 'teleport' (known: ${known}, session_taint_max:<level>)` },
      { rule: 'LD-007', severity: 'error', verb: v, message: "unknown effect 'teleport'" },
      { rule: 'LD-007', severity: 'error', verb: v, message: "unknown trait 'acme.nope'" },
      { rule: 'LD-007', severity: 'error', verb: v, message: "x: unknown role 'party.nobody'" },
      { rule: 'LD-007', severity: 'error', verb: v, message: "y: unknown format 'zip'" },
    ]);
  });
  it('an invalid custom trait set is an LD-007 without a verb', () => {
    expect(lintDefs([clean()], { customTraits: badTraits })).toStrictEqual([
      { rule: 'LD-007', severity: 'error', message: "invalid custom traits: custom trait 'pca.destructive' may not redefine a core trait" },
    ]);
  });
  it('the attestation verifier is asked about every def', () => {
    const v = vi.fn(() => true);
    lintDefs([clean()], { attestationVerified: v });
    expect(v).toHaveBeenCalled();
  });
});

describe('lint: pack-level rules', () => {
  it('LD-009: a repeated verb is reported once, and an alias taken by another def is named', () => {
    expect(lintDefs([clean(), clean()])).toStrictEqual([{ rule: 'LD-009', severity: 'error', verb: 'acme.invoice.send', message: "verb 'acme.invoice.send' is defined twice" }]);
    const fs = lintDefs([d({ aliases: ['acme.invoice.get'] }), rd({ resource: ONE })]);
    expect(ofRule(fs, 'LD-009')).toStrictEqual([{ rule: 'LD-009', severity: 'error', verb: 'acme.invoice.get', message: "'acme.invoice.get' is also a name of 'acme.invoice.send'" }]);
  });
  it('LD-014: every binding kind is keyed and named in the message', () => {
    const b = {
      mcp: { tool: 't1' }, openapi: { operationId: 'op1' }, http: { method: 'post', path: '/x' },
      graphql: { op: 'query', field: 'f' }, grpc: { service: 'S', method: 'm' }, asyncapi: { channel: 'ch', op: 'send' },
    };
    const fs = lintDefs([d({ bindings: b }), o('acme.invoice.send2', { bindings: b })]);
    const v = 'acme.invoice.send2';
    const own = "is also bound by 'acme.invoice.send'";
    expect(ofRule(fs, 'LD-014')).toStrictEqual([
      { rule: 'LD-014', severity: 'error', verb: v, message: `binding asyncapi:send ch ${own}` },
      { rule: 'LD-014', severity: 'error', verb: v, message: `binding graphql:query.f ${own}` },
      { rule: 'LD-014', severity: 'error', verb: v, message: `binding grpc:S/m ${own}` },
      { rule: 'LD-014', severity: 'error', verb: v, message: `binding http:POST /x ${own}` },
      { rule: 'LD-014', severity: 'error', verb: v, message: `binding mcp:t1 ${own}` },
      { rule: 'LD-014', severity: 'error', verb: v, message: `binding openapi:op1 ${own}` },
    ]);
  });
  it('LD-014: a repeated def does not collide with itself', () => {
    const b = { mcp: { tool: 't1' } };
    expect(ofRule(lintDefs([d({ bindings: b }), d({ bindings: b })]), 'LD-014')).toEqual([]);
  });
  it('LW-008: the majority prefix wins; the minority is named', () => {
    const run = (verbs: string[]): Finding[] => ofRule(lintDefs(verbs.map((v) => o(v))), 'LW-008');
    expect(run(['acme.invoice.create_draft', 'acme.invoice.new_copy', 'acme.invoice.new_final', 'acme.invoice.close'])).toStrictEqual([
      { rule: 'LW-008', severity: 'warning', verb: 'acme.invoice.create_draft', message: "uses 'create_' where its siblings use 'new_'" },
    ]);
    expect(run(['acme.invoice.remove_a', 'acme.invoice.remove_b', 'acme.invoice.delete_c'])).toStrictEqual([
      { rule: 'LW-008', severity: 'warning', verb: 'acme.invoice.delete_c', message: "uses 'delete_' where its siblings use 'remove_'" },
    ]);
  });
  it('LW-008: a tie goes to the prefix that sorts first, whatever the input order', () => {
    const want = [{ rule: 'LW-008', severity: 'warning', verb: 'acme.invoice.new_a', message: "uses 'new_' where its siblings use 'create_'" }];
    expect(ofRule(lintDefs([o('acme.invoice.new_a'), o('acme.invoice.create_b')]), 'LW-008')).toStrictEqual(want);
    expect(ofRule(lintDefs([o('acme.invoice.create_b'), o('acme.invoice.new_a')]), 'LW-008')).toStrictEqual(want);
  });
  it('LW-008: a verb outside the file namespace is named with both namespaces', () => {
    expect(ofRule(lintDefs([clean()], { ns: 'other' }), 'LW-008')).toStrictEqual([
      { rule: 'LW-008', severity: 'warning', verb: 'acme.invoice.send', message: "verb namespace 'acme' differs from the file namespace 'other'" },
    ]);
    expect(ofRule(lintDefs([clean()], { ns: 'acme' }), 'LW-008')).toEqual([]);
  });
});

describe('lint: error rules', () => {
  it('LD-001', () => {
    expect(msgs(lintDefs([d({ verb: 'acme.invoice.remove', effects: ['update'] })]), 'LD-001')).toEqual(["the verb says 'remove' but effects do not include delete"]);
  });
  it('LD-002: a money fee, or a money amount with a non-money unit, needs a currency', () => {
    const fee = lintDefs([pay({ fee: { type: 'integer', role: 'money.fee', min: 0, max: 100 } })]);
    expect(ofRule(fee, 'LD-002')).toStrictEqual([{ rule: 'LD-002', severity: 'error', verb: 'acme.charge.refund', param: 'fee', message: 'a money parameter needs a unit of kind money with a currency' }]);
    const count = lintDefs([pay({ amt: { type: 'integer', role: 'money.amount', min: 1, max: 9, unit: { kind: 'count' } } })]);
    expect(msgs(count, 'LD-002')).toEqual(['a money parameter needs a unit of kind money with a currency']);
  });
  it('LD-002: the named currency parameter needs both the role and the format', () => {
    const amt = { type: 'integer', role: 'money.amount', min: 1, max: 9, unit: { kind: 'money', ccy: { from: 'ccy' }, exp: 2 } };
    const wrongRole = lintDefs([pay({ amt, ccy: { type: 'string', format: 'iso_currency', max_len: 3 } })]);
    expect(ofRule(wrongRole, 'LD-002')).toStrictEqual([{ rule: 'LD-002', severity: 'error', verb: 'acme.charge.refund', param: 'amt', message: "the currency parameter 'ccy' needs role money.currency and format iso_currency" }]);
    const noFormat = lintDefs([pay({ amt, ccy: { type: 'string', role: 'money.currency', max_len: 3 } })]);
    expect(ofRule(noFormat, 'LD-002').map((f) => [f.param, f.message])).toEqual([
      ['amt', "the currency parameter 'ccy' needs role money.currency and format iso_currency"],
      ['ccy', 'a currency parameter needs the iso_currency format'],
    ]);
    expect(ofRule(lintDefs([pay({ amt, ccy: p.ccy() })]), 'LD-002')).toEqual([]);
  });
  it('LD-003: the message says which bound is missing; ids and bounded counts are exempt', () => {
    const fs = lintDefs([d({
      params: withParams({
        a_none: p.int(), b_min: { type: 'integer', min: 0 }, c_max: { type: 'integer', max: 9 }, d_dur: p.duration(), e_count: p.count(),
        f_ok: p.count(10), g_id: { type: 'integer', role: 'id.acme.thing' }, h_cnt: { type: 'integer', role: 'count.limit', max: 9 }, i_both: p.int(0, 10),
      }),
    })]);
    const m = (has: string): string => `a numeric parameter needs both min and max (has ${has})`;
    expect(ofRule(fs, 'LD-003').map((f) => [f.param, f.message])).toEqual([
      ['a_none', m('no min, no max')], ['b_min', m('min, no max')], ['c_max', m('no min, max')], ['d_dur', m('no min, no max')], ['e_count', m('min, no max')],
    ]);
  });
  it('LD-004: a money-moving trait alone, or a pay effect, needs idempotency', () => {
    const m = 'a money-moving action needs idempotency key_param or natural';
    expect(msgs(lintDefs([d({ effects: ['update'], traits: ['pca.money_moving'], idempotency: { mode: 'none' } })]), 'LD-004')).toEqual([m]);
    expect(msgs(lintDefs([pay({ amount: p.money('USD', { max: 100 }) }, { idempotency: { mode: 'none' } })]), 'LD-004')).toEqual([m]);
    expect(msgs(lintDefs([upd({ idempotency: { mode: 'none' } })]), 'LD-004')).toEqual([]);
  });
  it('LD-005: what can leave, by side effect or by verb, and which parameters carry it', () => {
    const sent = (names: string): string => `personal data can be sent (${names}) but effects do not include send`;
    const exported = (names: string): string => `personal data can be exported (${names}) but effects do not include export`;
    expect(msgs(lintDefs([upd({ side_effects: [{ target: 'customer.email', kind: 'send' }] })]), 'LD-005')).toEqual([sent('to')]);
    expect(msgs(lintDefs([upd({ side_effects: [{ target: 'customer.list', kind: 'export' }] })]), 'LD-005')).toEqual([exported('to')]);
    expect(msgs(lintDefs([upd({ side_effects: [{ target: 'customer.row', kind: 'create' }] })]), 'LD-005')).toEqual([]);
    expect(msgs(lintDefs([upd({ verb: 'acme.invoice.email_user' })]), 'LD-005')).toEqual([sent('to')]);
    expect(msgs(lintDefs([upd({ verb: 'acme.invoice.export_all' })]), 'LD-005')).toEqual([exported('to')]);
    expect(msgs(lintDefs([upd({ verb: 'acme.invoice.send_all', side_effects: [{ target: 'x', kind: 'export' }] })]), 'LD-005')).toEqual([exported('to'), sent('to')]);
    expect(msgs(lintDefs([upd({ verb: 'acme.invoice.email_user', params: withParams({ phone: p.phone() }) })]), 'LD-005')).toEqual([sent('phone, to')]);
  });
  it('LD-005: pii by tag, by contact role or by person role; other roles are not pii', () => {
    const v = (params: Raw): string[] => msgs(lintDefs([upd({ verb: 'acme.invoice.email_user', params: { invoice: p.id('acme.invoice'), ...params } })]), 'LD-005');
    const sent = (n: string): string => `personal data can be sent (${n}) but effects do not include send`;
    expect(v({ t: { type: 'string', tags: ['pii'], max_len: 50 } })).toEqual([sent('t')]);
    expect(v({ e: { type: 'string', role: 'contact.email', max_len: 50 } })).toEqual([sent('e')]);
    expect(v({ n: { type: 'string', role: 'person.name', max_len: 50 } })).toEqual([sent('n')]);
    expect(v({ m: { type: 'string', role: 'text.message', max_len: 50 } })).toEqual([]);
    expect(v({})).toEqual([]);
  });
  it('LD-005: parameter names are listed in plain string order, not integer-key order', () => {
    const fs = lintDefs([upd({ verb: 'acme.invoice.email_user', params: { invoice: p.id('acme.invoice'), 2: { type: 'string', tags: ['pii'], max_len: 5 }, 10: { type: 'string', tags: ['pii'], max_len: 5 } } })]);
    expect(msgs(fs, 'LD-005')).toEqual(['personal data can be sent (10, 2) but effects do not include send']);
  });
  it('LD-006: a declared reversibility or blast below the floor names both values', () => {
    const rev = lintDefs([del({ reversibility: 'reversible', compensates: 'acme.invoice.restore' })]);
    expect(msgs(rev, 'LD-006')).toHaveLength(1);
    expect(msgs(rev, 'LD-006')[0]).toMatch(/^declared reversibility reversible is below the floor [a-z_]+$/);
    const blast = lintDefs([pay({ amount: p.money('USD', { max: 100 }) }, { blast: { radius: 'one' } })]);
    expect(msgs(blast, 'LD-006')).toHaveLength(1);
    expect(msgs(blast, 'LD-006')[0]).toMatch(/^declared blast 50000 is below the floor \d+$/);
  });
  it('LD-008', () => {
    expect(msgs(lintDefs([d({ resource: { type: 'acme.invoice', id: '*', scope: 'one' } })]), 'LD-008')).toEqual(["resource id '*' with scope one names every resource at once"]);
  });
  it('LD-010: each way a reversible write can lack its undo has its own text', () => {
    const undoOf = (patch: Raw = {}): Raw => o('acme.invoice.undo', { title: 'Undo an invoice update', effects: ['update'], ...patch });
    expect(msgs(lintDefs([upd({ reversibility: 'reversible' })]), 'LD-010')).toEqual(['a write declared reversible must name its compensating action (compensates)']);
    expect(msgs(lintDefs([upd({ reversibility: 'reversible', compensates: 'acme.invoice.undo' })]), 'LD-010')).toEqual(["compensates 'acme.invoice.undo', which is not in the pack"]);
    expect(msgs(lintDefs([upd({ reversibility: 'reversible', compensates: 'acme.invoice.get' }), rd({ resource: ONE })]), 'LD-010')).toEqual([
      "compensates 'acme.invoice.get', which cannot undo it: the compensating action acme.invoice.get only reads",
    ]);
    expect(msgs(lintDefs([upd({ reversibility: 'reversible', compensates: 'acme.invoice.undo' }), undoOf({ params: withParams({ reason: p.text(50) }) })]), 'LD-010')).toEqual([
      "compensates 'acme.invoice.undo', which cannot undo it: the compensating action acme.invoice.undo needs 'reason', which neither the original call nor its result supplies",
    ]);
  });
  it('LD-011: each reason a confirmed review fails has its own text', () => {
    const r = (x: Raw, opts = {}): string[] => msgs(lintDefs([x], opts), 'LD-011');
    expect(r(d({ review: { state: 'confirmed' } }))).toEqual(['confirmed without an attestation']);
    expect(r({ ...attested(), title: 'Send another invoice' })).toEqual(['the attestation covers a different digest of this def']);
    const a = attested() as { review: { attestation: Raw } };
    a.review.attestation.traits_digest = 'AAAA';
    expect(r(a)).toEqual(['the attestation was made against a different trait registry']);
    const unsigned = attested() as { review: { attestation: Raw } };
    delete unsigned.review.attestation.sig;
    expect(r(unsigned)).toEqual(['the attestation is not signed by a pinned reviewer']);
    expect(r(attested())).toEqual([]);
  });
  it('LD-011: the verifier, when given, decides the signature', () => {
    expect(msgs(lintDefs([attested()], { attestationVerified: () => false }), 'LD-011')).toEqual(['the attestation is not signed by a pinned reviewer']);
    const unsigned = attested() as { review: { attestation: Raw } };
    delete unsigned.review.attestation.sig;
    expect(msgs(lintDefs([unsigned], { attestationVerified: () => true }), 'LD-011')).toEqual([]);
  });
  it('LD-011: a union-added trait leaves only with a signed dismissal, and only a confirmed review can sign one', () => {
    const union = ['pca.zzz', 'pca.aaa'];
    const text = (t: string): string => `the union-added trait ${t} was removed without a signed dismissal`;
    const review = (state: string): Raw => ({ state, provenance: { union }, attestation: att([{ trait: 'pca.aaa', reason: 'reviewed carefully' }]) });
    const union11 = (x: Raw): string[] => msgs(lintDefs([x]), 'LD-011').filter((m) => m.startsWith('the union-added'));
    expect(union11(d({ review: review('unreviewed') }))).toEqual([text('pca.aaa'), text('pca.zzz')]);
    expect(union11(d({ review: review('confirmed') }))).toEqual([text('pca.zzz')]);
  });
  it('LD-012: the structural rule is named; the three rules with their own finding are not repeated', () => {
    const fs = lintDefs([d({ params: { invoice: p.id('acme.invoice') } })]);
    expect(msgs(fs, 'LD-012')).toContain("structural rule recipient_param_declared is required by the action's traits and violated");
    const noCcy = lintDefs([pay({ amount: { type: 'integer', role: 'money.amount', min: 1, max: 100 } })]);
    expect(msgs(noCcy, 'LD-002')).toHaveLength(1);
    expect(msgs(noCcy, 'LD-012').join('\n')).not.toContain('money_has_currency');
    const unbounded = lintDefs([pay({ amount: p.money('USD') })]);
    expect(msgs(unbounded, 'LD-012').join('\n')).not.toContain('money_amount_bounded');
    const noKey = lintDefs([pay({ amount: p.money('USD', { max: 100 }) }, { idempotency: { mode: 'none' } })]);
    expect(msgs(noKey, 'LD-004')).toHaveLength(1);
    expect(msgs(noKey, 'LD-012').join('\n')).not.toContain('pay_has_idempotency');
  });
  it('LD-013: code, a query and a credential in a read-only action; nothing for a writing one', () => {
    const cmd = { type: 'string', role: 'code.command', max_len: 100 };
    const sql = { type: 'string', role: 'query.sql', max_len: 100 };
    const tok = { type: 'string', tags: ['credential', 'secret'], max_len: 50 };
    const code = 'a read-only action takes code or a query it cannot prove read-only (declare context sandbox_attested)';
    const fs = lintDefs([rd({ params: { invoice: p.id('acme.invoice'), c: cmd, q: sql, tok } })]);
    expect(ofRule(fs, 'LD-013').map((f) => [f.param, f.message])).toEqual([['c', code], ['q', code], ['tok', 'a read-only action handles a credential']]);
    const sandboxed = lintDefs([rd({ context: ['sandbox_attested'], params: { invoice: p.id('acme.invoice'), c: cmd, q: sql } })]);
    expect(ofRule(sandboxed, 'LD-013')).toEqual([]);
    expect(ofRule(lintDefs([d({ params: withParams({ c: cmd, tok }) })]), 'LD-013')).toEqual([]);
  });
});

describe('lint: warning rules', () => {
  it('LW-001: the description is missing, or longer than 400 bytes', () => {
    const none = d(); delete none.description;
    expect(msgs(lintDefs([none]), 'LW-001')).toEqual(['description is missing']);
    expect(msgs(lintDefs([d({ description: 'x'.repeat(400) })]), 'LW-001')).toEqual([]);
    expect(msgs(lintDefs([d({ description: 'x'.repeat(401) })]), 'LW-001')).toEqual(['description is longer than 400 bytes']);
  });
  it('LW-001: which first words make a title not imperative', () => {
    const flagged = ['Sending invoices', 'Created invoice', 'Sends an invoice', 'Disables a user', 'A new invoice', 'An invoice', 'The invoice'];
    for (const t of flagged) expect(msgs(lintDefs([d({ title: t })]), 'LW-001'), t).toEqual([`title '${t}' is not imperative`]);
    for (const t of ['Edit an invoice', 'Focus the view', 'Pass the token', 'Analysis report', 'Send an invoice']) expect(msgs(lintDefs([d({ title: t })]), 'LW-001'), t).toEqual([]);
  });
  it('LW-002, LW-006, LW-007: the parameter is named with the exact text', () => {
    const fs = lintDefs([d({ params: withParams({ s: { type: 'string' }, arr: p.array('string'), crit: { type: 'string', max_len: 9, sensitivity: 'critical' } }) })]);
    expect(ofRule(fs, 'LW-002').map((f) => [f.param, f.message])).toEqual([['s', 'a string parameter without max_len (the default is 1024; say it)']]);
    expect(ofRule(fs, 'LW-006').map((f) => [f.param, f.message])).toEqual([['arr', 'an array parameter without max_items']]);
    expect(ofRule(fs, 'LW-007').map((f) => [f.param, f.message])).toEqual([['crit', 'a critical parameter without provenance_min']]);
  });
  it('LW-003: free text only, by role and format; the message names the tag', () => {
    const fs = lintDefs([d({ params: withParams({ free: p.text(50), msg: { type: 'string', role: 'text.message', max_len: 100 }, ref: { type: 'string', format: 'uuid', max_len: 36 } }) })]);
    expect(ofRule(fs, 'LW-003').map((f) => [f.param, f.message])).toEqual([
      ['free', 'free text flows into an outbound action without tags: [free_text_outbound]'],
      ['msg', 'free text flows into an outbound action without tags: [free_text_outbound]'],
    ]);
  });
  it('LW-004: the state is named', () => {
    expect(msgs(lintDefs([d({ review: { state: 'unreviewed' } })], { stability: 'stable' }), 'LW-004')).toEqual(['a unreviewed def in a stable pack']);
    expect(msgs(lintDefs([d({ review: { state: 'suggested' } })], { stability: 'stable' }), 'LW-004')).toEqual(['a suggested def in a stable pack']);
  });
  it('LW-005: a reason is at least five characters once trimmed', () => {
    const x = d({
      review: { state: 'confirmed', attestation: att([{ trait: 'pca.bulk', reason: 'abcd' }, { trait: 'pca.destructive', reason: 'abcde' }, { trait: 'pca.irreversible', reason: '  ab  ' }]) },
    });
    expect(msgs(lintDefs([x]), 'LW-005')).toEqual(['dismissed trait pca.bulk has no reason', 'dismissed trait pca.irreversible has no reason']);
  });
  it('LW-009: a privilege-change trait alone needs an example', () => {
    expect(msgs(lintDefs([d({ traits: ['pca.privilege_change'] })]), 'LW-009')).toEqual(['no example for a money-moving, destructive or privilege-changing action']);
    expect(msgs(lintDefs([clean()]), 'LW-009')).toEqual([]);
  });
});

describe('lint: order of findings', () => {
  const key = (f: Finding): string[] => [f.verb ?? '', f.rule, f.param ?? '', f.message];
  const before = (a: string[], b: string[]): number => {
    for (let i = 0; i < 4; i++) { if (a[i]! < b[i]!) return -1; if (a[i]! > b[i]!) return 1; }
    return 0;
  };
  const sorted = (fs: Finding[]): boolean => fs.every((f, i) => i === 0 || before(key(fs[i - 1]!), key(f)) <= 0);

  it('one def: a pack-level warning comes after a per-def error of the same verb', () => {
    const fs = lintDefs([d({ verb: 'acme.invoice.remove', effects: ['update'] })], { ns: 'other' });
    expect(fs.map((f) => f.rule)).toContain('LD-001');
    expect(fs.map((f) => f.rule).indexOf('LD-001')).toBeLessThan(fs.map((f) => f.rule).indexOf('LW-008'));
    expect(sorted(fs)).toBe(true);
  });
  it('the verb decides before the rule', () => {
    const a = d({ verb: 'acme.invoice.aaa', since: undefined });
    const b = d({ verb: 'acme.invoice.remove_zzz' });
    const fs = lintDefs([a, b]);
    expect(fs.map((f) => [f.verb, f.rule])).toEqual([['acme.invoice.aaa', 'LW-010'], ['acme.invoice.remove_zzz', 'LD-001']]);
  });
  it('the parameter decides before the message, and unsorted emission is sorted', () => {
    const fs = lintDefs([d({ params: withParams({ zamt: { type: 'integer', role: 'money.amount', min: 1, max: 5 }, acc: { type: 'string', role: 'money.currency', max_len: 3 } }) })]);
    expect(ofRule(fs, 'LD-002').map((f) => f.param)).toEqual(['acc', 'zamt']);
    const amt = { type: 'integer', role: 'money.amount', min: 1, max: 9, unit: { kind: 'money', ccy: { from: 'ccy' }, exp: 2 } };
    const two = lintDefs([pay({ amt, ccy: { type: 'string', role: 'money.currency', max_len: 3 } })]);
    expect(ofRule(two, 'LD-002').map((f) => f.param)).toEqual(['amt', 'ccy']);
    expect(sorted(fs) && sorted(two)).toBe(true);
  });
  it('the message decides last', () => {
    const x = d({ review: { state: 'unreviewed', provenance: { union: ['pca.zzz', 'pca.aaa'] } } });
    expect(msgs(lintDefs([x]), 'LD-011')).toEqual([
      'the union-added trait pca.aaa was removed without a signed dismissal',
      'the union-added trait pca.zzz was removed without a signed dismissal',
    ]);
  });
  it('findings without a verb come first, and ties among them fall to rule and message', () => {
    // emitted: custom traits (LD-007), then the raw values in order
    expect(lintDefs([d({ verb: 'Acme.x' }), d({ verb: 5 })]).map((f) => f.verb)).toEqual([undefined, 'Acme.x']);
    expect(lintDefs([42, d({ verb: 5 })]).map((f) => f.message)).toEqual(['def must be an object', BAD_VERB]);
    expect(lintDefs([42], { customTraits: badTraits }).map((f) => f.rule)).toEqual(['LD-000', 'LD-007']);
    expect(lintDefs([d({ verb: 'Acme.x' })], { customTraits: badTraits }).map((f) => [f.verb, f.rule])).toEqual([[undefined, 'LD-007'], ['Acme.x', 'LD-000']]);
  });
});

describe('lintFails', () => {
  const f = (severity: Finding['severity']): Finding => ({ rule: 'LD-001', severity, message: 'm' });
  it('errors fail, warnings fail under strict only, notes never', () => {
    expect(lintFails([])).toBe(false);
    expect(lintFails([], true)).toBe(false);
    expect(lintFails([f('warning'), f('error')])).toBe(true);
    expect(lintFails([f('error')], false)).toBe(true);
    expect(lintFails([f('warning')])).toBe(false);
    expect(lintFails([f('warning')], true)).toBe(true);
    expect(lintFails([f('note')], true)).toBe(false);
  });
});

describe('lintText', () => {
  const fs: Finding[] = [
    { rule: 'LD-001', severity: 'error', verb: 'acme.a.b', param: 'p', message: 'm1', file: 'x.yaml', line: 3, column: 5 },
    { rule: 'LW-002', severity: 'warning', verb: 'acme.a.b', message: 'm2', file: 'x.yaml', line: 7 },
    { rule: 'LN-001', severity: 'note', message: 'm3', file: 'x.yaml' },
    { rule: 'LD-007', severity: 'error', param: 'q', message: 'm4' },
    { rule: 'LD-007', severity: 'error', message: 'm5' },
  ];
  it('formats every part of a line, and counts errors, warnings and notes', () => {
    expect(lintText(fs)).toBe([
      'error   LD-001  x.yaml:3:5: acme.a.b [p]: m1',
      'warning LW-002  x.yaml:7:1: acme.a.b: m2',
      'note    LN-001  x.yaml: m3',
      'error   LD-007   [q]: m4',
      'error   LD-007  m5',
      '3 errors, 1 warning, 1 note',
    ].join('\n'));
  });
  it('pluralises each count on its own', () => {
    const last = (xs: Finding[]): string => lintText(xs).split('\n').pop()!;
    const e = fs[0]!; const w = fs[1]!; const n = fs[2]!;
    expect(last([e])).toBe('1 error, 0 warnings');
    expect(last([w, w])).toBe('0 errors, 2 warnings');
    expect(last([e, w, n])).toBe('1 error, 1 warning, 1 note');
    expect(last([w, w, n, n])).toBe('0 errors, 2 warnings, 2 notes');
    expect(last([n, n])).toBe('0 errors, 0 warnings, 2 notes');
    expect(last([e, e, w, n, n, n])).toBe('2 errors, 1 warning, 3 notes');
  });
});

describe('toSarif', () => {
  it('describes every rule with its level, starting with the structure and note rules', () => {
    const s = toSarif([]) as any;
    expect(s.$schema).toBe('https://json.schemastore.org/sarif-2.1.0.json');
    expect(s.version).toBe('2.1.0');
    const driver = s.runs[0].tool.driver;
    expect(driver.name).toBe('pca actions lint');
    expect('version' in driver).toBe(false);
    expect(s.runs[0].results).toEqual([]);
    const level = (sev: string): string => (sev === 'error' ? 'error' : sev === 'warning' ? 'warning' : 'note');
    expect(driver.rules).toStrictEqual([STRUCTURE_RULE, NOTE_RULE, ...LINT_RULES].map((r) => ({ id: r.id, shortDescription: { text: r.title }, defaultConfiguration: { level: level(r.severity) } })));
    expect(driver.rules[0]).toStrictEqual({ id: 'LD-000', shortDescription: { text: 'the def is not well formed and cannot be loaded' }, defaultConfiguration: { level: 'error' } });
    expect(driver.rules[1].defaultConfiguration.level).toBe('note');
    expect(driver.rules.find((r: any) => r.id === 'LW-001').defaultConfiguration.level).toBe('warning');
  });
  it('takes the tool name and version when given', () => {
    const driver = (toSarif([], { name: 'mine', version: '1.2.3' }) as any).runs[0].tool.driver;
    expect(driver.name).toBe('mine');
    expect(driver.version).toBe('1.2.3');
  });
  it('a result has its level, message text and locations', () => {
    const s = toSarif([
      { rule: 'LD-001', severity: 'error', verb: 'acme.a.b', param: 'p', message: 'm', file: 'x.yaml', line: 3, column: 5 },
      { rule: 'LW-001', severity: 'warning', message: 'w' },
      { rule: 'LN-001', severity: 'note', verb: 'acme.a.b', message: 'n', file: 'y.yaml' },
      { rule: 'LW-002', severity: 'warning', message: 'c', file: 'z.yaml', line: 7 },
    ]) as any;
    expect(s.runs[0].results).toStrictEqual([
      {
        ruleId: 'LD-001', level: 'error', message: { text: 'acme.a.b [p]: m' },
        locations: [{ physicalLocation: { artifactLocation: { uri: 'x.yaml' }, region: { startLine: 3, startColumn: 5 } }, logicalLocations: [{ name: 'acme.a.b', kind: 'member' }] }],
      },
      { ruleId: 'LW-001', level: 'warning', message: { text: 'w' }, locations: [{}] },
      {
        ruleId: 'LN-001', level: 'note', message: { text: 'acme.a.b: n' },
        locations: [{ physicalLocation: { artifactLocation: { uri: 'y.yaml' } }, logicalLocations: [{ name: 'acme.a.b', kind: 'member' }] }],
      },
      { ruleId: 'LW-002', level: 'warning', message: { text: 'c' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'z.yaml' }, region: { startLine: 7, startColumn: 1 } } }] },
    ]);
  });
});
