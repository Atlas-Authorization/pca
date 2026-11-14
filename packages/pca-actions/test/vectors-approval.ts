// vectors-approval.ts - shared vectors for what-you-see-is-what-you-sign approvals (K7): the canonical render of an action, its digest,
// the approval challenge, the PSD2 linking view, a batch commitment, and escalation answers bound to a render. Every expectation is
// computed by the TypeScript reference; the natives must reproduce it byte for byte. Keys derive from fixed labels (Ed25519 is
// deterministic) so the files are reproducible.
import {
  approvalChallengeB64u, approvalRenderDigest, approvalRenderShapeError, bindingWords, b64u, publicKeyOf, sha256, signEscalationAnswer, utf8, verifyEscalationAnswer,
  type ApprovalRender, type EscalationAnswerBody,
} from '@atlasauth/pca';
import { ActionKitError, approvalBatch, psd2Linking, renderApproval, validateDef, type ActionDef } from '../src';

export interface ACase { id: string; kind: string; input: unknown; expect: unknown }
export const APPROVAL_KINDS: readonly string[] = ['approval_render', 'approval_digest', 'approval_challenge', 'approval_escalation'];
/** The profile vectors (PSD2 linking, batch) live in their own directory: the TypeScript reference, Python, Go, Ruby and PHP replay them. */
export const APPROVAL_PROFILE_KINDS: readonly string[] = ['approval_psd2', 'approval_batch'];

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const seed = (l: string) => sha256(utf8(`atlas-pca-vectors/approval/${l}`));
const PRINCIPAL = seed('principal');
const OTHER = seed('other-principal');
const dg = (c: string) => b64u(new Uint8Array(32).fill(c.charCodeAt(0)));

/** A payment verb: amount in minor units with the currency taken from a sibling parameter, a payee, an optional memo. */
export const TRANSFER: ActionDef = {
  v: 1, kind: 'pca-action-def', verb: 'bank.transfer.send', title: 'Send a transfer', description: 'Sends money to a payee.',
  effects: ['pay'], resource: { type: 'bank.account', id: '*', scope: 'one' },
  params: {
    amount: { type: 'integer', min: 1, max: 100_000_000, role: 'money.amount', unit: { kind: 'money', ccy: { from: 'currency' }, exp: 2 } },
    currency: { type: 'string', role: 'money.currency', format: 'iso_currency' },
    payee: { type: 'string', role: 'party.payee', max_len: 64 },
    memo: { type: 'string', max_len: 140, required: false },
  },
  reversibility: 'irreversible', idempotency: { mode: 'natural' },
  review: { state: 'authored' },
};
/** A verb with a fixed currency and a nested parameter. */
export const FIXED: ActionDef = {
  ...TRANSFER, verb: 'bank.transfer.eur',
  params: {
    amount: { type: 'integer', min: 1, max: 1_000_000, role: 'money.amount', unit: { kind: 'money', ccy: 'EUR', exp: 2 } },
    'to.iban': { type: 'string', role: 'party.payee', format: 'iban' },
    'to.name': { type: 'string', max_len: 64, required: false },
  },
};

type Out = { ok: true; [k: string]: unknown } | { ok: false; code: string };
const codeOfErr = (e: unknown): { ok: false; code: string } => ({ ok: false, code: e instanceof ActionKitError ? e.code : 'error' });

export function replayApproval(c: ACase): unknown {
  const i = c.input as Record<string, any>;
  switch (c.kind) {
    case 'approval_render': {
      try {
        const r = renderApproval(i.def, i.params, i.confirmed === true ? { attestationVerified: () => true } : {});
        const digest = approvalRenderDigest(r);
        return { ok: true, render: r, digest, words: bindingWords(digest) } satisfies Out;
      } catch (e) { return codeOfErr(e); }
    }
    case 'approval_digest': {
      const e = approvalRenderShapeError(i.render);
      if (e !== null) return { ok: false };
      return { ok: true, digest: approvalRenderDigest(i.render as ApprovalRender) };
    }
    case 'approval_challenge': {
      try { return { ok: true, challenge: approvalChallengeB64u(i.action_digest, i.render_digest) }; } catch { return { ok: false }; }
    }
    case 'approval_escalation': {
      const v = verifyEscalationAnswer(i.answer, i.principals, i.bind, i.now);
      return v.ok ? { ok: true, decision: v.decision } : { ok: false, reason: v.reason };
    }
    case 'approval_psd2': {
      try { return { ok: true, linking: psd2Linking(i.render) }; } catch (e) { return codeOfErr(e); }
    }
    case 'approval_batch': {
      try {
        const b = approvalBatch(i.items);
        return { ok: true, batch: b.batch, action_digest: b.action_digest, render_digest: b.render_digest, challenge: b64u(b.challenge), words: b.words };
      } catch (e) { return codeOfErr(e); }
    }
    default: throw new Error(`unknown approval vector kind ${c.kind}`);
  }
}

export function approvalCases(): ACase[] {
  const cases: ACase[] = [];
  const mk = (id: string, kind: string, input: unknown) => cases.push({ id, kind, input, expect: undefined });
  if (validateDef(TRANSFER) !== null || validateDef(FIXED) !== null) throw new Error(`approval vector defs invalid: ${validateDef(TRANSFER) ?? validateDef(FIXED)}`);
  const ok = { amount: 12_500, currency: 'EUR', payee: 'Acme GmbH' };
  const r = (id: string, def: ActionDef, params: unknown, confirmed = false) => mk(`approval-render-${id}`, 'approval_render', { def, params, confirmed });
  r('transfer', TRANSFER, ok);
  r('transfer-confirmed', TRANSFER, ok, true);
  r('transfer-memo', TRANSFER, { ...ok, memo: 'Invoice 2026-10' });
  r('transfer-key-order', TRANSFER, { payee: 'Acme GmbH', currency: 'EUR', amount: 12_500 });
  r('transfer-unicode', TRANSFER, { ...ok, payee: 'Zoë ‮evil' });
  r('transfer-usd', TRANSFER, { amount: 1, currency: 'USD', payee: 'x' });
  r('fixed-nested', FIXED, { amount: 100, to: { iban: 'DE89370400440532013000', name: 'Acme' } });
  r('fixed-confirmed', FIXED, { amount: 100, to: { iban: 'DE89370400440532013000' } }, true);
  r('adv-undeclared-param', TRANSFER, { ...ok, hidden: 'x' });
  r('adv-undeclared-nested', TRANSFER, { ...ok, memo: 'm', extra: { deep: 1 } });
  r('adv-missing-required', TRANSFER, { amount: 5, currency: 'EUR' });
  r('adv-currency-not-string', TRANSFER, { amount: 5, currency: 7, payee: 'x' });
  r('adv-params-array', TRANSFER, [ok]);
  r('adv-dotted-key', FIXED, { amount: 100, 'to.iban': 'DE89370400440532013000' });
  r('adv-null-value', TRANSFER, { ...ok, memo: null });
  r('adv-wrong-type', TRANSFER, { ...ok, payee: 7 });
  r('adv-lone-surrogate', TRANSFER, { ...ok, payee: 'x\ud800' });
  r('fixed-empty-object-leaf', FIXED, { amount: 1, 'to': { iban: 'DE89370400440532013000', name: 'A' } });
  r('adv-float-amount', TRANSFER, { ...ok, amount: 1.5 });
  r('adv-amount-unsafe', TRANSFER, { ...ok, amount: 2 ** 60 });
  // digest of a render object: shape errors are refused
  const base = renderApproval(TRANSFER, ok);
  const dm = (id: string, render: unknown) => mk(`approval-digest-${id}`, 'approval_digest', { render });
  dm('valid', base);
  dm('unreviewed-false', renderApproval(TRANSFER, ok, { attestationVerified: () => true }));
  const mut = (id: string, f: (x: Record<string, any>) => void) => { const x = clone(base) as unknown as Record<string, any>; f(x); dm(id, x); };
  mut('adv-extra-member', (x) => { x.note = 'friendly copy'; });
  mut('adv-missing-unreviewed', (x) => { delete x.unreviewed; });
  mut('adv-unsorted-fields', (x) => { x.fields.reverse(); });
  mut('adv-duplicate-field', (x) => { x.fields.push(clone(x.fields[0])); });
  mut('adv-bad-kind', (x) => { x.kind = 'other'; });
  mut('adv-field-extra', (x) => { x.fields[0].label = 'Amount'; });
  mut('adv-bad-def-digest', (x) => { x.def_digest = 'short'; });
  mut('adv-unit-unknown', (x) => { x.fields[0].unit = { kind: 'parsecs' }; });
  mut('adv-fields-not-array', (x) => { x.fields = {}; });
  // challenge
  const ch = (id: string, a: unknown, rd: unknown) => mk(`approval-challenge-${id}`, 'approval_challenge', { action_digest: a, render_digest: rd });
  ch('basic', dg('a'), dg('r'));
  ch('swap', dg('r'), dg('a'));
  ch('real', dg('b'), approvalRenderDigest(base));
  ch('short-action', 'AAAA', dg('r'));
  ch('short-render', dg('a'), 'AAAA');
  ch('non-canonical', dg('a') + '=', dg('r'));
  ch('not-string', 7, dg('r'));
  ch('zero-digests', b64u(new Uint8Array(32)), b64u(new Uint8Array(32)));
  // escalation answers bound to a render
  const rd = approvalRenderDigest(base);
  const bind = { policy_digest: dg('p'), action_digest: dg('a'), history_head: dg('h') };
  const pk = b64u(publicKeyOf(PRINCIPAL));
  const body = (extra: Partial<EscalationAnswerBody> = {}): EscalationAnswerBody => ({
    v: 1, kind: 'pca-escalation-answer', principal: pk, ...bind, decision: 'allow', iat: 1_800_000_000_000, expires_at: 1_800_000_300_000, nonce: b64u(new Uint8Array(16).fill(7)), ...extra,
  });
  const NOW = 1_800_000_100_000;
  const es = (id: string, answer: unknown, b: Record<string, unknown>, now = NOW, principals: unknown = [pk]) => mk(`approval-escalation-${id}`, 'approval_escalation', { answer, principals, bind: b, now });
  es('bound-ok', signEscalationAnswer(body({ render_digest: rd }), PRINCIPAL), { ...bind, render_digest: rd });
  es('unbound-ok', signEscalationAnswer(body(), PRINCIPAL), bind);
  es('adv-answer-without-render', signEscalationAnswer(body(), PRINCIPAL), { ...bind, render_digest: rd });
  es('adv-render-not-checked', signEscalationAnswer(body({ render_digest: rd }), PRINCIPAL), bind);
  es('adv-other-render', signEscalationAnswer(body({ render_digest: dg('z') }), PRINCIPAL), { ...bind, render_digest: rd });
  es('adv-bad-render-digest', { ...signEscalationAnswer(body({ render_digest: rd }), PRINCIPAL), render_digest: 'short' }, { ...bind, render_digest: rd });
  es('adv-render-digest-swapped-after-signing', { ...signEscalationAnswer(body({ render_digest: dg('z') }), PRINCIPAL), render_digest: rd }, { ...bind, render_digest: rd });
  es('adv-other-principal', signEscalationAnswer(body({ principal: b64u(publicKeyOf(OTHER)), render_digest: rd }), OTHER), { ...bind, render_digest: rd });
  es('adv-expired', signEscalationAnswer(body({ render_digest: rd }), PRINCIPAL), { ...bind, render_digest: rd }, 1_800_000_400_000);
  es('deny-bound', signEscalationAnswer(body({ decision: 'deny', render_digest: rd }), PRINCIPAL), { ...bind, render_digest: rd });
  return cases;
}

export function approvalProfileCases(): ACase[] {
  const cases: ACase[] = [];
  const mk = (id: string, kind: string, input: unknown) => cases.push({ id, kind, input, expect: undefined });
  const ok = { amount: 12_500, currency: 'EUR', payee: 'Acme GmbH' };
  const dg = (c: string) => b64u(new Uint8Array(32).fill(c.charCodeAt(0)));
  // PSD2 linking
  const p2 = (id: string, render: unknown) => mk(`approval-psd2-${id}`, 'approval_psd2', { render });
  p2('transfer-confirmed', renderApproval(TRANSFER, ok, { attestationVerified: () => true }));
  p2('fixed-confirmed', renderApproval(FIXED, { amount: 100, to: { iban: 'DE89370400440532013000' } }, { attestationVerified: () => true }));
  p2('adv-unreviewed', renderApproval(TRANSFER, ok));
  p2('adv-no-payee', renderApproval({ ...TRANSFER, params: { amount: TRANSFER.params.amount!, currency: TRANSFER.params.currency! } }, { amount: 5, currency: 'EUR' }, { attestationVerified: () => true }));
  p2('adv-no-amount', renderApproval({ ...TRANSFER, params: { payee: TRANSFER.params.payee! } }, { payee: 'x' }, { attestationVerified: () => true }));
  // batch
  const conf = { attestationVerified: () => true };
  const item = (params: Record<string, unknown>, a: string, def: ActionDef = TRANSFER) => ({ action_digest: dg(a), render: renderApproval(def, params, conf) });
  const bt = (id: string, items: unknown) => mk(`approval-batch-${id}`, 'approval_batch', { items });
  bt('two-payees', [item({ amount: 1000, currency: 'EUR', payee: 'A' }, 'a'), item({ amount: 250, currency: 'EUR', payee: 'B' }, 'b')]);
  bt('same-payee-twice', [item({ amount: 1000, currency: 'EUR', payee: 'A' }, 'a'), item({ amount: 250, currency: 'EUR', payee: 'A' }, 'b')]);
  bt('two-currencies', [item({ amount: 1000, currency: 'EUR', payee: 'A' }, 'a'), item({ amount: 250, currency: 'USD', payee: 'B' }, 'b')]);
  bt('single', [item({ amount: 5, currency: 'EUR', payee: 'A' }, 'a')]);
  bt('adv-empty', []);
  bt('adv-unreviewed-item', [item({ amount: 5, currency: 'EUR', payee: 'A' }, 'a'), { action_digest: dg('b'), render: renderApproval(TRANSFER, { amount: 5, currency: 'EUR', payee: 'B' }) }]);
  bt('adv-overflow', [item({ amount: 100_000_000, currency: 'EUR', payee: 'A' }, 'a', { ...TRANSFER, params: { ...TRANSFER.params, amount: { ...TRANSFER.params.amount!, max: 2 ** 53 - 2 } } }), item({ amount: 2 ** 53 - 2, currency: 'EUR', payee: 'B' }, 'b', { ...TRANSFER, params: { ...TRANSFER.params, amount: { ...TRANSFER.params.amount!, max: 2 ** 53 - 2 } } })]);
  bt('adv-two-exponents', [item({ amount: 5, currency: 'EUR', payee: 'A' }, 'a'), item({ amount: 5, currency: 'EUR', payee: 'B' }, 'b', { ...TRANSFER, params: { ...TRANSFER.params, amount: { ...TRANSFER.params.amount!, unit: { kind: 'money', ccy: { from: 'currency' }, exp: 3 } } } })]);
  return cases;
}
