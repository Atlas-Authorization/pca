// Oracle: approval-channels.ts (the approval-notification channel layer over a step-up request), TS reference.
// Written for the Java lane; reusable by any native. No keys, no clock: a request is plain data.
//
// PORTING (fn(args) -> native entry point; results compared by JSON value, a reference throw = the native throws):
//   actionSummary(request)                      -> string
//   lineageLines(request) / renderLines(request) -> string[]
//   buildSlackMessage(request, ctx)             -> the Block Kit message {text, blocks}
//   buildWebhookBody(request, ctx)              -> {type, stepup, summary, lineage, inbox_url?}
//   buildTextBody(request, ctx)                 -> {subject, text}
//   notify(kind, request, ctx, cfg)             -> one delivery {kind, requestId, delivered, payload, status?, reason?} through the channel of `kind`
//       (slack|webhook|email|sms|push) with cfg {configured: bool, transport: "ok"|"http500"|"throw"|"throw-empty", headers?}: the transport
//       answers 200 / 500 / throws Error("boom") / throws an Error with an empty message; a text channel's sender returns {id:"m1"} or throws.
//       Native: the same channel with a fake transport; the delivery's payload is compared in full. `url` is never part of the result.
//   notifyAll(request, ctx, cfgs[])             -> the deliveries of a dispatcher over the channels (disabled ones skipped)
import { Oracle, refWrite } from './lib.mjs';
const m: any = await import('../../../packages/pca/src/approval-channels.ts');

const o = new Oracle('core-approval-channels', 'tools/pca-audit/oracles/approval-channels.mts', 'TS-reference oracle for the approval-channel layer (payload builders, channels, dispatcher).');

const DIGEST = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const render = (unreviewed: boolean, fields: any[]) => ({ v: 1, kind: 'pca-approval-render', verb: 'payments.send', def_digest: 'A'.repeat(43), unreviewed, fields });
const lineage = (because: string, chain: any[]) => ({ because, chain });
const base = (over: any = {}) => ({
  id: 'su_1', verb: 'payments.send', resource: 'acct/1', tier: 3, reason: 'needs a human', goalCommit: 'gc', r: 0.455, requestedAt: 1,
  lineage: lineage('Because you asked to pay vendors', [{ label: 'goal', detail: 'pay vendors' }, { label: 'authority' }, { label: 'action', detail: '' }]), ...over,
});
const requests: [string, any][] = [
  ['plain', base()],
  ['tier2', base({ tier: 2, r: 0, verb: 'a.b', resource: 'x' })],
  ['risk-round', base({ r: 0.005 })],
  ['risk-round2', base({ r: 1 })],
  ['risk-big', base({ r: 12.345 })],
  ['unicode', base({ verb: 'ünï.cødé', resource: 'ac/ct☃', reason: 'raison “d’être”' })],
  ['markup', base({ resource: 'a`b*c_d', reason: '<b>*bold*</b> _it_' })],
  ['empty-chain', base({ lineage: lineage('Because', []) })],
  ['render-money', base({ render: render(false, [{ id: 'amount', class: 'money.amount', value: 1250, unit: { kind: 'money', ccy: 'USD', exp: 2 } }, { id: 'payee', class: 'party.payee', value: 'acme' }]), renderDigest: DIGEST })],
  ['render-unreviewed', base({ render: render(true, [{ id: 'note', class: 'param', value: 'a‮b\nc\u0007d​e' }, { id: 'obj', class: 'param', value: { z: [1, 2.5, null, true], a: 'x' } }]), renderDigest: DIGEST })],
  ['render-count', base({ render: render(false, [{ id: 'n', class: 'param', value: 3, unit: { kind: 'count' } }]), renderDigest: DIGEST })],
  ['render-no-digest', base({ render: render(false, [{ id: 'n', class: 'param', value: 3 }]) })],
];
const ctxs: [string, any][] = [['none', {}], ['inbox', { inboxUrl: 'https://x.example/inbox' }], ['inbox-q', { inboxUrl: 'https://x.example/inbox?a=1' }], ['inbox-frag', { inboxUrl: 'https://x.example/inbox?a=1#tok' }], ['inbox-empty', { inboxUrl: '' }], ['inbox-enc', { inboxUrl: 'https://x.example/i n' }]];
for (const [rn, r] of requests) {
  await o.run('actionSummary', rn, m.actionSummary, [r]);
  await o.run('lineageLines', rn, m.lineageLines, [r]);
  await o.run('renderLines', rn, m.renderLines, [r]);
  for (const [cn, c] of ctxs) {
    await o.run('buildSlackMessage', `${rn}-${cn}`, m.buildSlackMessage, [r, c]);
    await o.run('buildWebhookBody', `${rn}-${cn}`, m.buildWebhookBody, [r, c]);
    await o.run('buildTextBody', `${rn}-${cn}`, m.buildTextBody, [r, c]);
  }
}
for (const bad of [null, {}, { lineage: null }, base({ lineage: { chain: 'x' } }), base({ lineage: lineage('b', [null]) })]) {
  await o.run('lineageLines', 'bad-' + JSON.stringify(bad), m.lineageLines, [bad]);
}

const transport = (mode: string) => async (_u: string, _i: any) => {
  if (mode === 'ok') return { ok: true, status: 200 };
  if (mode === 'http500') return { ok: false, status: 500 };
  if (mode === 'throw') throw new Error('boom');
  throw new Error('');
};
const channel = (kind: string, cfg: any) => {
  const sender = cfg.transport === 'ok' ? async () => ({ id: 'm1' }) : async () => { throw cfg.transport === 'throw-empty' ? new Error('') : new Error('boom'); };
  if (kind === 'slack') return m.slackApprovalChannel({ ...(cfg.configured ? { webhookUrl: 'https://hooks.example/secret' } : {}), fetch: transport(cfg.transport) });
  if (kind === 'webhook') return m.webhookApprovalChannel({ ...(cfg.configured ? { url: 'https://hooks.example/secret' } : {}), fetch: transport(cfg.transport), ...(cfg.headers ? { headers: cfg.headers } : {}) });
  return m.textApprovalChannel(kind, cfg.configured ? { send: sender } : {});
};
const notify = async (kind: string, request: any, ctx: any, cfg: any) => channel(kind, cfg).notify(request, ctx);
for (const kind of ['slack', 'webhook', 'email', 'sms', 'push']) for (const configured of [true, false]) for (const t of ['ok', 'http500', 'throw', 'throw-empty']) {
  if (!configured && t !== 'ok') continue;
  for (const [rn, r] of requests.filter((_, i) => i % 4 === 0)) for (const [cn, c] of ctxs.filter((_, i) => i % 3 === 0)) {
    await o.run('notify', `${kind}-${configured}-${t}-${rn}-${cn}`, notify, [kind, r, c, { configured, transport: t }]);
  }
}
await o.run('notify', 'webhook-headers', notify, ['webhook', requests[0][1], ctxs[1][1], { configured: true, transport: 'ok', headers: { 'x-sig': 'abc' } }]);
const notifyAll = async (request: any, ctx: any, cfgs: any[]) => m.createApprovalDispatcher(cfgs.map((c) => channel(c.kind, c))).notifyAll(request, ctx);
await o.run('notifyAll', 'mixed', notifyAll, [requests[0][1], ctxs[1][1], [{ kind: 'slack', configured: true, transport: 'ok' }, { kind: 'email', configured: false, transport: 'ok' }, { kind: 'webhook', configured: true, transport: 'http500' }, { kind: 'sms', configured: true, transport: 'throw' }]]);
await o.run('notifyAll', 'none', notifyAll, [requests[0][1], ctxs[0][1], []]);
await o.run('notifyAll', 'all-disabled', notifyAll, [requests[1][1], ctxs[0][1], [{ kind: 'slack', configured: false, transport: 'ok' }, { kind: 'push', configured: false, transport: 'ok' }]]);
refWrite(o, 'core-approval-channels');
