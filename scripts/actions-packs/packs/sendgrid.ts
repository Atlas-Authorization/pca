import { openApiPack } from '../lib/factory';

const SEND = /^sendgrid\.(create_mail_send|post_mail_send|create_(single_send_schedule|schedule_single_send)|schedule_single_send|send_test\w*|create_send_test\w*|create_scheduled_send|create_schedule)\w*$/;

export default openApiPack({
  name: 'sendgrid',
  ns: 'sendgrid',
  redistribution: 'permitted',
  licence_notes: 'Twilio SendGrid publishes its OpenAPI descriptions (twilio/sendgrid-oai) under the MIT licence. Operation ids, parameter names/types/bounds and short summaries are carried; the trait review is ours.',
  config_file: __filename,
  ops: (id, ops) => ops.map((o) => ({ ...o, bindings: { openapi: { ...o.bindings!.openapi!, operationId: `${id}:${o.opId}` } } })),
  oa: () => ({ naming: 'opid', flatten: true }),
  build: () => ({
    ns: 'sendgrid',
    vendorTitles: true,
    rules: [
      { re: /^sendgrid\.(create_mail_send|send_mail|mail_send)$/, on: 'verb', patch: { effects: ['send'], rev: 'irreversible', recipient: 'personalizations' } },
      { re: /send_test/, on: 'verb', patch: { effects: ['send'], rev: 'irreversible', recipient: 'to' } },
      { re: /schedule_single_send|create_scheduled_send/, on: 'verb', patch: { effects: ['send'], rev: 'irreversible', recipient: 'send_at' } },
      { re: /^sendgrid\.update_api_key\w*$/, on: 'verb', patch: { effects: ['update', 'privilege'], rev: 'rate_limited', traits: ['pca.credential_access'] } },
      { re: /^sendgrid\.create_api_key$/, on: 'verb', patch: { effects: ['create', 'privilege'], rev: 'rate_limited', traits: ['pca.credential_access'] } },
      { re: /^sendgrid\.(export_\w+)$/, on: 'verb', patch: { effects: ['export'], rev: 'irreversible' } },
      { re: /^sendgrid\.delete_\w*(teammate|subuser|sso|scope)/, on: 'verb', patch: { effects: ['delete', 'privilege'], rev: 'irreversible' } },
      { re: /^sendgrid\.(?!get_|list_)\w*(teammate|subuser|sso|scope)/, on: 'verb', patch: { effects: ['privilege'], rev: 'rate_limited' } },
    ],
  }),
});
void SEND;
