import { openApiPack } from '../lib/factory';

// Reviewed Slack rules on the derived verb (first match wins).
const SEND = /^slack\.chat\.(post_message|post_ephemeral|schedule_message|me_message)$/;
const SEND_PRIV = /^slack\.(conversations\.(invite|invite_shared)|admin\.(users|conversations)\.invite)$/;
const UPDATE = /^slack\.chat\.(unfurl|update)$/;

export default openApiPack({
  name: 'slack',
  ns: 'slack',
  redistribution: 'permitted',
  licence_notes: 'The Slack Web API OpenAPI description (slackapi/slack-api-specs) is MIT licensed. Method names, parameter names/types and short summaries are carried; the auth token parameter is dropped (the platform supplies it); the trait review is ours.',
  config_file: __filename,
  oa: () => ({ naming: 'dotted', flatten: true, skipParams: /^token$/ }),
  build: () => ({
    ns: 'slack',
    vendorTitles: true,
    rules: [
      { re: SEND, on: 'verb', patch: { effects: ['send'], rev: 'irreversible' } },
      { re: SEND_PRIV, on: 'verb', patch: { effects: ['send', 'privilege'], rev: 'irreversible' } },
      { re: UPDATE, on: 'verb', patch: { effects: ['update'], rev: 'rate_limited' } },
      { re: /^slack\.(apps\.uninstall|calls\.end)$/, on: 'verb', patch: { effects: ['delete'], rev: 'irreversible' } },
      { re: /^slack\.(views\.(open|publish|push|update)|dialog\.open|workflows\.update_step|conversations\.join|dnd\.end_dnd|dnd\.end_snooze|reminders\.complete)$/, on: 'verb', patch: { effects: ['update'], rev: 'rate_limited' } },
      { re: /^slack\.files\.(remote\.share|shared_public_url)$/, on: 'verb', patch: { effects: ['publish'], rev: 'irreversible' } },
      { re: /^slack\.files\.revoke_public_url$/, on: 'verb', patch: { effects: ['update'], rev: 'rate_limited' } },
    ],
  }),
});
