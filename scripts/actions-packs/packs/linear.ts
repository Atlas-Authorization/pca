import { graphqlPack } from '../lib/factory';

export default graphqlPack({
  name: 'linear',
  ns: 'linear',
  redistribution: 'permitted',
  licence_notes: 'The Linear GraphQL schema is published in linear/linear under the MIT licence. Field names, argument names/types and the first sentence of a field description are carried; the trait review is ours.',
  config_file: __filename,
  gql: () => ({}),
  build: () => ({
    ns: 'linear',
    vendorTitles: true,
    rules: [
      { re: /^linear\.(file_upload_dangerously|time_schedule)\.delete$/, on: 'verb', patch: { effects: ['delete'], rev: 'irreversible' } },
      { re: /^linear\.(\w+_)?(share|unshare|update_general_access|collaborator_role|change_role|revoke_session|revoke_all_sessions|logout\w*|unlink_identity_provider|external_user_disconnect)$/, on: 'verb', patch: { effects: ['privilege'], rev: 'rate_limited' } },
      { re: /^linear\.(user_|organization_invite|organization_domain|team_membership|integration|oauth|api_key|personal_access|user_settings)\w*\.(create|update|add|remove|suspend|unsuspend|promote|demote)$/, on: 'verb', patch: { effects: ['privilege'], rev: 'rate_limited' } },
      { re: /^linear\.(user_|organization_invite|organization_domain|team_membership|integration|oauth|api_key|personal_access|user_settings)\w*\.delete$/, on: 'verb', patch: { effects: ['delete', 'privilege'], rev: 'irreversible' } },
      { re: /^linear\.organization\.(delete|cancel_delete)$|^linear\.organization_delete\w*$/, on: 'verb', patch: { effects: ['delete'], rev: 'irreversible' } },
      { re: /rotate_secret|rotate_webhook_secret|email_intake_address_rotate/, on: 'verb', patch: { effects: ['update'], rev: 'irreversible', traits: ['pca.credential_access'] } },
      { re: /_auth$|passkey_login_\w+|_account_auth(_challenge)?$/, on: 'verb', patch: { effects: ['create'], rev: 'reversible', traits: ['pca.credential_access'] } },
      { re: /^linear\.attachment_link_\w+|_import_create_\w+|_import_process$|file_upload|image_upload_from_url|customer_need_create_attachment|agent_activity_create_prompt|agent_session_create_on_\w+|\.create$/, on: 'verb', patch: { effects: ['create'], rev: 'reversible' } },
      { re: /sync_to_slack|project_create_slack_channel/, on: 'verb', patch: { effects: ['publish'], rev: 'irreversible' } },
      { re: /resend_organization|\.resend$|email_refresh|send_queued|push_subscription_test/, on: 'verb', patch: { effects: ['send'], rev: 'irreversible', recipient: 'email' } },
      { re: /delete_queued|issue_delete_issue_release/, on: 'verb', patch: { effects: ['delete'], rev: 'irreversible' } },
      { re: /_(add|remove)_label$|_label_retire$|comment_(un)?resolve|issue_reminder|project_reassign_status|cycle_shift_all|cycle_start_upcoming|customer_(upsert|unsync)|external_sync_disable|time_(schedule|integration)\w*|_connect$|agent_(restart|update)\w*|origin_installation_cancel|partner_offer_redeem|join_organization_onboarding|issue_description_update_front|organization_domain_claim|document_\w+|notification_\w*_all|notification_subscriptions?(\.update(_2)?)?$|\.update(_2)?$|issue_solubility_prediction|project_channel_creation_failure/, on: 'verb', patch: { effects: ['update'], rev: 'rate_limited' } },
    ],
  }),
});
