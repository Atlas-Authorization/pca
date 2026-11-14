import { openApiPack } from '../lib/factory';

// Microsoft Graph v1.0: a curated slice (mail, calendar, files, Teams, users, groups, identity, devices). The full description reaches every
// resource through dozens of navigation paths; only the canonical top-level resources and their direct children are kept.
const TOP = '(users|groups|teams|chats|drives|sites|applications|servicePrincipals|devices|directoryRoles|domains|organization|contacts|planner|subscriptions|roleManagement)';
const GENERIC = new RegExp(`^/${TOP}(/\\{[^}/]+\\})?(/[A-Za-z]+(/\\{[^}/]+\\})?)?(/[A-Za-z.]+)?$`);
const INTUNE = /^\/deviceManagement\/(managedDevices|deviceCompliancePolicies|deviceConfigurations|detectedApps)(\/\{[^}/]+\})?(\/[A-Za-z.]+)?$/;
const INCLUDE = { test: (p: string) => GENERIC.test(p) || INTUNE.test(p) } as RegExp;

// Graph operation ids repeat the entity name after the collection (users.user.messages.message.send): drop the singular echo.
function dedupe(segs: string[]): string[] {
  const out: string[] = [];
  for (const s of segs.slice(0, -1)) {
    const prev = out[out.length - 1];
    if (prev && prev.endsWith('s') && s === prev.slice(0, -1)) continue;
    out.push(s);
  }
  return [...out, segs[segs.length - 1]!];
}

const DEV = 'device_management\\.managed_devices|users\\.managed_devices';
export default openApiPack({
  name: 'm365',
  ns: 'm365',
  redistribution: 'permitted',
  licence_notes: 'The Microsoft Graph OpenAPI description (microsoftgraph/msgraph-metadata) is MIT licensed. Operation ids, parameter names/types and short summaries are carried for a curated slice of the v1.0 surface; the trait review is ours.',
  config_file: __filename,
  oa: () => ({ naming: 'opid', flatten: true, include: INCLUDE, exclude: /\/\$|\/microsoft\.graph\.(?!.*(send|reply|forward|copy|move))/, rename: dedupe }),
  build: () => ({
    ns: 'm365',
    vendorTitles: true,
    rules: [
      { re: /^m365\.users\.send_mail$|^m365\.users\.user\.send_mail$/, on: 'verb', patch: { effects: ['send'], rev: 'irreversible', recipient: 'message' } },
      { re: /\.messages\.message\.(send|reply|reply_all|forward|create_reply|create_reply_all|create_forward)$|\.messages\.(send|reply|reply_all|forward)$/, on: 'verb', patch: { effects: ['send'], rev: 'irreversible', recipient: 'message_id' } },
      { re: /\.events\.event\.forward$/, on: 'verb', patch: { effects: ['send'], rev: 'irreversible', recipient: 'ToRecipients' } },
      { re: /\.send_activity_notification$/, on: 'verb', patch: { effects: ['send'], rev: 'irreversible', recipient: 'recipient' } },
      { re: /\.send_(appointment_reminder|virtual_appointment)_sms$/, on: 'verb', patch: { effects: ['send'], rev: 'irreversible', recipient: 'attendees' } },
      { re: /\.drive_item\.invite$/, on: 'verb', patch: { effects: ['send', 'privilege'], rev: 'irreversible', recipient: 'recipients' } },
      { re: /\.permissions\.(grant|revoke_grants)$/, on: 'verb', patch: { effects: ['privilege'], rev: 'rate_limited' } },
      { re: /\.revoke_sign_in_sessions$/, on: 'verb', patch: { effects: ['privilege'], rev: 'rate_limited' } },
      { re: new RegExp(`^m365\\.(${DEV})\\.(retire|clean_windows_device)$`), on: 'verb', patch: { effects: ['delete'], rev: 'irreversible' } },
      { re: new RegExp(`^m365\\.(${DEV})\\.(bypass_activation_lock|request_remote_assistance)$`), on: 'verb', patch: { effects: ['privilege'], rev: 'irreversible' } },
      { re: new RegExp(`^m365\\.(${DEV})\\.(windows_defender_scan|windows_update_signatures)$`), on: 'verb', patch: { effects: ['exec'], rev: 'irreversible' } },
      { re: new RegExp(`^m365\\.(${DEV})\\.(reboot_now|shut_down|remote_lock|logout_apple_device_active_user)$`), on: 'verb', patch: { effects: ['update'], rev: 'rate_limited' } },
      { re: new RegExp(`^m365\\.(${DEV})\\.(locate_device|recover_passcode)$`), on: 'verb', patch: { effects: ['read'], rev: 'reversible', traits: ['pca.credential_access'] } },
      { re: /\.cloud_p_cs\.cloud_pc\.(reboot|reprovision|resize|troubleshoot|end_grace_period)$/, on: 'verb', patch: { effects: ['update'], rev: 'rate_limited' } },
      { re: /\.(complete_migration|start_migration|retry_service_provisioning|reprocess_license_assignment|soft_delete|undo_soft_delete|unset_reaction|checkin|checkout|reauthorize|tentatively_accept|associate_with_hub_sites|provision_email)$/, on: 'verb', patch: { effects: ['update'], rev: 'rate_limited' } },
      { re: /\.(translate_exchange_ids|extract_sensitivity_labels)$/, on: 'verb', patch: { effects: ['read'], rev: 'reversible' } },
      { re: /\.synchronization\.acquire_access_token$/, on: 'verb', patch: { effects: ['read'], rev: 'reversible', traits: ['pca.credential_access'] } },
    ],
  }),
});
