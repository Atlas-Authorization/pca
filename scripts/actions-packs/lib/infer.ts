// infer.ts - noun- and parameter-aware trait inference shared by the generic classifier (generated packs) and the hand-written packs.
// WHY: the action-word table only looks at the verb of an operation, so `POST /exports`, `POST /chats/{id}/messages`, `PATCH /cronjobs/{name}`
// or a read of `/payment_intents/{id}` carried no export / send / exec / financial-read trait. The cross-check against the suggestion rules
// plus a blind adjudication of the disagreements (corpus/adjudication.tsv) showed those were real misses, not rule noise. Every rule here only
// ADDS a restriction. Rules that can break a required parameter rule (export, send) are `soft`: the builder falls back to `unreviewed`.
import type { Effect } from '@atlasauth/pca-actions';

const set = (s: string): ReadonlySet<string> => new Set(s.split(/\s+/).filter(Boolean));
export const wordsOf = (...parts: string[]): Set<string> => {
  const out = new Set<string>();
  const add = (t: string): void => { out.add(t); out.add(t.endsWith('s') ? t.slice(0, -1) : `${t}s`); };
  for (const p of parts) {
    const ts = p.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
    ts.forEach((t, i) => { add(t); if (i > 0) add(`${ts[i - 1]}_${t}`); }); // adjacent pairs, so two-word nouns (run_command, trust_bundle) match
  }
  return out;
};
const any = (w: ReadonlySet<string>, s: ReadonlySet<string>): boolean => { for (const x of s) if (w.has(x)) return true; return false; };

const EXPORT_N = set('export exports takeout dump dumps');
const BACKUP_N = set('backup backups');
const EXPORT_DL = set('export exports snapshot snapshots archive archives artifacts artifact takeout dump tarball zipball');
const EXPORT_X = set('package packages import restore status schedule continuous run runs settings setting config configuration bucket destination policy list delete remove');
const MSG_N = set('message messages comment comments reply replies thread threads email emails sms mms notification notifications invitation invitations invite invites mention mentions announcement announcements whisper broadcast');
const MSG_X = set('template templates setting settings config configuration configurations rule rules policy policies filter filters label labels draft drafts subscription subscriptions webhook webhooks preference preferences schema type types category categories dashboard reaction reactions copy move attachment attachments extension extensions preview link links hosted_contents emails_on_push email_on_push pipelines_email service services integration integrations');
// parameter leaves are compared lower-cased with underscores removed
const MSG_P = set('sendactivation triggeremailverification verificationemail sendnotificationemail sendnotifications sendnotification emailmessage notify notifyusers notifymembers sendinvitation sendemail notificationmessage');
const EXEC_N = set('job jobs cronjob cronjobs daemonset daemonsets deployment deployments statefulset statefulsets replicaset replicasets pod pods build builds function functions lambda run_command run_commands runcommand runcommands codespace codespaces script scripts task_definition task_definitions');
const EXEC_X = set('schedule schedules variable variables secret secrets label labels tag tags permission permissions role roles policy policies alias aliases config configuration configurations setting settings artifact artifacts cache caches log logs event_source_mapping layer layers status approval approvals job_token scale patch_scale stop unarchive archive register sync generate resize preview podtemplate podtemplates autoscaler autoscalers scheduler request');
const FIN_N = set('payment payments charge charges invoice invoices balance balances transaction transactions payout payouts refund refunds treasury ledger statement statements bank cash receipt receipts billing tax taxes order orders expense expenses revenue payroll budget budgets cost costs credit_note credit_notes dispute disputes payment_record payment_records financial d_secure setup_intent setup_intents cardholder cardholders line_item line_items reserved_instance reserved_instances');
const FIN_X = set('alert alerts portal config configuration configurations setting settings webhook webhooks log logs logging meter meters shared draft disruption rate rates feedback link links copilot');
const SCHED_X = set('iam test_iam iam_policy variable variables');
const SCHED_N = set('schedule schedules scheduled cron cronjob cronjobs recurring timer timers reminder reminders snooze event_window event_windows maintenance_window maintenance_windows');
const PRIV_N = set('participant participants delegate delegates local_user local_users trust_bundle trust_bundles trustbundle trustbundles classification classifications registration_token registration_tokens principal principals access_control runner_group runner_groups protect protection identity_credentials master_auth teacher teachers credential_list credential_lists ssh_public_key ssh_public_keys authorized_key authorized_keys');
const PRIV_P = set('permission permissions accesslevel privilege privileges isadmin grantee principal principals');
// credential material in any operation (read or write): signed callback URLs, cluster master auth, generated secrets, state files
const CRED_ANY = set('master_auth callback_url callback_urls signed_url random_password random_string random_id');
// fail-strict breadth, widened after the residual-sample rounds: identity/authentication/certificate nouns are access changes on any write
const AUTH_N = set('auth authentication authorization user_cred user_creds creds token_auth based_auth ssl_cert ssl_certs certificate certificates cert certs identity identities iam sso saml oidc login common_instance_metadata endpoint_connection endpoint_connections private_endpoint installed_app installed_apps app_installation trust federated protected_branch protected_branches security_rule security_rules snapshot_attribute snapshot_attributes image_attribute image_attributes selected_repos selected_repositories selected_repo join');
const CRED_BROAD = set('key keys token tokens secret secrets password passwords credential credentials cred creds cert certs certificate certificates login login_link login_links signed sas connection_string access_key access_keys hybrid_connection hybrid_connections storage_accounts smime app_settings connection_details connection_info config_get auth_methods authentication');
const DESTR_A = set('rebase seek reimage commit replace reset rebuild rollback restore overwrite format wipe flush truncate');
const FIN_CATALOG = set('offerings pricing price prices quote quotes');
const REVOKE = set('revoke deauthorize invalidate expire');
const CRED_N = set('token tokens key keys credential credentials secret secrets certificate certificates');
const RESTORE_X = set('recycle_bin trash tier');
const RESTORE_N = set('backup backups snapshot snapshots blob_ranges from_backup');
const CANCELISH = set('cancel void recall abort terminate');

export interface Inferred { effects: Effect[]; traits: string[]; soft: boolean; why: string[] }

/** `words`: tokens of the operation's path / verb / tags; `leaves`: parameter leaf names; `action`: first token of the action. */
export function infer(words: ReadonlySet<string>, effects: readonly Effect[], leaves: readonly string[], action: string): Inferred {
  const out: Inferred = { effects: [], traits: [], soft: false, why: [] };
  const has = (e: Effect): boolean => effects.includes(e);
  const read = effects.every((e) => e === 'read');
  const plain = effects.every((e) => e === 'create' || e === 'update' || e === 'provision');
  const noDelete = !read && !has('delete');
  const addE = (e: Effect, why: string, soft = false): void => { if (!has(e) && !out.effects.includes(e)) { out.effects.push(e); out.soft ||= soft; out.why.push(why); } };
  const addT = (t: string, why: string): void => { if (!out.traits.includes(t)) { out.traits.push(t); out.why.push(why); } };
  const lp = leaves.map((l) => l.toLowerCase().replace(/_/g, ''));
  const dl = words.has('download');
  if (((plain && (any(words, EXPORT_N) || (action === 'create' && any(words, BACKUP_N)))) || (read && dl && any(words, EXPORT_DL))) && !any(words, EXPORT_X)) addE('export', 'export/backup noun', true);
  if ((plain || has('publish')) && ((any(words, MSG_N) && !any(words, MSG_X)) || lp.some((l) => MSG_P.has(l)))) addE('send', 'message noun or notify parameter', true);
  if (plain && any(words, EXEC_N) && !any(words, EXEC_X)) addE('exec', 'workload/job/build/function noun');
  if (read && any(words, FIN_N) && !any(words, FIN_X)) addT('pca.financial_data_read', 'financial noun on a read');
  if (noDelete && any(words, SCHED_N) && !any(words, SCHED_X)) addT('pca.scheduled', 'schedule/recurring noun on a write');
  if (!read && (any(words, PRIV_N) || lp.some((l) => PRIV_P.has(l))) && !has('privilege')) addE('privilege', 'access noun or role/permission parameter');
  if (!read && any(words, AUTH_N)) addE('privilege', 'identity/authentication/certificate noun on a write');
  if (any(words, CRED_BROAD)) addT('pca.credential_access', 'credential-like noun');
  if (!read && DESTR_A.has(action)) addT('pca.destructive', 'overwrites or resets state');
  if (read && any(words, FIN_CATALOG)) addT('pca.financial_data_read', 'pricing/offering read');
  if (any(words, CRED_ANY) || (words.has('terraform') && words.has('state') && read)) addT('pca.credential_access', 'credential material or a state file');
  // a terraform update can force replacement of the resource, destroying it
  if (words.has('terraform') && action === 'update') addT('pca.destructive', 'terraform update may force replacement');
  if (REVOKE.has(action) && any(words, CRED_N)) addE('delete', 'revokes a credential');
  if (action === 'restore' && any(words, RESTORE_N) && !any(words, RESTORE_X)) addE('delete', 'restore overwrites current state');
  if (CANCELISH.has(action) && !read) addE('delete', 'cancel/void ends the thing');
  return out;
}
