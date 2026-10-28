// rules.ts - the shipped suggestion rules (spec section 5.2). DATA, versioned: the published form is
// `rules/suggest-rules.json` (scripts/emit-rules.ts writes and checks it, and a release signs it). Every rule only ADDS.
// These are heuristics measured against a labeled corpus (`eval-suggest`); none of them is a safety guarantee.

import { sealRules, type SignedSuggestRules, type SuggestRule, type SuggestRules } from './suggest';

const T = (n: string) => `pca.${n}`;
let n = 0;
const r = (match: SuggestRule['match'], adds: string[], note: string): SuggestRule => ({ id: `SR-${String(++n).padStart(3, '0')}`, match, adds, note });

export const DEFAULT_RULES_VERSION = '1.1.0';

/** An operation that only reads cannot move money, send, run code, publish or change who can do what; rules for those traits match writes only. */
const WRITE = ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] as const;

const RULES: SuggestRule[] = [
  // ---- destructive ------------------------------------------------------------------------------------------------
  r({ methods: ['DELETE'] }, [T('destructive')], 'HTTP DELETE'),
  r({ name_tokens: ['delete', 'remove', 'destroy', 'drop', 'erase', 'purge', 'wipe', 'truncate', 'terminate', 'revoke', 'cancel', 'unsubscribe', 'deactivate', 'obliterate', 'void'], effects: [...WRITE] }, [T('destructive')], 'a name that deletes or destroys'),
  // ---- money_moving -----------------------------------------------------------------------------------------------
  r({ name_tokens: ['refund', 'charge', 'payout', 'payment', 'pay', 'transfer', 'withdraw', 'withdrawal', 'disburse', 'remit', 'settle', 'debit', 'purchase', 'checkout', 'donate', 'reimburse', 'invoice.pay', 'wire.transfer'], effects: [...WRITE] }, [T('money_moving')], 'a name that moves money'),
  r({ param_names_all: ['amount', 'currency'], param_types: ['integer'] }, [T('money_moving')], 'an integer amount together with a currency'),
  r({ param_names: ['amount', 'price', 'total', 'fee', 'amount_cents', 'amount_minor'], param_types: ['integer'] }, ['money.amount'], 'an integer amount'),
  r({ param_names: ['currency', 'ccy', 'currency_code'], param_types: ['string'] }, ['money.currency'], 'a currency code'),
  r({ param_names: ['payee', 'beneficiary', 'recipient_account', 'destination_account'], param_types: ['string'] }, ['party.payee'], 'a payee'),
  // ---- external_communication -------------------------------------------------------------------------------------
  r({ name_tokens: ['send', 'notify', 'notification', 'email', 'mail', 'sms', 'message', 'broadcast', 'invite', 'announce', 'dispatch', 'reply', 'comment', 'tweet', 'post_to', 'whatsapp', 'push_notification', 'newsletter'], effects: [...WRITE] }, [T('external_communication')], 'a name that sends to people'),
  r({ methods: ['SEND'] }, [T('external_communication')], 'a broker publish leaves the trust domain'),
  r({ param_names: ['recipient', 'recipients', 'to_address', 'cc', 'bcc'], param_types: ['string', 'array'] }, [T('external_communication')], 'a recipient parameter'),
  r({ param_names: ['message', 'subject'], param_types: ['string'] }, ['text.message'], 'a message body'),
  // ---- privilege_change -------------------------------------------------------------------------------------------
  r({ name_tokens: ['invite', 'share', 'grant', 'role', 'permission', 'policy', 'iam', 'member', 'acl', 'owner', 'sudo', 'collaborator', 'assign_role', 'privilege', 'entitlement', 'authorize', 'transfer_ownership', 'add_user', 'add_member'], effects: [...WRITE] }, [T('privilege_change')], 'a name that changes who can do what'),
  r({ name_tokens_strict: ['admin', 'administrator'], effects: [...WRITE] }, [T('privilege_change')], 'an admin operation'),
  r({ path_re: '^/?(v\\d+/)?admin(/|$)', effects: [...WRITE] }, [T('privilege_change')], 'an admin path'),
  r({ param_names: ['role', 'roles', 'permission', 'permissions', 'scope', 'scopes'], param_types: ['string', 'set', 'array'], effects: [...WRITE] }, [T('privilege_change')], 'a role or permission parameter'),
  // ---- data_export ------------------------------------------------------------------------------------------------
  r({ name_tokens: ['export', 'download', 'dump', 'backup', 'extract', 'report.generate', 'snapshot', 'csv', 'bulk_export'] }, [T('data_export')], 'a name that exports data'),
  r({ path_re: '/(exports?|downloads?|dumps?|backups?)(/|$)' }, [T('data_export')], 'an export path'),
  // ---- code_execution ---------------------------------------------------------------------------------------------
  r({ name_tokens: ['exec', 'execute', 'run', 'invoke', 'eval', 'shell', 'script', 'command', 'deploy', 'build', 'bash', 'spawn_process', 'lambda', 'pod', 'container', 'job'], effects: [...WRITE] }, [T('code_execution')], 'a name that runs code'),
  r({ param_names: ['command', 'cmd', 'shell_command'], param_types: ['string'] }, ['code.command'], 'a command parameter'),
  r({ param_names: ['script', 'code', 'source_code', 'expression'], param_types: ['string'] }, ['code.source'], 'a code parameter'),
  r({ param_names: ['sql', 'sql_query', 'raw_query'], param_types: ['string'] }, ['query.sql'], 'a SQL parameter'),
  // ---- credential_access ------------------------------------------------------------------------------------------
  r({ name_tokens: ['token', 'secret', 'key', 'credential', 'password', 'api_key', 'oauth', 'passphrase', 'private_key', 'certificate'] }, [T('credential_access')], 'a name that handles credentials'),
  r({ path_re: '/(oauth|tokens?|secrets?|credentials?|api[_-]?keys?)(/|$)' }, [T('credential_access')], 'a credential path'),
  r({ param_names: ['password', 'passwd', 'passphrase', 'client_secret', 'secret'], param_types: ['string'] }, ['credential.secret'], 'a secret parameter'),
  r({ param_names: ['token', 'access_token', 'refresh_token', 'bearer', 'session_token', 'id_token'], param_types: ['string'] }, ['credential.token'], 'a token parameter'),
  r({ param_names: ['api_key', 'private_key', 'secret_key', 'signing_key'], param_types: ['string'] }, ['credential.key'], 'a key parameter'),
  // ---- bulk -------------------------------------------------------------------------------------------------------
  r({ name_tokens: ['batch', 'bulk', 'all', 'purge', 'truncate', 'wipe', 'mass', 'every'] }, [T('bulk')], 'a name that acts on many items'),
  // ---- pii / regulated --------------------------------------------------------------------------------------------
  r({ param_names: ['email', 'email_address', 'e_mail'], param_types: ['string'] }, ['contact.email', 'tag:pii'], 'an email address'),
  r({ param_formats: ['email'] }, ['contact.email', 'tag:pii'], 'email-format parameter'),
  r({ param_names: ['phone', 'phone_number', 'mobile', 'msisdn'], param_types: ['string'] }, ['contact.phone', 'tag:pii'], 'a phone number'),
  r({ param_formats: ['phone_e164'] }, ['contact.phone', 'tag:pii'], 'phone-format parameter'),
  r({ param_names: ['street_address', 'mailing_address', 'billing_address', 'shipping_address', 'postal_address', 'home_address', 'postcode', 'zip_code'], param_types: ['string'] }, ['contact.address', 'tag:pii'], 'a postal address'),
  r({ param_names: ['ssn', 'social_security_number', 'national_id', 'tax_id', 'passport', 'passport_number', 'drivers_license'], param_types: ['string'] }, ['person.national_id', 'tag:pii'], 'a national identifier'),
  r({ param_names: ['dob', 'birthdate', 'birthday', 'date_of_birth'] }, ['person.dob', 'tag:pii'], 'a date of birth'),
  r({ param_names: ['first_name', 'last_name', 'full_name', 'given_name', 'family_name'], param_types: ['string'] }, ['person.name', 'tag:pii'], 'a person name'),
  r({ param_names: ['iban', 'account_number', 'routing_number', 'card_number', 'cvv', 'cvc', 'pan'], param_types: ['string'] }, ['tag:pci'], 'a payment instrument number'),
  r({ param_formats: ['iban'] }, ['tag:pci'], 'iban-format parameter'),
  r({ name_tokens: ['contact', 'profile', 'employee', 'person', 'people', 'patient', 'lead', 'subscriber', 'applicant', 'candidate'] }, [T('pii_access')], 'a name that handles personal records'),
  r({ name_tokens: ['patient', 'medical', 'health', 'hipaa', 'phi', 'diagnosis', 'prescription', 'ehr', 'fhir', 'clinical'] }, [T('regulated_data')], 'a name that handles regulated health data'),
  // ---- the rest of the core traits --------------------------------------------------------------------------------
  r({ name_tokens: ['publish', 'public', 'publicize', 'expose', 'tweet', 'announce', 'make_public'], effects: [...WRITE] }, [T('public_exposure')], 'a name that makes content public'),
  r({ name_tokens: ['webhook', 'callback', 'proxy', 'crawl', 'scrape', 'ping', 'fetch_url'] }, [T('network_egress')], 'a name that reaches the network'),
  r({ param_names: ['url', 'callback_url', 'webhook_url', 'endpoint', 'target_url', 'redirect_uri'], param_types: ['string'] }, ['url.target'], 'a URL parameter'),
  r({ name_tokens: ['schedule', 'scheduled', 'cron', 'recurring', 'repeat', 'timer', 'every'] }, [T('scheduled')], 'a name that runs later or repeatedly'),
  r({ name_tokens: ['install', 'daemon', 'autostart', 'startup', 'persistent', 'provision'] }, [T('persistence')], 'a name that creates standing access'),
  r({ name_tokens: ['scale', 'restart', 'reboot', 'terminate', 'instance', 'cluster', 'vpc', 'firewall', 'dns', 'deploy', 'rollback', 'namespace', 'volume', 'subnet', 'autoscale'] }, [T('infra_mutation')], 'a name that changes infrastructure'),
  r({ name_tokens: ['launch', 'provision', 'purchase', 'order', 'subscribe', 'buy', 'upgrade', 'allocate', 'reserve', 'billing'] }, [T('cost_incurring')], 'a name that incurs cost'),
  r({ name_tokens: ['sign', 'esign', 'contract', 'agreement', 'consent', 'accept_terms', 'notarize', 'attest'] }, [T('legal_binding')], 'a name that binds you legally'),
  r({ name_tokens: ['impersonate', 'sudo', 'act_as', 'assume_role', 'login_as', 'delegate'] }, [T('impersonation')], 'a name that acts as someone else'),
  r({ name_tokens: ['spawn', 'agent', 'subagent', 'orchestrate', 'delegate_task'] }, [T('agent_spawning')], 'a name that starts another agent'),
  r({ name_tokens: ['balance', 'ledger', 'statement', 'transactions', 'payouts', 'invoices', 'revenue'], effects: ['read'] }, [T('financial_data_read')], 'a read of financial data'),
  // ---- vocabulary widening: synonyms and idioms (found by measuring recall on the labeled corpus) ------------------------
  r({ name_tokens: ['wire', 'reload', 'top_up', 'cash_out', 'redeem', 'compensate', 'rebate', 'fund', 'tip', 'bill', 'drawdown', 'send_money', 'initiate_wire', 'sweep', 'deposit', 'repay', 'prepay', 'subsidize'] }, [T('money_moving')], 'more names that move money'),
  r({ name_tokens: ['discard', 'trash', 'decommission', 'zap', 'evict', 'dispose', 'expunge', 'shred', 'kill', 'nuke', 'blow_away', 'tear_down', 'deprovision', 'unlink_permanently', 'hard_delete', 'scrub', 'clobber', 'overwrite_all'] }, [T('destructive')], 'more names that destroy'),
  r({ name_tokens: ['contact', 'ping', 'text', 'page', 'dm', 'cc', 'bcc', 'whisper', 'shout', 'greet', 'follow_up', 'respond', 'write_to', 'forward', 'alert', 'remind', 'nudge', 'reach_out', 'message', 'call', 'poke'] , effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('external_communication')], 'more names that contact people (writes only)'),
  r({ name_tokens: ['elevate', 'promote', 'whitelist', 'allowlist', 'entitle', 'deputize', 'trust', 'allow_access', 'add_to_group', 'assign', 'delegate', 'enroll', 'onboard_admin', 'unblock'] , effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('privilege_change')], 'more names that change who can do what (writes only)'),
  r({ name_tokens: ['trigger', 'apply', 'compile', 'start', 'launch', 'fire', 'play', 'evaluate', 'submit', 'kick_off', 'spin_up', 'call', 'dispatch_run', 'enqueue', 'queue', 'schedule_run', 'rerun', 'retry'] , effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('code_execution')], 'a verb that starts something running (writes only)'),
  r({ name_tokens: ['pipeline', 'workflow', 'notebook', 'macro', 'snippet', 'plugin', 'function', 'lambda', 'task', 'action', 'query', 'job', 'script', 'build', 'run', 'worker', 'container'] , effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('code_execution')], 'a runnable object being written or started (writes only)'),
  // public exposure
  r({ name_tokens: ['public', 'publish', 'unpublish', 'expose', 'release', 'go_live', 'syndicate', 'promote_to_production', 'put_online', 'make_public', 'unrestrict', 'open_to_web', 'share_publicly', 'post_publicly', 'list_publicly', 'visibility', 'unlist'], effects: [...WRITE] }, [T('public_exposure')], 'a name that changes who can see content'),
  r({ param_names: ['visibility', 'is_public', 'public', 'public_access', 'acl'], param_types: ['string', 'boolean'], effects: [...WRITE] }, [T('public_exposure')], 'a visibility parameter'),
  // financial data read
  r({ name_tokens: ['balance', 'ledger', 'statement', 'transaction', 'payout', 'invoice', 'revenue', 'billing', 'cash_position', 'account_summary', 'tax', 'expense', 'payment', 'earnings', 'receipt', 'payroll', 'budget'] }, [T('financial_data_read')], 'a read of financial records'),
  // scheduled and persistent
  r({ name_tokens: ['schedule', 'cron', 'recurring', 'repeating', 'standing', 'startup', 'autostart', 'persist', 'daemon', 'install', 'timer', 'interval', 'periodic', 'nightly', 'hourly', 'daily', 'weekly'], effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('scheduled')], 'a name that runs later or repeatedly'),
  r({ param_names: ['cron', 'schedule', 'interval', 'rrule', 'recurrence'], param_types: ['string', 'integer'] }, [T('scheduled')], 'a schedule parameter'),
  r({ name_tokens: ['automation', 'trigger', 'rule', 'standing', 'permanent', 'daemon', 'install', 'autostart', 'persist', 'register'], effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('persistence')], 'a name that creates standing behaviour'),
  r({ name_tokens: ['share', 'issue', 'calendar_event', 'meeting', 'invite', 'sns', 'topic_publish', 'post_comment', 'publish_message', 'reply', 'ticket', 'event_invite'] , effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('external_communication')], 'a write that notifies others (share, issue, meeting, topic publish)'),
  r({ name_tokens: ['transfer', 'deactivate', 'reset_factors', 'reset_mfa', 'db_user', 'deploy_key', 'forwarding', 'service_account', 'impersonate', 'make_owner', 'revoke_session'] , effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('privilege_change')], 'a write that changes identities, keys or ownership'),
  r({ name_tokens: ['push', 'merge', 'release_build', 'cherry_pick', 'rebase'] , effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('code_execution')], 'a write that triggers pipelines or deploys'),
  r({ name_tokens: ['book', 'booking', 'reserve', 'order_place', 'cancel_booking', 'cancel_order'] , effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('money_moving')], 'a booking or order that charges or refunds'),
  r({ name_tokens: ['open_to_the_web', 'open_to_web', 'world_readable', 'anyone_with_link'] }, [T('public_exposure')], 'an idiom for public access'),
  r({ name_tokens: ['issue', 'comment', 'merge', 'push', 'deploy', 'deployment', 'release', 'bucket_policy', 'acl', 'channel', 'payment_link', 'repo', 'repos', 'page', 'site', 'topic', 'status', 'tweet', 'post'] , effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('public_exposure')], 'a write whose result others can see (issues, comments, deploys, channels, links, ACLs)'),
  r({ name_tokens: ['archive', 'clear', 'restore', 'truncate', 'reset_all', 'overwrite'] , effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('destructive')], 'a write that clears or overwrites content'),
  // ---- round 2: idioms read off the tuning half of the real-spec corpus (specs the hold-out never sees) ------------------------------------
  r({ name_tokens: ['api_key', 'application_key', 'signing_key', 'access_key', 'credential_list', 'ip_access', 'access_control', 'protection', 'restriction', 'ruleset', 'registration_token', 'jitconfig', 'presigned', 'login_link', 'ephemeral_key', 'portal_session', 'client_token', 'authentication_token', 'authorization_code', 'membership', 'seat', 'workforce', 'permit', 'authorised_user', 'access_group', 'security_manager', 'bypass', 'suspend', 'idp', 'child_org', 'billing_account', 'kick', 'approval', 'invitation', 'user_group', 'usergroup', 'gpg_key', 'ssh_key', 'public_key', 'sip_credential', 'oauth', 'collaborator', 'impersonat', 'jit'] , effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('privilege_change')], 'a write that issues or changes access material or membership'),
  r({ name_tokens: ['deployment', 'dispatch', 'codespace', 'variant_analysis', 'rerequest', 'rollback', 'daemon_set', 'daemonset', 'stateful_set', 'statefulset', 'prediction', 'training', 'restart', 'execution', 'invocation', 'run', 'task'] , effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('code_execution')], 'a write that starts or restarts running workloads'),
  r({ name_tokens: ['campaign', 'journey', 'booklet', 'letter', 'postcard', 'self_mailer', 'snap_pack', 'booking', 'review', 'reviewer', 'release', 'conversation', 'participant', 'validation_request', 'remote_share', 'upload', 'publish', 'evidence', 'space', 'announcement', 'invoice', 'shift', 'reminder', 'thread', 'channel_message', 'comment', 'reply'] , effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('external_communication')], 'a write that reaches other people (mail, bookings, reviews, shares)'),
  r({ name_tokens: ['subscription', 'adjustment', 'credit_note', 'cashout', 'beneficiary', 'topup', 'top_up', 'purchase', 'buy', 'renew', 'register', 'order', 'dispute', 'reversal', 'gift_card', 'savings_plan', 'training_plan', 'external_transaction', 'quote', 'phone_number', 'check', 'extend', 'provision', 'entitle', 'issue', 'load', 'transaction', 'position', 'refund', 'grant', 'sweep', 'payment'] , effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('money_moving')], 'a write on a money object (orders, subscriptions, transfers, purchases)'),
  r({ name_tokens: ['article', 'news_item', 'checkout', 'promote', 'version', 'manifest', 'pull_request', 'route', 'redirect', 'alias', 'domain', 'page', 'site', 'blog'] , effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('public_exposure')], 'a write that changes what is published'),
  r({ name_tokens: ['reminder', 'subscription', 'synthetic', 'resume', 'recurring', 'timer', 'trigger', 'rule', 'job', 'workflow', 'monitor', 'alert', 'watch'] , effects: ['create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] }, [T('scheduled')], 'a write that creates something that fires later'),
  r({ name_tokens: ['balance', 'ledger', 'statement', 'transaction', 'payout', 'invoice', 'revenue', 'billing', 'payment', 'expense', 'tax', 'earnings', 'receipt', 'usage', 'cost', 'charge', 'order', 'subscription', 'account', 'position', 'wallet', 'report'] , effects: ['read'] }, [T('financial_data_read')], 'a read of a money object'),
  // ---- round 3 (second tuning round): gaps read off the adjudicated pack defs on the TUNE side of the split (corpus/adjudication.tsv) ------------
  r({ name_tokens: ['access_pass', 'new_key', 'api_token', 'access_token', 'access_request', 'subuser', 'access_entry', 'set_password', 'password', 'reactivate', 'security_group', 'firewall_rule', 'public_access', 'serial_console', 'temporary_access', 'access_application'], effects: [...WRITE] }, [T('privilege_change')], 'a write that issues or resets access material or changes an access boundary'),
  r({ name_tokens: ['retire', 'expire', 'detach', 'uninstall', 'deregister', 'clean', 'prune'], effects: [...WRITE] }, [T('destructive')], 'a write that retires, expires, detaches or removes something'),
  r({ name_tokens: ['verification', 'verify_phone', 'otp'], effects: [...WRITE] }, [T('external_communication')], 'a write that sends a code to a person'),
  r({ name_tokens: ['publication', 'downtime'], effects: [...WRITE] }, [T('scheduled')], 'a write that creates a standing publication or planned window'),
];

export const DEFAULT_RULES: SuggestRules = Object.freeze({ v: 1, kind: 'pca-suggest-rules', version: DEFAULT_RULES_VERSION, rules: RULES }) as SuggestRules;
export const DEFAULT_RULES_SEALED: SignedSuggestRules = sealRules(DEFAULT_RULES);
