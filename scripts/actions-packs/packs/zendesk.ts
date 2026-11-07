// zendesk - Support tickets, users, organisations, help center and administration. Hand written from Zendesk's public API documentation
// (operation names only); the published OAS file has no stated redistribution licence, so none of it is copied.
import { P, crud, def, handPack, type H } from '../lib/hand';

const E = crud('zendesk', [
  { name: 'ticket', title: 'ticket', pii: true, trash: true, fields: { subject: P.str(255), comment: P.str(65_000, { role: 'text.message' }), requester_email: P.opt(P.email()), priority: P.opt(P.enum(['low', 'normal', 'high', 'urgent'])), tags: P.opt(P.arr('string', 100)) } },
  { name: 'user', title: 'user', pii: true, trash: true, fields: { name: P.str(255, { role: 'person.name', tags: ['pii'] }), email: P.opt(P.email()), role: P.opt(P.enum(['end-user', 'agent', 'admin'])), phone: P.opt(P.phone()) } },
  { name: 'organization', title: 'organization', fields: { name: P.str(255), domain_names: P.opt(P.arr('string', 50)) } },
  { name: 'group', title: 'group', fields: { name: P.str(255) } },
  { name: 'view', title: 'view', fields: { title: P.str(255), conditions: P.obj() } },
  { name: 'macro', title: 'macro', fields: { title: P.str(255), actions: P.arr('string', 50) } },
  { name: 'trigger', title: 'trigger', fields: { title: P.str(255), conditions: P.obj(), actions: P.arr('string', 50) } },
  { name: 'automation', title: 'automation', fields: { title: P.str(255), conditions: P.obj(), actions: P.arr('string', 50) } },
  { name: 'ticket_field', title: 'ticket field', fields: { title: P.str(255), type: P.str(32) } },
  { name: 'article', title: 'help center article', fields: { title: P.str(255), body: P.pub(1_000_000), section_id: P.str(32) } },
  { name: 'section', title: 'help center section', fields: { name: P.str(255), category_id: P.str(32) } },
  { name: 'webhook', title: 'webhook', fields: { name: P.str(255), endpoint: P.url(), http_method: P.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) }, ops: ['get', 'list', 'create', 'update', 'delete'] },
  { name: 'target', title: 'target', fields: { title: P.str(255), target_url: P.url() }, ops: ['get', 'list', 'create', 'update', 'delete'] },
  { name: 'sla_policy', title: 'SLA policy', fields: { title: P.str(255) } },
  { name: 'satisfaction_rating', title: 'satisfaction rating', ops: ['get', 'list'] },
  { name: 'audit_log', title: 'audit log entry', ops: ['get', 'list'] },
]);
const S: H[] = [
  { verb: 'zendesk.ticket.add_comment', title: 'Reply on a ticket', description: 'Adds a public reply the requester receives, or an internal note.', effects: ['send'], rev: 'irreversible', res: ['zendesk.ticket', 'one'], params: { ticket: P.id('zendesk.ticket'), body: P.text(65_000), public: P.bool(), requester: P.email({ role: 'contact.email' }) } },
  { verb: 'zendesk.ticket.merge', title: 'Merge tickets', description: 'Merges tickets into a target and closes the sources.', effects: ['update', 'delete'], res: ['zendesk.ticket', 'one'], params: { target: P.id('zendesk.ticket'), sources: P.arr('string', 5) } },
  { verb: 'zendesk.ticket.bulk_update', title: 'Update many tickets', description: 'Applies one change to up to 100 tickets.', effects: ['update'], rev: 'rate_limited', res: ['zendesk.ticket', 'set'], params: { ids: P.arr('string', 100), changes: P.obj() } },
  { verb: 'zendesk.ticket.bulk_delete', title: 'Delete many tickets', description: 'Moves up to 100 tickets to the trash.', effects: ['delete'], rev: 'rate_limited', res: ['zendesk.ticket', 'set'], params: { ids: P.arr('string', 100) } },
  { verb: 'zendesk.ticket.restore', title: 'Restore a deleted ticket', description: 'Brings a ticket back from the trash.', effects: ['update'], rev: 'rate_limited', res: ['zendesk.ticket', 'one'], params: { ticket: P.id('zendesk.ticket') } },
  { verb: 'zendesk.ticket.purge', title: 'Permanently delete a ticket', description: 'Erases a deleted ticket for good.', effects: ['delete'], rev: 'irreversible', res: ['zendesk.ticket', 'one'], params: { ticket: P.id('zendesk.ticket') } },
  { verb: 'zendesk.ticket.redact_comment', title: 'Redact text in a comment', description: 'Permanently masks text in a comment.', effects: ['update'], rev: 'irreversible', res: ['zendesk.ticket', 'one'], params: { ticket: P.id('zendesk.ticket'), comment: P.str(32), text: P.str(65_000) } },
  { verb: 'zendesk.ticket.export', title: 'Export tickets', description: 'Exports tickets incrementally in bulk.', effects: ['export'], traits: ['pca.pii_access'], res: ['zendesk.export', 'one'], params: { export: P.id('zendesk.export'), start_time: P.int(0, 4_102_444_800) } },
  { verb: 'zendesk.user.merge', title: 'Merge users', description: 'Merges one user into another; cannot be undone.', effects: ['update', 'delete'], res: ['zendesk.user', 'one'], params: { target: P.id('zendesk.user'), source: P.str(32) } },
  { verb: 'zendesk.user.set_password', title: 'Set a user password', description: 'Sets a password directly.', effects: ['privilege'], rev: 'rate_limited', traits: ['pca.credential_access'], res: ['zendesk.user', 'one'], params: { user: P.id('zendesk.user'), password: P.secret() } },
  { verb: 'zendesk.user.change_role', title: 'Change a user role', description: 'Promotes or demotes a user, changing what they can access.', effects: ['privilege'], rev: 'rate_limited', res: ['zendesk.user', 'one'], params: { user: P.id('zendesk.user'), role: P.enum(['end-user', 'agent', 'admin']) } },
  { verb: 'zendesk.user.suspend', title: 'Suspend a user', description: 'Blocks a user from signing in.', effects: ['privilege'], rev: 'rate_limited', res: ['zendesk.user', 'one'], params: { user: P.id('zendesk.user') } },
  { verb: 'zendesk.user.permanently_delete', title: 'Permanently delete a user', description: 'Erases a deleted user and their data (GDPR).', effects: ['delete'], rev: 'irreversible', res: ['zendesk.user', 'one'], params: { user: P.id('zendesk.user') } },
  { verb: 'zendesk.user.request_password_reset', title: 'Send a password reset', description: 'Emails a reset link to a user.', effects: ['send'], rev: 'irreversible', traits: ['pca.credential_access'], res: ['zendesk.user', 'one'], params: { user: P.id('zendesk.user'), email: P.email({ role: 'contact.email' }) } },
  { verb: 'zendesk.group.add_member', title: 'Add an agent to a group', description: 'Adds a group membership.', effects: ['privilege'], rev: 'rate_limited', res: ['zendesk.group', 'one'], params: { group: P.id('zendesk.group'), user: P.str(32) } },
  { verb: 'zendesk.group.revoke_member', title: 'Revoke an agent from a group', description: 'Removes a group membership.', effects: ['privilege'], rev: 'rate_limited', res: ['zendesk.group', 'one'], params: { group: P.id('zendesk.group'), user: P.str(32) } },
  { verb: 'zendesk.article.publish', title: 'Publish an article', description: 'Makes an article public.', effects: ['publish'], rev: 'irreversible', res: ['zendesk.article', 'one'], params: { article: P.id('zendesk.article') } },
  { verb: 'zendesk.webhook.test', title: 'Send a test webhook', description: 'Posts a sample payload to the endpoint.', effects: ['publish'], rev: 'irreversible', res: ['zendesk.webhook', 'one'], params: { webhook: P.id('zendesk.webhook'), payload: P.opt(P.obj()) } },
  { verb: 'zendesk.api_token.create', title: 'Create an API token', description: 'Creates a credential for API access.', effects: ['create', 'privilege'], rev: 'rate_limited', traits: ['pca.credential_access'], res: ['zendesk.api_token', 'set'], params: { description: P.str(255) } },
  { verb: 'zendesk.oauth_client.create', title: 'Create an OAuth client', description: 'Registers an OAuth client and secret.', effects: ['create', 'privilege'], rev: 'rate_limited', traits: ['pca.credential_access'], res: ['zendesk.oauth_client', 'set'], params: { name: P.str(255), redirect_uris: P.arr('string', 10) } },
  { verb: 'zendesk.job.bulk_delete_tickets', title: 'Delete tickets by job', description: 'Starts an asynchronous bulk delete.', effects: ['delete'], rev: 'rate_limited', res: ['zendesk.ticket', 'set'], params: { ids: P.arr('string', 100) } },
  { verb: 'zendesk.search', title: 'Search', description: 'Searches tickets, users and organisations.', effects: ['read'], traits: ['pca.pii_access'], res: ['zendesk.search', 'set'], params: { query: P.str(2048, { role: 'query.search' }), limit: P.limit(1000) } },
  { verb: 'zendesk.sunshine.query_events', title: 'Query customer events', description: 'Reads event data profiles.', effects: ['read'], traits: ['pca.pii_access'], res: ['zendesk.event', 'set'], params: { query: P.str(2048, { role: 'query.search' }) } },
  { verb: 'zendesk.account.update_settings', title: 'Change account settings', description: 'Changes account-wide settings such as authentication.', effects: ['privilege'], rev: 'rate_limited', res: ['zendesk.account', 'one'], params: { account: P.id('zendesk.account'), settings: P.obj() } },
];

export default handPack({
  name: 'zendesk',
  licence_notes: 'Hand written from Zendesk public developer documentation (operation names only). The published OpenAPI file carries no stated licence permitting redistribution, so none of it is copied.',
  config_file: __filename,
  sourceUri: 'in-repo:scripts/actions-packs/packs/zendesk.ts',
  defs: [...E, ...S].map(def),
});
