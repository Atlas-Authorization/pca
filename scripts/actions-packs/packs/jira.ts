// jira - Jira Cloud issues, projects, boards, workflows and administration. Hand written from Atlassian's public REST documentation
// (operation names only). Atlassian's published OpenAPI description is under Atlassian developer terms that we do not rely on to redistribute
// derived data, so none of it is copied; this pack is smaller than a generated one on purpose.
import { P, crud, def, handPack, type H } from '../lib/hand';

const E = crud('jira', [
  { name: 'issue', title: 'issue', fields: { project: P.str(32), summary: P.str(255), description: P.opt(P.str(32_000)), issuetype: P.str(64), assignee: P.opt(P.str(128, { role: 'person.name' })), labels: P.opt(P.arr('string', 50)) } },
  { name: 'comment', title: 'comment', fields: { issue: P.id('jira.issue'), body: P.pub(32_000) }, noun: 'issue.comment' },
  { name: 'project', title: 'project', fields: { key: P.str(10), name: P.str(80), lead: P.str(128), type: P.opt(P.enum(['software', 'business', 'service_desk'])) } },
  { name: 'board', title: 'board', fields: { name: P.str(255), type: P.enum(['scrum', 'kanban']), filter: P.str(32) } },
  { name: 'sprint', title: 'sprint', fields: { name: P.str(255), board: P.str(32), start: P.opt(P.dt()), end: P.opt(P.dt()) } },
  { name: 'filter', title: 'filter', fields: { name: P.str(255), jql: P.str(8000, { role: 'query.search' }) } },
  { name: 'version', title: 'project version', fields: { project: P.str(32), name: P.str(255) } },
  { name: 'component', title: 'project component', fields: { project: P.str(32), name: P.str(255) } },
  { name: 'dashboard', title: 'dashboard', fields: { name: P.str(255) } },
  { name: 'user', title: 'user', pii: true, ops: ['get', 'search'] },
  { name: 'group', title: 'group', fields: { name: P.str(255) }, ops: ['get', 'list', 'create', 'delete'] },
  { name: 'field', title: 'custom field', fields: { name: P.str(255), type: P.str(128) }, ops: ['list', 'create', 'update', 'delete'] },
  { name: 'workflow', title: 'workflow', fields: { name: P.str(255) }, ops: ['get', 'list', 'create', 'update', 'delete'] },
  { name: 'webhook', title: 'webhook', fields: { url: P.url(), events: P.arr('string', 50), jql: P.opt(P.str(8000)) }, ops: ['list', 'create', 'delete'] },
]);
const S: H[] = [
  { verb: 'jira.issue.search_jql', title: 'Search issues with JQL', description: 'Runs a JQL query.', effects: ['read'], res: ['jira.issue', 'set'], params: { jql: P.str(8000, { role: 'query.search' }), limit: P.limit(1000) } },
  { verb: 'jira.issue.transition', title: 'Transition an issue', description: 'Moves an issue through its workflow; post functions may run.', effects: ['update'], rev: 'rate_limited', res: ['jira.issue', 'one'], params: { issue: P.id('jira.issue'), transition: P.str(32) } },
  { verb: 'jira.issue.assign', title: 'Assign an issue', description: 'Sets the assignee, who may be notified.', effects: ['update'], rev: 'rate_limited', res: ['jira.issue', 'one'], params: { issue: P.id('jira.issue'), assignee: P.str(128) } },
  { verb: 'jira.issue.bulk_edit', title: 'Edit many issues', description: 'Applies one change to many issues.', effects: ['update'], rev: 'rate_limited', res: ['jira.issue', 'set'], params: { issues: P.arr('string', 1000), edit: P.obj() } },
  { verb: 'jira.issue.bulk_delete', title: 'Delete many issues', description: 'Deletes many issues permanently.', effects: ['delete'], res: ['jira.issue', 'set'], params: { issues: P.arr('string', 1000) } },
  { verb: 'jira.issue.move', title: 'Move an issue to another project', description: 'Changes the project and key of an issue.', effects: ['update'], rev: 'rate_limited', res: ['jira.issue', 'one'], params: { issue: P.id('jira.issue'), project: P.str(32) } },
  { verb: 'jira.issue.link', title: 'Link two issues', description: 'Creates an issue link.', effects: ['create'], rev: 'reversible', res: ['jira.issue', 'one'], params: { inward: P.id('jira.issue'), outward: P.str(64), type: P.str(64) } },
  { verb: 'jira.issue.attach_file', title: 'Attach a file to an issue', description: 'Uploads a file visible to everyone who can see the issue.', effects: ['create'], rev: 'reversible', res: ['jira.issue', 'one'], params: { issue: P.id('jira.issue'), path: P.path() } },
  { verb: 'jira.issue.add_watcher', title: 'Add a watcher', description: 'Subscribes a user to notifications.', effects: ['update'], rev: 'rate_limited', res: ['jira.issue', 'one'], params: { issue: P.id('jira.issue'), user: P.str(128) } },
  { verb: 'jira.issue.notify', title: 'Send an issue notification', description: 'Emails users about an issue.', effects: ['send'], rev: 'irreversible', res: ['jira.issue', 'one'], params: { issue: P.id('jira.issue'), to: P.email({ role: 'contact.email' }), subject: P.str(255), text: P.text(10_000) } },
  { verb: 'jira.issue.log_work', title: 'Log work', description: 'Adds a worklog entry.', effects: ['create'], rev: 'reversible', res: ['jira.issue', 'one'], params: { issue: P.id('jira.issue'), seconds: P.int(60, 8_640_000) } },
  { verb: 'jira.issue.set_security_level', title: 'Change issue security level', description: 'Changes who can see an issue.', effects: ['privilege'], rev: 'rate_limited', res: ['jira.issue', 'one'], params: { issue: P.id('jira.issue'), level: P.str(32) } },
  { verb: 'jira.sprint.start', title: 'Start a sprint', description: 'Starts a sprint.', effects: ['update'], rev: 'rate_limited', res: ['jira.sprint', 'one'], params: { sprint: P.id('jira.sprint') } },
  { verb: 'jira.sprint.complete', title: 'Complete a sprint', description: 'Closes a sprint and moves unfinished issues.', effects: ['update'], rev: 'irreversible', res: ['jira.sprint', 'one'], params: { sprint: P.id('jira.sprint') } },
  { verb: 'jira.version.release', title: 'Release a version', description: 'Marks a version released.', effects: ['update', 'publish'], rev: 'irreversible', res: ['jira.version', 'one'], params: { version: P.id('jira.version') } },
  { verb: 'jira.project.archive', title: 'Archive a project', description: 'Archives a project.', effects: ['update'], rev: 'rate_limited', res: ['jira.project', 'one'], params: { project: P.id('jira.project') } },
  { verb: 'jira.project.set_role_actors', title: 'Set project role members', description: 'Changes who has a role in a project.', effects: ['privilege'], rev: 'rate_limited', res: ['jira.project', 'one'], params: { project: P.id('jira.project'), role: P.str(32), users: P.arr('string', 500) } },
  { verb: 'jira.project.set_permission_scheme', title: 'Assign a permission scheme', description: 'Changes the permissions of a project.', effects: ['privilege'], rev: 'rate_limited', res: ['jira.project', 'one'], params: { project: P.id('jira.project'), scheme: P.str(32) } },
  { verb: 'jira.permission_scheme.grant', title: 'Grant a permission in a scheme', description: 'Adds a permission grant.', effects: ['privilege'], rev: 'rate_limited', res: ['jira.permission_scheme', 'one'], params: { scheme: P.id('jira.permission_scheme'), permission: P.str(64), holder: P.str(128) } },
  { verb: 'jira.permission_scheme.revoke', title: 'Revoke a permission in a scheme', description: 'Removes a permission grant.', effects: ['privilege'], rev: 'rate_limited', res: ['jira.permission_scheme', 'one'], params: { scheme: P.id('jira.permission_scheme'), grant: P.str(32) } },
  { verb: 'jira.group.add_user', title: 'Add a user to a group', description: 'Adds a member, who inherits the group permissions.', effects: ['privilege'], rev: 'rate_limited', res: ['jira.group', 'one'], params: { group: P.id('jira.group'), user: P.str(128) } },
  { verb: 'jira.group.revoke_user', title: 'Revoke a user from a group', description: 'Takes a member out of a group.', effects: ['privilege'], rev: 'rate_limited', res: ['jira.group', 'one'], params: { group: P.id('jira.group'), user: P.str(128) } },
  { verb: 'jira.user.create', title: 'Create a user', description: 'Creates or invites a user.', effects: ['create', 'privilege'], rev: 'rate_limited', res: ['jira.user', 'set'], params: { email: P.email(), display_name: P.opt(P.str(128, { role: 'person.name', tags: ['pii'] })) } },
  { verb: 'jira.user.deactivate', title: 'Deactivate a user', description: 'Disables a user account.', effects: ['privilege'], rev: 'rate_limited', res: ['jira.user', 'one'], params: { user: P.id('jira.user') } },
  { verb: 'jira.user.delete', title: 'Delete a user', description: 'Deletes a user account.', effects: ['delete', 'privilege'], res: ['jira.user', 'one'], params: { user: P.id('jira.user') } },
  { verb: 'jira.api_token.create', title: 'Create an API token', description: 'Creates a credential acting as the user.', effects: ['create', 'privilege'], rev: 'rate_limited', traits: ['pca.credential_access'], res: ['jira.api_token', 'set'], params: { label: P.str(255) } },
  { verb: 'jira.automation.run_rule', title: 'Run an automation rule', description: 'Triggers a rule, which can edit issues and send messages.', effects: ['exec'], res: ['jira.automation_rule', 'one'], params: { rule: P.id('jira.automation_rule') } },
  { verb: 'jira.workflow.publish_draft', title: 'Publish a workflow draft', description: 'Applies workflow changes to all issues using it.', effects: ['update'], rev: 'irreversible', res: ['jira.workflow', 'one'], params: { workflow: P.id('jira.workflow') } },
  { verb: 'jira.data.export', title: 'Export issues', description: 'Exports issues to CSV or XML.', effects: ['export'], traits: ['pca.pii_access'], res: ['jira.export', 'one'], params: { export: P.id('jira.export'), jql: P.str(8000, { role: 'query.search' }) } },
  { verb: 'jira.audit.list_records', title: 'Read audit records', description: 'Administrative activity log.', effects: ['read'], res: ['jira.audit', 'set'], params: { limit: P.limit(1000) } },
];

export default handPack({
  name: 'jira',
  licence_notes: 'Hand written from Atlassian public developer documentation (operation names only). The Jira Cloud OpenAPI description is under Atlassian developer terms that were not relied on for redistribution, so nothing from it is copied.',
  config_file: __filename,
  sourceUri: 'in-repo:scripts/actions-packs/packs/jira.ts',
  defs: [...E, ...S].map(def),
});
