// notion - pages, databases, blocks, comments, users and search. Hand written from Notion's public API reference (operation names only).
import { P, crud, def, handPack, type H } from '../lib/hand';

const E = crud('notion', [
  { name: 'page', title: 'page', trash: true, fields: { parent: P.str(64), title: P.opt(P.str(2000)), properties: P.opt(P.obj()), children: P.opt(P.arr('string', 100)) }, ops: ['get', 'create', 'update', 'archive'] },
  { name: 'database', title: 'database', fields: { parent: P.str(64), title: P.str(2000), properties: P.obj() }, ops: ['get', 'create', 'update'] },
  { name: 'block', title: 'block', trash: true, fields: { children: P.arr('string', 100) }, ops: ['get', 'update', 'delete'] },
  { name: 'comment', title: 'comment', fields: { parent_page: P.id('notion.page'), rich_text: P.pub(2000) }, ops: ['list', 'create'] },
  { name: 'user', title: 'user', pii: true, ops: ['get', 'list'] },
]);
const S: H[] = [
  { verb: 'notion.search', title: 'Search the workspace', description: 'Searches pages and databases shared with the integration.', effects: ['read'], res: ['notion.page', 'set'], params: { query: P.str(2048, { role: 'query.search' }), limit: P.limit(100) } },
  { verb: 'notion.database.query', title: 'Query a database', description: 'Reads rows of a database with filters.', effects: ['read'], res: ['notion.database', 'one'], params: { database: P.id('notion.database'), filter: P.opt(P.obj()), limit: P.limit(100) } },
  { verb: 'notion.block.list_children', title: 'List block children', description: 'Reads the blocks inside a block or page.', effects: ['read'], res: ['notion.block', 'one'], params: { block: P.id('notion.block'), limit: P.limit(100) } },
  { verb: 'notion.block.append_children', title: 'Append blocks', description: 'Adds blocks to a page or block.', effects: ['update'], rev: 'rate_limited', res: ['notion.block', 'one'], params: { block: P.id('notion.block'), children: P.arr('string', 100) } },
  { verb: 'notion.page.restore', title: 'Restore a page from the trash', description: 'Un-archives a page.', effects: ['update'], rev: 'rate_limited', res: ['notion.page', 'one'], params: { page: P.id('notion.page') } },
  { verb: 'notion.page.move', title: 'Move a page', description: 'Moves a page to another parent, which can change who sees it.', effects: ['update'], rev: 'rate_limited', res: ['notion.page', 'one'], params: { page: P.id('notion.page'), new_parent: P.str(64) } },
  { verb: 'notion.page.share_publicly', title: 'Publish a page to the web', description: 'Makes a page readable by anyone with the link.', effects: ['publish'], rev: 'irreversible', res: ['notion.page', 'one'], params: { page: P.id('notion.page') } },
  { verb: 'notion.page.invite', title: 'Invite someone to a page', description: 'Shares a page with a person and notifies them.', effects: ['privilege', 'send'], rev: 'irreversible', res: ['notion.page', 'one'], params: { page: P.id('notion.page'), email: P.email({ role: 'contact.email' }), access: P.enum(['read', 'comment', 'edit', 'full']) } },
  { verb: 'notion.page.set_permissions', title: 'Change page permissions', description: 'Changes who can read or edit a page.', effects: ['privilege'], rev: 'rate_limited', res: ['notion.page', 'one'], params: { page: P.id('notion.page'), grants: P.obj() } },
  { verb: 'notion.page.duplicate', title: 'Duplicate a page', description: 'Copies a page and its contents.', effects: ['create'], rev: 'reversible', res: ['notion.page', 'set'], params: { page: P.id('notion.page') } },
  { verb: 'notion.file.upload', title: 'Upload a file', description: 'Uploads a file to attach to a page.', effects: ['create'], rev: 'reversible', res: ['notion.file', 'set'], params: { path: P.path() } },
  { verb: 'notion.token.introspect', title: 'Introspect a token', description: 'Reads token metadata.', effects: ['read'], traits: ['pca.credential_access'], res: ['notion.token', 'one'], params: { token: P.secret() } },
  { verb: 'notion.token.revoke', title: 'Revoke a token', description: 'Revokes an integration access token.', effects: ['privilege'], rev: 'irreversible', traits: ['pca.credential_access'], res: ['notion.token', 'one'], params: { token: P.secret() } },
  { verb: 'notion.workspace.export', title: 'Export the workspace', description: 'Exports pages and databases to files.', effects: ['export'], res: ['notion.workspace', 'one'], params: { workspace: P.id('notion.workspace'), format: P.enum(['markdown', 'html', 'pdf']) } },
  { verb: 'notion.member.invite', title: 'Invite a workspace member', description: 'Adds a person to the workspace.', effects: ['privilege', 'send'], rev: 'irreversible', res: ['notion.member', 'set'], params: { email: P.email({ role: 'contact.email' }), role: P.enum(['member', 'admin', 'guest']) } },
  { verb: 'notion.member.change_role', title: 'Change a member role', description: 'Changes workspace role.', effects: ['privilege'], rev: 'rate_limited', res: ['notion.member', 'one'], params: { member: P.id('notion.member'), role: P.enum(['member', 'admin', 'guest']) } },
  { verb: 'notion.member.deactivate', title: 'Deactivate a member', description: 'Removes a member from the workspace.', effects: ['privilege', 'delete'], res: ['notion.member', 'one'], params: { member: P.id('notion.member') } },
];

export default handPack({
  name: 'notion',
  licence_notes: 'Hand written from the public Notion API reference (operation names only). Notion publishes no redistributable machine-readable specification we rely on, so none is copied.',
  config_file: __filename,
  sourceUri: 'in-repo:scripts/actions-packs/packs/notion.ts',
  defs: [...E, ...S].map(def),
});
