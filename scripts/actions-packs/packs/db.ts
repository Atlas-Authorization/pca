// db - database operations by class (read, DML, DDL, admin, export) for PostgreSQL, MySQL, SQLite, MongoDB and Redis. Structured
// verbs are preferred to raw query text: a raw statement is a program, so `execute_sql` is classed as running code that can
// also change and delete data. Hand written from public product documentation (classes of operation, not API schemas).
import { P, def, handPack, type H } from '../lib/hand';

const SQL_ENGINES: { ns: string; name: string; admin: boolean; schemas: boolean; file: boolean }[] = [
  { ns: 'pg', name: 'PostgreSQL', admin: true, schemas: true, file: true },
  { ns: 'mysql', name: 'MySQL', admin: true, schemas: false, file: true },
  { ns: 'sqlite', name: 'SQLite', admin: false, schemas: false, file: false },
];

function sqlFamily(e: (typeof SQL_ENGINES)[number]): H[] {
  const t = (id = true) => ({ table: id ? P.id(`${e.ns}.table`) : P.str(128) });
  const tbl = (x: Partial<H> & Pick<H, 'verb' | 'title' | 'description' | 'effects' | 'params'>): H => ({ res: [`${e.ns}.table`, 'one'], ...x });
  const set = (x: Partial<H> & Pick<H, 'verb' | 'title' | 'description' | 'effects' | 'params'>): H => ({ res: [`${e.ns}.database`, 'set'], ...x });
  const v = (n: string) => `${e.ns}.${n}`;
  const out: H[] = [
    // reads
    tbl({ verb: v('select_rows'), title: `Read rows from a ${e.name} table`, description: 'Reads rows with optional column list, filter, ordering and limit.', effects: ['read'], params: { ...t(), columns: P.opt(P.arr('string', 256)), where: P.opt(P.obj()), order_by: P.opt(P.str(256)), limit: P.limit(100_000) } }),
    tbl({ verb: v('count_rows'), title: `Count rows in a ${e.name} table`, description: 'Counts rows matching an optional filter.', effects: ['read'], params: { ...t(), where: P.opt(P.obj()) } }),
    tbl({ verb: v('describe_table'), title: `Describe a ${e.name} table`, description: 'Columns, types, keys and indexes.', effects: ['read'], params: t() }),
    set({ verb: v('list_tables'), title: `List ${e.name} tables`, description: 'Names of tables in the database.', effects: ['read'], params: { database: P.opt(P.str(128)) } }),
    // DML
    tbl({ verb: v('insert_rows'), title: `Insert rows into a ${e.name} table`, description: 'Inserts up to 1000 rows.', effects: ['create'], rev: 'reversible', params: { ...t(), rows: P.arr('string', 1000), returning: P.opt(P.arr('string', 64)) } }),
    tbl({ verb: v('update_rows'), title: `Update rows in a ${e.name} table`, description: 'Changes columns of the rows matching a required filter.', effects: ['update'], rev: 'rate_limited', params: { ...t(), set: P.obj(), where: P.obj() } }),
    tbl({ verb: v('upsert_rows'), title: `Upsert rows in a ${e.name} table`, description: 'Inserts rows or updates them on key conflict.', effects: ['create', 'update'], rev: 'rate_limited', params: { ...t(), rows: P.arr('string', 1000), conflict_columns: P.arr('string', 16) } }),
    tbl({ verb: v('delete_rows'), title: `Delete rows from a ${e.name} table`, description: 'Deletes the rows matching a required filter.', effects: ['delete'], params: { ...t(), where: P.obj() } }),
    tbl({ verb: v('truncate_table'), title: `Truncate a ${e.name} table`, description: 'Removes every row of a table at once.', effects: ['delete'], params: t() }),
    // DDL
    set({ verb: v('create_table'), title: `Create a ${e.name} table`, description: 'Creates a table from a column definition.', effects: ['create'], rev: 'reversible', params: { table: P.str(128), columns: P.obj(), if_not_exists: P.opt(P.bool()) } }),
    tbl({ verb: v('drop_table'), title: `Drop a ${e.name} table`, description: 'Deletes a table and all its data.', effects: ['delete'], params: t() }),
    tbl({ verb: v('rename_table'), title: `Rename a ${e.name} table`, description: 'Renames a table; clients using the old name break.', effects: ['update'], rev: 'rate_limited', params: { ...t(), to: P.str(128) } }),
    tbl({ verb: v('add_column'), title: `Add a column to a ${e.name} table`, description: 'Adds a column.', effects: ['update'], rev: 'rate_limited', params: { ...t(), column: P.str(128), type: P.str(128) } }),
    tbl({ verb: v('drop_column'), title: `Drop a column from a ${e.name} table`, description: 'Removes a column and its data.', effects: ['update', 'delete'], params: { ...t(), column: P.str(128) } }),
    tbl({ verb: v('create_index'), title: `Create an index on a ${e.name} table`, description: 'Builds an index; large tables lock or slow down while it builds.', effects: ['create'], rev: 'reversible', params: { ...t(), columns: P.arr('string', 16), unique: P.opt(P.bool()) } }),
    tbl({ verb: v('drop_index'), title: `Drop an index on a ${e.name} table`, description: 'Removes an index.', effects: ['delete'], rev: 'rate_limited', params: { ...t(), index: P.str(128) } }),
    set({ verb: v('create_view'), title: `Create a ${e.name} view`, description: 'Creates a named stored query.', effects: ['create'], rev: 'reversible', params: { view: P.str(128), definition: P.sql() } }),
    set({ verb: v('drop_view'), title: `Drop a ${e.name} view`, description: 'Deletes a view.', effects: ['delete'], rev: 'rate_limited', params: { view: P.str(128) } }),
    // raw
    set({ verb: v('execute_sql'), title: `Run a raw ${e.name} statement`, description: 'Runs arbitrary SQL, which can read, change, delete or define anything the connection may.', effects: ['exec', 'update', 'delete'], params: { sql: P.sql(), params: P.opt(P.arr('string', 256)) } }),
    set({ verb: v('execute_script'), title: `Run a ${e.name} script`, description: 'Runs a multi-statement script.', effects: ['exec', 'update', 'delete'], params: { script: P.sql({ max_len: 1_000_000 }) } }),
    set({ verb: v('vacuum'), title: `Vacuum or optimise ${e.name}`, description: 'Reclaims space and rewrites storage; can lock tables.', effects: ['update'], rev: 'rate_limited', params: {} }),
    // export / import
    set({ verb: v('dump'), title: `Dump a ${e.name} database`, description: 'Writes the schema and data of a database to a file.', effects: ['export'], rev: 'irreversible', res: [`${e.ns}.database`, 'one'], params: { database: P.id(`${e.ns}.database`), to: P.path() } }),
    tbl({ verb: v('export_table'), title: `Export a ${e.name} table to a file`, description: 'Writes the rows of a table to CSV or JSON on disk.', effects: ['export'], params: { ...t(), to: P.path(), format: P.enum(['csv', 'json']) } }),
    tbl({ verb: v('import_file'), title: `Import a file into a ${e.name} table`, description: 'Loads rows from a CSV or JSON file.', effects: ['create', 'update'], rev: 'rate_limited', params: { ...t(), from: P.path(), format: P.enum(['csv', 'json']) } }),
  ];
  if (e.schemas) {
    out.push(
      set({ verb: v('list_schemas'), title: `List ${e.name} schemas`, description: 'Names of schemas.', effects: ['read'], params: {} }),
      set({ verb: v('create_schema'), title: `Create a ${e.name} schema`, description: 'Creates a schema.', effects: ['create'], rev: 'reversible', params: { schema: P.str(128) } }),
      set({ verb: v('drop_schema'), title: `Drop a ${e.name} schema`, description: 'Deletes a schema; with cascade, everything in it.', effects: ['delete'], params: { schema: P.str(128), cascade: P.opt(P.bool()) } }),
    );
  }
  if (e.admin) {
    out.push(
      set({ verb: v('list_databases'), title: `List ${e.name} databases`, description: 'Names of databases on the server.', effects: ['read'], res: [`${e.ns}.server`, 'set'], params: {} }),
      { verb: v('create_database'), title: `Create a ${e.name} database`, description: 'Creates a database.', effects: ['create'], rev: 'reversible', res: [`${e.ns}.server`, 'set'], params: { database: P.str(128) } },
      { verb: v('drop_database'), title: `Drop a ${e.name} database`, description: 'Deletes a whole database.', effects: ['delete'], res: [`${e.ns}.database`, 'one'], params: { database: P.id(`${e.ns}.database`) } },
      { verb: v('create_role'), title: `Create a ${e.name} role or user`, description: 'Creates a login role.', effects: ['privilege', 'create'], rev: 'rate_limited', traits: ['pca.credential_access'], res: [`${e.ns}.role`, 'set'], params: { role: P.str(128), password: P.opt(P.secret()) } },
      { verb: v('drop_role'), title: `Drop a ${e.name} role or user`, description: 'Deletes a role.', effects: ['privilege', 'delete'], res: [`${e.ns}.role`, 'one'], params: { role: P.id(`${e.ns}.role`) } },
      { verb: v('set_password'), title: `Change a ${e.name} role password`, description: 'Sets a new password for a role.', effects: ['privilege', 'update'], rev: 'rate_limited', traits: ['pca.credential_access'], res: [`${e.ns}.role`, 'one'], params: { role: P.id(`${e.ns}.role`), password: P.secret() } },
      { verb: v('grant'), title: `Grant ${e.name} privileges`, description: 'Gives a role privileges on objects.', effects: ['privilege'], rev: 'rate_limited', res: [`${e.ns}.role`, 'one'], params: { role: P.id(`${e.ns}.role`), privileges: P.arr('string', 64), on: P.str(256) } },
      { verb: v('revoke'), title: `Revoke ${e.name} privileges`, description: 'Removes privileges from a role.', effects: ['privilege'], rev: 'rate_limited', res: [`${e.ns}.role`, 'one'], params: { role: P.id(`${e.ns}.role`), privileges: P.arr('string', 64), on: P.str(256) } },
      { verb: v('kill_session'), title: `Terminate a ${e.name} session`, description: 'Ends a running session or query.', effects: ['delete'], rev: 'rate_limited', res: [`${e.ns}.session`, 'one'], params: { session: P.id(`${e.ns}.session`, { max_len: 20 }) } },
      { verb: v('list_sessions'), title: `List ${e.name} sessions`, description: 'Running sessions and queries, which may contain statement text.', effects: ['read'], res: [`${e.ns}.session`, 'set'], params: {} },
      { verb: v('set_config'), title: `Change ${e.name} server settings`, description: 'Changes a server configuration setting.', effects: ['update', 'privilege'], rev: 'rate_limited', res: [`${e.ns}.server`, 'set'], params: { name: P.str(128), value: P.str(4096) } },
      { verb: v('get_config'), title: `Read ${e.name} server settings`, description: 'Reads configuration settings.', effects: ['read'], res: [`${e.ns}.server`, 'set'], params: { name: P.opt(P.str(128)) } },
    );
  }
  if (e.ns === 'pg') {
    out.push(
      { verb: 'pg.create_extension', title: 'Install a PostgreSQL extension', description: 'Loads extension code into the server.', effects: ['exec', 'provision'], res: ['pg.database', 'set'], params: { extension: P.str(128) } },
      { verb: 'pg.create_publication', title: 'Create a logical replication publication', description: 'Streams table changes to subscribers outside the database.', effects: ['provision', 'export'], res: ['pg.publication', 'one'], params: { publication: P.id('pg.publication'), tables: P.arr('string', 256) } },
      { verb: 'pg.create_replication_slot', title: 'Create a replication slot', description: 'Reserves a change stream that retains write-ahead log until consumed.', effects: ['provision'], rev: 'rate_limited', res: ['pg.database', 'set'], params: { slot: P.str(128) } },
      { verb: 'pg.restore', title: 'Restore a PostgreSQL dump', description: 'Loads a dump, creating and replacing objects.', effects: ['exec', 'create', 'update', 'delete'], res: ['pg.database', 'one'], params: { database: P.id('pg.database'), from: P.path() } },
      { verb: 'pg.copy_to_program', title: 'Copy query output to a program', description: 'Pipes table data into a server-side command.', effects: ['exec', 'export'], res: ['pg.table', 'one'], params: { table: P.id('pg.table'), command: P.cmd() } },
    );
  }
  void file(e);
  return out;
}
function file(_e: unknown): void { /* kept for symmetry with engines that add file ops */ }

const MONGO: H[] = (() => {
  const c = (x: Partial<H> & Pick<H, 'verb' | 'title' | 'description' | 'effects' | 'params'>): H => ({ res: ['mongo.collection', 'one'], ...x });
  const coll = { collection: P.id('mongo.collection') };
  return [
    c({ verb: 'mongo.find', title: 'Find documents', description: 'Reads documents matching a filter.', effects: ['read'], params: { ...coll, filter: P.opt(P.obj()), projection: P.opt(P.obj()), sort: P.opt(P.obj()), limit: P.limit(100_000) } }),
    c({ verb: 'mongo.count', title: 'Count documents', description: 'Counts documents matching a filter.', effects: ['read'], params: { ...coll, filter: P.opt(P.obj()) } }),
    c({ verb: 'mongo.distinct', title: 'List distinct values', description: 'Distinct values of a field.', effects: ['read'], params: { ...coll, field: P.str(256), filter: P.opt(P.obj()) } }),
    c({ verb: 'mongo.aggregate', title: 'Run an aggregation pipeline', description: 'Runs a pipeline; stages such as out and merge write to collections, so it is not classed read-only.', effects: ['read', 'update'], rev: 'rate_limited', params: { ...coll, pipeline: P.arr('string', 256) } }),
    c({ verb: 'mongo.insert_one', title: 'Insert a document', description: 'Inserts one document.', effects: ['create'], rev: 'reversible', params: { ...coll, document: P.obj() } }),
    c({ verb: 'mongo.insert_many', title: 'Insert documents', description: 'Inserts up to 1000 documents.', effects: ['create'], rev: 'reversible', params: { ...coll, documents: P.arr('string', 1000) } }),
    c({ verb: 'mongo.update_one', title: 'Update one document', description: 'Applies an update to the first document matching a filter.', effects: ['update'], rev: 'rate_limited', params: { ...coll, filter: P.obj(), update: P.obj(), upsert: P.opt(P.bool()) } }),
    c({ verb: 'mongo.update_many', title: 'Update many documents', description: 'Applies an update to every document matching a required filter.', effects: ['update'], rev: 'rate_limited', res: ['mongo.collection', 'one'], params: { ...coll, filter: P.obj(), update: P.obj() } }),
    c({ verb: 'mongo.replace_one', title: 'Replace a document', description: 'Replaces a whole document.', effects: ['update'], rev: 'rate_limited', params: { ...coll, filter: P.obj(), replacement: P.obj() } }),
    c({ verb: 'mongo.delete_one', title: 'Delete one document', description: 'Deletes the first document matching a filter.', effects: ['delete'], params: { ...coll, filter: P.obj() } }),
    c({ verb: 'mongo.delete_many', title: 'Delete many documents', description: 'Deletes every document matching a required filter.', effects: ['delete'], params: { ...coll, filter: P.obj() } }),
    c({ verb: 'mongo.find_one_and_modify', title: 'Find and modify a document', description: 'Atomically updates or deletes one document and returns it.', effects: ['update', 'delete'], params: { ...coll, filter: P.obj(), update: P.opt(P.obj()), remove: P.opt(P.bool()) } }),
    c({ verb: 'mongo.create_collection', title: 'Create a collection', description: 'Creates a collection.', effects: ['create'], rev: 'reversible', params: { collection: P.str(128), options: P.opt(P.obj()) } }),
    c({ verb: 'mongo.drop_collection', title: 'Drop a collection', description: 'Deletes a collection and its documents.', effects: ['delete'], params: coll }),
    c({ verb: 'mongo.rename_collection', title: 'Rename a collection', description: 'Renames a collection, optionally dropping the target.', effects: ['update'], rev: 'rate_limited', params: { ...coll, to: P.str(128), drop_target: P.opt(P.bool()) } }),
    c({ verb: 'mongo.create_index', title: 'Create an index', description: 'Builds an index.', effects: ['create'], rev: 'reversible', params: { ...coll, keys: P.obj(), unique: P.opt(P.bool()) } }),
    c({ verb: 'mongo.drop_index', title: 'Drop an index', description: 'Removes an index.', effects: ['delete'], rev: 'rate_limited', params: { ...coll, index: P.str(128) } }),
    { verb: 'mongo.list_collections', title: 'List collections', description: 'Names of collections.', effects: ['read'], res: ['mongo.database', 'set'], params: { database: P.opt(P.str(128)) } },
    { verb: 'mongo.list_databases', title: 'List databases', description: 'Names of databases on the deployment.', effects: ['read'], res: ['mongo.deployment', 'set'], params: {} },
    { verb: 'mongo.drop_database', title: 'Drop a database', description: 'Deletes a database and everything in it.', effects: ['delete'], res: ['mongo.database', 'one'], params: { database: P.id('mongo.database') } },
    { verb: 'mongo.run_command', title: 'Run a database command', description: 'Runs an arbitrary server command.', effects: ['exec', 'update', 'delete', 'privilege'], res: ['mongo.database', 'set'], params: { command: P.obj() } },
    { verb: 'mongo.eval_js', title: 'Run server-side JavaScript', description: 'Evaluates script on the server.', effects: ['exec', 'update', 'delete'], res: ['mongo.database', 'set'], params: { source: P.code() } },
    { verb: 'mongo.create_user', title: 'Create a database user', description: 'Creates a user with roles.', effects: ['privilege', 'create'], rev: 'rate_limited', traits: ['pca.credential_access'], res: ['mongo.user', 'set'], params: { user: P.str(128), password: P.secret(), roles: P.arr('string', 64) } },
    { verb: 'mongo.drop_user', title: 'Drop a database user', description: 'Deletes a user.', effects: ['privilege', 'delete'], res: ['mongo.user', 'one'], params: { user: P.id('mongo.user') } },
    { verb: 'mongo.grant_roles', title: 'Grant roles to a user', description: 'Adds roles to a user.', effects: ['privilege'], rev: 'rate_limited', res: ['mongo.user', 'one'], params: { user: P.id('mongo.user'), roles: P.arr('string', 64) } },
    { verb: 'mongo.revoke_roles', title: 'Revoke roles from a user', description: 'Removes roles from a user.', effects: ['privilege'], rev: 'rate_limited', res: ['mongo.user', 'one'], params: { user: P.id('mongo.user'), roles: P.arr('string', 64) } },
    { verb: 'mongo.dump', title: 'Dump a database', description: 'Writes a database to files with mongodump.', effects: ['export'], res: ['mongo.database', 'one'], params: { database: P.id('mongo.database'), to: P.path() } },
    { verb: 'mongo.restore', title: 'Restore a dump', description: 'Loads a dump, replacing documents.', effects: ['create', 'update', 'delete'], res: ['mongo.database', 'one'], params: { database: P.id('mongo.database'), from: P.path(), drop: P.opt(P.bool()) } },
    { verb: 'mongo.kill_op', title: 'Kill an operation', description: 'Stops a running operation.', effects: ['delete'], rev: 'rate_limited', res: ['mongo.operation', 'one'], params: { op: P.id('mongo.operation', { max_len: 20 }) } },
  ];
})();

const REDIS: H[] = (() => {
  const k = (x: Partial<H> & Pick<H, 'verb' | 'title' | 'description' | 'effects' | 'params'>): H => ({ res: ['redis.key', 'one'], ...x });
  const key = { key: P.id('redis.key', { max_len: 512 }) };
  const set = (x: Partial<H> & Pick<H, 'verb' | 'title' | 'description' | 'effects' | 'params'>): H => ({ res: ['redis.server', 'set'], ...x });
  const reads: [string, string, Record<string, ReturnType<typeof P.str>>][] = [
    ['get', 'Read a string key', {}], ['hgetall', 'Read all fields of a hash', {}], ['lrange', 'Read a range of a list', {}], ['smembers', 'Read all members of a set', {}],
    ['zrange', 'Read a range of a sorted set', {}], ['exists', 'Check whether a key exists', {}], ['ttl', 'Read the time to live of a key', {}], ['type', 'Read the type of a key', {}],
  ];
  const out: H[] = reads.map(([n, t]) => k({ verb: `redis.${n}`, title: t, description: `${t}.`, effects: ['read'], params: key }));
  const w = (n: string, title: string, desc: string, effects: H['effects'], rev: H['rev'], extra: H['params'] = {}) => out.push(k({ verb: `redis.${n}`, title, description: desc, effects, rev, params: { ...key, ...extra } }));
  w('set', 'Set a string key', 'Sets a key, replacing any value.', ['update'], 'rate_limited', { value: P.str(16_000_000), ttl_s: P.opt(P.int(1, 31_536_000)) });
  w('del', 'Delete a key', 'Deletes a key.', ['delete'], 'irreversible');
  w('unlink', 'Unlink a key', 'Deletes a key asynchronously.', ['delete'], 'irreversible');
  w('expire', 'Set a key expiry', 'Makes a key expire after a number of seconds.', ['update'], 'rate_limited', { seconds: P.int(1, 31_536_000) });
  w('incr', 'Increment a counter', 'Adds one to an integer key.', ['update'], 'rate_limited');
  w('decr', 'Decrement a counter', 'Subtracts one from an integer key.', ['update'], 'rate_limited');
  w('hset', 'Set hash fields', 'Sets fields of a hash.', ['update'], 'rate_limited', { fields: P.obj() });
  w('hdel', 'Delete hash fields', 'Removes fields from a hash.', ['delete'], 'irreversible', { fields: P.arr('string', 256) });
  w('lpush', 'Push to a list head', 'Adds values to the head of a list.', ['create'], 'rate_limited', { values: P.arr('string', 1000) });
  w('rpush', 'Push to a list tail', 'Adds values to the tail of a list.', ['create'], 'rate_limited', { values: P.arr('string', 1000) });
  w('lpop', 'Pop from a list', 'Removes and returns the first element.', ['update', 'delete'], 'irreversible');
  w('sadd', 'Add set members', 'Adds members to a set.', ['create'], 'rate_limited', { members: P.arr('string', 1000) });
  w('srem', 'Remove set members', 'Removes members from a set.', ['delete'], 'irreversible', { members: P.arr('string', 1000) });
  w('zadd', 'Add sorted set members', 'Adds scored members.', ['create'], 'rate_limited', { members: P.arr('string', 1000) });
  out.push(
    set({ verb: 'redis.mget', title: 'Read many keys', description: 'Reads the values of up to 1000 keys.', effects: ['read'], params: { keys: P.arr('string', 1000) } }),
    set({ verb: 'redis.scan', title: 'Scan keys', description: 'Iterates over keys matching a pattern.', effects: ['read'], params: { pattern: P.opt(P.str(512)), limit: P.limit(100_000) } }),
    set({ verb: 'redis.keys', title: 'List all keys matching a pattern', description: 'Lists keys by pattern; blocks a large server.', effects: ['read'], params: { pattern: P.str(512) } }),
    set({ verb: 'redis.info', title: 'Read server information', description: 'Server statistics.', effects: ['read'], params: {} }),
    set({ verb: 'redis.config_get', title: 'Read server configuration', description: 'Reads configuration values.', effects: ['read'], params: { pattern: P.str(128) } }),
    { verb: 'redis.publish', title: 'Publish to a channel', description: 'Sends a message to every subscriber of a channel.', effects: ['send'], res: ['redis.channel', 'one'], params: { channel: P.to({ role: 'contact.address' }), message: P.text(16_000_000) } },
    set({ verb: 'redis.flushdb', title: 'Delete every key in a database', description: 'Empties one logical database.', effects: ['delete'], params: { database: P.id('redis.server', { max_len: 8 }) } }),
    { verb: 'redis.flushall', title: 'Delete every key on the server', description: 'Empties every logical database.', effects: ['delete'], blast: { radius: 'global' }, res: ['redis.server', 'global'], params: {} },
    set({ verb: 'redis.config_set', title: 'Change server configuration', description: 'Changes configuration, including persistence paths and limits.', effects: ['update', 'privilege'], rev: 'rate_limited', params: { name: P.str(128), value: P.str(4096) } }),
    set({ verb: 'redis.eval', title: 'Run a Lua script', description: 'Runs a script on the server with access to all keys.', effects: ['exec', 'update', 'delete'], params: { script: P.code(), keys: P.opt(P.arr('string', 1000)) } }),
    set({ verb: 'redis.acl_setuser', title: 'Create or change an ACL user', description: 'Defines a user with permissions.', effects: ['privilege'], rev: 'rate_limited', traits: ['pca.credential_access'], params: { user: P.str(128), rules: P.arr('string', 128), password: P.opt(P.secret()) } }),
    set({ verb: 'redis.acl_deluser', title: 'Delete an ACL user', description: 'Removes a user.', effects: ['privilege', 'delete'], params: { user: P.str(128) } }),
    set({ verb: 'redis.replicaof', title: 'Change replication source', description: 'Makes the server replicate from another host, replacing its data.', effects: ['privilege', 'update', 'delete'], params: { host: P.str(255), port: P.int(1, 65_535) } }),
    { verb: 'redis.save', title: 'Write a snapshot to disk', description: 'Saves the dataset to the dump file.', effects: ['export'], res: ['redis.server', 'one'], params: { server: P.id('redis.server', { max_len: 255 }) } },
    set({ verb: 'redis.client_kill', title: 'Disconnect a client', description: 'Closes a client connection.', effects: ['delete'], rev: 'rate_limited', params: { client: P.str(128) } }),
    set({ verb: 'redis.shutdown', title: 'Shut the server down', description: 'Stops the server process.', effects: ['exec', 'privilege'], params: {} }),
  );
  return out;
})();

export default handPack({
  name: 'db',
  licence_notes: 'Written in-house from the public documentation of PostgreSQL, MySQL, SQLite, MongoDB and Redis, describing classes of operation; no vendor text or schema is carried.',
  config_file: __filename,
  sourceUri: 'in-repo:scripts/actions-packs/packs/db.ts',
  defs: [...SQL_ENGINES.flatMap(sqlFamily), ...MONGO, ...REDIS].map(def),
});
