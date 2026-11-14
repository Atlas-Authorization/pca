// gen-corpus.ts - generate the synthetic part of the suggestion corpus (corpus/synthetic.jsonl). Seeded and deterministic:
// `--check` fails if the committed file differs from a fresh generation. Labels come from the LEXICON below (what an operation
// with that verb and object can do), which is written independently of `suggest-rules.json`: the lexicon deliberately uses
// synonyms and phrasings the rules do not cover (so recall is measured, not assumed) and benign decoys that contain risky
// words (so precision is measured). The synthetic entries are reported separately from the hand-labeled ones.

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

type Kind = 'openapi' | 'mcp' | 'graphql' | 'grpc' | 'asyncapi';
interface Row { id: string; src: 'syn'; kind: Kind; name: string; method?: string; path?: string; params: string[]; labels: string[]; description: string }

// mulberry32
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const R = rng(20261026);
const pick = <T,>(xs: readonly T[]): T => xs[Math.floor(R() * xs.length)]!;
const chance = (p: number): boolean => R() < p;

const words = (s: string): string[] => s.replace(/[^A-Za-z0-9 _-]/g, '').split(/[ _-]+/).filter(Boolean);
const cap = (s: string): string => s.charAt(0).toUpperCase() + s.slice(1);
const camel = (s: string): string => words(s).map((w, i) => (i === 0 ? w : cap(w))).join('');
const pascal = (s: string): string => words(s).map(cap).join('');
const snake = (s: string): string => words(s).join('_');
const plural = (s: string): string => (s.endsWith('y') ? s.slice(0, -1) + 'ies' : s.endsWith('s') ? s : s + 's');
const slug = (s: string): string => words(s).join('-');

interface Cat {
  labels: string[];
  verbs: string[];
  objects: string[];
  params: string[][];
  n: number;
  /** HTTP method choice for the openapi style. */
  methods: string[];
  /** words that follow the object in the name some of the time (suffix) */
  describe: (v: string, o: string) => string;
}

const MONEY_OBJ = ['order', 'invoice', 'subscription', 'customer', 'account', 'wallet', 'merchant', 'vendor', 'employee', 'claim', 'deposit', 'escrow', 'balance', 'card', 'booking', 'contractor', 'seller', 'tenant', 'donor'];
const CATS: Cat[] = [
  { labels: ['money_moving'], n: 190, methods: ['POST', 'POST', 'PUT'], describe: (v, o) => `${cap(v)} funds for a ${o}`,
    verbs: ['refund', 'payout', 'wire', 'remit', 'reimburse', 'disburse', 'settle', 'pay out', 'charge', 'pay', 'tip', 'top up', 'fund', 'cash out', 'send money to', 'transfer funds to', 'redeem', 'issue refund for', 'process payment for', 'initiate wire for', 'reload', 'bill', 'debit', 'credit', 'purchase for', 'checkout', 'donate to', 'compensate', 'rebate', 'drawdown'],
    objects: MONEY_OBJ, params: [['amount:integer', 'currency:string', 'account:string'], ['amount:integer', 'currency:string'], ['account:string', 'reference:string'], ['id:string', 'amount:integer'], ['customer:string', 'amount:integer', 'currency:string']] },
  { labels: ['destructive'], n: 230, methods: ['DELETE', 'DELETE', 'POST', 'POST', 'PUT'], describe: (v, o) => `${cap(v)} a ${o}`,
    verbs: ['delete', 'remove', 'destroy', 'drop', 'erase', 'purge', 'terminate', 'revoke', 'cancel', 'kill', 'tear down', 'obliterate', 'discard', 'expunge', 'shred', 'trash', 'decommission', 'nuke', 'hard delete', 'wipe', 'unlink permanently', 'deprovision', 'dispose of', 'evict', 'blow away', 'zap'],
    objects: ['user', 'project', 'record', 'bucket', 'database', 'workspace', 'repository', 'token', 'key', 'branch', 'table', 'cluster', 'volume', 'snapshot', 'webhook', 'session', 'file', 'folder', 'comment', 'team', 'queue', 'index', 'topic', 'dashboard', 'environment', 'instance', 'domain', 'template'], params: [['id:string'], ['name:string', 'force:boolean'], ['ids:array'], ['id:string', 'confirm:boolean'], ['resource:string']] },
  { labels: ['external_communication'], n: 210, methods: ['POST', 'POST', 'PUT'], describe: (v, o) => `${cap(v)} a ${o}`,
    verbs: ['send', 'notify', 'email', 'text', 'message', 'announce to', 'broadcast to', 'invite', 'ping', 'alert', 'page', 'reply to', 'forward to', 'dm', 'post to', 'tweet at', 'dispatch to', 'push notification to', 'remind', 'nudge', 'cc', 'whisper to', 'shout at', 'mail', 'sms', 'contact', 'write to', 'respond to', 'follow up with', 'greet'],
    objects: ['customer', 'user', 'team', 'channel', 'subscriber', 'member', 'contact', 'thread', 'group', 'client', 'lead', 'attendee', 'candidate', 'partner', 'follower', 'supplier'], params: [['to:string', 'subject:string', 'body:string'], ['channel:string', 'text:string'], ['recipient:string', 'message:string'], ['user_id:string', 'content:string'], ['recipients:array', 'text:string']] },
  { labels: ['privilege_change'], n: 170, methods: ['POST', 'PUT', 'PATCH'], describe: (v, o) => `${cap(v)} access for a ${o}`,
    verbs: ['grant', 'assign', 'elevate', 'promote', 'add to group', 'share', 'set role of', 'change permission of', 'make admin', 'delegate', 'authorize', 'allow access to', 'whitelist', 'add collaborator to', 'update acl of', 'attach policy to', 'bind role to', 'entitle', 'enroll in admin', 'give access to', 'deputize', 'trust'],
    objects: ['user', 'member', 'group', 'role', 'project', 'document', 'repo', 'org', 'service account', 'folder', 'bucket', 'api', 'tenant', 'workspace', 'team'], params: [['user_id:string', 'role:string'], ['member:string', 'permission:string'], ['principal:string', 'resource:string'], ['id:string', 'level:string'], ['subject:string', 'scope:string']] },
  { labels: ['data_export'], n: 120, methods: ['GET', 'POST'], describe: (v, o) => `${cap(v)} ${plural(o)}`,
    verbs: ['export', 'download', 'dump', 'backup', 'extract', 'generate report of', 'archive', 'snapshot', 'bulk download', 'pull all', 'save as csv', 'mirror', 'copy out', 'take a copy of', 'ship out', 'offload', 'save a copy of', 'retrieve everything about'],
    objects: ['contacts', 'orders', 'users', 'records', 'logs', 'transactions', 'documents', 'database', 'mailbox', 'analytics', 'audit log', 'customers', 'messages', 'files', 'tickets', 'metrics history'], params: [['format:string', 'since:string'], ['dataset:string'], ['id:string', 'destination:string'], ['filter:string', 'format:string'], ['from:string', 'to:string']] },
  { labels: ['code_execution'], n: 170, methods: ['POST', 'POST', 'PUT'], describe: (v, o) => `${cap(v)} a ${o}`,
    verbs: ['run', 'execute', 'exec', 'invoke', 'eval', 'deploy', 'build', 'trigger', 'launch', 'run script in', 'apply', 'compile', 'start', 'schedule run of', 'call', 'evaluate', 'kick off', 'fire', 'spin up', 'submit', 'dispatch run of', 'play'],
    objects: ['script', 'command', 'workflow', 'pipeline', 'function', 'notebook', 'job', 'query', 'macro', 'task', 'container', 'build', 'lambda', 'plugin', 'shell', 'snippet', 'batch job', 'action'], params: [['command:string'], ['script:string', 'args:array'], ['id:string'], ['payload:string'], ['code:string'], ['source:string', 'language:string']] },
  { labels: ['credential_access'], n: 120, methods: ['GET', 'POST', 'POST'], describe: (v, o) => `${cap(v)} a ${o}`,
    verbs: ['get', 'read', 'create', 'rotate', 'reveal', 'export', 'fetch', 'show', 'mint', 'issue', 'reset', 'regenerate', 'decrypt', 'unseal', 'retrieve', 'unlock'],
    objects: ['secret', 'api key', 'token', 'password', 'credential', 'private key', 'client secret', 'access token', 'ssh key', 'certificate', 'passphrase', 'session token', 'signing key', 'webhook secret', 'recovery code', 'vault entry', 'keychain item', 'otp seed', 'bearer credential', 'jwt', 'hmac secret'], params: [['name:string'], ['id:string'], ['scope:string', 'ttl:integer'], ['user_id:string'], ['path:string']] },
  { labels: ['bulk'], n: 80, methods: ['POST', 'PATCH', 'PUT'], describe: (v, o) => `${cap(v)} many ${plural(o)} at once`,
    verbs: ['batch update', 'bulk tag', 'mass label', 'batch move', 'bulk import', 'mass archive', 'batch sync', 'update many', 'bulk reassign', 'batch retag', 'mass update', 'bulk edit', 'tag multiple', 'update multiple', 'sweep and relabel', 'en masse rename'],
    objects: ['users', 'records', 'items', 'tickets', 'products', 'contacts', 'tasks', 'files', 'orders', 'rows', 'entries', 'documents'], params: [['ids:array'], ['items:array', 'tag:string'], ['filter:string', 'value:string'], ['query:string']] },
  { labels: ['public_exposure'], n: 80, methods: ['POST', 'PUT', 'PATCH'], describe: (v, o) => `${cap(v)} a ${o}`,
    verbs: ['publish', 'make public', 'expose', 'release', 'go live with', 'share publicly', 'post publicly', 'set public', 'open to the web', 'unrestrict', 'list publicly', 'syndicate', 'put online', 'promote to production'],
    objects: ['page', 'post', 'repo', 'bucket', 'document', 'dashboard', 'site', 'link', 'profile', 'album', 'snippet', 'release notes', 'video', 'form', 'calendar'], params: [['id:string'], ['id:string', 'visibility:string'], ['slug:string']] },
  { labels: ['infra_mutation'], n: 80, methods: ['POST', 'PUT', 'PATCH'], describe: (v, o) => `${cap(v)} a ${o}`,
    verbs: ['scale', 'restart', 'reboot', 'resize', 'reconfigure', 'migrate', 'failover', 'rollback', 'reprovision', 'drain', 'cordon', 'reroute', 'repoint', 'detach', 'attach', 'peer'],
    objects: ['cluster', 'instance', 'vpc', 'firewall', 'dns record', 'load balancer', 'node pool', 'namespace', 'volume', 'subnet', 'gateway', 'autoscaler', 'database instance', 'route table'], params: [['id:string', 'size:string'], ['name:string', 'replicas:integer'], ['id:string'], ['config:string']] },
  { labels: ['cost_incurring'], n: 50, methods: ['POST'], describe: (v, o) => `${cap(v)} a ${o} (billable)`,
    verbs: ['launch', 'provision', 'order', 'subscribe to', 'buy', 'upgrade', 'allocate', 'reserve', 'rent', 'commit to', 'book', 'purchase capacity for', 'spin up paid'],
    objects: ['gpu instance', 'plan', 'license', 'seat', 'domain', 'phone number', 'reserved capacity', 'storage tier', 'support package', 'ad campaign', 'ml training run'], params: [['plan:string'], ['quantity:integer'], ['type:string', 'region:string'], ['sku:string']] },
  { labels: ['legal_binding'], n: 40, methods: ['POST', 'PUT'], describe: (v, o) => `${cap(v)} a ${o}`,
    verbs: ['sign', 'e-sign', 'accept', 'countersign', 'attest', 'consent to', 'ratify', 'execute (legal)', 'notarize', 'agree to', 'certify', 'bind'],
    objects: ['contract', 'agreement', 'terms of service', 'nda', 'order form', 'declaration', 'filing', 'statement of work', 'lease', 'waiver'], params: [['id:string'], ['document:string', 'signer:string'], ['version:string']] },
  { labels: ['network_egress'], n: 70, methods: ['POST', 'GET', 'PUT'], describe: (v, o) => `${cap(v)} ${o} (reaches out)`,
    verbs: ['register', 'fetch', 'crawl', 'proxy', 'scrape', 'call out to', 'subscribe a callback for', 'pull from', 'poll', 'forward request to', 'hit', 'download from', 'connect to', 'tunnel to'],
    objects: ['webhook', 'url', 'callback', 'remote endpoint', 'feed', 'external api', 'remote host', 'rss source', 'third party', 'link preview'], params: [['url:string'], ['callback_url:string', 'events:array'], ['endpoint:string'], ['target_url:string', 'method:string']] },
  { labels: ['scheduled', 'persistence'], n: 40, methods: ['POST', 'PUT'], describe: (v, o) => `${cap(v)} a ${o}`,
    verbs: ['schedule', 'cron', 'set up recurring', 'install', 'register permanent', 'enable autostart for', 'create standing', 'configure repeating', 'add startup', 'persist'],
    objects: ['job', 'task', 'report', 'rule', 'trigger', 'backup', 'sync', 'daemon', 'agent', 'automation'], params: [['cron:string'], ['schedule:string', 'id:string'], ['interval:integer']] },
  { labels: ['pii_access'], n: 100, methods: ['GET', 'GET', 'POST'], describe: (v, o) => `${cap(v)} ${o} details`,
    verbs: ['get', 'list', 'find', 'search', 'lookup', 'read', 'show', 'fetch', 'query', 'view', 'look up', 'browse', 'open'],
    objects: ['customer', 'user', 'contact', 'employee', 'subscriber', 'lead', 'applicant', 'member', 'profile', 'address book', 'candidate', 'person', 'student', 'donor'], params: [['id:string'], ['email:string'], ['query:string', 'limit:integer'], ['limit:integer']] },
  { labels: ['pii_access', 'regulated_data'], n: 40, methods: ['GET', 'POST'], describe: (v, o) => `${cap(v)} ${o} records (health)`,
    verbs: ['get', 'list', 'read', 'search', 'fetch', 'update', 'open'],
    objects: ['patient', 'medical record', 'diagnosis', 'prescription', 'lab result', 'clinical note', 'health record', 'insurance claim', 'immunization record'], params: [['id:string'], ['patient_id:string'], ['query:string']] },
  { labels: ['financial_data_read'], n: 60, methods: ['GET', 'GET', 'POST'], describe: (v, o) => `${cap(v)} ${o}`,
    verbs: ['get', 'list', 'read', 'fetch', 'show', 'download statement for', 'query', 'view'],
    objects: ['balance', 'ledger', 'statement', 'transactions', 'payouts', 'invoices', 'revenue report', 'billing history', 'cash position', 'account summary', 'tax summary', 'expenses'], params: [['account:string'], ['from:string', 'to:string'], ['limit:integer'], ['id:string']] },
  { labels: ['agent_spawning'], n: 30, methods: ['POST'], describe: (v, o) => `${cap(v)} a ${o}`,
    verbs: ['spawn', 'start', 'create', 'launch', 'fork', 'delegate to', 'orchestrate', 'hire'],
    objects: ['sub agent', 'worker agent', 'assistant', 'agent run', 'swarm', 'delegate', 'autonomous task', 'crew'], params: [['task:string'], ['prompt:string', 'tools:array'], ['id:string']] },
  { labels: ['impersonation'], n: 25, methods: ['POST'], describe: (v, o) => `${cap(v)} ${o}`,
    verbs: ['impersonate', 'act as', 'sudo as', 'assume role of', 'login as', 'masquerade as', 'switch to', 'borrow identity of'],
    objects: ['user', 'service account', 'admin', 'customer', 'tenant owner'], params: [['user_id:string'], ['target:string', 'reason:string']] },
];

// benign operations, and decoys that contain risky words but do nothing risky
const BENIGN_VERBS = ['get', 'list', 'find', 'search', 'count', 'describe', 'show', 'lookup', 'check', 'validate', 'preview', 'calculate', 'estimate', 'convert', 'format', 'rename', 'tag', 'label', 'star', 'favorite', 'bookmark', 'pin', 'mark read', 'reorder', 'resize', 'duplicate', 'compare', 'summarize', 'sort', 'filter'];
const BENIGN_OBJECTS = ['weather', 'status', 'version', 'schema', 'metadata', 'config', 'health', 'metrics', 'docs', 'catalog', 'product', 'category', 'price list', 'currency rate', 'time zone', 'feature flags', 'tags', 'labels', 'bookmark', 'playlist', 'recipe', 'map tile', 'thumbnail', 'stock level', 'shipping estimate', 'tax rate', 'color palette', 'font', 'emoji', 'locale', 'sitemap', 'changelog', 'quota', 'translation', 'timezone offset'];
const DECOYS = ['list refund reasons', 'get charge categories', 'preview email template', 'list role names', 'get payment terms', 'get send time estimate', 'list export formats', 'get delete policy', 'list token types', 'get notification settings', 'show password requirements', 'list invoice templates', 'get transfer limits', 'check permission support', 'get webhook event types', 'list admin contacts', 'get publish schedule', 'show backup status', 'get key rotation policy', 'list message templates', 'describe execution environment', 'get run history summary', 'list supported payment methods', 'get billing cycle info', 'show terms version', 'list bulk limits', 'get batch size limits', 'show public holidays', 'list member count', 'get owner display name', 'list command palette entries', 'get script language list', 'show session timeout setting', 'get cost estimate', 'list subscription tiers', 'show wire format', 'get oauth provider list', 'list sign in methods', 'show consent text', 'get build status badge', 'check deploy window', 'list allowed senders', 'list invite templates', 'get email delivery stats', 'show message length limit'];

const rows: Row[] = [];
const seen = new Set<string>();

function style(kind: Kind, phrase: string, object: string, cat: Cat | null, labels: string[], params: string[], method: string): Row | null {
  const full = `${phrase} ${object}`.trim();
  let name: string;
  let path: string | undefined;
  if (kind === 'openapi') {
    // verbs ending in a preposition ("send money to") keep it out of the id
    name = pascal(full.replace(/ (to|for|of|in|at|with|from|as|on)$/, '')) ;
    const obj = slug(plural(object));
    const verbSlug = slug(phrase.replace(/ (to|for|of|in|at|with|from|as|on)$/, ''));
    const withId = method === 'DELETE' || method === 'PATCH' || (method !== 'POST' && chance(0.5)) || chance(0.3);
    path = `/${pick(['v1', 'v2', 'api', 'v1'])}/${obj}${withId ? '/{id}' : ''}${method === 'POST' && chance(0.6) && cat !== null && !['DELETE'].includes(method) ? `/${verbSlug}` : ''}`.replace('/api/', '/api/v1/');
  } else if (kind === 'mcp') name = snake(full.replace(/ (to|for|of|in|at|with|from|as|on)$/, ''));
  else if (kind === 'graphql') name = camel(full.replace(/ (to|for|of|in|at|with|from|as|on)$/, ''));
  else if (kind === 'grpc') name = `${pascal(object)}Service/${pascal(phrase.replace(/ (to|for|of|in|at|with|from|as|on)$/, ''))}${pascal(object)}`;
  else name = `${slug(plural(object))}/${slug(phrase.replace(/ (to|for|of|in|at|with|from|as|on)$/, ''))}`;
  const key = `${kind}:${name}`;
  if (seen.has(key) || (kind === 'openapi' && seen.has(`path:${method} ${path}`))) return null;
  seen.add(key);
  if (path !== undefined) seen.add(`path:${method} ${path}`);
  return {
    id: `syn-${String(rows.length + 1).padStart(5, '0')}`, src: 'syn', kind, name,
    ...(kind === 'openapi' ? { method, path } : {}),
    params, labels: [...new Set(kind === 'asyncapi' ? [...labels, 'external_communication'] : labels)].sort(), description: cat ? cat.describe(phrase, object) : `${cap(full)}`,
  };
}
const KINDS: Kind[] = ['openapi', 'openapi', 'openapi', 'openapi', 'openapi', 'openapi', 'mcp', 'mcp', 'graphql', 'grpc', 'asyncapi'];

for (const cat of CATS) {
  let made = 0, guard = 0;
  while (made < cat.n && guard++ < cat.n * 40) {
    const phrase = pick(cat.verbs);
    const object = pick(cat.objects);
    const kind = pick(KINDS);
    const method = kind === 'openapi' ? pick(cat.methods) : 'POST';
    const params = pick(cat.params);
    const row = style(kind, phrase, object, cat, cat.labels, params, method);
    if (row) { rows.push(row); made++; }
  }
}
// benign: ordinary reads and writes
for (let made = 0, guard = 0; made < 330 && guard++ < 20000;) {
  const v = pick(BENIGN_VERBS), o = pick(BENIGN_OBJECTS), kind = pick(KINDS);
  const read = ['get', 'list', 'find', 'search', 'count', 'describe', 'show', 'lookup', 'check', 'validate', 'preview', 'calculate', 'estimate', 'convert', 'format', 'compare', 'summarize', 'sort', 'filter'].includes(v);
  const method = read ? 'GET' : pick(['POST', 'PUT', 'PATCH']);
  const row = style(kind, v, o, null, [], pick([['id:string'], ['q:string', 'limit:integer'], ['name:string'], ['locale:string']]), method);
  if (row) { rows.push(row); made++; }
}
// decoys: risky words, no risky action
for (const d of DECOYS) {
  for (const kind of ['openapi', 'mcp', 'graphql'] as Kind[]) {
    if (!chance(0.8)) continue;
    const row = style(kind, d, '', null, [], pick([['id:string'], ['limit:integer'], []]), 'GET');
    if (row) rows.push(row);
  }
}

const out = rows.map((r) => JSON.stringify(r)).join('\n') + '\n';
const file = join(__dirname, '..', 'corpus', 'synthetic.jsonl');
if (process.argv.includes('--check')) {
  let cur = '';
  try { cur = readFileSync(file, 'utf8'); } catch { /* missing */ }
  if (cur !== out) { console.error('corpus/synthetic.jsonl is not a fresh generation; run scripts/gen-corpus.ts'); process.exit(1); }
  console.log(`corpus/synthetic.jsonl is current (${rows.length} entries)`);
} else {
  writeFileSync(file, out);
  console.log(`wrote ${rows.length} entries to corpus/synthetic.jsonl`);
}
