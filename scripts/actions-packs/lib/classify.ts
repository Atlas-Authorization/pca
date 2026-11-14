// classify.ts - the trait review engine: from an operation's HTTP method, action word and the nouns on its path to its
// effects, reversibility, scope and declared traits. Deliberately conservative: where the evidence is not unambiguous
// the verdict is `sure: false` and the def stays `unreviewed` (maximal floor). Pack configs add reviewed overrides.
import type { Effect } from '@atlasauth/pca-actions';
import { infer, wordsOf } from './infer';
import type { RawOp, Verdict } from './types';

const set = (s: string): ReadonlySet<string> => new Set(s.split(/\s+/).filter(Boolean));

// Action words (first token of the final verb segment).
const READ = set(`scan select get list retrieve search find fetch read describe query lookup check show view count exists head preview validate verify
  calculate estimate resolve suggest autocomplete compare diff history status stats statistics summary whoami introspect tail poll peek inspect
  discover lint batch_get metrics usage report logs log related`);
const CREATE = set(`create add new insert register open make build generate upload import clone fork copy duplicate append enroll compose write
  record log_event track submit quick_add`);
const UPDATE = set(`update edit patch set modify rename move change replace enable disable activate deactivate pause resume reorder mark archive
  unarchive pin unpin star unstar subscribe unsubscribe follow unfollow lock unlock merge reopen close assign unassign label unlabel tag untag sync put start stop reboot associate disassociate rotate receive sign_out sign_in turn_off turn_on turn_in
  refresh restore undelete untrash accept decline reject dismiss hide unhide toggle apply bump snooze resend_verification rotate_noop touch put reset
  convert cancel_noop link unlink attach rebase react unreact vote mute unmute watch_noop read_mark mark_read mark_unread star_noop select
  reply_noop reschedule extend renew upgrade downgrade select_noop`);
const DELETE = set(`delete deprovision remove kick release destroy drop purge erase wipe clear empty detach cancel terminate uninstall disconnect leave kill expire
  deregister unregister truncate cleanup prune trash discard abort delist void retract withdraw_noop unpublish unshare_noop`);
const SEND = set(`send notify email message mail sms broadcast invite remind text dm forward page alert push post_message`);
const PUBLISH = set(`publish announce tweet`);
const PAY = set(`pay refund charge payout capture disburse topup deposit settle chargeback purchase buy`);
const EXEC = set(`run execute exec trigger dispatch invoke deploy rerun rebuild eval launch spawn enqueue evaluate`);
const PRIV = set(`revoke grant authorize deauthorize impersonate assume elevate promote demote ban unban block unblock suspend unsuspend allow deny
  transfer_ownership share unshare approve_access`);
const EXPORT = set(`export download dump backup takeout`);
const SIGN = set(`sign esign certify attest countersign`);

const NOUN_PRIV = set(`permission permissions role roles collaborator collaborators member members membership memberships access acl acls policy
  policies grant grants admin admins invitation invitations iam sso saml scim protection ruleset rulesets restrictions allowlist`);
const NOUN_CRED = set(`secret secrets password passwords credential credentials private_key api_key api_keys access_key access_keys ssh_key ssh_keys
  deploy_key deploy_keys gpg_key gpg_keys signing_key signing_keys client_secret client_secrets token tokens`);
const READ_CRED = set(`secret secrets password passwords credential credentials private_key client_secret`);
const BULK = set(`bulk batch many all multiple mass`);
const TRASH = set(`archive trash soft restorable`);

export const tokens = (s: string): string[] => s.split(/[^a-z0-9]+/).filter(Boolean);

/** The first token of the action segment, with a two-word look-ahead for compound words in the tables (batch_get, post_message). */
function actionWord(seg: string): string {
  let t = tokens(seg);
  if (t.length === 0) return '';
  // 'batch_delete', 'bulk_update': the verb after the batch marker is the action
  if (t.length > 1 && ['batch', 'bulk', 'mass', 'permanent', 'permanently', 'hard', 'force', 'soft'].includes(t[0]!) && !READ.has(`${t[0]}_${t[1]}`)) t = t.slice(1);
  const two = `${t[0]}_${t[1] ?? ''}`;
  if (t.length > 1 && (READ.has(two) || SEND.has(two) || PRIV.has(two) || UPDATE.has(two) || CREATE.has(two) || DELETE.has(two))) return two;
  return t[0]!;
}

function baseOf(a: string, m: string | undefined, kind: string | undefined): { effects: Effect[]; sure: boolean; why: string } {
  if (SIGN.has(a)) return { effects: ['sign'], sure: true, why: `action word '${a}' signs` };
  if (PAY.has(a)) return { effects: ['pay'], sure: true, why: `action word '${a}' moves money` };
  if (EXEC.has(a)) return { effects: ['exec'], sure: true, why: `action word '${a}' runs something` };
  if (SEND.has(a)) return { effects: ['send'], sure: true, why: `action word '${a}' sends` };
  if (PUBLISH.has(a)) return { effects: ['publish'], sure: true, why: `action word '${a}' publishes` };
  if (EXPORT.has(a)) return { effects: ['export'], sure: true, why: `action word '${a}' exports data` };
  if (PRIV.has(a)) return { effects: ['privilege'], sure: true, why: `action word '${a}' changes access` };
  if (DELETE.has(a)) return { effects: ['delete'], sure: true, why: `action word '${a}' removes` };
  if (m === 'DELETE') return { effects: ['delete'], sure: true, why: 'HTTP DELETE' };
  if (CREATE.has(a)) return { effects: ['create'], sure: true, why: `action word '${a}' creates` };
  if (UPDATE.has(a)) return { effects: ['update'], sure: true, why: `action word '${a}' updates` };
  if (READ.has(a)) return { effects: ['read'], sure: true, why: `action word '${a}' reads` };
  if (m === 'GET' || m === 'HEAD') return { effects: ['read'], sure: true, why: 'HTTP GET' };
  if (kind === 'query') return { effects: ['read'], sure: true, why: 'GraphQL query' };
  if (m === 'PUT' || m === 'PATCH') return { effects: ['update'], sure: true, why: `HTTP ${m}` };
  return { effects: ['update'], sure: false, why: `unrecognised action word '${a}'` };
}

/** Classify an operation. `ns` is the pack namespace (not read; kept for rule predicates). */
const HTTPISH = new Set(['post', 'put', 'patch']); // not GET: `export.get` is a read of the export, not an export
/** `soft`: apply the inferences whose effect can break a required parameter rule; with `soft: false` they only mark the verdict unsure. */
export function classify(op: RawOp, o: { soft?: boolean } = {}): Verdict {
  const soft = o.soft ?? true;
  let seg = op.path[op.path.length - 1] ?? '';
  // a trailing bare HTTP method name ('...delete_bastion_shareable_link.post') leaves a delete in the segment before it
  if (HTTPISH.has(seg) && op.path.length > 1 && DELETE.has(tokens(op.path[op.path.length - 2]!)[0] ?? '')) seg = op.path[op.path.length - 2]!;
  const a = actionWord(seg);
  const m = op.method;
  const nouns = new Set<string>([...op.path.slice(0, -1).flatMap(tokens), ...tokens(seg).slice(1), ...op.tags.flatMap((t) => tokens(t.toLowerCase()))]);
  const nounJoined = new Set<string>(nouns);
  for (const n of [...nouns]) nounJoined.add(n.endsWith('s') ? n.slice(0, -1) : `${n}s`);
  // compound nouns (ssh_key) appear as adjacent tokens
  const all = [...op.path.flatMap(tokens)];
  for (let i = 0; i + 1 < all.length; i++) nounJoined.add(`${all[i]}_${all[i + 1]}`);

  let { effects, sure, why } = baseOf(a, m, op.kind);
  // a GET that names a write word is a side-effecting GET: treat it as that write, but never "sure"
  if ((m === 'GET' || m === 'HEAD') && !effects.includes('read')) sure = false;
  // POST with a search-like action word is a read (handled by READ); an unknown POST noun-led name stays unsure
  const traits: string[] = [];
  const baseSends = effects.includes('send'); // a send by action word; an inferred send does not hide the privilege noun
  const inf = infer(wordsOf(...op.path, (op.httpPath ?? '').replace(/\{[^}]*\}/g, ' '), op.opId ?? ''), effects, op.params.map((p) => p.name.split('.').pop()!), a);
  const useInf = !inf.soft || soft;
  if (useInf) effects = [...effects, ...inf.effects];
  traits.push(...inf.traits);
  if (inf.soft && !soft) sure = false;
  const write = !effects.every((e) => e === 'read');
  if (write) {
    const priv = [...nounJoined].some((n) => NOUN_PRIV.has(n));
    if (priv && !effects.includes('privilege') && !baseSends) { effects = [...effects, 'privilege']; why += '; privilege noun on path'; }
    if ([...nounJoined].some((n) => NOUN_CRED.has(n)) && !traits.includes('pca.credential_access')) { traits.push('pca.credential_access'); why += '; credential noun on path'; }
  } else if ([...nounJoined].some((n) => READ_CRED.has(n))) {
    traits.push('pca.credential_access');
    why += '; reads a secret noun';
  }
  const bulk = [...nounJoined].some((n) => BULK.has(n)) || tokens(seg).some((t) => BULK.has(t));
  // a destructive op on a collection (no trailing id) acts on a set
  const trailingId = op.params.some((p) => p.where === 'path');
  const scope = bulk || (!trailingId && op.method === 'DELETE') ? 'set' : 'one';
  const trashy = tokens(seg).some((t) => TRASH.has(t));
  const e = new Set(effects);
  const rev = e.has('send') || e.has('pay') || e.has('publish') || e.has('exec') || e.has('sign') || e.has('export') ? 'irreversible'
    : e.has('delete') ? (trashy ? 'rate_limited' : 'irreversible')
    : e.has('privilege') ? 'rate_limited'
    : e.has('update') ? 'rate_limited'
    : 'reversible';
  return { effects, rev, scope, traits, sure, why: inf.why.length ? `${why}; inferred: ${inf.why.join(', ')}` : why, ...(inf.effects.length && useInf ? { inferred: inf.effects } : {}), ...(inf.soft ? { soft: true } : {}) };
}

/** Is `t` a recognised action word (used by the path-name derivation to tell an action segment from a noun)? */
export const isActionWord = (t: string): boolean =>
  [READ, CREATE, UPDATE, DELETE, SEND, PUBLISH, PAY, EXEC, PRIV, EXPORT, SIGN].some((s) => s.has(t));
