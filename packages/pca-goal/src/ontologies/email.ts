import type { IntentOntology } from '../ontology';
import { and, ban, cmp, countCap, exact, grant, related } from './dsl';

const LABELS = ['important', 'follow_up', 'receipts', 'newsletters', 'later'];
export const email: IntentOntology = {
  id: 'atlas.email', version: 1, domain: 'email',
  types: [{ id: 'mailbox', id_prefix: 'mb_' }, { id: 'thread', id_prefix: 'th_' }],
  units: { count: { kind: 'count' } },
  relations: [{ id: 'threads_of', from: 'mailbox', to: 'thread' }],
  verbs: [
    { id: 'read_thread', effect: 'read', resource_type: 'thread', params: {} },
    { id: 'label', effect: 'reversible', resource_type: 'thread', params: { label: { kind: 'enum', values: LABELS } } },
    { id: 'archive', effect: 'reversible', resource_type: 'thread', params: {} },
    { id: 'delete', effect: 'irreversible', resource_type: 'thread', params: {} },
    { id: 'send', effect: 'external_send', resource_type: 'thread', params: { to_domain: { kind: 'text' } } },
    { id: 'forward', effect: 'external_send', resource_type: 'thread', params: { to_domain: { kind: 'text' } } },
  ],
  aliases: { trash: 'delete', remove: 'delete', reply: 'send', respond: 'send', file_away: 'archive', tag: 'label', open: 'read_thread', read: 'read_thread' },
  templates: [
    {
      id: 'triage_inbox', title: 'Triage a mailbox: read, label, archive', phrases: ['triage my inbox', 'triage the inbox', 'organize my inbox', 'sort my inbox'],
      slots: [
        { name: 'mailbox', kind: 'id', of: 'mailbox', mandatory: true },
        { name: 'max_archive', kind: 'count', mandatory: false, default: { n: 200 }, cue: ['archive', 'up to', 'at most', 'max'], max: 5000 },
      ],
      grants: [grant('read', 'read_thread', related('threads_of', 'mailbox')), grant('label', 'label', related('threads_of', 'mailbox')), grant('archive', 'archive', related('threads_of', 'mailbox'))],
      prohibits: ban('delete', 'send', 'forward'), bounds: [countCap('archives', ['archive'], 0, 'max_archive')],
      example: { mailbox: 'mb_1' },
    },
    {
      id: 'reply_to_thread', title: 'Reply on one thread to listed domains', phrases: ['reply to thread', 'respond to thread', 'reply on thread'],
      slots: [
        { name: 'thread', kind: 'id', of: 'thread', mandatory: true },
        { name: 'domains', kind: 'text_list', mandatory: true },
        { name: 'max_sends', kind: 'count', mandatory: false, default: { n: 1 }, cue: ['up to', 'at most', 'max', 'no more than'], max: 20 },
      ],
      grants: [grant('read', 'read_thread', exact('thread')), grant('send', 'send', exact('thread'), cmp('in', 'to_domain', 'domains'))],
      prohibits: ban('delete', 'forward'), bounds: [countCap('sends', ['send'], 0, 'max_sends')],
      example: { thread: 'th_1', domains: ['example.com'] },
    },
    {
      id: 'archive_old', title: 'Archive threads of one mailbox (bounded)', phrases: ['archive old', 'archive everything in', 'clean up mailbox'],
      slots: [{ name: 'mailbox', kind: 'id', of: 'mailbox', mandatory: true }, { name: 'max_archive', kind: 'count', mandatory: true, cue: ['up to', 'at most', 'max', 'no more than', 'archive'], max: 5000 }],
      grants: [grant('archive', 'archive', related('threads_of', 'mailbox'))],
      prohibits: ban('delete', 'send', 'forward'), bounds: [countCap('archives', 'all', 0, 'max_archive')],
      example: { mailbox: 'mb_1', max_archive: { n: 50 } },
    },
  ],
};
void and; void cmp;
