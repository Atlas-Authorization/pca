import type { IntentOntology, OntParam } from '../ontology';
import { and, ban, cmp, cmpEnum, countCap, exact, grant } from './dsl';

const prot: OntParam = { kind: 'enum', values: ['yes', 'no'] };
const branch: OntParam = { kind: 'id', of: 'ref' };
export const code: IntentOntology = {
  id: 'atlas.code', version: 1, domain: 'code_repos',
  types: [{ id: 'repo', id_prefix: 'repo_' }, { id: 'ref', id_prefix: 'ref_' }],
  units: { count: { kind: 'count' } },
  relations: [],
  verbs: [
    { id: 'read_repo', effect: 'read', resource_type: 'repo', params: {} },
    { id: 'create_branch', effect: 'reversible', resource_type: 'repo', params: { branch } },
    { id: 'push', effect: 'reversible', resource_type: 'repo', params: { branch, protected: prot } },
    { id: 'merge', effect: 'irreversible', resource_type: 'repo', params: { branch, protected: prot } },
    { id: 'release', effect: 'external_send', resource_type: 'repo', params: {} },
    { id: 'delete_branch', effect: 'irreversible', resource_type: 'repo', params: { branch, protected: prot } },
  ],
  aliases: { clone: 'read_repo', fetch: 'read_repo', commit_and_push: 'push', publish: 'release', ship: 'release', remove_branch: 'delete_branch', open_branch: 'create_branch' },
  templates: [
    {
      id: 'fix_on_branch', title: 'Work on one feature branch (never protected)', phrases: ['push to branch', 'fix on branch', 'work on branch', 'work only on branch'],
      slots: [
        { name: 'repo', kind: 'id', of: 'repo', mandatory: true }, { name: 'branch', kind: 'id', of: 'ref', mandatory: true },
        { name: 'max_pushes', kind: 'count', mandatory: false, default: { n: 20 }, cue: ['up to', 'at most', 'max', 'no more than'], max: 200 },
      ],
      grants: [
        grant('read', 'read_repo', exact('repo')),
        grant('create', 'create_branch', exact('repo'), cmp('eq', 'branch', 'branch')),
        grant('push', 'push', exact('repo'), and(cmp('eq', 'branch', 'branch'), cmpEnum('eq', 'protected', 'no'))),
      ],
      prohibits: ban('merge', 'release', 'delete_branch'), bounds: [countCap('pushes', ['push'], 0, 'max_pushes')],
      example: { repo: 'repo_1', branch: 'ref_fix' },
    },
    {
      id: 'read_only_repo', title: 'Read one repository only', phrases: ['read the repo', 'read-only access to', 'look at the repo', 'read only'],
      slots: [{ name: 'repo', kind: 'id', of: 'repo', mandatory: true }],
      grants: [grant('read', 'read_repo', exact('repo'))],
      prohibits: ban('create_branch', 'push', 'merge', 'release', 'delete_branch'), bounds: [],
      example: { repo: 'repo_1' },
    },
    {
      id: 'merge_branch', title: 'Merge one non-protected branch', phrases: ['merge branch', 'merge the branch'],
      slots: [{ name: 'repo', kind: 'id', of: 'repo', mandatory: true }, { name: 'branch', kind: 'id', of: 'ref', mandatory: true }],
      grants: [grant('read', 'read_repo', exact('repo')), grant('merge', 'merge', exact('repo'), and(cmp('eq', 'branch', 'branch'), cmpEnum('eq', 'protected', 'no')))],
      prohibits: ban('release', 'delete_branch'), bounds: [countCap('one-merge', ['merge'], 1)],
      example: { repo: 'repo_1', branch: 'ref_fix' },
    },
  ],
};
