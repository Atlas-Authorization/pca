import { domainVerbs } from '@atlasauth/pca-actions';
import type { IntentOntology } from '../ontology';
import { and, ban, cmp, cmpEnum, countCap, exact, grant } from './dsl';

const VERBS = domainVerbs('code_repos');
export const code: IntentOntology = {
  id: 'atlas.code', version: 1, domain: 'code_repos',
  types: [{ id: 'repo', id_prefix: 'repo_' }, { id: 'ref', id_prefix: 'ref_' }],
  units: { count: { kind: 'count' } },
  relations: [],
  // derived from the action definitions (@atlasauth/pca-actions): the effect class, parameter kinds and aliases are not written here
  verbs: VERBS.verbs,
  aliases: VERBS.aliases,
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
