import type { IntentOntology, OntParam } from '../ontology';
import { and, ban, cmp, cmpEnum, countCap, exact, grant, inEnum } from './dsl';

const cls: OntParam = { kind: 'enum', values: ['public', 'internal', 'pii'] };
const purpose: OntParam = { kind: 'enum', values: ['analytics', 'support', 'research', 'marketing'] };
const rows = { kind: 'count' } as const;
export const data: IntentOntology = {
  id: 'atlas.data', version: 1, domain: 'data_access',
  types: [{ id: 'dataset', id_prefix: 'ds_' }],
  units: { count: { kind: 'count' } },
  relations: [],
  verbs: [
    { id: 'query', effect: 'read', resource_type: 'dataset', params: { column_class: cls, rows, purpose } },
    { id: 'export', effect: 'external_send', resource_type: 'dataset', params: { column_class: cls, rows, purpose } },
    { id: 'delete_dataset', effect: 'irreversible', resource_type: 'dataset', params: {} },
  ],
  aliases: { select: 'query', read_rows: 'query', download: 'export', dump: 'export', drop: 'delete_dataset', purge: 'delete_dataset' },
  templates: [
    {
      id: 'analytics_query', title: 'Query a dataset (non-PII, row-limited)', phrases: ['analytics on', 'run a query on', 'query the dataset', 'analyze dataset'],
      slots: [
        { name: 'dataset', kind: 'id', of: 'dataset', mandatory: true },
        { name: 'max_rows', kind: 'count', mandatory: true, cue: ['up to', 'at most', 'max', 'no more than', 'rows'], max: 1_000_000 },
        { name: 'max_queries', kind: 'count', mandatory: false, default: { n: 100 }, cue: ['queries'], max: 10_000 },
      ],
      grants: [grant('query', 'query', exact('dataset'), and(inEnum('column_class', ['public', 'internal']), cmp('lte', 'rows', 'max_rows')))],
      prohibits: ban('export', 'delete_dataset'), bounds: [countCap('queries', 'all', 0, 'max_queries')],
      example: { dataset: 'ds_1', max_rows: { n: 1000 } },
    },
    {
      id: 'export_aggregate', title: 'Export public aggregates for one purpose', phrases: ['export aggregate', 'export summary', 'export aggregated'],
      slots: [
        { name: 'dataset', kind: 'id', of: 'dataset', mandatory: true },
        { name: 'purpose', kind: 'enum', values: ['analytics', 'support', 'research', 'marketing'], mandatory: true },
        { name: 'max_rows', kind: 'count', mandatory: true, cue: ['up to', 'at most', 'max', 'no more than', 'rows'], max: 100_000 },
      ],
      grants: [grant('export', 'export', exact('dataset'), and(cmpEnum('eq', 'column_class', 'public'), cmp('eq', 'purpose', 'purpose'), cmp('lte', 'rows', 'max_rows')))],
      prohibits: ban('delete_dataset'), bounds: [countCap('one-export', 'all', 1)],
      example: { dataset: 'ds_1', purpose: 'research', max_rows: { n: 500 } },
    },
    {
      id: 'delete_one_dataset', title: 'Delete one dataset', phrases: ['delete dataset', 'delete the dataset', 'purge dataset'],
      slots: [{ name: 'dataset', kind: 'id', of: 'dataset', mandatory: true }],
      grants: [grant('delete', 'delete_dataset', exact('dataset'))],
      prohibits: ban('export'), bounds: [countCap('once', 'all', 1)],
      example: { dataset: 'ds_1' },
    },
  ],
};
