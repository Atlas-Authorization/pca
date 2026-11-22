import type { IntentOntology } from '../ontology';
import { code } from './code';
import { data } from './data';
import { email } from './email';
import { payments } from './payments';
import { travel } from './travel';

export { code, data, email, payments, travel };
export const ALL_ONTOLOGIES: Record<string, IntentOntology> = { payments, email, calendar_travel: travel, code_repos: code, data_access: data };
