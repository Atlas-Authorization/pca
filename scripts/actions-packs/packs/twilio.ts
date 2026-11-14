import { openApiPack } from '../lib/factory';
import { snake } from '../lib/naming';
import { readSources } from '../lib/source';

// Reviewed Twilio rules on the derived verb (first match wins). Verbs are twilio.<service>_<version>.<operation>.
const SEND = /\.(create_(message|call|conversation_message|notification|verification|participant_conversation|service_notification|binding)|send_\w+)$/;
const PAY = /\.(create_(incoming_phone_number|available_phone_number\w*|number_order|port_in_request|sim|esim_profile|hosted_number_order|regulatory\w*))$/;
const KEYS = /\.(create_(new_key|key|signing_key|credential|api_key|secret)|update_key)$/;
const ACCOUNTS = /\.(create_account|update_account|delete_account)$/;

export default openApiPack({
  name: 'twilio',
  ns: 'twilio',
  redistribution: 'permitted',
  licence_notes: 'Twilio publishes its OpenAPI descriptions (twilio/twilio-oai) under the MIT licence. Operation ids, parameter names/types/bounds and short summaries are carried; the trait review is ours.',
  config_file: __filename,
  oa: () => ({ naming: 'opid', flatten: true }),
  ops: (id, ops) => ops.map((o) => ({ ...o, path: [snake(id), ...o.path], bindings: { openapi: { ...o.bindings!.openapi!, operationId: `${id}:${o.opId}` } } })),
  build: () => ({
    ns: 'twilio',
    vendorTitles: true,
    rules: [
      { re: SEND, on: 'verb', patch: { effects: ['send'], rev: 'irreversible', recipient: 'To' } },
      { re: PAY, on: 'verb', patch: { effects: ['provision'], rev: 'rate_limited', traits: ['pca.cost_incurring'] } },
      { re: KEYS, on: 'verb', patch: { effects: ['create', 'privilege'], rev: 'rate_limited', traits: ['pca.credential_access'] } },
      { re: ACCOUNTS, on: 'verb', patch: { effects: ['privilege'], rev: 'irreversible' } },
    ],
  }),
});
void readSources;
