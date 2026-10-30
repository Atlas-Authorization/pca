import { discoveryPack } from '../lib/factory';
import { readSources } from '../lib/source';

// Reviewed Google Workspace rules on the derived verb (first match wins).
// Gmail's recipients are inside the raw RFC 822 message (or the draft's message object), so that parameter carries the recipient role.
const GMAIL_SEND = /^gmail\.(messages|drafts)\.send$/;
const CHAT_SEND = /^chat\.spaces\.messages\.create$/;
const WATCH = /(^|\.)watch$/; // opens a push channel to a caller-supplied address
const STOP = /(^|\.)channels\.stop$|^gmail\.stop$/;
const READ_CONTENT = /^(drive\.files\.(export|generate_ids)|chat\.media\.download|keep\.media\.download)$/;
const PRIV = /^(directory\.two_step_verification\.turn_off|cloudidentity\.devices\.device_users\.(approve|block)|calendar\.calendars\.transfer_ownership)$/;
const WIPE = /^directory\.(chromeosdevices|mobiledevices)\.action$/;
const EXEC = /^directory\.customer\.devices\.chromeos\.issue_command$/;
const SIGN = /^drive\.approvals\.approve$/;
const UPDATE = /^(chat\.(sections\.position|spaces\.complete_import)|classroom\.courses\.course_work\.student_submissions\.(reclaim|return|turn_in)|directory\.(verification_codes\.invalidate|sign_out)|drive\.approvals\.(comment|reassign|start)|directory\.users\.sign_out)$/;
const CREATE = /^(chat\.spaces\.setup|calendar\.events\.quick_add)$/;

export default discoveryPack({
  name: 'google-workspace',
  ns: 'gws',
  redistribution: 'permitted',
  licence_notes: 'Built from Google API discovery documents as published in googleapis/google-api-go-client (BSD-3-Clause). Method ids, parameter names/types/bounds and the first sentence of a method description are carried; the trait review is ours.',
  config_file: __filename,
  nsOf: (id) => readSources('google-workspace').find((s) => s.id === id)!.opts!.ns!,
  disc: () => ({ dropSegments: ['users'] }),
  build: (id) => ({ ns: readSources('google-workspace').find((s) => s.id === id)!.opts!.ns!, vendorTitles: true, rules: [
      { re: GMAIL_SEND, on: 'verb', patch: { effects: ['send'], rev: 'irreversible', recipient: 'raw' } },
      { re: CHAT_SEND, on: 'verb', patch: { effects: ['send'], rev: 'irreversible', recipient: 'parent' } },
      { re: /^gmail\.drafts\.send$/, on: 'verb', patch: { effects: ['send'], rev: 'irreversible', recipient: 'message' } },
      { re: WATCH, on: 'verb', patch: { effects: ['provision'], rev: 'rate_limited' } },
      { re: STOP, on: 'verb', patch: { effects: ['delete'], rev: 'rate_limited' } },
      { re: READ_CONTENT, on: 'verb', patch: { effects: ['read'], rev: 'reversible' } },
      { re: /^drive\.files\.generate_cse_token$/, on: 'verb', patch: { effects: ['read'], rev: 'reversible', traits: ['pca.credential_access'] } },
      { re: WIPE, on: 'verb', patch: { effects: ['delete', 'privilege'], rev: 'irreversible' } },
      { re: EXEC, on: 'verb', patch: { effects: ['exec'], rev: 'irreversible' } },
      { re: PRIV, on: 'verb', patch: { effects: ['privilege'], rev: 'rate_limited' } },
      { re: SIGN, on: 'verb', patch: { effects: ['sign'], rev: 'irreversible' } },
      { re: /^meet\.spaces\.end_active_conference$/, on: 'verb', patch: { effects: ['delete'], rev: 'irreversible' } },
      { re: /^gmail\.settings\.cse\.keypairs\.obliterate$/, on: 'verb', patch: { effects: ['delete'], rev: 'irreversible', traits: ['pca.credential_access'] } },
      { re: UPDATE, on: 'verb', patch: { effects: ['update'], rev: 'rate_limited' } },
      { re: CREATE, on: 'verb', patch: { effects: ['create'], rev: 'reversible' } },
    ],
  }),
});
