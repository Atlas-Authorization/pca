import { openApiPack } from '../lib/factory';

// Reviewed GitLab rules on the derived verb (first match wins).
// `authorize` endpoints are the upload pre-authorisation handshake, not a permission change.
const UPLOAD_AUTH = /\.authorize(_\d+)?$/;
// exec: starts CI work (pipelines, jobs, schedules) or a chat-triggered command
const EXEC = /^gitlab\.(projects\.(pipeline|pipelines\.retry|jobs\.(play|retry)|pipeline_schedules\.play|integrations\.\w+\.trigger|services\.\w+\.trigger)|slack\.trigger)$/;
const PRIV = /^gitlab\.(groups\.(transfer|transfer_to_organization|share)|projects\.(share|transfer)|groups\.members\.override|projects\.deployments\.approval)$/;
const CREATE = /\.(award_emoji|wikis|time_estimate|housekeeping|repository_size)$/;
const UPDATE = /^gitlab\.(projects\.repository\.commits\.(cherry_pick|revert)|groups\.ldap_sync|projects\.environments\.stop|projects\.pipeline_schedules\.take_ownership|projects\.releases\.evidence|projects\.hooks\.events\.resend|geo\.node_proxy\.graphql|projects\.merge_requests\.(approve|unapprove))$/;
const ROTATE = /^gitlab\.(personal_access_tokens\.rotate)$/;

export default openApiPack({
  name: 'gitlab',
  ns: 'gitlab',
  redistribution: 'permitted',
  licence_notes: 'The GitLab REST OpenAPI description is generated from the open source (MIT) GitLab repository. Operation paths, parameter names/types/bounds and short summaries are carried; the trait review is ours.',
  config_file: __filename,
  oa: () => ({ naming: 'path', flatten: true }),
  build: () => ({
    ns: 'gitlab',
    vendorTitles: true,
    rules: [
      { re: UPLOAD_AUTH, on: 'verb', patch: { effects: ['create'], rev: 'reversible' } },
      { re: EXEC, on: 'verb', patch: { effects: ['exec'], rev: 'irreversible' } },
      { re: PRIV, on: 'verb', patch: { effects: ['privilege'], rev: 'irreversible' } },
      { re: CREATE, on: 'verb', patch: { effects: ['create'], rev: 'reversible' } },
      { re: UPDATE, on: 'verb', patch: { effects: ['update'], rev: 'rate_limited' } },
      { re: ROTATE, on: 'verb', patch: { effects: ['update'], rev: 'irreversible', traits: ['pca.credential_access'] } },
    ],
  }),
});
