import { openApiPack } from '../lib/factory';

// Reviewed GitHub rules, applied to the derived verb (first match wins). Everything else is classified by the generic engine.
// exec: starts a CI run, a deployment or a build (code runs with the repository's credentials)
const EXEC = /^github\.(actions\.(create_workflow_dispatch|re_run_workflow|re_run_workflow_failed_jobs|re_run_job_for_workflow_run|approve_workflow_run|review_custom_gates_for_run|review_pending_deployments_run)|repos\.(create_dispatch_event|create_deployment|request_pages_build|create_pages_deployment)|checks\.rerequest_(run|suite)|codespaces\.(start_for_authenticated_user|create_for_authenticated_user))$/;
// publish: content other people (or the public) can read
const PUBLISH = /^github\.(issues\.(create|create_comment|update_comment)|pulls\.(create|create_review|create_review_comment|create_reply_for_review_comment|update_review|submit_review)|repos\.(create_commit_comment|create_release|update_release|upload_release_asset)|gists\.(create|create_comment|update|update_comment)|discussions\.\w+|codespaces\.publish_for_authenticated_user|repos\.(create_status|create_commit_status))$/;
// send: notifies named people
const SEND = /^github\.(pulls\.(request_reviewers|rerequest_reviewers)|issues\.add_assignees)$/;
const EXPORT_GET = /^github\.(actions\.download_\w+|dependency_graph\.(export_sbom|generate_sbom_report)|migrations\.(download_archive_for_org|start_for_org|start_for_authenticated_user)|repos\.download_(tarball|zipball)_archive|codespaces\.export_for_authenticated_user)$/;
const PROVISION = /^github\.(repos|orgs)\.create_webhook$/;
const WEBHOOK_PUSH = /^github\.(repos|orgs|apps)\.(ping_webhook|test_push_webhook|redeliver_webhook_delivery)$/;
const ACCESS_CHANGE = /^github\.(repos\.transfer|orgs\.(review_pat_grant_request|review_pat_grant_requests_bulk)|issues\.approve_suggestion)$/;
const BENIGN = /^github\.(markdown\.render|markdown\.render_raw|pull_request_stacks\.unstack|codespaces\.(stop_for_authenticated_user|stop_in_organization)|code_scanning\.commit_autofix|orgs\.external_app_installation|secret_scanning\.bulk_create_\w+_custom_patterns|apps\.scope_token|credentials\.revoke)$/;

export default openApiPack({
  name: 'github',
  ns: 'github',
  redistribution: 'permitted',
  licence_notes: 'GitHub publishes the REST API description (github/rest-api-description) under the MIT licence. Operation ids, parameter names/types/bounds and short summaries are carried; the trait review is ours.',
  config_file: __filename,
  oa: () => ({ naming: 'opid', flatten: true }),
  build: () => ({
    ns: 'github',
    vendorTitles: true,
    rules: [
      { re: EXPORT_GET, on: 'verb', patch: { effects: ['export'], rev: 'irreversible' } },
      { re: EXEC, on: 'verb', patch: { effects: ['exec'], rev: 'irreversible' } },
      { re: PUBLISH, on: 'verb', patch: { effects: ['publish'], rev: 'irreversible' } },
      { re: SEND, on: 'verb', patch: { effects: ['send'], rev: 'irreversible' } },
      { re: PROVISION, on: 'verb', patch: { effects: ['provision'], rev: 'rate_limited' } },
      { re: WEBHOOK_PUSH, on: 'verb', patch: { effects: ['publish'], rev: 'irreversible' } },
      { re: ACCESS_CHANGE, on: 'verb', patch: { effects: ['privilege'], rev: 'irreversible' } },
      { re: BENIGN, on: 'verb', patch: { effects: ['update'], rev: 'rate_limited' } },
      { re: /^github\.(markdown\.render|markdown\.render_raw)$/, on: 'verb', patch: { effects: ['read'], rev: 'reversible' } },
    ],
  }),
});
